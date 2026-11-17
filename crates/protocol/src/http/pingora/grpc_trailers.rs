// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Trailers-Only responses for proxy-generated gRPC errors.

use pingora_core::protocols::http::HttpTask;
use pingora_proxy::Session;
use praxis_core::{
    grpc::{GrpcStatusCode, encode_grpc_message},
    next_hop_headers::is_forbidden_client_response_header,
};
use praxis_filter::GrpcErrorMapping;
use tracing::debug;

// -----------------------------------------------------------------------------
// Writer
// -----------------------------------------------------------------------------

/// Send a gRPC Trailers-Only response and end the downstream stream.
///
/// gRPC reports a failed call as HTTP `200` with a `grpc-status`, sent
/// as one header block and nothing else. On HTTP/2 that is a `HEADERS`
/// frame with `END_STREAM`; on HTTP/1.1 it is a header block with an
/// explicit `content-length: 0`, since HTTP/1.1 has no `END_STREAM` and a
/// keepalive client would otherwise read the body until an EOF that
/// never comes.
///
/// Written through `response_duplex_vec` rather than
/// `write_response_header`, because the latter hardcodes
/// `end_of_stream: false` for HTTP/2 and would emit `HEADERS` without
/// `END_STREAM` followed by a stray empty `DATA` frame. gRPC clients report
/// that as "server closed the stream without sending trailers" and lose
/// the status entirely.
pub(crate) async fn send_trailers_only(
    session: &mut Session,
    mapping: &GrpcErrorMapping,
    http_status: u16,
    message: &str,
) {
    let grpc_status = GrpcStatusCode::from_http_status(http_status);
    let Some(header) = build_header(session, mapping, grpc_status, message) else {
        return;
    };
    debug!(
        http_status,
        grpc_status = grpc_status.as_u32(),
        "sending gRPC trailers-only response"
    );
    write_header_only(session, header).await;
}

/// Send a rejection that already carries its own gRPC headers.
///
/// Used for statuses Praxis chooses itself, such as the deadline
/// filter's `DEADLINE_EXCEEDED`, which no HTTP status maps to. Framing
/// still has to go through the `END_STREAM` path, or an HTTP/2 client
/// loses the status.
pub(crate) async fn send_grpc_rejection(session: &mut Session, rejection: &praxis_filter::Rejection) {
    let Some(header) = build_grpc_rejection_header(rejection, session.req_header().version) else {
        return;
    };
    debug!("sending gRPC rejection as a trailers-only response");
    write_header_only(session, header).await;
}

/// Build a preformatted rejection with safe headers and an empty H1 body boundary.
fn build_grpc_rejection_header(
    rejection: &praxis_filter::Rejection,
    version: http::Version,
) -> Option<pingora_http::ResponseHeader> {
    let mut header = pingora_http::ResponseHeader::build(rejection.status, Some(rejection.headers.len()))
        .inspect_err(|error| debug!(%error, "could not build a gRPC rejection header"))
        .ok()?;
    append_grpc_string_headers(&mut header, rejection);
    append_grpc_map_headers(&mut header, rejection);
    // H2 ends the header block with END_STREAM. H1 needs its own boundary.
    if matches!(version, http::Version::HTTP_10 | http::Version::HTTP_11)
        && rejection.status >= 200
        && rejection.status != 204
        && rejection.status != 304
    {
        let _inserted = header.insert_header(http::header::CONTENT_LENGTH, "0");
    }
    Some(header)
}

/// Copy safe string-valued fields except untrusted body framing.
fn append_grpc_string_headers(header: &mut pingora_http::ResponseHeader, rejection: &praxis_filter::Rejection) {
    for (name, value) in &rejection.headers {
        if is_forbidden_client_response_header(name) || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        if let Err(error) = header.append_header(name.clone(), value.clone()) {
            debug!(%error, name, "dropping unencodable gRPC rejection header");
        }
    }
}

/// Copy safe byte-valued fields except untrusted body framing.
fn append_grpc_map_headers(header: &mut pingora_http::ResponseHeader, rejection: &praxis_filter::Rejection) {
    if let Some(headers) = rejection.header_map.as_deref() {
        for (name, value) in headers {
            if is_forbidden_client_response_header(name.as_str()) || name == http::header::CONTENT_LENGTH {
                continue;
            }
            if let Err(error) = header.append_header(name.clone(), value.clone()) {
                debug!(%error, %name, "dropping unencodable gRPC rejection header");
            }
        }
    }
}

/// Write a header block that ends the downstream stream.
async fn write_header_only(session: &mut Session, header: pingora_http::ResponseHeader) {
    if let Err(error) = session
        .as_downstream_mut()
        .response_duplex_vec(vec![HttpTask::Header(Box::new(header), true)])
        .await
    {
        debug!(%error, "failed to write gRPC trailers-only response");
    }
}

/// Build the Trailers-Only header block.
fn build_header(
    session: &Session,
    mapping: &GrpcErrorMapping,
    grpc_status: GrpcStatusCode,
    message: &str,
) -> Option<pingora_http::ResponseHeader> {
    // content-type, grpc-status, grpc-message, content-length.
    let mut header = pingora_http::ResponseHeader::build(200, Some(4))
        .inspect_err(|error| debug!(%error, "could not build a gRPC error response header"))
        .ok()?;
    let _insert = header.insert_header(http::header::CONTENT_TYPE, mapping.content_type().clone());
    let _insert = header.insert_header("grpc-status", grpc_status.as_header_value());

    if mapping.include_message() && !message.is_empty() {
        // Percent-encoding is what keeps a control character in the
        // proxy's error text from splitting the header.
        let encoded = encode_grpc_message(message);
        match http::HeaderValue::from_str(&encoded) {
            Ok(value) => {
                let _insert = header.insert_header("grpc-message", value);
            },
            Err(error) => debug!(%error, "dropping unencodable grpc-message"),
        }
    }

    if session.req_header().version != http::Version::HTTP_2 {
        let _insert = header.insert_header(http::header::CONTENT_LENGTH, "0");
    }
    Some(header)
}

// Tested via integration tests in tests/integration/tests/suite/examples/grpc_status_errors.rs
// and related files, which verify the HTTP/2 END_STREAM behavior and protocol-level details
// that require a full Session context.

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use praxis_core::grpc::GrpcKind;

    use super::*;

    fn make_test_mapping_with_message() -> GrpcErrorMapping {
        GrpcErrorMapping::new(GrpcKind::Grpc, true)
    }

    fn make_test_mapping_without_message() -> GrpcErrorMapping {
        GrpcErrorMapping::new(GrpcKind::GrpcProto, false)
    }

    #[test]
    fn grpc_error_mapping_include_message() {
        let mapping_with = make_test_mapping_with_message();
        assert!(mapping_with.include_message());

        let mapping_without = make_test_mapping_without_message();
        assert!(!mapping_without.include_message());
    }

    #[test]
    fn grpc_status_as_header_value() -> Result<(), Box<dyn std::error::Error>> {
        let codes = vec![
            GrpcStatusCode::Ok,
            GrpcStatusCode::Cancelled,
            GrpcStatusCode::Unknown,
            GrpcStatusCode::InvalidArgument,
            GrpcStatusCode::DeadlineExceeded,
            GrpcStatusCode::NotFound,
            GrpcStatusCode::AlreadyExists,
            GrpcStatusCode::PermissionDenied,
            GrpcStatusCode::ResourceExhausted,
            GrpcStatusCode::FailedPrecondition,
            GrpcStatusCode::Aborted,
            GrpcStatusCode::OutOfRange,
            GrpcStatusCode::Unimplemented,
            GrpcStatusCode::Internal,
            GrpcStatusCode::Unavailable,
            GrpcStatusCode::DataLoss,
            GrpcStatusCode::Unauthenticated,
        ];

        for code in codes {
            let header_val = code.as_header_value();
            let val_str = header_val.to_str()?;
            let parsed = val_str.parse::<u32>()?;
            assert_eq!(parsed, code.as_u32(), "Invalid gRPC status: {val_str}");
        }
        Ok(())
    }

    #[test]
    fn edge_case_http_status_codes() {
        for status in [0, 100, 301, 999] {
            assert_eq!(
                GrpcStatusCode::from_http_status(status),
                GrpcStatusCode::Unknown,
                "unmapped HTTP status {status} should fall back to UNKNOWN without panicking"
            );
        }
    }

    #[test]
    fn message_encoding_edge_cases() {
        let long_message = format!("Error: {}", "x".repeat(1000));
        let encoded = encode_grpc_message(&long_message);
        assert!(
            encoded.len() >= long_message.len(),
            "encoding a very long message must not shrink it"
        );

        let special_only = "\n\r\t";
        let encoded = encode_grpc_message(special_only);
        assert!(
            !encoded.is_empty(),
            "a message of only special characters must still encode"
        );
        assert!(encoded.starts_with('%'), "control characters must be percent-encoded");

        let with_null = "Error\0Details";
        let encoded = encode_grpc_message(with_null);
        assert!(encoded.contains("%00"), "a null byte must be percent-encoded to %00");

        let already_encoded = "Error%20message";
        let encoded = encode_grpc_message(already_encoded);
        assert!(
            encoded.contains("%25"),
            "an already percent-encoded message has its own percent sign encoded"
        );
    }

    #[test]
    fn content_type_variations() {
        let kinds = vec![
            (GrpcKind::Grpc, "application/grpc"),
            (GrpcKind::GrpcProto, "application/grpc+proto"),
            (GrpcKind::GrpcJson, "application/grpc+json"),
        ];

        for (kind, expected_ct) in kinds {
            let mapping = GrpcErrorMapping::new(kind, true);
            assert_eq!(mapping.content_type().to_str().unwrap(), expected_ct);
        }
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one matrix proves both header representations on H1 and H2"
    )]
    fn grpc_rejection_strips_forbidden_headers() {
        let mut rejection = praxis_filter::Rejection::status(200)
            .with_header("grpc-status", "7")
            .with_header("grpc-message", "denied")
            .with_header("x-safe", "kept")
            .with_header("x-praxis-secret", "hidden")
            .with_header("x-ext-protocol-secret", "hidden")
            .with_header("x-ext-agent-secret", "hidden")
            .with_header("connection", "close")
            .with_header("content-length", "0");
        let mut opaque = http::HeaderMap::new();
        opaque.insert("x-praxis-map", http::HeaderValue::from_static("hidden"));
        opaque.insert("x-map-safe", http::HeaderValue::from_static("kept"));
        rejection.header_map = Some(Box::new(opaque));

        for version in [http::Version::HTTP_11, http::Version::HTTP_2] {
            let header = build_grpc_rejection_header(&rejection, version).unwrap();
            assert_eq!(header.headers.get("grpc-status").unwrap(), "7");
            assert_eq!(header.headers.get("grpc-message").unwrap(), "denied");
            assert_eq!(header.headers.get("x-safe").unwrap(), "kept");
            assert_eq!(header.headers.get("x-map-safe").unwrap(), "kept");
            for name in [
                "x-praxis-secret",
                "x-ext-protocol-secret",
                "x-ext-agent-secret",
                "connection",
                "x-praxis-map",
            ] {
                assert!(!header.headers.contains_key(name), "{name} must not escape");
            }
            assert_eq!(
                header.headers.contains_key(http::header::CONTENT_LENGTH),
                version == http::Version::HTTP_11,
                "only H1 needs an explicit empty-body boundary"
            );
            if version == http::Version::HTTP_11 {
                assert_eq!(header.headers.get(http::header::CONTENT_LENGTH).unwrap(), "0");
            }
        }
    }

    #[test]
    fn grpc_rejection_normalizes_missing_and_conflicting_lengths() {
        for (case, string_lengths, map_lengths) in [
            ("missing", vec![], vec![]),
            ("string zero", vec!["0"], vec![]),
            ("string nonzero", vec!["19"], vec![]),
            ("string nonnumeric", vec!["bogus"], vec![]),
            ("string empty", vec![""], vec![]),
            ("string comma list", vec!["0, 19"], vec![]),
            ("string duplicates", vec!["0", "19"], vec![]),
            ("map zero", vec![], vec!["0"]),
            ("map nonzero", vec![], vec!["19"]),
            ("map nonnumeric", vec![], vec!["bogus"]),
            ("map empty", vec![], vec![""]),
            ("map comma list", vec![], vec!["0, 19"]),
            ("map duplicates", vec![], vec!["0", "19"]),
            ("cross-channel conflict", vec!["19"], vec!["0"]),
        ] {
            assert_grpc_rejection_length_case(case, &string_lengths, &map_lengths);
        }
    }

    /// Compare one source-channel permutation across H1 and H2.
    fn assert_grpc_rejection_length_case(case: &str, string_lengths: &[&str], map_lengths: &[&str]) {
        let mut rejection = praxis_filter::Rejection::status(200).with_header("grpc-status", "7");
        for length in string_lengths {
            rejection
                .headers
                .push(("Content-Length".to_owned(), (*length).to_owned()));
        }
        let mut map = http::HeaderMap::new();
        for length in map_lengths {
            map.append(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from_str(length).unwrap(),
            );
        }
        rejection.header_map = Some(Box::new(map));
        for version in [http::Version::HTTP_10, http::Version::HTTP_11, http::Version::HTTP_2] {
            let header = build_grpc_rejection_header(&rejection, version).unwrap();
            assert_grpc_rejection_length(version, &header.headers, case);
        }
    }

    /// Require one exact H1 length and no H2 length after normalization.
    fn assert_grpc_rejection_length(version: http::Version, headers: &http::HeaderMap, case: &str) {
        let lengths = headers
            .get_all(http::header::CONTENT_LENGTH)
            .iter()
            .map(http::HeaderValue::as_bytes)
            .collect::<Vec<_>>();
        if version == http::Version::HTTP_2 {
            assert!(lengths.is_empty(), "{case}: H2 END_STREAM is the body boundary");
        } else {
            assert_eq!(lengths, [b"0".as_slice()], "{case}: H1 needs one exact zero length");
        }
        assert_eq!(headers.get("grpc-status").unwrap(), "7", "{case}");
    }

    #[test]
    fn body_prohibited_grpc_rejection_statuses_never_gain_length() {
        for status in [101, 204, 304] {
            let rejection = praxis_filter::Rejection::status(status)
                .with_header("grpc-status", "7")
                .with_header("content-length", "19");
            for version in [http::Version::HTTP_10, http::Version::HTTP_11, http::Version::HTTP_2] {
                let header = build_grpc_rejection_header(&rejection, version).unwrap();
                assert_eq!(header.status.as_u16(), status, "the rejection status is preserved");
                assert!(
                    !header.headers.contains_key(http::header::CONTENT_LENGTH),
                    "status {status} on {version:?} cannot carry a body length"
                );
            }
        }
    }

    #[test]
    fn grpc_rejection_drops_unencodable_string_headers() {
        let rejection = praxis_filter::Rejection::status(200)
            .with_header("grpc-status", "7")
            .with_header("x-safe", "kept")
            .with_header("bad name", "hidden")
            .with_header("x-invalid-value", "bad\r\nvalue");
        for version in [http::Version::HTTP_11, http::Version::HTTP_2] {
            let header = build_grpc_rejection_header(&rejection, version).unwrap();
            assert_eq!(header.headers.get("grpc-status").unwrap(), "7");
            assert_eq!(header.headers.get("x-safe").unwrap(), "kept");
            assert!(!header.headers.contains_key("x-invalid-value"));
            assert_eq!(
                header.headers.len(),
                if version == http::Version::HTTP_2 { 2 } else { 3 }
            );
            assert_grpc_rejection_length(version, &header.headers, "invalid string fields");
        }
    }

    #[test]
    fn grpc_rejection_invalid_status_returns_none() {
        let mut rejection = praxis_filter::Rejection::status(200).with_header("grpc-status", "7");
        for status in [0, 1000] {
            rejection.status = status;
            for version in [http::Version::HTTP_11, http::Version::HTTP_2] {
                assert!(build_grpc_rejection_header(&rejection, version).is_none());
            }
        }
    }
}
