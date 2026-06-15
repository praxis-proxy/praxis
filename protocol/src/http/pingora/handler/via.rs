// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Via header injection per [RFC 9110 Section 7.6.3].
//!
//! A proxy SHOULD append a `Via` header to forwarded requests
//! and responses indicating the received protocol version and
//! proxy pseudonym.
//!
//! [RFC 9110 Section 7.6.3]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.3

use http::Version;
use tracing::debug;

// -----------------------------------------------------------------------------
// Via Header Utilities
// -----------------------------------------------------------------------------

/// Build a Via header value for the given protocol version.
///
/// Returns a static string like `"1.1 praxis"` or `"2.0 praxis"`.
/// The pseudonym is hardcoded per [RFC 9110 Section 7.6.3].
///
/// [RFC 9110 Section 7.6.3]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.3
fn via_value(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "0.9 praxis",
        Version::HTTP_10 => "1.0 praxis",
        Version::HTTP_11 => "1.1 praxis",
        Version::HTTP_2 => "2 praxis",
        Version::HTTP_3 => "3 praxis",
        _ => {
            tracing::warn!(?version, "unknown HTTP version in Via header, defaulting to 1.1");
            "1.1 praxis"
        },
    }
}

/// Append a Via entry to a Pingora request header.
///
/// If a valid UTF-8 `Via` header already exists, appends
/// comma-separated. Non-UTF-8 values are replaced outright
/// to avoid producing a malformed header.
pub(crate) fn append_request_via(req: &mut pingora_http::RequestHeader, upstream_version: Version) {
    let entry = via_value(upstream_version);
    match req.headers.get("via").and_then(|v| v.to_str().ok()) {
        Some(existing) if !existing.is_empty() => {
            debug!(existing, new = %entry, "appending to existing request Via");
            let _insert = req.insert_header("via", format!("{existing}, {entry}"));
        },
        _ => {
            debug!(via = %entry, "adding request Via header");
            let _insert = req.insert_header("via", entry);
        },
    }
}

/// Append a Via entry to a Pingora response header.
///
/// If a valid UTF-8 `Via` header already exists, appends
/// comma-separated. Non-UTF-8 values are replaced outright
/// to avoid producing a malformed header.
pub(crate) fn append_response_via(resp: &mut pingora_http::ResponseHeader, client_version: Version) {
    let entry = via_value(client_version);
    match resp.headers.get("via").and_then(|v| v.to_str().ok()) {
        Some(existing) if !existing.is_empty() => {
            debug!(existing, new = %entry, "appending to existing response Via");
            let _insert = resp.insert_header("via", format!("{existing}, {entry}"));
        },
        _ => {
            debug!(via = %entry, "adding response Via header");
            let _insert = resp.insert_header("via", entry);
        },
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default,
    reason = "tests"
)]
mod tests {
    use http::HeaderValue;

    use super::*;

    #[test]
    fn via_value_http11() {
        assert_eq!(
            via_value(Version::HTTP_11),
            "1.1 praxis",
            "Via value for HTTP/1.1 should be '1.1 praxis'"
        );
    }

    #[test]
    fn via_value_http2() {
        assert_eq!(
            via_value(Version::HTTP_2),
            "2 praxis",
            "Via value for HTTP/2 should be '2 praxis'"
        );
    }

    #[test]
    fn append_request_via_new_header() {
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        append_request_via(&mut req, Version::HTTP_11);
        assert_eq!(
            req.headers.get("via").unwrap(),
            "1.1 praxis",
            "new Via header should be set on request"
        );
    }

    #[test]
    fn append_request_via_existing_header() {
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let _insert = req.insert_header("via", "1.0 downstream-proxy");
        append_request_via(&mut req, Version::HTTP_11);
        assert_eq!(
            req.headers.get("via").unwrap(),
            "1.0 downstream-proxy, 1.1 praxis",
            "Via should be appended to existing value"
        );
    }

    #[test]
    fn append_response_via_new_header() {
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        append_response_via(&mut resp, Version::HTTP_11);
        assert_eq!(
            resp.headers.get("via").unwrap(),
            "1.1 praxis",
            "new Via header should be set on response"
        );
    }

    #[test]
    fn append_response_via_existing_header() {
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let _insert = resp.insert_header("via", "1.1 upstream-proxy");
        append_response_via(&mut resp, Version::HTTP_11);
        assert_eq!(
            resp.headers.get("via").unwrap(),
            "1.1 upstream-proxy, 1.1 praxis",
            "Via should be appended to existing response value"
        );
    }

    #[test]
    fn append_request_via_replaces_non_utf8() {
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let _insert = req.insert_header("via", HeaderValue::from_bytes(&[0x80, 0xFF]).unwrap());
        append_request_via(&mut req, Version::HTTP_11);
        assert_eq!(
            req.headers.get("via").unwrap(),
            "1.1 praxis",
            "non-UTF8 Via should be replaced, not appended to"
        );
    }

    #[test]
    fn append_response_via_replaces_non_utf8() {
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let _insert = resp.insert_header("via", HeaderValue::from_bytes(&[0x80, 0xFF]).unwrap());
        append_response_via(&mut resp, Version::HTTP_11);
        assert_eq!(
            resp.headers.get("via").unwrap(),
            "1.1 praxis",
            "non-UTF8 Via should be replaced, not appended to"
        );
    }

    #[test]
    fn append_request_via_h2() {
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        append_request_via(&mut req, Version::HTTP_2);
        assert_eq!(
            req.headers.get("via").unwrap(),
            "2 praxis",
            "HTTP/2 request Via should use '2' token"
        );
    }

    #[test]
    fn append_response_via_h2() {
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        append_response_via(&mut resp, Version::HTTP_2);
        assert_eq!(
            resp.headers.get("via").unwrap(),
            "2 praxis",
            "HTTP/2 response Via should use '2' token"
        );
    }
}
