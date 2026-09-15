// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

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

/// Pre-validated [`http::HeaderValue`] for [`via_value`]'s entry.
///
/// Inserting the `&str` directly would re-validate and heap-copy the
/// value on every forwarded request and response; these statics wrap
/// the same bytes once at compile time.
fn via_header_value(entry: &'static str) -> http::HeaderValue {
    const V09: http::HeaderValue = http::HeaderValue::from_static("0.9 praxis");
    const V10: http::HeaderValue = http::HeaderValue::from_static("1.0 praxis");
    const V11: http::HeaderValue = http::HeaderValue::from_static("1.1 praxis");
    const V2: http::HeaderValue = http::HeaderValue::from_static("2 praxis");
    const V3: http::HeaderValue = http::HeaderValue::from_static("3 praxis");
    match entry {
        "0.9 praxis" => V09,
        "1.0 praxis" => V10,
        "2 praxis" => V2,
        "3 praxis" => V3,
        _ => V11,
    }
}

/// Combine existing `Via` field-lines with this proxy's `entry`.
///
/// [RFC 9110 Section 7.6.3] treats multiple `Via` field-lines as a
/// single comma-separated list, so every prior entry is preserved.
/// Returns `None` when there is no valid chain to keep (absent, empty,
/// or any non-UTF-8 line), signalling the caller to write the
/// pre-validated static value outright rather than emit a malformed
/// header.
///
/// [RFC 9110 Section 7.6.3]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.3
fn combined_via(headers: &http::HeaderMap, entry: &str) -> Option<String> {
    let mut existing: Vec<&str> = Vec::new();
    for value in headers.get_all("via") {
        // A non-UTF-8 line means the chain cannot be rebuilt safely.
        let text = value.to_str().ok()?;
        if !text.is_empty() {
            existing.push(text);
        }
    }
    (!existing.is_empty()).then(|| format!("{}, {entry}", existing.join(", ")))
}

/// Append a Via entry to a Pingora request header.
///
/// All existing valid UTF-8 `Via` field-lines are preserved and this
/// proxy's entry is appended comma-separated (RFC 9110 treats multiple
/// `Via` field-lines as one list). If any existing line is non-UTF-8,
/// the header is replaced outright to avoid a malformed value.
pub(crate) fn append_request_via(req: &mut pingora_http::RequestHeader, upstream_version: Version) {
    let entry = via_value(upstream_version);
    if let Some(combined) = combined_via(&req.headers, entry) {
        debug!(via = %combined, "appending to existing request Via");
        let _insert = req.insert_header("via", combined);
    } else {
        debug!(via = %entry, "adding request Via header");
        let _insert = req.insert_header("via", via_header_value(entry));
    }
}

/// Append a Via entry to a Pingora response header.
///
/// Per [RFC 9110 Section 7.6.3] the `received-protocol` on a response `Via`
/// records the protocol version over which this proxy received the response,
/// i.e. the upstream leg (not the downstream client's version). Callers must
/// pass the upstream response version accordingly.
///
/// All existing valid UTF-8 `Via` field-lines are preserved and this
/// proxy's entry is appended comma-separated (RFC 9110 treats multiple
/// `Via` field-lines as one list). If any existing line is non-UTF-8,
/// the header is replaced outright to avoid a malformed value.
///
/// [RFC 9110 Section 7.6.3]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.3
pub(crate) fn append_response_via(resp: &mut pingora_http::ResponseHeader, upstream_version: Version) {
    let entry = via_value(upstream_version);
    if let Some(combined) = combined_via(&resp.headers, entry) {
        debug!(via = %combined, "appending to existing response Via");
        let _insert = resp.insert_header("via", combined);
    } else {
        debug!(via = %entry, "adding response Via header");
        let _insert = resp.insert_header("via", via_header_value(entry));
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
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

    #[test]
    fn append_request_via_combines_multiple_field_lines() {
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.append_header("via", "1.0 a").unwrap();
        req.append_header("via", "1.1 b").unwrap();
        append_request_via(&mut req, Version::HTTP_11);
        assert_eq!(
            req.headers.get("via").unwrap(),
            "1.0 a, 1.1 b, 1.1 praxis",
            "all existing request Via field-lines must be preserved"
        );
    }

    #[test]
    fn append_response_via_combines_multiple_field_lines() {
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        resp.append_header("via", "1.1 a").unwrap();
        resp.append_header("via", "2 b").unwrap();
        append_response_via(&mut resp, Version::HTTP_11);
        assert_eq!(
            resp.headers.get("via").unwrap(),
            "1.1 a, 2 b, 1.1 praxis",
            "all existing response Via field-lines must be preserved"
        );
    }

    #[test]
    fn append_request_via_replaces_when_any_line_non_utf8() {
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.append_header("via", "1.0 a").unwrap();
        req.append_header("via", HeaderValue::from_bytes(&[0x80, 0xFF]).unwrap())
            .unwrap();
        append_request_via(&mut req, Version::HTTP_11);
        assert_eq!(
            req.headers.get("via").unwrap(),
            "1.1 praxis",
            "a non-UTF-8 field-line forces outright replacement"
        );
    }

    #[test]
    fn append_response_via_replaces_when_any_line_non_utf8() {
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        resp.append_header("via", "1.0 a").unwrap();
        resp.append_header("via", HeaderValue::from_bytes(&[0x80, 0xFF]).unwrap())
            .unwrap();
        append_response_via(&mut resp, Version::HTTP_11);
        assert_eq!(
            resp.headers.get("via").unwrap(),
            "1.1 praxis",
            "a non-UTF-8 response field-line forces outright replacement"
        );
    }
}
