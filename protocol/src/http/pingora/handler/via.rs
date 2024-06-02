// SPDX-License-Identifier: LGPL-3.0-only
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
// Constants
// -----------------------------------------------------------------------------

/// Proxy pseudonym used in Via header values.
const PSEUDONYM: &str = "praxis";

// -----------------------------------------------------------------------------
// Via Header Utilities
// -----------------------------------------------------------------------------

/// Format the protocol version token for a Via header value.
///
/// ```ignore
/// assert_eq!(version_token(http::Version::HTTP_11), "1.1");
/// assert_eq!(version_token(http::Version::HTTP_2), "2.0");
/// ```
fn version_token(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_2 => "2.0",
        Version::HTTP_3 => "3.0",
        _ => "1.1",
    }
}

/// Build a Via header value for the given protocol version.
///
/// Returns a string like `"1.1 praxis"` or `"2.0 praxis"`.
fn via_value(version: Version) -> String {
    format!("{} {PSEUDONYM}", version_token(version))
}

/// Append a Via entry to a Pingora request header.
///
/// If a `Via` header already exists, appends comma-separated.
/// Otherwise inserts a new header.
pub(crate) fn append_request_via(req: &mut pingora_http::RequestHeader, upstream_version: Version) {
    let entry = via_value(upstream_version);
    let combined = match req.headers.get("via") {
        Some(existing) if !existing.is_empty() => {
            let existing = existing.to_str().unwrap_or("");
            debug!(existing, new = %entry, "appending to existing request Via");
            format!("{existing}, {entry}")
        },
        _ => {
            debug!(via = %entry, "adding request Via header");
            entry
        },
    };
    let _insert = req.insert_header("via", combined);
}

/// Append a Via entry to a Pingora response header.
///
/// If a `Via` header already exists, appends comma-separated.
/// Otherwise inserts a new header.
pub(crate) fn append_response_via(resp: &mut pingora_http::ResponseHeader, client_version: Version) {
    let entry = via_value(client_version);
    let combined = match resp.headers.get("via") {
        Some(existing) if !existing.is_empty() => {
            let existing = existing.to_str().unwrap_or("");
            debug!(existing, new = %entry, "appending to existing response Via");
            format!("{existing}, {entry}")
        },
        _ => {
            debug!(via = %entry, "adding response Via header");
            entry
        },
    };
    let _insert = resp.insert_header("via", combined);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_token_http11() {
        assert_eq!(
            version_token(Version::HTTP_11),
            "1.1",
            "HTTP/1.1 should produce 1.1 token"
        );
    }

    #[test]
    fn version_token_http2() {
        assert_eq!(version_token(Version::HTTP_2), "2.0", "HTTP/2 should produce 2.0 token");
    }

    #[test]
    fn version_token_http10() {
        assert_eq!(
            version_token(Version::HTTP_10),
            "1.0",
            "HTTP/1.0 should produce 1.0 token"
        );
    }

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
            "2.0 praxis",
            "Via value for HTTP/2 should be '2.0 praxis'"
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
    fn append_request_via_h2() {
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        append_request_via(&mut req, Version::HTTP_2);
        assert_eq!(
            req.headers.get("via").unwrap(),
            "2.0 praxis",
            "HTTP/2 request Via should use 2.0 token"
        );
    }

    #[test]
    fn append_response_via_h2() {
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        append_response_via(&mut resp, Version::HTTP_2);
        assert_eq!(
            resp.headers.get("via").unwrap(),
            "2.0 praxis",
            "HTTP/2 response Via should use 2.0 token"
        );
    }
}
