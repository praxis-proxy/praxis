// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! Hop-by-hop header stripping on upstream responses ([RFC 9110]).
//!
//! [RFC 9110 Section 7.6.1] requires intermediaries to remove
//! hop-by-hop headers in both directions. This module handles
//! the response path: stripping hop-by-hop headers from the
//! upstream response before forwarding to the client.
//!
//! [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110
//! [RFC 9110 Section 7.6.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.1

use pingora_http::ResponseHeader;

use super::hop_by_hop::{self, RESPONSE_HOP_BY_HOP};

// -----------------------------------------------------------------------------
// Hop-by-hop Header Stripping (Response)
// -----------------------------------------------------------------------------

/// Strip hop-by-hop headers from an upstream response.
///
/// Removes all RFC-defined hop-by-hop headers plus any custom
/// headers declared in the `Connection` header value. Must be
/// called before the response reaches the client.
///
/// ```ignore
/// use pingora_http::ResponseHeader;
/// use praxis_protocol::http::pingora::handler::upstream_response;
///
/// let mut resp = ResponseHeader::build(200, None).unwrap();
/// resp.insert_header("Connection", "X-Internal").unwrap();
/// resp.insert_header("X-Internal", "secret").unwrap();
/// upstream_response::strip_hop_by_hop_response(&mut resp);
/// assert!(resp.headers.get("Connection").is_none());
/// assert!(resp.headers.get("X-Internal").is_none());
/// ```
pub(crate) fn strip_hop_by_hop_response(resp: &mut ResponseHeader) {
    let extra = hop_by_hop::connection_tokens(&resp.headers, RESPONSE_HOP_BY_HOP);

    for name in RESPONSE_HOP_BY_HOP {
        let _remove = resp.remove_header(*name);
    }
    for name in &extra {
        let _remove = resp.remove_header(name.as_str());
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_standard_response_hop_by_hop() {
        let mut resp = make_response(&[
            ("connection", "close"),
            ("keep-alive", "300"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("te", "trailers"),
            ("trailer", "X-Checksum"),
            ("proxy-authenticate", "Basic"),
            ("x-real-header", "keep-me"),
            ("content-type", "text/plain"),
        ]);

        strip_hop_by_hop_response(&mut resp);

        assert!(
            resp.headers.get("connection").is_none(),
            "connection header should be stripped from response"
        );
        assert!(
            resp.headers.get("keep-alive").is_none(),
            "keep-alive header should be stripped from response"
        );
        assert!(
            resp.headers.get("transfer-encoding").is_none(),
            "transfer-encoding header should be stripped from response"
        );
        assert!(
            resp.headers.get("upgrade").is_none(),
            "upgrade header should be stripped from response"
        );
        assert!(
            resp.headers.get("te").is_none(),
            "te header should be stripped from response"
        );
        assert!(
            resp.headers.get("trailer").is_none(),
            "trailer header should be stripped from response"
        );
        assert!(
            resp.headers.get("proxy-authenticate").is_none(),
            "proxy-authenticate header should be stripped from response"
        );
        assert_eq!(
            resp.headers.get("x-real-header").unwrap(),
            "keep-me",
            "end-to-end header should be preserved on response"
        );
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/plain",
            "content-type should be preserved on response"
        );
    }

    #[test]
    fn strips_custom_connection_declared_headers() {
        let mut resp = make_response(&[
            ("connection", "X-Internal, X-Debug"),
            ("x-internal", "secret"),
            ("x-debug", "true"),
            ("x-safe", "keep"),
        ]);

        strip_hop_by_hop_response(&mut resp);

        assert!(
            resp.headers.get("connection").is_none(),
            "connection header should be stripped"
        );
        assert!(
            resp.headers.get("x-internal").is_none(),
            "custom connection-listed header should be stripped"
        );
        assert!(
            resp.headers.get("x-debug").is_none(),
            "custom connection-listed header should be stripped"
        );
        assert_eq!(
            resp.headers.get("x-safe").unwrap(),
            "keep",
            "header not listed in connection should be preserved"
        );
    }

    #[test]
    fn does_not_strip_proxy_authorization_from_response() {
        let mut resp = make_response(&[("proxy-authorization", "Bearer tok"), ("content-type", "text/plain")]);

        strip_hop_by_hop_response(&mut resp);

        assert!(
            resp.headers.get("proxy-authorization").is_some(),
            "proxy-authorization is a request-only header and should not be stripped from responses"
        );
    }

    #[test]
    fn preserves_standard_response_headers() {
        let mut resp = make_response(&[
            ("connection", "close"),
            ("content-type", "application/json"),
            ("content-length", "42"),
            ("cache-control", "no-cache"),
            ("set-cookie", "session=abc"),
            ("server", "praxis"),
            ("date", "Wed, 01 Jan 2025 00:00:00 GMT"),
        ]);

        strip_hop_by_hop_response(&mut resp);

        assert!(
            resp.headers.get("connection").is_none(),
            "connection header should be stripped"
        );
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "application/json",
            "content-type should be preserved"
        );
        assert_eq!(
            resp.headers.get("content-length").unwrap(),
            "42",
            "content-length should be preserved"
        );
        assert_eq!(
            resp.headers.get("cache-control").unwrap(),
            "no-cache",
            "cache-control should be preserved"
        );
        assert_eq!(
            resp.headers.get("set-cookie").unwrap(),
            "session=abc",
            "set-cookie should be preserved"
        );
        assert_eq!(
            resp.headers.get("server").unwrap(),
            "praxis",
            "server should be preserved"
        );
        assert_eq!(
            resp.headers.get("date").unwrap(),
            "Wed, 01 Jan 2025 00:00:00 GMT",
            "date should be preserved"
        );
    }

    #[test]
    fn no_hop_by_hop_headers_is_noop() {
        let mut resp = make_response(&[("content-type", "text/html"), ("x-request-id", "abc-123")]);

        strip_hop_by_hop_response(&mut resp);

        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/html",
            "content-type should be preserved"
        );
        assert_eq!(
            resp.headers.get("x-request-id").unwrap(),
            "abc-123",
            "x-request-id should be preserved"
        );
    }

    #[test]
    fn connection_value_with_whitespace() {
        let mut resp = make_response(&[
            ("connection", " X-A ,  X-B  "),
            ("x-a", "1"),
            ("x-b", "2"),
            ("x-c", "3"),
        ]);

        strip_hop_by_hop_response(&mut resp);

        assert!(
            resp.headers.get("x-a").is_none(),
            "x-a should be stripped despite whitespace"
        );
        assert!(
            resp.headers.get("x-b").is_none(),
            "x-b should be stripped despite whitespace"
        );
        assert_eq!(
            resp.headers.get("x-c").unwrap(),
            "3",
            "x-c not in connection list should be preserved"
        );
    }

    #[test]
    fn connection_value_case_insensitive() {
        let mut resp = make_response(&[("connection", "X-MiXeD"), ("x-mixed", "stripped")]);

        strip_hop_by_hop_response(&mut resp);

        assert!(
            resp.headers.get("x-mixed").is_none(),
            "connection header matching should be case-insensitive"
        );
    }

    #[test]
    fn empty_connection_header_value() {
        let mut resp = make_response(&[("connection", ""), ("x-safe", "keep")]);

        strip_hop_by_hop_response(&mut resp);

        assert!(
            resp.headers.get("connection").is_none(),
            "empty connection header should be stripped"
        );
        assert_eq!(
            resp.headers.get("x-safe").unwrap(),
            "keep",
            "unrelated header should be preserved"
        );
    }

    #[test]
    fn empty_response_no_panic() {
        let mut resp = ResponseHeader::build(200, None).unwrap();
        strip_hop_by_hop_response(&mut resp);
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a response with the given headers for tests.
    fn make_response(headers: &[(&str, &str)]) -> ResponseHeader {
        let mut resp = ResponseHeader::build(200, None).unwrap();
        for (name, value) in headers {
            let _inserted = resp.insert_header((*name).to_owned(), (*value).to_owned());
        }
        resp
    }
}
