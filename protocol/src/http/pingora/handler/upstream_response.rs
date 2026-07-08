// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Upstream response transformations: hop-by-hop header stripping
//! and reserved internal header removal ([RFC 9110]).
//!
//! [RFC 9110 Section 7.6.1] requires intermediaries to remove
//! hop-by-hop headers in both directions. This module handles
//! the response path: stripping hop-by-hop headers from the
//! upstream response before forwarding to the client. It also
//! removes reserved internal routing headers that backends may
//! echo back.
//!
//! [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110
//! [RFC 9110 Section 7.6.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.1

use pingora_http::ResponseHeader;
use tracing::debug;

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
/// On 101 responses, preserves the `Upgrade` and `Connection`
/// headers only when the `Upgrade` value is `websocket`
/// ([RFC 6455]). Non-`WebSocket` 101 responses (e.g. `h2c`) have
/// upgrade headers stripped to prevent smuggling.
///
/// ```ignore
/// use pingora_http::ResponseHeader;
/// use praxis_protocol::http::pingora::handler::upstream_response;
///
/// let mut resp = ResponseHeader::build(200, None).unwrap();
/// resp.insert_header("Connection", "X-Internal").unwrap();
/// resp.insert_header("X-Internal", "secret").unwrap();
/// upstream_response::strip_hop_by_hop_response(&mut resp, false);
/// assert!(resp.headers.get("Connection").is_none());
/// assert!(resp.headers.get("X-Internal").is_none());
/// ```
///
/// [RFC 6455]: https://datatracker.ietf.org/doc/html/rfc6455
pub(crate) fn strip_hop_by_hop_response(resp: &mut ResponseHeader, is_upgrade_response: bool) {
    let is_ws = is_upgrade_response && is_websocket_response(&resp.headers);
    let conn_values = hop_by_hop::snapshot_connection_values(&resp.headers);

    for name in RESPONSE_HOP_BY_HOP {
        if hop_by_hop::preserve_for_upgrade(name, is_ws) {
            continue;
        }
        let _remove = resp.remove_header(*name);
    }
    hop_by_hop::strip_connection_tokens(resp, &conn_values, RESPONSE_HOP_BY_HOP);

    if is_upgrade_response && !is_ws {
        debug!("stripping non-WebSocket upgrade headers from 101 response");
    }
}

/// Check whether the response's `Upgrade` header is `WebSocket`.
fn is_websocket_response(headers: &http::HeaderMap) -> bool {
    headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(hop_by_hop::is_websocket_upgrade)
}

// -----------------------------------------------------------------------------
// Reserved Internal Header Stripping (Response)
// -----------------------------------------------------------------------------

/// Strip reserved internal headers from an upstream response.
///
/// Removes proxy-internal routing metadata that backends may echo
/// back. These headers are for intra-proxy routing only and must
/// not reach the client.
pub(crate) fn strip_reserved_internal_response(resp: &mut ResponseHeader) {
    let to_remove: Vec<http::HeaderName> = resp
        .headers
        .keys()
        .filter(|name| super::reserved_headers::is_reserved_internal_header(name))
        .cloned()
        .collect();

    for name in &to_remove {
        let _removed = resp.remove_header(name);
    }

    if !to_remove.is_empty() {
        debug!(
            count = to_remove.len(),
            "stripped reserved internal headers from upstream response"
        );
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
    clippy::too_many_lines,
    reason = "tests"
)]
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

        strip_hop_by_hop_response(&mut resp, false);

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

        strip_hop_by_hop_response(&mut resp, false);

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

        strip_hop_by_hop_response(&mut resp, false);

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

        strip_hop_by_hop_response(&mut resp, false);

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

        strip_hop_by_hop_response(&mut resp, false);

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

        strip_hop_by_hop_response(&mut resp, false);

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

        strip_hop_by_hop_response(&mut resp, false);

        assert!(
            resp.headers.get("x-mixed").is_none(),
            "connection header matching should be case-insensitive"
        );
    }

    #[test]
    fn empty_connection_header_value() {
        let mut resp = make_response(&[("connection", ""), ("x-safe", "keep")]);

        strip_hop_by_hop_response(&mut resp, false);

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
        strip_hop_by_hop_response(&mut resp, false);
    }

    #[test]
    fn upgrade_response_preserves_upgrade_and_connection() {
        let mut resp = make_response(&[
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            ("keep-alive", "300"),
        ]);

        strip_hop_by_hop_response(&mut resp, true);

        assert_eq!(
            resp.headers.get("upgrade").unwrap(),
            "websocket",
            "upgrade header should be preserved for 101 responses"
        );
        assert_eq!(
            resp.headers.get("connection").unwrap(),
            "Upgrade",
            "connection header should be preserved for 101 responses"
        );
        assert_eq!(
            resp.headers.get("sec-websocket-accept").unwrap(),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            "websocket headers should be preserved"
        );
        assert!(
            resp.headers.get("keep-alive").is_none(),
            "other hop-by-hop headers should still be stripped"
        );
    }

    #[test]
    fn non_upgrade_response_strips_upgrade_and_connection() {
        let mut resp = make_response(&[("upgrade", "websocket"), ("connection", "Upgrade")]);

        strip_hop_by_hop_response(&mut resp, false);

        assert!(
            resp.headers.get("upgrade").is_none(),
            "upgrade should be stripped for non-upgrade responses"
        );
        assert!(
            resp.headers.get("connection").is_none(),
            "connection should be stripped for non-upgrade responses"
        );
    }

    #[test]
    fn h2c_upgrade_response_strips_headers() {
        let mut resp = make_response(&[("upgrade", "h2c"), ("connection", "Upgrade")]);

        strip_hop_by_hop_response(&mut resp, true);

        assert!(
            resp.headers.get("upgrade").is_none(),
            "h2c upgrade header must be stripped from response to prevent smuggling"
        );
        assert!(
            resp.headers.get("connection").is_none(),
            "connection must be stripped for h2c upgrade responses"
        );
    }

    #[test]
    fn websocket_upgrade_response_preserves() {
        let mut resp = make_response(&[
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        ]);

        strip_hop_by_hop_response(&mut resp, true);

        assert_eq!(
            resp.headers.get("upgrade").unwrap(),
            "websocket",
            "websocket upgrade should be preserved in response"
        );
        assert_eq!(
            resp.headers.get("connection").unwrap(),
            "Upgrade",
            "connection should be preserved for websocket upgrade response"
        );
        assert_eq!(
            resp.headers.get("sec-websocket-accept").unwrap(),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            "websocket accept header should be preserved"
        );
    }

    #[test]
    fn strips_x_praxis_reserved_headers_from_response() {
        let mut resp = make_response(&[
            ("x-praxis-filter-action", "routed"),
            ("x-praxis-route", "internal"),
            ("content-type", "application/json"),
        ]);

        strip_reserved_internal_response(&mut resp);

        assert!(
            resp.headers.get("x-praxis-filter-action").is_none(),
            "x-praxis-filter-action should be stripped from response"
        );
        assert!(
            resp.headers.get("x-praxis-route").is_none(),
            "x-praxis-route should be stripped from response"
        );
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "application/json",
            "content-type should be preserved"
        );
    }

    #[test]
    fn strips_x_ext_protocol_reserved_headers_from_response() {
        let mut resp = make_response(&[
            ("x-ext-protocol-servername", "backend-1"),
            ("x-ext-protocol-toolname", "get_weather"),
            ("server", "test"),
        ]);

        strip_reserved_internal_response(&mut resp);

        assert!(
            resp.headers.get("x-ext-protocol-servername").is_none(),
            "x-ext-protocol-servername should be stripped from response"
        );
        assert!(
            resp.headers.get("x-ext-protocol-toolname").is_none(),
            "x-ext-protocol-toolname should be stripped from response"
        );
        assert_eq!(
            resp.headers.get("server").unwrap(),
            "test",
            "server header should be preserved"
        );
    }

    #[test]
    fn strips_x_ext_agent_reserved_headers_from_response() {
        let mut resp = make_response(&[
            ("x-ext-agent-method", "task/send"),
            ("x-ext-agent-family", "internal"),
            ("cache-control", "no-cache"),
        ]);

        strip_reserved_internal_response(&mut resp);

        assert!(
            resp.headers.get("x-ext-agent-method").is_none(),
            "x-ext-agent-method should be stripped from response"
        );
        assert!(
            resp.headers.get("x-ext-agent-family").is_none(),
            "x-ext-agent-family should be stripped from response"
        );
        assert_eq!(
            resp.headers.get("cache-control").unwrap(),
            "no-cache",
            "cache-control should be preserved"
        );
    }

    #[test]
    fn strips_multiple_reserved_prefixes_from_response() {
        let mut resp = make_response(&[
            ("x-praxis-filter-action", "routed"),
            ("x-ext-protocol-servername", "backend-1"),
            ("x-ext-agent-method", "task/send"),
            ("x-request-id", "abc-123"),
            ("content-type", "text/plain"),
        ]);

        strip_reserved_internal_response(&mut resp);

        assert!(
            resp.headers.get("x-praxis-filter-action").is_none(),
            "x-praxis-* should be stripped"
        );
        assert!(
            resp.headers.get("x-ext-protocol-servername").is_none(),
            "x-ext-protocol-* should be stripped"
        );
        assert!(
            resp.headers.get("x-ext-agent-method").is_none(),
            "x-ext-agent-* should be stripped"
        );
        assert_eq!(
            resp.headers.get("x-request-id").unwrap(),
            "abc-123",
            "non-reserved x- headers should be preserved"
        );
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/plain",
            "standard headers should be preserved"
        );
    }

    #[test]
    fn preserves_standard_protocol_headers_in_response() {
        let mut resp = make_response(&[
            ("ext-session-id", "session-123"),
            ("ext-method", "process"),
            ("ext-name", "get_weather"),
            ("ext-protocol-version", "2025-03-26"),
        ]);

        strip_reserved_internal_response(&mut resp);

        assert_eq!(
            resp.headers.get("ext-session-id").unwrap(),
            "session-123",
            "standard ext-session-id should be preserved (no x- prefix)"
        );
        assert_eq!(
            resp.headers.get("ext-method").unwrap(),
            "process",
            "standard ext-method should be preserved"
        );
        assert_eq!(
            resp.headers.get("ext-name").unwrap(),
            "get_weather",
            "standard ext-name should be preserved"
        );
        assert_eq!(
            resp.headers.get("ext-protocol-version").unwrap(),
            "2025-03-26",
            "standard ext-protocol-version should be preserved"
        );
    }

    #[test]
    fn preserves_non_reserved_x_headers_in_response() {
        let mut resp = make_response(&[
            ("x-request-id", "abc-123"),
            ("x-correlation-id", "xyz-789"),
            ("x-forwarded-for", "10.0.0.1"),
            ("x-custom-header", "custom-value"),
        ]);

        strip_reserved_internal_response(&mut resp);

        assert_eq!(
            resp.headers.get("x-request-id").unwrap(),
            "abc-123",
            "x-request-id should be preserved"
        );
        assert_eq!(
            resp.headers.get("x-correlation-id").unwrap(),
            "xyz-789",
            "x-correlation-id should be preserved"
        );
        assert_eq!(
            resp.headers.get("x-forwarded-for").unwrap(),
            "10.0.0.1",
            "x-forwarded-for should be preserved"
        );
        assert_eq!(
            resp.headers.get("x-custom-header").unwrap(),
            "custom-value",
            "x-custom-header should be preserved"
        );
    }

    #[test]
    fn no_reserved_headers_is_noop_response() {
        let mut resp = make_response(&[
            ("content-type", "text/html"),
            ("x-request-id", "abc-123"),
            ("server", "test"),
        ]);

        strip_reserved_internal_response(&mut resp);

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
        assert_eq!(
            resp.headers.get("server").unwrap(),
            "test",
            "server should be preserved"
        );
    }

    #[test]
    fn empty_response_reserved_strip_no_panic() {
        let mut resp = ResponseHeader::build(200, None).unwrap();
        strip_reserved_internal_response(&mut resp);
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
