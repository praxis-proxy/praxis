// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! [RFC 9110] HTTP Semantics conformance tests.
//!
//! [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110

use std::time::Duration;

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_send, parse_body, parse_header, parse_status, simple_proxy_yaml, start_backend,
    start_header_echo_backend, start_slow_backend, wait_for_http2,
};

use super::test_utils::{
    h2c_get, start_304_backend, start_custom_response_header_backend, start_etag_backend, start_garbage_backend,
    start_partial_header_backend, start_range_backend, start_redirect_backend, timeout_filter_yaml,
};

// -----------------------------------------------------------------------------
// RFC 9110 Section 7.2 - Host Header
// -----------------------------------------------------------------------------

/// [RFC 9110 Section 7.2]: a request with multiple
/// conflicting Host headers must be rejected with 400.
/// This prevents request smuggling via ambiguous routing.
///
/// [RFC 9110 Section 7.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.2
#[test]
fn rfc9110_multiple_host_headers_rejected() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: alpha.example.com\r\n\
         Host: beta.example.com\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);

    assert_eq!(
        status, 400,
        "conflicting Host headers must be rejected with 400, got {status}"
    );
}

/// [RFC 9110 Section 7.2]: when the request-target is in
/// absolute-form, the Host header (if present) should
/// agree. A mismatch may be rejected or handled by
/// preferring one value.
///
/// [RFC 9110 Section 7.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.2
#[test]
fn rfc9110_host_mismatch_with_absolute_uri() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET http://example.com/ HTTP/1.1\r\n\
         Host: other.example.com\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert!(
        status == 200 || status == 400 || status == 404 || status == 0,
        "expected 200, 400, 404, or connection close for \
         Host/URI mismatch, got {status}"
    );
}

// -----------------------------------------------------------------------------
// RFC 9110 Section 9.3.8 - TRACE
// -----------------------------------------------------------------------------

/// [RFC 9110 Section 9.3.8]: TRACE should be handled by
/// the proxy without crashing. A strict implementation
/// would not return the backend's arbitrary body, but
/// Pingora forwards TRACE like any other method.
///
/// [RFC 9110 Section 9.3.8]: https://datatracker.ietf.org/doc/html/rfc9110#section-9.3.8
#[test]
fn rfc9110_trace_request_handled() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "TRACE / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert!(
        status == 200 || status == 405 || status == 0,
        "expected 200, 405, or connection close for \
         TRACE, got {status}"
    );
}

// -----------------------------------------------------------------------------
// RFC 9110 Section 8.6 - Duplicate Content-Length
// -----------------------------------------------------------------------------

/// [RFC 9110 Section 8.6]: two Content-Length headers with
/// different values must be rejected. Pingora rejects
/// with 400 to prevent request smuggling.
///
/// [RFC 9110 Section 8.6]: https://datatracker.ietf.org/doc/html/rfc9110#section-8.6
#[test]
fn rfc9110_duplicate_cl_different_values_rejected() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 5\r\n\
         Content-Length: 10\r\n\
         Connection: close\r\n\
         \r\n\
         hello",
    );
    let status = parse_status(&raw);

    assert_eq!(
        status, 400,
        "duplicate Content-Length with different values must be rejected (got {status})"
    );
}

/// [RFC 9110 Section 8.6]: two Content-Length headers with
/// identical values. Pingora rejects any duplicate CL
/// headers, even with matching values.
///
/// [RFC 9110 Section 8.6]: https://datatracker.ietf.org/doc/html/rfc9110#section-8.6
#[test]
fn rfc9110_duplicate_cl_same_value_rejected() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 5\r\n\
         Content-Length: 5\r\n\
         Connection: close\r\n\
         \r\n\
         hello",
    );
    let status = parse_status(&raw);

    assert_eq!(
        status, 400,
        "duplicate Content-Length even with same value must be rejected (got {status})"
    );
}

// -----------------------------------------------------------------------------
// RFC 9110 Section 15.6.3 - 502 Bad Gateway
// -----------------------------------------------------------------------------

/// [RFC 9110 Section 15.6.3]: a proxy MUST return 502 when the
/// upstream is unreachable (connection refused).
///
/// [RFC 9110 Section 15.6.3]: https://datatracker.ietf.org/doc/html/rfc9110#section-15.6.3
#[test]
fn rfc9110_connection_refused_returns_502() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, dead_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 502,
        "connection refused upstream must produce 502 (RFC 9110 S15.6.3)"
    );
}

/// [RFC 9110 Section 15.6.3]: a proxy MUST return 502 when the
/// upstream sends garbage (non-HTTP) bytes instead of a valid
/// response.
///
/// [RFC 9110 Section 15.6.3]: https://datatracker.ietf.org/doc/html/rfc9110#section-15.6.3
#[test]
fn rfc9110_garbage_upstream_returns_502() {
    let backend_port = start_garbage_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 502,
        "garbage upstream response must produce 502 (RFC 9110 S15.6.3)"
    );
}

/// [RFC 9110 Section 15.6.3]: a proxy MUST return 502 when the
/// upstream sends an incomplete response (partial headers, then
/// drops the connection).
///
/// [RFC 9110 Section 15.6.3]: https://datatracker.ietf.org/doc/html/rfc9110#section-15.6.3
#[test]
fn rfc9110_incomplete_upstream_returns_502() {
    let backend_port = start_partial_header_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 502,
        "incomplete upstream response must produce 502 (RFC 9110 S15.6.3)"
    );
}

// -----------------------------------------------------------------------------
// RFC 9110 Section 15.6.5 - 504 Gateway Timeout
// -----------------------------------------------------------------------------

/// [RFC 9110 Section 15.6.5]: a proxy MUST return 504 when the
/// upstream does not respond within the configured timeout.
///
/// [RFC 9110 Section 15.6.5]: https://datatracker.ietf.org/doc/html/rfc9110#section-15.6.5
#[test]
fn rfc9110_upstream_timeout_returns_504() {
    let slow_port = start_slow_backend("slow", Duration::from_millis(500));
    let proxy_port = free_port();
    let yaml = timeout_filter_yaml(proxy_port, slow_port, 100);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 504,
        "upstream exceeding timeout must produce 504 (RFC 9110 S15.6.5)"
    );
}

/// [RFC 9110 Section 15.6.5]: an upstream responding within the
/// timeout must succeed (boundary check).
///
/// [RFC 9110 Section 15.6.5]: https://datatracker.ietf.org/doc/html/rfc9110#section-15.6.5
#[test]
fn rfc9110_upstream_within_timeout_succeeds() {
    let backend_port = start_backend("fast-response");
    let proxy_port = free_port();
    let yaml = timeout_filter_yaml(proxy_port, backend_port, 5000);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "upstream within timeout must succeed (RFC 9110 S15.6.5)");
    assert_eq!(body, "fast-response", "response body must pass through correctly");
}

// -----------------------------------------------------------------------------
// RFC 9110 Section 5.1 - Unrecognized Header Forwarding
// -----------------------------------------------------------------------------

/// [RFC 9110 Section 5.1]: a proxy MUST forward unrecognized
/// headers to upstream. Custom `X-Custom-Widget` should appear
/// in the upstream request.
///
/// [RFC 9110 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-5.1
#[test]
fn rfc9110_custom_header_forwarded_to_upstream() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Custom-Widget: test-value-42\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(status, 200, "request with custom header should succeed");
    assert!(
        body.to_lowercase().contains("x-custom-widget: test-value-42"),
        "custom header X-Custom-Widget must be forwarded to upstream; echoed headers: {body}"
    );
}

/// [RFC 9110 Section 5.1]: custom response headers from
/// upstream MUST be forwarded to the client.
///
/// [RFC 9110 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-5.1
#[test]
fn rfc9110_custom_response_header_forwarded_to_client() {
    let backend_port = start_custom_response_header_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let header_val = parse_header(&raw, "x-custom-response");

    assert_eq!(status, 200, "response with custom header should succeed");
    assert_eq!(
        header_val.as_deref(),
        Some("backend-value-99"),
        "custom response header X-Custom-Response must be forwarded to client"
    );
}

/// [RFC 9110 Section 5.1]: a header listed in the Connection
/// header MUST be stripped before forwarding, even if the header
/// name is unrecognized.
///
/// [RFC 9110 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-5.1
#[test]
fn rfc9110_connection_listed_header_stripped() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close, X-Secret-Hop\r\n\
         X-Secret-Hop: should-be-stripped\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(status, 200, "request should succeed");
    assert!(
        !body.to_lowercase().contains("x-secret-hop"),
        "header listed in Connection must be stripped before upstream; echoed headers: {body}"
    );
}

/// [RFC 9110 Section 5.1]: multiple custom headers MUST all
/// be forwarded transparently.
///
/// [RFC 9110 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-5.1
#[test]
fn rfc9110_multiple_custom_headers_all_forwarded() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-First: alpha\r\n\
         X-Second: beta\r\n\
         X-Third: gamma\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert_eq!(status, 200, "request with multiple custom headers should succeed");
    assert!(
        body_lower.contains("x-first: alpha"),
        "X-First must be forwarded; echoed headers: {body}"
    );
    assert!(
        body_lower.contains("x-second: beta"),
        "X-Second must be forwarded; echoed headers: {body}"
    );
    assert!(
        body_lower.contains("x-third: gamma"),
        "X-Third must be forwarded; echoed headers: {body}"
    );
}

/// [RFC 9110 Section 5.1]: standard but uncommon headers (like
/// `Accept-Patch`) MUST be forwarded transparently.
///
/// [RFC 9110 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-5.1
#[test]
fn rfc9110_uncommon_standard_header_forwarded() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Accept-Patch: application/json\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(status, 200, "request with Accept-Patch should succeed");
    assert!(
        body.to_lowercase().contains("accept-patch: application/json"),
        "uncommon standard header Accept-Patch must be forwarded; echoed headers: {body}"
    );
}

// -----------------------------------------------------------------------------
// RFC 9110 Sections 8.8.3, 13.1, 13.2 - Conditional Header Passthrough
// -----------------------------------------------------------------------------

/// [RFC 9110 Section 13.1.2]: `If-None-Match` must be forwarded
/// transparently to upstream so the origin can evaluate it.
///
/// [RFC 9110 Section 13.1.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-13.1.2
#[test]
fn rfc9110_if_none_match_forwarded_to_upstream() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         If-None-Match: \"abc123\"\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(status, 200, "request with If-None-Match should succeed");
    assert!(
        body.to_lowercase().contains("if-none-match"),
        "If-None-Match must be forwarded to upstream; echoed headers: {body}"
    );
}

/// [RFC 9110 Section 13.1.3]: `If-Modified-Since` must be
/// forwarded transparently to upstream.
///
/// [RFC 9110 Section 13.1.3]: https://datatracker.ietf.org/doc/html/rfc9110#section-13.1.3
#[test]
fn rfc9110_if_modified_since_forwarded_to_upstream() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         If-Modified-Since: Sat, 01 Jan 2025 00:00:00 GMT\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(status, 200, "request with If-Modified-Since should succeed");
    assert!(
        body.to_lowercase().contains("if-modified-since"),
        "If-Modified-Since must be forwarded to upstream; echoed headers: {body}"
    );
}

/// [RFC 9110 Section 8.8.3]: `ETag` from upstream must be
/// forwarded to the client without modification.
///
/// [RFC 9110 Section 8.8.3]: https://datatracker.ietf.org/doc/html/rfc9110#section-8.8.3
#[test]
fn rfc9110_etag_forwarded_to_client() {
    let backend_port = start_etag_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let etag = parse_header(&raw, "etag");

    assert_eq!(status, 200, "response with ETag should succeed");
    assert_eq!(
        etag.as_deref(),
        Some("\"v1-abc\""),
        "ETag from upstream must be forwarded to client"
    );
}

/// [RFC 9110 Section 15.4.5]: when upstream returns 304 Not
/// Modified, the proxy must forward it to the client with the
/// correct status and headers (no body).
///
/// [RFC 9110 Section 15.4.5]: https://datatracker.ietf.org/doc/html/rfc9110#section-15.4.5
#[test]
fn rfc9110_304_not_modified_forwarded() {
    let backend_port = start_304_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         If-None-Match: \"v1-abc\"\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let etag = parse_header(&raw, "etag");

    assert_eq!(status, 304, "304 from upstream must be forwarded to client");
    assert_eq!(
        etag.as_deref(),
        Some("\"v1-abc\""),
        "304 response must include ETag header"
    );
}

// -----------------------------------------------------------------------------
// RFC 9110 Section 14.2 - Range Request Forwarding
// -----------------------------------------------------------------------------

/// [RFC 9110 Section 14.2]: the `Range` header must be forwarded
/// to upstream so the origin can serve partial content.
///
/// [RFC 9110 Section 14.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-14.2
#[test]
fn rfc9110_range_header_forwarded_to_upstream() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Range: bytes=0-99\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(status, 200, "request with Range header should succeed");
    assert!(
        body.to_lowercase().contains("range: bytes=0-99"),
        "Range header must be forwarded to upstream; echoed headers: {body}"
    );
}

/// [RFC 9110 Section 14.2]: a 206 Partial Content response from
/// upstream must be forwarded to the client with the
/// `Content-Range` header intact.
///
/// [RFC 9110 Section 14.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-14.2
#[test]
fn rfc9110_206_partial_content_forwarded() {
    let backend_port = start_range_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Range: bytes=0-4\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let content_range = parse_header(&raw, "content-range");
    let body = parse_body(&raw);

    assert_eq!(status, 206, "206 Partial Content must be forwarded from upstream");
    assert!(
        content_range.is_some_and(|cr| cr.contains("bytes 0-4")),
        "Content-Range header must be forwarded in 206 response"
    );
    assert_eq!(body, "hello", "partial body must match requested range");
}

// -----------------------------------------------------------------------------
// RFC 9110 Section 15.4 - Redirect Transparency
// -----------------------------------------------------------------------------

/// [RFC 9110 Section 15.4.2]: a 301 Moved Permanently from
/// upstream must be forwarded to the client (proxy must not
/// follow redirects).
///
/// [RFC 9110 Section 15.4.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-15.4.2
#[test]
fn rfc9110_301_redirect_forwarded() {
    let backend_port = start_redirect_backend(301);
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let location = parse_header(&raw, "location");

    assert_eq!(status, 301, "301 from upstream must be forwarded, not followed");
    assert_eq!(
        location.as_deref(),
        Some("https://example.com/new"),
        "Location header must be forwarded in 301 response"
    );
}

/// [RFC 9110 Section 15.4.3]: a 302 Found from upstream must
/// be forwarded to the client.
///
/// [RFC 9110 Section 15.4.3]: https://datatracker.ietf.org/doc/html/rfc9110#section-15.4.3
#[test]
fn rfc9110_302_redirect_forwarded() {
    let backend_port = start_redirect_backend(302);
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let location = parse_header(&raw, "location");

    assert_eq!(status, 302, "302 from upstream must be forwarded, not followed");
    assert_eq!(
        location.as_deref(),
        Some("https://example.com/new"),
        "Location header must be forwarded in 302 response"
    );
}

/// [RFC 9110 Section 15.4.8]: a 307 Temporary Redirect from
/// upstream must be forwarded to the client.
///
/// [RFC 9110 Section 15.4.8]: https://datatracker.ietf.org/doc/html/rfc9110#section-15.4.8
#[test]
fn rfc9110_307_redirect_forwarded() {
    let backend_port = start_redirect_backend(307);
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let location = parse_header(&raw, "location");

    assert_eq!(status, 307, "307 from upstream must be forwarded, not followed");
    assert_eq!(
        location.as_deref(),
        Some("https://example.com/new"),
        "Location header must be forwarded in 307 response"
    );
}

/// [RFC 9110 Section 15.4.9]: a 308 Permanent Redirect from
/// upstream must be forwarded to the client.
///
/// [RFC 9110 Section 15.4.9]: https://datatracker.ietf.org/doc/html/rfc9110#section-15.4.9
#[test]
fn rfc9110_308_redirect_forwarded() {
    let backend_port = start_redirect_backend(308);
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let location = parse_header(&raw, "location");

    assert_eq!(status, 308, "308 from upstream must be forwarded, not followed");
    assert_eq!(
        location.as_deref(),
        Some("https://example.com/new"),
        "Location header must be forwarded in 308 response"
    );
}

// -----------------------------------------------------------------------------
// RFC 9110 Section 7.6.3 - Via Header
// -----------------------------------------------------------------------------

/// [RFC 9110 Section 7.6.3]: the proxy SHOULD add a `Via` header
/// to forwarded requests indicating the protocol version and proxy pseudonym.
///
/// [RFC 9110 Section 7.6.3]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.3
#[test]
fn rfc9110_via_header_added_to_request() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(status, 200, "request should succeed");
    assert!(
        body.to_lowercase().contains("via: 1.1 praxis"),
        "request Via header must contain '1.1 praxis'; echoed headers: {body}"
    );
}

/// [RFC 9110 Section 7.6.3]: the proxy SHOULD add a `Via` header
/// to the response sent to the client.
///
/// [RFC 9110 Section 7.6.3]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.3
#[test]
fn rfc9110_via_header_added_to_response() {
    let backend_port = start_backend("via-test");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let via = parse_header(&raw, "via");

    assert_eq!(status, 200, "response should succeed");
    assert!(
        via.is_some_and(|v| v.contains("1.1 praxis")),
        "response Via header must contain '1.1 praxis'"
    );
}

/// [RFC 9110 Section 7.6.3]: when a downstream proxy has already
/// set a Via header, this proxy MUST append its entry rather than
/// replacing the existing value.
///
/// [RFC 9110 Section 7.6.3]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.3
#[test]
fn rfc9110_via_header_appended_not_replaced() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Via: 1.0 downstream\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(status, 200, "request should succeed");
    assert!(
        body.to_lowercase().contains("1.0 downstream") && body.to_lowercase().contains("1.1 praxis"),
        "existing Via must be preserved and new entry appended; echoed headers: {body}"
    );
}

/// [RFC 9110 Section 7.6.3]: an H2 client should see `2.0 praxis`
/// in the response Via header, reflecting the downstream protocol.
///
/// [RFC 9110 Section 7.6.3]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.3
#[test]
fn rfc9110_via_header_h2_client_gets_2_0() {
    let backend_port = start_backend("via-h2-test");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    wait_for_http2(proxy.addr());

    let (response, _body) = h2c_get(proxy.addr(), "/");
    let via = response.headers().get("via").and_then(|v| v.to_str().ok());

    assert!(
        via.is_some_and(|v| v.contains("2.0 praxis")),
        "H2 client response Via should contain '2.0 praxis', got: {via:?}"
    );
}

// -----------------------------------------------------------------------------
// RFC 9110 Section 7.6.2 - Max-Forwards
// -----------------------------------------------------------------------------

/// [RFC 9110 Section 7.6.2]: for OPTIONS with `Max-Forwards: 1`,
/// the proxy MUST decrement it and forward with `Max-Forwards: 0`.
///
/// [RFC 9110 Section 7.6.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.2
#[test]
fn rfc9110_max_forwards_decremented_on_options() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Max-Forwards: 1\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(status, 200, "OPTIONS with Max-Forwards: 1 should be forwarded");
    assert!(
        body.to_lowercase().contains("max-forwards: 0"),
        "Max-Forwards must be decremented to 0; echoed headers: {body}"
    );
}

/// [RFC 9110 Section 7.6.2]: for TRACE with `Max-Forwards: 0`,
/// the proxy MUST NOT forward the request and should respond
/// directly with a 200.
///
/// [RFC 9110 Section 7.6.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.2
#[test]
fn rfc9110_max_forwards_zero_trace_returns_200() {
    let backend_port = start_backend("should-not-reach");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "TRACE / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Max-Forwards: 0\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);

    assert_eq!(
        status, 200,
        "TRACE with Max-Forwards: 0 must return 200 from proxy itself"
    );
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    assert!(
        body.contains("TRACE") && body_lower.contains("host:"),
        "TRACE response body should echo the request message; got: {body}"
    );
}

/// [RFC 9110 Section 7.6.2]: requests without Max-Forwards should
/// be forwarded normally (Max-Forwards only applies when present).
///
/// [RFC 9110 Section 7.6.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.2
#[test]
fn rfc9110_no_max_forwards_forwarded_normally() {
    let backend_port = start_backend("normal-forward");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(status, 200, "OPTIONS without Max-Forwards should be forwarded normally");
    assert_eq!(
        body, "normal-forward",
        "response body should come from upstream backend"
    );
}

// -----------------------------------------------------------------------------
// RFC 9110 Section 10.1.4 - TE Header Hop-by-Hop
// -----------------------------------------------------------------------------

/// [RFC 9110 Section 10.1.4]: TE header is hop-by-hop. Values other
/// than "trailers" must be stripped before forwarding to upstream.
///
/// [RFC 9110 Section 10.1.4]: https://datatracker.ietf.org/doc/html/rfc9110#section-10.1.4
#[test]
fn rfc9110_te_header_stripped_from_upstream_request() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         TE: gzip, chunked\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(status, 200, "request with TE header should succeed");
    assert!(
        !body.to_lowercase().contains("te: gzip"),
        "TE header with non-trailers values must be stripped before upstream; echoed headers: {body}"
    );
}

// -----------------------------------------------------------------------------
// RFC 9110 Section 15.2 - 1xx Interim Responses
// -----------------------------------------------------------------------------

/// [RFC 9110 Section 15.2]: proxy must forward 1xx responses.
/// Verifies 100-continue negotiation completes end-to-end
/// and the full request body is received by the backend.
///
/// [RFC 9110 Section 15.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-15.2
#[test]
fn rfc9110_100_continue_allows_body_upload() {
    let backend_port = start_backend("upload-ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body_data = "test-payload-data";
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\n\
             Host: localhost\r\n\
             Expect: 100-continue\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body_data}",
            body_data.len()
        ),
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(
        status, 200,
        "POST with Expect: 100-continue must complete successfully (got {status})"
    );
    assert_eq!(
        body, "upload-ok",
        "response body from backend must be forwarded after 100-continue negotiation"
    );
}

// -----------------------------------------------------------------------------
// RFC 9110 Section 7.6.2 - Max-Forwards on Non-TRACE/OPTIONS
// -----------------------------------------------------------------------------

/// [RFC 9110 Section 7.6.2]: Max-Forwards only applies to TRACE
/// and OPTIONS. A GET with Max-Forwards: 0 must be forwarded
/// normally to the upstream.
///
/// [RFC 9110 Section 7.6.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.2
#[test]
fn rfc9110_max_forwards_ignored_on_get() {
    let backend_port = start_backend("max-fwd-get");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Max-Forwards: 0\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(
        status, 200,
        "GET with Max-Forwards: 0 must be forwarded normally, not intercepted (got {status})"
    );
    assert_eq!(
        body, "max-fwd-get",
        "GET with Max-Forwards: 0 must reach the upstream backend"
    );
}

// -----------------------------------------------------------------------------
// RFC 9110 Section 7.6.1 - Multiple Connection Headers
// -----------------------------------------------------------------------------

/// [RFC 9110 Section 7.6.1]: when multiple Connection headers are
/// present, all listed tokens must be treated as hop-by-hop and
/// stripped before forwarding to upstream.
///
/// [RFC 9110 Section 7.6.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.1
#[test]
fn rfc9110_multiple_connection_headers_all_tokens_stripped() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close, X-Custom1\r\n\
         Connection: X-Custom2\r\n\
         X-Custom1: val1\r\n\
         X-Custom2: val2\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert_eq!(status, 200, "request with multiple Connection headers should succeed");
    assert!(
        !body_lower.contains("x-custom1"),
        "X-Custom1 listed in Connection must be stripped; echoed headers: {body}"
    );
    assert!(
        !body_lower.contains("x-custom2"),
        "X-Custom2 listed in second Connection header must also be stripped; echoed headers: {body}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Wrapper for [`praxis_test_utils::start_proxy`] used across
/// RFC 9110 tests.
fn start_proxy(config: &Config) -> praxis_test_utils::ProxyGuard {
    praxis_test_utils::start_proxy(config)
}
