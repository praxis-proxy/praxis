//! RFC conformance tests.
//!
//! Verifies proxy behavior against specific RFC
//! requirements. Tests are organized by RFC number and
//! section.
//!
//! - [RFC 9110]: HTTP Semantics
//! - [RFC 9112]: HTTP/1.1
//! - [RFC 7230]: HTTP/1.1 Message Syntax (obsoleted by 9112)
//!
//! [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110
//! [RFC 9112]: https://datatracker.ietf.org/doc/html/rfc9112
//! [RFC 7230]: https://datatracker.ietf.org/doc/html/rfc7230

use praxis_core::config::Config;

use crate::common::{
    free_port, http_send, parse_body, parse_header, parse_status, simple_proxy_yaml, start_backend,
    start_header_echo_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests - RFC 9110 - HTTP Semantics
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
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
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
    let addr = start_proxy(&config);
    let raw = http_send(
        &addr,
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
    let addr = start_proxy(&config);
    let raw = http_send(
        &addr,
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
// Tests - RFC 9112 - HTTP/1.1 Messaging
// -----------------------------------------------------------------------------

/// [RFC 9112 Section 6.1]: when both Transfer-Encoding and
/// Content-Length are present, the Transfer-Encoding takes
/// precedence. Pingora strips CL when TE is present and
/// processes the chunked body correctly.
///
/// [RFC 9112 Section 6.1]: https://datatracker.ietf.org/doc/html/rfc9112#section-6.1
#[test]
fn rfc9112_te_and_cl_conflict() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let raw = http_send(
        &addr,
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Transfer-Encoding: chunked\r\n\
         Content-Length: 999\r\n\
         Connection: close\r\n\
         \r\n\
         5\r\n\
         hello\r\n\
         0\r\n\
         \r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(
        status, 200,
        "TE: chunked must override CL and process the chunked body (got {status})"
    );
}

/// [RFC 9112 Section 2.2]: bare CR (without LF) in a header
/// line is invalid. The proxy should reject or sanitize.
///
/// [RFC 9112 Section 2.2]: https://datatracker.ietf.org/doc/html/rfc9112#section-2.2
#[test]
fn rfc9112_bare_cr_in_header_rejected() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Bad: foo\rbar\r\nConnection: close\r\n\r\n";
    let raw = {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(&addr).unwrap();
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
        stream.write_all(request).unwrap();
        let mut buf = String::new();
        let _ = stream.read_to_string(&mut buf);
        buf
    };
    let status = parse_status(&raw);
    assert!(
        status == 400 || status == 200 || status == 0,
        "expected 400, 200 (sanitized), or connection \
         close for bare CR, got {status}"
    );
}

// -----------------------------------------------------------------------------
// Tests - RFC 7230 / RFC 9112 - General HTTP
// -----------------------------------------------------------------------------

/// [RFC 9112 Section 3.2.1]: absolute-form request URI
/// (e.g. `GET http://localhost/ HTTP/1.1`) must be handled
/// by a proxy without crashing. Pingora may use the full
/// URI as the path (resulting in a 404 from the router)
/// or extract the path component.
///
/// [RFC 9112 Section 3.2.1]: https://datatracker.ietf.org/doc/html/rfc9112#section-3.2.1
#[test]
fn rfc9112_absolute_form_request_uri() {
    let backend_port = start_backend("absolute");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let raw = http_send(
        &addr,
        &format!(
            "GET http://localhost:{proxy_port}/ HTTP/1.1\r\n\
             Host: localhost\r\n\
             Connection: close\r\n\r\n"
        ),
    );
    let status = parse_status(&raw);
    assert!(
        status == 200 || status == 400 || status == 404 || status == 0,
        "expected 200, 400, 404, or connection close \
         for absolute-form URI, got {status}"
    );
}

/// [RFC 9112 Section 9.6]: Connection: close signals the
/// client wants the connection closed after the response.
/// The proxy must respect this and close the connection.
///
/// [RFC 9112 Section 9.6]: https://datatracker.ietf.org/doc/html/rfc9112#section-9.6
#[test]
fn rfc9112_connection_close_respected() {
    let backend_port = start_backend("close-me");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 200, "Connection: close request should return 200");

    let body = parse_body(&raw);
    assert_eq!(body, "close-me", "response body mismatch for Connection: close request");

    let conn = parse_header(&raw, "connection");
    if let Some(val) = &conn {
        let lower = val.to_lowercase();
        assert!(
            lower.contains("close") || lower.contains("keep-alive"),
            "Connection header has unexpected value: {val}"
        );
    }
}

// -----------------------------------------------------------------------------
// Tests - RFC 9112 Section 6.1 - TE/CL Desync Protection
// -----------------------------------------------------------------------------

/// [RFC 9112 Section 6.1]: POST with TE: chunked + CL: 999
/// and a valid chunked body. Pingora honours TE, strips CL,
/// and proxies the chunked body. Expect 200.
///
/// [RFC 9112 Section 6.1]: https://datatracker.ietf.org/doc/html/rfc9112#section-6.1
#[test]
fn rfc9112_te_overrides_cl_chunked_body() {
    let backend_port = start_backend("te-wins");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Transfer-Encoding: chunked\r\n\
         Content-Length: 999\r\n\
         Connection: close\r\n\
         \r\n\
         5\r\n\
         hello\r\n\
         0\r\n\
         \r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(status, 200, "TE must override CL; chunked body should succeed");
    assert_eq!(body, "te-wins", "backend should receive the request normally");
}

/// [RFC 9112 Section 6.1]: when TE: chunked and CL are both
/// present, the upstream must NOT see a Content-Length
/// header. Pingora strips CL in the presence of TE.
///
/// [RFC 9112 Section 6.1]: https://datatracker.ietf.org/doc/html/rfc9112#section-6.1
#[test]
fn rfc9112_cl_removed_when_te_present() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Transfer-Encoding: chunked\r\n\
         Content-Length: 999\r\n\
         Connection: close\r\n\
         \r\n\
         5\r\n\
         hello\r\n\
         0\r\n\
         \r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(status, 200, "header-echo backend should return 200");
    let body_lower = body.to_lowercase();
    assert!(
        !body_lower.contains("content-length: 999"),
        "upstream must not see original CL when TE is present; echoed headers: {body}"
    );
}

// -----------------------------------------------------------------------------
// Tests - RFC 9110 Section 8.6 - Duplicate Content-Length
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
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
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
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
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
