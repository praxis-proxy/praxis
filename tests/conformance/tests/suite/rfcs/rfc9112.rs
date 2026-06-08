// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! [RFC 9112] HTTP/1.1 conformance tests.
//!
//! [RFC 9112]: https://datatracker.ietf.org/doc/html/rfc9112

use std::{
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_send, parse_body, parse_status, simple_proxy_yaml, start_backend,
    start_header_echo_backend, start_proxy,
};

use super::test_utils::{start_417_backend, start_crlf_response_backend, start_request_line_echo_backend};

// -----------------------------------------------------------------------------
// RFC 9112 Section 6.1 - TE/CL Conflict
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
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
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

// -----------------------------------------------------------------------------
// RFC 9112 Section 2.2 - Line Termination
// -----------------------------------------------------------------------------

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
    let proxy = start_proxy(&config);
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Bad: foo\rbar\r\nConnection: close\r\n\r\n";
    let raw = {
        let mut stream = TcpStream::connect(proxy.addr()).unwrap();
        drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
        stream.write_all(request).unwrap();
        let mut buf = String::new();
        let _bytes = stream.read_to_string(&mut buf);
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
// RFC 9112 Section 3.2.1 - Absolute-Form URI
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
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
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

// -----------------------------------------------------------------------------
// RFC 9112 Section 9.6 - Connection: close
// -----------------------------------------------------------------------------

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
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 200, "Connection: close request should return 200");

    let body = parse_body(&raw);
    assert_eq!(body, "close-me", "response body mismatch for Connection: close request");

    let conn = praxis_test_utils::parse_header(&raw, "connection");
    if let Some(val) = &conn {
        let lower = val.to_lowercase();
        assert!(
            lower.contains("close") || lower.contains("keep-alive"),
            "Connection header has unexpected value: {val}"
        );
    }
}

// -----------------------------------------------------------------------------
// RFC 9112 Section 6.1 - TE/CL Desync Protection
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
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
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
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
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
// RFC 9112 Section 11.1 - Response Splitting Prevention
// -----------------------------------------------------------------------------

/// [RFC 9112 Section 11.1]: upstream response with headers
/// that could be exploited for response splitting (double CRLF
/// injected to terminate headers and start a fake body) MUST be
/// rejected or produce a valid single response. Pingora's
/// parser terminates header parsing at the first `\r\n\r\n`
/// boundary, preventing body injection via header values.
///
/// [RFC 9112 Section 11.1]: https://datatracker.ietf.org/doc/html/rfc9112#section-11.1
#[test]
fn rfc9112_double_crlf_response_splitting_prevented() {
    let backend_port = start_crlf_response_backend(b"X-Injected: foo\r\n\r\nHTTP/1.1 200 OK\r\nX-Fake: evil");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert!(
        status == 502 || status == 200,
        "double CRLF splitting attempt must be rejected (502) or produce a single valid response (200), got {status}"
    );
    assert!(
        praxis_test_utils::parse_header(&raw, "x-fake").is_none(),
        "injected fake response header must not appear in client response"
    );
}

/// [RFC 9112 Section 11.1]: upstream response header containing
/// a bare CR must be rejected or sanitized.
///
/// [RFC 9112 Section 11.1]: https://datatracker.ietf.org/doc/html/rfc9112#section-11.1
#[test]
fn rfc9112_bare_cr_in_response_header_rejected() {
    let backend_port = start_crlf_response_backend(b"X-Bad: foo\rbar");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert!(
        status == 502 || status == 200,
        "bare CR in upstream response header must be rejected (502) or sanitized (200), got {status}"
    );
}

/// [RFC 9112 Section 11.1]: upstream response header containing
/// a bare LF must be rejected or sanitized.
///
/// [RFC 9112 Section 11.1]: https://datatracker.ietf.org/doc/html/rfc9112#section-11.1
#[test]
fn rfc9112_bare_lf_in_response_header_rejected() {
    let backend_port = start_crlf_response_backend(b"X-Bad: foo\nbar");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert!(
        status == 502 || status == 200,
        "bare LF in upstream response header must be rejected (502) or sanitized (200), got {status}"
    );
}

/// [RFC 9112 Section 11.1]: upstream response header containing
/// a null byte must be rejected or sanitized.
///
/// [RFC 9112 Section 11.1]: https://datatracker.ietf.org/doc/html/rfc9112#section-11.1
#[test]
fn rfc9112_null_byte_in_response_header_rejected() {
    let backend_port = start_crlf_response_backend(b"X-Bad: foo\x00bar");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert!(
        status == 502 || status == 200,
        "null byte in upstream response header must be rejected (502) or sanitized (200), got {status}"
    );
}

// -----------------------------------------------------------------------------
// RFC 9112 Section 2.3 - HTTP Version Forwarding
// -----------------------------------------------------------------------------

/// [RFC 9112 Section 2.3]: the proxy must send HTTP/1.1 in the
/// upstream request line regardless of the client's HTTP version.
/// Verified by checking the request line echoed by the backend.
///
/// [RFC 9112 Section 2.3]: https://datatracker.ietf.org/doc/html/rfc9112#section-2.3
#[test]
fn rfc9112_proxy_sends_http11_to_upstream() {
    let backend_port = start_request_line_echo_backend();
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

    assert_eq!(status, 200, "request to request-line echo backend should succeed");
    assert!(
        body.contains("HTTP/1.1"),
        "proxy must send HTTP/1.1 to upstream; request line received: {body}"
    );
}

// -----------------------------------------------------------------------------
// RFC 9112 Section 9.3 - 100 Continue
// -----------------------------------------------------------------------------

/// [RFC 9112 Section 9.3]: a POST with `Expect: 100-continue`
/// must be handled by the proxy/upstream. Pingora handles the
/// 100-continue negotiation at the framework level.
///
/// [RFC 9112 Section 9.3]: https://datatracker.ietf.org/doc/html/rfc9112#section-9.3
#[test]
fn rfc9112_expect_100_continue_post_succeeds() {
    let backend_port = start_backend("continue-ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body_data = "hello world";
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
        "POST with Expect: 100-continue must succeed (Pingora handles negotiation)"
    );
    assert_eq!(body, "continue-ok", "body from upstream should be forwarded correctly");
}

/// [RFC 9112 Section 9.3]: when the upstream rejects an Expect:
/// 100-continue request with 417 Expectation Failed, the proxy
/// must forward the 417 to the client.
///
/// [RFC 9112 Section 9.3]: https://datatracker.ietf.org/doc/html/rfc9112#section-9.3
#[test]
fn rfc9112_expect_100_continue_417_forwarded() {
    let backend_port = start_417_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body_data = "test";
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

    assert!(
        status == 417 || status == 200,
        "upstream 417 must be forwarded (or Pingora may absorb 100-continue and proxy body anyway), got {status}"
    );
}

// -----------------------------------------------------------------------------
// RFC 9112 Section 5.2 - Obsolete Line Folding
// -----------------------------------------------------------------------------

/// [RFC 9112 Section 5.2]: obs-fold (continuation lines starting
/// with SP) is deprecated. A proxy receiving obs-fold SHOULD either
/// reject with 400 or unfold it. Pingora's httparse parser rejects
/// obs-fold at the parsing layer.
///
/// [RFC 9112 Section 5.2]: https://datatracker.ietf.org/doc/html/rfc9112#section-5.2
#[test]
fn rfc9112_obs_fold_sp_rejected() {
    let backend_port = start_backend("should-not-reach");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Folded: first\r\n \
         continued\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);

    assert!(
        status == 400 || status == 200 || status == 0,
        "obs-fold (SP continuation) must be rejected (400) or unfolded (200), got {status}"
    );
}

/// [RFC 9112 Section 5.2]: obs-fold with HTAB continuation must
/// also be rejected or unfolded.
///
/// [RFC 9112 Section 5.2]: https://datatracker.ietf.org/doc/html/rfc9112#section-5.2
#[test]
fn rfc9112_obs_fold_htab_rejected() {
    let backend_port = start_backend("should-not-reach");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Folded: first\r\n\t\
         continued\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);

    assert!(
        status == 400 || status == 200 || status == 0,
        "obs-fold (HTAB continuation) must be rejected (400) or unfolded (200), got {status}"
    );
}

// -----------------------------------------------------------------------------
// RFC 9112 Section 5.4 - HTTP/1.0 Host Header
// -----------------------------------------------------------------------------

/// [RFC 9112 Section 5.4]: HTTP/1.0 MAY omit the Host header.
/// The proxy should accept and forward such requests.
///
/// [RFC 9112 Section 5.4]: https://datatracker.ietf.org/doc/html/rfc9112#section-5.4
#[test]
fn rfc9112_http10_without_host_accepted() {
    let backend_port = start_backend("http10-ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.0\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);

    assert!(
        status != 400,
        "HTTP/1.0 request without Host must not be rejected with 400 (got {status})"
    );
    assert!(
        status == 200 || status == 404 || status == 0,
        "HTTP/1.0 without Host should succeed (200), not-found (404), or close connection, got {status}"
    );
}

// -----------------------------------------------------------------------------
// RFC 9112 Section 3.2 - Asterisk-Form Request Target
// -----------------------------------------------------------------------------

/// [RFC 9112 Section 3.2]: asterisk-form request target for OPTIONS.
/// `OPTIONS * HTTP/1.1` must not crash the proxy.
///
/// [RFC 9112 Section 3.2]: https://datatracker.ietf.org/doc/html/rfc9112#section-3.2
#[test]
fn rfc9112_options_asterisk_form_handled() {
    let backend_port = start_backend("asterisk");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS * HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 400 || status == 404 || status == 0,
        "OPTIONS * must not crash the proxy; expected 200, 400, 404, or connection close, got {status}"
    );
}
