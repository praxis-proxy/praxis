// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Request smuggling hardening tests.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, parse_body, parse_status, simple_proxy_yaml, start_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests - Host Header Validation
// -----------------------------------------------------------------------------

#[test]
fn conflicting_host_headers_rejected() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: victim.example.com\r\n\
         Host: attacker.example.com\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);

    assert_eq!(
        status, 400,
        "conflicting Host headers must be rejected with 400 (got {status})"
    );
}

#[test]
fn duplicate_identical_host_headers_accepted() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(
        status, 200,
        "duplicate identical Host headers should be accepted (got {status})"
    );
    assert_eq!(body, "ok", "backend should receive the request normally");
}

/// [RFC 9112 Section 3.2]: HTTP/1.1 requests without a Host
/// header must be rejected with 400.
///
/// [RFC 9112 Section 3.2]: https://datatracker.ietf.org/doc/html/rfc9112#section-3.2
#[test]
fn missing_host_header_http11_rejected() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);

    assert_eq!(
        status, 400,
        "HTTP/1.1 request without Host must be rejected with 400 (got {status})"
    );
}

#[test]
fn host_with_port_vs_without_port_considered_different() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: example.com\r\n\
         Host: example.com:8080\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);

    assert_eq!(
        status, 400,
        "Host with and without port are different values; must reject (got {status})"
    );
}

// -----------------------------------------------------------------------------
// Tests - CL-TE Desync Protection
// -----------------------------------------------------------------------------

#[test]
fn cl_te_desync_does_not_poison_connection() {
    let backend_port = start_backend("clean");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    use std::io::{Read as _, Write as _};
    let mut stream = std::net::TcpStream::connect(proxy.addr()).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();

    let ambiguous = "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Transfer-Encoding: chunked\r\n\
         Content-Length: 999\r\n\
         \r\n\
         5\r\n\
         hello\r\n\
         0\r\n\
         \r\n";
    stream.write_all(ambiguous.as_bytes()).unwrap();

    let mut first_response = vec![0_u8; 8192];
    let n = stream.read(&mut first_response).unwrap_or(0);
    let first_raw = String::from_utf8_lossy(&first_response[..n]);
    let first_status = parse_status(&first_raw);

    assert!(
        first_status == 200 || first_status == 400,
        "ambiguous request should get 200 or 400, got {first_status}"
    );

    let normal = "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n";
    let write_result = stream.write_all(normal.as_bytes());

    if write_result.is_ok() {
        let mut second_response = String::new();
        let _bytes = stream.read_to_string(&mut second_response);
        let second_status = parse_status(&second_response);

        if second_status > 0 {
            assert!(
                second_status == 200 || second_status == 400,
                "follow-up request must not return smuggled data (got {second_status})"
            );
        }
    }
}

// -----------------------------------------------------------------------------
// Tests - Transfer-Encoding Edge Cases
// -----------------------------------------------------------------------------

/// Transfer-Encoding value matching must be case-insensitive
/// per [RFC 9112]. "Chunked" (capital C) should work.
///
/// [RFC 9112]: https://datatracker.ietf.org/doc/html/rfc9112
#[test]
fn te_chunked_case_insensitive() {
    let backend_port = start_backend("chunked-ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Transfer-Encoding: Chunked\r\n\
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
        "Transfer-Encoding: Chunked (capital C) must be accepted (got {status})"
    );
}

#[test]
fn te_with_whitespace_padding() {
    let backend_port = start_backend("ws-ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Transfer-Encoding:  chunked \r\n\
         Connection: close\r\n\
         \r\n\
         5\r\n\
         hello\r\n\
         0\r\n\
         \r\n",
    );
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 400,
        "TE with whitespace padding should be accepted or cleanly rejected (got {status})"
    );
}

// -----------------------------------------------------------------------------
// Tests - Content-Length Edge Cases
// -----------------------------------------------------------------------------

#[test]
fn cl_with_leading_zeros() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 005\r\n\
         Connection: close\r\n\
         \r\n\
         hello",
    );
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 400,
        "CL with leading zeros should be accepted or rejected, not crash (got {status})"
    );
}

/// Negative Content-Length must be rejected. This is
/// malformed per [RFC 9110 Section 8.6].
///
/// [RFC 9110 Section 8.6]: https://datatracker.ietf.org/doc/html/rfc9110#section-8.6
#[test]
fn negative_content_length_rejected() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: -1\r\n\
         Connection: close\r\n\
         \r\n",
    );
    let status = parse_status(&raw);

    assert!(
        status == 400 || status == 0,
        "negative Content-Length must be rejected or connection closed (got {status})"
    );
}

#[test]
fn content_length_overflow_rejected() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 99999999999999999999\r\n\
         Connection: close\r\n\
         \r\n",
    );
    let status = parse_status(&raw);

    assert!(
        status == 400 || status == 0,
        "Content-Length overflow must be rejected or connection closed (got {status})"
    );
}

/// Empty Transfer-Encoding value must be rejected. An empty
/// TE is invalid per [RFC 9112].
///
/// [RFC 9112]: https://datatracker.ietf.org/doc/html/rfc9112
#[test]
fn empty_transfer_encoding_rejected() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Transfer-Encoding: \r\n\
         Connection: close\r\n\
         \r\n",
    );
    let status = parse_status(&raw);

    assert_eq!(
        status, 400,
        "empty Transfer-Encoding must be rejected with 400, got {status}"
    );
}
