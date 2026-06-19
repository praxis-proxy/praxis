// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! [RFC 6265] HTTP State Management (Cookie) conformance tests.
//!
//! [RFC 6265]: https://datatracker.ietf.org/doc/html/rfc6265

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, parse_header, parse_header_all, parse_status, simple_proxy_yaml, start_proxy,
};

use super::test_utils::{start_multi_set_cookie_backend, start_set_cookie_with_attributes_backend};

// -----------------------------------------------------------------------------
// RFC 6265 Section 3 - Set-Cookie Preservation
// -----------------------------------------------------------------------------

/// [RFC 6265 Section 3]: multiple `Set-Cookie` headers from
/// upstream MUST NOT be folded into one. Each must remain as
/// a separate header line.
///
/// [RFC 6265 Section 3]: https://datatracker.ietf.org/doc/html/rfc6265#section-3
#[test]
fn rfc6265_multiple_set_cookie_headers_not_folded() {
    let backend_port = start_multi_set_cookie_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let cookies = parse_header_all(&raw, "set-cookie");

    assert_eq!(status, 200, "response with Set-Cookie headers should succeed");
    assert!(
        cookies.len() >= 2,
        "multiple Set-Cookie headers must remain separate (not folded); found {}: {cookies:?}",
        cookies.len()
    );
    assert!(
        cookies.iter().any(|c| c.contains("session=abc123")),
        "session cookie must be present in Set-Cookie headers: {cookies:?}"
    );
    assert!(
        cookies.iter().any(|c| c.contains("theme=dark")),
        "theme cookie must be present in Set-Cookie headers: {cookies:?}"
    );
}

/// [RFC 6265 Section 3]: a single `Set-Cookie` with special
/// characters must be forwarded intact.
///
/// [RFC 6265 Section 3]: https://datatracker.ietf.org/doc/html/rfc6265#section-3
#[test]
fn rfc6265_set_cookie_with_attributes_forwarded() {
    let backend_port = start_set_cookie_with_attributes_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let cookie = parse_header(&raw, "set-cookie");

    assert_eq!(status, 200, "response with Set-Cookie should succeed");
    assert!(
        cookie.is_some_and(|c| c.contains("session=abc123") && c.contains("HttpOnly")),
        "Set-Cookie with attributes must be forwarded intact"
    );
}
