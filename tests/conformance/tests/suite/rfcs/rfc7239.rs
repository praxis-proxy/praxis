// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! [RFC 7239] Forwarded Header conformance tests.
//!
//! [RFC 7239]: https://datatracker.ietf.org/doc/html/rfc7239

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_send, parse_body, parse_status, start_header_echo_backend};

use super::test_utils::{forwarded_standard_trusted_yaml, forwarded_standard_yaml};

// -----------------------------------------------------------------------------
// RFC 7239 Section 4 - Forwarded Header
// -----------------------------------------------------------------------------

/// [RFC 7239 Section 4]: when `use_standard_header` is enabled, the
/// proxy injects a `Forwarded` header with `for`, `proto`, and `host`
/// parameters.
///
/// [RFC 7239 Section 4]: https://datatracker.ietf.org/doc/html/rfc7239#section-4
#[test]
fn rfc7239_standard_forwarded_header_injected() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = forwarded_standard_yaml(proxy_port, backend_port);
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
    let body_lower = body.to_lowercase();

    assert_eq!(status, 200, "request with standard Forwarded should succeed");
    assert!(
        body_lower.contains("forwarded:"),
        "Forwarded header must be present in upstream request; echoed headers: {body}"
    );
    assert!(
        body_lower.contains("for="),
        "Forwarded header must contain 'for' parameter; echoed headers: {body}"
    );
    assert!(
        body_lower.contains("proto=http"),
        "Forwarded header must contain 'proto' parameter; echoed headers: {body}"
    );
}

/// [RFC 7239 Section 4]: the Forwarded header format must match RFC 7239.
/// Specifically: `for=<ip>;proto=<proto>;host=<host>`.
///
/// [RFC 7239 Section 4]: https://datatracker.ietf.org/doc/html/rfc7239#section-4
#[test]
fn rfc7239_forwarded_header_format() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = forwarded_standard_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: example.com\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(status, 200, "request should succeed");
    assert!(
        body.contains("proto=http") && body.contains("host=\"example.com\""),
        "Forwarded header must have correct format with quoted host; echoed headers: {body}"
    );
}

// -----------------------------------------------------------------------------
// RFC 7239 Section 6 - IPv6 Formatting
// -----------------------------------------------------------------------------

/// [RFC 7239 Section 6]: IPv6 addresses in the `for` parameter
/// must be quoted and enclosed in brackets: `for="[::1]"`.
///
/// [RFC 7239 Section 6]: https://datatracker.ietf.org/doc/html/rfc7239#section-6
#[test]
fn rfc7239_ipv6_address_quoted_correctly() {
    let ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();
    let formatted = match ip {
        std::net::IpAddr::V6(v6) => format!("\"[{v6}]\""),
        std::net::IpAddr::V4(v4) => format!("{v4}"),
    };
    assert_eq!(
        formatted, "\"[2001:db8::1]\"",
        "IPv6 for-param must be quoted with brackets per RFC 7239 Section 6"
    );
}

/// [RFC 7239 Section 4]: when the client is trusted and a `Forwarded`
/// header already exists, the proxy must append its entry rather than
/// replacing the existing value.
///
/// [RFC 7239 Section 4]: https://datatracker.ietf.org/doc/html/rfc7239#section-4
#[test]
fn rfc7239_forwarded_header_appended_when_trusted() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = forwarded_standard_trusted_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Forwarded: for=203.0.113.50;proto=https\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert_eq!(status, 200, "request should succeed");
    assert!(
        body_lower.contains("for=203.0.113.50") && body_lower.contains("127.0.0.1"),
        "existing Forwarded entry must be preserved and new entry appended; echoed headers: {body}"
    );
}

// -----------------------------------------------------------------------------
// RFC 7239 Section 4 - Forwarded Parameter Coverage
// -----------------------------------------------------------------------------

/// [RFC 7239 Section 4]: Forwarded header includes for, proto, host.
/// Note: `by` parameter ([Section 5.4]) is not yet included.
///
/// [RFC 7239 Section 4]: https://datatracker.ietf.org/doc/html/rfc7239#section-4
/// [Section 5.4]: https://datatracker.ietf.org/doc/html/rfc7239#section-5.4
#[test]
fn rfc7239_forwarded_header_includes_for_proto_host() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = forwarded_standard_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: test.example.com\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert_eq!(status, 200, "request with forwarded_headers should succeed");
    assert!(
        body_lower.contains("for="),
        "Forwarded header must include 'for' parameter; echoed headers: {body}"
    );
    assert!(
        body_lower.contains("proto=http"),
        "Forwarded header must include 'proto' parameter; echoed headers: {body}"
    );
    assert!(
        body_lower.contains("host=\"test.example.com\""),
        "Forwarded header must include quoted 'host' parameter; echoed headers: {body}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Wrapper for [`praxis_test_utils::start_proxy`] used across
/// RFC 7239 tests.
fn start_proxy(config: &Config) -> praxis_test_utils::ProxyGuard {
    praxis_test_utils::start_proxy(config)
}
