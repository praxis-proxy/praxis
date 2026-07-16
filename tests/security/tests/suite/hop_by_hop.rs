// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Hop-by-hop header injection adversarial tests.
//!
//! Verifies that the proxy strips Connection-nominated headers
//! from upstream requests and hop-by-hop headers from downstream
//! responses, preventing header smuggling attacks.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, parse_body, parse_header, parse_status, simple_proxy_yaml, start_header_echo_backend,
    start_hop_by_hop_response_backend, start_proxy,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn connection_nominated_header_stripped_from_request() {
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
         Connection: X-Auth-Token, close\r\n\
         X-Auth-Token: secret-credential\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 200, "request should succeed");

    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    assert!(
        !body_lower.contains("x-auth-token"),
        "Connection-nominated X-Auth-Token must be stripped \
         before reaching upstream; echoed headers: {body}"
    );
    assert!(
        !body_lower.contains("secret-credential"),
        "Connection-nominated header value must not reach \
         upstream; echoed headers: {body}"
    );
}

#[test]
fn multiple_connection_nominated_headers_stripped() {
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
         Connection: X-Secret-A, X-Secret-B, close\r\n\
         X-Secret-A: alpha\r\n\
         X-Secret-B: bravo\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 200, "request should succeed");

    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    assert!(
        !body_lower.contains("x-secret-a"),
        "Connection-nominated X-Secret-A must be stripped; \
         echoed headers: {body}"
    );
    assert!(
        !body_lower.contains("x-secret-b"),
        "Connection-nominated X-Secret-B must be stripped; \
         echoed headers: {body}"
    );
}

#[test]
fn h2c_upgrade_via_connection_stripped() {
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
         Connection: Upgrade, close\r\n\
         Upgrade: h2c\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert!(
        status == 200 || status == 400,
        "h2c upgrade should succeed (stripped) or be rejected, \
         got {status}"
    );

    if status == 200 {
        let body = parse_body(&raw);
        let body_lower = body.to_lowercase();
        assert!(
            !body_lower.contains("upgrade: h2c") && !body_lower.contains("upgrade:h2c"),
            "h2c Upgrade header must be stripped to prevent \
             h2c smuggling; echoed headers: {body}"
        );
    }
}

#[test]
fn hop_by_hop_response_headers_stripped_from_client() {
    let backend_port = start_hop_by_hop_response_backend();
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
    assert_eq!(status, 200, "request should succeed");

    assert!(
        parse_header(&raw, "keep-alive").is_none(),
        "Keep-Alive hop-by-hop header must not reach client"
    );
    assert!(
        parse_header(&raw, "proxy-authenticate").is_none(),
        "Proxy-Authenticate hop-by-hop header must not reach \
         client"
    );
    assert!(
        parse_header(&raw, "trailer").is_none(),
        "Trailer hop-by-hop header must not reach client"
    );
    assert!(
        parse_header(&raw, "x-internal-token").is_none(),
        "Connection-nominated X-Internal-Token from upstream \
         must not reach client"
    );
}

#[test]
fn safe_headers_survive_hop_by_hop_stripping() {
    let backend_port = start_hop_by_hop_response_backend();
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
    assert_eq!(status, 200, "request should succeed");

    let body = parse_body(&raw);
    assert_eq!(body, "hop-by-hop-test", "response body must be forwarded intact");

    let safe = parse_header(&raw, "x-safe-header");
    assert_eq!(
        safe.as_deref(),
        Some("visible"),
        "non-hop-by-hop X-Safe-Header must survive forwarding"
    );
}

#[test]
fn non_nominated_headers_preserved_in_request() {
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
         Connection: X-Strip-Me, close\r\n\
         X-Strip-Me: gone\r\n\
         X-Keep-Me: stays\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 200, "request should succeed");

    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    assert!(
        !body_lower.contains("x-strip-me"),
        "Connection-nominated header must be stripped; body: {body}"
    );
    assert!(
        body_lower.contains("x-keep-me"),
        "non-nominated X-Keep-Me must be preserved; body: {body}"
    );
}
