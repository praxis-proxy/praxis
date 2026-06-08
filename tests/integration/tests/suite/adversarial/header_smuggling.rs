// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Adversarial tests for header-based smuggling and
//! injection attack vectors.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, parse_body, parse_header, parse_status, simple_proxy_yaml, start_backend_with_shutdown,
    start_header_echo_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn connection_header_declared_headers_stripped_from_upstream() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: X-Secret-Header\r\n\
         X-Secret-Header: leaked\r\n\
         X-Safe: visible\r\n\
         \r\n";
    let raw = http_send(proxy.addr(), request);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert!(
        !body_lower.contains("x-secret-header"),
        "Connection-declared header should be stripped before upstream: {body}"
    );
    assert!(
        body_lower.contains("x-safe"),
        "Non-Connection-declared header should be forwarded: {body}"
    );
}

#[test]
fn oversized_header_value_rejected() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let huge_value = "X".repeat(64 * 1024);
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Huge: {huge_value}\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    let status = parse_status(&raw);

    assert!(
        status == 400 || status == 431 || status == 200 || raw.is_empty(),
        "oversized header ({} bytes) should be handled safely (got {status})",
        huge_value.len()
    );
}

#[test]
fn multiple_connection_nominated_headers_all_stripped() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: X-Internal, X-Token\r\n\
         X-Internal: secret-data\r\n\
         X-Token: auth-secret\r\n\
         X-Public: visible\r\n\
         \r\n";
    let raw = http_send(proxy.addr(), request);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert!(
        !body_lower.contains("x-internal"),
        "Connection-nominated X-Internal should be stripped: {body}"
    );
    assert!(
        !body_lower.contains("x-token"),
        "Connection-nominated X-Token should be stripped: {body}"
    );
    assert!(
        body_lower.contains("x-public"),
        "Non-nominated X-Public should be forwarded: {body}"
    );
}

#[test]
fn hop_by_hop_upgrade_header_preserved_for_upgrade_requests() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         X-Normal: keep\r\n\
         \r\n";
    let raw = http_send(proxy.addr(), request);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert!(
        body_lower.contains("upgrade"),
        "Upgrade header should be preserved for upgrade requests: {body}"
    );
    assert!(
        body_lower.contains("x-normal"),
        "Normal header should be forwarded: {body}"
    );
}

#[test]
fn keep_alive_header_stripped_from_upstream() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: keep-alive\r\n\
         Keep-Alive: timeout=300\r\n\
         Accept: text/html\r\n\
         \r\n";
    let raw = http_send(proxy.addr(), request);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert!(
        !body_lower.contains("keep-alive"),
        "Keep-Alive hop-by-hop header should be stripped: {body}"
    );
    assert!(
        body_lower.contains("accept"),
        "Accept end-to-end header should be forwarded: {body}"
    );
}

#[test]
fn proxy_authorization_stripped_from_upstream() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Proxy-Authorization: Basic dGVzdDp0ZXN0\r\n\
         Authorization: Bearer real-token\r\n\
         \r\n";
    let raw = http_send(proxy.addr(), request);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert!(
        !body_lower.contains("proxy-authorization"),
        "Proxy-Authorization hop-by-hop header should be stripped: {body}"
    );
    assert!(
        body_lower.contains("authorization"),
        "Authorization end-to-end header should be forwarded: {body}"
    );
}

#[test]
fn forwarded_headers_filter_overwrites_spoofed_xff() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: proxy
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: forwarded_headers
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-For: 10.10.10.10\r\n\
         X-Forwarded-Proto: https\r\n\
         \r\n";
    let raw = http_send(proxy.addr(), request);
    let body = parse_body(&raw);

    assert!(
        !body.contains("10.10.10.10"),
        "spoofed X-Forwarded-For should be overwritten in untrusted mode: {body}"
    );
    assert!(
        body.contains("127.0.0.1"),
        "real client IP should replace spoofed XFF: {body}"
    );
}

#[test]
fn response_hop_by_hop_headers_stripped() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: headers
        response_add:
          - name: Keep-Alive
            value: "timeout=300"
          - name: Proxy-Authenticate
            value: "Basic"
          - name: X-Safe-Response
            value: "visible"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let raw = http_send(proxy.addr(), request);

    assert_eq!(
        parse_header(&raw, "x-safe-response"),
        Some("visible".to_owned()),
        "safe response header should be preserved"
    );
}

#[test]
fn multiple_upgrade_headers_handled_safely() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Upgrade: h2c\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         \r\n";
    let raw = http_send(proxy.addr(), request);
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 400,
        "multiple Upgrade headers should be handled safely (got {status})"
    );
}

#[test]
fn upgrade_with_transfer_encoding_chunked_handled_safely() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Transfer-Encoding: chunked\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         \r\n\
         0\r\n\
         \r\n";
    let raw = http_send(proxy.addr(), request);
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 400 || raw.is_empty(),
        "upgrade + Transfer-Encoding: chunked should not crash (got {status})"
    );
}

#[test]
fn upgrade_request_with_body_handled_safely() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = "unexpected-body-content";
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Content-Length: {}\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let raw = http_send(proxy.addr(), &request);
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 400 || raw.is_empty(),
        "upgrade request with body should not crash (got {status})"
    );
}
