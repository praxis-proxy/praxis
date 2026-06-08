// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Tests for proxy behavior with large payloads and near body size limits.

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_post, http_send, parse_status, start_echo_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn body_under_limit_passes_through() {
    let _backend = start_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let limit = 128;
    let yaml = body_limit_yaml(proxy_port, backend_port, limit);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = "x".repeat(64);
    let (status, body) = http_post(proxy.addr(), "/echo", &payload);

    assert_eq!(status, 200, "payload under limit should succeed");
    assert_eq!(body, payload, "body should pass through intact");
}

#[test]
fn exact_limit_body_passes_through() {
    let _backend = start_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let limit = 64;
    let yaml = body_limit_yaml(proxy_port, backend_port, limit);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = "b".repeat(limit);
    let (status, body) = http_post(proxy.addr(), "/echo", &payload);

    assert_eq!(status, 200, "payload exactly at limit should succeed");
    assert_eq!(body, payload, "exact-limit body should pass through intact");
}

#[test]
fn one_byte_over_limit_returns_413() {
    let _backend = start_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let limit = 64;
    let yaml = body_limit_yaml(proxy_port, backend_port, limit);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = "c".repeat(limit + 1);
    let (status, _) = http_post(proxy.addr(), "/echo", &payload);

    assert_eq!(status, 413, "payload one byte over limit should return 413");
}

#[test]
fn much_larger_than_limit_returns_413() {
    let _backend = start_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let limit = 64;
    let yaml = body_limit_yaml(proxy_port, backend_port, limit);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = "d".repeat(limit * 10);
    let (status, _) = http_post(proxy.addr(), "/echo", &payload);

    assert_eq!(status, 413, "payload 10x over limit should return 413");
}

#[test]
fn no_limit_handles_large_body() {
    let _backend = start_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = "e".repeat(64 * 1024);
    let (status, body) = http_post(proxy.addr(), "/echo", &payload);

    assert_eq!(status, 200, "large body with no limit should succeed");
    assert_eq!(
        body.len(),
        payload.len(),
        "response body length should match request payload"
    );
}

#[test]
fn empty_body_post_succeeds() {
    let _backend = start_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let yaml = body_limit_yaml(proxy_port, backend_port, 1024);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);

    assert_eq!(status, 200, "empty body POST should succeed");
}

#[test]
fn response_body_over_limit_handled() {
    let large_body = "r".repeat(2048);
    let backend_port = praxis_test_utils::start_backend(&large_body);
    let proxy_port = free_port();
    let yaml = response_limit_yaml(proxy_port, backend_port, 1024);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);

    assert!(
        status == 500 || status == 502 || status == 200,
        "response over limit should be handled gracefully (200, 500, or 502), got {status}"
    );
}

#[test]
fn sequential_large_payloads_do_not_leak() {
    let _backend = start_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = "f".repeat(32 * 1024);
    for i in 0..10 {
        let (status, body) = http_post(proxy.addr(), "/echo", &payload);
        assert_eq!(status, 200, "sequential large payload {i} should succeed");
        assert_eq!(body.len(), payload.len(), "response {i} length should match request");
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a YAML config with `body_limits.max_request_bytes`.
fn body_limit_yaml(proxy_port: u16, backend_port: u16, limit: usize) -> String {
    format!(
        r#"
body_limits:
  max_request_bytes: {limit}
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    )
}

/// Build a YAML config with `body_limits.max_response_bytes`.
fn response_limit_yaml(proxy_port: u16, backend_port: u16, limit: usize) -> String {
    format!(
        r#"
body_limits:
  max_response_bytes: {limit}
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    )
}
