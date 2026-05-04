// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Filter header leakage security tests.

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_send, parse_header, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn forwarded_headers_not_leaked_to_client() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = fwd_only_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );

    assert!(
        parse_header(&raw, "x-forwarded-for").is_none(),
        "X-Forwarded-For must not leak to client response"
    );
    assert!(
        !response_has_header(&raw, "x-forwarded-proto"),
        "X-Forwarded-Proto must not leak to client response"
    );
    assert!(
        !response_has_header(&raw, "x-forwarded-host"),
        "X-Forwarded-Host must not leak to client response"
    );
}

#[test]
fn headers_request_add_not_leaked_to_client() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = headers_request_add_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );

    assert!(
        parse_header(&raw, "x-internal-debug").is_none(),
        "X-Internal-Debug (request_add) must not leak to client response"
    );
}

#[test]
fn request_id_not_leaked_to_client() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = request_id_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );

    assert!(
        parse_header(&raw, "x-request-id").is_none(),
        "X-Request-Id must not leak to client response when backend does not echo it"
    );
}

#[test]
fn combined_request_headers_not_leaked_to_client() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = combined_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );

    let leaked: Vec<&str> = [
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-request-id",
        "x-internal-debug",
    ]
    .iter()
    .copied()
    .filter(|h| response_has_header(&raw, h))
    .collect();

    assert!(
        leaked.is_empty(),
        "request-injected headers leaked to client response: {leaked:?}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Generate proxy YAML with forwarded_headers filter only.
fn fwd_only_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
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
    )
}

/// Generate proxy YAML with headers filter adding a request header.
fn headers_request_add_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: proxy
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: headers
        request_add:
          - name: "X-Internal-Debug"
            value: "true"
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
    )
}

/// Generate proxy YAML with request_id filter only.
fn request_id_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: proxy
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: request_id
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
    )
}

/// Generate proxy YAML combining all request-injecting filters.
fn combined_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
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
      - filter: request_id
      - filter: headers
        request_add:
          - name: "X-Internal-Debug"
            value: "true"
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
    )
}

/// Check whether a header name appears anywhere in the raw
/// response headers (before the body separator).
fn response_has_header(raw: &str, name: &str) -> bool {
    let headers_part = match raw.split_once("\r\n\r\n") {
        Some((h, _)) => h,
        None => raw,
    };
    let lower = name.to_lowercase();
    headers_part.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(k, _)| k.trim().to_lowercase() == lower)
    })
}
