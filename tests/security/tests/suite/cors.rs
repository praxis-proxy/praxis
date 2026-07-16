// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! CORS runtime security tests.
//!
//! Verifies that the CORS filter blocks null-origin and
//! disallowed-origin requests at runtime through the proxy.
//! Config-time validation is tested in `cors_validation.rs`.

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_send, parse_header, parse_status, start_backend, start_proxy};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn cors_null_origin_blocked_at_runtime() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = cors_yaml(
        proxy_port,
        backend_port,
        r#"
        allow_origins:
          - "https://app.example.com""#,
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Origin: null\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 200, "request should still succeed");

    let acao = parse_header(&raw, "access-control-allow-origin");
    assert!(
        acao.is_none() || acao.as_deref() != Some("null"),
        "null origin must NOT be reflected in ACAO header; \
         got: {acao:?}"
    );
}

#[test]
fn cors_disallowed_origin_gets_no_acao() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = cors_yaml(
        proxy_port,
        backend_port,
        r#"
        allow_origins:
          - "https://trusted.example.com""#,
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Origin: https://evil.com\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 200, "request should still succeed");

    let acao = parse_header(&raw, "access-control-allow-origin");
    assert!(
        acao.is_none(),
        "disallowed origin must not receive ACAO header; \
         got: {acao:?}"
    );
}

#[test]
fn cors_preflight_null_origin_rejected() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = cors_yaml(
        proxy_port,
        backend_port,
        r#"
        allow_origins:
          - "https://app.example.com"
        allow_methods:
          - GET
          - POST
        disallowed_origin_mode: reject"#,
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Origin: null\r\n\
         Access-Control-Request-Method: POST\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(
        status, 403,
        "preflight from null origin must be rejected when \
         disallowed_origin_mode is reject; got {status}"
    );
}

#[test]
fn cors_allowed_origin_reflected() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = cors_yaml(
        proxy_port,
        backend_port,
        r#"
        allow_origins:
          - "https://app.example.com""#,
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Origin: https://app.example.com\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 200, "request should succeed");

    let acao = parse_header(&raw, "access-control-allow-origin");
    assert_eq!(
        acao.as_deref(),
        Some("https://app.example.com"),
        "allowed origin must be reflected in ACAO header"
    );
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

/// Build proxy YAML with a CORS filter using the given config fragment.
fn cors_yaml(proxy_port: u16, backend_port: u16, cors_config: &str) -> String {
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
      - filter: cors
{cors_config}
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
