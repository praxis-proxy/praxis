// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for the `cors` filter.

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_send, parse_header, parse_status, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn cors_simple_request_allowed_origin() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port, &default_cors_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "allowed origin should return 200");
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        Some("https://app.example.com".to_owned()),
        "should have ACAO header"
    );
    assert_eq!(
        parse_header(&raw, "vary"),
        Some("Origin".to_owned()),
        "dynamic origin should inject Vary: Origin"
    );
}

#[test]
fn cors_simple_request_disallowed_origin() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port, &default_cors_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.com\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "disallowed origin still gets 200 (omit mode)");
    assert!(
        parse_header(&raw, "access-control-allow-origin").is_none(),
        "disallowed origin should not have ACAO header"
    );
}

#[test]
fn cors_preflight_allowed() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port, &default_cors_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nAccess-Control-Request-Method: PUT\r\nAccess-Control-Request-Headers: Content-Type\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 204, "preflight should return 204");
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        Some("https://app.example.com".to_owned()),
        "preflight should have ACAO header"
    );
    assert!(
        parse_header(&raw, "access-control-allow-methods").is_some(),
        "preflight should have Access-Control-Allow-Methods"
    );
    assert!(
        parse_header(&raw, "access-control-max-age").is_some(),
        "preflight should have Access-Control-Max-Age"
    );
}

#[test]
fn cors_preflight_disallowed_origin_omit() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port, &default_cors_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.com\r\nAccess-Control-Request-Method: GET\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 204, "omit mode preflight should return 204");
    assert!(
        parse_header(&raw, "access-control-allow-origin").is_none(),
        "omit mode should not include ACAO header"
    );
}

#[test]
fn cors_preflight_disallowed_origin_reject() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let cors_block = r#"
      - filter: cors
        allow_origins:
          - "https://app.example.com"
        allow_methods:
          - GET
        disallowed_origin_mode: "reject"
"#;
    let yaml = cors_yaml(proxy_port, backend_port, cors_block);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.com\r\nAccess-Control-Request-Method: GET\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 403, "reject mode preflight should return 403");
}

#[test]
fn cors_options_without_request_method_is_not_preflight() {
    let backend_port_guard = start_backend_with_shutdown("options-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port, &default_cors_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "OPTIONS without Access-Control-Request-Method should pass to upstream"
    );
}

#[test]
fn cors_vary_origin_on_all_responses() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port, &default_cors_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api/data HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "non-CORS request should return 200");
    assert_eq!(
        parse_header(&raw, "vary"),
        Some("Origin".to_owned()),
        "non-CORS request should still have Vary: Origin"
    );
}

#[test]
fn cors_wildcard_origin_no_vary() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let cors_block = r#"
      - filter: cors
        allow_origins:
          - "*"
        allow_methods:
          - GET
"#;
    let yaml = cors_yaml(proxy_port, backend_port, cors_block);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://anything.com\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "wildcard origin should return 200");
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        Some("*".to_owned()),
        "wildcard should return * as ACAO"
    );
    assert!(
        parse_header(&raw, "vary").is_none() || parse_header(&raw, "vary") != Some("Origin".to_owned()),
        "wildcard without credentials should not add Vary: Origin"
    );
}

#[test]
fn cors_credentials_reflects_exact_origin() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let cors_block = r#"
      - filter: cors
        allow_origins:
          - "https://app.example.com"
        allow_methods:
          - GET
        allow_credentials: true
"#;
    let yaml = cors_yaml(proxy_port, backend_port, cors_block);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        Some("https://app.example.com".to_owned()),
        "credentials mode should reflect exact origin"
    );
    assert_eq!(
        parse_header(&raw, "access-control-allow-credentials"),
        Some("true".to_owned()),
        "credentials mode should set Allow-Credentials"
    );
}

#[test]
fn cors_expose_headers_present() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port, &default_cors_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_header(&raw, "access-control-expose-headers"),
        Some("X-Request-ID, X-RateLimit-Remaining".to_owned()),
        "should expose configured headers"
    );
}

#[test]
fn cors_null_origin_rejected_by_default() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port, &default_cors_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: null\r\nConnection: close\r\n\r\n",
    );
    assert!(
        parse_header(&raw, "access-control-allow-origin").is_none(),
        "null origin should not be reflected by default"
    );
}

#[test]
fn cors_null_origin_allowed_with_opt_in() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let cors_block = r#"
      - filter: cors
        allow_origins:
          - "https://app.example.com"
        allow_methods:
          - GET
        allow_null_origin: true
"#;
    let yaml = cors_yaml(proxy_port, backend_port, cors_block);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: null\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        Some("null".to_owned()),
        "null origin should be reflected when opt-in"
    );
}

#[test]
fn cors_with_other_filters() {
    let backend_port_guard = start_backend_with_shutdown("composed");
    let backend_port = backend_port_guard.port();
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
      - filter: cors
        allow_origins:
          - "https://app.example.com"
        allow_methods:
          - GET
          - POST
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: headers
        response_add:
          - name: X-Custom
            value: "yes"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "composed pipeline should return 200");
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        Some("https://app.example.com".to_owned()),
        "CORS headers should be present in composed pipeline"
    );
    assert_eq!(
        parse_header(&raw, "x-custom"),
        Some("yes".to_owned()),
        "other filter headers should also be present"
    );
}

#[test]
fn cors_wildcard_subdomain_through_proxy() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port, &default_cors_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://sub.example.com\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "wildcard subdomain origin should return 200");
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        Some("https://sub.example.com".to_owned()),
        "wildcard subdomain origin should be reflected"
    );
}

#[test]
fn cors_preflight_disallowed_method_rejected() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port, &default_cors_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nAccess-Control-Request-Method: PATCH\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 204, "disallowed method preflight should return 204");
    assert!(
        parse_header(&raw, "access-control-allow-origin").is_none(),
        "disallowed method preflight should not include ACAO"
    );
    assert!(
        parse_header(&raw, "vary").is_some(),
        "disallowed preflight should include Vary header"
    );
}

#[test]
fn cors_preflight_disallowed_headers_rejected() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = cors_yaml(proxy_port, backend_port, &default_cors_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nAccess-Control-Request-Method: GET\r\nAccess-Control-Request-Headers: X-Not-Allowed\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        204,
        "disallowed headers preflight should return 204"
    );
    assert!(
        parse_header(&raw, "access-control-allow-origin").is_none(),
        "disallowed headers preflight should not include ACAO"
    );
    assert!(
        parse_header(&raw, "vary").is_some(),
        "disallowed headers preflight should include Vary header"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Default CORS filter config block for reuse across tests.
fn default_cors_block() -> String {
    r#"
      - filter: cors
        allow_origins:
          - "https://app.example.com"
          - "https://*.example.com"
        allow_methods:
          - GET
          - POST
          - PUT
          - DELETE
        allow_headers:
          - Content-Type
          - Authorization
          - X-Request-ID
        expose_headers:
          - X-Request-ID
          - X-RateLimit-Remaining
        max_age: 3600
"#
    .to_owned()
}

/// Build a full proxy YAML config with the given CORS filter block.
fn cors_yaml(proxy_port: u16, backend_port: u16, cors_block: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
{cors_block}
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
