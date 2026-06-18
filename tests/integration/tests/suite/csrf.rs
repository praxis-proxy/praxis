// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for the `csrf` filter.

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_send, parse_status, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn csrf_get_bypasses_check() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = csrf_yaml(proxy_port, backend_port, &default_csrf_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api/data HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "GET should bypass CSRF check");
}

#[test]
fn csrf_post_with_trusted_origin_allowed() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = csrf_yaml(proxy_port, backend_port, &default_csrf_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "POST with trusted origin should be allowed");
}

#[test]
fn csrf_post_with_untrusted_origin_rejected() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = csrf_yaml(proxy_port, backend_port, &default_csrf_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 403, "POST with untrusted origin should be rejected");
}

#[test]
fn csrf_post_without_origin_rejected() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = csrf_yaml(proxy_port, backend_port, &default_csrf_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /api/data HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 403, "POST without origin should be rejected");
}

#[test]
fn csrf_post_with_trusted_referer_allowed() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = csrf_yaml(proxy_port, backend_port, &default_csrf_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /api/data HTTP/1.1\r\nHost: localhost\r\nReferer: https://app.example.com/form\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "POST with trusted Referer should be allowed");
}

#[test]
fn csrf_sec_fetch_site_cross_site_rejected() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = csrf_yaml(proxy_port, backend_port, &default_csrf_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nSec-Fetch-Site: cross-site\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 403, "cross-site Sec-Fetch-Site should be rejected");
}

#[test]
fn csrf_wildcard_subdomain_allowed() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = csrf_yaml(proxy_port, backend_port, &default_csrf_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://sub.example.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "wildcard subdomain should match");
}

#[test]
fn csrf_head_bypasses_check() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = csrf_yaml(proxy_port, backend_port, &default_csrf_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "HEAD /api/data HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "HEAD should bypass CSRF check");
}

#[test]
fn csrf_delete_with_untrusted_origin_rejected() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = csrf_yaml(proxy_port, backend_port, &default_csrf_block());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "DELETE /api/resource HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.com\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        403,
        "DELETE with untrusted origin should be rejected"
    );
}

#[test]
fn csrf_with_cors_filter_composition() {
    let backend_guard = start_backend_with_shutdown("ok");
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
      - filter: cors
        allow_origins:
          - "https://app.example.com"
        allow_methods:
          - GET
          - POST
      - filter: csrf
        trusted_origins:
          - "https://app.example.com"
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

    let raw = http_send(
        proxy.addr(),
        "POST /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "CORS + CSRF with trusted origin should allow");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Default CSRF filter config block for reuse.
fn default_csrf_block() -> String {
    r#"
      - filter: csrf
        trusted_origins:
          - "https://app.example.com"
          - "https://*.example.com"
        enforce_percentage: 100
        enable_sec_fetch_site: true
"#
    .to_owned()
}

/// Build a full proxy YAML config with the given CSRF block.
fn csrf_yaml(proxy_port: u16, backend_port: u16, csrf_block: &str) -> String {
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
{csrf_block}
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
