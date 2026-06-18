// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Adversarial tests verifying rate limit bypass attempts
//! via spoofed headers.

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, http_send, parse_status, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn spoofed_xff_does_not_bypass_per_ip_rate_limit() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "per_ip", 1.0, 3);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "first request should succeed");

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "second request should succeed");

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 10.99.99.99\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(
        status, 429,
        "spoofed X-Forwarded-For should not bypass per-IP rate limit (got {status})"
    );
}

#[test]
fn spoofed_x_real_ip_does_not_bypass_per_ip_rate_limit() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "per_ip", 1.0, 3);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "first request should succeed");

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "second request should succeed");

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 10.88.88.88\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(
        status, 429,
        "spoofed X-Real-IP should not bypass per-IP rate limit (got {status})"
    );
}

#[test]
fn spoofed_forwarded_header_does_not_bypass_per_ip_rate_limit() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "per_ip", 1.0, 3);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "first request should succeed");

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "second request should succeed");

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nForwarded: for=10.77.77.77\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(
        status, 429,
        "spoofed Forwarded header should not bypass per-IP rate limit (got {status})"
    );
}

#[test]
fn global_rate_limit_unaffected_by_xff() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 1.0, 3);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "first request should succeed");

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "second request should succeed");

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 10.66.66.66\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(
        status, 429,
        "XFF should have no effect on global rate limiter (got {status})"
    );
}

#[test]
fn varying_xff_values_still_rate_limited() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "per_ip", 1.0, 3);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "first request should succeed");

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "second request should succeed");

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 1.1.1.1\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        429,
        "third request with XFF 1.1.1.1 should still be rate limited"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a rate-limited proxy YAML config.
fn rate_limit_yaml(proxy_port: u16, backend_port: u16, mode: &str, rate: f64, burst: u32) -> String {
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
      - filter: rate_limit
        mode: {mode}
        rate: {rate}
        burst: {burst}
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
