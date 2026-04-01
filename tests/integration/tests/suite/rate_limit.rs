//! Integration tests for the `rate_limit` filter.

use praxis_core::config::Config;

use crate::common::{free_port, http_get, http_send, parse_header, parse_status, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn rate_limit_allows_within_burst() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 1.0, 6);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    for i in 0..5 {
        let (status, body) = http_get(&addr, "/", None);
        assert_eq!(status, 200, "request {i} within burst should return 200");
        assert_eq!(body, "ok", "request {i} within burst should return backend response");
    }

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let status = parse_status(&raw);
    assert_eq!(status, 429, "request past burst should return 429");
}

#[test]
fn rate_limit_rejects_over_burst() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 1.0, 4);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    for _ in 0..3 {
        let (status, _) = http_get(&addr, "/", None);
        assert_eq!(status, 200, "requests within burst should return 200");
    }

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let status = parse_status(&raw);
    assert_eq!(status, 429, "request over burst should return 429");

    let retry_after = parse_header(&raw, "retry-after");
    assert!(retry_after.is_some(), "429 should include Retry-After header");
}

#[test]
fn rate_limit_global_shared() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 1.0, 4);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, _) = http_get(&addr, "/a", None);
    assert_eq!(status, 200, "first request should succeed");

    let (status, _) = http_get(&addr, "/b", None);
    assert_eq!(status, 200, "second request should succeed");

    let (status, _) = http_get(&addr, "/c", None);
    assert_eq!(status, 200, "third request should succeed");

    let (status, _) = http_get(&addr, "/d", None);
    assert_eq!(
        status, 429,
        "fourth request should be rate limited (global shares one bucket)"
    );
}

#[test]
fn rate_limit_response_headers_present() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 1.0, 10);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(parse_status(&raw), 200, "request should succeed");

    assert!(
        parse_header(&raw, "x-ratelimit-limit").is_some(),
        "response should contain X-RateLimit-Limit"
    );
    assert!(
        parse_header(&raw, "x-ratelimit-remaining").is_some(),
        "response should contain X-RateLimit-Remaining"
    );
    assert!(
        parse_header(&raw, "x-ratelimit-reset").is_some(),
        "response should contain X-RateLimit-Reset"
    );
}

#[test]
fn rate_limit_429_includes_rate_limit_headers() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 1.0, 2);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    http_get(&addr, "/", None);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(parse_status(&raw), 429, "second request should be 429");

    assert!(
        parse_header(&raw, "x-ratelimit-limit").is_some(),
        "429 should include X-RateLimit-Limit"
    );
    assert!(
        parse_header(&raw, "x-ratelimit-remaining").is_some(),
        "429 should include X-RateLimit-Remaining"
    );
    assert!(
        parse_header(&raw, "x-ratelimit-reset").is_some(),
        "429 should include X-RateLimit-Reset"
    );
}

#[test]
fn rate_limit_with_conditions() {
    let backend_port = start_backend("ok");
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
      - filter: rate_limit
        mode: global
        rate: 1
        burst: 1
        conditions:
          - when:
              path_prefix: "/api/"
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
    let addr = start_proxy(&config);

    let (status, _) = http_get(&addr, "/api/data", None);
    assert_eq!(status, 200, "first /api/ request should succeed");

    let (status, _) = http_get(&addr, "/api/data", None);
    assert_eq!(status, 429, "second /api/ request should be rate limited");

    let (status, body) = http_get(&addr, "/public", None);
    assert_eq!(status, 200, "non-API path should bypass rate limiter");
    assert_eq!(body, "ok", "non-API path should return backend response");
}

#[test]
fn rate_limit_per_ip_isolates_clients() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "per_ip", 1.0, 3);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "first request within burst should return 200");
    assert_eq!(body, "ok", "first request should return backend response");

    let (status, _) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "second request within burst should return 200");

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let status = parse_status(&raw);
    assert_eq!(status, 429, "request exceeding per-IP burst should be rate limited");
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
