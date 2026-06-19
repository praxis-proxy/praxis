// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for rate limiter behavior under burst conditions.

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, http_send, parse_header, parse_status, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn burst_exhaustion_then_rejection() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let usable = 4_u32;
    let burst = usable + 2;
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 0.1, burst);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    for i in 0..usable {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "request {i} within burst should return 200");
        assert_eq!(body, "ok", "request {i} should get backend response");
    }

    let mut first_429_at = None;
    for i in 0..4_u32 {
        let raw = http_send(
            proxy.addr(),
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        if parse_status(&raw) == 429 {
            first_429_at = Some(usable + i);
            break;
        }
    }
    let rejected_at = first_429_at.expect("burst exhaustion should produce a 429 within 4 extra requests");
    assert!(
        rejected_at <= burst,
        "first 429 at request {rejected_at} should not exceed burst capacity {burst}"
    );
}

#[test]
fn rejection_includes_retry_after_header() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 1.0, 2);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    http_get(proxy.addr(), "/", None);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 429, "second request should be rate limited");

    let retry_after = parse_header(&raw, "retry-after");
    assert!(retry_after.is_some(), "429 response should include Retry-After header");

    let retry_secs: f64 = retry_after
        .as_ref()
        .unwrap()
        .parse()
        .expect("Retry-After should be a number");
    assert!(retry_secs > 0.0, "Retry-After should be positive, got {retry_secs}");
}

#[test]
fn rate_limit_headers_present_on_success() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 100.0, 200);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "request should succeed");

    assert!(
        parse_header(&raw, "x-ratelimit-limit").is_some(),
        "200 response should include X-RateLimit-Limit"
    );
    assert!(
        parse_header(&raw, "x-ratelimit-remaining").is_some(),
        "200 response should include X-RateLimit-Remaining"
    );
    assert!(
        parse_header(&raw, "x-ratelimit-reset").is_some(),
        "200 response should include X-RateLimit-Reset"
    );
}

#[test]
fn rate_limit_remaining_decreases() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 0.1, 10);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw1 = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let remaining1: u32 = parse_header(&raw1, "x-ratelimit-remaining")
        .expect("first response should have X-RateLimit-Remaining")
        .parse()
        .expect("remaining should be a number");

    let raw2 = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let remaining2: u32 = parse_header(&raw2, "x-ratelimit-remaining")
        .expect("second response should have X-RateLimit-Remaining")
        .parse()
        .expect("remaining should be a number");

    assert!(
        remaining2 < remaining1,
        "remaining should decrease: first={remaining1}, second={remaining2}"
    );
}

#[test]
fn rate_limit_headers_present_on_rejection() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 0.1, 2);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    http_get(proxy.addr(), "/", None);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 429, "should be rate limited");

    assert!(
        parse_header(&raw, "x-ratelimit-limit").is_some(),
        "429 should include X-RateLimit-Limit"
    );
    assert!(
        parse_header(&raw, "x-ratelimit-remaining").is_some(),
        "429 should include X-RateLimit-Remaining"
    );

    let remaining: u32 = parse_header(&raw, "x-ratelimit-remaining")
        .unwrap()
        .parse()
        .expect("remaining should be a number");
    assert_eq!(remaining, 0, "remaining should be 0 on rejection");
}

#[test]
fn per_ip_burst_exhaustion() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "per_ip", 0.1, 5);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    for i in 0..3 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "per-IP request {i} within burst should succeed");
    }

    let mut saw_429 = false;
    for _ in 0..4 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        if status == 429 {
            saw_429 = true;
            break;
        }
    }
    assert!(saw_429, "per-IP request past burst should be rate limited");
}

#[test]
fn rapid_burst_uses_all_tokens() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let burst: u32 = 8;
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 0.1, burst);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let mut successes = 0_u32;
    let total = burst + 5;
    for _ in 0..total {
        let (status, _) = http_get(proxy.addr(), "/", None);
        if status == 200 {
            successes += 1;
        }
    }

    assert!(
        successes <= burst,
        "successes ({successes}) should not exceed burst capacity ({burst})"
    );
    assert!(
        successes >= burst - 2,
        "successes ({successes}) should be close to burst capacity ({burst})"
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
    filter_chains: [main]
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
