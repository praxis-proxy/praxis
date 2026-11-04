// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the `bandwidth_limit` filter.

use std::time::{Duration, Instant};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, http_post, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn download_is_paced_when_there_is_no_burst() {
    let body = "x".repeat(16_000);
    let backend = start_backend_with_shutdown(&body);
    let proxy_port = free_port();
    let config = Config::from_yaml(&bandwidth_yaml(proxy_port, backend.port(), 0, true)).unwrap();
    let proxy = start_proxy(&config);

    let started = Instant::now();
    let (status, response) = http_get(proxy.addr(), "/", None);
    let elapsed = started.elapsed();

    assert_eq!(status, 200, "paced download should still succeed");
    assert_eq!(response.len(), 16_000, "the full body should arrive");
    assert!(
        elapsed >= Duration::from_millis(1_200),
        "16000 bytes at 8000 bytes per second should take about two seconds, elapsed {elapsed:?}"
    );
}

#[test]
fn download_burst_covers_a_small_body() {
    let body = "x".repeat(16_000);
    let backend = start_backend_with_shutdown(&body);
    let proxy_port = free_port();
    let config = Config::from_yaml(&bandwidth_yaml(proxy_port, backend.port(), 16_000, true)).unwrap();
    let proxy = start_proxy(&config);

    let started = Instant::now();
    let (status, response) = http_get(proxy.addr(), "/", None);
    let elapsed = started.elapsed();

    assert_eq!(status, 200, "a burst-covered download should succeed");
    assert_eq!(response.len(), 16_000, "the full body should arrive");
    assert!(
        elapsed < Duration::from_millis(1_000),
        "a burst that covers the body should not wait out the byte rate, elapsed {elapsed:?}"
    );
}

#[test]
fn upload_is_paced_when_there_is_no_burst() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = Config::from_yaml(&bandwidth_yaml(proxy_port, backend.port(), 0, false)).unwrap();
    let proxy = start_proxy(&config);
    let payload = "y".repeat(8_000);

    let started = Instant::now();
    let (status, response) = http_post(proxy.addr(), "/", &payload);
    let elapsed = started.elapsed();

    assert_eq!(status, 200, "paced upload should still succeed");
    assert_eq!(response, "ok", "the backend response should be unchanged");
    assert!(
        elapsed >= Duration::from_millis(700),
        "8000 bytes at 8000 bytes per second should take about a second, elapsed {elapsed:?}"
    );
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Proxy config that paces either the response or the request.
fn bandwidth_yaml(proxy_port: u16, backend_port: u16, burst_bytes: u64, download: bool) -> String {
    let direction = if download {
        "download_bytes_per_sec: 8000"
    } else {
        "upload_bytes_per_sec: 8000"
    };
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
      - filter: bandwidth_limit
        mode: per_connection
        {direction}
        burst_bytes: {burst_bytes}
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
