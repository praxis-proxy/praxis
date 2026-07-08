// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! End-to-end resilience tests for the circuit breaker filter,
//! verifying open/half-open/closed state transitions under
//! real proxy traffic.

use std::time::Duration;

use praxis_core::config::Config;
use praxis_test_utils::{Backend, free_port, http_get, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn circuit_breaker_opens_after_failures() {
    let backend_port = Backend::status(500, "error").start();
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
      - filter: circuit_breaker
        clusters:
          - name: backend
            consecutive_failures: 3
            recovery_window_secs: 60
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 500,
        "first request should reach the 500-returning backend (circuit starts closed)"
    );

    let mut saw_503 = false;
    for _ in 0..10 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        if status == 503 {
            saw_503 = true;
            break;
        }
        assert!(
            status == 500 || status == 502,
            "pre-trip requests should return an upstream error, got {status}"
        );
    }
    assert!(
        saw_503,
        "circuit should open and reject with 503 after threshold failures"
    );

    for i in 0..3 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        assert_eq!(
            status, 503,
            "request {i} after circuit opens should remain rejected with 503"
        );
    }
}

#[test]
fn circuit_breaker_recovers_after_window() {
    let backend_port = Backend::status(500, "error").start();
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
      - filter: circuit_breaker
        clusters:
          - name: backend
            consecutive_failures: 3
            recovery_window_secs: 1
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let mut circuit_open = false;
    for _ in 0..10 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        if status == 503 {
            circuit_open = true;
            break;
        }
    }
    assert!(circuit_open, "circuit should open after consecutive failures");

    std::thread::sleep(Duration::from_millis(1500));

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 500, "half-open probe should reach the backend and return 500");

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 503, "circuit should re-open after failed half-open probe");
}
