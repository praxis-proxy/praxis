// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for timeout filter behavior.

use std::time::Duration;

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_proxy, start_slow_backend};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn timeout() {
    let fast_port_guard = start_backend_with_shutdown("fast");
    let fast_port = fast_port_guard.port();
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
      - filter: timeout
        timeout_ms: 200
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{fast_port}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "fast backend should return 200 within timeout");
    assert_eq!(body, "fast", "fast backend response should pass through");

    let slow_port = start_slow_backend("slow", Duration::from_secs(2));
    let proxy_port2 = free_port();
    let yaml2 = format!(
        r#"
listeners:
  - name: slow
    address: "127.0.0.1:{proxy_port2}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: timeout
        timeout_ms: 200
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{slow_port}"
"#
    );
    let config2 = Config::from_yaml(&yaml2).unwrap();
    let proxy2 = start_proxy(&config2);
    let (status, body) = http_get(proxy2.addr(), "/", None);
    assert_eq!(status, 504, "slow backend should trigger timeout");
    assert!(
        !body.contains("slow"),
        "timeout body should not contain backend response"
    );
}
