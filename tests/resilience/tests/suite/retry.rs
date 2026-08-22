// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Resilience tests for HTTP status forwarding and status-based retry.

use praxis_core::config::Config;
use praxis_test_utils::{Backend, free_port, http_get, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn upstream_502_forwarded_without_status_retry_by_default() {
    let backend_port = Backend::status(502, "bad gateway").start();
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
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 502,
        "without Status5xx in policy, upstream 502 should be forwarded"
    );
}

#[test]
fn all_backends_502_returns_502_without_status_retry() {
    let backend_a = Backend::status(502, "bad gateway a").start();
    let backend_b = Backend::status(502, "bad gateway b").start();
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
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_a}"
              - "127.0.0.1:{backend_b}"
insecure_options:
  allow_private_endpoints: true
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    for i in 0..5 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        assert_eq!(
            status, 502,
            "request {i}: without Status5xx, 502 backends are forwarded"
        );
    }
}

#[test]
fn status_5xx_retry_recovers_on_healthy_backend() {
    let failing = Backend::status(503, "unavailable").start();
    let healthy = Backend::fixed("ok").start();
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
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{failing}"
              - "127.0.0.1:{healthy}"
            load_balancer_strategy: round_robin
            retry_policy:
              max_retries: 3
              retriable_conditions: [status_5xx]
              backoff:
                base_interval_ms: 1
                max_interval_ms: 5
insecure_options:
  allow_private_endpoints: true
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "Status5xx policy should retry onto healthy host");
    assert_eq!(body, "ok");
}
