// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for proxy error forwarding when backends return 5xx
//! responses. Praxis does not support cluster-level retry
//! configuration; upstream errors are forwarded directly.

use praxis_core::config::Config;
use praxis_test_utils::{Backend, free_port, http_get, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn upstream_502_forwarded_without_retry() {
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
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 502, "upstream 502 should be forwarded to client without retry");
}

#[test]
fn all_backends_502_returns_502() {
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
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    for i in 0..5 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        assert_eq!(
            status, 502,
            "request {i} to all-502 backends should consistently return 502"
        );
    }
}
