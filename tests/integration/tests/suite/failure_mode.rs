// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Integration tests for per-filter `failure_mode` (open/closed).

use praxis_core::config::Config;
use praxis_filter::{FilterAction, FilterError, HttpFilter, HttpFilterContext};
use praxis_test_utils::{free_port, http_post, registry_with, start_echo_backend, start_proxy_with_registry};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn failure_mode_closed_returns_500() {
    let backend_port = start_echo_backend();
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
      - filter: always_error
        failure_mode: closed
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
    let registry = registry_with("always_error", || Box::new(AlwaysErrorFilter));
    let addr = start_proxy_with_registry(&config, &registry);

    let (status, _) = http_post(&addr, "/anything", "hello");

    assert_eq!(
        status, 500,
        "failure_mode: closed should abort the request with 500 on filter error"
    );
}

#[test]
fn failure_mode_open_continues_to_backend() {
    let backend_port = start_echo_backend();
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
      - filter: always_error
        failure_mode: open
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
    let registry = registry_with("always_error", || Box::new(AlwaysErrorFilter));
    let addr = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(&addr, "/anything", "hello from client");

    assert_eq!(
        status, 200,
        "failure_mode: open should skip the failing filter and reach the backend"
    );
    assert_eq!(body, "hello from client", "backend should echo the request body");
}

#[test]
fn failure_mode_default_is_closed() {
    let backend_port = start_echo_backend();
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
      - filter: always_error
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
    let registry = registry_with("always_error", || Box::new(AlwaysErrorFilter));
    let addr = start_proxy_with_registry(&config, &registry);

    let (status, _) = http_post(&addr, "/anything", "hello");

    assert_eq!(
        status, 500,
        "omitting failure_mode should default to closed (500 on filter error)"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// A filter that always returns `Err` from `on_request`.
struct AlwaysErrorFilter;

#[async_trait::async_trait]
impl HttpFilter for AlwaysErrorFilter {
    fn name(&self) -> &'static str {
        "always_error"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Err("deliberate failure_mode test error".into())
    }
}
