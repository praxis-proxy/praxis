// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Response filter and access log tests.

use praxis_core::config::Config;
use praxis_filter::{FilterAction, FilterError, HttpFilter, HttpFilterContext};
use praxis_test_utils::{
    free_port, http_get, http_send, registry_with, start_backend_with_shutdown, start_proxy_with_registry,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn response_filter_executes() {
    let backend_port_guard = start_backend_with_shutdown("filtered response");
    let backend_port = backend_port_guard.port();
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
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
      - filter: test_response_header
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("test_response_header", || Box::new(ResponseHeaderFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let host_header = "localhost";
    let raw = http_send(
        proxy.addr(),
        &format!("GET / HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"),
    );
    let raw_lower = raw.to_lowercase();
    assert!(
        raw_lower.contains("x-praxis-filtered: true"),
        "response should contain header set by on_response filter, got:\n{raw}"
    );

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "response filter should still return 200");
    assert_eq!(body, "filtered response", "response body should pass through filter");
}

#[test]
fn access_log_filter_processes_request() {
    let backend_port_guard = start_backend_with_shutdown("logged response");
    let backend_port = backend_port_guard.port();
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
      - filter: access_log
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
    let proxy = praxis_test_utils::start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/api/test", None);
    assert_eq!(status, 200, "access_log filter should not change status");
    assert_eq!(body, "logged response", "access_log filter should not alter body");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// A test filter that adds a custom header during the response phase.
struct ResponseHeaderFilter;

#[async_trait::async_trait]
impl HttpFilter for ResponseHeaderFilter {
    fn name(&self) -> &'static str {
        "test_response_header"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if let Some(resp) = ctx.response_header.as_mut() {
            resp.headers.insert("X-Praxis-Filtered", "true".parse().unwrap());
        }

        Ok(FilterAction::Continue)
    }
}
