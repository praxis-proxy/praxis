// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for per-filter `failure_mode` (open/closed).

use std::sync::Arc;

use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext,
};
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
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, _) = http_post(proxy.addr(), "/anything", "hello");

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
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/anything", "hello from client");

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
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, _) = http_post(proxy.addr(), "/anything", "hello");

    assert_eq!(
        status, 500,
        "omitting failure_mode should default to closed (500 on filter error)"
    );
}

#[test]
fn failure_mode_open_on_response_error_still_returns_200() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let yaml = make_yaml(proxy_port, backend_port, "response_error", "open");
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("response_error", || Box::new(ResponseErrorFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/", "hello");

    assert_eq!(
        status, 200,
        "failure_mode: open on_response error should still return 200"
    );
    assert_eq!(body, "hello", "backend should echo the request body");
}

#[test]
fn mixed_chain_open_skipped_closed_blocks() {
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
      - filter: open_error
        failure_mode: open
      - filter: closed_error
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
    let mut registry = FilterRegistry::with_builtins();
    register_test_filter(&mut registry, "open_error", || Box::new(AlwaysErrorFilter));
    register_test_filter(&mut registry, "closed_error", || Box::new(AlwaysErrorFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, _) = http_post(proxy.addr(), "/", "hello");

    assert_eq!(
        status, 500,
        "open filter should be skipped but closed filter should still block"
    );
}

#[test]
fn failure_mode_open_on_request_body_error_still_succeeds() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let yaml = make_yaml(proxy_port, backend_port, "body_error", "open");
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("body_error", || Box::new(RequestBodyErrorFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/", "hello");

    assert_eq!(
        status, 200,
        "failure_mode: open on_request_body error should still return 200"
    );
    assert_eq!(body, "hello", "backend should echo the request body");
}

#[test]
fn failure_mode_open_on_response_body_error_still_succeeds() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let yaml = make_yaml(proxy_port, backend_port, "resp_body_error", "open");
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("resp_body_error", || Box::new(ResponseBodyErrorFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, _body) = http_post(proxy.addr(), "/", "hello");

    assert_eq!(
        status, 200,
        "failure_mode: open on_response_body error should still return 200"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build YAML config with a single custom filter and explicit failure mode.
fn make_yaml(proxy_port: u16, backend_port: u16, filter: &str, mode: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: {filter}
        failure_mode: {mode}
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
    )
}

/// Register a custom test filter in the given registry.
fn register_test_filter(registry: &mut FilterRegistry, name: &str, make: fn() -> Box<dyn HttpFilter>) {
    registry
        .register(name, FilterFactory::Http(Arc::new(move |_| Ok(make()))))
        .unwrap();
}

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

/// A filter that passes `on_request` but errors in `on_request_body`.
struct RequestBodyErrorFilter;

#[async_trait::async_trait]
impl HttpFilter for RequestBodyErrorFilter {
    fn name(&self) -> &'static str {
        "body_error"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(1_048_576),
        }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        Err("deliberate on_request_body error".into())
    }
}

/// A filter that passes request/response but errors in `on_response_body`.
struct ResponseBodyErrorFilter;

#[async_trait::async_trait]
impl HttpFilter for ResponseBodyErrorFilter {
    fn name(&self) -> &'static str {
        "resp_body_error"
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        Err("deliberate on_response_body error".into())
    }
}

/// A filter that passes `on_request` but errors in `on_response`.
struct ResponseErrorFilter;

#[async_trait::async_trait]
impl HttpFilter for ResponseErrorFilter {
    fn name(&self) -> &'static str {
        "response_error"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Err("deliberate on_response error".into())
    }
}
