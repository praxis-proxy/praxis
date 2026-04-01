//! Integration tests for filter execution ordering and composition.

use praxis_core::config::Config;
use praxis_filter::{FilterAction, FilterError, HttpFilter, HttpFilterContext};

use crate::common::{
    free_port, http_get, http_send, parse_body, parse_status, start_backend, start_header_echo_backend, start_proxy,
    start_proxy_with_registry,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn multiple_request_filters_all_execute_in_order() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: test_first_request
  - filter: test_second_request
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
    let mut registry = praxis_filter::FilterRegistry::with_builtins();
    registry
        .register(
            "test_first_request",
            praxis_filter::FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(FirstRequestFilter)))),
        )
        .expect("duplicate filter name");
    registry
        .register(
            "test_second_request",
            praxis_filter::FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(SecondRequestFilter)))),
        )
        .expect("duplicate filter name");
    let addr = start_proxy_with_registry(&config, &registry);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("x-first: true"),
        "first filter's header should reach backend, got:\n{body}"
    );
    assert!(
        body_lower.contains("x-second: true"),
        "second filter's header should reach backend, got:\n{body}"
    );
}

#[test]
fn reject_filter_prevents_subsequent_filters_from_executing() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: test_reject_all
  - filter: test_first_request
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
    let mut registry = praxis_filter::FilterRegistry::with_builtins();
    registry
        .register(
            "test_reject_all",
            praxis_filter::FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(RejectAllFilter)))),
        )
        .expect("duplicate filter name");
    registry
        .register(
            "test_first_request",
            praxis_filter::FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(FirstRequestFilter)))),
        )
        .expect("duplicate filter name");
    let addr = start_proxy_with_registry(&config, &registry);

    let (status, _body) = http_get(&addr, "/", None);
    assert_eq!(status, 403, "reject filter should produce 403 before other filters run");
}

#[test]
fn multiple_response_filters_compose_headers() {
    let backend_port = start_backend("composed");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: "backend"
  - filter: load_balancer
    clusters:
      - name: "backend"
        endpoints:
          - "127.0.0.1:{backend_port}"
  - filter: test_response_alpha
  - filter: test_response_beta
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let mut registry = praxis_filter::FilterRegistry::with_builtins();
    registry
        .register(
            "test_response_alpha",
            praxis_filter::FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(ResponseAlphaFilter)))),
        )
        .expect("duplicate filter name");
    registry
        .register(
            "test_response_beta",
            praxis_filter::FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(ResponseBetaFilter)))),
        )
        .expect("duplicate filter name");
    let addr = start_proxy_with_registry(&config, &registry);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let status = parse_status(&raw);
    assert_eq!(status, 200, "composed response should return 200");
    let raw_lower = raw.to_lowercase();
    assert!(
        raw_lower.contains("x-response-a: alpha"),
        "response should contain alpha filter's header, got:\n{raw}"
    );
    assert!(
        raw_lower.contains("x-response-b: beta"),
        "response should contain beta filter's header, got:\n{raw}"
    );
}

#[test]
fn access_log_and_headers_filters_compose() {
    let backend_port = start_backend("composed ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
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
  - filter: headers
    response_add:
      - name: X-Composed
        value: "yes"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET /test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 200, "access_log + headers composition should return 200");
    assert!(
        raw.to_lowercase().contains("x-composed: yes"),
        "headers filter should add header alongside access_log, got:\n{raw}"
    );
    let body = parse_body(&raw);
    assert_eq!(body, "composed ok", "body should pass through both filters unchanged");
}

#[test]
fn request_id_and_headers_filters_compose() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: request_id
  - filter: headers
    request_add:
      - name: X-Custom
        value: "injected"
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
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let status = parse_status(&raw);
    assert_eq!(status, 200, "request_id + headers composition should return 200");

    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("x-request-id:"),
        "request_id filter should inject X-Request-Id into upstream request, got:\n{body}"
    );
    assert!(
        body_lower.contains("x-custom: injected"),
        "headers filter should add X-Custom to request, got:\n{body}"
    );
}

#[test]
fn conditional_filter_does_not_affect_unconditional_filters() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: headers
    conditions:
      - when:
          path_prefix: "/api/"
    request_add:
      - name: X-Api-Only
        value: "true"
  - filter: headers
    request_add:
      - name: X-Always
        value: "present"
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
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET /other HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    assert!(
        !body_lower.contains("x-api-only"),
        "conditional filter should not fire on /other path, got:\n{body}"
    );
    assert!(
        body_lower.contains("x-always: present"),
        "unconditional filter should still fire on /other path, got:\n{body}"
    );

    let raw = http_send(
        &addr,
        "GET /api/data HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("x-api-only: true"),
        "conditional filter should fire on /api/ path, got:\n{body}"
    );
    assert!(
        body_lower.contains("x-always: present"),
        "unconditional filter should still fire on /api/ path, got:\n{body}"
    );
}

// -----------------------------------------------------------------------------
// Test Filters
// -----------------------------------------------------------------------------

/// A filter that adds `X-First: true` during the request phase.
struct FirstRequestFilter;

#[async_trait::async_trait]
impl HttpFilter for FirstRequestFilter {
    fn name(&self) -> &'static str {
        "test_first_request"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        ctx.extra_request_headers
            .push((std::borrow::Cow::Borrowed("X-First"), "true".to_owned()));
        Ok(FilterAction::Continue)
    }
}

/// A filter that adds `X-Second: true` during the request phase.
struct SecondRequestFilter;

#[async_trait::async_trait]
impl HttpFilter for SecondRequestFilter {
    fn name(&self) -> &'static str {
        "test_second_request"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        ctx.extra_request_headers
            .push((std::borrow::Cow::Borrowed("X-Second"), "true".to_owned()));
        Ok(FilterAction::Continue)
    }
}

/// A filter that rejects all requests with 403.
struct RejectAllFilter;

#[async_trait::async_trait]
impl HttpFilter for RejectAllFilter {
    fn name(&self) -> &'static str {
        "test_reject_all"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Reject(praxis_filter::Rejection::status(403)))
    }
}

/// A filter that adds `X-Response-A: alpha` during the response phase.
struct ResponseAlphaFilter;

#[async_trait::async_trait]
impl HttpFilter for ResponseAlphaFilter {
    fn name(&self) -> &'static str {
        "test_response_alpha"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if let Some(resp) = ctx.response_header.as_mut() {
            resp.headers.insert("X-Response-A", "alpha".parse().unwrap());
        }
        Ok(FilterAction::Continue)
    }
}

/// A filter that adds `X-Response-B: beta` during the response phase.
struct ResponseBetaFilter;

#[async_trait::async_trait]
impl HttpFilter for ResponseBetaFilter {
    fn name(&self) -> &'static str {
        "test_response_beta"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if let Some(resp) = ctx.response_header.as_mut() {
            resp.headers.insert("X-Response-B", "beta".parse().unwrap());
        }
        Ok(FilterAction::Continue)
    }
}
