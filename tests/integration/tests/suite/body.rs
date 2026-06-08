// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Tests for request and response body filtering.

use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{BodyAccess, BodyMode, FilterAction, FilterError, HttpFilter, HttpFilterContext, Rejection};
use praxis_test_utils::{
    custom_filter_yaml, free_port, http_post, http_send, parse_status, registry_with, simple_proxy_yaml,
    start_backend_with_shutdown, start_echo_backend, start_proxy, start_proxy_with_registry,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn body_passthrough_without_body_filters() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&simple_proxy_yaml(proxy_port, backend_port)).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_post(proxy.addr(), "/echo", "hello world");

    assert_eq!(status, 200, "passthrough should return 200");
    assert_eq!(body, "hello world", "body should pass through unmodified");
}

#[test]
fn body_uppercase_filter_transforms_request_body() {
    let backend_guard = start_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "body_uppercase")).unwrap();
    let registry = registry_with("body_uppercase", || Box::new(BodyUppercaseFilter::streaming()));
    let proxy = start_proxy_with_registry(&config, &registry);
    let (status, body) = http_post(proxy.addr(), "/echo", "hello world");

    assert_eq!(status, 200, "uppercase filter should return 200");
    assert_eq!(body, "HELLO WORLD", "body should be uppercased by filter");
}

#[test]
fn body_reject_filter_blocks_forbidden_content() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "body_reject")).unwrap();
    let registry = registry_with("body_reject", || Box::new(BodyRejectFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, _) = http_post(proxy.addr(), "/upload", "this is FORBIDDEN content");

    assert_eq!(status, 403, "forbidden content should be rejected with 403");
}

#[test]
fn body_reject_filter_allows_clean_content() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "body_reject")).unwrap();
    let registry = registry_with("body_reject", || Box::new(BodyRejectFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/upload", "this is clean content");

    assert_eq!(status, 200, "clean content should return 200");
    assert_eq!(body, "this is clean content", "clean body should pass through");
}

#[test]
fn body_buffer_mode_delivers_complete_body() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "body_buffered_uppercase")).unwrap();
    let registry = registry_with("body_buffered_uppercase", || {
        Box::new(BodyUppercaseFilter::buffered(1024))
    });
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "hello world");

    assert_eq!(status, 200, "buffered uppercase should return 200");
    assert_eq!(body, "HELLO WORLD", "buffered body should be uppercased");
}

#[test]
fn body_size_limit_returns_413() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "body_tiny_buffer")).unwrap();
    let registry = registry_with("body_tiny_buffer", || Box::new(TinyBufferFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, _) = http_post(proxy.addr(), "/upload", "this body is too large");

    assert_eq!(status, 413, "oversized body should be rejected with 413");
}

#[test]
fn async_body_filter_performs_async_work() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "async_body")).unwrap();
    let registry = registry_with("async_body", || Box::new(AsyncBodyFilter));
    let proxy = start_proxy_with_registry(&config, &registry);
    let (status, body) = http_post(proxy.addr(), "/echo", "async works");

    assert_eq!(status, 200, "async body filter should return 200");
    assert_eq!(body, "ASYNC WORKS", "async body filter should uppercase content");
}

#[test]
fn body_response_reject_filter_aborts_forbidden_response() {
    let backend_port_guard = start_backend_with_shutdown("this FORBIDDEN response must not reach the client");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "response_body_reject")).unwrap();
    let registry = registry_with("response_body_reject", || Box::new(ResponseBodyRejectFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = praxis_test_utils::http_get(proxy.addr(), "/", None);

    assert_ne!(status, 200, "rejection should not return 200");
    assert!(
        !body.contains("FORBIDDEN"),
        "forbidden response body must not reach the client; got: {body:?}"
    );
}

#[test]
fn body_response_reject_filter_allows_clean_response() {
    let backend_port_guard = start_backend_with_shutdown("this is a clean response");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "response_body_reject")).unwrap();
    let registry = registry_with("response_body_reject", || Box::new(ResponseBodyRejectFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = praxis_test_utils::http_get(proxy.addr(), "/", None);

    assert_eq!(status, 200, "clean response should return 200");
    assert_eq!(
        body, "this is a clean response",
        "clean response body should pass through"
    );
}

#[test]
fn body_uppercase_filter_transforms_response_body() {
    let backend_port_guard = start_backend_with_shutdown("hello world");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "response_body_uppercase")).unwrap();
    let registry = registry_with("response_body_uppercase", || Box::new(ResponseBodyUppercaseFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = praxis_test_utils::http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "response uppercase should return 200");
    assert_eq!(body, "HELLO WORLD", "response body should be uppercased");
}

#[test]
fn filter_error_in_on_request_returns_500() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "error_on_request")).unwrap();
    let registry = registry_with("error_on_request", || Box::new(ErrorOnRequestFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, _) = http_post(proxy.addr(), "/anything", "hello");

    assert_eq!(
        status, 500,
        "filter returning Err(FilterError) from on_request should produce 500"
    );
}

#[test]
fn filter_error_in_request_body_returns_500() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "error_on_body")).unwrap();
    let registry = registry_with("error_on_body", || Box::new(ErrorOnBodyFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, _) = http_post(proxy.addr(), "/upload", "some payload");

    assert_eq!(
        status, 500,
        "filter returning Err(FilterError) from on_request_body should produce 500"
    );
}

#[test]
fn filter_rejection_with_custom_status_propagates() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "reject_418")).unwrap();
    let registry = registry_with("reject_418", || Box::new(Reject418Filter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, _) = http_post(proxy.addr(), "/teapot", "brew");

    assert_eq!(
        status, 418,
        "filter rejecting with 418 should propagate that status to the client"
    );
}

#[test]
fn body_size_limit_without_content_length_enforced() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&body_limit_yaml(proxy_port, backend_port, 16)).unwrap();
    let proxy = start_proxy(&config);

    let oversized = "x".repeat(64);
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST /echo HTTP/1.1\r\n\
             Host: localhost\r\n\
             Transfer-Encoding: chunked\r\n\
             Connection: close\r\n\r\n\
             {chunk_size:x}\r\n\
             {oversized}\r\n\
             0\r\n\r\n",
            chunk_size = oversized.len(),
        ),
    );
    let status = parse_status(&raw);

    assert_eq!(
        status, 413,
        "chunked body exceeding limit without Content-Length should be rejected with 413"
    );
}

#[test]
fn response_body_over_limit_returns_error() {
    let large_body = "z".repeat(512);
    let backend_port_guard = start_backend_with_shutdown(&large_body);
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&body_limit_yaml_response(proxy_port, backend_port, 64)).unwrap();
    let registry = registry_with("response_body_reject_large", || Box::new(ResponseBodyLimitCheckFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = praxis_test_utils::http_get(proxy.addr(), "/", None);

    assert!(
        status == 502 || status == 500 || body.len() <= 64,
        "response exceeding limit should be rejected or truncated; got status={status} body_len={}",
        body.len()
    );
}

#[test]
fn body_size_limit_under_limit_succeeds() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&body_limit_yaml(proxy_port, backend_port, 64)).unwrap();
    let proxy = start_proxy(&config);

    let payload = "a".repeat(32);
    let (status, body) = http_post(proxy.addr(), "/echo", &payload);

    assert_eq!(status, 200, "32-byte body under 64-byte limit should succeed");
    assert_eq!(body, payload, "body well under the limit should be forwarded intact");
}

#[test]
fn body_size_limit_exact_boundary_succeeds() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&body_limit_yaml(proxy_port, backend_port, 64)).unwrap();
    let proxy = start_proxy(&config);

    let payload = "b".repeat(64);
    let (status, body) = http_post(proxy.addr(), "/echo", &payload);

    assert_eq!(status, 200, "64-byte body at exactly the 64-byte limit should succeed");
    assert_eq!(body, payload, "body exactly at the limit should be forwarded intact");
}

#[test]
fn body_size_limit_one_byte_over_rejected() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&body_limit_yaml(proxy_port, backend_port, 64)).unwrap();
    let proxy = start_proxy(&config);

    let payload = "c".repeat(65);
    let (status, _) = http_post(proxy.addr(), "/echo", &payload);

    assert_eq!(
        status, 413,
        "65-byte body exceeding 64-byte limit by one byte should be rejected with 413"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// A filter that rejects response bodies containing "FORBIDDEN".
struct ResponseBodyRejectFilter;

#[async_trait::async_trait]
impl HttpFilter for ResponseBodyRejectFilter {
    fn name(&self) -> &'static str {
        "response_body_reject"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn response_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(1_048_576),
        }
    }

    fn on_response_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        if let Some(b) = body
            && b.windows(9).any(|w| w == b"FORBIDDEN")
        {
            return Ok(FilterAction::Reject(Rejection::status(502)));
        }

        Ok(FilterAction::Continue)
    }
}

/// A filter that uppercases request body chunks.
/// When constructed with a buffer limit it upgrades the per-request
/// body mode to StreamBuffer during `on_request` (Option B), so
/// the body is buffered inline rather than via the pre-read path.
struct BodyUppercaseFilter {
    /// Per-request StreamBuffer limit, or `None` for pure streaming.
    buffer_limit: Option<usize>,
}

impl BodyUppercaseFilter {
    fn streaming() -> Self {
        Self { buffer_limit: None }
    }

    fn buffered(max_bytes: usize) -> Self {
        Self {
            buffer_limit: Some(max_bytes),
        }
    }
}

#[async_trait::async_trait]
impl HttpFilter for BodyUppercaseFilter {
    fn name(&self) -> &'static str {
        "body_uppercase"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if let Some(limit) = self.buffer_limit {
            ctx.set_request_body_mode(BodyMode::StreamBuffer { max_bytes: Some(limit) });
        }
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if self.buffer_limit.is_some() && !end_of_stream {
            return Ok(FilterAction::Continue);
        }
        if let Some(b) = body {
            let upper: Vec<u8> = b.iter().map(|c| c.to_ascii_uppercase()).collect();
            *b = Bytes::from(upper);
        }

        Ok(FilterAction::Continue)
    }
}

/// A filter with a 5-byte StreamBuffer limit, used to test 413 rejection.
struct TinyBufferFilter;

#[async_trait::async_trait]
impl HttpFilter for TinyBufferFilter {
    fn name(&self) -> &'static str {
        "body_tiny_buffer"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        ctx.set_request_body_mode(BodyMode::StreamBuffer { max_bytes: Some(5) });
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }
        Ok(FilterAction::Continue)
    }
}

/// A filter that rejects request bodies containing "FORBIDDEN".
struct BodyRejectFilter;

#[async_trait::async_trait]
impl HttpFilter for BodyRejectFilter {
    fn name(&self) -> &'static str {
        "body_reject"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body
            && b.windows(9).any(|w| w == b"FORBIDDEN")
        {
            return Ok(FilterAction::Reject(Rejection::status(403)));
        }

        Ok(FilterAction::Continue)
    }
}

/// A filter that performs async I/O during request body processing.
struct AsyncBodyFilter;

#[async_trait::async_trait]
impl HttpFilter for AsyncBodyFilter {
    fn name(&self) -> &'static str {
        "async_body"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        tokio::task::yield_now().await;

        if let Some(b) = body {
            let upper: Vec<u8> = b.iter().map(|c| c.to_ascii_uppercase()).collect();
            *b = Bytes::from(upper);
        }

        Ok(FilterAction::Continue)
    }
}

/// A filter that uppercases response body chunks.
struct ResponseBodyUppercaseFilter;

#[async_trait::async_trait]
impl HttpFilter for ResponseBodyUppercaseFilter {
    fn name(&self) -> &'static str {
        "response_body_uppercase"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn on_response_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body {
            let upper: Vec<u8> = b.iter().map(|c| c.to_ascii_uppercase()).collect();
            *b = Bytes::from(upper);
        }

        Ok(FilterAction::Continue)
    }
}

/// A filter that always returns `Err` from `on_request`.
struct ErrorOnRequestFilter;

#[async_trait::async_trait]
impl HttpFilter for ErrorOnRequestFilter {
    fn name(&self) -> &'static str {
        "error_on_request"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Err("deliberate filter error in on_request".into())
    }
}

/// A filter that always returns `Err` from `on_request_body`.
struct ErrorOnBodyFilter;

#[async_trait::async_trait]
impl HttpFilter for ErrorOnBodyFilter {
    fn name(&self) -> &'static str {
        "error_on_body"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        Err("deliberate filter error in on_request_body".into())
    }
}

/// A filter that rejects all requests with HTTP 418.
struct Reject418Filter;

#[async_trait::async_trait]
impl HttpFilter for Reject418Filter {
    fn name(&self) -> &'static str {
        "reject_418"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Reject(Rejection::status(418)))
    }
}

/// A filter that rejects response bodies exceeding a small threshold.
struct ResponseBodyLimitCheckFilter;

#[async_trait::async_trait]
impl HttpFilter for ResponseBodyLimitCheckFilter {
    fn name(&self) -> &'static str {
        "response_body_reject_large"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn response_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(1_048_576),
        }
    }

    fn on_response_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }
        if let Some(b) = body
            && b.len() > 64
        {
            return Ok(FilterAction::Reject(Rejection::status(502)));
        }
        Ok(FilterAction::Continue)
    }
}

/// YAML config with `body_limits.max_request_bytes` set to the given limit.
fn body_limit_yaml(proxy_port: u16, backend_port: u16, limit: usize) -> String {
    format!(
        r#"
body_limits:
  max_request_bytes: {limit}
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
"#
    )
}

/// YAML config with `body_limits.max_response_bytes` and a custom response filter.
fn body_limit_yaml_response(proxy_port: u16, backend_port: u16, limit: usize) -> String {
    format!(
        r#"
body_limits:
  max_response_bytes: {limit}
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: response_body_reject_large
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

// -----------------------------------------------------------------------------
// StreamBuffer Large-Body Regression (#75)
// -----------------------------------------------------------------------------

#[test]
fn stream_buffer_body_above_64kib_forwarded_intact() {
    let backend_guard = start_echo_backend();
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
      - filter: json_rpc
        max_body_bytes: 131072
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{}"
"#,
        backend_guard.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"test","params":{{"data":"{}"}}}}"#,
        "x".repeat(70_000)
    );
    let request = format!(
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {payload}",
        payload.len(),
    );

    let raw = http_send(proxy.addr(), &request);
    let status = parse_status(&raw);
    assert_eq!(status, 200, "request should succeed");

    let echoed = praxis_test_utils::parse_body(&raw);
    assert_eq!(
        echoed.len(),
        payload.len(),
        "backend should receive the full body ({} bytes), but got {} bytes — \
         Pingora retry buffer truncates at 64 KiB (BODY_BUF_LIMIT)",
        payload.len(),
        echoed.len()
    );
}
