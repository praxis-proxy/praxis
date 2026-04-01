use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{BodyAccess, BodyMode, FilterAction, FilterError, HttpFilter, HttpFilterContext, Rejection};

use crate::common::{
    custom_filter_yaml, free_port, http_post, registry_with, simple_proxy_yaml, start_echo_backend, start_proxy,
    start_proxy_with_registry,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn body_passthrough_without_body_filters() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&simple_proxy_yaml(proxy_port, backend_port)).unwrap();
    let addr = start_proxy(&config);

    let (status, body) = http_post(&addr, "/echo", "hello world");

    assert_eq!(status, 200, "passthrough should return 200");
    assert_eq!(body, "hello world", "body should pass through unmodified");
}

#[test]
fn body_uppercase_filter_transforms_request_body() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "body_uppercase")).unwrap();
    let registry = registry_with("body_uppercase", || Box::new(BodyUppercaseFilter::streaming()));
    let addr = start_proxy_with_registry(&config, &registry);
    let (status, body) = http_post(&addr, "/echo", "hello world");

    assert_eq!(status, 200, "uppercase filter should return 200");
    assert_eq!(body, "HELLO WORLD", "body should be uppercased by filter");
}

#[test]
fn body_reject_filter_blocks_forbidden_content() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "body_reject")).unwrap();
    let registry = registry_with("body_reject", || Box::new(BodyRejectFilter));
    let addr = start_proxy_with_registry(&config, &registry);

    let (status, _) = http_post(&addr, "/upload", "this is FORBIDDEN content");

    assert_eq!(status, 403, "forbidden content should be rejected with 403");
}

#[test]
fn body_reject_filter_allows_clean_content() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "body_reject")).unwrap();
    let registry = registry_with("body_reject", || Box::new(BodyRejectFilter));
    let addr = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(&addr, "/upload", "this is clean content");

    assert_eq!(status, 200, "clean content should return 200");
    assert_eq!(body, "this is clean content", "clean body should pass through");
}

#[test]
fn body_buffer_mode_delivers_complete_body() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "body_buffered_uppercase")).unwrap();
    let registry = registry_with("body_buffered_uppercase", || {
        Box::new(BodyUppercaseFilter::buffered(1024))
    });
    let addr = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(&addr, "/echo", "hello world");

    assert_eq!(status, 200, "buffered uppercase should return 200");
    assert_eq!(body, "HELLO WORLD", "buffered body should be uppercased");
}

#[test]
fn body_size_limit_returns_413() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "body_tiny_buffer")).unwrap();
    let registry = registry_with("body_tiny_buffer", || Box::new(TinyBufferFilter));
    let addr = start_proxy_with_registry(&config, &registry);

    let (status, _) = http_post(&addr, "/upload", "this body is too large");

    assert_eq!(status, 413, "oversized body should be rejected with 413");
}

#[test]
fn async_body_filter_performs_async_work() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "async_body")).unwrap();
    let registry = registry_with("async_body", || Box::new(AsyncBodyFilter));
    let addr = start_proxy_with_registry(&config, &registry);
    let (status, body) = http_post(&addr, "/echo", "async works");

    assert_eq!(status, 200, "async body filter should return 200");
    assert_eq!(body, "ASYNC WORKS", "async body filter should uppercase content");
}

#[test]
fn body_response_reject_filter_aborts_forbidden_response() {
    let backend_port = crate::common::start_backend("this FORBIDDEN response must not reach the client");
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "response_body_reject")).unwrap();
    let registry = registry_with("response_body_reject", || Box::new(ResponseBodyRejectFilter));
    let addr = start_proxy_with_registry(&config, &registry);

    let (status, body) = crate::common::http_get(&addr, "/", None);

    assert_ne!(status, 200, "rejection should not return 200");
    assert!(
        !body.contains("FORBIDDEN"),
        "forbidden response body must not reach the client; got: {body:?}"
    );
}

#[test]
fn body_response_reject_filter_allows_clean_response() {
    let backend_port = crate::common::start_backend("this is a clean response");
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "response_body_reject")).unwrap();
    let registry = registry_with("response_body_reject", || Box::new(ResponseBodyRejectFilter));
    let addr = start_proxy_with_registry(&config, &registry);

    let (status, body) = crate::common::http_get(&addr, "/", None);

    assert_eq!(status, 200, "clean response should return 200");
    assert_eq!(
        body, "this is a clean response",
        "clean response body should pass through"
    );
}

#[test]
fn body_uppercase_filter_transforms_response_body() {
    let backend_port = crate::common::start_backend("hello world");
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "response_body_uppercase")).unwrap();
    let registry = registry_with("response_body_uppercase", || Box::new(ResponseBodyUppercaseFilter));
    let addr = start_proxy_with_registry(&config, &registry);

    let (status, body) = crate::common::http_get(&addr, "/", None);
    assert_eq!(status, 200, "response uppercase should return 200");
    assert_eq!(body, "HELLO WORLD", "response body should be uppercased");
}

#[test]
fn body_size_limit_under_limit_succeeds() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&body_limit_yaml(proxy_port, backend_port, 64)).unwrap();
    let addr = start_proxy(&config);

    let payload = "a".repeat(32);
    let (status, body) = http_post(&addr, "/echo", &payload);

    assert_eq!(status, 200, "32-byte body under 64-byte limit should succeed");
    assert_eq!(body, payload, "body well under the limit should be forwarded intact");
}

#[test]
fn body_size_limit_exact_boundary_succeeds() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&body_limit_yaml(proxy_port, backend_port, 64)).unwrap();
    let addr = start_proxy(&config);

    let payload = "b".repeat(64);
    let (status, body) = http_post(&addr, "/echo", &payload);

    assert_eq!(status, 200, "64-byte body at exactly the 64-byte limit should succeed");
    assert_eq!(body, payload, "body exactly at the limit should be forwarded intact");
}

#[test]
fn body_size_limit_one_byte_over_rejected() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&body_limit_yaml(proxy_port, backend_port, 64)).unwrap();
    let addr = start_proxy(&config);

    let payload = "c".repeat(65);
    let (status, _) = http_post(&addr, "/echo", &payload);

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
        BodyMode::Buffer { max_bytes: 1024 * 1024 }
    }

    fn on_response_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body {
            if b.windows(9).any(|w| w == b"FORBIDDEN") {
                return Ok(FilterAction::Reject(Rejection::status(502)));
            }
        }

        Ok(FilterAction::Continue)
    }
}

/// A filter that uppercases request body chunks.
/// When constructed with a `Buffer` mode it buffers the full body first.
struct BodyUppercaseFilter {
    mode: BodyMode,
}

impl BodyUppercaseFilter {
    fn streaming() -> Self {
        Self { mode: BodyMode::Stream }
    }

    fn buffered(max_bytes: usize) -> Self {
        Self {
            mode: BodyMode::Buffer { max_bytes },
        }
    }
}

#[async_trait::async_trait]
impl HttpFilter for BodyUppercaseFilter {
    fn name(&self) -> &'static str {
        "body_uppercase"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        self.mode
    }

    async fn on_request_body(
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

/// A filter with a 5-byte buffer limit, used to test 413 rejection.
struct TinyBufferFilter;

#[async_trait::async_trait]
impl HttpFilter for TinyBufferFilter {
    fn name(&self) -> &'static str {
        "body_tiny_buffer"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::Buffer { max_bytes: 5 }
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
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
        if let Some(b) = body {
            if b.windows(9).any(|w| w == b"FORBIDDEN") {
                return Ok(FilterAction::Reject(Rejection::status(403)));
            }
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

/// YAML config with `max_request_body_bytes` set to the given limit.
fn body_limit_yaml(proxy_port: u16, backend_port: u16, limit: usize) -> String {
    format!(
        r#"
max_request_body_bytes: {limit}
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
routes:
  - path_prefix: "/"
    cluster: "backend"
clusters:
  - name: "backend"
    endpoints:
      - "127.0.0.1:{backend_port}"
"#
    )
}
