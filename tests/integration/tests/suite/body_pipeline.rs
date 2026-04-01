//! Integration tests for multi-filter body pipelines exercising
//! Stream, Buffer, and StreamBuffer modes.
//!
//! Each listener runs a pipeline of three body filters to verify
//! correct chaining, mode aggregation, routing, and payload
//! integrity.

use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext,
    Rejection,
};

use crate::common::{
    free_port, free_port_guard, http_post, http_send, parse_body, parse_status, start_backend, start_echo_backend,
    start_proxy_with_registry, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests: Stream Mode (3 filters)
// -----------------------------------------------------------------------------

#[test]
fn stream_pipeline_transforms_body_through_three_filters() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&stream_pipeline_yaml(proxy_port, backend_port)).unwrap();
    let registry = stream_registry();
    let addr = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(&addr, "/echo", "hello world");

    assert_eq!(status, 200, "stream pipeline should return 200");
    assert_eq!(
        body, "HELLO WORLD",
        "body should be uppercased after passing through 3 stream filters"
    );
}

#[test]
fn stream_pipeline_rejects_blocked_content() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&stream_pipeline_yaml(proxy_port, backend_port)).unwrap();
    let registry = stream_registry();
    let addr = start_proxy_with_registry(&config, &registry);

    let (status, _) = http_post(&addr, "/echo", "this is BLOCKED content");

    assert_eq!(status, 403, "stream pipeline should reject BLOCKED content");
}

#[test]
fn stream_pipeline_allows_clean_content() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&stream_pipeline_yaml(proxy_port, backend_port)).unwrap();
    let registry = stream_registry();
    let addr = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(&addr, "/echo", "clean content");

    assert_eq!(status, 200, "clean content should pass stream pipeline");
    assert_eq!(body, "CLEAN CONTENT", "clean body should be uppercased");
}

// -----------------------------------------------------------------------------
// Tests: Buffer Mode (3 filters)
// -----------------------------------------------------------------------------

#[test]
fn buffer_pipeline_transforms_complete_body() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&buffer_pipeline_yaml(proxy_port, backend_port)).unwrap();
    let registry = buffer_registry();
    let addr = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(&addr, "/echo", "hello world");

    assert_eq!(status, 200, "buffer pipeline should return 200");
    assert_eq!(
        body, "HELLO WORLD",
        "buffered body should be uppercased after passing through 3 buffer filters"
    );
}

#[test]
fn buffer_pipeline_rejects_oversized_body() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&buffer_pipeline_yaml(proxy_port, backend_port)).unwrap();
    let registry = buffer_registry();
    let addr = start_proxy_with_registry(&config, &registry);

    let payload = "x".repeat(200);
    let (status, _) = http_post(&addr, "/echo", &payload);

    assert_eq!(status, 413, "body exceeding buffer limit should be rejected with 413");
}

#[test]
fn buffer_pipeline_exact_boundary_succeeds() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&buffer_pipeline_yaml(proxy_port, backend_port)).unwrap();
    let registry = buffer_registry();
    let addr = start_proxy_with_registry(&config, &registry);

    let payload = "a".repeat(128);
    let (status, body) = http_post(&addr, "/echo", &payload);

    assert_eq!(status, 200, "body at exact buffer limit should succeed");
    assert_eq!(body, "A".repeat(128), "body at boundary should be fully uppercased");
}

#[test]
fn buffer_pipeline_rejects_forbidden_content() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&buffer_pipeline_yaml(proxy_port, backend_port)).unwrap();
    let registry = buffer_registry();
    let addr = start_proxy_with_registry(&config, &registry);

    let (status, _) = http_post(&addr, "/echo", "BLOCKED payload");

    assert_eq!(status, 403, "buffer pipeline should reject content containing BLOCKED");
}

// -----------------------------------------------------------------------------
// Tests: StreamBuffer Mode (3 filters)
// -----------------------------------------------------------------------------

#[test]
fn stream_buffer_pipeline_extracts_and_routes() {
    let claude_port = start_backend("claude-response");
    let default_port = start_backend("default-response");
    let proxy_port = free_port();
    let config = Config::from_yaml(&stream_buffer_routing_yaml(proxy_port, claude_port, default_port)).unwrap();
    let addr = crate::common::start_proxy(&config);

    let raw = http_send(
        &addr,
        &json_post(
            "/v1/chat",
            r#"{"model":"claude-sonnet-4-5","user_id":"u-1","prompt":"hi"}"#,
        ),
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "stream-buffer claude-sonnet-4-5 routing should return 200"
    );
    assert_eq!(
        parse_body(&raw),
        "claude-response",
        "model=claude-sonnet-4-5 should route to claude_sonnet cluster"
    );
}

#[test]
fn stream_buffer_pipeline_fallback_routing() {
    let claude_port = start_backend("claude-response");
    let default_port = start_backend("default-response");
    let proxy_port = free_port();
    let config = Config::from_yaml(&stream_buffer_routing_yaml(proxy_port, claude_port, default_port)).unwrap();
    let addr = crate::common::start_proxy(&config);

    let raw = http_send(&addr, &json_post("/v1/chat", r#"{"model":"unknown","user_id":"u-1"}"#));
    assert_eq!(parse_status(&raw), 200, "unknown model routing should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-response",
        "unknown model should route to default cluster"
    );
}

// -----------------------------------------------------------------------------
// Tests: Multi-Listener (all modes on one server)
// -----------------------------------------------------------------------------

#[test]
fn multi_listener_each_mode_processes_independently() {
    let echo_port = start_echo_backend();
    let stream_guard = free_port_guard();
    let buffer_guard = free_port_guard();
    let passthrough_guard = free_port_guard();

    let yaml = format!(
        r#"
listeners:
  - name: stream
    address: "127.0.0.1:{stream_guard}"
  - name: buffer
    address: "127.0.0.1:{buffer_guard}"
  - name: passthrough
    address: "127.0.0.1:{passthrough_guard}"
pipeline:
  - filter: stream_uppercase
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: backend
  - filter: load_balancer
    clusters:
      - name: backend
        endpoints:
          - "127.0.0.1:{echo_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let registry = stream_uppercase_registry();
    let stream_port = stream_guard.release();
    let buffer_port = buffer_guard.release();
    let passthrough_port = passthrough_guard.release();
    start_proxy_with_registry(&config, &registry);
    wait_for_tcp(&format!("127.0.0.1:{buffer_port}"));
    wait_for_tcp(&format!("127.0.0.1:{passthrough_port}"));

    let (status_a, body_a) = http_post(&format!("127.0.0.1:{stream_port}"), "/echo", "test alpha");
    assert_eq!(status_a, 200, "stream listener should return 200");
    assert_eq!(body_a, "TEST ALPHA", "stream listener should uppercase body");

    let (status_b, body_b) = http_post(&format!("127.0.0.1:{buffer_port}"), "/echo", "test beta");
    assert_eq!(status_b, 200, "buffer listener should return 200");
    assert_eq!(body_b, "TEST BETA", "buffer listener should uppercase body");

    let (status_c, body_c) = http_post(&format!("127.0.0.1:{passthrough_port}"), "/echo", "test gamma");
    assert_eq!(status_c, 200, "passthrough listener should return 200");
    assert_eq!(body_c, "TEST GAMMA", "passthrough listener should uppercase body");
}

#[test]
fn multi_listener_per_listener_filter_chains() {
    let echo_port = start_echo_backend();
    let claude_port = start_backend("claude-routed");
    let default_port = start_backend("default-routed");
    let extraction_guard = free_port_guard();
    let passthrough_guard = free_port_guard();

    let yaml = format!(
        r#"
listeners:
  - name: extraction
    address: "127.0.0.1:{extraction_guard}"
    filter_chains:
      - extract-and-route
  - name: passthrough
    address: "127.0.0.1:{passthrough_guard}"
    filter_chains:
      - echo-route
filter_chains:
  - name: extract-and-route
    filters:
      - filter: json_body_field
        fields:
          - field: model
            header: X-Model
          - field: user_id
            header: X-User-Id
      - filter: router
        routes:
          - path_prefix: "/"
            headers:
              x-model: "claude-sonnet-4-5"
            cluster: claude_sonnet
          - path_prefix: "/"
            cluster: default
      - filter: load_balancer
        clusters:
          - name: claude_sonnet
            endpoints:
              - "127.0.0.1:{claude_port}"
          - name: default
            endpoints:
              - "127.0.0.1:{default_port}"
  - name: echo-route
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: echo
      - filter: load_balancer
        clusters:
          - name: echo
            endpoints:
              - "127.0.0.1:{echo_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let extraction_port = extraction_guard.release();
    let passthrough_port = passthrough_guard.release();
    crate::common::start_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{passthrough_port}"));

    let raw = http_send(
        &format!("127.0.0.1:{extraction_port}"),
        &json_post("/v1/chat", r#"{"model":"claude-sonnet-4-5","user_id":"u-99"}"#),
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "extraction listener claude-sonnet-4-5 should return 200"
    );
    assert_eq!(
        parse_body(&raw),
        "claude-routed",
        "extraction listener should route claude-sonnet-4-5 to claude_sonnet cluster"
    );

    let raw = http_send(
        &format!("127.0.0.1:{extraction_port}"),
        &json_post("/v1/chat", r#"{"model":"other"}"#),
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "extraction listener other model should return 200"
    );
    assert_eq!(
        parse_body(&raw),
        "default-routed",
        "extraction listener should route unknown model to default"
    );

    let payload = r#"{"model":"claude-sonnet-4-5","prompt":"hi"}"#;
    let (status, body) = http_post(&format!("127.0.0.1:{passthrough_port}"), "/echo", payload);
    assert_eq!(status, 200, "passthrough listener should return 200");
    assert_eq!(body, payload, "passthrough listener should forward body unmodified");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a raw HTTP POST request with a JSON Content-Type.
fn json_post(path: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    )
}

/// Build a registry with a single stream-mode uppercase filter.
fn stream_uppercase_registry() -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "stream_uppercase",
            FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(StreamUppercaseFilter)))),
        )
        .unwrap();
    registry
}

/// Build a registry with three stream-mode filters.
fn stream_registry() -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "stream_uppercase",
            FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(StreamUppercaseFilter)))),
        )
        .unwrap();
    registry
        .register(
            "stream_scanner",
            FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(StreamScannerFilter)))),
        )
        .unwrap();
    registry
        .register(
            "stream_reject_blocked",
            FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(StreamRejectBlockedFilter)))),
        )
        .unwrap();
    registry
}

/// Build a registry with three buffer-mode filters.
fn buffer_registry() -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "buffer_reject_blocked",
            FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(BufferRejectBlockedFilter)))),
        )
        .unwrap();
    registry
        .register(
            "buffer_uppercase",
            FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(BufferUppercaseFilter)))),
        )
        .unwrap();
    registry
        .register(
            "buffer_scanner",
            FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(BufferScannerFilter)))),
        )
        .unwrap();
    registry
}

/// YAML for a 3-filter stream-mode pipeline.
fn stream_pipeline_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: stream_reject_blocked
  - filter: stream_uppercase
  - filter: stream_scanner
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
    )
}

/// YAML for a 3-filter buffer-mode pipeline with size limit.
fn buffer_pipeline_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: buffer_reject_blocked
  - filter: buffer_uppercase
  - filter: buffer_scanner
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
    )
}

/// YAML for stream-buffer mode with multi-field extraction and routing.
fn stream_buffer_routing_yaml(proxy_port: u16, claude_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: json_body_field
    fields:
      - field: model
        header: X-Model
      - field: user_id
        header: X-User-Id
  - filter: router
    routes:
      - path_prefix: "/"
        headers:
          x-model: "claude-sonnet-4-5"
        cluster: claude_sonnet
      - path_prefix: "/"
        cluster: default
  - filter: load_balancer
    clusters:
      - name: claude_sonnet
        endpoints:
          - "127.0.0.1:{claude_port}"
      - name: default
        endpoints:
          - "127.0.0.1:{default_port}"
"#
    )
}

// -----------------------------------------------------------------------------
// Stream Mode Filters
// -----------------------------------------------------------------------------

/// Uppercases request body chunks in streaming mode.
struct StreamUppercaseFilter;

#[async_trait::async_trait]
impl HttpFilter for StreamUppercaseFilter {
    fn name(&self) -> &'static str {
        "stream_uppercase"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::Stream
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

/// Read-only body scanner in streaming mode; third filter in chain.
struct StreamScannerFilter;

#[async_trait::async_trait]
impl HttpFilter for StreamScannerFilter {
    fn name(&self) -> &'static str {
        "stream_scanner"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::Stream
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

/// Rejects body chunks containing "BLOCKED" in streaming mode.
struct StreamRejectBlockedFilter;

#[async_trait::async_trait]
impl HttpFilter for StreamRejectBlockedFilter {
    fn name(&self) -> &'static str {
        "stream_reject_blocked"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::Stream
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body {
            if b.windows(7).any(|w| w == b"BLOCKED") {
                return Ok(FilterAction::Reject(Rejection::status(403)));
            }
        }
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Buffer Mode Filters
// -----------------------------------------------------------------------------

/// Rejects buffered body containing "BLOCKED" with a 128-byte limit.
struct BufferRejectBlockedFilter;

#[async_trait::async_trait]
impl HttpFilter for BufferRejectBlockedFilter {
    fn name(&self) -> &'static str {
        "buffer_reject_blocked"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::Buffer { max_bytes: 128 }
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body {
            if b.windows(7).any(|w| w == b"BLOCKED") {
                return Ok(FilterAction::Reject(Rejection::status(403)));
            }
        }
        Ok(FilterAction::Continue)
    }
}

/// Uppercases the complete buffered body.
struct BufferUppercaseFilter;

#[async_trait::async_trait]
impl HttpFilter for BufferUppercaseFilter {
    fn name(&self) -> &'static str {
        "buffer_uppercase"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::Buffer { max_bytes: 128 }
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

/// Read-only body scanner in buffer mode; third filter in chain.
struct BufferScannerFilter;

#[async_trait::async_trait]
impl HttpFilter for BufferScannerFilter {
    fn name(&self) -> &'static str {
        "buffer_scanner"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::Buffer { max_bytes: 128 }
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
