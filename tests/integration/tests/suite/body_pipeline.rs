// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for multi-filter body pipelines exercising Stream, Buffer, and StreamBuffer modes.

use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext,
    Rejection,
};
use praxis_test_utils::{
    free_port, free_port_guard, http_post, http_send, json_post, parse_body, parse_status, start_backend_with_shutdown,
    start_echo_backend, start_proxy_with_registry, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn stream_pipeline_transforms_body_through_three_filters() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&stream_pipeline_yaml(proxy_port, backend_port)).unwrap();
    let registry = stream_registry();
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "hello world");

    assert_eq!(status, 200, "stream pipeline should return 200");
    assert_eq!(
        body, "HELLO WORLD",
        "body should be uppercased after passing through 3 stream filters"
    );
}

#[test]
fn stream_pipeline_rejects_blocked_content() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&stream_pipeline_yaml(proxy_port, backend_port)).unwrap();
    let registry = stream_registry();
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, _) = http_post(proxy.addr(), "/echo", "this is BLOCKED content");

    assert_eq!(status, 403, "stream pipeline should reject BLOCKED content");
}

#[test]
fn stream_pipeline_allows_clean_content() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&stream_pipeline_yaml(proxy_port, backend_port)).unwrap();
    let registry = stream_registry();
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "clean content");

    assert_eq!(status, 200, "clean content should pass stream pipeline");
    assert_eq!(body, "CLEAN CONTENT", "clean body should be uppercased");
}

#[test]
fn buffer_pipeline_transforms_complete_body() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&buffer_pipeline_yaml(proxy_port, backend_port)).unwrap();
    let registry = buffer_registry();
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "hello world");

    assert_eq!(status, 200, "buffer pipeline should return 200");
    assert_eq!(
        body, "HELLO WORLD",
        "buffered body should be uppercased after passing through 3 buffer filters"
    );
}

#[test]
fn buffer_pipeline_rejects_oversized_body() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&buffer_pipeline_yaml(proxy_port, backend_port)).unwrap();
    let registry = buffer_registry();
    let proxy = start_proxy_with_registry(&config, &registry);

    let payload = "x".repeat(200);
    let (status, _) = http_post(proxy.addr(), "/echo", &payload);

    assert_eq!(status, 413, "body exceeding buffer limit should be rejected with 413");
}

#[test]
fn buffer_pipeline_exact_boundary_succeeds() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&buffer_pipeline_yaml(proxy_port, backend_port)).unwrap();
    let registry = buffer_registry();
    let proxy = start_proxy_with_registry(&config, &registry);

    let payload = "a".repeat(128);
    let (status, body) = http_post(proxy.addr(), "/echo", &payload);

    assert_eq!(status, 200, "body at exact buffer limit should succeed");
    assert_eq!(body, "A".repeat(128), "body at boundary should be fully uppercased");
}

#[test]
fn buffer_pipeline_rejects_forbidden_content() {
    let backend_port_guard = start_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&buffer_pipeline_yaml(proxy_port, backend_port)).unwrap();
    let registry = buffer_registry();
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, _) = http_post(proxy.addr(), "/echo", "BLOCKED payload");

    assert_eq!(status, 403, "buffer pipeline should reject content containing BLOCKED");
}

#[test]
fn stream_buffer_pipeline_extracts_and_routes() {
    let alpha_port_guard = start_backend_with_shutdown("alpha-response");
    let alpha_port = alpha_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-response");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&stream_buffer_routing_yaml(proxy_port, alpha_port, default_port)).unwrap();
    let proxy = praxis_test_utils::start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/chat", r#"{"model":"model-alpha-1","user_id":"u-1","prompt":"hi"}"#),
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "stream-buffer model-alpha-1 routing should return 200"
    );
    assert_eq!(
        parse_body(&raw),
        "alpha-response",
        "model=model-alpha-1 should route to alpha_cluster cluster"
    );
}

#[test]
fn stream_buffer_pipeline_fallback_routing() {
    let alpha_port_guard = start_backend_with_shutdown("alpha-response");
    let alpha_port = alpha_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-response");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&stream_buffer_routing_yaml(proxy_port, alpha_port, default_port)).unwrap();
    let proxy = praxis_test_utils::start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/chat", r#"{"model":"unknown","user_id":"u-1"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "unknown model routing should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-response",
        "unknown model should route to default cluster"
    );
}

#[test]
fn multi_listener_each_mode_processes_independently() {
    let echo_port_guard = start_echo_backend();
    let echo_port = echo_port_guard.port();
    let stream_guard = free_port_guard();
    let buffer_guard = free_port_guard();
    let passthrough_guard = free_port_guard();

    let yaml = format!(
        r#"
listeners:
  - name: stream
    address: "127.0.0.1:{stream_guard}"
    filter_chains: [main]
  - name: buffer
    address: "127.0.0.1:{buffer_guard}"
    filter_chains: [main]
  - name: passthrough
    address: "127.0.0.1:{passthrough_guard}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
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
    let _proxy = start_proxy_with_registry(&config, &registry);
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
    let echo_port_guard = start_echo_backend();
    let echo_port = echo_port_guard.port();
    let alpha_port_guard = start_backend_with_shutdown("alpha-routed");
    let alpha_port = alpha_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-routed");
    let default_port = default_port_guard.port();
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
              x-model: "model-alpha-1"
            cluster: alpha_cluster
          - path_prefix: "/"
            cluster: default
      - filter: load_balancer
        clusters:
          - name: alpha_cluster
            endpoints:
              - "127.0.0.1:{alpha_port}"
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
    let _proxy = praxis_test_utils::start_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{passthrough_port}"));

    let raw = http_send(
        &format!("127.0.0.1:{extraction_port}"),
        &json_post("/v1/chat", r#"{"model":"model-alpha-1","user_id":"u-99"}"#),
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "extraction listener model-alpha-1 should return 200"
    );
    assert_eq!(
        parse_body(&raw),
        "alpha-routed",
        "extraction listener should route model-alpha-1 to alpha_cluster cluster"
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

    let payload = r#"{"model":"model-alpha-1","prompt":"hi"}"#;
    let (status, body) = http_post(&format!("127.0.0.1:{passthrough_port}"), "/echo", payload);
    assert_eq!(status, 200, "passthrough listener should return 200");
    assert_eq!(body, payload, "passthrough listener should forward body unmodified");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

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

/// Build a registry with three StreamBuffer-mode filters.
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
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
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
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
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
fn stream_buffer_routing_yaml(proxy_port: u16, alpha_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
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
              x-model: "model-alpha-1"
            cluster: alpha_cluster
          - path_prefix: "/"
            cluster: default
      - filter: load_balancer
        clusters:
          - name: alpha_cluster
            endpoints:
              - "127.0.0.1:{alpha_port}"
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
        if let Some(b) = body
            && b.windows(7).any(|w| w == b"BLOCKED")
        {
            return Ok(FilterAction::Reject(Rejection::status(403)));
        }
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// StreamBuffer Mode Filters
// -----------------------------------------------------------------------------

/// Rejects stream-buffered body containing "BLOCKED" with a 128-byte limit.
struct BufferRejectBlockedFilter;

#[async_trait::async_trait]
impl HttpFilter for BufferRejectBlockedFilter {
    fn name(&self) -> &'static str {
        "buffer_reject_blocked"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        ctx.set_request_body_mode(BodyMode::StreamBuffer { max_bytes: Some(128) });
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }
        if let Some(b) = body
            && b.windows(7).any(|w| w == b"BLOCKED")
        {
            return Ok(FilterAction::Reject(Rejection::status(403)));
        }
        Ok(FilterAction::Continue)
    }
}

/// Uppercases the complete stream-buffered body.
struct BufferUppercaseFilter;

#[async_trait::async_trait]
impl HttpFilter for BufferUppercaseFilter {
    fn name(&self) -> &'static str {
        "buffer_uppercase"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        ctx.set_request_body_mode(BodyMode::StreamBuffer { max_bytes: Some(128) });
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
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }
        if let Some(b) = body {
            let upper: Vec<u8> = b.iter().map(|c| c.to_ascii_uppercase()).collect();
            *b = Bytes::from(upper);
        }
        Ok(FilterAction::Continue)
    }
}

/// Read-only body scanner in StreamBuffer mode; third filter in chain.
struct BufferScannerFilter;

#[async_trait::async_trait]
impl HttpFilter for BufferScannerFilter {
    fn name(&self) -> &'static str {
        "buffer_scanner"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        ctx.set_request_body_mode(BodyMode::StreamBuffer { max_bytes: Some(128) });
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
