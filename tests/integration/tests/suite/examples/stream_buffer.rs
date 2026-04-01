use std::sync::Arc;

use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext,
};

use crate::common::{free_port, http_post, http_send, parse_status, start_backend, start_proxy_with_registry};

// -----------------------------------------------------------------------------
// TinyStreamBufferFilter
// -----------------------------------------------------------------------------

/// Declares StreamBuffer with a small max_bytes for testing 413 enforcement.
struct TinyStreamBufferFilter {
    max_bytes: usize,
}

impl TinyStreamBufferFilter {
    fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        #[derive(serde::Deserialize)]
        struct Cfg {
            max_bytes: usize,
        }
        let cfg: Cfg = serde_yaml::from_value(config.clone()).map_err(|e| -> FilterError { e.to_string().into() })?;
        Ok(Box::new(Self {
            max_bytes: cfg.max_bytes,
        }))
    }
}

#[async_trait::async_trait]
impl HttpFilter for TinyStreamBufferFilter {
    fn name(&self) -> &'static str {
        "tiny_stream_buffer"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.max_bytes),
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
        Ok(FilterAction::Release)
    }
}

/// Start a proxy with a tiny stream buffer filter and return the address.
fn setup(max_bytes: usize) -> String {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: tiny_stream_buffer
    max_bytes: {max_bytes}
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
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "tiny_stream_buffer",
            FilterFactory::Http(Arc::new(TinyStreamBufferFilter::from_config)),
        )
        .expect("duplicate filter name");
    start_proxy_with_registry(&config, &registry)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn stream_buffer_within_limit_succeeds() {
    let addr = setup(256);
    let body = "a".repeat(100);
    let (status, _) = http_post(&addr, "/", &body);
    assert_eq!(status, 200, "body within limit should be accepted");
}

#[test]
fn stream_buffer_at_exact_limit_succeeds() {
    let addr = setup(64);
    let body = "b".repeat(64);
    let (status, _) = http_post(&addr, "/", &body);
    assert_eq!(status, 200, "body at exact limit should be accepted");
}

#[test]
fn stream_buffer_exceeding_limit_returns_413() {
    let addr = setup(64);
    let body = "c".repeat(128);
    let (status, _) = http_post(&addr, "/", &body);
    assert_eq!(status, 413, "body exceeding limit should be rejected with 413");
}

#[test]
fn stream_buffer_one_byte_over_returns_413() {
    let addr = setup(64);
    let body = "d".repeat(65);
    let (status, _) = http_post(&addr, "/", &body);
    assert_eq!(status, 413, "body one byte over limit should be rejected with 413");
}

#[test]
fn stream_buffer_empty_body_succeeds() {
    let addr = setup(64);
    let raw = http_send(
        &addr,
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "empty body should be accepted");
}
