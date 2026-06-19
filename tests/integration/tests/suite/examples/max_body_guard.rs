// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for max body guard filter behavior.

use std::sync::Arc;

use praxis_core::config::Config;
use praxis_filter::{
    FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext, Rejection,
};
use praxis_test_utils::{
    free_port, http_get, http_send, parse_body, parse_status, start_backend_with_shutdown, start_proxy_with_registry,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn max_body_guard() {
    let backend_port_guard = start_backend_with_shutdown("accepted");
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
      - filter: max_body_guard
        max_content_length: 1024
        reject_status: 413
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
            "max_body_guard",
            FilterFactory::Http(Arc::new(MaxBodyGuard::from_config)),
        )
        .expect("duplicate filter name");
    let proxy = start_proxy_with_registry(&config, &registry);

    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 5\r\n\
         Connection: close\r\n\r\nhello",
    );
    assert_eq!(parse_status(&raw), 200, "small body should be accepted");
    assert_eq!(parse_body(&raw), "accepted", "small body response should match backend");

    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 2048\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 413, "large body should be rejected with 413");

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "GET without content-length should be accepted");
    assert_eq!(body, "accepted", "GET response should match backend");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Custom filter that rejects requests exceeding a
/// configured content length.
struct MaxBodyGuard {
    /// Maximum allowed content length in bytes.
    max_content_length: u64,

    /// HTTP status to return on rejection.
    reject_status: u16,
}

impl MaxBodyGuard {
    /// Parse filter configuration from YAML.
    fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        #[derive(serde::Deserialize)]
        struct Cfg {
            max_content_length: u64,
            #[serde(default = "default_status")]
            reject_status: u16,
        }
        fn default_status() -> u16 {
            413
        }
        let cfg: Cfg = serde_yaml::from_value(config.clone()).map_err(|e| -> FilterError { e.to_string().into() })?;
        Ok(Box::new(Self {
            max_content_length: cfg.max_content_length,
            reject_status: cfg.reject_status,
        }))
    }
}

#[async_trait::async_trait]
impl HttpFilter for MaxBodyGuard {
    fn name(&self) -> &'static str {
        "max_body_guard"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let too_large = ctx
            .request
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|len| len > self.max_content_length);

        if too_large {
            return Ok(FilterAction::Reject(Rejection::status(self.reject_status)));
        }
        Ok(FilterAction::Continue)
    }
}
