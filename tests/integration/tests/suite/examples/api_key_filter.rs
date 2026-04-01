use std::sync::Arc;

use praxis_core::config::Config;
use praxis_filter::{
    FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext, Rejection,
};

use crate::common::{
    free_port, http_get, http_send, parse_body, parse_status, start_backend, start_proxy_with_registry,
};

// -----------------------------------------------------------------------------
// ApiKeyFilter (from docs/filters.md)
// -----------------------------------------------------------------------------

struct ApiKeyFilter {
    valid_keys: Vec<String>,
}

impl ApiKeyFilter {
    fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        #[derive(serde::Deserialize)]
        struct Cfg {
            keys: Vec<String>,
        }
        let cfg: Cfg = serde_yaml::from_value(config.clone()).map_err(|e| -> FilterError { e.to_string().into() })?;
        Ok(Box::new(Self { valid_keys: cfg.keys }))
    }
}

#[async_trait::async_trait]
impl HttpFilter for ApiKeyFilter {
    fn name(&self) -> &'static str {
        "api_key"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let key = ctx.request.headers.get("x-api-key").and_then(|v| v.to_str().ok());
        match key {
            Some(k) if self.valid_keys.iter().any(|v| v == k) => Ok(FilterAction::Continue),
            _ => Ok(FilterAction::Reject(Rejection::status(401))),
        }
    }
}

// -----------------------------------------------------------------------------
// Tests - API Key Filter
// -----------------------------------------------------------------------------

#[test]
fn api_key_filter() {
    let backend_port = start_backend("protected");
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: api_key
    keys: ["secret-1", "secret-2"]
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
        .register("api_key", FilterFactory::Http(Arc::new(ApiKeyFilter::from_config)))
        .expect("duplicate filter name");
    let addr = start_proxy_with_registry(&config, &registry);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Api-Key: secret-1\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "valid API key should return 200");
    assert_eq!(parse_body(&raw), "protected", "valid API key should reach backend");

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Api-Key: wrong\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 401, "invalid API key should return 401");

    let (status, _) = http_get(&addr, "/", None);
    assert_eq!(status, 401, "missing API key should return 401");
}
