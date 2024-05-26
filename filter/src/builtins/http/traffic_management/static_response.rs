//! Static response filter: returns a fixed status, headers, and body without contacting an upstream.

use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;

use crate::{
    actions::{FilterAction, Rejection},
    factory::parse_filter_config,
    filter::{FilterError, HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// StaticResponseConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the static response filter.
#[derive(Debug, Deserialize)]
struct StaticResponseConfig {
    /// HTTP status code to return.
    status: u16,

    /// Response headers to include.
    #[serde(default)]
    headers: Vec<HeaderEntry>,

    /// Optional response body string.
    #[serde(default)]
    body: Option<String>,
}

/// A name/value header pair in the static response config.
#[derive(Debug, Deserialize)]
struct HeaderEntry {
    /// Header field name.
    name: String,

    /// Header field value.
    value: String,
}

// -----------------------------------------------------------------------------
// StaticResponseFilter
// -----------------------------------------------------------------------------

/// Returns a fixed response without contacting any upstream.
///
/// # YAML configuration
///
/// ```yaml
/// filter: static_response
/// status: 200
/// body: "OK"
/// ```
///
/// # Example
///
/// ```
/// use praxis_filter::StaticResponseFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str("status: 200").unwrap();
/// let filter = StaticResponseFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "static_response");
/// ```
pub struct StaticResponseFilter {
    /// HTTP status code to return.
    status: u16,
    /// Response headers as (name, value) pairs.
    headers: Vec<(String, String)>,
    /// Optional response body.
    body: Option<Bytes>,
}

impl StaticResponseFilter {
    /// Create from YAML config.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: StaticResponseConfig = parse_filter_config("static_response", config)?;

        Ok(Box::new(Self {
            status: cfg.status,
            headers: cfg.headers.into_iter().map(|h| (h.name, h.value)).collect(),
            body: cfg.body.map(Bytes::from),
        }))
    }
}

#[async_trait]
impl HttpFilter for StaticResponseFilter {
    fn name(&self) -> &'static str {
        "static_response"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let mut rejection = Rejection::status(self.status);
        for (name, value) in &self.headers {
            rejection = rejection.with_header(name, value);
        }
        if let Some(ref body) = self.body {
            rejection = rejection.with_body(body.clone());
        }
        Ok(FilterAction::Reject(rejection))
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_minimal() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>("status: 200").unwrap();
        let filter = StaticResponseFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "static_response", "minimal config should parse");
    }

    #[test]
    fn from_config_with_body_and_headers() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
status: 200
headers:
  - name: Content-Type
    value: application/json
body: '{"ok": true}'
"#,
        )
        .unwrap();
        let filter = StaticResponseFilter::from_config(&yaml).unwrap();
        assert_eq!(
            filter.name(),
            "static_response",
            "config with body and headers should parse"
        );
    }

    #[test]
    fn from_config_missing_status_fails() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>("body: hello").unwrap();
        let result = StaticResponseFilter::from_config(&yaml);
        assert!(result.is_err(), "missing status should fail");
    }

    #[tokio::test]
    async fn returns_configured_response() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
status: 418
headers:
  - name: X-Custom
    value: teapot
body: "I'm a teapot"
"#,
        )
        .unwrap();
        let filter = StaticResponseFilter::from_config(&yaml).unwrap();

        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(r) => {
                assert_eq!(r.status, 418, "status should be 418");
                assert_eq!(r.headers.len(), 1, "should have one custom header");
                assert_eq!(r.headers[0].0, "X-Custom", "header name should match config");
                assert_eq!(r.headers[0].1, "teapot", "header value should match config");
                assert_eq!(r.body.unwrap(), Bytes::from("I'm a teapot"), "body should match config");
            },
            _ => panic!("expected reject"),
        }
    }
}
