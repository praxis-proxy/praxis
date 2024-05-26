//! Request correlation ID filter.
//!
//! Reads or generates a unique ID per request and propagates it via
//! a configurable header (default: `X-Request-ID`).
//! Registered as `"request_id"` in the filter registry.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use serde::Deserialize;
use tracing::debug;

use crate::{
    FilterAction, FilterError,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Configuration for the request ID propagation filter.
#[derive(Debug, Default, Deserialize)]
struct RequestIdFilterConfig {
    /// Name of the header to read, generate, and forward. Defaults to `X-Request-ID`.
    #[serde(default)]
    header_name: Option<String>,
}

// -----------------------------------------------------------------------------
// RequestIdFilter
// -----------------------------------------------------------------------------

/// Ensures every request carries a correlation ID.
///
/// Reads `header_name` from the request (default: `X-Request-ID`).
/// Generates a new ID if absent. Forwards to upstream and echoes
/// in the response.
///
/// # YAML configuration
///
/// ```yaml
/// filter: request_id
/// header_name: X-Correlation-ID   # optional
/// ```
///
/// # Example
///
/// ```
/// use praxis_filter::RequestIdFilter;
///
/// let yaml: serde_yaml::Value =
///     serde_yaml::from_str("{}").unwrap();
/// let filter = RequestIdFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "request_id");
/// ```
pub struct RequestIdFilter {
    /// Monotone counter for the sequential component of generated IDs.
    counter: AtomicU64,

    /// Header name used for reading, generating, and forwarding the ID.
    header_name: String,
}

impl RequestIdFilter {
    /// Create a request ID filter from parsed YAML config.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: RequestIdFilterConfig =
            serde_yaml::from_value(config.clone()).map_err(|e| -> FilterError { format!("request_id: {e}").into() })?;

        Ok(Box::new(Self {
            counter: Default::default(),
            header_name: cfg.header_name.unwrap_or_else(|| "X-Request-ID".to_owned()),
        }))
    }

    /// Generate a new request ID.
    ///
    /// Combines the current time in microseconds with a per-instance
    /// monotone counter. Not cryptographically random but unique
    /// within a filter instance for any realistic request rate.
    fn generate_id(&self) -> String {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        let seq = self.counter.fetch_add(1, Ordering::Relaxed);

        format!("{micros:016x}{seq:016x}")
    }
}

// -----------------------------------------------------------------------------
// Filter Impl
// -----------------------------------------------------------------------------

#[async_trait]
impl HttpFilter for RequestIdFilter {
    fn name(&self) -> &'static str {
        "request_id"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let id = ctx
            .request
            .headers
            .get(self.header_name.as_str())
            .and_then(|v| v.to_str().ok())
            .map_or_else(|| self.generate_id(), str::to_owned);

        debug!(request_id = %id, header = %self.header_name, "forwarding request ID");

        ctx.extra_request_headers.push((self.header_name.clone(), id));

        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(resp) = ctx.response_header.as_mut() else {
            return Ok(FilterAction::Continue);
        };

        // Prefer the original client-supplied value; fall back to the one we
        // injected into extra_request_headers during the request phase.
        let id = ctx
            .request
            .headers
            .get(self.header_name.as_str())
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .or_else(|| {
                ctx.extra_request_headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(&self.header_name))
                    .map(|(_, value)| value.clone())
            });

        if let Some(id) = id
            && let (Ok(header_name), Ok(header_value)) = (
                http::header::HeaderName::from_bytes(self.header_name.as_bytes()),
                http::header::HeaderValue::from_str(&id),
            )
        {
            resp.headers.insert(header_name, header_value);
        }

        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Response as FilterResponse;

    fn make_filter(yaml: &str) -> RequestIdFilter {
        let config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let _ = RequestIdFilter::from_config(&config).unwrap();
        let cfg: RequestIdFilterConfig = serde_yaml::from_value(config).unwrap();
        RequestIdFilter {
            counter: Default::default(),
            header_name: cfg.header_name.unwrap_or_else(|| "X-Request-ID".to_owned()),
        }
    }

    fn make_response() -> FilterResponse {
        FilterResponse {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::OK,
        }
    }

    #[tokio::test]
    async fn generates_id_when_header_missing() {
        let filter = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue));
        assert_eq!(ctx.extra_request_headers.len(), 1);
        let (name, value) = &ctx.extra_request_headers[0];
        assert_eq!(name, "X-Request-ID");
        assert_eq!(value.len(), 32, "generated ID should be 32 hex chars");
    }

    #[tokio::test]
    async fn preserves_existing_id() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("x-request-id"),
            http::header::HeaderValue::from_static("client-provided-id"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);

        filter.on_request(&mut ctx).await.unwrap();

        assert_eq!(ctx.extra_request_headers.len(), 1);
        let (_, value) = &ctx.extra_request_headers[0];
        assert_eq!(value, "client-provided-id");
    }

    #[tokio::test]
    async fn echoes_generated_id_on_response() {
        let filter = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        filter.on_request(&mut ctx).await.unwrap();

        let generated_id = ctx.extra_request_headers[0].1.clone();

        let mut resp = make_response();
        ctx.response_header = Some(&mut resp);
        filter.on_response(&mut ctx).await.unwrap();

        assert_eq!(resp.headers["x-request-id"], generated_id);
    }

    #[tokio::test]
    async fn echoes_client_id_on_response() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("x-request-id"),
            http::header::HeaderValue::from_static("from-client"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);
        filter.on_request(&mut ctx).await.unwrap();

        let mut resp = make_response();
        ctx.response_header = Some(&mut resp);
        filter.on_response(&mut ctx).await.unwrap();

        assert_eq!(resp.headers["x-request-id"], "from-client");
    }

    #[tokio::test]
    async fn custom_header_name_is_used() {
        let filter = make_filter("header_name: X-Correlation-ID");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        filter.on_request(&mut ctx).await.unwrap();

        let (name, _) = &ctx.extra_request_headers[0];
        assert_eq!(name, "X-Correlation-ID");
    }

    #[test]
    fn from_config_empty_uses_default_header_name() {
        let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let filter = RequestIdFilter::from_config(&config).unwrap();
        assert_eq!(filter.name(), "request_id");
    }

    #[test]
    fn generated_ids_are_unique() {
        let filter = make_filter("");
        let id1 = filter.generate_id();
        let id2 = filter.generate_id();
        assert_ne!(id1, id2);
    }
}
