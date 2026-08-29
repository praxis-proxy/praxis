// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Request correlation ID filter.

use std::{borrow::Cow, sync::Arc};

use async_trait::async_trait;
use serde::Deserialize;
use tracing::debug;

use crate::{
    FilterAction, FilterError,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default header name when none is configured.
const DEFAULT_HEADER_NAME: &str = "X-Request-ID";

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Configuration for the request ID propagation filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestIdFilterConfig {
    /// Name of the header to read, generate, and forward.
    #[serde(default = "default_header_name")]
    header_name: String,
}

/// Default header name for request ID propagation.
fn default_header_name() -> String {
    DEFAULT_HEADER_NAME.to_owned()
}

// -----------------------------------------------------------------------------
// RequestIdFilter
// -----------------------------------------------------------------------------

/// Ensures every request carries a correlation ID.
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
/// ```ignore
/// use praxis_filter::RequestIdFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
/// let filter = RequestIdFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "request_id");
/// ```
pub struct RequestIdFilter {
    /// Header name used for reading, generating, and forwarding the ID.
    header_name: Arc<str>,
}

/// Per-request marker recording that the client supplied the ID itself.
///
/// Present only when the incoming request already carried the header.
/// Its absence means the proxy generated the ID, which must not be
/// echoed to the client.
struct ClientSuppliedId(String);

impl RequestIdFilter {
    /// Create a request ID filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is malformed.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: RequestIdFilterConfig = parse_filter_config("request_id", config)?;

        Ok(Box::new(Self {
            header_name: Arc::from(cfg.header_name.as_str()),
        }))
    }

    /// Resolve the request ID to echo on the response.
    ///
    /// Only a **client-supplied** ID is echoed. Returning the value the
    /// client sent is not a disclosure — they already have it — and it
    /// lets a caller correlate its own request with the response.
    ///
    /// A proxy-*generated* ID is deliberately not echoed. It is
    /// request-phase state injected for the benefit of the upstream, and
    /// the leakage suite treats it the same as `X-Forwarded-For` or an
    /// internal debug header: request-injected values must not appear on
    /// the client response
    /// (`tests/security/tests/suite/filter_leakage.rs`). A backend that
    /// wants the ID visible to clients can echo it itself, which the
    /// proxy passes through untouched.
    ///
    /// Provenance comes from [`ClientSuppliedId`] recorded during
    /// `on_request`, not from `ctx.request`. The request snapshot
    /// reflects the headers as sent upstream, injected ones included, so
    /// it cannot distinguish "the client sent this" from "we added it".
    fn resolve_response_id(&self, ctx: &HttpFilterContext<'_>) -> Option<http::header::HeaderValue> {
        let ClientSuppliedId(id) = ctx.get_filter_state::<ClientSuppliedId>()?;
        tracing::trace!(header = %self.header_name, "using client-supplied request ID for response header");
        // Build the HeaderValue directly from the borrowed id: the copy
        // into the value happens either way, while the old intermediate
        // String clone existed only to end the state borrow early.
        match http::header::HeaderValue::from_str(id) {
            Ok(value) => Some(value),
            Err(value_err) => {
                debug!(
                    header = %self.header_name,
                    value_err = ?Some(value_err),
                    "failed to set request ID on response header"
                );
                None
            },
        }
    }

    /// Insert the request ID header into the response.
    fn insert_response_header(&self, resp: &mut crate::Response, value: http::header::HeaderValue) {
        match http::header::HeaderName::from_bytes(self.header_name.as_bytes()) {
            Ok(header_name) => {
                resp.headers.insert(header_name, value);
            },
            Err(name_err) => {
                debug!(
                    header = %self.header_name,
                    name_err = ?Some(name_err),
                    "failed to set request ID on response header"
                );
            },
        }
    }
}

#[async_trait]
impl HttpFilter for RequestIdFilter {
    fn name(&self) -> &'static str {
        "request_id"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let client_id = ctx
            .request
            .headers
            .get(&*self.header_name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        // Record provenance now, while the request headers are still
        // exactly what the client sent. By `on_response` the snapshot
        // also carries proxy-injected headers and cannot be used to tell
        // the two apart.
        if let Some(client_id) = client_id.clone() {
            ctx.insert_filter_state(ClientSuppliedId(client_id));
        }

        let id = client_id.unwrap_or_else(|| ctx.id_generator.generate(ctx.time_source));

        debug!(request_id = %id, header = %self.header_name, "forwarding request ID");
        tracing::Span::current().record("request_id", &*id);

        ctx.extra_request_headers
            .push((Cow::Owned((*self.header_name).to_owned()), id));

        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if ctx.response_header.is_none() {
            return Ok(FilterAction::Continue);
        }

        let value = self.resolve_response_id(ctx);
        if let Some(value) = value
            && let Some(resp) = ctx.response_header.as_mut()
        {
            self.insert_response_header(resp, value);
        }

        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generates_id_when_header_missing() {
        let filter = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue), "on_request should continue");
        assert_eq!(ctx.extra_request_headers.len(), 1, "should inject exactly one header");
        let (name, value) = &ctx.extra_request_headers[0];
        assert_eq!(name, "X-Request-ID", "header name should be X-Request-ID");
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

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(ctx.extra_request_headers.len(), 1, "should forward one header");
        let (_, value) = &ctx.extra_request_headers[0];
        assert_eq!(
            value, "client-provided-id",
            "should preserve client-supplied request ID"
        );
    }

    #[tokio::test]
    async fn does_not_echo_generated_id_on_response() {
        let filter = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        drop(filter.on_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.extra_request_headers.len(),
            1,
            "an ID was injected for the upstream"
        );

        let mut resp = crate::test_utils::make_response();
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());

        assert!(
            !resp.headers.contains_key("x-request-id"),
            "a proxy-generated ID is request-phase state and must not reach the client; \
             see filter_leakage::request_id_not_leaked_to_client"
        );
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
        // Filter state is keyed by the executing filter's id, which the
        // pipeline sets around each hook.
        ctx.current_filter_id = Some(0);
        drop(filter.on_request(&mut ctx).await.unwrap());

        let mut resp = crate::test_utils::make_response();
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());

        assert_eq!(
            resp.headers["x-request-id"], "from-client",
            "response should echo client-supplied ID"
        );
    }

    #[tokio::test]
    async fn custom_header_name_is_used() {
        let filter = make_filter("header_name: X-Correlation-ID");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        let (name, _) = &ctx.extra_request_headers[0];
        assert_eq!(name, "X-Correlation-ID", "should use custom header name from config");
    }

    #[test]
    fn from_config_empty_uses_default_header_name() {
        let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let filter = RequestIdFilter::from_config(&config).unwrap();
        assert_eq!(
            filter.name(),
            "request_id",
            "empty config should use default header name"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`RequestIdFilter`] from a YAML config string.
    fn make_filter(yaml: &str) -> RequestIdFilter {
        let config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let cfg: RequestIdFilterConfig = parse_filter_config("request_id", &config).unwrap();
        RequestIdFilter {
            header_name: Arc::from(cfg.header_name.as_str()),
        }
    }
}
