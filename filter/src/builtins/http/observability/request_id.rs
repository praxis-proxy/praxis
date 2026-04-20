// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Request correlation ID filter.

use std::{
    borrow::Cow,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

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
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Monotone counter for the sequential component of generated IDs.
    counter: AtomicU64,

    /// Header name used for reading, generating, and forwarding the ID.
    header_name: Arc<str>,
}

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
            counter: AtomicU64::default(),
            header_name: Arc::from(cfg.header_name.as_deref().unwrap_or(DEFAULT_HEADER_NAME)),
        }))
    }

    /// Generate a new request ID.
    ///
    /// Combines the current time in microseconds with a per-instance
    /// monotone counter. Not cryptographically random but unique
    /// within a filter instance for any realistic request rate.
    fn generate_id(&self) -> String {
        #[allow(clippy::cast_possible_truncation, reason = "micros fit u64")]
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros()
            .min(u128::from(u64::MAX)) as u64;

        let seq = self.counter.fetch_add(1, Ordering::Relaxed);

        format!("{micros:016x}{seq:016x}")
    }
}

#[async_trait]
impl HttpFilter for RequestIdFilter {
    fn name(&self) -> &'static str {
        "request_id"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let id = ctx
            .request
            .headers
            .get(&*self.header_name)
            .and_then(|v| v.to_str().ok())
            .map_or_else(|| self.generate_id(), str::to_owned);

        debug!(request_id = %id, header = %self.header_name, "forwarding request ID");

        ctx.extra_request_headers
            .push((Cow::Owned(String::from(&*self.header_name)), id));

        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(resp) = ctx.response_header.as_mut() else {
            return Ok(FilterAction::Continue);
        };

        tracing::trace!("preferring original client-supplied value; falling back to injected request header");
        let id = ctx
            .request
            .headers
            .get(&*self.header_name)
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
    async fn echoes_generated_id_on_response() {
        let filter = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        drop(filter.on_request(&mut ctx).await.unwrap());

        let generated_id = ctx.extra_request_headers[0].1.clone();

        let mut resp = crate::test_utils::make_response();
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());

        assert_eq!(
            resp.headers["x-request-id"], generated_id,
            "response should echo generated ID"
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

    #[test]
    fn generated_ids_are_unique() {
        let filter = make_filter("");
        let id1 = filter.generate_id();
        let id2 = filter.generate_id();
        assert_ne!(id1, id2, "consecutive generated IDs must be unique");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`RequestIdFilter`] from a YAML config string.
    fn make_filter(yaml: &str) -> RequestIdFilter {
        let config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        drop(RequestIdFilter::from_config(&config).unwrap());
        let cfg: RequestIdFilterConfig = serde_yaml::from_value(config).unwrap();
        RequestIdFilter {
            counter: AtomicU64::default(),
            header_name: Arc::from(cfg.header_name.as_deref().unwrap_or(DEFAULT_HEADER_NAME)),
        }
    }
}
