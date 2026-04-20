// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Request timeout filter: returns 504 if the response takes too long.

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tracing::warn;

use crate::{
    FilterAction, FilterError, Rejection,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Configuration for the timeout filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimeoutFilterConfig {
    /// Maximum allowed elapsed time from request receipt to response headers,
    /// in milliseconds. Requests that exceed this limit receive a 504.
    timeout_ms: u64,
}

// -----------------------------------------------------------------------------
// TimeoutFilter
// -----------------------------------------------------------------------------

/// Enforces a maximum end-to-end latency from request receipt to response headers.
///
/// This does not cancel the upstream connection; the upstream has already
/// responded by the time this check runs. It is useful for enforcing SLAs.
///
/// # YAML configuration
///
/// ```yaml
/// filter: timeout
/// timeout_ms: 5000   # 5 seconds
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::TimeoutFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str("timeout_ms: 5000").unwrap();
/// let filter = TimeoutFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "timeout");
/// ```
pub struct TimeoutFilter {
    /// Maximum allowed elapsed time.
    max_duration: Duration,
}

impl TimeoutFilter {
    /// Create a timeout filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if `timeout_ms` is missing or zero.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: TimeoutFilterConfig = parse_filter_config("timeout", config)?;

        if cfg.timeout_ms == 0 {
            return Err("timeout: timeout_ms must be greater than 0".into());
        }

        Ok(Box::new(Self {
            max_duration: Duration::from_millis(cfg.timeout_ms),
        }))
    }
}

#[async_trait]
impl HttpFilter for TimeoutFilter {
    fn name(&self) -> &'static str {
        "timeout"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let elapsed = ctx.request_start.elapsed();

        if elapsed > self.max_duration {
            warn!(
                elapsed_ms = elapsed.as_millis(),
                limit_ms = self.max_duration.as_millis(),
                "request exceeded timeout; returning 504"
            );

            return Ok(FilterAction::Reject(Rejection::status(504)));
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
    use std::time::{Duration, Instant};

    use super::*;

    #[tokio::test]
    async fn on_request_always_continues() {
        let filter = make_filter(1000);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "on_request should always continue"
        );
    }

    #[tokio::test]
    async fn on_response_continues_within_timeout() {
        let filter = make_filter(10_000);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut resp = crate::test_utils::make_response();
        ctx.response_header = Some(&mut resp);

        let action = filter.on_response(&mut ctx).await.unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "response within timeout should continue"
        );
    }

    #[tokio::test]
    async fn on_response_rejects_when_deadline_exceeded() {
        let filter = make_filter(1);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.request_start = Instant::now() - Duration::from_millis(100);

        let mut resp = crate::test_utils::make_response();
        ctx.response_header = Some(&mut resp);

        let action = filter.on_response(&mut ctx).await.unwrap();

        match action {
            FilterAction::Reject(r) => assert_eq!(r.status, 504, "exceeded deadline should return 504"),
            other => panic!("expected Reject(504), got {other:?}"),
        }
    }

    #[test]
    fn from_config_parses_timeout_ms() {
        let config: serde_yaml::Value = serde_yaml::from_str("timeout_ms: 3000").unwrap();
        let filter = TimeoutFilter::from_config(&config).unwrap();
        assert_eq!(filter.name(), "timeout", "config should parse timeout_ms");
    }

    #[test]
    fn from_config_missing_timeout_ms_errors() {
        let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        assert!(
            TimeoutFilter::from_config(&config).is_err(),
            "missing timeout_ms should error"
        );
    }

    #[test]
    fn from_config_rejects_zero_timeout_ms() {
        let config: serde_yaml::Value = serde_yaml::from_str("timeout_ms: 0").unwrap();
        let err = TimeoutFilter::from_config(&config).err().expect("should fail");
        assert!(
            err.to_string().contains("timeout_ms must be greater than 0"),
            "got: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`TimeoutFilter`] with the given timeout in milliseconds.
    fn make_filter(timeout_ms: u64) -> TimeoutFilter {
        TimeoutFilter {
            max_duration: Duration::from_millis(timeout_ms),
        }
    }
}
