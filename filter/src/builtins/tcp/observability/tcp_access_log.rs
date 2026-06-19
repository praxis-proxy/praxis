// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! TCP connection access log filter.

use async_trait::async_trait;
use tracing::info;

use crate::{
    actions::FilterAction,
    filter::FilterError,
    tcp_filter::{TcpFilter, TcpFilterContext},
};

// -----------------------------------------------------------------------------
// TcpAccessLogFilter
// -----------------------------------------------------------------------------

/// Logs TCP connection events.
///
/// # YAML configuration
///
/// ```yaml
/// filter: tcp_access_log
/// # no configurable parameters
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::TcpAccessLogFilter;
///
/// let yaml = serde_yaml::Value::Null;
/// let filter = TcpAccessLogFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "tcp_access_log");
/// ```
pub struct TcpAccessLogFilter;

impl TcpAccessLogFilter {
    /// Create from YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    #[expect(clippy::unnecessary_wraps, reason = "matches factory signature")]
    pub fn from_config(_config: &serde_yaml::Value) -> Result<Box<dyn TcpFilter>, FilterError> {
        Ok(Box::new(Self))
    }
}

#[async_trait]
impl TcpFilter for TcpAccessLogFilter {
    fn name(&self) -> &'static str {
        "tcp_access_log"
    }

    async fn on_connect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        info!(
            remote = ctx.remote_addr,
            local = ctx.local_addr,
            upstream = ctx.upstream_addr.as_deref().unwrap_or("-"),
            sni = ctx.sni.unwrap_or("-"),
            "TCP connection accepted"
        );
        Ok(FilterAction::Continue)
    }

    async fn on_disconnect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<(), FilterError> {
        #[expect(clippy::cast_possible_truncation, reason = "millis fit u64")]
        let duration_ms = ctx.connect_time.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        info!(
            remote = ctx.remote_addr,
            upstream = ctx.upstream_addr.as_deref().unwrap_or("-"),
            sni = ctx.sni.unwrap_or("-"),
            duration_ms,
            bytes_in = ctx.bytes_in,
            bytes_out = ctx.bytes_out,
            "TCP connection closed"
        );
        Ok(())
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
    use std::time::Instant;

    use super::*;
    use crate::tcp_filter::TcpFilterContext;

    #[test]
    fn from_config_succeeds() {
        let filter = TcpAccessLogFilter::from_config(&serde_yaml::Value::Null).unwrap();
        assert_eq!(filter.name(), "tcp_access_log", "filter name should be tcp_access_log");
    }

    #[tokio::test]
    async fn on_connect_returns_ok() {
        let filter = TcpAccessLogFilter;
        let mut ctx = TcpFilterContext {
            remote_addr: "127.0.0.1:12345",
            local_addr: "0.0.0.0:9000",
            sni: None,
            upstream_addr: Some(std::borrow::Cow::Borrowed("10.0.0.1:80")),
            cluster: None,
            health_registry: None,
            kv_stores: None,
            connect_time: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
        };
        let action = filter.on_connect(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue), "on_connect should continue");
    }

    #[tokio::test]
    async fn on_disconnect_returns_ok() {
        let filter = TcpAccessLogFilter;
        let mut ctx = TcpFilterContext {
            remote_addr: "127.0.0.1:12345",
            local_addr: "0.0.0.0:9000",
            sni: None,
            upstream_addr: Some(std::borrow::Cow::Borrowed("10.0.0.1:80")),
            cluster: None,
            health_registry: None,
            kv_stores: None,
            connect_time: Instant::now(),
            bytes_in: 1024,
            bytes_out: 2048,
        };
        filter.on_disconnect(&mut ctx).await.unwrap();
    }
}
