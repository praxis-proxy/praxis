//! TCP connection access log filter.
//!
//! Logs connect and disconnect events for `protocol: tcp` listeners.
//! Registered as `"tcp_access_log"` in the filter registry.

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
/// ```
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
    /// This filter has no configurable parameters; the config
    /// value is accepted and ignored for interface consistency.
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
            upstream = ctx.upstream_addr,
            "TCP connection accepted"
        );
        Ok(FilterAction::Continue)
    }

    async fn on_disconnect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<(), FilterError> {
        let duration_ms = ctx.connect_time.elapsed().as_millis() as u64;
        info!(
            remote = ctx.remote_addr,
            upstream = ctx.upstream_addr,
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
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::tcp_filter::TcpFilterContext;

    #[test]
    fn from_config_succeeds() {
        let filter = TcpAccessLogFilter::from_config(&serde_yaml::Value::Null).unwrap();
        assert_eq!(filter.name(), "tcp_access_log");
    }

    #[tokio::test]
    async fn on_connect_returns_ok() {
        let filter = TcpAccessLogFilter;
        let mut ctx = TcpFilterContext {
            remote_addr: "127.0.0.1:12345",
            local_addr: "0.0.0.0:9000",
            upstream_addr: "10.0.0.1:80",
            connect_time: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
        };
        let action = filter.on_connect(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
    }

    #[tokio::test]
    async fn on_disconnect_returns_ok() {
        let filter = TcpAccessLogFilter;
        let mut ctx = TcpFilterContext {
            remote_addr: "127.0.0.1:12345",
            local_addr: "0.0.0.0:9000",
            upstream_addr: "10.0.0.1:80",
            connect_time: Instant::now(),
            bytes_in: 1024,
            bytes_out: 2048,
        };
        filter.on_disconnect(&mut ctx).await.unwrap();
    }
}
