//! The [`TcpFilter`] trait and per-connection [`TcpFilterContext`].

use std::time::Instant;

use async_trait::async_trait;

use crate::{actions::FilterAction, filter::FilterError};

// -----------------------------------------------------------------------------
// TcpFilter Trait
// -----------------------------------------------------------------------------

/// A filter that participates in TCP connection processing.
///
/// ```
/// use std::time::Instant;
///
/// use async_trait::async_trait;
/// use praxis_filter::{FilterAction, FilterError, TcpFilter, TcpFilterContext};
///
/// struct LogFilter;
///
/// #[async_trait]
/// impl TcpFilter for LogFilter {
///     fn name(&self) -> &'static str { "log" }
///
///     async fn on_connect(
///         &self, ctx: &mut TcpFilterContext<'_>,
///     ) -> Result<FilterAction, FilterError> {
///         println!("connection from {}", ctx.remote_addr);
///         Ok(FilterAction::Continue)
///     }
/// }
///
/// # fn example() {
/// let mut ctx = TcpFilterContext {
///     remote_addr: "127.0.0.1:1234",
///     local_addr: "0.0.0.0:8080",
///     upstream_addr: "10.0.0.1:80",
///     connect_time: Instant::now(),
///     bytes_in: 0,
///     bytes_out: 0,
/// };
/// # }
/// ```
#[async_trait]
pub trait TcpFilter: Send + Sync {
    /// Unique name identifying this filter type.
    fn name(&self) -> &'static str;

    /// Called when a new TCP connection is accepted.
    async fn on_connect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let _ = ctx;
        Ok(FilterAction::Continue)
    }

    /// Called when a TCP connection is closed.
    async fn on_disconnect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<(), FilterError> {
        let _ = ctx;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// TcpFilterContext
// -----------------------------------------------------------------------------

/// Per-connection state for TCP filters.
pub struct TcpFilterContext<'a> {
    /// Remote client address.
    pub remote_addr: &'a str,

    /// Local listener address.
    pub local_addr: &'a str,

    /// Upstream address being proxied to.
    pub upstream_addr: &'a str,

    /// When the connection was accepted.
    pub connect_time: Instant,

    /// Bytes received from client (populated after forwarding completes).
    pub bytes_in: u64,

    /// Bytes sent to client (populated after forwarding completes).
    pub bytes_out: u64,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopTcpFilter;

    #[async_trait]
    impl TcpFilter for NoopTcpFilter {
        fn name(&self) -> &'static str {
            "noop_tcp"
        }
    }

    #[tokio::test]
    async fn default_on_connect_returns_continue() {
        let filter = NoopTcpFilter;
        let mut ctx = TcpFilterContext {
            remote_addr: "127.0.0.1:12345",
            local_addr: "0.0.0.0:5432",
            upstream_addr: "10.0.0.1:5432",
            connect_time: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
        };
        let action = filter.on_connect(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
    }

    #[tokio::test]
    async fn default_on_disconnect_succeeds() {
        let filter = NoopTcpFilter;
        let mut ctx = TcpFilterContext {
            remote_addr: "127.0.0.1:12345",
            local_addr: "0.0.0.0:5432",
            upstream_addr: "10.0.0.1:5432",
            connect_time: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
        };
        filter.on_disconnect(&mut ctx).await.unwrap();
    }
}
