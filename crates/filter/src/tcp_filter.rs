// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! The [`TcpFilter`] trait and per-connection [`TcpFilterContext`].

use std::{borrow::Cow, sync::Arc, time::Instant};

use async_trait::async_trait;
use praxis_core::{health::HealthRegistry, kv::KvStoreRegistry};

#[cfg(feature = "bandwidth")]
use crate::bandwidth::TcpBandwidthPacer;
use crate::{actions::FilterAction, filter::FilterError};

// -----------------------------------------------------------------------------
// TcpFilter Trait
// -----------------------------------------------------------------------------

/// A filter that participates in TCP connection processing.
///
/// ```
/// use std::{borrow::Cow, time::Instant};
///
/// use async_trait::async_trait;
/// use praxis_filter::{FilterAction, FilterError, TcpFilter, TcpFilterContext};
///
/// struct LogFilter;
///
/// #[async_trait]
/// impl TcpFilter for LogFilter {
///     fn name(&self) -> &'static str {
///         "log"
///     }
///
///     async fn on_connect(
///         &self,
///         ctx: &mut TcpFilterContext<'_>,
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
///     sni: None,
///     upstream_addr: Some(Cow::Borrowed("10.0.0.1:80")),
///     cluster: None,
///     health_registry: None,
///     kv_stores: None,
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

    /// Attach this filter's slow-start tables when the pipeline is installed.
    ///
    /// Framework-internal. A TCP load balancer that configures `slow_start`
    /// records the current endpoints as the baseline here. Builds without the
    /// `slow-start` feature reject that key and do not grow the trait.
    #[doc(hidden)]
    #[cfg(feature = "slow-start")]
    fn bind_slow_start(&self, _registry: &Arc<crate::SlowStartRegistry>) {}

    /// Called when a new TCP connection is accepted.
    async fn on_connect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let _ = ctx;
        Ok(FilterAction::Continue)
    }

    /// Opt-in connection state for filters that install a byte pacer.
    ///
    /// Existing implementations inherit `on_connect` unchanged. The separate
    /// state preserves the public `TcpFilterContext` literal contract.
    #[cfg(feature = "bandwidth")]
    async fn on_connect_with_state(
        &self,
        ctx: &mut TcpFilterContext<'_>,
        _state: &mut TcpConnectState,
    ) -> Result<FilterAction, FilterError> {
        self.on_connect(ctx).await
    }

    /// Called when a TCP connection is closed.
    async fn on_disconnect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<(), FilterError> {
        let _ = ctx;
        Ok(())
    }
}

/// Optional state owned by the TCP connection rather than its public context.
#[cfg(feature = "bandwidth")]
#[derive(Default)]
pub struct TcpConnectState {
    /// Byte schedules installed by the executed connect filters.
    pub(crate) bandwidth: Option<Arc<TcpBandwidthPacer>>,
    /// Trusted connection-close metadata.
    pub(crate) extensions: crate::RequestExtensions,
}

#[cfg(feature = "bandwidth")]
impl TcpConnectState {
    /// Take the byte pacer after the connection pipeline succeeds.
    pub fn take_bandwidth(&mut self) -> Option<Arc<TcpBandwidthPacer>> {
        self.bandwidth.take()
    }

    /// Why this connection was rejected without a protocol response.
    #[must_use]
    pub fn close_reason(&self) -> Option<&'static str> {
        crate::connection_close_reason(&self.extensions)
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

    /// SNI hostname extracted from the TLS `ClientHello`, if present.
    pub sni: Option<&'a str>,

    /// Upstream address being proxied to.
    ///
    /// `None` until a static upstream or a filter (e.g. `sni_router`)
    /// provides one.
    pub upstream_addr: Option<Cow<'a, str>>,

    /// Cluster name selected for this connection.
    ///
    /// Set by the listener config when `cluster` is configured.
    /// Read by `tcp_load_balancer` to look up the strategy.
    pub cluster: Option<Arc<str>>,

    /// Shared health registry for endpoint health lookups.
    pub health_registry: Option<&'a HealthRegistry>,

    /// Named key-value stores for runtime mappings.
    pub kv_stores: Option<&'a KvStoreRegistry>,

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
    async fn default_on_connect_returns_continue() {
        let filter = NoopTcpFilter;
        let mut ctx = TcpFilterContext {
            remote_addr: "127.0.0.1:12345",
            local_addr: "0.0.0.0:5432",
            sni: None,
            upstream_addr: Some(Cow::Borrowed("10.0.0.1:5432")),
            cluster: None,
            health_registry: None,
            kv_stores: None,
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
            sni: None,
            upstream_addr: Some(Cow::Borrowed("10.0.0.1:5432")),
            cluster: None,
            health_registry: None,
            kv_stores: None,
            connect_time: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
        };
        filter.on_disconnect(&mut ctx).await.unwrap();
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Minimal TCP filter that uses all trait defaults.
    struct NoopTcpFilter;

    #[async_trait]
    impl TcpFilter for NoopTcpFilter {
        fn name(&self) -> &'static str {
            "noop_tcp"
        }
    }
}
