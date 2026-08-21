// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Endpoint re-selection for alternate-host retries.

use std::sync::Arc;

use praxis_core::{
    config::{CachedClusterTls, RetryPolicy},
    connectivity::{ConnectionOptions, Upstream},
    health::ClusterHealthState,
    retry::ClusterRetryState,
};

use super::strategy::Strategy;

// -----------------------------------------------------------------------------
// EndpointReselector
// -----------------------------------------------------------------------------

/// Captures enough cluster state to re-select an upstream on retry
/// without re-running the filter pipeline.
pub struct EndpointReselector {
    /// LB strategy for re-selection.
    strategy: Arc<Strategy>,
    /// Connection options (timeouts, keepalive, etc.).
    opts: Arc<ConnectionOptions>,
    /// Optional TLS configuration for the cluster.
    tls: Option<CachedClusterTls>,
    /// Hash key captured at first selection (for consistent-hash).
    hash_key: Option<Arc<str>>,
    /// Resolved retry policy for this cluster.
    pub retry_policy: Arc<RetryPolicy>,
    /// Shared retry budget / active-request counter.
    pub retry_state: Arc<ClusterRetryState>,
}

impl EndpointReselector {
    /// Build a reselector from resolved cluster pieces.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "grouping into a config struct adds indirection without benefit here"
    )]
    pub(super) fn new(
        strategy: Arc<Strategy>,
        opts: Arc<ConnectionOptions>,
        tls: Option<CachedClusterTls>,
        hash_key: Option<Arc<str>>,
        retry_policy: Arc<RetryPolicy>,
        retry_state: Arc<ClusterRetryState>,
    ) -> Self {
        Self {
            strategy,
            opts,
            tls,
            hash_key,
            retry_policy,
            retry_state,
        }
    }

    /// Select an upstream address, skipping `exclude`d endpoints.
    pub fn select_address(&self, health: Option<&ClusterHealthState>, exclude: &[Arc<str>]) -> Option<Arc<str>> {
        self.strategy.select_with_key(self.hash_key.as_deref(), health, exclude)
    }

    /// Build an [`Upstream`] for `addr`.
    #[must_use]
    pub fn build_upstream(&self, addr: Arc<str>) -> Upstream {
        Upstream {
            address: addr,
            connection: Arc::clone(&self.opts),
            tls: self.tls.clone(),
        }
    }

    /// Release an in-flight counter for strategies that track load.
    pub fn release(&self, addr: &str) {
        self.strategy.release(addr);
    }
}
