// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Endpoint re-selection for alternate-host retries.

use std::sync::Arc;

use praxis_core::{
    config::{CachedClusterTls, RetryPolicy},
    connectivity::{ConnectionOptions, Upstream},
    health::ClusterHealthState,
    retry::ClusterRetryState,
};

use super::{authority::AuthorityResolver, strategy::Strategy};
use crate::load_balancing::slow_start::EffectiveWeights;

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
    /// The cluster's upstream `Host` source, carried so a retry to a
    /// reselected endpoint keeps rewriting `Host` (to the new endpoint's
    /// address when the authority follows the endpoint) instead of
    /// silently reverting to the downstream value.
    authority: AuthorityResolver,

    /// Normalized upstream base path for this cluster, if any.
    base_path: Option<Arc<str>>,
    /// Hash key captured at first selection (for consistent-hash).
    hash_key: Option<Arc<str>>,
    /// Resolved retry policy for this cluster.
    pub retry_policy: Arc<RetryPolicy>,
    /// Shared retry budget / active-request counter.
    pub retry_state: Arc<ClusterRetryState>,

    /// Ramp weights captured for this request's retries.
    ///
    /// `None` keeps configured weights. A shared reselector leaves this empty;
    /// a request whose cluster is scaling gets its own reselector.
    weights: Option<EffectiveWeights>,
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
        authority: AuthorityResolver,
        base_path: Option<Arc<str>>,
        hash_key: Option<Arc<str>>,
        retry_policy: Arc<RetryPolicy>,
        retry_state: Arc<ClusterRetryState>,
    ) -> Self {
        Self {
            strategy,
            opts,
            tls,
            authority,
            base_path,
            hash_key,
            retry_policy,
            retry_state,
            weights: None,
        }
    }

    /// Remember the ramp snapshot used for the first pick of this request.
    #[must_use]
    pub(super) fn with_weights(mut self, weights: EffectiveWeights) -> Self {
        self.weights = Some(weights);
        self
    }

    /// Select an upstream address, skipping `exclude`d endpoints.
    pub fn select_address(&self, health: Option<&ClusterHealthState>, exclude: &[Arc<str>]) -> Option<Arc<str>> {
        self.strategy
            .select_with_key(self.hash_key.as_deref(), health, exclude, self.weights.as_ref())
    }

    /// Build an [`Upstream`] for `addr`.
    #[must_use]
    pub fn build_upstream(&self, addr: Arc<str>) -> Upstream {
        let authority = self.authority.for_address(&addr);
        Upstream {
            address: addr,
            authority,
            base_path: self.base_path.clone(),
            connection: Arc::clone(&self.opts),
            tls: self.tls.clone(),
        }
    }

    /// Release an in-flight counter for strategies that track load.
    pub fn release(&self, addr: &str) {
        self.strategy.release(addr);
    }
}
