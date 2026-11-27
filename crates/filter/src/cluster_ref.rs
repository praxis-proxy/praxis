// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Bind-time handles to top-level clusters for chain-binding callouts.
//!
//! A chain-binding filter resolves a cluster name once, at construction,
//! through [`ChainBindingContext::cluster`], and stages the returned
//! [`ClusterRef`] on each callout with
//! [`StagedCluster`](crate::StagedCluster). Resolving at construction means a
//! misspelled or removed cluster fails config load (and hot reload) instead of
//! failing a request.
//!
//! [`ChainBindingContext::cluster`]: crate::ChainBindingContext::cluster

use std::sync::Arc;

use praxis_core::{config::Cluster, connectivity::Upstream, retry::AdmissionLease};

use crate::{
    FilterError, HttpFilterContext,
    builtins::http::{ClusterEntry, build_cluster_entry},
};

// -----------------------------------------------------------------------------
// ClusterRef
// -----------------------------------------------------------------------------

/// A resolved top-level cluster a callout can be staged at.
///
/// Holds the same resolved state a `load_balancer` filter keeps for a cluster:
/// endpoints and load-balancing strategy, TLS material, authority, base path,
/// connection options, and retry policy with its budget. Health is read at
/// request time from the pipeline's health registry, by cluster name.
///
/// Cloning is cheap and shares the state, so round-robin position, in-flight
/// counts, and the retry budget are shared by every holder. One pipeline build
/// hands out a single `ClusterRef` per cluster name.
#[derive(Clone)]
pub struct ClusterRef {
    /// Shared resolved state.
    inner: Arc<ClusterRefInner>,
}

/// Shared state behind a [`ClusterRef`].
struct ClusterRefInner {
    /// Interned cluster name, used as `ctx.cluster` and the health key.
    name: Arc<str>,

    /// Resolved cluster state, built by the load balancer's own constructor.
    entry: ClusterEntry,

    /// Slow-start ramp for this cluster, when it configures one.
    #[cfg(feature = "slow-start")]
    ramp: Option<crate::load_balancing::slow_start::SlowStartBinding>,
}

impl ClusterRef {
    /// Resolve `cluster` into a handle.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] when the cluster's TLS material or authority
    /// override cannot be prepared.
    pub(crate) fn resolve(cluster: &Cluster) -> Result<Self, FilterError> {
        Ok(Self {
            inner: Arc::new(ClusterRefInner {
                name: Arc::clone(&cluster.name),
                entry: build_cluster_entry(cluster)?,
                #[cfg(feature = "slow-start")]
                ramp: crate::load_balancing::slow_start::binding_for_cluster(cluster),
            }),
        })
    }

    /// The cluster's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// The interned cluster name.
    pub(crate) fn name_arc(&self) -> &Arc<str> {
        &self.inner.name
    }

    /// The resolved cluster state.
    pub(crate) fn entry(&self) -> &ClusterEntry {
        &self.inner.entry
    }

    /// Claim one of the cluster's `max_connections` slots for a callout, as a
    /// `load_balancer` does for a request.
    ///
    /// One claim covers the whole callout, retries included; the slot goes
    /// back when the last lease holding it is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] when the cluster is at its `max_connections`.
    pub(crate) fn admit(&self) -> Result<Arc<AdmissionLease>, FilterError> {
        let state = self.entry().retry_state();
        AdmissionLease::claim(state).ok_or_else(|| {
            tracing::debug!(
                cluster = %self.name(),
                max_connections = state.max_concurrent.unwrap_or_default(),
                "cluster at max_connections, shedding callout"
            );
            crate::metrics::record_cluster_overload_reject(metrics::SharedString::from(Arc::clone(self.name_arc())));
            format!("filtered_subrequest: cluster '{}' is at max_connections", self.name()).into()
        })
    }

    /// Select an endpoint for a callout admitted under `admission`, as a
    /// `load_balancer` would.
    ///
    /// Reads the cluster's health from `ctx.health_registry`, applies panic
    /// mode and slow start, and picks with the cluster's strategy, skipping
    /// `exclude`d addresses. The lease records the endpoint index. The
    /// returned lease releases the endpoint's in-flight count when dropped and
    /// keeps `admission` alive until then.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] when the cluster has no endpoint to offer.
    pub(crate) fn select(
        &self,
        ctx: &HttpFilterContext<'_>,
        exclude: &[Arc<str>],
        admission: &Arc<AdmissionLease>,
    ) -> Result<(Upstream, ClusterLease), FilterError> {
        let entry = self.entry();
        let health = ctx.health_registry.and_then(|registry| registry.get(self.name()));
        let weights = self.slow_start_weights(health);
        let address = entry.pick(ctx, health, weights.as_ref(), exclude)?;
        let index = health
            .and_then(|state| state.endpoint_index(&address))
            .unwrap_or(usize::MAX);
        let upstream = entry.build_upstream(Arc::clone(&address), ctx);
        let lease = ClusterLease {
            cluster: self.clone(),
            address,
            index,
            admission: Arc::clone(admission),
        };
        Ok((upstream, lease))
    }

    /// Ramp snapshot for this pick, when the cluster configures slow start.
    fn slow_start_weights(
        &self,
        health: Option<&praxis_core::health::ClusterHealthState>,
    ) -> Option<crate::load_balancing::slow_start::EffectiveWeights> {
        #[cfg(feature = "slow-start")]
        {
            self.inner.ramp.as_ref().map(|ramp| ramp.snapshot(None, health))
        }
        #[cfg(not(feature = "slow-start"))]
        {
            let _ = (self, health);
            None
        }
    }

    /// Callouts currently holding one of this cluster's admission slots.
    #[cfg(test)]
    pub(crate) fn active_requests(&self) -> u64 {
        self.entry().retry_state().active_requests()
    }

    /// Attach this cluster's slow-start ramp to the pipeline's registry.
    ///
    /// Idempotent: opening an already-attached binding is a no-op.
    #[cfg(feature = "slow-start")]
    pub(crate) fn bind_slow_start(&self, registry: &Arc<crate::SlowStartRegistry>) {
        if let Some(ramp) = &self.inner.ramp {
            ramp.open(registry);
        }
    }

    /// Whether this cluster's slow-start ramp is attached to a registry.
    #[cfg(all(test, feature = "slow-start"))]
    pub(crate) fn ramp_attached(&self) -> bool {
        self.inner
            .ramp
            .as_ref()
            .is_some_and(crate::load_balancing::slow_start::SlowStartBinding::is_attached)
    }

    /// Whether two handles share the same resolved state.
    #[cfg(test)]
    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl std::fmt::Debug for ClusterRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterRef").field("name", &self.inner.name).finish()
    }
}

// -----------------------------------------------------------------------------
// ClusterLease
// -----------------------------------------------------------------------------

/// An endpoint selected from a [`ClusterRef`] for one callout.
///
/// Dropping the lease releases the endpoint's in-flight count (for
/// load-tracking strategies) exactly once, whichever way the callout ends.
/// It shares the callout's admission slot, which goes back with the last
/// lease holding it.
pub(crate) struct ClusterLease {
    /// Cluster the endpoint belongs to.
    cluster: ClusterRef,

    /// Selected endpoint address.
    address: Arc<str>,

    /// Index in the health registry, or `usize::MAX` for an untracked address.
    pub(crate) index: usize,

    /// The callout's `max_connections` slot.
    admission: Arc<AdmissionLease>,
}

impl ClusterLease {
    /// The callout's admission slot, for selecting a retry endpoint under it.
    pub(crate) fn admission(&self) -> &Arc<AdmissionLease> {
        &self.admission
    }
}

impl Drop for ClusterLease {
    fn drop(&mut self) {
        self.cluster.entry().release(&self.address);
    }
}

impl std::fmt::Debug for ClusterLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterLease")
            .field("cluster", &self.cluster.name())
            .field("address", &self.address)
            .finish()
    }
}
