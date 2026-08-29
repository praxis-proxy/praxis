// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Load-balancer filter: select an upstream endpoint from the routed cluster.

mod entry;
mod reselector;
mod strategy;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests;

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use metrics::SharedString;
use praxis_core::{
    config::Cluster,
    health::{ClusterHealthState, HealthRegistry},
};
use tracing::{debug, warn};

use self::entry::{ClusterEntry, build_cluster_entry};
pub use self::reselector::EndpointReselector;
use crate::{
    FilterError,
    actions::FilterAction,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// LoadBalancerFilter
// -----------------------------------------------------------------------------

/// Selects an upstream endpoint using the cluster's configured strategy.
///
/// Supported strategies:
/// - `round_robin` (default): cycles through endpoints in order, respecting weights via endpoint expansion.
/// - `least_connections`: picks the endpoint with the fewest active in-flight requests; decrements the counter on
///   `on_response`.
/// - `p2c`: samples two random endpoints and picks the less loaded one.
/// - `random`: picks a uniformly random endpoint, weighted by endpoint weight.
/// - `consistent_hash`: hashes a configurable request header (or the URI path when the header is absent) to pin
///   requests to a stable endpoint.
/// - `maglev`: hashes a configurable request header (or the URI path) through a Maglev lookup table for even
///   distribution and minimal disruption when endpoints change.
///
/// # YAML configuration
///
/// ```yaml
/// filter: load_balancer
/// clusters:
///   - name: backend
///     endpoints: ["10.0.0.1:80"]
/// ```
///
/// # Example
///
/// ```
/// use praxis_filter::LoadBalancerFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// clusters:
///   - name: backend
///     endpoints: ["10.0.0.1:80"]
/// "#,
/// )
/// .unwrap();
/// let filter = LoadBalancerFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "load_balancer");
/// ```
pub struct LoadBalancerFilter {
    /// Per-cluster resolved state (strategy, connection opts, TLS config).
    clusters: HashMap<Arc<str>, ClusterEntry>,
}

/// Deserialization wrapper for the load balancer's YAML config.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadBalancerConfig {
    /// Cluster definitions.
    #[serde(default)]
    clusters: Vec<Cluster>,
}

impl LoadBalancerFilter {
    /// Create a load balancer from a list of cluster definitions.
    ///
    /// # Panics
    ///
    /// Panics when a cluster contains an invalid authority override.
    /// Use [`Self::try_new`] when cluster definitions are not already
    /// validated.
    #[expect(clippy::panic, reason = "preserves the infallible public constructor contract")]
    pub fn new(clusters: &[Cluster]) -> Self {
        match Self::try_new(clusters) {
            Ok(filter) => filter,
            Err(error) => panic!("invalid load balancer cluster configuration: {error}"),
        }
    }

    /// Try to create a load balancer from a list of cluster definitions.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if any cluster's authority override
    /// is invalid.
    pub fn try_new(clusters: &[Cluster]) -> Result<Self, FilterError> {
        let map = clusters
            .iter()
            .map(|c| Ok((Arc::clone(&c.name), build_cluster_entry(c)?)))
            .collect::<Result<_, FilterError>>()?;
        Ok(Self { clusters: map })
    }

    /// Create a load balancer from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the cluster config is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: LoadBalancerConfig = crate::parse_filter_config("load_balancer", config)?;
        if cfg.clusters.is_empty() {
            return Err("load_balancer: 'clusters' is empty; every request would fail with 502".into());
        }
        Ok(Box::new(Self::try_new(&cfg.clusters)?))
    }

    /// Look up health state for `cluster_name` from the context's
    /// [`HealthRegistry`].
    fn cluster_health<'a>(registry: Option<&'a HealthRegistry>, cluster_name: &str) -> Option<&'a ClusterHealthState> {
        registry.and_then(|r| r.get(cluster_name))
    }
}

#[async_trait]
#[expect(
    clippy::too_many_lines,
    reason = "on_request orchestrates sequential setup and the pinned-endpoint branch"
)]
impl HttpFilter for LoadBalancerFilter {
    fn name(&self) -> &'static str {
        "load_balancer"
    }

    fn load_balancer_clusters(&self) -> Vec<String> {
        self.clusters.keys().map(ToString::to_string).collect()
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if ctx.upstream.is_some() {
            debug!("upstream already set, skipping LB selection");
            return Ok(FilterAction::Continue);
        }

        let Some(cluster) = ctx.cluster.as_ref() else {
            return Err(
                "load_balancer filter: no cluster set in context (is a router filter configured before this?)".into(),
            );
        };
        let cluster_name = cluster.as_ref();

        let entry = self.clusters.get(cluster_name).ok_or_else(|| -> FilterError {
            format!("load_balancer filter: unknown cluster '{cluster_name}'").into()
        })?;

        let health = Self::cluster_health(ctx.health_registry, cluster_name);

        // Session affinity: a preceding filter pinned an endpoint address.
        // Build a proper Upstream with the cluster's TLS and connection options.
        if let Some(pinned_addr) = ctx.pinned_endpoint_address.take() {
            // Health state is built from the cluster's configured endpoints,
            // so an unknown index means the pinned address left the cluster
            // (e.g. a config reload); fall through to normal selection rather
            // than routing to a removed endpoint. Recording the index also
            // lets passive health checks observe pinned traffic.
            let pinned_index = health.and_then(|h| h.endpoint_index(&pinned_addr));
            if health.is_none() || pinned_index.is_some() {
                debug!(cluster = %cluster_name, upstream = %pinned_addr, "using pinned endpoint from session affinity");
                ctx.selected_endpoint_index = pinned_index;
                // Known limitation: a pinned request is served directly without
                // a retry policy, retry budget, or endpoint reselector, so it is
                // not retried or failed over on a transient connect failure, and
                // its load is not tracked by counter-based strategies (strategy
                // .select is bypassed to honor affinity). Health-check-detected
                // outages are handled upstream by the session-affinity filter,
                // which does not pin to a down endpoint.
                ctx.upstream = Some(entry.build_upstream(pinned_addr, ctx));
                return Ok(FilterAction::Continue);
            }
            debug!(
                cluster = %cluster_name,
                pinned = %pinned_addr,
                "pinned endpoint no longer in cluster; selecting a new endpoint"
            );
        }

        if let Some(h) = health
            && h.endpoints().iter().all(|ep| !ep.is_healthy())
        {
            warn!(cluster = %cluster_name, "all endpoints unhealthy, routing to all (panic mode)");
            crate::metrics::record_lb_panic_mode(SharedString::from(Arc::clone(cluster)));
        }

        let addr = entry.strategy.select(ctx, health, &[]).ok_or_else(|| -> FilterError {
            format!("load_balancer filter: cluster '{cluster_name}' has no available endpoints").into()
        })?;
        debug!(cluster = %cluster_name, upstream = %addr, "upstream selected");

        ctx.selected_endpoint_index = health.and_then(|h| h.endpoint_index(&addr)).or(Some(usize::MAX));
        ctx.set_metadata("lb.selected", "true");

        // Track active request for retry budget.
        entry.retry_state.enter();
        ctx.cluster_retry_state = Some(Arc::clone(&entry.retry_state));

        let policy = match &ctx.route_retry_policy {
            Some(route_override) => entry.merged_retry_policy(route_override),
            None => Arc::clone(&entry.retry_policy),
        };
        ctx.retry_policy = Some(Arc::clone(&policy));

        let hash_key = entry.strategy.capture_hash_key(ctx);
        // The reselector is stateless config data: share one instance for
        // the dominant no-hash-key, cluster-default-policy case instead of
        // allocating a fresh one per request.
        ctx.endpoint_reselector = Some(if hash_key.is_none() && Arc::ptr_eq(&policy, &entry.retry_policy) {
            Arc::clone(entry.default_reselector())
        } else {
            Arc::new(entry.reselector_with_policy(hash_key, policy))
        });
        ctx.attempted_endpoints.push(Arc::clone(&addr));
        ctx.upstream = Some(entry.build_upstream(addr, ctx));

        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if ctx.get_metadata("lb.selected").is_none() {
            return Ok(FilterAction::Continue);
        }

        tracing::trace!("releasing in-flight counter");
        if let (Some(cluster_name), Some(upstream)) = (&ctx.cluster, &ctx.upstream)
            && let Some(entry) = self.clusters.get(cluster_name)
        {
            entry.strategy.release(&upstream.address);
        }
        if let Some(state) = &ctx.cluster_retry_state {
            state.leave();
            ctx.cluster_retry_state_released = true;
        }

        Ok(FilterAction::Continue)
    }
}
