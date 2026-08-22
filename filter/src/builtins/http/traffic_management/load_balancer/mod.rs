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
    /// # Errors
    ///
    /// Returns [`FilterError`] when a cluster's TLS material cannot be
    /// loaded (missing or unparsable CA / client-cert files).
    pub fn new(clusters: &[Cluster]) -> Result<Self, FilterError> {
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
        Ok(Box::new(Self::new(&cfg.clusters)?))
    }

    /// Look up health state for `cluster_name` from the context's
    /// [`HealthRegistry`].
    fn cluster_health<'a>(registry: Option<&'a HealthRegistry>, cluster_name: &str) -> Option<&'a ClusterHealthState> {
        registry.and_then(|r| r.get(cluster_name))
    }
}

#[async_trait]
#[expect(clippy::too_many_lines, reason = "on_request orchestrates sequential setup")]
impl HttpFilter for LoadBalancerFilter {
    fn name(&self) -> &'static str {
        "load_balancer"
    }

    fn load_balancer_clusters(&self) -> Vec<String> {
        self.clusters.keys().map(ToString::to_string).collect()
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
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

        if let Some(h) = health {
            ctx.selected_endpoint_index = h.endpoint_index(&addr);
        }

        // Track active request for retry budget.
        entry.retry_state.enter();
        ctx.cluster_retry_state = Some(Arc::clone(&entry.retry_state));

        let policy = match &ctx.route_retry_policy {
            Some(route_override) => Arc::new(entry.retry_policy.merge_override(route_override)),
            None => Arc::clone(&entry.retry_policy),
        };
        ctx.retry_policy = Some(Arc::clone(&policy));

        let hash_key = entry.strategy.capture_hash_key(ctx);
        ctx.endpoint_reselector = Some(Arc::new(entry.reselector_with_policy(hash_key, policy)));
        ctx.attempted_endpoints.push(Arc::clone(&addr));
        ctx.upstream = Some(entry.build_upstream(addr, ctx));

        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
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
