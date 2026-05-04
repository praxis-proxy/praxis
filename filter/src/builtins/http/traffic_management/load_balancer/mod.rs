// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Load-balancer filter: select an upstream endpoint from the routed cluster.

mod entry;
mod strategy;

#[cfg(test)]
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
use praxis_core::{
    config::Cluster,
    health::{ClusterHealthState, HealthRegistry},
};
use tracing::{debug, warn};

use self::entry::{ClusterEntry, build_cluster_entry};
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
/// - `consistent_hash`: hashes a configurable request header (or the URI path when the header is absent) to pin
///   requests to a stable endpoint.
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
    pub fn new(clusters: &[Cluster]) -> Self {
        let map = clusters
            .iter()
            .map(|c| (Arc::clone(&c.name), build_cluster_entry(c)))
            .collect();
        Self { clusters: map }
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
        Ok(Box::new(Self::new(&cfg.clusters)))
    }

    /// Look up health state for `cluster_name` from the context's
    /// [`HealthRegistry`].
    fn cluster_health<'a>(registry: Option<&'a HealthRegistry>, cluster_name: &str) -> Option<&'a ClusterHealthState> {
        registry.and_then(|r| r.get(cluster_name))
    }
}

#[async_trait]
impl HttpFilter for LoadBalancerFilter {
    fn name(&self) -> &'static str {
        "load_balancer"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(cluster_name) = ctx.cluster.as_deref() else {
            return Err(
                "load_balancer filter: no cluster set in context (is a router filter configured before this?)".into(),
            );
        };

        let entry = self.clusters.get(cluster_name).ok_or_else(|| -> FilterError {
            format!("load_balancer filter: unknown cluster '{cluster_name}'").into()
        })?;

        let health = Self::cluster_health(ctx.health_registry, cluster_name);

        if let Some(h) = health
            && h.endpoints().iter().all(|ep| !ep.is_healthy())
        {
            warn!(cluster = %cluster_name, "all endpoints unhealthy, routing to all (panic mode)");
        }

        let addr = entry.strategy.select(ctx, health);
        debug!(cluster = %cluster_name, upstream = %addr, "upstream selected");

        if let Some(h) = health {
            ctx.selected_endpoint_index = h.endpoint_index(&addr);
        }

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

        Ok(FilterAction::Continue)
    }
}
