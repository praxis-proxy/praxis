// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! TCP load-balancer filter: select an upstream endpoint from a cluster.

use std::{borrow::Cow, collections::HashMap, sync::Arc};

use async_trait::async_trait;
use praxis_core::{
    config::Cluster,
    health::{ClusterHealthState, HealthRegistry},
};
use tracing::{debug, warn};

use crate::{
    FilterError,
    actions::FilterAction,
    load_balancing::{
        endpoint::build_weighted_endpoints,
        strategy::{Strategy, build_strategy},
    },
    tcp_filter::{TcpFilter, TcpFilterContext},
};

// -----------------------------------------------------------------------------
// TcpLoadBalancerConfig
// -----------------------------------------------------------------------------

/// Deserialization wrapper for the TCP load balancer's YAML config.
#[derive(serde::Deserialize)]
struct TcpLoadBalancerConfig {
    /// Cluster definitions.
    #[serde(default)]
    clusters: Vec<Cluster>,
}

// -----------------------------------------------------------------------------
// TcpLoadBalancerFilter
// -----------------------------------------------------------------------------

/// Selects an upstream TCP endpoint using the cluster's configured strategy.
///
/// Reads `ctx.cluster` to find the target cluster, selects an endpoint via
/// the configured strategy, and writes the result to `ctx.upstream_addr`.
/// On disconnect, releases the least-connections counter if applicable.
///
/// # YAML configuration
///
/// ```yaml
/// filter: tcp_load_balancer
/// clusters:
///   - name: db_pool
///     endpoints: ["10.0.0.1:5432", "10.0.0.2:5432"]
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::TcpLoadBalancerFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// clusters:
///   - name: db_pool
///     endpoints: ["10.0.0.1:5432"]
/// "#,
/// )
/// .unwrap();
/// let filter = TcpLoadBalancerFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "tcp_load_balancer");
/// ```
pub struct TcpLoadBalancerFilter {
    /// Per-cluster resolved strategy.
    clusters: HashMap<Arc<str>, Strategy>,
}

impl TcpLoadBalancerFilter {
    /// Create a TCP load balancer from a list of cluster definitions.
    pub fn new(clusters: &[Cluster]) -> Self {
        let map = clusters
            .iter()
            .map(|c| {
                let endpoints = build_weighted_endpoints(c);
                let total_weight: u32 = endpoints.iter().map(|ep| ep.weight).sum();
                debug!(
                    cluster = %c.name,
                    endpoints = endpoints.len(),
                    total_weight,
                    "TCP cluster registered"
                );
                let strategy = build_strategy(&c.load_balancer_strategy, endpoints);
                (Arc::clone(&c.name), strategy)
            })
            .collect();
        Self { clusters: map }
    }

    /// Create a TCP load balancer from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the cluster config is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn TcpFilter>, FilterError> {
        let cfg: TcpLoadBalancerConfig = crate::factory::parse_filter_config("tcp_load_balancer", config)?;
        Ok(Box::new(Self::new(&cfg.clusters)))
    }

    /// Look up health state for `cluster_name` from the context's
    /// [`HealthRegistry`].
    fn cluster_health<'a>(registry: Option<&'a HealthRegistry>, cluster_name: &str) -> Option<&'a ClusterHealthState> {
        registry.and_then(|r| r.get(cluster_name))
    }
}

#[async_trait]
impl TcpFilter for TcpLoadBalancerFilter {
    fn name(&self) -> &'static str {
        "tcp_load_balancer"
    }

    async fn on_connect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(cluster_name) = ctx.cluster.as_deref() else {
            return Err(
                "tcp_load_balancer: no cluster set in context (is a cluster configured on the listener?)".into(),
            );
        };

        let strategy = self
            .clusters
            .get(cluster_name)
            .ok_or_else(|| -> FilterError { format!("tcp_load_balancer: unknown cluster '{cluster_name}'").into() })?;

        let health = Self::cluster_health(ctx.health_registry, cluster_name);

        if let Some(h) = health
            && h.endpoints().iter().all(|ep| !ep.is_healthy())
        {
            warn!(cluster = %cluster_name, "all endpoints unhealthy, routing to all (panic mode)");
        }

        let client_ip = ctx.remote_addr.rsplit_once(':').map_or(ctx.remote_addr, |(ip, _)| ip);
        let addr = strategy.select(Some(client_ip), health);
        debug!(cluster = %cluster_name, upstream = %addr, "TCP upstream selected");

        ctx.upstream_addr = Some(Cow::Owned(addr.to_string()));

        Ok(FilterAction::Continue)
    }

    async fn on_disconnect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<(), FilterError> {
        if let (Some(cluster_name), Some(upstream_addr)) = (&ctx.cluster, &ctx.upstream_addr)
            && let Some(strategy) = self.clusters.get(cluster_name.as_ref())
        {
            strategy.release(upstream_addr);
        }

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    unused_must_use,
    reason = "tests"
)]
mod tests {
    use std::{borrow::Cow, collections::HashMap, sync::Arc, time::Instant};

    use praxis_core::{
        config::{Cluster, ConsistentHashOpts, Endpoint, LoadBalancerStrategy, ParameterisedStrategy, SimpleStrategy},
        health::{ClusterHealthEntry, ClusterHealthState, EndpointHealth},
    };

    use super::*;

    #[tokio::test]
    async fn round_robin_distributes_across_endpoints() {
        let lb = TcpLoadBalancerFilter::new(&[test_cluster("db", &["10.0.0.1:5432", "10.0.0.2:5432"])]);
        let mut addrs = Vec::new();
        for _ in 0..4 {
            let mut ctx = make_ctx("db");
            lb.on_connect(&mut ctx).await.unwrap();
            addrs.push(ctx.upstream_addr.unwrap().into_owned());
        }
        assert_eq!(&addrs[0], "10.0.0.1:5432", "first should be endpoint 1");
        assert_eq!(&addrs[1], "10.0.0.2:5432", "second should be endpoint 2");
        assert_eq!(&addrs[2], "10.0.0.1:5432", "third should wrap to endpoint 1");
        assert_eq!(&addrs[3], "10.0.0.2:5432", "fourth should be endpoint 2");
    }

    #[tokio::test]
    async fn least_connections_picks_least_loaded() {
        let cluster = cluster_with_strategy(
            "db",
            &["10.0.0.1:5432", "10.0.0.2:5432"],
            LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections),
        );
        let lb = TcpLoadBalancerFilter::new(&[cluster]);

        let mut ctx1 = make_ctx("db");
        lb.on_connect(&mut ctx1).await.unwrap();
        let first = ctx1.upstream_addr.as_deref().unwrap().to_owned();

        let mut ctx2 = make_ctx("db");
        lb.on_connect(&mut ctx2).await.unwrap();
        let second = ctx2.upstream_addr.as_deref().unwrap().to_owned();
        assert_ne!(first, second, "should select different endpoint for second connection");

        lb.on_disconnect(&mut ctx1).await.unwrap();

        let mut ctx3 = make_ctx("db");
        lb.on_connect(&mut ctx3).await.unwrap();
        assert_eq!(
            ctx3.upstream_addr.as_deref().unwrap(),
            &first,
            "released endpoint should be selected again"
        );
    }

    #[tokio::test]
    async fn consistent_hash_stable_for_same_client() {
        let cluster = cluster_with_strategy(
            "cache",
            &["10.0.0.1:6379", "10.0.0.2:6379", "10.0.0.3:6379"],
            LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ConsistentHash(ConsistentHashOpts {
                header: None,
            })),
        );
        let lb = TcpLoadBalancerFilter::new(&[cluster]);

        let mut first_addr = String::new();
        for i in 0..10 {
            let mut ctx = make_ctx("cache");
            lb.on_connect(&mut ctx).await.unwrap();
            let addr = ctx.upstream_addr.unwrap().into_owned();
            if i == 0 {
                first_addr = addr.clone();
            }
            assert_eq!(
                addr, first_addr,
                "same client IP should always route to same endpoint (call {i})"
            );
        }
    }

    #[tokio::test]
    async fn health_aware_skips_unhealthy() {
        let cluster = test_cluster("db", &["10.0.0.1:5432", "10.0.0.2:5432", "10.0.0.3:5432"]);
        let lb = TcpLoadBalancerFilter::new(&[cluster]);

        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new(), EndpointHealth::new(), EndpointHealth::new()],
            vec![
                Arc::from("10.0.0.1:5432"),
                Arc::from("10.0.0.2:5432"),
                Arc::from("10.0.0.3:5432"),
            ],
            None,
            None,
        ));
        state.endpoints()[0].mark_unhealthy();

        let registry: HealthRegistry = Arc::new([(Arc::from("db"), state)].into_iter().collect());

        let mut ctx = make_ctx_with_health("db", &registry);
        lb.on_connect(&mut ctx).await.unwrap();
        assert_ne!(
            ctx.upstream_addr.as_deref().unwrap(),
            "10.0.0.1:5432",
            "unhealthy endpoint should be skipped"
        );
    }

    #[tokio::test]
    async fn weighted_endpoints_proportional() {
        let cluster = Cluster::with_defaults(
            "weighted",
            vec![
                Endpoint::Simple("10.0.0.1:80".into()),
                Endpoint::Weighted {
                    address: "10.0.0.2:80".into(),
                    weight: 3,
                },
            ],
        );
        let lb = TcpLoadBalancerFilter::new(&[cluster]);

        let mut counts = HashMap::new();
        for _ in 0..4 {
            let mut ctx = make_ctx("weighted");
            lb.on_connect(&mut ctx).await.unwrap();
            *counts.entry(ctx.upstream_addr.unwrap().into_owned()).or_insert(0u32) += 1;
        }
        assert_eq!(
            *counts.get("10.0.0.1:80").unwrap_or(&0),
            1,
            "weight-1 endpoint should be selected once per cycle"
        );
        assert_eq!(
            *counts.get("10.0.0.2:80").unwrap_or(&0),
            3,
            "weight-3 endpoint should be selected three times per cycle"
        );
    }

    #[tokio::test]
    async fn consistent_hash_stable_across_ephemeral_ports() {
        let cluster = cluster_with_strategy(
            "cache",
            &["10.0.0.1:6379", "10.0.0.2:6379", "10.0.0.3:6379"],
            LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ConsistentHash(ConsistentHashOpts {
                header: None,
            })),
        );
        let lb = TcpLoadBalancerFilter::new(&[cluster]);

        let mut first_addr = String::new();
        let ports = [54321, 54322, 60000, 12345, 9999];
        for (i, port) in ports.iter().enumerate() {
            let mut ctx = TcpFilterContext {
                remote_addr: &format!("192.168.1.10:{port}"),
                local_addr: "0.0.0.0:6379",
                sni: None,
                upstream_addr: None,
                cluster: Some(Arc::from("cache")),
                health_registry: None,
                connect_time: Instant::now(),
                bytes_in: 0,
                bytes_out: 0,
            };
            lb.on_connect(&mut ctx).await.unwrap();
            let addr = ctx.upstream_addr.unwrap().into_owned();
            if i == 0 {
                first_addr = addr.clone();
            }
            assert_eq!(
                addr, first_addr,
                "same client IP with port {port} should route to same endpoint"
            );
        }
    }

    #[tokio::test]
    async fn errors_when_no_cluster_set() {
        let lb = TcpLoadBalancerFilter::new(&[test_cluster("db", &["10.0.0.1:5432"])]);
        let mut ctx = TcpFilterContext {
            remote_addr: "127.0.0.1:12345",
            local_addr: "0.0.0.0:5432",
            sni: None,
            upstream_addr: None,
            cluster: None,
            health_registry: None,
            connect_time: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
        };
        let err = lb.on_connect(&mut ctx).await.unwrap_err();
        assert!(
            err.to_string().contains("no cluster set"),
            "error should mention no cluster set: {err}"
        );
    }

    #[tokio::test]
    async fn errors_for_unknown_cluster() {
        let lb = TcpLoadBalancerFilter::new(&[test_cluster("db", &["10.0.0.1:5432"])]);
        let mut ctx = make_ctx("nonexistent");
        let err = lb.on_connect(&mut ctx).await.unwrap_err();
        assert!(
            err.to_string().contains("unknown cluster"),
            "error should mention unknown cluster: {err}"
        );
    }

    #[test]
    fn from_config_parses_yaml() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
clusters:
  - name: "db_pool"
    endpoints: ["10.0.0.1:5432"]
"#,
        )
        .unwrap();
        let filter = TcpLoadBalancerFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "tcp_load_balancer", "filter name should match");
    }

    #[test]
    fn from_config_empty_clusters() {
        let yaml = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let filter = TcpLoadBalancerFilter::from_config(&yaml).unwrap();
        assert_eq!(
            filter.name(),
            "tcp_load_balancer",
            "empty clusters should still create filter"
        );
    }

    #[tokio::test]
    async fn disconnect_without_cluster_is_noop() {
        let lb = TcpLoadBalancerFilter::new(&[test_cluster("db", &["10.0.0.1:5432"])]);
        let mut ctx = TcpFilterContext {
            remote_addr: "127.0.0.1:12345",
            local_addr: "0.0.0.0:5432",
            sni: None,
            upstream_addr: Some(Cow::Borrowed("10.0.0.1:5432")),
            cluster: None,
            health_registry: None,
            connect_time: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
        };
        lb.on_disconnect(&mut ctx).await.unwrap();
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`Cluster`] with default strategy for testing.
    fn test_cluster(name: &str, endpoints: &[&str]) -> Cluster {
        Cluster::with_defaults(name, endpoints.iter().map(|s| (*s).into()).collect())
    }

    /// Build a [`Cluster`] with a specific load balancer strategy.
    fn cluster_with_strategy(name: &str, endpoints: &[&str], strategy: LoadBalancerStrategy) -> Cluster {
        Cluster {
            load_balancer_strategy: strategy,
            ..Cluster::with_defaults(name, endpoints.iter().map(|s| (*s).into()).collect())
        }
    }

    /// Build a [`TcpFilterContext`] with a cluster set.
    fn make_ctx(cluster: &str) -> TcpFilterContext<'static> {
        TcpFilterContext {
            remote_addr: "192.168.1.10:54321",
            local_addr: "0.0.0.0:5432",
            sni: None,
            upstream_addr: None,
            cluster: Some(Arc::from(cluster)),
            health_registry: None,
            connect_time: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    /// Build a [`TcpFilterContext`] with a cluster and health registry.
    fn make_ctx_with_health<'a>(cluster: &str, registry: &'a HealthRegistry) -> TcpFilterContext<'a> {
        TcpFilterContext {
            remote_addr: "192.168.1.10:54321",
            local_addr: "0.0.0.0:5432",
            sni: None,
            upstream_addr: None,
            cluster: Some(Arc::from(cluster)),
            health_registry: Some(registry),
            connect_time: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
        }
    }
}
