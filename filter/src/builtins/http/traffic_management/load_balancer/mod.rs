//! Load-balancer filter: select an upstream endpoint from the routed cluster.

mod consistent_hash;
mod least_connections;
mod round_robin;

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use consistent_hash::ConsistentHash;
use least_connections::LeastConnections;
use praxis_core::{
    config::{Cluster, LoadBalancerStrategy, ParameterisedStrategy, SimpleStrategy},
    connectivity::{ConnectionOptions, Upstream},
    health::{ClusterHealthState, HealthRegistry},
};
use round_robin::RoundRobin;
use tracing::{debug, warn};

use crate::{
    FilterError,
    actions::FilterAction,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// WeightedEndpoint
// -----------------------------------------------------------------------------

/// A deduplicated endpoint carrying its own weight and original index.
///
/// ```ignore
/// let ep = WeightedEndpoint { address: "10.0.0.1:80".into(), weight: 3, index: 0 };
/// assert_eq!(ep.address.as_str(), "10.0.0.1:80");
/// assert_eq!(ep.weight, 3);
/// assert_eq!(ep.index, 0);
/// ```
#[derive(Debug, Clone)]
pub(crate) struct WeightedEndpoint {
    /// Socket address as `host:port`.
    pub(crate) address: Arc<str>,

    /// Relative forwarding weight (>= 1).
    pub(crate) weight: u32,

    /// Position in the original cluster endpoint list (for health state lookups).
    pub(crate) index: usize,
}

/// Build a [`WeightedEndpoint`] list from a cluster's endpoints.
fn build_weighted_endpoints(cluster: &Cluster) -> Vec<WeightedEndpoint> {
    cluster
        .endpoints
        .iter()
        .enumerate()
        .map(|(i, ep)| WeightedEndpoint {
            address: Arc::from(ep.address()),
            weight: ep.weight(),
            index: i,
        })
        .collect()
}

// -----------------------------------------------------------------------------
// LoadBalancerFilter
// -----------------------------------------------------------------------------

/// Selects an upstream endpoint using the cluster's configured strategy.
///
/// Supported strategies:
/// - `round_robin` (default): cycles through endpoints in order, respecting
///   weights via endpoint expansion.
/// - `least_connections`: picks the endpoint with the fewest active
///   in-flight requests; decrements the counter on `on_response`.
/// - `consistent_hash`: hashes a configurable request header (or the URI
///   path when the header is absent) to pin requests to a stable endpoint.
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
/// let yaml: serde_yaml::Value = serde_yaml::from_str(r#"
/// clusters:
///   - name: backend
///     endpoints: ["10.0.0.1:80"]
/// "#).unwrap();
/// let filter = LoadBalancerFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "load_balancer");
/// ```
pub struct LoadBalancerFilter {
    /// Per-cluster resolved state (strategy, connection opts, TLS config).
    clusters: HashMap<Arc<str>, ClusterEntry>,
}

/// Resolved state for a single cluster.
struct ClusterEntry {
    /// Connection options derived from the cluster config.
    opts: ConnectionOptions,

    /// Whether to use TLS when connecting to endpoints in this cluster.
    tls: bool,

    /// Optional SNI override for upstream TLS connections.
    sni: Option<String>,

    /// The load-balancing strategy for this cluster.
    strategy: Strategy,
}

/// Load-balancing strategy variant for a cluster.
enum Strategy {
    /// Cycle through endpoints in order, respecting weights.
    RoundRobin(RoundRobin),

    /// Pick the endpoint with the fewest active requests.
    LeastConnections(LeastConnections),

    /// Hash a request attribute to a stable endpoint.
    ConsistentHash(ConsistentHash),
}

impl Strategy {
    /// Pick the next endpoint address, skipping unhealthy
    /// endpoints when health state is available.
    fn select(&self, ctx: &HttpFilterContext<'_>, health: Option<&ClusterHealthState>) -> Arc<str> {
        match self {
            Self::RoundRobin(rr) => rr.select(health),
            Self::LeastConnections(lc) => lc.select(health),
            Self::ConsistentHash(ch) => ch.select(ctx, health),
        }
    }

    /// Called after a response arrives so that strategies that track in-flight
    /// request counts (e.g. `LeastConnections`) can decrement their counter.
    fn release(&self, addr: &str) {
        if let Self::LeastConnections(lc) = self {
            lc.release(addr);
        }
    }
}

impl LoadBalancerFilter {
    /// Create a load balancer from a list of cluster definitions.
    pub fn new(clusters: &[Cluster]) -> Self {
        let mut map = HashMap::new();

        for cluster in clusters {
            let endpoints = build_weighted_endpoints(cluster);
            let total_weight: u32 = endpoints.iter().map(|ep| ep.weight).sum();
            debug!(
                cluster = %cluster.name,
                endpoints = endpoints.len(),
                total_weight,
                "cluster registered"
            );

            let strategy = match &cluster.load_balancer_strategy {
                LoadBalancerStrategy::Simple(SimpleStrategy::RoundRobin) => {
                    Strategy::RoundRobin(RoundRobin::new(endpoints))
                },
                LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections) => {
                    Strategy::LeastConnections(LeastConnections::new(endpoints))
                },
                LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ConsistentHash(opts)) => {
                    Strategy::ConsistentHash(ConsistentHash::new(endpoints, opts.header.clone()))
                },
            };

            let opts = ConnectionOptions::from(cluster);
            map.insert(
                cluster.name.clone(),
                ClusterEntry {
                    opts,
                    tls: cluster.upstream_tls,
                    sni: cluster.upstream_sni.clone(),
                    strategy,
                },
            );
        }

        Self { clusters: map }
    }

    /// Look up health state for `cluster_name` from the context's
    /// [`HealthRegistry`].
    fn cluster_health<'a>(registry: Option<&'a HealthRegistry>, cluster_name: &str) -> Option<&'a ClusterHealthState> {
        registry.and_then(|r| r.get(cluster_name))
    }

    /// Create a load balancer from parsed YAML config.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let clusters: Vec<Cluster> = serde_yaml::from_value(
            config
                .get("clusters")
                .cloned()
                .unwrap_or(serde_yaml::Value::Sequence(vec![])),
        )
        .map_err(|e| -> FilterError { format!("load_balancer: {e}").into() })?;

        Ok(Box::new(Self::new(&clusters)))
    }
}

// -----------------------------------------------------------------------------
// Filter Impl
// -----------------------------------------------------------------------------

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
            && h.iter().all(|ep| !ep.is_healthy())
        {
            warn!(cluster = %cluster_name, "all endpoints unhealthy, routing to all (panic mode)");
        }

        let addr = entry.strategy.select(ctx, health);
        debug!(cluster = %cluster_name, upstream = %addr, "upstream selected");

        let sni = entry.sni.clone().or_else(|| {
            ctx.request
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        });

        ctx.upstream = Some(Upstream {
            address: addr,
            tls: entry.tls,
            sni,
            connection: entry.opts.clone(),
        });

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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, atomic::Ordering},
        time::Duration,
    };

    use praxis_core::config::{
        Cluster, ConsistentHashOpts, Endpoint, LoadBalancerStrategy, ParameterisedStrategy, SimpleStrategy,
    };

    use super::*;

    fn test_cluster(name: &str, endpoints: &[&str]) -> Cluster {
        Cluster::with_defaults(name, endpoints.iter().map(|s| (*s).into()).collect())
    }

    fn cluster_with_strategy(name: &str, endpoints: &[&str], strategy: LoadBalancerStrategy) -> Cluster {
        Cluster {
            load_balancer_strategy: strategy,
            ..Cluster::with_defaults(name, endpoints.iter().map(|s| (*s).into()).collect())
        }
    }

    #[test]
    fn new_creates_clusters() {
        let clusters = vec![test_cluster("web", &["127.0.0.1:8080"])];
        let lb = LoadBalancerFilter::new(&clusters);
        assert!(lb.clusters.contains_key("web"), "cluster 'web' should be registered");
    }

    #[test]
    fn new_multiple_clusters() {
        let clusters = vec![
            test_cluster("web", &["127.0.0.1:8080"]),
            test_cluster("api", &["127.0.0.1:9090"]),
        ];
        let lb = LoadBalancerFilter::new(&clusters);
        assert_eq!(lb.clusters.len(), 2, "both clusters should be registered");
    }

    #[tokio::test]
    async fn on_request_sets_upstream_round_robin() {
        let lb = LoadBalancerFilter::new(&[test_cluster("web", &["127.0.0.1:8080"])]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some(Arc::from("web"));
        let action = lb.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue), "round robin should continue");
        let upstream = ctx.upstream.expect("upstream should be set");
        assert_eq!(
            &*upstream.address, "127.0.0.1:8080",
            "upstream address should match endpoint"
        );
    }

    #[tokio::test]
    async fn on_request_sets_upstream_least_connections() {
        let cluster = cluster_with_strategy(
            "web",
            &["127.0.0.1:8080", "127.0.0.1:8081"],
            LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections),
        );
        let lb = LoadBalancerFilter::new(&[cluster]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some(Arc::from("web"));
        let action = lb.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "least connections should continue"
        );
        assert!(ctx.upstream.is_some(), "upstream should be set by least connections");
    }

    #[tokio::test]
    async fn on_request_sets_upstream_consistent_hash() {
        let cluster = cluster_with_strategy(
            "web",
            &["127.0.0.1:8080", "127.0.0.1:8081"],
            LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ConsistentHash(ConsistentHashOpts {
                header: None,
            })),
        );
        let lb = LoadBalancerFilter::new(&[cluster]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some(Arc::from("web"));
        let action = lb.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "consistent hash should continue"
        );
        assert!(ctx.upstream.is_some(), "upstream should be set by consistent hash");
    }

    #[tokio::test]
    async fn on_response_releases_least_connections_counter() {
        let cluster = cluster_with_strategy(
            "web",
            &["127.0.0.1:8080"],
            LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections),
        );
        let lb = LoadBalancerFilter::new(&[cluster]);

        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some(Arc::from("web"));

        lb.on_request(&mut ctx).await.unwrap();

        let entry = lb.clusters.get("web").unwrap();
        if let Strategy::LeastConnections(lc) = &entry.strategy {
            assert_eq!(
                lc.counters["127.0.0.1:8080"].load(Ordering::Relaxed),
                1,
                "counter should be 1 after request"
            );
        }

        lb.on_response(&mut ctx).await.unwrap();

        if let Strategy::LeastConnections(lc) = &entry.strategy {
            assert_eq!(
                lc.counters["127.0.0.1:8080"].load(Ordering::Relaxed),
                0,
                "counter should be 0 after response"
            );
        }
    }

    #[tokio::test]
    async fn on_request_errors_when_no_cluster() {
        let lb = LoadBalancerFilter::new(&[test_cluster("web", &["127.0.0.1:8080"])]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let result = lb.on_request(&mut ctx).await;
        assert!(result.is_err(), "missing cluster should produce error");
        assert!(
            result.unwrap_err().to_string().contains("no cluster set"),
            "error should mention no cluster set"
        );
    }

    #[tokio::test]
    async fn on_request_errors_for_unknown_cluster() {
        let lb = LoadBalancerFilter::new(&[test_cluster("web", &["127.0.0.1:8080"])]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some(Arc::from("nonexistent"));
        let result = lb.on_request(&mut ctx).await;
        assert!(result.is_err(), "unknown cluster should produce error");
        assert!(
            result.unwrap_err().to_string().contains("unknown cluster"),
            "error should mention unknown cluster"
        );
    }

    #[test]
    fn from_config_parses_yaml() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            clusters:
              - name: "backend"
                endpoints: ["10.0.0.1:80"]
            "#,
        )
        .unwrap();
        let filter = LoadBalancerFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "load_balancer", "filter name should be load_balancer");
    }

    #[test]
    fn from_config_empty_clusters() {
        let yaml = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let filter = LoadBalancerFilter::from_config(&yaml).unwrap();
        assert_eq!(
            filter.name(),
            "load_balancer",
            "empty clusters should still create filter"
        );
    }

    #[test]
    fn timeout_options_from_cluster() {
        let cluster = Cluster {
            connection_timeout_ms: Some(5000),
            idle_timeout_ms: Some(30000),
            read_timeout_ms: Some(10000),
            ..Cluster::with_defaults("web", vec!["127.0.0.1:80".into()])
        };
        let opts = ConnectionOptions::from(&cluster);
        assert_eq!(
            opts.connection_timeout,
            Some(Duration::from_millis(5000)),
            "connection timeout should be parsed from config"
        );
        assert_eq!(
            opts.idle_timeout,
            Some(Duration::from_millis(30000)),
            "idle timeout should be parsed from config"
        );
        assert_eq!(
            opts.read_timeout,
            Some(Duration::from_millis(10000)),
            "read timeout should be parsed from config"
        );
        assert!(opts.write_timeout.is_none(), "unset write timeout should be None");
    }

    #[test]
    fn timeout_options_all_none() {
        let cluster = test_cluster("web", &["127.0.0.1:80"]);
        let opts = ConnectionOptions::from(&cluster);
        assert!(
            opts.connection_timeout.is_none(),
            "default connection timeout should be None"
        );
        assert!(opts.idle_timeout.is_none(), "default idle timeout should be None");
        assert!(opts.read_timeout.is_none(), "default read timeout should be None");
        assert!(opts.write_timeout.is_none(), "default write timeout should be None");
    }

    #[tokio::test]
    async fn weighted_endpoints_expand_proportionally() {
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

        let lb = LoadBalancerFilter::new(&[cluster]);

        let mut counts = std::collections::HashMap::new();
        for _ in 0..4 {
            let req = crate::test_utils::make_request(http::Method::GET, "/");
            let mut ctx = crate::test_utils::make_filter_context(&req);
            ctx.cluster = Some(Arc::from("weighted"));
            let action = lb.on_request(&mut ctx).await.unwrap();
            assert!(
                matches!(action, FilterAction::Continue),
                "weighted selection should continue"
            );
            *counts.entry(ctx.upstream.unwrap().address).or_insert(0u32) += 1;
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
    async fn sni_fallback_to_host_header_when_upstream_sni_none() {
        let cluster = Cluster {
            upstream_tls: true,
            ..Cluster::with_defaults("no-sni", vec!["10.0.0.1:443".into()])
        };
        let lb = LoadBalancerFilter::new(&[cluster]);

        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers
            .insert("host", http::HeaderValue::from_static("api.example.com"));
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some(Arc::from("no-sni"));

        lb.on_request(&mut ctx).await.unwrap();
        let upstream = ctx.upstream.expect("upstream should be set");
        assert!(upstream.tls, "TLS should be enabled");
        assert_eq!(
            upstream.sni.as_deref(),
            Some("api.example.com"),
            "SNI should fall back to Host header when upstream_sni is None"
        );
    }

    #[tokio::test]
    async fn sni_fallback_is_none_when_no_host_header() {
        let cluster = Cluster {
            upstream_tls: true,
            ..Cluster::with_defaults("no-sni", vec!["10.0.0.1:443".into()])
        };
        let lb = LoadBalancerFilter::new(&[cluster]);

        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some(Arc::from("no-sni"));

        lb.on_request(&mut ctx).await.unwrap();
        let upstream = ctx.upstream.expect("upstream should be set");
        assert!(upstream.tls, "TLS should be enabled");
        assert!(
            upstream.sni.is_none(),
            "SNI should be None when no Host header and no upstream_sni"
        );
    }

    #[tokio::test]
    async fn explicit_sni_overrides_host_header() {
        let cluster = Cluster {
            upstream_sni: Some("override.example.com".into()),
            upstream_tls: true,
            ..Cluster::with_defaults("explicit-sni", vec!["10.0.0.1:443".into()])
        };
        let lb = LoadBalancerFilter::new(&[cluster]);

        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers
            .insert("host", http::HeaderValue::from_static("original.example.com"));
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some(Arc::from("explicit-sni"));

        lb.on_request(&mut ctx).await.unwrap();
        let upstream = ctx.upstream.expect("upstream should be set");
        assert_eq!(
            upstream.sni.as_deref(),
            Some("override.example.com"),
            "explicit upstream_sni should override Host header"
        );
    }

    #[tokio::test]
    async fn upstream_tls_and_sni_wired_from_cluster() {
        let cluster = Cluster {
            upstream_sni: Some("api.example.com".into()),
            upstream_tls: true,
            ..Cluster::with_defaults("secure", vec!["10.0.0.1:443".into()])
        };
        let lb = LoadBalancerFilter::new(&[cluster]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some(Arc::from("secure"));
        lb.on_request(&mut ctx).await.unwrap();
        let upstream = ctx.upstream.unwrap();
        assert!(upstream.tls, "TLS should be enabled from cluster config");
        assert_eq!(
            upstream.sni.as_deref(),
            Some("api.example.com"),
            "SNI should match cluster config"
        );
    }
}
