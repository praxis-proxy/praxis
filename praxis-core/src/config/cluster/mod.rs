//! Upstream cluster definitions: endpoints, load-balancing strategies, and timeouts.
//!
//! Referenced by router and load-balancer filters at runtime.

mod endpoint;
mod load_balancer_strategy;

pub use endpoint::Endpoint;
pub use load_balancer_strategy::{ConsistentHashOpts, LoadBalancerStrategy, ParameterisedStrategy, SimpleStrategy};
use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// Cluster
// -----------------------------------------------------------------------------

/// A named group of upstream endpoints.
///
/// ```
/// # use praxis_core::config::Cluster;
/// let yaml = r#"
/// name: "backend"
/// endpoints: ["10.0.0.1:8080"]
/// connection_timeout_ms: 5000
/// idle_timeout_ms: 30000
/// "#;
/// let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
/// assert_eq!(cluster.connection_timeout_ms, Some(5000));
/// assert_eq!(cluster.idle_timeout_ms, Some(30000));
/// assert!(cluster.read_timeout_ms.is_none());
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]

pub struct Cluster {
    /// Unique name for the cluster.
    pub name: String,

    /// TCP connection timeout in milliseconds.
    #[serde(default)]
    pub connection_timeout_ms: Option<u64>,

    /// List of endpoints for the cluster. Each entry is either a plain
    /// `"host:port"` string or a `{ address, weight }` object.
    pub endpoints: Vec<Endpoint>,

    /// Total connection timeout in milliseconds (TCP connect + TLS
    /// handshake combined). When set alongside `connection_timeout_ms`,
    /// the difference is effectively the TLS handshake budget.
    #[serde(default)]
    pub total_connection_timeout_ms: Option<u64>,

    /// Idle connection timeout in milliseconds.
    #[serde(default)]
    pub idle_timeout_ms: Option<u64>,

    /// Load-balancing algorithm for this cluster. Defaults to `round_robin`.
    #[serde(default)]
    pub load_balancer_strategy: LoadBalancerStrategy,

    /// Read timeout in milliseconds.
    #[serde(default)]
    pub read_timeout_ms: Option<u64>,

    /// SNI hostname to present when opening TLS connections to upstream
    /// endpoints. Defaults to the `Host` request header when not set.
    #[serde(default)]
    pub upstream_sni: Option<String>,

    /// Connect to upstream endpoints over TLS. Defaults to `false` (plain
    /// HTTP).
    #[serde(default)]
    pub upstream_tls: bool,

    /// Write timeout in milliseconds.
    #[serde(default)]
    pub write_timeout_ms: Option<u64>,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cluster_minimal() {
        let yaml = r#"
name: "backend"
endpoints: ["10.0.0.1:8080"]
"#;
        let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cluster.name, "backend");
        assert_eq!(cluster.endpoints[0].address(), "10.0.0.1:8080");
        assert_eq!(cluster.endpoints[0].weight(), 1);
        assert_eq!(cluster.load_balancer_strategy, LoadBalancerStrategy::default());
        assert!(cluster.connection_timeout_ms.is_none());
    }

    #[test]
    fn parse_cluster_with_weights() {
        let yaml = r#"
name: "backend"
endpoints:
  - "10.0.0.1:8080"
  - address: "10.0.0.2:8080"
    weight: 3
"#;
        let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cluster.endpoints.len(), 2);
        assert_eq!(cluster.endpoints[0].weight(), 1);
        assert_eq!(cluster.endpoints[1].weight(), 3);
    }

    #[test]
    fn parse_cluster_with_timeouts() {
        let yaml = r#"
name: "backend"
endpoints: ["10.0.0.1:8080"]
connection_timeout_ms: 5000
idle_timeout_ms: 30000
read_timeout_ms: 10000
write_timeout_ms: 10000
"#;
        let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cluster.connection_timeout_ms, Some(5000));
        assert_eq!(cluster.idle_timeout_ms, Some(30000));
        assert_eq!(cluster.read_timeout_ms, Some(10000));
        assert_eq!(cluster.write_timeout_ms, Some(10000));
    }

    #[test]
    fn cluster_roundtrips_via_serde() {
        let cluster = Cluster {
            name: "web".into(),
            endpoints: vec!["10.0.0.1:80".into()],
            connection_timeout_ms: Some(1000),
            idle_timeout_ms: None,
            load_balancer_strategy: Default::default(),
            read_timeout_ms: None,
            total_connection_timeout_ms: None,
            upstream_sni: None,
            upstream_tls: false,
            write_timeout_ms: None,
        };
        let value = serde_yaml::to_value(&cluster).unwrap();
        let back: Cluster = serde_yaml::from_value(value).unwrap();
        assert_eq!(back.name, cluster.name);
        assert_eq!(back.endpoints, cluster.endpoints);
        assert_eq!(back.connection_timeout_ms, cluster.connection_timeout_ms);
    }

    #[test]
    fn upstream_tls_and_sni_parse_correctly() {
        let yaml = r#"
name: "backend"
endpoints: ["10.0.0.1:443"]
upstream_tls: true
upstream_sni: "api.example.com"
"#;
        let cluster: Cluster = serde_yaml::from_str(yaml).unwrap();
        assert!(cluster.upstream_tls);
        assert_eq!(cluster.upstream_sni.as_deref(), Some("api.example.com"));
    }
}
