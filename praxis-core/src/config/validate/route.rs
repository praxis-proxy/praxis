//! Route validation: cluster references and cardinality limits.

use std::collections::HashSet;

use tracing::warn;

use crate::{
    config::{Cluster, Route},
    errors::ProxyError,
};

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Validate route count, cluster references, and warn on unused clusters.
pub(super) fn validate_routes(routes: &[Route], clusters: &[Cluster]) -> Result<(), ProxyError> {
    const MAX_ROUTES: usize = 10_000;

    if routes.len() > MAX_ROUTES {
        return Err(ProxyError::Config(format!(
            "too many routes ({}, max {MAX_ROUTES})",
            routes.len()
        )));
    }

    if !routes.is_empty() && clusters.is_empty() {
        return Err(ProxyError::Config("at least one cluster required".into()));
    }

    let referenced: HashSet<&str> = routes.iter().map(|r| r.cluster.as_str()).collect();
    for cluster in clusters {
        if !referenced.contains(cluster.name.as_str()) {
            warn!(cluster = %cluster.name, "cluster defined but never referenced by any route");
        }
    }

    for route in routes {
        if !clusters.iter().any(|c| c.name == route.cluster) {
            return Err(ProxyError::Config(format!(
                "route references unknown cluster '{}'",
                route.cluster
            )));
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::validate_routes;
    use crate::config::{Cluster, Config, Route};

    #[test]
    fn reject_no_clusters() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
routes:
  - path_prefix: "/"
    cluster: "missing"
clusters: []
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("at least one cluster"));
    }

    #[test]
    fn reject_unknown_cluster_ref() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
routes:
  - path_prefix: "/"
    cluster: "nonexistent"
clusters:
  - name: "backend"
    endpoints: ["1.2.3.4:80"]
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("unknown cluster 'nonexistent'"));
    }

    #[test]
    fn validate_routes_rejects_unknown_cluster() {
        let routes = vec![Route {
            path_prefix: "/".into(),
            host: None,
            headers: None,
            cluster: "missing".into(),
        }];

        let clusters = vec![Cluster {
            name: "other".into(),
            endpoints: vec!["1.2.3.4:80".into()],
            connection_timeout_ms: None,
            idle_timeout_ms: None,
            load_balancer_strategy: Default::default(),
            read_timeout_ms: None,
            total_connection_timeout_ms: None,
            upstream_sni: None,
            upstream_tls: false,
            write_timeout_ms: None,
        }];

        let err = validate_routes(&routes, &clusters).unwrap_err();
        assert!(err.to_string().contains("unknown cluster 'missing'"));
    }

    #[test]
    fn reject_too_many_routes() {
        let routes: Vec<Route> = (0..10_001)
            .map(|i| Route {
                path_prefix: format!("/r{i}"),
                host: None,
                headers: None,
                cluster: "backend".into(),
            })
            .collect();
        let clusters = vec![Cluster {
            name: "backend".into(),
            endpoints: vec!["10.0.0.1:80".into()],
            connection_timeout_ms: None,
            idle_timeout_ms: None,
            load_balancer_strategy: Default::default(),
            read_timeout_ms: None,
            total_connection_timeout_ms: None,
            upstream_sni: None,
            upstream_tls: false,
            write_timeout_ms: None,
        }];
        let err = validate_routes(&routes, &clusters).unwrap_err();
        assert!(err.to_string().contains("too many routes"), "got: {err}");
    }

    #[test]
    fn accept_valid_routes() {
        let routes = vec![Route {
            path_prefix: "/".into(),
            host: None,
            headers: None,
            cluster: "backend".into(),
        }];
        let clusters = vec![Cluster {
            name: "backend".into(),
            endpoints: vec!["10.0.0.1:80".into()],
            connection_timeout_ms: None,
            idle_timeout_ms: None,
            load_balancer_strategy: Default::default(),
            read_timeout_ms: None,
            total_connection_timeout_ms: None,
            upstream_sni: None,
            upstream_tls: false,
            write_timeout_ms: None,
        }];
        validate_routes(&routes, &clusters).unwrap();
    }
}
