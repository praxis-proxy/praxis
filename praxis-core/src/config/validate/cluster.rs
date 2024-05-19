//! Cluster validation: endpoints, weights, SNI hostnames, and timeouts.

use crate::{config::Cluster, errors::ProxyError};

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Validate endpoint counts, weights, SNI hostnames, and timeout consistency.
pub(super) fn validate_clusters(clusters: &[Cluster]) -> Result<(), ProxyError> {
    const MAX_ENDPOINTS: usize = 10_000;
    const MAX_CLUSTERS: usize = 10_000;

    if clusters.len() > MAX_CLUSTERS {
        return Err(ProxyError::Config(format!(
            "too many clusters ({}, max {MAX_CLUSTERS})",
            clusters.len()
        )));
    }

    for cluster in clusters {
        if cluster.endpoints.is_empty() {
            return Err(ProxyError::Config(format!(
                "cluster '{}' has no endpoints",
                cluster.name
            )));
        }
        if cluster.endpoints.len() > MAX_ENDPOINTS {
            return Err(ProxyError::Config(format!(
                "cluster '{}' has too many endpoints ({}, max {MAX_ENDPOINTS})",
                cluster.name,
                cluster.endpoints.len()
            )));
        }

        // Reject zero-weight endpoints.
        for ep in &cluster.endpoints {
            if ep.weight() == 0 {
                return Err(ProxyError::Config(format!(
                    "cluster '{}': endpoint '{}' has weight 0 (must be >= 1)",
                    cluster.name,
                    ep.address()
                )));
            }
        }

        if let Some(ref sni) = cluster.upstream_sni {
            validate_sni(sni, &cluster.name)?;
        }

        validate_timeouts(cluster)?;
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// SNI Validation
// -----------------------------------------------------------------------------

/// Validates that an SNI hostname is a legal DNS name.
fn validate_sni(sni: &str, cluster_name: &str) -> Result<(), ProxyError> {
    if sni.is_empty() {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': upstream_sni is empty"
        )));
    }
    if sni.len() > 253 {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': upstream_sni exceeds 253 characters"
        )));
    }
    let labels: Vec<&str> = sni.split('.').collect();
    for (i, label) in labels.iter().enumerate() {
        if label.is_empty() || label.len() > 63 {
            return Err(ProxyError::Config(format!(
                "cluster '{cluster_name}': upstream_sni has invalid label length"
            )));
        }
        // RFC 6125: wildcard `*` is only valid as the complete
        // leftmost label (e.g. `*.example.com`).
        if label.contains('*') {
            if *label != "*" || i != 0 {
                return Err(ProxyError::Config(format!(
                    "cluster '{cluster_name}': upstream_sni wildcard is only \
                     permitted as the complete leftmost label (e.g. *.example.com)"
                )));
            }
            continue;
        }
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(ProxyError::Config(format!(
                "cluster '{cluster_name}': upstream_sni contains invalid characters"
            )));
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Timeout Validation
// -----------------------------------------------------------------------------

/// Validates timeout bounds and relational consistency.
fn validate_timeouts(cluster: &Cluster) -> Result<(), ProxyError> {
    let name = &cluster.name;

    for (field, value) in [
        ("connection_timeout_ms", cluster.connection_timeout_ms),
        ("total_connection_timeout_ms", cluster.total_connection_timeout_ms),
        ("idle_timeout_ms", cluster.idle_timeout_ms),
        ("read_timeout_ms", cluster.read_timeout_ms),
        ("write_timeout_ms", cluster.write_timeout_ms),
    ] {
        if let Some(0) = value {
            return Err(ProxyError::Config(format!(
                "cluster '{name}': {field} is 0 (must be > 0)"
            )));
        }
    }

    // connection_timeout must be <= total_connection_timeout.
    if let (Some(conn), Some(total)) = (cluster.connection_timeout_ms, cluster.total_connection_timeout_ms)
        && conn > total
    {
        return Err(ProxyError::Config(format!(
            "cluster '{name}': connection_timeout_ms ({conn}) exceeds \
             total_connection_timeout_ms ({total})"
        )));
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::validate_clusters;
    use crate::config::{Cluster, Config};

    #[test]
    fn reject_empty_endpoints() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
routes:
  - path_prefix: "/"
    cluster: "empty"
clusters:
  - name: "empty"
    endpoints: []
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("cluster 'empty' has no endpoints"));
    }

    #[test]
    fn validate_clusters_rejects_empty_endpoints() {
        let clusters = vec![Cluster {
            name: "empty".into(),
            endpoints: vec![],
            connection_timeout_ms: None,
            idle_timeout_ms: None,
            load_balancer_strategy: Default::default(),
            read_timeout_ms: None,
            total_connection_timeout_ms: None,
            upstream_sni: None,
            upstream_tls: false,
            write_timeout_ms: None,
        }];

        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("has no endpoints"));
    }

    #[test]
    fn reject_zero_weight_endpoint() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
routes:
  - path_prefix: "/"
    cluster: "backend"
clusters:
  - name: "backend"
    endpoints:
      - address: "10.0.0.1:80"
        weight: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("weight 0"), "got: {err}");
    }

    #[test]
    fn reject_too_many_clusters() {
        let clusters: Vec<Cluster> = (0..10_001)
            .map(|i| Cluster {
                name: format!("c{i}"),
                endpoints: vec!["10.0.0.1:80".into()],
                connection_timeout_ms: None,
                idle_timeout_ms: None,
                load_balancer_strategy: Default::default(),
                read_timeout_ms: None,
                total_connection_timeout_ms: None,
                upstream_sni: None,
                upstream_tls: false,
                write_timeout_ms: None,
            })
            .collect();
        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("too many clusters"), "got: {err}");
    }

    // ---------------------------------------------------------
    // SNI Tests (RFC 6125)
    // ---------------------------------------------------------

    #[test]
    fn reject_empty_sni() {
        let clusters = vec![Cluster {
            name: "web".into(),
            endpoints: vec!["10.0.0.1:443".into()],
            connection_timeout_ms: None,
            idle_timeout_ms: None,
            load_balancer_strategy: Default::default(),
            read_timeout_ms: None,
            total_connection_timeout_ms: None,
            upstream_sni: Some("".into()),
            upstream_tls: true,
            write_timeout_ms: None,
        }];
        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    #[test]
    fn reject_overlong_sni() {
        let long_sni = format!("{}.example.com", "a".repeat(250));
        let clusters = vec![Cluster {
            name: "web".into(),
            endpoints: vec!["10.0.0.1:443".into()],
            connection_timeout_ms: None,
            idle_timeout_ms: None,
            load_balancer_strategy: Default::default(),
            read_timeout_ms: None,
            total_connection_timeout_ms: None,
            upstream_sni: Some(long_sni),
            upstream_tls: true,
            write_timeout_ms: None,
        }];
        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("253"), "got: {err}");
    }

    #[test]
    fn reject_sni_with_invalid_chars() {
        let clusters = vec![Cluster {
            name: "web".into(),
            endpoints: vec!["10.0.0.1:443".into()],
            connection_timeout_ms: None,
            idle_timeout_ms: None,
            load_balancer_strategy: Default::default(),
            read_timeout_ms: None,
            total_connection_timeout_ms: None,
            upstream_sni: Some("api.exam ple.com".into()),
            upstream_tls: true,
            write_timeout_ms: None,
        }];
        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("invalid characters"), "got: {err}");
    }

    #[test]
    fn accept_valid_sni() {
        let clusters = vec![Cluster {
            name: "web".into(),
            endpoints: vec!["10.0.0.1:443".into()],
            connection_timeout_ms: None,
            idle_timeout_ms: None,
            load_balancer_strategy: Default::default(),
            read_timeout_ms: None,
            total_connection_timeout_ms: None,
            upstream_sni: Some("api.example.com".into()),
            upstream_tls: true,
            write_timeout_ms: None,
        }];
        validate_clusters(&clusters).unwrap();
    }

    #[test]
    fn reject_partial_wildcard_sni() {
        let clusters = vec![Cluster {
            name: "web".into(),
            endpoints: vec!["10.0.0.1:443".into()],
            connection_timeout_ms: None,
            idle_timeout_ms: None,
            load_balancer_strategy: Default::default(),
            read_timeout_ms: None,
            total_connection_timeout_ms: None,
            upstream_sni: Some("a*b.example.com".into()),
            upstream_tls: true,
            write_timeout_ms: None,
        }];
        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("wildcard"), "got: {err}");
    }

    #[test]
    fn reject_nested_wildcard_sni() {
        let clusters = vec![Cluster {
            name: "web".into(),
            endpoints: vec!["10.0.0.1:443".into()],
            connection_timeout_ms: None,
            idle_timeout_ms: None,
            load_balancer_strategy: Default::default(),
            read_timeout_ms: None,
            total_connection_timeout_ms: None,
            upstream_sni: Some("*.*.example.com".into()),
            upstream_tls: true,
            write_timeout_ms: None,
        }];
        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("wildcard"), "got: {err}");
    }

    #[test]
    fn reject_non_leftmost_wildcard_sni() {
        let clusters = vec![Cluster {
            name: "web".into(),
            endpoints: vec!["10.0.0.1:443".into()],
            connection_timeout_ms: None,
            idle_timeout_ms: None,
            load_balancer_strategy: Default::default(),
            read_timeout_ms: None,
            total_connection_timeout_ms: None,
            upstream_sni: Some("foo.*.example.com".into()),
            upstream_tls: true,
            write_timeout_ms: None,
        }];
        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("wildcard"), "got: {err}");
    }

    #[test]
    fn accept_wildcard_sni() {
        let clusters = vec![Cluster {
            name: "web".into(),
            endpoints: vec!["10.0.0.1:443".into()],
            connection_timeout_ms: None,
            idle_timeout_ms: None,
            load_balancer_strategy: Default::default(),
            read_timeout_ms: None,
            total_connection_timeout_ms: None,
            upstream_sni: Some("*.example.com".into()),
            upstream_tls: true,
            write_timeout_ms: None,
        }];
        validate_clusters(&clusters).unwrap();
    }

    // ---------------------------------------------------------
    // Timeout Tests
    // ---------------------------------------------------------

    #[test]
    fn reject_zero_timeout() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
routes:
  - path_prefix: "/"
    cluster: "backend"
clusters:
  - name: "backend"
    endpoints: ["10.0.0.1:80"]
    connection_timeout_ms: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("connection_timeout_ms is 0"), "got: {err}");
    }

    #[test]
    fn reject_connection_exceeds_total() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
routes:
  - path_prefix: "/"
    cluster: "backend"
clusters:
  - name: "backend"
    endpoints: ["10.0.0.1:80"]
    connection_timeout_ms: 10000
    total_connection_timeout_ms: 5000
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "got: {err}");
    }

    #[test]
    fn accept_valid_timeouts() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
routes:
  - path_prefix: "/"
    cluster: "backend"
clusters:
  - name: "backend"
    endpoints: ["10.0.0.1:80"]
    connection_timeout_ms: 5000
    total_connection_timeout_ms: 10000
"#;
        Config::from_yaml(yaml).unwrap();
    }
}
