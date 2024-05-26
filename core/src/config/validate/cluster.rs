//! Cluster validation: endpoints, weights, SNI hostnames, and timeouts.

use crate::{
    config::{Cluster, HealthCheckType},
    errors::ProxyError,
};

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

        if let Some(ref hc) = cluster.health_check {
            validate_health_check(hc, &cluster.name)?;
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Health Check Validation
// -----------------------------------------------------------------------------

/// Validates health check configuration constraints.
fn validate_health_check(hc: &crate::config::HealthCheckConfig, cluster_name: &str) -> Result<(), ProxyError> {
    match hc.check_type {
        HealthCheckType::Http | HealthCheckType::Tcp => {},
        HealthCheckType::Grpc => {
            return Err(ProxyError::Config(format!(
                "cluster '{cluster_name}': health check type 'grpc' is not yet supported"
            )));
        },
    }

    if hc.interval_ms == 0 {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health check interval_ms must be > 0"
        )));
    }

    if hc.timeout_ms == 0 {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health_check.timeout_ms must be greater than 0"
        )));
    }

    if hc.path.contains('\r') || hc.path.contains('\n') {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health_check.path must not contain CR or LF characters"
        )));
    }

    if hc.timeout_ms >= hc.interval_ms {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health check timeout_ms ({}) must be \
             less than interval_ms ({})",
            hc.timeout_ms, hc.interval_ms
        )));
    }

    if hc.healthy_threshold == 0 {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health check healthy_threshold must be >= 1"
        )));
    }

    if hc.unhealthy_threshold == 0 {
        return Err(ProxyError::Config(format!(
            "cluster '{cluster_name}': health check unhealthy_threshold must be >= 1"
        )));
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
        // RFC 6125 (https://datatracker.ietf.org/doc/html/rfc6125):
        // wildcard `*` is only valid as the complete leftmost label
        // (e.g. `*.example.com`).
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
        let clusters = vec![Cluster::with_defaults("empty", vec![])];

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
            .map(|i| Cluster::with_defaults(&format!("c{i}"), vec!["10.0.0.1:80".into()]))
            .collect();
        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("too many clusters"), "got: {err}");
    }

    #[test]
    fn reject_empty_sni() {
        let clusters = vec![Cluster {
            upstream_sni: Some("".into()),
            upstream_tls: true,
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    #[test]
    fn reject_overlong_sni() {
        let long_sni = format!("{}.example.com", "a".repeat(250));
        let clusters = vec![Cluster {
            upstream_sni: Some(long_sni),
            upstream_tls: true,
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("253"), "got: {err}");
    }

    #[test]
    fn reject_sni_with_invalid_chars() {
        let clusters = vec![Cluster {
            upstream_sni: Some("api.exam ple.com".into()),
            upstream_tls: true,
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("invalid characters"), "got: {err}");
    }

    #[test]
    fn accept_valid_sni() {
        let clusters = vec![Cluster {
            upstream_sni: Some("api.example.com".into()),
            upstream_tls: true,
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        validate_clusters(&clusters).unwrap();
    }

    #[test]
    fn reject_partial_wildcard_sni() {
        let clusters = vec![Cluster {
            upstream_sni: Some("a*b.example.com".into()),
            upstream_tls: true,
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("wildcard"), "got: {err}");
    }

    #[test]
    fn reject_nested_wildcard_sni() {
        let clusters = vec![Cluster {
            upstream_sni: Some("*.*.example.com".into()),
            upstream_tls: true,
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("wildcard"), "got: {err}");
    }

    #[test]
    fn reject_non_leftmost_wildcard_sni() {
        let clusters = vec![Cluster {
            upstream_sni: Some("foo.*.example.com".into()),
            upstream_tls: true,
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("wildcard"), "got: {err}");
    }

    #[test]
    fn accept_wildcard_sni() {
        let clusters = vec![Cluster {
            upstream_sni: Some("*.example.com".into()),
            upstream_tls: true,
            ..Cluster::with_defaults("web", vec!["10.0.0.1:443".into()])
        }];
        validate_clusters(&clusters).unwrap();
    }

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

    #[test]
    fn accept_valid_http_health_check() {
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
    health_check:
      type: http
      path: "/healthz"
      interval_ms: 5000
      timeout_ms: 2000
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn accept_valid_tcp_health_check() {
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
    health_check:
      type: tcp
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_grpc_health_check() {
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
    health_check:
      type: grpc
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("not yet supported"), "got: {err}");
    }

    #[test]
    fn reject_unknown_health_check_type() {
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
    health_check:
      type: websocket
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("websocket") || err.to_string().contains("unknown variant"),
            "serde should reject unknown health check type, got: {err}"
        );
    }

    #[test]
    fn reject_zero_interval() {
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
    health_check:
      type: http
      interval_ms: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("interval_ms must be > 0"), "got: {err}");
    }

    #[test]
    fn reject_timeout_gte_interval() {
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
    health_check:
      type: http
      interval_ms: 2000
      timeout_ms: 2000
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string()
                .contains("timeout_ms (2000) must be less than interval_ms (2000)"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_zero_healthy_threshold() {
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
    health_check:
      type: http
      healthy_threshold: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("healthy_threshold must be >= 1"), "got: {err}");
    }

    #[test]
    fn reject_zero_unhealthy_threshold() {
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
    health_check:
      type: http
      unhealthy_threshold: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("unhealthy_threshold must be >= 1"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_zero_timeout_ms() {
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
    health_check:
      type: http
      interval_ms: 5000
      timeout_ms: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("timeout_ms must be greater than 0"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_health_check_path_with_cr() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                path: "/health\r\nEvil: header".to_owned(),
                expected_status: 200,
                interval_ms: 5000,
                timeout_ms: 2000,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:80".into()])
        }];
        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("must not contain CR or LF"), "got: {err}");
    }

    #[test]
    fn reject_health_check_path_with_lf() {
        let clusters = vec![Cluster {
            health_check: Some(crate::config::HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                path: "/health\nEvil: header".to_owned(),
                expected_status: 200,
                interval_ms: 5000,
                timeout_ms: 2000,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
            }),
            ..Cluster::with_defaults("web", vec!["10.0.0.1:80".into()])
        }];
        let err = validate_clusters(&clusters).unwrap_err();
        assert!(err.to_string().contains("must not contain CR or LF"), "got: {err}");
    }
}
