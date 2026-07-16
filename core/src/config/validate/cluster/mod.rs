// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Cluster validation: endpoints, weights, SNI hostnames, timeouts, and health check addresses.

mod endpoints;
mod health_check;
mod timeouts;
mod tls;

pub use health_check::is_ssrf_sensitive;

use crate::{config::InsecureOptions, errors::ProxyError};

// -----------------------------------------------------------------------------
// Cluster Validation Constants
// -----------------------------------------------------------------------------

/// Maximum number of clusters allowed in the configuration.
const MAX_CLUSTERS: usize = 10_000;

/// Maximum allowed timeout value in milliseconds (1 hour).
pub(crate) const MAX_TIMEOUT_MS: u64 = 3_600_000;

/// Maximum number of endpoints allowed per cluster.
pub(crate) const MAX_ENDPOINTS: usize = 10_000;

// -----------------------------------------------------------------------------
// Cluster Validation
// -----------------------------------------------------------------------------

/// Validate endpoint counts, weights, SNI hostnames, and timeout consistency.
pub(in crate::config::validate) fn validate_clusters(
    clusters: &[crate::config::Cluster],
    insecure_options: &InsecureOptions,
) -> Result<(), ProxyError> {
    if clusters.len() > MAX_CLUSTERS {
        return Err(ProxyError::Config(format!(
            "too many clusters ({}, max {MAX_CLUSTERS})",
            clusters.len()
        )));
    }
    for cluster in clusters {
        if cluster.name.is_empty() {
            return Err(ProxyError::Config("cluster name must not be empty".into()));
        }
        super::validate_name_chars(&cluster.name, "cluster")?;
        endpoints::validate_endpoints(cluster, insecure_options)?;
        tls::validate_tls_settings(cluster, insecure_options)?;
        timeouts::validate_timeouts(cluster)?;
        validate_cluster_max_connections(cluster)?;
        if let Some(hc) = &cluster.health_check {
            health_check::validate_health_check(hc, &cluster.name)?;
        }
        health_check::validate_health_check_ssrf(cluster, insecure_options)?;
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Max Connections Validation
// -----------------------------------------------------------------------------

/// Validate `max_connections` is at least 1 and within the allowed ceiling.
fn validate_cluster_max_connections(cluster: &crate::config::Cluster) -> Result<(), ProxyError> {
    let Some(v) = cluster.max_connections else {
        return Ok(());
    };
    let name = &cluster.name;
    if v == 0 {
        return Err(ProxyError::Config(format!(
            "cluster '{name}': max_connections must be >= 1"
        )));
    }
    if v > super::MAX_CONNECTIONS {
        return Err(ProxyError::Config(format!(
            "cluster '{name}': max_connections ({v}) exceeds maximum ({})",
            super::MAX_CONNECTIONS,
        )));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::validate_clusters;
    use crate::config::{Cluster, Config, InsecureOptions};

    #[test]
    fn reject_too_many_clusters() {
        let clusters: Vec<Cluster> = (0..10_001)
            .map(|i| Cluster::with_defaults(&format!("c{i}"), vec!["10.0.0.1:80".into()]))
            .collect();
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("too many clusters"), "got: {err}");
    }

    #[test]
    fn no_tls_skips_tls_validation() {
        let clusters = vec![Cluster::with_defaults("web", vec!["10.0.0.1:80".into()])];
        validate_clusters(&clusters, &InsecureOptions::default()).expect("no TLS should skip TLS validation");
    }

    #[test]
    fn reject_cluster_zero_max_connections() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
    max_connections: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("max_connections must be >= 1"),
            "should reject zero cluster max_connections: {err}"
        );
    }

    #[test]
    fn reject_cluster_max_connections_exceeding_maximum() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
    max_connections: 1000001
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "should reject cluster max_connections > 1M: {err}"
        );
    }

    #[test]
    fn accept_cluster_max_connections_at_maximum() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
    max_connections: 1000000
"#;
        Config::from_yaml(yaml).unwrap();
    }
}
