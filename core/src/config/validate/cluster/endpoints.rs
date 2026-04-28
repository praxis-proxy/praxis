// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Endpoint count and weight validation for clusters.

use super::MAX_ENDPOINTS;
use crate::{config::Cluster, errors::ProxyError};

// -----------------------------------------------------------------------------
// Endpoint Validation
// -----------------------------------------------------------------------------

/// Validate endpoint count and per-endpoint weights for a single cluster.
pub(super) fn validate_endpoints(cluster: &Cluster) -> Result<(), ProxyError> {
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
    for ep in &cluster.endpoints {
        if ep.weight() == 0 {
            return Err(ProxyError::Config(format!(
                "cluster '{}': endpoint '{}' has weight 0 (must be >= 1)",
                cluster.name,
                ep.address()
            )));
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::super::validate_clusters;
    use crate::config::{Cluster, Config, InsecureOptions};

    #[test]
    fn reject_empty_endpoints() {
        let clusters = vec![Cluster::with_defaults("empty", vec![])];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(err.to_string().contains("cluster 'empty' has no endpoints"));
    }

    #[test]
    fn reject_too_many_endpoints() {
        let endpoints: Vec<_> = (0..10_001)
            .map(|i| format!("10.0.{}.{}:80", i / 256, i % 256).into())
            .collect();
        let clusters = vec![Cluster::with_defaults("big", endpoints)];
        let err = validate_clusters(&clusters, &InsecureOptions::default()).unwrap_err();
        assert!(
            err.to_string().contains("too many endpoints"),
            "should reject cluster exceeding MAX_ENDPOINTS: {err}"
        );
    }

    #[test]
    fn reject_zero_weight_endpoint() {
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
  - name: "backend"
    endpoints:
      - address: "10.0.0.1:80"
        weight: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("weight 0"), "got: {err}");
    }
}
