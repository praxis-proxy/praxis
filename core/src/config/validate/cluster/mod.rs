// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Cluster validation: endpoints, weights, SNI hostnames, timeouts, and health check addresses.

mod endpoints;
mod health_check;
mod timeouts;
mod tls;

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
        if let Some(hc) = &cluster.health_check {
            health_check::validate_health_check(hc, &cluster.name)?;
        }
        health_check::validate_health_check_ssrf(cluster, insecure_options)?;
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
    use crate::config::{Cluster, InsecureOptions};

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
}
