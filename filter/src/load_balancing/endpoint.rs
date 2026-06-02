// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Weighted endpoint type and construction from cluster config.

use std::sync::Arc;

use praxis_core::config::Cluster;

// -----------------------------------------------------------------------------
// WeightedEndpoint
// -----------------------------------------------------------------------------

/// A deduplicated endpoint carrying its own weight and original index.
///
/// ```ignore
/// let ep = WeightedEndpoint { address: "10.0.0.1:80".into(), weight: 3, index: 0 };
/// assert_eq!(ep.address.as_ref(), "10.0.0.1:80");
/// assert_eq!(ep.weight, 3);
/// assert_eq!(ep.index, 0);
/// ```
#[derive(Debug, Clone)]
pub(crate) struct WeightedEndpoint {
    /// Socket address as `host:port`.
    pub(crate) address: Arc<str>,

    /// Position in the original cluster endpoint list (for health state lookups).
    pub(crate) index: usize,

    /// Relative forwarding weight (>= 1).
    pub(crate) weight: u32,
}

/// Build a [`WeightedEndpoint`] list from a cluster's endpoints.
pub(crate) fn build_weighted_endpoints(cluster: &Cluster) -> Vec<WeightedEndpoint> {
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
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use praxis_core::config::Endpoint;

    use super::*;

    #[test]
    fn build_weighted_endpoints_three_endpoints() {
        let cluster = Cluster::with_defaults(
            "test",
            vec![
                Endpoint::from("10.0.0.1:80"),
                Endpoint::Weighted {
                    address: "10.0.0.2:80".to_owned(),
                    weight: 3,
                },
                Endpoint::from("10.0.0.3:80"),
            ],
        );
        let weighted = build_weighted_endpoints(&cluster);
        assert_eq!(
            weighted.len(),
            3,
            "should produce one WeightedEndpoint per cluster endpoint"
        );
        assert_endpoint(&weighted[0], "10.0.0.1:80", 1, 0);
        assert_endpoint(&weighted[1], "10.0.0.2:80", 3, 1);
        assert_endpoint(&weighted[2], "10.0.0.3:80", 1, 2);
    }

    #[test]
    fn build_weighted_endpoints_empty_cluster() {
        let cluster = Cluster::with_defaults("empty", vec![]);
        let weighted = build_weighted_endpoints(&cluster);
        assert!(weighted.is_empty(), "empty cluster should produce empty vec");
    }

    // ---------------------------------------------------------------------------
    // Test Utilities
    // ---------------------------------------------------------------------------

    /// Assert a [`WeightedEndpoint`] has the expected address, weight, and index.
    fn assert_endpoint(ep: &WeightedEndpoint, addr: &str, weight: u32, index: usize) {
        assert_eq!(ep.address.as_ref(), addr, "address mismatch for index {index}");
        assert_eq!(ep.weight, weight, "weight mismatch for {addr}");
        assert_eq!(ep.index, index, "index mismatch for {addr}");
    }
}
