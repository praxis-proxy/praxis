// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Weighted endpoint type and construction from cluster config.

use std::{collections::HashMap, sync::Arc};

use praxis_core::config::Cluster;

// -----------------------------------------------------------------------------
// WeightedEndpoint
// -----------------------------------------------------------------------------

/// A deduplicated endpoint carrying its own weight.
///
/// ```ignore
/// let ep = WeightedEndpoint { address: "10.0.0.1:80".into(), weight: 3, ..Default::default() };
/// assert_eq!(ep.address.as_ref(), "10.0.0.1:80");
/// assert_eq!(ep.weight, 3);
/// ```
#[derive(Clone, Debug)]
pub(crate) struct WeightedEndpoint {
    /// Socket address as `host:port`.
    pub(crate) address: Arc<str>,

    /// Relative forwarding weight (>= 1).
    pub(crate) weight: u32,

    /// Arbitrary key-value metadata for subset-based load balancing.
    pub(crate) metadata: HashMap<String, String>,

    /// Priority tier (0 = primary, 1 = first failover, etc.).
    pub(crate) priority: u32,

    /// Locality zone identifier for zone-aware routing.
    pub(crate) zone: Option<Arc<str>>,
}

impl WeightedEndpoint {
    /// Construct a minimal endpoint for use in tests and strategies that don't
    /// need metadata/zone/priority.
    #[cfg(test)]
    pub(crate) fn simple(address: Arc<str>, weight: u32) -> Self {
        Self {
            address,
            weight,
            metadata: HashMap::new(),
            priority: 0,
            zone: None,
        }
    }
}

/// Build a [`WeightedEndpoint`] list from a cluster's endpoints.
pub(crate) fn build_weighted_endpoints(cluster: &Cluster) -> Vec<WeightedEndpoint> {
    cluster
        .endpoints
        .iter()
        .map(|ep| WeightedEndpoint {
            address: Arc::from(ep.address()),
            weight: ep.weight(),
            metadata: ep.metadata().clone(),
            priority: ep.priority(),
            zone: ep.zone().map(Arc::from),
        })
        .collect()
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
                    metadata: HashMap::new(),
                    priority: 0,
                    zone: None,
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
        assert_endpoint(&weighted[0], "10.0.0.1:80", 1);
        assert_endpoint(&weighted[1], "10.0.0.2:80", 3);
        assert_endpoint(&weighted[2], "10.0.0.3:80", 1);
    }

    #[test]
    fn build_weighted_endpoints_empty_cluster() {
        let cluster = Cluster::with_defaults("empty", vec![]);
        let weighted = build_weighted_endpoints(&cluster);
        assert!(weighted.is_empty(), "empty cluster should produce empty vec");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Assert a [`WeightedEndpoint`] has the expected address and weight.
    fn assert_endpoint(ep: &WeightedEndpoint, addr: &str, weight: u32) {
        assert_eq!(ep.address.as_ref(), addr, "address mismatch for {addr}");
        assert_eq!(ep.weight, weight, "weight mismatch for {addr}");
    }
}
