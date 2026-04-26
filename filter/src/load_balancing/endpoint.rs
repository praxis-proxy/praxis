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
