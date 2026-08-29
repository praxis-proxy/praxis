// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Subset-based load balancing: filter endpoints by metadata labels, then
//! apply an inner strategy within the matching subset.

use std::{collections::HashMap, sync::Arc};

use praxis_core::{
    config::{SimpleStrategy, SubsetFallbackPolicy},
    health::ClusterHealthState,
};

use super::{
    endpoint::WeightedEndpoint,
    strategy::{Strategy, build_simple_strategy},
};

// -----------------------------------------------------------------------------
// Subset
// -----------------------------------------------------------------------------

/// Routes requests to the subset of endpoints matching a metadata selector,
/// using an inner strategy for endpoint selection within that subset.
pub(crate) struct Subset {
    /// Strategy built from only the matching endpoints.
    subset_strategy: Option<Box<Strategy>>,

    /// Strategy built from all endpoints (used as fallback).
    fallback_strategy: Box<Strategy>,

    /// Fallback behavior when the subset is empty.
    fallback_policy: SubsetFallbackPolicy,

    /// Indices of the matched subset endpoints in the health state array.
    subset_indices: Vec<usize>,
}

impl Subset {
    /// Create a subset LB that filters endpoints by the given selector and
    /// applies the inner strategy within the matching subset.
    pub(crate) fn new(
        endpoints: Vec<WeightedEndpoint>,
        selector: &HashMap<String, String>,
        inner_strategy: &SimpleStrategy,
        fallback_policy: SubsetFallbackPolicy,
    ) -> Self {
        let matched: Vec<WeightedEndpoint> = endpoints
            .iter()
            .filter(|ep| {
                selector
                    .iter()
                    .all(|(k, v)| ep.metadata.get(k).is_some_and(|mv| mv == v))
            })
            .cloned()
            .collect();

        let subset_indices: Vec<usize> = matched.iter().map(|ep| ep.index).collect();

        let subset_strategy = if matched.is_empty() {
            None
        } else {
            Some(Box::new(build_simple_strategy(inner_strategy, matched)))
        };

        let fallback_strategy = Box::new(build_simple_strategy(inner_strategy, endpoints));

        Self {
            subset_strategy,
            fallback_strategy,
            fallback_policy,
            subset_indices,
        }
    }

    /// Select an endpoint from the matched subset, or apply the fallback policy.
    pub(crate) fn select(
        &self,
        hash_key: Option<&str>,
        health: Option<&ClusterHealthState>,
        exclude: &[Arc<str>],
    ) -> Option<Arc<str>> {
        if let Some(strategy) = &self.subset_strategy
            && !self.all_subset_unhealthy(health)
        {
            let result = strategy.select(hash_key, health, exclude);
            if result.is_some() {
                return result;
            }
        }

        match self.fallback_policy {
            SubsetFallbackPolicy::AnyEndpoint => self.fallback_strategy.select(hash_key, health, exclude),
            SubsetFallbackPolicy::NoEndpoint => None,
        }
    }

    /// Returns `true` when every endpoint in the subset is unhealthy.
    fn all_subset_unhealthy(&self, health: Option<&ClusterHealthState>) -> bool {
        let Some(state) = health else {
            return false;
        };
        let endpoints = state.endpoints();
        !self.subset_indices.is_empty()
            && self
                .subset_indices
                .iter()
                .all(|&idx| endpoints.get(idx).is_none_or(|ep| !ep.is_healthy()))
    }

    /// Propagate release to inner strategies.
    /// Release is forwarded to both inner strategies because the composite
    /// cannot know which one served the request. With counter-based inner
    /// strategies (`least_connections`, `p2c`) the counters therefore
    /// saturate toward zero on the side that did not serve, making in-flight
    /// counts approximate when the fallback path is in use.
    pub(crate) fn release(&self, addr: &str) {
        if let Some(strategy) = &self.subset_strategy {
            strategy.release(addr);
        }
        self.fallback_strategy.release(addr);
    }
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
    use std::collections::HashSet;

    use praxis_core::health::{ClusterHealthEntry, EndpointHealth};

    use super::*;

    #[test]
    fn selects_from_matching_subset() {
        let endpoints = vec![
            ep("10.0.0.1:80", 0, &[("version", "stable")]),
            ep("10.0.0.2:80", 1, &[("version", "canary")]),
            ep("10.0.0.3:80", 2, &[("version", "canary")]),
        ];
        let selector = HashMap::from([("version".to_owned(), "canary".to_owned())]);
        let subset = Subset::new(
            endpoints,
            &selector,
            &SimpleStrategy::RoundRobin,
            SubsetFallbackPolicy::AnyEndpoint,
        );

        let mut seen = HashSet::new();
        for _ in 0..10 {
            let addr = subset.select(None, None, &[]).unwrap();
            seen.insert(addr);
        }
        assert!(!seen.contains("10.0.0.1:80"), "stable endpoint should not be selected");
        assert!(seen.contains("10.0.0.2:80"), "canary endpoint 2 should be selected");
        assert!(seen.contains("10.0.0.3:80"), "canary endpoint 3 should be selected");
    }

    #[test]
    fn fallback_any_endpoint_when_no_match() {
        let endpoints = vec![
            ep("10.0.0.1:80", 0, &[("version", "stable")]),
            ep("10.0.0.2:80", 1, &[("version", "stable")]),
        ];
        let selector = HashMap::from([("version".to_owned(), "canary".to_owned())]);
        let subset = Subset::new(
            endpoints,
            &selector,
            &SimpleStrategy::RoundRobin,
            SubsetFallbackPolicy::AnyEndpoint,
        );

        let addr = subset.select(None, None, &[]);
        assert!(addr.is_some(), "AnyEndpoint fallback should return an endpoint");
    }

    #[test]
    fn fallback_no_endpoint_when_no_match() {
        let endpoints = vec![
            ep("10.0.0.1:80", 0, &[("version", "stable")]),
            ep("10.0.0.2:80", 1, &[("version", "stable")]),
        ];
        let selector = HashMap::from([("version".to_owned(), "canary".to_owned())]);
        let subset = Subset::new(
            endpoints,
            &selector,
            &SimpleStrategy::RoundRobin,
            SubsetFallbackPolicy::NoEndpoint,
        );

        let addr = subset.select(None, None, &[]);
        assert!(addr.is_none(), "NoEndpoint fallback should return None");
    }

    #[test]
    fn multi_key_selector() {
        let endpoints = vec![
            ep("10.0.0.1:80", 0, &[("version", "canary"), ("gpu", "a100")]),
            ep("10.0.0.2:80", 1, &[("version", "canary"), ("gpu", "h100")]),
            ep("10.0.0.3:80", 2, &[("version", "stable"), ("gpu", "a100")]),
        ];
        let selector = HashMap::from([
            ("version".to_owned(), "canary".to_owned()),
            ("gpu".to_owned(), "a100".to_owned()),
        ]);
        let subset = Subset::new(
            endpoints,
            &selector,
            &SimpleStrategy::RoundRobin,
            SubsetFallbackPolicy::AnyEndpoint,
        );

        for _ in 0..10 {
            let addr = subset.select(None, None, &[]).unwrap();
            assert_eq!(&*addr, "10.0.0.1:80", "only endpoint matching both keys");
        }
    }

    #[test]
    fn empty_selector_matches_all() {
        let endpoints = vec![
            ep("10.0.0.1:80", 0, &[("version", "stable")]),
            ep("10.0.0.2:80", 1, &[("version", "canary")]),
        ];
        let selector = HashMap::new();
        let subset = Subset::new(
            endpoints,
            &selector,
            &SimpleStrategy::RoundRobin,
            SubsetFallbackPolicy::AnyEndpoint,
        );

        let mut seen = HashSet::new();
        for _ in 0..10 {
            seen.insert(subset.select(None, None, &[]).unwrap());
        }
        assert_eq!(seen.len(), 2, "empty selector should match all endpoints");
    }

    #[test]
    fn fallback_when_all_subset_unhealthy() {
        let endpoints = vec![
            ep("10.0.0.1:80", 0, &[("version", "canary")]),
            ep("10.0.0.2:80", 1, &[("version", "canary")]),
            ep("10.0.0.3:80", 2, &[("version", "stable")]),
            ep("10.0.0.4:80", 3, &[("version", "stable")]),
        ];
        let selector = HashMap::from([("version".to_owned(), "canary".to_owned())]);
        let subset = Subset::new(
            endpoints,
            &selector,
            &SimpleStrategy::RoundRobin,
            SubsetFallbackPolicy::AnyEndpoint,
        );

        let state = health_state(4);
        // Mark both canary endpoints unhealthy.
        state.endpoints()[0].mark_unhealthy();
        state.endpoints()[1].mark_unhealthy();

        let mut seen = HashSet::new();
        for _ in 0..20 {
            seen.insert(subset.select(None, Some(&state), &[]).unwrap());
        }
        assert!(!seen.contains("10.0.0.1:80"), "unhealthy canary should not be selected");
        assert!(!seen.contains("10.0.0.2:80"), "unhealthy canary should not be selected");
        assert!(
            seen.contains("10.0.0.3:80") || seen.contains("10.0.0.4:80"),
            "fallback should route to healthy stable endpoints"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    fn ep(addr: &str, index: usize, meta: &[(&str, &str)]) -> WeightedEndpoint {
        WeightedEndpoint {
            address: Arc::from(addr),
            index,
            weight: 1,
            metadata: meta.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect(),
            priority: 0,
            zone: None,
        }
    }

    fn health_state(n: usize) -> Arc<ClusterHealthEntry> {
        let healths: Vec<_> = std::iter::repeat_with(EndpointHealth::new).take(n).collect();
        let addrs: Vec<_> = (0..n)
            .map(|i| Arc::from(format!("10.0.0.{}:80", i + 1).as_str()))
            .collect();
        Arc::new(ClusterHealthEntry::new(healths, addrs, None, None))
    }
}
