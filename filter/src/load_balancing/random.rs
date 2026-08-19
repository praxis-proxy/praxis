// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Weighted random endpoint selection.

use std::{
    borrow::Borrow,
    sync::{Arc, atomic::AtomicU64},
};

use praxis_core::health::ClusterHealthState;
use smallvec::SmallVec;

use super::endpoint::WeightedEndpoint;

// -----------------------------------------------------------------------------
// Random
// -----------------------------------------------------------------------------

/// Uniform random endpoint selection, weighted by endpoint weight.
///
/// Each endpoint's probability of selection is proportional to its weight
/// relative to the total weight of all (healthy) endpoints. With equal
/// weights this reduces to uniform random selection.
pub(crate) struct Random {
    /// Deduplicated endpoint list with weights and original indices.
    endpoints: Vec<WeightedEndpoint>,

    /// Sum of all endpoint weights (pre-computed, widened to `usize`).
    total_weight: usize,

    /// Deterministic RNG state.
    rng: AtomicU64,
}

impl Random {
    /// Create a random selector from a deduplicated weighted endpoint list.
    pub(crate) fn new(endpoints: Vec<WeightedEndpoint>) -> Self {
        let total_weight: usize = endpoints.iter().map(|ep| ep.weight as usize).sum();
        Self {
            endpoints,
            total_weight,
            rng: AtomicU64::new(1),
        }
    }

    /// Return a randomly selected healthy endpoint address.
    ///
    /// Selection probability is proportional to endpoint weight. Falls back
    /// to the first healthy endpoint when all healthy candidates have zero
    /// weight, or to all endpoints (panic mode) when none are healthy.
    #[inline]
    pub(crate) fn select(&self, health: Option<&ClusterHealthState>) -> Option<Arc<str>> {
        if self.total_weight == 0 {
            return None;
        }

        if let Some(state) = health {
            let healthy = self.healthy_candidates(state);
            if let Some(first) = healthy.first() {
                let total: usize = healthy.iter().map(|ep| ep.weight as usize).sum();
                if total > 0 {
                    return Some(pick(&healthy, super::next_random(&self.rng), total));
                }
                return Some(Arc::clone(&first.address));
            }
        }

        Some(pick(&self.endpoints, super::next_random(&self.rng), self.total_weight))
    }

    /// Filter to healthy endpoints.
    #[expect(clippy::indexing_slicing, reason = "bounds checked by ep.index < len()")]
    fn healthy_candidates(&self, state: &ClusterHealthState) -> SmallVec<[&WeightedEndpoint; 8]> {
        self.endpoints
            .iter()
            .filter(|ep| ep.index < state.endpoints().len() && state.endpoints()[ep.index].is_healthy())
            .collect()
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Map a random value to an endpoint via cumulative weight buckets.
#[expect(clippy::cast_possible_truncation, reason = "modulo total_weight bounds the result")]
#[expect(clippy::expect_used, reason = "total_weight > 0 guaranteed by caller")]
fn pick<E: Borrow<WeightedEndpoint>>(endpoints: &[E], random: u64, total_weight: usize) -> Arc<str> {
    let slot = (random as usize) % total_weight;
    let mut cumulative = 0_usize;
    for ep in endpoints {
        let ep = ep.borrow();
        cumulative += ep.weight as usize;
        if slot < cumulative {
            return Arc::clone(&ep.address);
        }
    }
    Arc::clone(&endpoints.last().expect("endpoints must be non-empty").borrow().address)
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
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use praxis_core::health::{ClusterHealthEntry, EndpointHealth};

    use super::*;

    #[test]
    fn single_endpoint_always_selected() {
        let r = Random::new(vec![ep("10.0.0.1:80", 1, 0)]);
        for _ in 0..10 {
            assert_eq!(
                &*r.select(None).unwrap(),
                "10.0.0.1:80",
                "single endpoint must always be returned"
            );
        }
    }

    #[test]
    fn distributes_across_endpoints() {
        let r = Random::new(vec![
            ep("10.0.0.1:80", 1, 0),
            ep("10.0.0.2:80", 1, 1),
            ep("10.0.0.3:80", 1, 2),
        ]);

        let mut counts = std::collections::HashMap::new();
        for _ in 0..300 {
            *counts.entry(r.select(None).unwrap()).or_insert(0_u32) += 1;
        }

        assert_eq!(counts.len(), 3, "random should use all 3 endpoints");
        for (addr, count) in &counts {
            assert!((50..=200).contains(count), "expected ~100 for {addr}, got {count}");
        }
    }

    #[test]
    fn weighted_bias() {
        let r = Random::new(vec![ep("10.0.0.1:80", 1, 0), ep("10.0.0.2:80", 9, 1)]);

        let mut counts = std::collections::HashMap::new();
        for _ in 0..1000 {
            *counts.entry(r.select(None).unwrap()).or_insert(0_u32) += 1;
        }

        let heavy = counts.get("10.0.0.2:80").copied().unwrap_or(0);
        assert!(
            heavy > 700,
            "weight-9 endpoint should get ~90% of traffic: heavy={heavy}"
        );
    }

    #[test]
    fn skips_unhealthy() {
        let r = Random::new(vec![ep("10.0.0.1:80", 1, 0), ep("10.0.0.2:80", 1, 1)]);
        let state = health_state(2);
        state.endpoints()[0].mark_unhealthy();

        for _ in 0..10 {
            assert_eq!(
                &*r.select(Some(&state)).unwrap(),
                "10.0.0.2:80",
                "should skip unhealthy endpoint"
            );
        }
    }

    #[test]
    fn panic_mode_when_all_unhealthy() {
        let r = Random::new(vec![ep("10.0.0.1:80", 1, 0), ep("10.0.0.2:80", 1, 1)]);
        let state = health_state(2);
        state.endpoints()[0].mark_unhealthy();
        state.endpoints()[1].mark_unhealthy();

        let addr = r.select(Some(&state)).unwrap();
        assert!(
            &*addr == "10.0.0.1:80" || &*addr == "10.0.0.2:80",
            "panic mode should still return an endpoint"
        );
    }

    #[test]
    fn empty_endpoints_returns_none() {
        let r = Random::new(vec![]);
        assert!(r.select(None).is_none(), "empty endpoint list should return None");
    }

    #[test]
    fn empty_endpoints_with_health_returns_none() {
        let r = Random::new(vec![]);
        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(vec![], vec![], None, None));
        assert!(
            r.select(Some(&state)).is_none(),
            "empty endpoint list with health state should return None"
        );
    }

    #[test]
    fn all_zero_weight_returns_none() {
        let r = Random::new(vec![ep("10.0.0.1:80", 0, 0), ep("10.0.0.2:80", 0, 1)]);
        assert!(r.select(None).is_none(), "all-zero-weight endpoints should return None");
    }

    #[test]
    fn zero_weight_healthy_returns_first_healthy() {
        let r = Random::new(vec![ep("10.0.0.1:80", 0, 0), ep("10.0.0.2:80", 5, 1)]);
        let state = health_state(2);
        state.endpoints()[1].mark_unhealthy();

        let addr = r.select(Some(&state)).unwrap();
        assert_eq!(
            &*addr, "10.0.0.1:80",
            "should return first healthy endpoint when healthy candidates have zero total weight"
        );
    }

    #[test]
    fn pick_exact_bucket_boundaries() {
        let endpoints = vec![ep("A", 1, 0), ep("B", 3, 1), ep("C", 1, 2)];
        // total_weight = 5, buckets: A=[0], B=[1,2,3], C=[4]
        assert_eq!(&*pick(&endpoints, 0, 5), "A", "slot 0 → A");
        assert_eq!(&*pick(&endpoints, 1, 5), "B", "slot 1 → B");
        assert_eq!(&*pick(&endpoints, 2, 5), "B", "slot 2 → B");
        assert_eq!(&*pick(&endpoints, 3, 5), "B", "slot 3 → B");
        assert_eq!(&*pick(&endpoints, 4, 5), "C", "slot 4 → C");
        // values beyond total_weight wrap via modulo
        assert_eq!(&*pick(&endpoints, 5, 5), "A", "slot 5 wraps to 0 → A");
        assert_eq!(&*pick(&endpoints, 9, 5), "C", "slot 9 wraps to 4 → C");
    }

    #[test]
    fn pick_with_borrowed_refs() {
        let endpoints = [ep("A", 2, 0), ep("B", 2, 1)];
        let refs: Vec<&WeightedEndpoint> = endpoints.iter().collect();
        // total_weight = 4, buckets: A=[0,1], B=[2,3]
        assert_eq!(&*pick(&refs, 0, 4), "A", "slot 0 → A via refs");
        assert_eq!(&*pick(&refs, 1, 4), "A", "slot 1 → A via refs");
        assert_eq!(&*pick(&refs, 2, 4), "B", "slot 2 → B via refs");
        assert_eq!(&*pick(&refs, 3, 4), "B", "slot 3 → B via refs");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    fn ep(addr: &str, weight: u32, index: usize) -> WeightedEndpoint {
        WeightedEndpoint {
            address: Arc::from(addr),
            weight,
            index,
        }
    }

    fn health_state(n: usize) -> ClusterHealthState {
        let healths: Vec<_> = std::iter::repeat_with(EndpointHealth::new).take(n).collect();
        let addrs: Vec<_> = (0..n).map(|i| Arc::from(format!("10.0.0.{i}:80").as_str())).collect();
        Arc::new(ClusterHealthEntry::new(healths, addrs, None, None))
    }
}
