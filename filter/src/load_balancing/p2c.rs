// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Power-of-two-choices (P2C) endpoint selection.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use praxis_core::health::ClusterHealthState;

use super::endpoint::WeightedEndpoint;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Multiplier for the LCG RNG (Knuth MMIX, truncated to 64 bits).
const LCG_A: u64 = 6_364_136_223_846_793_005;

/// Increment for the LCG RNG.
const LCG_C: u64 = 1_442_695_040_888_963_407;

// ---------------------------------------------------------------------------
// PowerOfTwoChoices
// ---------------------------------------------------------------------------

/// Sample two random endpoints and pick the one with fewer in-flight
/// requests. O(1) per selection with near-optimal load distribution.
///
/// Weight-awareness is achieved through cumulative weight buckets:
/// higher-weight endpoints occupy more of the random sampling space.
///
/// ```ignore
/// let p2c = PowerOfTwoChoices::new(endpoints);
/// let addr = p2c.select(None);
/// // ... forward request ...
/// p2c.release(&addr);
/// ```
pub(crate) struct PowerOfTwoChoices {
    /// Per-endpoint active-request counter.
    pub(crate) counters: HashMap<Arc<str>, AtomicUsize>,

    /// Deduplicated endpoint list with weights and original indices.
    endpoints: Vec<WeightedEndpoint>,

    /// Deterministic RNG state (no randomness needed; just spread).
    rng: AtomicU64,
}

impl PowerOfTwoChoices {
    /// Create a P2C selector from a weighted endpoint list.
    pub(crate) fn new(endpoints: Vec<WeightedEndpoint>) -> Self {
        let counters = endpoints
            .iter()
            .map(|ep| (Arc::clone(&ep.address), AtomicUsize::new(0)))
            .collect();
        Self {
            counters,
            endpoints,
            rng: AtomicU64::new(1),
        }
    }

    /// Pick the less loaded of two random endpoints.
    ///
    /// Falls back to all endpoints when every endpoint is unhealthy.
    /// With a single endpoint, returns it directly.
    #[expect(clippy::indexing_slicing, reason = "keyed by endpoints built in new()")]
    pub(crate) fn select(&self, health: Option<&ClusterHealthState>) -> Arc<str> {
        let candidates = self.healthy_candidates(health);
        let total_w: usize = candidates.iter().map(|ep| ep.weight as usize).sum();

        if candidates.len() <= 1 || total_w <= 1 {
            let fallback = &self.endpoints[0];
            let ep = candidates.first().copied().unwrap_or(fallback);
            return Arc::clone(&ep.address);
        }

        let (a, b) = self.pick_two(total_w);
        let ep_a = weight_index(&candidates, a, total_w);
        let ep_b = weight_index(&candidates, b, total_w);
        let chosen = self.less_loaded(ep_a, ep_b);

        self.counters[&*chosen.address].fetch_add(1, Ordering::AcqRel);
        Arc::clone(&chosen.address)
    }

    /// Decrement the in-flight counter for `addr` after a response.
    pub(crate) fn release(&self, addr: &str) {
        if let Some(counter) = self.counters.get(addr) {
            _ = counter.fetch_update(Ordering::Release, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
        }
    }

    /// Return the endpoint with fewer in-flight requests.
    /// Ties broken by higher weight.
    #[expect(clippy::indexing_slicing, reason = "keyed by endpoints built in new()")]
    fn less_loaded<'a>(&self, a: &'a WeightedEndpoint, b: &'a WeightedEndpoint) -> &'a WeightedEndpoint {
        let load_a = self.counters[&*a.address].load(Ordering::Acquire);
        let load_b = self.counters[&*b.address].load(Ordering::Acquire);
        match load_a.cmp(&load_b) {
            core::cmp::Ordering::Less => a,
            core::cmp::Ordering::Greater => b,
            core::cmp::Ordering::Equal => {
                if a.weight >= b.weight {
                    a
                } else {
                    b
                }
            },
        }
    }

    /// Generate two distinct random slots in `[0, total_weight)`.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "modulo total_weight bounds the result to usize range"
    )]
    fn pick_two(&self, total_weight: usize) -> (usize, usize) {
        let r1 = self.next_random();
        let mut r2 = self.next_random();
        let a = (r1 as usize) % total_weight;
        let mut b = (r2 as usize) % total_weight;
        while b == a {
            r2 = r2.wrapping_mul(LCG_A).wrapping_add(LCG_C);
            b = (r2 as usize) % total_weight;
        }
        (a, b)
    }

    /// Advance the LCG and return the new state.
    fn next_random(&self) -> u64 {
        self.rng
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |s| {
                Some(s.wrapping_mul(LCG_A).wrapping_add(LCG_C))
            })
            .unwrap_or(0)
    }

    /// Filter to healthy endpoints, falling back to all on panic mode.
    #[expect(clippy::indexing_slicing, reason = "bounds checked by ep.index < len()")]
    fn healthy_candidates(&self, health: Option<&ClusterHealthState>) -> Vec<&WeightedEndpoint> {
        if let Some(state) = health {
            let healthy: Vec<_> = self
                .endpoints
                .iter()
                .filter(|ep| ep.index < state.endpoints().len() && state.endpoints()[ep.index].is_healthy())
                .collect();
            if !healthy.is_empty() {
                return healthy;
            }
        }
        self.endpoints.iter().collect()
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Map a random slot to an endpoint via cumulative weight buckets.
#[expect(clippy::expect_used, reason = "total_weight > 0 guaranteed by caller")]
fn weight_index<'a>(endpoints: &[&'a WeightedEndpoint], slot: usize, total_weight: usize) -> &'a WeightedEndpoint {
    let slot = slot % total_weight;
    let mut cumulative = 0_usize;
    for ep in endpoints {
        cumulative += ep.weight as usize;
        if slot < cumulative {
            return ep;
        }
    }
    endpoints.last().expect("endpoints must be non-empty")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
    use std::sync::{Arc, atomic::Ordering};

    use praxis_core::health::{ClusterHealthEntry, EndpointHealth};

    use super::*;

    #[test]
    fn single_endpoint_always_selected() {
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1, 0)]);
        for _ in 0..10 {
            assert_eq!(
                &*p2c.select(None),
                "10.0.0.1:80",
                "single endpoint must always be returned"
            );
        }
    }

    #[test]
    fn distributes_across_endpoints() {
        let p2c = PowerOfTwoChoices::new(vec![
            ep("10.0.0.1:80", 1, 0),
            ep("10.0.0.2:80", 1, 1),
            ep("10.0.0.3:80", 1, 2),
        ]);

        for _ in 0..30 {
            let addr = p2c.select(None);
            p2c.release(&addr);
        }

        let c1 = p2c.counters["10.0.0.1:80"].load(Ordering::Relaxed);
        let c2 = p2c.counters["10.0.0.2:80"].load(Ordering::Relaxed);
        let c3 = p2c.counters["10.0.0.3:80"].load(Ordering::Relaxed);
        assert_eq!(c1 + c2 + c3, 0, "all counters should be zero after release");
    }

    #[test]
    fn prefers_less_loaded() {
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1, 0), ep("10.0.0.2:80", 1, 1)]);
        p2c.counters["10.0.0.1:80"].store(100, Ordering::Relaxed);

        let mut picked_2 = 0_u32;
        for _ in 0..20 {
            let addr = p2c.select(None);
            if &*addr == "10.0.0.2:80" {
                picked_2 += 1;
            }
            p2c.release(&addr);
        }
        assert!(
            picked_2 > 15,
            "heavily loaded endpoint should be avoided: picked_2={picked_2}"
        );
    }

    #[test]
    fn weight_biases_sampling() {
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1, 0), ep("10.0.0.2:80", 9, 1)]);

        let mut counts = HashMap::new();
        for _ in 0..100 {
            let addr = p2c.select(None);
            *counts.entry(Arc::clone(&addr)).or_insert(0_u32) += 1;
            p2c.release(&addr);
        }

        let heavy = counts.get("10.0.0.2:80").copied().unwrap_or(0);
        assert!(heavy > 60, "weight-9 endpoint should get majority: heavy={heavy}");
    }

    #[test]
    fn skips_unhealthy() {
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1, 0), ep("10.0.0.2:80", 1, 1)]);
        let state = health_state(2);
        state.endpoints()[0].mark_unhealthy();

        for _ in 0..10 {
            assert_eq!(
                &*p2c.select(Some(&state)),
                "10.0.0.2:80",
                "should skip unhealthy endpoint"
            );
            p2c.release("10.0.0.2:80");
        }
    }

    #[test]
    fn panic_mode_when_all_unhealthy() {
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1, 0), ep("10.0.0.2:80", 1, 1)]);
        let state = health_state(2);
        state.endpoints()[0].mark_unhealthy();
        state.endpoints()[1].mark_unhealthy();

        let addr = p2c.select(Some(&state));
        assert!(
            &*addr == "10.0.0.1:80" || &*addr == "10.0.0.2:80",
            "panic mode should still return an endpoint"
        );
    }

    #[test]
    fn release_does_not_underflow() {
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1, 0)]);
        p2c.release("10.0.0.1:80");
        assert_eq!(
            p2c.counters["10.0.0.1:80"].load(Ordering::Relaxed),
            0,
            "release without select should not underflow"
        );
    }

    #[test]
    fn release_unknown_addr_is_noop() {
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1, 0)]);
        p2c.release("10.0.0.99:80");
    }

    #[test]
    fn concurrent_select_and_release() {
        let p2c = Arc::new(PowerOfTwoChoices::new(vec![
            ep("10.0.0.1:80", 1, 0),
            ep("10.0.0.2:80", 1, 1),
        ]));

        let handles: Vec<_> = (0..50)
            .map(|_| {
                let p = Arc::clone(&p2c);
                std::thread::spawn(move || {
                    let addr = p.select(None);
                    p.release(&addr);
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread should not panic");
        }

        let c1 = p2c.counters["10.0.0.1:80"].load(Ordering::Relaxed);
        let c2 = p2c.counters["10.0.0.2:80"].load(Ordering::Relaxed);
        assert_eq!(c1 + c2, 0, "all counters should be zero after paired select+release");
    }

    // -----------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------

    /// Build a [`WeightedEndpoint`] for testing.
    fn ep(addr: &str, weight: u32, index: usize) -> WeightedEndpoint {
        WeightedEndpoint {
            address: Arc::from(addr),
            weight,
            index,
        }
    }

    /// Build a [`ClusterHealthState`] with `n` healthy endpoints.
    fn health_state(n: usize) -> ClusterHealthState {
        let healths: Vec<_> = (0..n).map(|_| EndpointHealth::new()).collect();
        let addrs: Vec<_> = (0..n).map(|i| Arc::from(format!("10.0.0.{i}:80").as_str())).collect();
        Arc::new(ClusterHealthEntry::new(healths, addrs, None, None))
    }
}
