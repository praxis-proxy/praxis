// SPDX-License-Identifier: Apache-2.0
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
use smallvec::SmallVec;

use super::endpoint::WeightedEndpoint;

// -----------------------------------------------------------------------------
// PowerOfTwoChoices
// -----------------------------------------------------------------------------

/// Sample two random endpoints and pick the one with fewer in-flight
/// requests. O(1) per selection with near-optimal load distribution.
///
/// Weight-awareness is achieved through cumulative weight buckets:
/// higher-weight endpoints occupy more of the random sampling space.
///
/// ```ignore
/// let p2c = PowerOfTwoChoices::new(endpoints);
/// let addr = p2c.select(None, &[]);
/// // ... forward request ...
/// p2c.release(&addr);
/// ```
pub(crate) struct PowerOfTwoChoices {
    /// Per-endpoint active-request counters, positionally aligned with
    /// `endpoints` so selection indexes instead of hashing the address
    /// string on every load and increment.
    counters: Vec<AtomicUsize>,

    /// Address-to-position lookup for [`release`], the only entry point
    /// keyed by address.
    ///
    /// [`release`]: Self::release
    index_by_addr: HashMap<Arc<str>, usize>,

    /// Deduplicated endpoint list with weights and original indices.
    endpoints: Vec<WeightedEndpoint>,

    /// Deterministic RNG state (no randomness needed; just spread).
    rng: AtomicU64,
}

impl PowerOfTwoChoices {
    /// Create a P2C selector from a weighted endpoint list.
    pub(crate) fn new(endpoints: Vec<WeightedEndpoint>) -> Self {
        let counters = endpoints.iter().map(|_| AtomicUsize::new(0)).collect();
        let index_by_addr: HashMap<Arc<str>, usize> = endpoints
            .iter()
            .enumerate()
            .map(|(pos, ep)| (Arc::clone(&ep.address), pos))
            .collect();
        // Config validation rejects duplicate endpoint addresses; a
        // programmatic caller bypassing it would silently leak counters
        // (release() only ever decrements the last duplicate's slot).
        debug_assert_eq!(
            index_by_addr.len(),
            endpoints.len(),
            "endpoint addresses must be unique for positional load counters"
        );
        Self {
            counters,
            index_by_addr,
            endpoints,
            rng: AtomicU64::new(1),
        }
    }

    /// Pick the less loaded of two random endpoints.
    ///
    /// Falls back to all endpoints when every endpoint is unhealthy.
    /// With a single endpoint, returns it directly.
    #[expect(clippy::indexing_slicing, reason = "positions come from the endpoints scan")]
    pub(crate) fn select(&self, health: Option<&ClusterHealthState>, exclude: &[Arc<str>]) -> Option<Arc<str>> {
        if self.endpoints.is_empty() {
            return None;
        }
        let candidates = self.candidate_positions(health, exclude);
        let total_w: usize = candidates.iter().map(|&pos| self.endpoints[pos].weight as usize).sum();

        if candidates.len() <= 1 || total_w <= 1 {
            let fallback_pos = self
                .endpoints
                .iter()
                .position(|ep| !is_excluded(&ep.address, exclude))
                .unwrap_or(0);
            let pos = candidates.first().copied().unwrap_or(fallback_pos);
            let ep = &self.endpoints[pos];
            if is_excluded(&ep.address, exclude) {
                return None;
            }
            self.counters[pos].fetch_add(1, Ordering::AcqRel);
            return Some(Arc::clone(&ep.address));
        }

        let (a, b) = self.pick_two(total_w);
        let pos_a = self.weight_index_pos(&candidates, a, total_w);
        let pos_b = self.weight_index_pos(&candidates, b, total_w);
        let chosen = self.less_loaded(pos_a, pos_b);

        self.counters[chosen].fetch_add(1, Ordering::AcqRel);
        Some(Arc::clone(&self.endpoints[chosen].address))
    }

    /// Decrement the in-flight counter for `addr` after a response.
    pub(crate) fn release(&self, addr: &str) {
        if let Some(counter) = self.index_by_addr.get(addr).and_then(|pos| self.counters.get(*pos)) {
            _ = counter.fetch_update(Ordering::Release, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
        }
    }

    /// The counter cell for `addr`; test observability and seeding.
    #[cfg(test)]
    #[expect(clippy::expect_used, reason = "tests only address known endpoints")]
    pub(crate) fn counter_for(&self, addr: &str) -> &AtomicUsize {
        self.index_by_addr
            .get(addr)
            .and_then(|pos| self.counters.get(*pos))
            .expect("counter must exist for every endpoint address")
    }

    /// Return the position with fewer in-flight requests.
    /// Ties broken by higher weight.
    #[expect(clippy::indexing_slicing, reason = "positions come from the endpoints scan")]
    fn less_loaded(&self, a: usize, b: usize) -> usize {
        let load_a = self.counters[a].load(Ordering::Acquire);
        let load_b = self.counters[b].load(Ordering::Acquire);
        match load_a.cmp(&load_b) {
            core::cmp::Ordering::Less => a,
            core::cmp::Ordering::Greater => b,
            core::cmp::Ordering::Equal => {
                if self.endpoints[a].weight >= self.endpoints[b].weight {
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
        let r1 = super::next_random(&self.rng);
        let mut r2 = super::next_random(&self.rng);
        let a = (r1 as usize) % total_weight;
        let mut b = (r2 as usize) % total_weight;
        while b == a {
            r2 = r2.wrapping_mul(super::LCG_A).wrapping_add(super::LCG_C);
            b = (r2 as usize) % total_weight;
        }
        (a, b)
    }

    /// Map a cumulative-weight slot to a candidate position.
    #[expect(clippy::indexing_slicing, reason = "positions come from the endpoints scan")]
    #[expect(clippy::expect_used, reason = "caller guarantees candidates is non-empty")]
    fn weight_index_pos(&self, candidates: &[usize], slot: usize, total_weight: usize) -> usize {
        let slot = slot % total_weight;
        let mut cumulative = 0_usize;
        for &pos in candidates {
            cumulative += self.endpoints[pos].weight as usize;
            if slot < cumulative {
                return pos;
            }
        }
        *candidates.last().expect("candidates must be non-empty")
    }

    /// Candidate positions in one pass: healthy-and-not-excluded when
    /// any endpoint is healthy, else all not-excluded (panic mode). The
    /// old shape collected the healthy set and then re-collected it
    /// through the exclusion filter — two passes and, past the inline
    /// capacity, two heap allocations per request.
    fn candidate_positions(&self, health: Option<&ClusterHealthState>, exclude: &[Arc<str>]) -> SmallVec<[usize; 8]> {
        if let Some(state) = health {
            let mut candidates: SmallVec<[usize; 8]> = SmallVec::new();
            let mut any_healthy = false;
            for (pos, ep) in self.endpoints.iter().enumerate() {
                let healthy = state
                    .endpoints()
                    .get(ep.index)
                    .is_some_and(praxis_core::health::EndpointHealth::is_healthy);
                if healthy {
                    any_healthy = true;
                    if !is_excluded(&ep.address, exclude) {
                        candidates.push(pos);
                    }
                }
            }
            if any_healthy {
                return candidates;
            }
        }
        self.endpoints
            .iter()
            .enumerate()
            .filter(|(_, ep)| !is_excluded(&ep.address, exclude))
            .map(|(pos, _)| pos)
            .collect()
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Returns `true` if `addr` appears in the exclusion list.
fn is_excluded(addr: &str, exclude: &[Arc<str>]) -> bool {
    exclude.iter().any(|e| e.as_ref() == addr)
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
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1, 0)]);
        for _ in 0..10 {
            assert_eq!(
                &*p2c.select(None, &[]).unwrap(),
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
            let addr = p2c.select(None, &[]).unwrap();
            p2c.release(&addr);
        }

        let c1 = p2c.counter_for("10.0.0.1:80").load(Ordering::Relaxed);
        let c2 = p2c.counter_for("10.0.0.2:80").load(Ordering::Relaxed);
        let c3 = p2c.counter_for("10.0.0.3:80").load(Ordering::Relaxed);
        assert_eq!(c1 + c2 + c3, 0, "all counters should be zero after release");
    }

    #[test]
    fn prefers_less_loaded() {
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1, 0), ep("10.0.0.2:80", 1, 1)]);
        p2c.counter_for("10.0.0.1:80").store(100, Ordering::Relaxed);

        let mut picked_2 = 0_u32;
        for _ in 0..20 {
            let addr = p2c.select(None, &[]).unwrap();
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
            let addr = p2c.select(None, &[]).unwrap();
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
                &*p2c.select(Some(&state), &[]).unwrap(),
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

        let addr = p2c.select(Some(&state), &[]).unwrap();
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
            p2c.counter_for("10.0.0.1:80").load(Ordering::Relaxed),
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

        let handles: Vec<_> = std::iter::repeat_with(|| {
            let p = Arc::clone(&p2c);
            std::thread::spawn(move || {
                let addr = p.select(None, &[]).unwrap();
                p.release(&addr);
            })
        })
        .take(50)
        .collect();
        for h in handles {
            h.join().expect("thread should not panic");
        }

        let c1 = p2c.counter_for("10.0.0.1:80").load(Ordering::Relaxed);
        let c2 = p2c.counter_for("10.0.0.2:80").load(Ordering::Relaxed);
        assert_eq!(c1 + c2, 0, "all counters should be zero after paired select+release");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`WeightedEndpoint`] for testing.
    fn ep(addr: &str, weight: u32, index: usize) -> WeightedEndpoint {
        WeightedEndpoint::simple(Arc::from(addr), index, weight)
    }

    /// Build a [`ClusterHealthState`] with `n` healthy endpoints.
    fn health_state(n: usize) -> ClusterHealthState {
        let healths: Vec<_> = std::iter::repeat_with(EndpointHealth::new).take(n).collect();
        let addrs: Vec<_> = (0..n).map(|i| Arc::from(format!("10.0.0.{i}:80").as_str())).collect();
        Arc::new(ClusterHealthEntry::new(healths, addrs, None, None))
    }
}
