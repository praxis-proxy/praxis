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

use super::{
    endpoint::WeightedEndpoint,
    is_excluded,
    slow_start::{self, EffectiveWeights},
};

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
    /// `endpoints`.
    counters: Vec<AtomicUsize>,

    /// Address-to-position lookup for [`release`], the only entry point
    /// keyed by address.
    ///
    /// [`release`]: Self::release
    index_by_addr: HashMap<Arc<str>, usize>,

    /// Deduplicated endpoint list with weights.
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
    pub(crate) fn select(&self, health: Option<&ClusterHealthState>, exclude: &[Arc<str>]) -> Option<Arc<str>> {
        self.select_weighted(health, exclude, None)
    }

    /// Sample two endpoints. Ramp weights replace configured weights while scaling.
    pub(crate) fn select_weighted(
        &self,
        health: Option<&ClusterHealthState>,
        exclude: &[Arc<str>],
        weights: Option<&EffectiveWeights>,
    ) -> Option<Arc<str>> {
        if let Some(weights) = slow_start::scaling_weights(weights) {
            return self.select_scaled(health, exclude, weights);
        }
        self.select_configured(health, exclude)
    }

    /// Sample two endpoints using configured weights.
    #[expect(clippy::indexing_slicing, reason = "positions come from the endpoints scan")]
    fn select_configured(&self, health: Option<&ClusterHealthState>, exclude: &[Arc<str>]) -> Option<Arc<str>> {
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

        let (pos_a, start_a) = self.weight_index_pos(&candidates, self.pick_slot(total_w));
        // Draw the second slot from the other endpoints' weight only, then
        // skip over `pos_a`'s slot range so the two samples are always
        // distinct endpoints, not merely distinct slots.
        let weight_a = self.endpoints[pos_a].weight as usize;
        let mut b = self.pick_slot(total_w - weight_a);
        if b >= start_a {
            b += weight_a;
        }
        let (pos_b, _) = self.weight_index_pos(&candidates, b);
        let chosen = self.less_loaded(pos_a, pos_b);

        self.counters[chosen].fetch_add(1, Ordering::AcqRel);
        Some(Arc::clone(&self.endpoints[chosen].address))
    }

    /// Sample two endpoints in proportion to their scaled ramp weight.
    #[expect(clippy::indexing_slicing, reason = "positions come from the endpoints scan")]
    #[expect(
        clippy::too_many_lines,
        reason = "the two samples and the empty-candidate fallback stay together"
    )]
    fn select_scaled(
        &self,
        health: Option<&ClusterHealthState>,
        exclude: &[Arc<str>],
        weights: &EffectiveWeights,
    ) -> Option<Arc<str>> {
        if self.endpoints.is_empty() {
            return None;
        }
        let mut candidates = self.candidate_positions(health, exclude);
        candidates.retain(|pos| self.scaled_weight(*pos, weights) > 0);
        if candidates.is_empty() {
            let any_healthy = health.is_some_and(|state| {
                state
                    .endpoints()
                    .iter()
                    .any(praxis_core::health::EndpointHealth::is_healthy)
            });
            if any_healthy {
                return None;
            }
            return self.select_configured(health, exclude);
        }
        let total: u64 = candidates.iter().map(|&pos| self.scaled_weight(pos, weights)).sum();
        let pos = if candidates.len() == 1 || total <= 1 {
            candidates[0]
        } else {
            let pos_a = self.pick_scaled(&candidates, weights, total);
            let rest: SmallVec<[usize; 8]> = candidates.iter().copied().filter(|&pos| pos != pos_a).collect();
            let rest_total = total.saturating_sub(self.scaled_weight(pos_a, weights));
            let pos_b = if rest.is_empty() || rest_total == 0 {
                pos_a
            } else {
                self.pick_scaled(&rest, weights, rest_total)
            };
            if pos_a == pos_b {
                pos_a
            } else {
                self.less_loaded_scaled(pos_a, pos_b, weights)
            }
        };
        self.counters[pos].fetch_add(1, Ordering::AcqRel);
        Some(Arc::clone(&self.endpoints[pos].address))
    }

    /// Scaled ramp weight for the endpoint at `pos`.
    #[expect(clippy::indexing_slicing, reason = "pos comes from the endpoints scan")]
    fn scaled_weight(&self, pos: usize, weights: &EffectiveWeights) -> u64 {
        let endpoint = &self.endpoints[pos];
        slow_start::endpoint_weight(&endpoint.address, endpoint.weight, Some(weights))
    }

    /// Map a random slot onto `candidates` using scaled weights.
    fn pick_scaled(&self, candidates: &[usize], weights: &EffectiveWeights, total: u64) -> usize {
        let slot = super::next_random(&self.rng) % total.max(1);
        let mut start = 0_u64;
        for &pos in candidates {
            let end = start.saturating_add(self.scaled_weight(pos, weights));
            if slot < end {
                return pos;
            }
            start = end;
        }
        candidates.last().copied().unwrap_or(0)
    }

    /// Lower `(load + 1) * configured / scaled`, breaking ties with higher configured weight.
    #[expect(clippy::indexing_slicing, reason = "positions come from the endpoints scan")]
    fn less_loaded_scaled(&self, a: usize, b: usize, weights: &EffectiveWeights) -> usize {
        let load_a = self.counters[a].load(Ordering::Acquire);
        let load_b = self.counters[b].load(Ordering::Acquire);
        let scaled_a = self.scaled_weight(a, weights);
        let scaled_b = self.scaled_weight(b, weights);
        let cost_a = slow_start::ramp_load_cost(load_a, self.endpoints[a].weight, scaled_b);
        let cost_b = slow_start::ramp_load_cost(load_b, self.endpoints[b].weight, scaled_a);
        match cost_a.cmp(&cost_b) {
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

    /// Generate a random slot in `[0, total_weight)`.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "modulo total_weight bounds the result to usize range"
    )]
    fn pick_slot(&self, total_weight: usize) -> usize {
        (super::next_random(&self.rng) as usize) % total_weight
    }

    /// Map a cumulative-weight slot to a candidate position and the first
    /// slot of that candidate's weight range.
    #[expect(clippy::indexing_slicing, reason = "positions come from the endpoints scan")]
    #[expect(clippy::expect_used, reason = "caller guarantees candidates is non-empty")]
    fn weight_index_pos(&self, candidates: &[usize], slot: usize) -> (usize, usize) {
        let mut start = 0_usize;
        for &pos in candidates {
            let end = start + self.endpoints[pos].weight as usize;
            if slot < end {
                return (pos, start);
            }
            start = end;
        }
        let last = *candidates.last().expect("candidates must be non-empty");
        (last, start - self.endpoints[last].weight as usize)
    }

    /// Candidate positions: healthy-and-not-excluded when any endpoint is
    /// healthy, else all not-excluded (panic mode).
    fn candidate_positions(&self, health: Option<&ClusterHealthState>, exclude: &[Arc<str>]) -> SmallVec<[usize; 8]> {
        if let Some(state) = health {
            let mut candidates: SmallVec<[usize; 8]> = SmallVec::new();
            let mut any_healthy = false;
            for (pos, ep) in self.endpoints.iter().enumerate() {
                let healthy = state.is_address_healthy(&ep.address);
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
    fn scaled_power_of_two_skips_a_zero_ramp() {
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1), ep("10.0.0.2:80", 1)]);
        let weights = EffectiveWeights::from_scaled(&[("10.0.0.1:80", 1_000_000), ("10.0.0.2:80", 0)]);
        for _ in 0..16 {
            let picked = p2c
                .select_weighted(None, &[], Some(&weights))
                .expect("the settled endpoint");
            assert_eq!(&*picked, "10.0.0.1:80", "an endpoint at zero is not sampled");
        }
    }

    #[test]
    fn single_endpoint_always_selected() {
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1)]);
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
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1), ep("10.0.0.2:80", 1), ep("10.0.0.3:80", 1)]);

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
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1), ep("10.0.0.2:80", 1)]);
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
    fn samples_every_endpoint_pair() {
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1), ep("10.0.0.2:80", 1), ep("10.0.0.3:80", 1)]);
        p2c.counter_for("10.0.0.1:80").store(1_000_000, Ordering::Relaxed);

        let mut picked_2 = 0_u32;
        for _ in 0..3000 {
            let addr = p2c.select(None, &[]).unwrap();
            if &*addr == "10.0.0.2:80" {
                picked_2 += 1;
            }
            p2c.release(&addr);
        }
        assert!(
            (1200..=1800).contains(&picked_2),
            "with the first endpoint pinned busy, the other two should split evenly: picked_2={picked_2}"
        );
    }

    #[test]
    fn weight_biases_sampling() {
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1), ep("10.0.0.2:80", 9)]);

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
    fn weighted_endpoints_are_still_compared_by_load() {
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 9), ep("10.0.0.2:80", 1)]);
        p2c.counter_for("10.0.0.1:80").store(100, Ordering::Relaxed);

        for _ in 0..50 {
            let addr = p2c.select(None, &[]).unwrap();
            assert_eq!(
                &*addr, "10.0.0.2:80",
                "a heavy endpoint must never be compared against itself and win by default"
            );
            p2c.release(&addr);
        }
    }

    #[test]
    fn skips_unhealthy() {
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1), ep("10.0.0.2:80", 1)]);
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
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1), ep("10.0.0.2:80", 1)]);
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
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1)]);
        p2c.release("10.0.0.1:80");
        assert_eq!(
            p2c.counter_for("10.0.0.1:80").load(Ordering::Relaxed),
            0,
            "release without select should not underflow"
        );
    }

    #[test]
    fn release_unknown_addr_is_noop() {
        let p2c = PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1)]);
        p2c.release("10.0.0.99:80");
    }

    #[test]
    fn concurrent_select_and_release() {
        let p2c = Arc::new(PowerOfTwoChoices::new(vec![ep("10.0.0.1:80", 1), ep("10.0.0.2:80", 1)]));

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
    fn ep(addr: &str, weight: u32) -> WeightedEndpoint {
        WeightedEndpoint::simple(Arc::from(addr), weight)
    }

    /// Build a [`ClusterHealthState`] with `n` healthy endpoints.
    fn health_state(n: usize) -> ClusterHealthState {
        let healths: Vec<_> = std::iter::repeat_with(EndpointHealth::new).take(n).collect();
        let addrs: Vec<_> = (0..n)
            .map(|i| Arc::from(format!("10.0.0.{}:80", i + 1).as_str()))
            .collect();
        Arc::new(ClusterHealthEntry::new(healths, addrs, None, None))
    }
}
