// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Least-connections endpoint selection with in-flight tracking.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use praxis_core::health::ClusterHealthState;

use super::{
    endpoint::WeightedEndpoint,
    is_excluded,
    slow_start::{self, EffectiveWeights},
};

// -----------------------------------------------------------------------------
// LeastConnections
// -----------------------------------------------------------------------------

/// Picks the endpoint with the fewest active in-flight requests.
///
/// Weight influences tie-breaking: when two endpoints have equal
/// connection counts, the one with the higher weight wins.
/// When weights are also equal, a round-robin counter ensures
/// even distribution across endpoints with identical load.
pub(crate) struct LeastConnections {
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

    /// Round-robin tiebreaker for equal load and weight.
    rr_counter: AtomicUsize,
}

impl LeastConnections {
    /// Create a least-connections selector from a weighted endpoint list.
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
            rr_counter: AtomicUsize::new(0),
        }
    }

    /// Pick the healthy endpoint with the fewest in-flight requests.
    ///
    /// Falls back to all endpoints (panic mode) when all are unhealthy.
    /// Ties are broken by preferring higher-weight endpoints.
    pub(crate) fn select(&self, health: Option<&ClusterHealthState>, exclude: &[Arc<str>]) -> Option<Arc<str>> {
        self.select_weighted(health, exclude, None)
    }

    /// Pick the least-loaded endpoint, comparing load to ramp weight when `weights` scales.
    ///
    /// A smaller effective weight fills up sooner: `load / weight` is the score,
    /// so a new endpoint takes traffic in proportion to how far it has ramped.
    pub(crate) fn select_weighted(
        &self,
        health: Option<&ClusterHealthState>,
        exclude: &[Arc<str>],
        weights: Option<&EffectiveWeights>,
    ) -> Option<Arc<str>> {
        if slow_start::scaling_weights(weights).is_some() {
            return self.select_scaled(health, exclude, weights);
        }
        self.select_configured(health, exclude)
    }

    /// Pick using configured weights as the tie-break.
    #[expect(clippy::indexing_slicing, reason = "positions come from the endpoints scan")]
    fn select_configured(&self, health: Option<&ClusterHealthState>, exclude: &[Arc<str>]) -> Option<Arc<str>> {
        loop {
            let (pos, load) = self.find_best(health, exclude)?;
            let counter = &self.counters[pos];

            if counter
                .compare_exchange_weak(load, load + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(Arc::clone(&self.endpoints[pos].address));
            }
        }
    }

    /// Pick using `load / effective_weight`. Endpoints still at zero are skipped.
    #[expect(clippy::indexing_slicing, reason = "positions come from the endpoints scan")]
    fn select_scaled(
        &self,
        health: Option<&ClusterHealthState>,
        exclude: &[Arc<str>],
        weights: Option<&EffectiveWeights>,
    ) -> Option<Arc<str>> {
        loop {
            let Some((pos, load)) = self.find_scaled(health, exclude, weights) else {
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
            };
            let counter = &self.counters[pos];
            if counter
                .compare_exchange_weak(load, load + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(Arc::clone(&self.endpoints[pos].address));
            }
        }
    }

    /// Decrement the in-flight counter for `addr` after a response.
    pub(crate) fn release(&self, addr: &str) {
        if let Some(counter) = self.index_by_addr.get(addr).and_then(|pos| self.counters.get(*pos)) {
            _ = counter.fetch_update(Ordering::Release, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
        }
    }

    /// Current in-flight load for `addr`; test observability.
    #[cfg(test)]
    pub(crate) fn load_for(&self, addr: &str) -> usize {
        self.index_by_addr
            .get(addr)
            .and_then(|pos| self.counters.get(*pos))
            .map_or(0, |counter| counter.load(Ordering::Relaxed))
    }

    /// Scan endpoints and return the best candidate address with its
    /// current load. Prefers healthy endpoints when health state is
    /// available; falls back to all endpoints.
    fn find_best(&self, health: Option<&ClusterHealthState>, exclude: &[Arc<str>]) -> Option<(usize, usize)> {
        let offset = self.rr_counter.fetch_add(1, Ordering::Relaxed);

        if let Some(state) = health
            && let Some((addr, load)) = self.select_from_candidates(
                |ep| state.is_address_healthy(&ep.address) && !is_excluded(&ep.address, exclude),
                offset,
            )
        {
            return Some((addr, load));
        }

        self.select_from_candidates(|ep| !is_excluded(&ep.address, exclude), offset)
    }

    /// Best endpoint by `(load + 1) * configured / scaled`, then higher weight, then rotation.
    #[expect(clippy::indexing_slicing, reason = "counters is positionally aligned with endpoints")]
    #[expect(
        clippy::too_many_lines,
        reason = "one scan owns the ratio comparison and rotation rank"
    )]
    fn find_scaled(
        &self,
        health: Option<&ClusterHealthState>,
        exclude: &[Arc<str>],
        weights: Option<&EffectiveWeights>,
    ) -> Option<(usize, usize)> {
        let offset = self.rr_counter.fetch_add(1, Ordering::Relaxed);
        let keep = |endpoint: &WeightedEndpoint| {
            slow_start::endpoint_weight(&endpoint.address, endpoint.weight, weights) > 0
                && !is_excluded(&endpoint.address, exclude)
                && health.is_none_or(|state| state.is_address_healthy(&endpoint.address))
        };
        let len = self.endpoints.iter().filter(|endpoint| keep(endpoint)).count();
        if len == 0 {
            return None;
        }
        let start = offset % len;
        let mut best: Option<(u32, u64, usize, usize, usize)> = None;
        let mut filtered_index = 0_usize;
        for (pos, endpoint) in self.endpoints.iter().enumerate() {
            if !keep(endpoint) {
                continue;
            }
            let rank = (filtered_index + len - start) % len;
            filtered_index += 1;
            let scaled = slow_start::endpoint_weight(&endpoint.address, endpoint.weight, weights);
            let load = self.counters[pos].load(Ordering::Acquire);
            let better = match best {
                None => true,
                Some((best_configured, best_scaled, best_rank, best_load, _)) => {
                    let left = slow_start::ramp_load_cost(load, endpoint.weight, best_scaled);
                    let right = slow_start::ramp_load_cost(best_load, best_configured, scaled);
                    left < right
                        || (left == right && endpoint.weight > best_configured)
                        || (left == right && endpoint.weight == best_configured && rank < best_rank)
                },
            };
            if better {
                best = Some((endpoint.weight, scaled, rank, load, pos));
            }
        }
        best.map(|(_, _, _, load, pos)| (pos, load))
    }

    /// Select the best candidate among endpoints matching `keep`, using the
    /// round-robin offset to break ties on equal load and weight.
    ///
    /// Tie-break order: lowest load wins, then highest weight, then the
    /// endpoint earliest in rotation order (rank 0 == `start`).
    #[expect(clippy::indexing_slicing, reason = "counters is positionally aligned with endpoints")]
    fn select_from_candidates(
        &self,
        keep: impl Fn(&WeightedEndpoint) -> bool,
        offset: usize,
    ) -> Option<(usize, usize)> {
        let len = self.endpoints.iter().filter(|ep| keep(ep)).count();
        if len == 0 {
            return None;
        }
        let start = offset % len;

        // best = (rank, load, weight, position); lower rank is earlier in
        // the rotation starting at `start`.
        let mut best: Option<(usize, usize, u32, usize)> = None;
        let mut filtered_index = 0_usize;
        for (pos, ep) in self.endpoints.iter().enumerate() {
            if !keep(ep) {
                continue;
            }
            let rank = (filtered_index + len - start) % len;
            filtered_index += 1;
            let load = self.counters[pos].load(Ordering::Acquire);
            let better = match best {
                None => true,
                Some((best_rank, best_load, best_weight, _)) => {
                    load < best_load
                        || (load == best_load && ep.weight > best_weight)
                        || (load == best_load && ep.weight == best_weight && rank < best_rank)
                },
            };
            if better {
                best = Some((rank, load, ep.weight, pos));
            }
        }
        best.map(|(_, load, _, pos)| (pos, load))
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
    use std::thread;

    use praxis_core::health::{ClusterHealthEntry, EndpointHealth};

    use super::*;

    #[test]
    fn a_small_ramp_does_not_beat_a_busy_full_endpoint() {
        let lc = LeastConnections::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1),
        ]);
        let weights = EffectiveWeights::from_scaled(&[("10.0.0.1:80", 1_000_000), ("10.0.0.2:80", 20_000)]);
        for pick in 0..4 {
            let picked = lc.select_weighted(None, &[], Some(&weights)).unwrap();
            assert_eq!(
                &*picked, "10.0.0.1:80",
                "an endpoint at 2% of its weight does not take request {pick} while the full one has load {pick}"
            );
        }
    }

    #[test]
    fn selects_min() {
        let lc = LeastConnections::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.3:80"), 1),
        ]);

        let first = lc.select(None, &[]).unwrap();
        assert_eq!(&*first, "10.0.0.1:80", "first selection should go to first endpoint");

        let second = lc.select(None, &[]).unwrap();
        assert_eq!(&*second, "10.0.0.2:80", "second selection should pick least-loaded");

        lc.release("10.0.0.1:80");
        let third = lc.select(None, &[]).unwrap();
        let load_of_third = lc.load_for(&third);
        assert_eq!(
            load_of_third, 1,
            "third selection should pick an endpoint that was at 0 (now incremented to 1)"
        );
        assert_ne!(&*third, "10.0.0.2:80", "should not pick the loaded endpoint");
    }

    #[test]
    fn release_does_not_underflow() {
        let lc = LeastConnections::new(vec![WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1)]);

        lc.release("10.0.0.1:80");
        assert_eq!(
            lc.load_for("10.0.0.1:80"),
            0,
            "release without select should not underflow"
        );
    }

    #[test]
    fn release_unknown_addr_is_noop() {
        let lc = LeastConnections::new(vec![WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1)]);

        lc.release("10.0.0.99:80");
    }

    #[test]
    fn skips_unhealthy_endpoints() {
        let lc = LeastConnections::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1),
        ]);
        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new(), EndpointHealth::new()],
            vec![Arc::from("10.0.0.1:80"), Arc::from("10.0.0.2:80")],
            None,
            None,
        ));
        state.endpoints()[0].mark_unhealthy();

        assert_eq!(
            &*lc.select(Some(&state), &[]).unwrap(),
            "10.0.0.2:80",
            "should skip unhealthy endpoint"
        );
    }

    #[test]
    fn panic_mode_when_all_unhealthy() {
        let lc = LeastConnections::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1),
        ]);
        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new(), EndpointHealth::new()],
            vec![Arc::from("10.0.0.1:80"), Arc::from("10.0.0.2:80")],
            None,
            None,
        ));
        state.endpoints()[0].mark_unhealthy();
        state.endpoints()[1].mark_unhealthy();

        let selected = lc.select(Some(&state), &[]).unwrap();
        assert!(
            &*selected == "10.0.0.1:80" || &*selected == "10.0.0.2:80",
            "panic mode should still return an endpoint"
        );
    }

    #[test]
    fn weight_breaks_ties() {
        let lc = LeastConnections::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 3),
        ]);

        assert_eq!(
            &*lc.select(None, &[]).unwrap(),
            "10.0.0.2:80",
            "higher-weight endpoint should win tie at 0 connections"
        );
    }

    #[test]
    fn concurrent_select_distributes_load() {
        let lc = Arc::new(LeastConnections::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1),
        ]));
        let total = 100;

        let handles: Vec<_> = std::iter::repeat_with(|| {
            let lc = Arc::clone(&lc);
            thread::spawn(move || lc.select(None, &[]))
        })
        .take(total)
        .collect();

        for h in handles {
            h.join().unwrap();
        }

        let c1 = lc.load_for("10.0.0.1:80");
        let c2 = lc.load_for("10.0.0.2:80");
        assert_eq!(c1 + c2, total, "total in-flight count must equal total selections");
    }

    #[test]
    fn concurrent_select_and_release() {
        let lc = Arc::new(LeastConnections::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1),
        ]));

        let handles: Vec<_> = std::iter::repeat_with(|| {
            let lc = Arc::clone(&lc);
            thread::spawn(move || {
                let addr = lc.select(None, &[]).unwrap();
                lc.release(&addr);
            })
        })
        .take(50)
        .collect();

        for h in handles {
            h.join().unwrap();
        }

        let c1 = lc.load_for("10.0.0.1:80");
        let c2 = lc.load_for("10.0.0.2:80");
        assert_eq!(
            c1 + c2,
            0,
            "all counters should return to zero after select+release pairs"
        );
    }
}
