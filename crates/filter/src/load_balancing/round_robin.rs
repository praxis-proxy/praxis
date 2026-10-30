// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Weighted round-robin endpoint selection via cumulative weight thresholds.

use std::sync::{Arc, Mutex, PoisonError};

use praxis_core::health::ClusterHealthState;

use super::{
    endpoint::WeightedEndpoint,
    is_excluded,
    slow_start::{self, EffectiveWeights},
};
use crate::weighted_cycle::{WeightedCycle, pick_weighted_matching};

// -----------------------------------------------------------------------------
// RoundRobin
// -----------------------------------------------------------------------------

/// Weighted round-robin selector using cumulative weight buckets.
pub(crate) struct RoundRobin {
    /// Deduplicated endpoint list with weights.
    endpoints: Vec<WeightedEndpoint>,

    /// Sum of all endpoint weights.
    total_weight: u64,

    /// Monotonically increasing weighted-round-robin cursor.
    cycle: WeightedCycle,

    /// Running scores for smooth weighted round robin.
    ///
    /// Used only while slow start is scaling. Contiguous buckets stay in
    /// place for configured weights, whose totals are small.
    smooth: Mutex<Vec<i64>>,
}

impl RoundRobin {
    /// Create a round-robin selector from a deduplicated weighted endpoint list.
    pub(crate) fn new(endpoints: Vec<WeightedEndpoint>) -> Self {
        let total_weight = endpoints.iter().fold(0_u64, |total, endpoint| {
            total.saturating_add(u64::from(endpoint.weight))
        });
        let smooth = Mutex::new(vec![0; endpoints.len()]);
        Self {
            endpoints,
            total_weight,
            cycle: WeightedCycle::new(),
            smooth,
        }
    }

    /// Return the next healthy endpoint address in weighted round-robin order.
    ///
    /// Falls back to all endpoints (panic mode) when every endpoint is
    /// unhealthy. Endpoints listed in `exclude` are skipped.
    #[inline]
    pub(crate) fn select(&self, health: Option<&ClusterHealthState>, exclude: &[Arc<str>]) -> Option<Arc<str>> {
        self.select_weighted(health, exclude, None)
    }

    /// Pick the next endpoint, using smooth weighted round robin when `weights` scales.
    pub(crate) fn select_weighted(
        &self,
        health: Option<&ClusterHealthState>,
        exclude: &[Arc<str>],
        weights: Option<&EffectiveWeights>,
    ) -> Option<Arc<str>> {
        if self.total_weight == 0 {
            return None;
        }
        if let Some(weights) = slow_start::scaling_weights(weights) {
            return self.select_smooth(health, exclude, weights);
        }
        let tick = self.cycle.next();

        if let Some(state) = health
            && let Some(addr) = self.select_healthy(tick, state, exclude)
        {
            return Some(addr);
        }

        self.pick_matching(tick, |endpoint| !is_excluded(&endpoint.address, exclude))
    }

    /// Nginx-style smooth weighted round robin over the scaled ramp weights.
    ///
    /// Each eligible endpoint adds its weight to a running score. The highest
    /// score is picked and then reduced by the total, so a fractional ramp
    /// interleaves instead of occupying a million contiguous slots.
    #[expect(
        clippy::too_many_lines,
        reason = "the score update and the winner adjustment are one critical section"
    )]
    fn select_smooth(
        &self,
        health: Option<&ClusterHealthState>,
        exclude: &[Arc<str>],
        weights: &EffectiveWeights,
    ) -> Option<Arc<str>> {
        let mut current = self.smooth.lock().unwrap_or_else(PoisonError::into_inner);
        let mut best: Option<(usize, i64)> = None;
        let mut total = 0_i64;
        for (pos, endpoint) in self.endpoints.iter().enumerate() {
            if !smooth_candidate(endpoint, health, exclude) {
                continue;
            }
            let weight = i64::try_from(slow_start::endpoint_weight(
                &endpoint.address,
                endpoint.weight,
                Some(weights),
            ))
            .unwrap_or(i64::MAX);
            if weight <= 0 {
                continue;
            }
            let score = current.get(pos).copied().unwrap_or(0).saturating_add(weight);
            if let Some(slot) = current.get_mut(pos) {
                *slot = score;
            }
            total = total.saturating_add(weight);
            if best.is_none_or(|(_, best_score)| score > best_score) {
                best = Some((pos, score));
            }
        }
        let (pos, _) = best?;
        if let Some(slot) = current.get_mut(pos) {
            *slot = slot.saturating_sub(total);
        }
        let address = Arc::clone(&self.endpoints.get(pos)?.address);
        drop(current);
        Some(address)
    }

    /// Attempt weighted selection among only healthy endpoints.
    fn select_healthy(&self, tick: u64, state: &ClusterHealthState, exclude: &[Arc<str>]) -> Option<Arc<str>> {
        self.pick_matching(tick, |endpoint| {
            state.is_address_healthy(&endpoint.address) && !is_excluded(&endpoint.address, exclude)
        })
    }

    /// Pick the weight bucket containing `tick` among matching endpoints.
    fn pick_matching<F>(&self, tick: u64, candidate: F) -> Option<Arc<str>>
    where
        F: Fn(&WeightedEndpoint) -> bool,
    {
        let index = pick_weighted_matching(
            tick,
            self.endpoints
                .iter()
                .enumerate()
                .map(|(index, endpoint)| (index, u64::from(endpoint.weight))),
            |index| self.endpoints.get(index).is_some_and(&candidate),
        )?;
        self.endpoints.get(index).map(|endpoint| Arc::clone(&endpoint.address))
    }
}

/// Whether `endpoint` is in the smooth-round-robin candidate set.
fn smooth_candidate(endpoint: &WeightedEndpoint, health: Option<&ClusterHealthState>, exclude: &[Arc<str>]) -> bool {
    if is_excluded(&endpoint.address, exclude) {
        return false;
    }
    health.is_none_or(|state| state.is_address_healthy(&endpoint.address))
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
    fn smooth_round_robin_interleaves_a_partial_ramp() {
        let rr = RoundRobin::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1),
        ]);
        let weights = EffectiveWeights::from_scaled(&[("10.0.0.1:80", 1_000_000), ("10.0.0.2:80", 500_000)]);
        let picks: Vec<String> = std::iter::repeat_with(|| {
            rr.select_weighted(None, &[], Some(&weights))
                .expect("both endpoints have weight")
                .to_string()
        })
        .take(6)
        .collect();
        let heavy = picks.iter().filter(|pick| pick.as_str() == "10.0.0.1:80").count();
        assert_eq!(
            heavy, 4,
            "weight 2/3 of the picks go to the settled endpoint: {picks:?}"
        );
        assert!(
            picks
                .windows(3)
                .all(|window| window.iter().filter(|pick| pick.as_str() == "10.0.0.1:80").count() < 3),
            "the heavier endpoint does not take three requests in a row: {picks:?}"
        );
    }

    #[test]
    fn smooth_round_robin_skips_a_zero_ramp() {
        let rr = RoundRobin::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1),
        ]);
        let weights = EffectiveWeights::from_scaled(&[("10.0.0.1:80", 1_000_000), ("10.0.0.2:80", 0)]);
        for _ in 0..4 {
            let picked = rr
                .select_weighted(None, &[], Some(&weights))
                .expect("the settled endpoint");
            assert_eq!(&*picked, "10.0.0.1:80", "an endpoint at zero stays out of rotation");
        }
    }

    #[test]
    fn an_idle_ramp_keeps_contiguous_buckets() {
        let rr = RoundRobin::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 2),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1),
        ]);
        let weights = EffectiveWeights::idle(&[("10.0.0.1:80", 2_000_000), ("10.0.0.2:80", 1_000_000)]);
        let picks: Vec<String> = std::iter::repeat_with(|| {
            rr.select_weighted(None, &[], Some(&weights))
                .expect("both endpoints have configured weight")
                .to_string()
        })
        .take(6)
        .collect();
        assert_eq!(
            picks,
            [
                "10.0.0.1:80",
                "10.0.0.1:80",
                "10.0.0.2:80",
                "10.0.0.1:80",
                "10.0.0.1:80",
                "10.0.0.2:80",
            ],
            "an idle ramp uses configured buckets: {picks:?}"
        );
    }

    #[test]
    fn single_endpoint() {
        let rr = RoundRobin::new(vec![WeightedEndpoint::simple(Arc::from("127.0.0.1:8080"), 1)]);
        assert_eq!(&*rr.select(None, &[]).unwrap(), "127.0.0.1:8080", "select #1");
        assert_eq!(&*rr.select(None, &[]).unwrap(), "127.0.0.1:8080", "select #2");
        assert_eq!(&*rr.select(None, &[]).unwrap(), "127.0.0.1:8080", "select #3");
    }

    #[test]
    fn full_cycle_ordering() {
        let rr = RoundRobin::new(vec![
            WeightedEndpoint::simple(Arc::from("127.0.0.1:8080"), 1),
            WeightedEndpoint::simple(Arc::from("127.0.0.1:8081"), 1),
            WeightedEndpoint::simple(Arc::from("127.0.0.1:8082"), 1),
        ]);
        assert_eq!(
            &*rr.select(None, &[]).unwrap(),
            "127.0.0.1:8080",
            "cycle 1: first endpoint"
        );
        assert_eq!(
            &*rr.select(None, &[]).unwrap(),
            "127.0.0.1:8081",
            "cycle 1: second endpoint"
        );
        assert_eq!(
            &*rr.select(None, &[]).unwrap(),
            "127.0.0.1:8082",
            "cycle 1: third endpoint"
        );
        assert_eq!(
            &*rr.select(None, &[]).unwrap(),
            "127.0.0.1:8080",
            "cycle 2: should wrap to first"
        );
    }

    #[test]
    fn weighted_distribution() {
        let rr = RoundRobin::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 3),
        ]);

        let mut counts = std::collections::HashMap::new();
        for _ in 0..4 {
            *counts.entry(rr.select(None, &[]).unwrap()).or_insert(0_u32) += 1;
        }
        assert_eq!(
            counts.get("10.0.0.1:80").copied().unwrap_or(0),
            1,
            "weight-1 endpoint should appear once per cycle of 4"
        );
        assert_eq!(
            counts.get("10.0.0.2:80").copied().unwrap_or(0),
            3,
            "weight-3 endpoint should appear three times per cycle of 4"
        );
    }

    #[test]
    fn skips_unhealthy() {
        let rr = RoundRobin::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.3:80"), 1),
        ]);
        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new(), EndpointHealth::new(), EndpointHealth::new()],
            vec![
                Arc::from("10.0.0.1:80"),
                Arc::from("10.0.0.2:80"),
                Arc::from("10.0.0.3:80"),
            ],
            None,
            None,
        ));
        state.endpoints()[0].mark_unhealthy();

        assert_eq!(
            &*rr.select(Some(&state), &[]).unwrap(),
            "10.0.0.2:80",
            "should skip unhealthy endpoint 0"
        );
    }

    #[test]
    fn health_lookup_is_by_address_not_position() {
        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new(), EndpointHealth::new()],
            vec![Arc::from("10.0.0.1:80"), Arc::from("10.0.0.2:80")],
            None,
            None,
        ));
        state.endpoints()[0].mark_unhealthy();

        let rr = RoundRobin::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1),
        ]);
        for _ in 0..10 {
            assert_eq!(
                &*rr.select(Some(&state), &[]).unwrap(),
                "10.0.0.2:80",
                "health is looked up by address, so reversing the LB order relative to the registry must still select the live endpoint, not the dead one by position"
            );
        }
    }

    #[test]
    fn weighted_with_health_redistributes() {
        let rr = RoundRobin::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 3),
            WeightedEndpoint::simple(Arc::from("10.0.0.3:80"), 1),
        ]);
        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new(), EndpointHealth::new(), EndpointHealth::new()],
            vec![
                Arc::from("10.0.0.1:80"),
                Arc::from("10.0.0.2:80"),
                Arc::from("10.0.0.3:80"),
            ],
            None,
            None,
        ));
        state.endpoints()[1].mark_unhealthy();

        let mut counts = std::collections::HashMap::new();
        for _ in 0..20 {
            let selected = rr.select(Some(&state), &[]).unwrap();
            assert_ne!(
                &*selected, "10.0.0.2:80",
                "unhealthy endpoint B should never be selected"
            );
            *counts.entry(selected).or_insert(0_u32) += 1;
        }

        let a_count = counts.get("10.0.0.1:80").copied().unwrap_or(0);
        let c_count = counts.get("10.0.0.3:80").copied().unwrap_or(0);
        assert_eq!(
            a_count, c_count,
            "A (weight=1) and C (weight=1) should get equal traffic: A={a_count}, C={c_count}"
        );
    }

    #[test]
    fn panic_mode_when_all_unhealthy() {
        let rr = RoundRobin::new(vec![
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

        let selected = rr.select(Some(&state), &[]).unwrap();
        assert!(
            &*selected == "10.0.0.1:80" || &*selected == "10.0.0.2:80",
            "panic mode should still return an endpoint"
        );
    }

    #[test]
    fn empty_endpoints_returns_none() {
        let rr = RoundRobin::new(vec![]);
        assert!(
            rr.select(None, &[]).is_none(),
            "empty endpoint list should return None instead of panicking"
        );
    }

    #[test]
    fn empty_endpoints_with_health_returns_none() {
        let rr = RoundRobin::new(vec![]);
        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(vec![], vec![], None, None));
        assert!(
            rr.select(Some(&state), &[]).is_none(),
            "empty endpoint list with health state should return None"
        );
    }

    #[test]
    fn all_zero_weight_returns_none() {
        let rr = RoundRobin::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 0),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 0),
        ]);
        assert!(
            rr.select(None, &[]).is_none(),
            "all-zero-weight endpoints should return None (total_weight is 0)"
        );
    }

    #[test]
    fn select_excludes_attempted_endpoints() {
        let rr = RoundRobin::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.3:80"), 1),
        ]);
        let exclude = [Arc::<str>::from("10.0.0.1:80"), Arc::<str>::from("10.0.0.2:80")];
        for _ in 0..6 {
            let selected = rr.select(None, &exclude).unwrap();
            assert_eq!(
                &*selected, "10.0.0.3:80",
                "exclude set should force selection of the remaining endpoint"
            );
        }
    }

    #[test]
    fn select_falls_back_when_all_excluded() {
        let rr = RoundRobin::new(vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1),
        ]);
        let exclude = [Arc::<str>::from("10.0.0.1:80"), Arc::<str>::from("10.0.0.2:80")];
        assert!(
            rr.select(None, &exclude).is_none(),
            "round robin returns None when every endpoint is excluded"
        );
        let strategy = crate::load_balancing::strategy::Strategy::RoundRobin(rr);
        assert!(
            strategy.select(None, None, &exclude).is_some(),
            "Strategy::select should fall back to the full set when all are excluded"
        );
    }
}
