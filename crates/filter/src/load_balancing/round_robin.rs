// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Weighted round-robin endpoint selection via cumulative weight thresholds.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use praxis_core::health::ClusterHealthState;

use super::endpoint::WeightedEndpoint;

// -----------------------------------------------------------------------------
// RoundRobin
// -----------------------------------------------------------------------------

/// Weighted round-robin selector using cumulative weight buckets.
pub(crate) struct RoundRobin {
    /// Deduplicated endpoint list with weights.
    endpoints: Vec<WeightedEndpoint>,

    /// Sum of all endpoint weights.
    total_weight: usize,

    /// Monotonically increasing counter; modulo-selected per call.
    counter: AtomicUsize,
}

impl RoundRobin {
    /// Create a round-robin selector from a deduplicated weighted endpoint list.
    pub(crate) fn new(endpoints: Vec<WeightedEndpoint>) -> Self {
        let total_weight: usize = endpoints.iter().map(|ep| ep.weight as usize).sum();
        Self {
            endpoints,
            total_weight,
            counter: AtomicUsize::new(0),
        }
    }

    /// Return the next healthy endpoint address in weighted round-robin order.
    ///
    /// Falls back to all endpoints (panic mode) when every endpoint is
    /// unhealthy. Endpoints listed in `exclude` are skipped.
    #[inline]
    pub(crate) fn select(&self, health: Option<&ClusterHealthState>, exclude: &[Arc<str>]) -> Option<Arc<str>> {
        if self.total_weight == 0 {
            return None;
        }
        let tick = self.counter.fetch_add(1, Ordering::Relaxed);

        if let Some(state) = health
            && let Some(addr) = self.select_healthy(tick, state, exclude)
        {
            return Some(addr);
        }

        select_by_weight_excluding(&self.endpoints, tick, exclude)
    }

    /// Attempt weighted selection among only healthy endpoints.
    #[expect(clippy::too_many_lines, reason = "fast/slow path split is clearer inline")]
    fn select_healthy(&self, tick: usize, state: &ClusterHealthState, exclude: &[Arc<str>]) -> Option<Arc<str>> {
        if exclude.is_empty() {
            let mut healthy_weight = 0_usize;
            for ep in &self.endpoints {
                if state.is_address_healthy(&ep.address) {
                    healthy_weight += ep.weight as usize;
                }
            }
            if healthy_weight == 0 {
                return None;
            }
            let slot = tick % healthy_weight;
            let mut cumulative = 0_usize;
            for ep in &self.endpoints {
                if state.is_address_healthy(&ep.address) {
                    cumulative += ep.weight as usize;
                    if slot < cumulative {
                        return Some(Arc::clone(&ep.address));
                    }
                }
            }
            return None;
        }

        // Slow path: filter by both health and exclusion list.
        let mut healthy_weight = 0_usize;
        for ep in &self.endpoints {
            if state.is_address_healthy(&ep.address) && !is_excluded(&ep.address, exclude) {
                healthy_weight += ep.weight as usize;
            }
        }
        if healthy_weight == 0 {
            return None;
        }
        let slot = tick % healthy_weight;
        let mut cumulative = 0_usize;
        for ep in &self.endpoints {
            if state.is_address_healthy(&ep.address) && !is_excluded(&ep.address, exclude) {
                cumulative += ep.weight as usize;
                if slot < cumulative {
                    return Some(Arc::clone(&ep.address));
                }
            }
        }
        None
    }
}

/// Walk `endpoints` to find the weight bucket containing `slot`.
#[expect(clippy::expect_used, reason = "non-empty at construction")]
fn select_by_weight(endpoints: &[WeightedEndpoint], tick: usize, total_weight: usize) -> Arc<str> {
    let slot = tick % total_weight;
    let mut cumulative = 0_usize;
    for ep in endpoints {
        cumulative += ep.weight as usize;
        if slot < cumulative {
            return Arc::clone(&ep.address);
        }
    }
    Arc::clone(&endpoints.last().expect("non-empty").address)
}

/// Weighted round-robin selection skipping excluded endpoints.
fn select_by_weight_excluding(endpoints: &[WeightedEndpoint], tick: usize, exclude: &[Arc<str>]) -> Option<Arc<str>> {
    if exclude.is_empty() {
        let total: usize = endpoints.iter().map(|ep| ep.weight as usize).sum();
        if total == 0 {
            return None;
        }
        return Some(select_by_weight(endpoints, tick, total));
    }
    let mut weight = 0_usize;
    for ep in endpoints {
        if !is_excluded(&ep.address, exclude) {
            weight += ep.weight as usize;
        }
    }
    if weight == 0 {
        return None;
    }
    let slot = tick % weight;
    let mut cumulative = 0_usize;
    for ep in endpoints {
        if !is_excluded(&ep.address, exclude) {
            cumulative += ep.weight as usize;
            if slot < cumulative {
                return Some(Arc::clone(&ep.address));
            }
        }
    }
    None
}

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
                "must select the live endpoint by address, not by position"
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
