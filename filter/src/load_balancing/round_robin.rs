// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

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
    /// Deduplicated endpoint list with weights and original indices.
    endpoints: Vec<WeightedEndpoint>,

    /// Sum of all endpoint weights (pre-computed, widened to `usize`).
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
    /// Computes `counter % total_healthy_weight`, then walks the healthy
    /// endpoint list to find the matching weight bucket. Falls back to
    /// all endpoints (panic mode) when every endpoint is unhealthy.
    #[inline]
    pub(crate) fn select(&self, health: Option<&ClusterHealthState>) -> Arc<str> {
        debug_assert!(!self.endpoints.is_empty(), "round-robin requires at least one endpoint");
        let tick = self.counter.fetch_add(1, Ordering::Relaxed);

        if let Some(state) = health
            && let Some(addr) = self.select_healthy(tick, state)
        {
            return addr;
        }

        select_by_weight(&self.endpoints, tick, self.total_weight)
    }

    /// Attempt weighted selection among only healthy endpoints.
    #[allow(clippy::indexing_slicing, reason = "bounds checked")]
    fn select_healthy(&self, tick: usize, state: &ClusterHealthState) -> Option<Arc<str>> {
        let healthy_weight: usize = self
            .endpoints
            .iter()
            .filter(|ep| ep.index < state.endpoints().len() && state.endpoints()[ep.index].is_healthy())
            .map(|ep| ep.weight as usize)
            .sum();

        if healthy_weight == 0 {
            return None;
        }

        let slot = tick % healthy_weight;
        let mut cumulative = 0usize;
        for ep in &self.endpoints {
            if ep.index < state.endpoints().len() && state.endpoints()[ep.index].is_healthy() {
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
#[allow(clippy::expect_used, reason = "non-empty at construction")]
fn select_by_weight(endpoints: &[WeightedEndpoint], tick: usize, total_weight: usize) -> Arc<str> {
    let slot = tick % total_weight;
    let mut cumulative = 0usize;
    for ep in endpoints {
        cumulative += ep.weight as usize;
        if slot < cumulative {
            return Arc::clone(&ep.address);
        }
    }
    Arc::clone(&endpoints.last().expect("endpoints must be non-empty").address)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use std::sync::Arc;

    use praxis_core::health::{ClusterHealthEntry, EndpointHealth};

    use super::*;

    #[test]
    fn single_endpoint() {
        let rr = RoundRobin::new(vec![WeightedEndpoint {
            address: Arc::from("127.0.0.1:8080"),
            weight: 1,
            index: 0,
        }]);
        assert_eq!(&*rr.select(None), "127.0.0.1:8080", "select #1");
        assert_eq!(&*rr.select(None), "127.0.0.1:8080", "select #2");
        assert_eq!(&*rr.select(None), "127.0.0.1:8080", "select #3");
    }

    #[test]
    fn full_cycle_ordering() {
        let rr = RoundRobin::new(vec![
            WeightedEndpoint {
                address: Arc::from("127.0.0.1:8080"),
                weight: 1,
                index: 0,
            },
            WeightedEndpoint {
                address: Arc::from("127.0.0.1:8081"),
                weight: 1,
                index: 1,
            },
            WeightedEndpoint {
                address: Arc::from("127.0.0.1:8082"),
                weight: 1,
                index: 2,
            },
        ]);
        assert_eq!(&*rr.select(None), "127.0.0.1:8080", "cycle 1: first endpoint");
        assert_eq!(&*rr.select(None), "127.0.0.1:8081", "cycle 1: second endpoint");
        assert_eq!(&*rr.select(None), "127.0.0.1:8082", "cycle 1: third endpoint");
        assert_eq!(&*rr.select(None), "127.0.0.1:8080", "cycle 2: should wrap to first");
    }

    #[test]
    fn weighted_distribution() {
        let rr = RoundRobin::new(vec![
            WeightedEndpoint {
                address: Arc::from("10.0.0.1:80"),
                weight: 1,
                index: 0,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.2:80"),
                weight: 3,
                index: 1,
            },
        ]);

        let mut counts = std::collections::HashMap::new();
        for _ in 0..4 {
            *counts.entry(rr.select(None)).or_insert(0u32) += 1;
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
            WeightedEndpoint {
                address: Arc::from("10.0.0.1:80"),
                weight: 1,
                index: 0,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.2:80"),
                weight: 1,
                index: 1,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.3:80"),
                weight: 1,
                index: 2,
            },
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
            &*rr.select(Some(&state)),
            "10.0.0.2:80",
            "should skip unhealthy endpoint 0"
        );
    }

    #[test]
    fn weighted_with_health_redistributes() {
        let rr = RoundRobin::new(vec![
            WeightedEndpoint {
                address: Arc::from("10.0.0.1:80"),
                weight: 1,
                index: 0,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.2:80"),
                weight: 3,
                index: 1,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.3:80"),
                weight: 1,
                index: 2,
            },
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
            let selected = rr.select(Some(&state));
            assert_ne!(
                &*selected, "10.0.0.2:80",
                "unhealthy endpoint B should never be selected"
            );
            *counts.entry(selected).or_insert(0u32) += 1;
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
            WeightedEndpoint {
                address: Arc::from("10.0.0.1:80"),
                weight: 1,
                index: 0,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.2:80"),
                weight: 1,
                index: 1,
            },
        ]);
        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new(), EndpointHealth::new()],
            vec![Arc::from("10.0.0.1:80"), Arc::from("10.0.0.2:80")],
            None,
            None,
        ));
        state.endpoints()[0].mark_unhealthy();
        state.endpoints()[1].mark_unhealthy();

        let selected = rr.select(Some(&state));
        assert!(
            &*selected == "10.0.0.1:80" || &*selected == "10.0.0.2:80",
            "panic mode should still return an endpoint"
        );
    }
}
