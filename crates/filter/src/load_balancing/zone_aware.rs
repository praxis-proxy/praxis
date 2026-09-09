// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Zone-aware load balancing: prefer same-zone endpoints, spilling to all
//! endpoints when local healthy capacity drops below a threshold.

use std::sync::Arc;

use praxis_core::{
    config::SimpleStrategy,
    health::{ClusterHealthState, EndpointHealth},
};

use super::{
    endpoint::WeightedEndpoint,
    strategy::{Strategy, build_simple_strategy},
};

// -----------------------------------------------------------------------------
// ZoneAware
// -----------------------------------------------------------------------------

/// Routes requests to local-zone endpoints when sufficient healthy capacity
/// exists, spilling to all endpoints when the local zone is degraded.
pub(crate) struct ZoneAware {
    /// Strategy built from only local-zone endpoints.
    local_strategy: Option<Box<Strategy>>,

    /// Strategy built from all endpoints (cross-zone fallback).
    all_strategy: Box<Strategy>,

    /// Indices of local-zone endpoints in the health state array.
    local_indices: Vec<usize>,

    /// Total number of endpoints (for health percentage calculation).
    local_count: usize,

    /// Minimum percentage of healthy local endpoints before spilling.
    min_local_healthy_pct: u8,
}

impl ZoneAware {
    /// Create a zone-aware LB that prefers endpoints in `local_zone`.
    pub(crate) fn new(
        endpoints: Vec<WeightedEndpoint>,
        local_zone: &str,
        inner_strategy: &SimpleStrategy,
        min_local_healthy_pct: u8,
    ) -> Self {
        let local_endpoints: Vec<WeightedEndpoint> = endpoints
            .iter()
            .filter(|ep| ep.zone.as_deref().is_some_and(|z| z == local_zone))
            .cloned()
            .collect();

        let local_indices: Vec<usize> = local_endpoints.iter().map(|ep| ep.index).collect();
        let local_count = local_endpoints.len();

        let local_strategy = if local_endpoints.is_empty() {
            None
        } else {
            Some(Box::new(build_simple_strategy(inner_strategy, local_endpoints)))
        };

        let all_strategy = Box::new(build_simple_strategy(inner_strategy, endpoints));

        Self {
            local_strategy,
            all_strategy,
            local_indices,
            local_count,
            min_local_healthy_pct,
        }
    }

    /// Select an endpoint, preferring the local zone if sufficiently healthy.
    pub(crate) fn select(
        &self,
        hash_key: Option<&str>,
        health: Option<&ClusterHealthState>,
        exclude: &[Arc<str>],
    ) -> Option<Arc<str>> {
        if let Some(local) = &self.local_strategy
            && self.local_zone_healthy_enough(health)
        {
            let result = local.select(hash_key, health, exclude);
            if result.is_some() {
                return result;
            }
        }

        self.all_strategy.select(hash_key, health, exclude)
    }

    /// Propagate release to both inner strategies.
    ///
    /// Release is forwarded to both inner strategies because the composite
    /// cannot know which one served the request. With counter-based inner
    /// strategies (`least_connections`, `p2c`) that costs accuracy on
    /// every request, not only while traffic spills between zones: the
    /// local and all-endpoint strategies keep separate counters for the
    /// local endpoints they share, `select` increments only the strategy
    /// that served, and `release` decrements both. The non-serving side
    /// saturates at zero, so the moment traffic moves to it, it sees idle
    /// endpoints that are in fact loaded and piles onto them until its own
    /// counters catch up.
    ///
    /// Exact counts would require the two strategies to share per-endpoint
    /// in-flight counters instead of owning one set each.
    pub(crate) fn release(&self, addr: &str) {
        if let Some(local) = &self.local_strategy {
            local.release(addr);
        }
        self.all_strategy.release(addr);
    }

    /// Check if the local zone has enough healthy endpoints to handle traffic.
    fn local_zone_healthy_enough(&self, health: Option<&ClusterHealthState>) -> bool {
        if self.local_count == 0 {
            return false;
        }

        let Some(state) = health else {
            return true;
        };

        let healthy_count = self
            .local_indices
            .iter()
            .filter(|&&idx| state.endpoints().get(idx).is_some_and(EndpointHealth::is_healthy))
            .count();

        #[expect(clippy::cast_possible_truncation, reason = "percentage is 0..=100")]
        let healthy_pct = ((healthy_count * 100) / self.local_count) as u8;
        healthy_pct >= self.min_local_healthy_pct
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

    use praxis_core::health::ClusterHealthEntry;

    use super::*;

    #[test]
    fn prefers_local_zone_when_healthy() {
        let endpoints = vec![
            ep("10.0.0.1:80", 0, "us-east-1a"),
            ep("10.0.0.2:80", 1, "us-east-1a"),
            ep("10.0.0.3:80", 2, "us-east-1b"),
            ep("10.0.0.4:80", 3, "us-west-2a"),
        ];
        let za = ZoneAware::new(endpoints, "us-east-1a", &SimpleStrategy::RoundRobin, 70);

        let mut seen = HashSet::new();
        for _ in 0..10 {
            seen.insert(za.select(None, None, &[]).unwrap());
        }
        assert!(seen.contains("10.0.0.1:80"), "local endpoint 1 should be used");
        assert!(seen.contains("10.0.0.2:80"), "local endpoint 2 should be used");
        assert!(!seen.contains("10.0.0.3:80"), "remote endpoint should not be used");
        assert!(!seen.contains("10.0.0.4:80"), "remote endpoint should not be used");
    }

    #[test]
    fn spills_to_all_when_local_degraded() {
        let endpoints = vec![
            ep("10.0.0.1:80", 0, "us-east-1a"),
            ep("10.0.0.2:80", 1, "us-east-1a"),
            ep("10.0.0.3:80", 2, "us-east-1a"),
            ep("10.0.0.4:80", 3, "us-east-1b"),
        ];
        let za = ZoneAware::new(endpoints, "us-east-1a", &SimpleStrategy::RoundRobin, 70);

        let state = health_state(4);
        state.endpoints()[0].mark_unhealthy();
        state.endpoints()[1].mark_unhealthy();
        // Only 1/3 local healthy = 33% < 70% threshold → spill

        let mut seen = HashSet::new();
        for _ in 0..20 {
            seen.insert(za.select(None, Some(&state), &[]).unwrap());
        }
        assert!(
            seen.contains("10.0.0.4:80"),
            "should spill to remote zone when local is degraded"
        );
    }

    #[test]
    fn stays_local_when_above_threshold() {
        let endpoints = vec![
            ep("10.0.0.1:80", 0, "us-east-1a"),
            ep("10.0.0.2:80", 1, "us-east-1a"),
            ep("10.0.0.3:80", 2, "us-east-1a"),
            ep("10.0.0.4:80", 3, "us-east-1b"),
        ];
        let za = ZoneAware::new(endpoints, "us-east-1a", &SimpleStrategy::RoundRobin, 50);

        let state = health_state(4);
        state.endpoints()[0].mark_unhealthy();
        // 2/3 local healthy = 66% >= 50% threshold → stay local

        let mut seen = HashSet::new();
        for _ in 0..20 {
            seen.insert(za.select(None, Some(&state), &[]).unwrap());
        }
        assert!(!seen.contains("10.0.0.4:80"), "should stay local when above threshold");
        assert!(!seen.contains("10.0.0.1:80"), "unhealthy local should be skipped");
    }

    #[test]
    fn no_local_endpoints_uses_all() {
        let endpoints = vec![ep("10.0.0.1:80", 0, "us-east-1b"), ep("10.0.0.2:80", 1, "us-west-2a")];
        let za = ZoneAware::new(endpoints, "us-east-1a", &SimpleStrategy::RoundRobin, 70);

        let mut seen = HashSet::new();
        for _ in 0..10 {
            seen.insert(za.select(None, None, &[]).unwrap());
        }
        assert_eq!(seen.len(), 2, "should use all endpoints when none are local");
    }

    #[test]
    fn endpoints_without_zone_are_not_local() {
        let mut endpoints = vec![ep("10.0.0.1:80", 0, "us-east-1a")];
        endpoints.push(WeightedEndpoint {
            address: Arc::from("10.0.0.2:80"),
            index: 1,
            weight: 1,
            metadata: std::collections::HashMap::new(),
            priority: 0,
            zone: None,
        });
        let za = ZoneAware::new(endpoints, "us-east-1a", &SimpleStrategy::RoundRobin, 70);

        for _ in 0..10 {
            let addr = za.select(None, None, &[]).unwrap();
            assert_eq!(&*addr, "10.0.0.1:80", "only zoned local endpoint should be selected");
        }
    }

    #[test]
    fn release_decrements_the_non_serving_strategy_too() {
        // Pins the documented approximation: a request served by the
        // local-zone strategy is released from the all-endpoint strategy
        // as well, so the latter's counter for a shared endpoint
        // saturates at zero while requests are still in flight there.
        let endpoints = vec![ep("10.0.0.1:80", 0, "us-east-1a"), ep("10.0.0.2:80", 1, "us-west-2a")];
        let za = ZoneAware::new(endpoints, "us-east-1a", &SimpleStrategy::LeastConnections, 70);

        for _ in 0..2 {
            assert_eq!(
                &*za.select(None, None, &[]).unwrap(),
                "10.0.0.1:80",
                "the only local endpoint must serve"
            );
        }
        za.release("10.0.0.1:80");

        let local = za.local_strategy.as_deref().expect("local zone is non-empty");
        assert_eq!(
            load_of(local, "10.0.0.1:80"),
            1,
            "the serving strategy must still see the second request in flight"
        );
        assert_eq!(
            load_of(&za.all_strategy, "10.0.0.1:80"),
            0,
            "the non-serving strategy is decremented too and saturates at zero"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// In-flight count an inner least-connections strategy holds for `addr`.
    fn load_of(strategy: &Strategy, addr: &str) -> usize {
        match strategy {
            Strategy::LeastConnections(lc) => lc.load_for(addr),
            _ => panic!("expected a least_connections inner strategy"),
        }
    }

    fn ep(addr: &str, index: usize, zone: &str) -> WeightedEndpoint {
        WeightedEndpoint {
            address: Arc::from(addr),
            index,
            weight: 1,
            metadata: std::collections::HashMap::new(),
            priority: 0,
            zone: Some(Arc::from(zone)),
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
