// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Priority-level load balancing: use primary endpoints exclusively until
//! their healthy capacity is insufficient, then spill to failover tiers.

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
// PriorityLevels
// -----------------------------------------------------------------------------

/// Routes requests to the highest-priority (lowest number) tier that has
/// sufficient healthy capacity. Spills to the next tier when the current
/// tier's healthy weight falls below `100 / overprovisioning_factor` of
/// its total weight.
pub(crate) struct PriorityLevels {
    /// Ordered tiers from highest priority (0) to lowest.
    tiers: Vec<PriorityTier>,

    /// Overprovisioning factor as a percentage (e.g. 140 → spill when
    /// healthy capacity < 100/140 ≈ 71% of tier weight).
    overprovisioning_factor: u32,
}

/// A single priority tier with its own inner strategy.
struct PriorityTier {
    /// Strategy for this tier's endpoints.
    strategy: Box<Strategy>,

    /// Endpoint indices in the health state for capacity calculation.
    indices: Vec<usize>,
}

impl PriorityLevels {
    /// Create a priority-level LB that groups endpoints by their `priority`
    /// field and builds an inner strategy for each tier.
    pub(crate) fn new(
        endpoints: Vec<WeightedEndpoint>,
        inner_strategy: &SimpleStrategy,
        overprovisioning_factor: u32,
    ) -> Self {
        let mut tier_map: std::collections::BTreeMap<u32, Vec<WeightedEndpoint>> = std::collections::BTreeMap::new();
        for ep in endpoints {
            tier_map.entry(ep.priority).or_default().push(ep);
        }

        let tiers: Vec<PriorityTier> = tier_map
            .into_values()
            .map(|tier_eps| {
                let indices: Vec<usize> = tier_eps.iter().map(|ep| ep.index).collect();
                let strategy = Box::new(build_simple_strategy(inner_strategy, tier_eps));
                PriorityTier { strategy, indices }
            })
            .collect();

        Self {
            tiers,
            overprovisioning_factor,
        }
    }

    /// Select an endpoint from the highest-priority tier with sufficient capacity.
    pub(crate) fn select(
        &self,
        hash_key: Option<&str>,
        health: Option<&ClusterHealthState>,
        exclude: &[Arc<str>],
    ) -> Option<Arc<str>> {
        if self.tiers.is_empty() {
            return None;
        }

        for tier in &self.tiers {
            if self.tier_has_capacity(tier, health) {
                let result = tier.strategy.select(hash_key, health, exclude);
                if result.is_some() {
                    return result;
                }
            }
        }

        // Panic mode: no tier meets its capacity threshold. Prefer the
        // highest-priority tier that still has at least one healthy endpoint;
        // blindly routing to tier 0 would send traffic to a fully-dead tier
        // while healthy lower tiers exist.
        self.tiers
            .iter()
            .find(|tier| Self::tier_healthy_count(tier, health) > 0)
            .or_else(|| self.tiers.first())
            .and_then(|t| t.strategy.select(hash_key, health, exclude))
    }

    /// Propagate release to all tier strategies.
    pub(crate) fn release(&self, addr: &str) {
        for tier in &self.tiers {
            tier.strategy.release(addr);
        }
    }

    /// A tier has capacity if its healthy endpoint ratio exceeds the
    /// overprovisioning threshold: `healthy% >= 100 / overprovisioning_factor`.
    fn tier_has_capacity(&self, tier: &PriorityTier, health: Option<&ClusterHealthState>) -> bool {
        let total_count = tier.indices.len();
        if total_count == 0 {
            return false;
        }

        if health.is_none() {
            return true;
        }

        let healthy_count = Self::tier_healthy_count(tier, health);

        // healthy% >= 100/overprovisioning_factor
        // ⟺ healthy_count * overprovisioning_factor >= total_count * 100
        let factor = u64::from(self.overprovisioning_factor);
        (healthy_count as u64) * factor >= (total_count as u64) * 100
    }

    /// Number of healthy endpoints in a tier; all endpoints count as healthy
    /// when no health state is available.
    fn tier_healthy_count(tier: &PriorityTier, health: Option<&ClusterHealthState>) -> usize {
        let Some(state) = health else {
            return tier.indices.len();
        };
        tier.indices
            .iter()
            .filter(|&&idx| state.endpoints().get(idx).is_some_and(EndpointHealth::is_healthy))
            .count()
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
    fn uses_primary_tier_when_healthy() {
        let endpoints = vec![
            ep("10.0.0.1:80", 0, 0),
            ep("10.0.0.2:80", 1, 0),
            ep("10.0.0.3:80", 2, 1),
            ep("10.0.0.4:80", 3, 1),
        ];
        let pl = PriorityLevels::new(endpoints, &SimpleStrategy::RoundRobin, 140);

        let mut seen = HashSet::new();
        for _ in 0..10 {
            seen.insert(pl.select(None, None, &[]).unwrap());
        }
        assert!(seen.contains("10.0.0.1:80"), "primary tier endpoint 1");
        assert!(seen.contains("10.0.0.2:80"), "primary tier endpoint 2");
        assert!(!seen.contains("10.0.0.3:80"), "failover should not be used");
        assert!(!seen.contains("10.0.0.4:80"), "failover should not be used");
    }

    #[test]
    fn spills_to_failover_when_primary_degraded() {
        let endpoints = vec![
            ep("10.0.0.1:80", 0, 0),
            ep("10.0.0.2:80", 1, 0),
            ep("10.0.0.3:80", 2, 1),
            ep("10.0.0.4:80", 3, 1),
        ];
        let pl = PriorityLevels::new(endpoints, &SimpleStrategy::RoundRobin, 140);

        let state = health_state(4);
        state.endpoints()[0].mark_unhealthy();
        state.endpoints()[1].mark_unhealthy();
        // Primary tier: 0/2 healthy = 0% < 71% → spill

        let mut seen = HashSet::new();
        for _ in 0..10 {
            seen.insert(pl.select(None, Some(&state), &[]).unwrap());
        }
        assert!(
            seen.contains("10.0.0.3:80") || seen.contains("10.0.0.4:80"),
            "should spill to failover tier"
        );
    }

    #[test]
    fn panic_mode_prefers_tier_with_healthy_endpoints() {
        let endpoints = vec![
            ep("10.0.0.1:80", 0, 0),
            ep("10.0.0.2:80", 1, 0),
            ep("10.0.0.3:80", 2, 1),
            ep("10.0.0.4:80", 3, 1),
        ];
        // Factor 400 → threshold 25%; tier 1 with 1/2 healthy (50%) passes it,
        // so raise the bar: factor 100 → threshold 100%. Tier 0 has 0/2 and
        // tier 1 has 1/2 healthy: no tier meets capacity, but panic mode must
        // still prefer tier 1's healthy endpoint over dead tier 0.
        let pl = PriorityLevels::new(endpoints, &SimpleStrategy::RoundRobin, 100);

        let state = health_state(4);
        state.endpoints()[0].mark_unhealthy();
        state.endpoints()[1].mark_unhealthy();
        state.endpoints()[2].mark_unhealthy();

        for _ in 0..10 {
            let selected = pl.select(None, Some(&state), &[]).unwrap();
            assert_eq!(
                selected.as_ref(),
                "10.0.0.4:80",
                "panic mode must route to the only tier with a healthy endpoint"
            );
        }
    }

    #[test]
    fn stays_primary_when_above_threshold() {
        let endpoints = vec![
            ep("10.0.0.1:80", 0, 0),
            ep("10.0.0.2:80", 1, 0),
            ep("10.0.0.3:80", 2, 0),
            ep("10.0.0.4:80", 3, 1),
        ];
        // overprovisioning=200 → threshold is 100/200 = 50%
        let pl = PriorityLevels::new(endpoints, &SimpleStrategy::RoundRobin, 200);

        let state = health_state(4);
        state.endpoints()[0].mark_unhealthy();
        // Primary: 2/3 healthy = 66% >= 50% → stay

        let mut seen = HashSet::new();
        for _ in 0..20 {
            seen.insert(pl.select(None, Some(&state), &[]).unwrap());
        }
        assert!(
            !seen.contains("10.0.0.4:80"),
            "should stay in primary tier when above threshold"
        );
        assert!(!seen.contains("10.0.0.1:80"), "unhealthy primary should be skipped");
    }

    #[test]
    fn multiple_failover_tiers() {
        let endpoints = vec![
            ep("10.0.0.1:80", 0, 0),
            ep("10.0.0.2:80", 1, 1),
            ep("10.0.0.3:80", 2, 2),
        ];
        let pl = PriorityLevels::new(endpoints, &SimpleStrategy::RoundRobin, 140);

        let state = health_state(3);
        state.endpoints()[0].mark_unhealthy();
        state.endpoints()[1].mark_unhealthy();
        // Tier 0: 0/1 healthy → spill
        // Tier 1: 0/1 healthy → spill
        // Tier 2: 1/1 healthy → use

        let addr = pl.select(None, Some(&state), &[]).unwrap();
        assert_eq!(&*addr, "10.0.0.3:80", "should reach third-priority tier");
    }

    #[test]
    fn all_same_priority_acts_as_single_tier() {
        let endpoints = vec![
            ep("10.0.0.1:80", 0, 0),
            ep("10.0.0.2:80", 1, 0),
            ep("10.0.0.3:80", 2, 0),
        ];
        let pl = PriorityLevels::new(endpoints, &SimpleStrategy::RoundRobin, 140);

        let mut seen = HashSet::new();
        for _ in 0..10 {
            seen.insert(pl.select(None, None, &[]).unwrap());
        }
        assert_eq!(seen.len(), 3, "all endpoints should be reachable in a single tier");
    }

    #[test]
    fn empty_endpoints_returns_none() {
        let pl = PriorityLevels::new(Vec::new(), &SimpleStrategy::RoundRobin, 140);
        assert!(pl.select(None, None, &[]).is_none());
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    fn ep(addr: &str, index: usize, priority: u32) -> WeightedEndpoint {
        WeightedEndpoint {
            address: Arc::from(addr),
            index,
            weight: 1,
            metadata: std::collections::HashMap::new(),
            priority,
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
