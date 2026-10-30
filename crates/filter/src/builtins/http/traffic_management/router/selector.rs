// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Route-level cluster selection.
//!
//! A route may name one cluster (the `cluster:` shorthand) or several weighted
//! targets split into priority tiers (`weighted_clusters:`). The selector picks
//! one cluster per request using weighted round-robin within the first tier that
//! has a healthy target, spilling to the next tier only when the current one has
//! none.
//!
//! Health is judged per cluster, not per endpoint: a target is eligible when
//! its cluster has at least one healthy endpoint. Endpoint weights inside the
//! selected cluster are applied later by the `load_balancer` filter, so the
//! effective share is `route_target_share * endpoint_share_within_cluster`.

use std::{collections::BTreeMap, sync::Arc};

use praxis_core::{
    config::RouteTargets,
    health::{ClusterHealthEntry, HealthRegistry},
};

use crate::weighted_cycle::{WeightedCycle, pick_weighted_cycle, pick_weighted_cycle_unfiltered};

// -----------------------------------------------------------------------------
// CompiledTargets
// -----------------------------------------------------------------------------

/// A route's compiled cluster destinations.
///
/// Tiers are ordered by priority number, lowest first. Compilation takes the
/// validated [`RouteTargets`], so the tier list and every tier are non-empty.
#[derive(Debug)]
pub(crate) struct CompiledTargets {
    /// Priority tiers, lowest priority number first.
    tiers: Box<[Tier]>,
}

/// One priority tier.
#[derive(Debug)]
struct Tier {
    /// Priority number from the route config; lower is preferred.
    priority: u32,

    /// Compiled targets in configuration order; index order is the tie-break.
    targets: Box<[CompiledTarget]>,

    /// Sum of the configured target weights in this tier.
    total_weight: u64,

    /// Weighted round-robin cursor. `None` for a single-target tier, which has
    /// nothing to rotate and should not pay for an atomic.
    cycle: Option<WeightedCycle>,

    /// Whether at least one target in this tier has a bound health handle.
    ///
    /// A tier with no health handles can skip eligibility scanning entirely and
    /// use the pre-computed [`Self::total_weight`].
    health_gated: bool,
}

/// One cluster target with everything selection needs.
#[derive(Debug)]
struct CompiledTarget {
    /// Cluster name.
    name: Arc<str>,

    /// Validated route-target weight.
    weight: u64,

    /// Health handle resolved at pipeline install, if the cluster is checked.
    health: Option<Arc<ClusterHealthEntry>>,
}

impl CompiledTargets {
    /// Compile a route's validated target set.
    pub(crate) fn compile(targets: &RouteTargets) -> Self {
        let mut by_priority: BTreeMap<u32, Vec<CompiledTarget>> = BTreeMap::new();
        for target in targets.targets() {
            by_priority.entry(target.priority).or_default().push(CompiledTarget {
                name: target.name.shared(),
                weight: u64::from(target.weight.get()),
                health: None,
            });
        }
        let tiers = by_priority
            .into_iter()
            .map(|(priority, targets)| {
                let total_weight = targets
                    .iter()
                    .fold(0_u64, |total, target| total.saturating_add(target.weight));
                Tier {
                    priority,
                    cycle: (targets.len() > 1).then(WeightedCycle::new),
                    targets: targets.into_boxed_slice(),
                    total_weight,
                    health_gated: false,
                }
            })
            .collect();
        Self { tiers }
    }

    /// Bind the pipeline's health handles, once per pipeline instance.
    pub(crate) fn bind_health(&mut self, registry: &HealthRegistry) {
        for tier in &mut self.tiers {
            for target in &mut tier.targets {
                target.health = registry.get(&*target.name).cloned();
            }
            tier.health_gated = tier.targets.iter().any(|target| target.health.is_some());
        }
    }

    /// Pass every cluster name this compiled set may select to `sink`.
    pub(crate) fn for_each_name<'a>(&'a self, sink: &mut dyn FnMut(&'a str)) {
        for tier in &self.tiers {
            for target in &tier.targets {
                sink(&target.name);
            }
        }
    }

    /// Warn when a failover target can never be gated by health.
    ///
    /// A target whose cluster has no top-level `health_check` has no registry
    /// entry, so it stays eligible. If its tier has a lower-priority tier below
    /// it, that lower tier can never be reached: the upper tier can never be
    /// marked fully unhealthy. That is valid for the last tier, but a silent
    /// misconfiguration anywhere above it.
    pub(crate) fn warn_unhealthy_priority_targets(&self, route: &str) {
        for (target, priority) in self.unhealthy_priority_targets() {
            let reason = if priority == 0 {
                "primary target has no health state; lower-priority tiers will never receive traffic"
            } else {
                "weighted target has no health state; this tier will never spill to lower-priority tiers"
            };
            tracing::warn!(
                cluster = %target.name,
                route = %route,
                priority,
                reason,
                "weighted target cannot be marked unhealthy"
            );
        }
    }

    /// Targets without health state that sit above a lower-priority tier.
    fn unhealthy_priority_targets(&self) -> impl Iterator<Item = (&CompiledTarget, u32)> {
        let last_priority = self.tiers.last().map(|tier| tier.priority);
        self.tiers
            .iter()
            .filter(move |tier| Some(tier.priority) != last_priority)
            .flat_map(|tier| {
                tier.targets
                    .iter()
                    .filter(|target| target.health.is_none())
                    .map(move |target| (target, tier.priority))
            })
    }

    /// Select the cluster for one request.
    ///
    /// # Panics
    ///
    /// Panics only if the compiled set is empty, which [`RouteTargets`] makes
    /// impossible and [`Self::compile`] is the only constructor.
    #[expect(clippy::expect_used, reason = "a compiled route target set is never empty")]
    pub(crate) fn select(&self) -> Arc<str> {
        self.try_select().expect("a compiled route target set is never empty")
    }

    /// Try each tier in order, then fan out to the primary tier in panic mode.
    fn try_select(&self) -> Option<Arc<str>> {
        for tier in &self.tiers {
            if let Some(cluster) = Self::select_from_tier(tier, true) {
                return Some(cluster);
            }
        }

        // Panic mode mirrors endpoint priority handling: no tier has a healthy
        // target, so use the highest-priority tier regardless of health and let
        // the downstream load balancer panic too.
        self.tiers.first().and_then(|tier| Self::select_from_tier(tier, false))
    }

    /// Weighted round-robin across one pre-computed tier.
    fn select_from_tier(tier: &Tier, require_health: bool) -> Option<Arc<str>> {
        let Some(cycle) = &tier.cycle else {
            let target = tier.targets.first()?;
            return target.is_eligible(require_health).then(|| Arc::clone(&target.name));
        };
        let candidates = || tier.targets.iter().map(|target| (target, target.weight));
        let winner = if require_health && tier.health_gated {
            pick_weighted_cycle(cycle, candidates(), |target| target.is_eligible(true))?
        } else {
            pick_weighted_cycle_unfiltered(cycle, tier.total_weight, candidates())?
        };
        Some(Arc::clone(&winner.name))
    }
}

impl CompiledTarget {
    /// Whether this target's cluster can serve traffic.
    ///
    /// No bound handle means "eligible": untracked clusters are not
    /// health-gated. A tracked cluster needs at least one healthy endpoint.
    fn is_eligible(&self, require_health: bool) -> bool {
        if !require_health {
            return true;
        }
        self.health.as_ref().is_none_or(|entry| entry.is_available())
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
    use std::collections::HashMap;

    use praxis_core::{config::Weight, health::EndpointHealth};

    use super::*;

    fn target(name: &str, weight: u16, priority: u32) -> praxis_core::config::WeightedTarget {
        praxis_core::config::WeightedTarget {
            name: name.into(),
            weight: Weight::from(weight),
            priority,
        }
    }

    fn compile(targets: Vec<praxis_core::config::WeightedTarget>) -> CompiledTargets {
        CompiledTargets::compile(&RouteTargets::try_new(targets).unwrap())
    }

    fn counts(
        selector: &mut CompiledTargets,
        registry: Option<&HealthRegistry>,
        runs: usize,
    ) -> HashMap<String, usize> {
        if let Some(registry) = registry {
            selector.bind_health(registry);
        }
        let mut seen = HashMap::new();
        for _ in 0..runs {
            let selected = selector.select();
            *seen.entry(selected.to_string()).or_insert(0) += 1;
        }
        seen
    }

    /// Registry with `(cluster, total_endpoints, unhealthy_indices)` entries.
    fn registry(clusters: &[(&str, usize, &[usize])]) -> HealthRegistry {
        let map: HashMap<Arc<str>, Arc<ClusterHealthEntry>> = clusters
            .iter()
            .map(|(name, total, unhealthy)| {
                let endpoints: Vec<EndpointHealth> = std::iter::repeat_with(EndpointHealth::new).take(*total).collect();
                let addresses: Vec<Arc<str>> = (0..*total)
                    .map(|index| Arc::from(format!("10.0.0.{index}:80").as_str()))
                    .collect();
                for &index in *unhealthy {
                    endpoints[index].mark_unhealthy();
                }
                (
                    Arc::from(*name),
                    Arc::new(ClusterHealthEntry::new(endpoints, addresses, None, None)),
                )
            })
            .collect();
        Arc::new(map)
    }

    #[test]
    fn nine_to_one_weights_split_accordingly() {
        let mut selector = compile(vec![target("stable", 9, 0), target("canary", 1, 0)]);
        let seen = counts(&mut selector, None, 100);
        assert_eq!(seen.get("stable"), Some(&90), "stable should take ~90%: {seen:?}");
        assert_eq!(seen.get("canary"), Some(&10), "canary should take ~10%: {seen:?}");
    }

    #[test]
    fn primary_tier_is_used_while_healthy() {
        let mut selector = compile(vec![target("stable", 9, 0), target("canary", 1, 0), target("dr", 1, 1)]);
        let seen = counts(&mut selector, None, 100);
        assert!(
            !seen.contains_key("dr"),
            "a healthy primary tier must not spill: {seen:?}"
        );
    }

    #[test]
    fn zero_healthy_canary_is_excluded_without_spilling() {
        let mut selector = compile(vec![target("stable", 1, 0), target("canary", 1, 0), target("dr", 1, 1)]);
        let registry = registry(&[("stable", 1, &[]), ("canary", 1, &[0]), ("dr", 1, &[])]);
        let seen = counts(&mut selector, Some(&registry), 20);
        assert_eq!(seen.get("stable"), Some(&20), "stable serves every request: {seen:?}");
        assert!(
            !seen.contains_key("canary"),
            "unhealthy target must be skipped: {seen:?}"
        );
        assert!(
            !seen.contains_key("dr"),
            "a partially healthy tier must not spill to the next tier: {seen:?}"
        );
    }

    #[test]
    fn fully_unhealthy_tier_spills_to_next() {
        let mut selector = compile(vec![
            target("stable", 1, 0),
            target("canary", 1, 0),
            target("dr-a", 1, 1),
            target("dr-b", 1, 1),
        ]);
        let registry = registry(&[
            ("stable", 1, &[0]),
            ("canary", 1, &[0]),
            ("dr-a", 1, &[]),
            ("dr-b", 1, &[]),
        ]);
        let seen = counts(&mut selector, Some(&registry), 10);
        assert_eq!(
            seen.get("dr-a"),
            Some(&5),
            "the failover tier must keep its rotation: {seen:?}"
        );
        assert_eq!(
            seen.get("dr-b"),
            Some(&5),
            "the failover tier must split evenly between its targets: {seen:?}"
        );
        assert_eq!(
            seen.get("stable"),
            None,
            "the unhealthy primary tier must not receive traffic: {seen:?}"
        );
    }

    #[test]
    fn all_unhealthy_enters_panic_mode_on_primary_tier() {
        let mut selector = compile(vec![target("stable", 1, 0), target("canary", 1, 0), target("dr", 1, 1)]);
        let registry = registry(&[("stable", 1, &[0]), ("canary", 1, &[0]), ("dr", 1, &[0])]);
        let seen = counts(&mut selector, Some(&registry), 10);
        assert_eq!(
            seen.get("stable"),
            Some(&5),
            "panic mode must rotate within the highest-priority tier: {seen:?}"
        );
        assert_eq!(
            seen.get("canary"),
            Some(&5),
            "panic mode must rotate within the highest-priority tier: {seen:?}"
        );
        assert_eq!(seen.get("dr"), None, "panic mode must not pick a lower tier: {seen:?}");
    }

    #[test]
    fn missing_registry_treats_all_targets_as_eligible() {
        let mut selector = compile(vec![target("stable", 1, 0), target("canary", 1, 0)]);
        let seen = counts(&mut selector, None, 10);
        assert_eq!(seen.get("stable"), Some(&5), "equal weights split evenly: {seen:?}");
        assert_eq!(seen.get("canary"), Some(&5), "equal weights split evenly: {seen:?}");
    }

    #[test]
    fn untracked_cluster_is_eligible() {
        let mut selector = compile(vec![target("stable", 1, 0)]);
        let registry = registry(&[("other", 1, &[0])]);
        selector.bind_health(&registry);
        assert_eq!(
            &*selector.select(),
            "stable",
            "a cluster absent from the registry is not health-gated"
        );
    }

    #[test]
    fn equal_weights_alternate_deterministically() {
        let selector = compile(vec![target("a", 1, 0), target("b", 1, 0)]);
        let mut picks = Vec::new();
        for _ in 0..4 {
            picks.push(selector.select().to_string());
        }
        assert_eq!(
            picks,
            vec!["a", "b", "a", "b"],
            "ties resolve to the lowest target index"
        );
    }

    #[test]
    fn single_target_skips_the_cycle_and_health_gate() {
        let mut selector = compile(vec![target("only", 5, 0)]);
        let registry = registry(&[("only", 1, &[0])]);
        selector.bind_health(&registry);
        for _ in 0..3 {
            assert_eq!(
                &*selector.select(),
                "only",
                "a single target has nothing to rotate or spill to"
            );
        }
    }

    #[test]
    fn diagnostics_cover_primary_and_intermediate_tiers() {
        let mut selector = compile(vec![target("a", 1, 0), target("b", 1, 1), target("c", 1, 2)]);
        let empty: HealthRegistry = Arc::new(HashMap::new());
        selector.bind_health(&empty);

        let diagnosed: Vec<(String, u32)> = selector
            .unhealthy_priority_targets()
            .map(|(target, priority)| (target.name.to_string(), priority))
            .collect();
        assert_eq!(
            diagnosed,
            vec![("a".to_owned(), 0), ("b".to_owned(), 1)],
            "every tier above a lower tier must be diagnosable"
        );
    }

    #[test]
    fn last_tier_without_health_is_not_a_misconfiguration() {
        let mut selector = compile(vec![target("a", 1, 0), target("dr", 1, 1)]);
        let empty: HealthRegistry = Arc::new(HashMap::new());
        selector.bind_health(&empty);

        let diagnosed: Vec<&str> = selector
            .unhealthy_priority_targets()
            .map(|(target, _)| target.name.as_ref())
            .collect();
        assert_eq!(diagnosed, vec!["a"], "the last tier has nothing below it to spill to");
    }

    #[test]
    fn rebinding_health_replaces_previous_handles() {
        let mut selector = compile(vec![target("a", 1, 0), target("b", 1, 0)]);
        let healthy = registry(&[("a", 1, &[]), ("b", 1, &[])]);
        selector.bind_health(&healthy);

        // A later binding marks `a` dead; selection follows the latest handles
        // rather than sticking to the first install.
        let dead = registry(&[("a", 1, &[0]), ("b", 1, &[])]);
        selector.bind_health(&dead);
        let seen = counts(&mut selector, None, 10);
        assert_eq!(seen.get("a"), None, "the latest binding gates selection: {seen:?}");
        assert_eq!(seen.get("b"), Some(&10), "the latest binding gates selection: {seen:?}");
    }
}
