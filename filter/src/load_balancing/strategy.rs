// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Load-balancing strategy selection and dispatch.

use std::sync::Arc;

use praxis_core::{
    config::{LoadBalancerStrategy, ParameterisedStrategy, SimpleStrategy},
    health::ClusterHealthState,
};

use super::{
    consistent_hash::ConsistentHash, endpoint::WeightedEndpoint, least_connections::LeastConnections, maglev::Maglev,
    p2c::PowerOfTwoChoices, priority::PriorityLevels, random::Random, ring_hash::RingHash, round_robin::RoundRobin,
    subset::Subset, zone_aware::ZoneAware,
};

// -----------------------------------------------------------------------------
// Strategy
// -----------------------------------------------------------------------------

/// Load-balancing strategy variant for a cluster.
pub(crate) enum Strategy {
    /// Cycle through endpoints in order, respecting weights.
    RoundRobin(RoundRobin),

    /// Pick the endpoint with the fewest active requests.
    LeastConnections(LeastConnections),

    /// Hash a request attribute to a stable endpoint.
    ConsistentHash(ConsistentHash),

    /// Sample two random endpoints; pick the less loaded one.
    PowerOfTwoChoices(PowerOfTwoChoices),

    /// Uniform random selection, weighted by endpoint weight.
    Random(Random),

    /// Maglev consistent hashing with a fixed-size lookup table.
    Maglev(Maglev),

    /// Ring-hash with configurable hash function and virtual node density.
    RingHash(RingHash),

    /// Subset-based: filter by metadata, then apply inner strategy.
    Subset(Subset),

    /// Zone-aware: prefer local-zone endpoints, spill when degraded.
    ZoneAware(ZoneAware),

    /// Priority-level tiering: primary first, failover when degraded.
    Priority(PriorityLevels),
}

impl Strategy {
    /// Pick the next endpoint address using a protocol-agnostic hash key.
    ///
    /// For HTTP, the caller extracts the key from headers or URI path.
    /// For TCP, the caller typically passes the client IP address.
    ///
    /// When `exclude` is non-empty, previously attempted endpoints are
    /// skipped. If every endpoint is excluded, the exclusion set is
    /// ignored and selection falls back to the full set (best-effort).
    pub(crate) fn select(
        &self,
        hash_key: Option<&str>,
        health: Option<&ClusterHealthState>,
        exclude: &[Arc<str>],
    ) -> Option<Arc<str>> {
        let addr = match self {
            Self::RoundRobin(rr) => rr.select(health, exclude),
            Self::LeastConnections(lc) => lc.select(health, exclude),
            Self::ConsistentHash(ch) => ch.select(hash_key, health, exclude),
            Self::PowerOfTwoChoices(p2c) => p2c.select(health, exclude),
            Self::Random(r) => r.select(health, exclude),
            Self::Maglev(m) => m.select(hash_key, health, exclude),
            Self::RingHash(rh) => rh.select(hash_key, health, exclude),
            Self::Subset(s) => s.select(hash_key, health, exclude),
            Self::ZoneAware(za) => za.select(hash_key, health, exclude),
            Self::Priority(p) => p.select(hash_key, health, exclude),
        };
        if addr.is_some() {
            return addr;
        }
        // All endpoints excluded — fall back to the full set.
        if !exclude.is_empty() {
            return match self {
                Self::RoundRobin(rr) => rr.select(health, &[]),
                Self::LeastConnections(lc) => lc.select(health, &[]),
                Self::ConsistentHash(ch) => ch.select(hash_key, health, &[]),
                Self::PowerOfTwoChoices(p2c) => p2c.select(health, &[]),
                Self::Random(r) => r.select(health, &[]),
                Self::Maglev(m) => m.select(hash_key, health, &[]),
                Self::RingHash(rh) => rh.select(hash_key, health, &[]),
                Self::Subset(s) => s.select(hash_key, health, &[]),
                Self::ZoneAware(za) => za.select(hash_key, health, &[]),
                Self::Priority(p) => p.select(hash_key, health, &[]),
            };
        }
        None
    }

    /// Called after a response arrives so that strategies that track in-flight
    /// request counts (e.g. `LeastConnections`) can decrement their counter.
    pub(crate) fn release(&self, addr: &str) {
        match self {
            Self::LeastConnections(lc) => lc.release(addr),
            Self::PowerOfTwoChoices(p2c) => p2c.release(addr),
            Self::Subset(s) => s.release(addr),
            Self::ZoneAware(za) => za.release(addr),
            Self::Priority(p) => p.release(addr),
            Self::RoundRobin(_) | Self::ConsistentHash(_) | Self::Random(_) | Self::Maglev(_) | Self::RingHash(_) => {},
        }
    }
}

/// Create the appropriate strategy variant from the config.
#[expect(
    clippy::too_many_lines,
    reason = "match arms are flat; splitting would reduce clarity"
)]
pub(crate) fn build_strategy(lb_strategy: &LoadBalancerStrategy, endpoints: Vec<WeightedEndpoint>) -> Strategy {
    match lb_strategy {
        LoadBalancerStrategy::Simple(simple) => build_simple_strategy(simple, endpoints),
        LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ConsistentHash(opts)) => {
            Strategy::ConsistentHash(ConsistentHash::new(endpoints, opts.header.clone()))
        },
        LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Maglev(opts)) => {
            Strategy::Maglev(Maglev::new(endpoints, opts.header.clone()))
        },
        LoadBalancerStrategy::Parameterised(ParameterisedStrategy::RingHash(opts)) => {
            Strategy::RingHash(RingHash::new(
                endpoints,
                opts.header.clone(),
                opts.hash_function.clone(),
                opts.virtual_nodes,
            ))
        },
        LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Subset(opts)) => Strategy::Subset(Subset::new(
            endpoints,
            &opts.selector,
            &opts.inner_strategy,
            opts.fallback_policy.clone(),
        )),
        LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ZoneAware(opts)) => {
            Strategy::ZoneAware(ZoneAware::new(
                endpoints,
                &opts.local_zone,
                &opts.inner_strategy,
                opts.min_local_healthy_pct,
            ))
        },
        LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Priority(opts)) => Strategy::Priority(
            PriorityLevels::new(endpoints, &opts.inner_strategy, opts.overprovisioning_factor),
        ),
    }
}

/// Build a strategy from a `SimpleStrategy` variant. Used by composite strategies
/// that need to construct inner strategies.
pub(crate) fn build_simple_strategy(simple: &SimpleStrategy, endpoints: Vec<WeightedEndpoint>) -> Strategy {
    match simple {
        SimpleStrategy::RoundRobin => Strategy::RoundRobin(RoundRobin::new(endpoints)),
        SimpleStrategy::LeastConnections => Strategy::LeastConnections(LeastConnections::new(endpoints)),
        SimpleStrategy::PowerOfTwoChoices => Strategy::PowerOfTwoChoices(PowerOfTwoChoices::new(endpoints)),
        SimpleStrategy::Random => Strategy::Random(Random::new(endpoints)),
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
    use std::{collections::HashMap, sync::atomic::Ordering};

    use praxis_core::config::{
        ConsistentHashOpts, HashFunction, MaglevOpts, PriorityOpts, RingHashOpts, SubsetFallbackPolicy, SubsetOpts,
        ZoneAwareOpts,
    };

    use super::*;

    #[test]
    fn build_strategy_round_robin() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Simple(SimpleStrategy::RoundRobin),
            make_endpoints(),
        );
        assert!(
            matches!(strategy, Strategy::RoundRobin(_)),
            "SimpleStrategy::RoundRobin should produce Strategy::RoundRobin"
        );
    }

    #[test]
    fn build_strategy_least_connections() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections),
            make_endpoints(),
        );
        assert!(
            matches!(strategy, Strategy::LeastConnections(_)),
            "SimpleStrategy::LeastConnections should produce Strategy::LeastConnections"
        );
    }

    #[test]
    fn build_strategy_consistent_hash() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ConsistentHash(ConsistentHashOpts {
                header: Some("X-Session".to_owned()),
            })),
            make_endpoints(),
        );
        assert!(
            matches!(strategy, Strategy::ConsistentHash(_)),
            "ParameterisedStrategy::ConsistentHash should produce Strategy::ConsistentHash"
        );
    }

    #[test]
    fn build_strategy_random() {
        let strategy = build_strategy(&LoadBalancerStrategy::Simple(SimpleStrategy::Random), make_endpoints());
        assert!(
            matches!(strategy, Strategy::Random(_)),
            "SimpleStrategy::Random should produce Strategy::Random"
        );
    }

    #[test]
    fn release_round_robin_is_noop() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Simple(SimpleStrategy::RoundRobin),
            make_endpoints(),
        );
        strategy.release("10.0.0.1:80");
    }

    #[test]
    fn release_random_is_noop() {
        let strategy = build_strategy(&LoadBalancerStrategy::Simple(SimpleStrategy::Random), make_endpoints());
        strategy.release("10.0.0.1:80");
    }

    #[test]
    fn release_consistent_hash_is_noop() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ConsistentHash(ConsistentHashOpts {
                header: None,
            })),
            make_endpoints(),
        );
        strategy.release("10.0.0.1:80");
    }

    #[test]
    fn release_least_connections_decrements() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections),
            make_endpoints(),
        );
        strategy.select(None, None, &[]);
        if let Strategy::LeastConnections(lc) = &strategy {
            let before = lc.counters["10.0.0.1:80"].load(Ordering::Relaxed);
            strategy.release("10.0.0.1:80");
            let after = lc.counters["10.0.0.1:80"].load(Ordering::Relaxed);
            assert_eq!(
                after,
                before.saturating_sub(1),
                "release should decrement in-flight counter"
            );
        } else {
            panic!("expected LeastConnections variant");
        }
    }

    #[test]
    fn select_round_robin_returns_some() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Simple(SimpleStrategy::RoundRobin),
            make_endpoints(),
        );
        assert!(
            strategy.select(None, None, &[]).is_some(),
            "RoundRobin select should return Some with healthy endpoints"
        );
    }

    #[test]
    fn select_least_connections_returns_some() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections),
            make_endpoints(),
        );
        assert!(
            strategy.select(None, None, &[]).is_some(),
            "LeastConnections select should return Some with healthy endpoints"
        );
    }

    #[test]
    fn select_consistent_hash_returns_some() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ConsistentHash(ConsistentHashOpts {
                header: None,
            })),
            make_endpoints(),
        );
        assert!(
            strategy.select(Some("/path"), None, &[]).is_some(),
            "ConsistentHash select should return Some with healthy endpoints"
        );
    }

    #[test]
    fn build_strategy_p2c() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Simple(SimpleStrategy::PowerOfTwoChoices),
            make_endpoints(),
        );
        assert!(
            matches!(strategy, Strategy::PowerOfTwoChoices(_)),
            "SimpleStrategy::PowerOfTwoChoices should produce Strategy::PowerOfTwoChoices"
        );
    }

    #[test]
    fn release_p2c_decrements() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Simple(SimpleStrategy::PowerOfTwoChoices),
            make_endpoints(),
        );
        strategy.select(None, None, &[]);
        if let Strategy::PowerOfTwoChoices(p2c) = &strategy {
            let before = p2c.counters["10.0.0.1:80"].load(Ordering::Relaxed)
                + p2c.counters["10.0.0.2:80"].load(Ordering::Relaxed);
            assert_eq!(before, 1, "one selection should have incremented one counter");
        }
        strategy.release("10.0.0.1:80");
        strategy.release("10.0.0.2:80");
    }

    #[test]
    fn select_random_returns_some() {
        let strategy = build_strategy(&LoadBalancerStrategy::Simple(SimpleStrategy::Random), make_endpoints());
        assert!(
            strategy.select(None, None, &[]).is_some(),
            "Random select should return Some with healthy endpoints"
        );
    }

    #[test]
    fn select_p2c_returns_some() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Simple(SimpleStrategy::PowerOfTwoChoices),
            make_endpoints(),
        );
        assert!(
            strategy.select(None, None, &[]).is_some(),
            "P2C select should return Some with healthy endpoints"
        );
    }

    #[test]
    fn build_strategy_maglev() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Maglev(MaglevOpts { header: None })),
            make_endpoints(),
        );
        assert!(
            matches!(strategy, Strategy::Maglev(_)),
            "ParameterisedStrategy::Maglev should produce Strategy::Maglev"
        );
    }

    #[test]
    fn release_maglev_is_noop() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Maglev(MaglevOpts { header: None })),
            make_endpoints(),
        );
        strategy.release("10.0.0.1:80");
    }

    #[test]
    fn select_maglev_returns_some() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Maglev(MaglevOpts { header: None })),
            make_endpoints(),
        );
        assert!(
            strategy.select(Some("/path"), None, &[]).is_some(),
            "Maglev select should return Some with healthy endpoints"
        );
    }

    #[test]
    fn build_strategy_ring_hash() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Parameterised(ParameterisedStrategy::RingHash(RingHashOpts {
                header: Some("X-Session".to_owned()),
                hash_function: HashFunction::Xxhash,
                virtual_nodes: 50,
            })),
            make_endpoints(),
        );
        assert!(
            matches!(strategy, Strategy::RingHash(_)),
            "ParameterisedStrategy::RingHash should produce Strategy::RingHash"
        );
    }

    #[test]
    fn select_ring_hash_returns_some() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Parameterised(ParameterisedStrategy::RingHash(RingHashOpts {
                header: None,
                hash_function: HashFunction::Fnv1a,
                virtual_nodes: 100,
            })),
            make_endpoints(),
        );
        assert!(
            strategy.select(Some("/path"), None, &[]).is_some(),
            "RingHash select should return Some with healthy endpoints"
        );
    }

    #[test]
    fn build_strategy_subset() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Subset(SubsetOpts {
                selector: HashMap::from([("version".to_owned(), "canary".to_owned())]),
                inner_strategy: SimpleStrategy::RoundRobin,
                fallback_policy: SubsetFallbackPolicy::AnyEndpoint,
            })),
            make_endpoints(),
        );
        assert!(
            matches!(strategy, Strategy::Subset(_)),
            "ParameterisedStrategy::Subset should produce Strategy::Subset"
        );
    }

    #[test]
    fn build_strategy_zone_aware() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ZoneAware(ZoneAwareOpts {
                local_zone: "us-east-1a".to_owned(),
                inner_strategy: SimpleStrategy::RoundRobin,
                min_local_healthy_pct: 70,
            })),
            make_endpoints(),
        );
        assert!(
            matches!(strategy, Strategy::ZoneAware(_)),
            "ParameterisedStrategy::ZoneAware should produce Strategy::ZoneAware"
        );
    }

    #[test]
    fn build_strategy_priority() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Priority(PriorityOpts {
                inner_strategy: SimpleStrategy::RoundRobin,
                overprovisioning_factor: 140,
            })),
            make_endpoints(),
        );
        assert!(
            matches!(strategy, Strategy::Priority(_)),
            "ParameterisedStrategy::Priority should produce Strategy::Priority"
        );
    }

    #[test]
    fn release_ring_hash_is_noop() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Parameterised(ParameterisedStrategy::RingHash(RingHashOpts {
                header: None,
                hash_function: HashFunction::Fnv1a,
                virtual_nodes: 100,
            })),
            make_endpoints(),
        );
        strategy.release("10.0.0.1:80");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a two-endpoint list for strategy tests.
    fn make_endpoints() -> Vec<WeightedEndpoint> {
        vec![
            WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 0, 1),
            WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1, 1),
        ]
    }
    /// Upstream's retry engine excludes already-attempted endpoints. The
    /// strategies added here must honour that contract too, or a retry lands
    /// straight back on the endpoint that just failed.
    #[test]
    #[expect(clippy::too_many_lines, reason = "table-driven over four strategy configs")]
    fn new_strategies_skip_excluded_endpoints() {
        use std::collections::HashMap;

        use praxis_core::config::{
            HashFunction, ParameterisedStrategy, PriorityOpts, RingHashOpts, SimpleStrategy, SubsetFallbackPolicy,
            SubsetOpts, ZoneAwareOpts,
        };

        let endpoints = || {
            vec![
                WeightedEndpoint::simple(Arc::from("10.0.0.1:80"), 0, 1),
                WeightedEndpoint::simple(Arc::from("10.0.0.2:80"), 1, 1),
            ]
        };
        let excluded: Vec<Arc<str>> = vec![Arc::from("10.0.0.1:80")];

        let cases: Vec<(&str, ParameterisedStrategy)> = vec![
            (
                "ring_hash",
                ParameterisedStrategy::RingHash(RingHashOpts {
                    hash_function: HashFunction::default(),
                    header: None,
                    virtual_nodes: 100,
                }),
            ),
            (
                "subset",
                ParameterisedStrategy::Subset(SubsetOpts {
                    inner_strategy: SimpleStrategy::default(),
                    selector: HashMap::new(),
                    fallback_policy: SubsetFallbackPolicy::default(),
                }),
            ),
            (
                "zone_aware",
                ParameterisedStrategy::ZoneAware(ZoneAwareOpts {
                    local_zone: "us-east-1a".to_owned(),
                    inner_strategy: SimpleStrategy::default(),
                    min_local_healthy_pct: 70,
                }),
            ),
            (
                "priority",
                ParameterisedStrategy::Priority(PriorityOpts {
                    inner_strategy: SimpleStrategy::default(),
                    overprovisioning_factor: 140,
                }),
            ),
        ];

        for (name, opts) in cases {
            let strategy = build_strategy(&LoadBalancerStrategy::Parameterised(opts), endpoints());
            for _ in 0..8 {
                let picked = strategy
                    .select(Some("/key"), None, &excluded)
                    .unwrap_or_else(|| panic!("{name} should still select an endpoint"));
                assert_eq!(
                    &*picked, "10.0.0.2:80",
                    "{name} must not select an excluded endpoint while an alternative exists"
                );
            }
        }
    }
}
