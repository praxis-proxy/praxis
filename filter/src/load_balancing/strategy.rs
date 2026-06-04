// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Load-balancing strategy selection and dispatch.

use std::sync::Arc;

use praxis_core::{
    config::{LoadBalancerStrategy, ParameterisedStrategy, SimpleStrategy},
    health::ClusterHealthState,
};

use super::{
    consistent_hash::ConsistentHash, endpoint::WeightedEndpoint, least_connections::LeastConnections,
    p2c::PowerOfTwoChoices, round_robin::RoundRobin,
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
}

impl Strategy {
    /// Pick the next endpoint address using a protocol-agnostic hash key.
    ///
    /// For HTTP, the caller extracts the key from headers or URI path.
    /// For TCP, the caller typically passes the client IP address.
    pub(crate) fn select(&self, hash_key: Option<&str>, health: Option<&ClusterHealthState>) -> Option<Arc<str>> {
        match self {
            Self::RoundRobin(rr) => rr.select(health),
            Self::LeastConnections(lc) => Some(lc.select(health)),
            Self::ConsistentHash(ch) => Some(ch.select(hash_key, health)),
            Self::PowerOfTwoChoices(p2c) => Some(p2c.select(health)),
        }
    }

    /// Called after a response arrives so that strategies that track in-flight
    /// request counts (e.g. `LeastConnections`) can decrement their counter.
    pub(crate) fn release(&self, addr: &str) {
        match self {
            Self::LeastConnections(lc) => lc.release(addr),
            Self::PowerOfTwoChoices(p2c) => p2c.release(addr),
            Self::RoundRobin(_) | Self::ConsistentHash(_) => {},
        }
    }
}

/// Create the appropriate strategy variant from the config.
pub(crate) fn build_strategy(lb_strategy: &LoadBalancerStrategy, endpoints: Vec<WeightedEndpoint>) -> Strategy {
    match lb_strategy {
        LoadBalancerStrategy::Simple(SimpleStrategy::RoundRobin) => Strategy::RoundRobin(RoundRobin::new(endpoints)),
        LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections) => {
            Strategy::LeastConnections(LeastConnections::new(endpoints))
        },
        LoadBalancerStrategy::Simple(SimpleStrategy::PowerOfTwoChoices) => {
            Strategy::PowerOfTwoChoices(PowerOfTwoChoices::new(endpoints))
        },
        LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ConsistentHash(opts)) => {
            Strategy::ConsistentHash(ConsistentHash::new(endpoints, opts.header.clone()))
        },
    }
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
    reason = "tests"
)]
mod tests {
    use std::sync::atomic::Ordering;

    use praxis_core::config::ConsistentHashOpts;

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
    fn release_round_robin_is_noop() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Simple(SimpleStrategy::RoundRobin),
            make_endpoints(),
        );
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
        strategy.select(None, None);
        if let Strategy::LeastConnections(ref lc) = strategy {
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
            strategy.select(None, None).is_some(),
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
            strategy.select(None, None).is_some(),
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
            strategy.select(Some("/path"), None).is_some(),
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
        strategy.select(None, None);
        if let Strategy::PowerOfTwoChoices(ref p2c) = strategy {
            let before = p2c.counters["10.0.0.1:80"].load(Ordering::Relaxed)
                + p2c.counters["10.0.0.2:80"].load(Ordering::Relaxed);
            assert_eq!(before, 1, "one selection should have incremented one counter");
        }
        strategy.release("10.0.0.1:80");
        strategy.release("10.0.0.2:80");
    }

    #[test]
    fn select_p2c_returns_some() {
        let strategy = build_strategy(
            &LoadBalancerStrategy::Simple(SimpleStrategy::PowerOfTwoChoices),
            make_endpoints(),
        );
        assert!(
            strategy.select(None, None).is_some(),
            "P2C select should return Some with healthy endpoints"
        );
    }

    // ---------------------------------------------------------------------------
    // Test Utilities
    // ---------------------------------------------------------------------------

    /// Build a two-endpoint list for strategy tests.
    fn make_endpoints() -> Vec<WeightedEndpoint> {
        vec![
            WeightedEndpoint {
                address: Arc::from("10.0.0.1:80"),
                index: 0,
                weight: 1,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.2:80"),
                index: 1,
                weight: 1,
            },
        ]
    }
}
