// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Validation rules for load-balancer strategy parameters.

use crate::{
    config::{Cluster, LoadBalancerStrategy, ParameterisedStrategy},
    errors::ProxyError,
};

/// Hard ceiling on ring-hash entries per cluster (`Σ weight × virtual_nodes`).
///
/// Each entry costs 16 bytes and the ring is rebuilt on every config reload,
/// so an unbounded product of weights (≤1000), `virtual_nodes` (≤10000), and
/// endpoint count could allocate gigabytes.
const MAX_RING_ENTRIES: u64 = 1_048_576; // 1 Mi entries ≈ 16 MiB

/// Validate that parameterised strategy options are within sane bounds.
pub(in crate::config::validate) fn validate_lb_strategy(cluster: &Cluster) -> Result<(), ProxyError> {
    let name = &cluster.name;
    if let LoadBalancerStrategy::Parameterised(param) = &cluster.load_balancer_strategy {
        validate_parameterised(name, param)?;
        if let ParameterisedStrategy::RingHash(opts) = param {
            let entries: u64 = cluster
                .endpoints
                .iter()
                .map(|ep| u64::from(ep.weight()) * u64::from(opts.virtual_nodes))
                .sum();
            if entries > MAX_RING_ENTRIES {
                return Err(ProxyError::Config(format!(
                    "cluster '{name}': ring_hash ring would have {entries} entries \
                     (sum of endpoint weight × virtual_nodes); maximum is {MAX_RING_ENTRIES} — \
                     lower virtual_nodes or endpoint weights",
                )));
            }
        }
    }
    Ok(())
}

/// Check bounds on parameterised strategy options.
#[expect(clippy::too_many_lines, reason = "match arms are individually simple")]
fn validate_parameterised(name: &str, param: &ParameterisedStrategy) -> Result<(), ProxyError> {
    match param {
        ParameterisedStrategy::RingHash(opts) if opts.virtual_nodes == 0 => {
            return Err(ProxyError::Config(format!(
                "cluster '{name}': ring_hash.virtual_nodes must be >= 1"
            )));
        },
        ParameterisedStrategy::RingHash(opts) if opts.virtual_nodes > 10_000 => {
            return Err(ProxyError::Config(format!(
                "cluster '{name}': ring_hash.virtual_nodes must be <= 10000 (got {})",
                opts.virtual_nodes,
            )));
        },
        ParameterisedStrategy::ZoneAware(opts) if opts.min_local_healthy_pct > 100 => {
            return Err(ProxyError::Config(format!(
                "cluster '{name}': zone_aware.min_local_healthy_pct must be <= 100 (got {})",
                opts.min_local_healthy_pct,
            )));
        },
        ParameterisedStrategy::Priority(opts) if opts.overprovisioning_factor < 100 => {
            // Capacity spill checks healthy% >= 100/factor; a factor below 100
            // is unsatisfiable even at full health, so every request would
            // take the panic path.
            return Err(ProxyError::Config(format!(
                "cluster '{name}': priority.overprovisioning_factor must be >= 100 (got {})",
                opts.overprovisioning_factor,
            )));
        },
        ParameterisedStrategy::Subset(opts) if opts.selector.is_empty() => {
            // An empty selector matches every endpoint (vacuous `all()`),
            // silently degrading the subset strategy to its inner strategy
            // over the full endpoint set and making fallback_policy dead
            // config. That is never what a subset strategy is configured for.
            return Err(ProxyError::Config(format!(
                "cluster '{name}': subset.selector must not be empty \
                 (an empty selector matches all endpoints, defeating the subset)"
            )));
        },
        ParameterisedStrategy::ConsistentHash(_)
        | ParameterisedStrategy::Maglev(_)
        | ParameterisedStrategy::RingHash(_)
        | ParameterisedStrategy::Subset(_)
        | ParameterisedStrategy::ZoneAware(_)
        | ParameterisedStrategy::Priority(_) => {},
    }
    Ok(())
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
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::validate_lb_strategy;
    use crate::config::{
        Cluster, HashFunction, LoadBalancerStrategy, ParameterisedStrategy, PriorityOpts, RingHashOpts, SimpleStrategy,
        SubsetFallbackPolicy, SubsetOpts, ZoneAwareOpts,
    };

    #[test]
    fn reject_ring_hash_zero_virtual_nodes() {
        let cluster = cluster_with_strategy(LoadBalancerStrategy::Parameterised(ParameterisedStrategy::RingHash(
            RingHashOpts {
                header: None,
                hash_function: HashFunction::default(),
                virtual_nodes: 0,
            },
        )));
        let err = validate_lb_strategy(&cluster).unwrap_err();
        assert!(err.to_string().contains("virtual_nodes must be >= 1"), "got: {err}");
    }

    #[test]
    fn accept_ring_hash_valid_virtual_nodes() {
        let cluster = cluster_with_strategy(LoadBalancerStrategy::Parameterised(ParameterisedStrategy::RingHash(
            RingHashOpts {
                header: None,
                hash_function: HashFunction::default(),
                virtual_nodes: 100,
            },
        )));
        validate_lb_strategy(&cluster).expect("valid virtual_nodes should pass");
    }

    #[test]
    fn reject_ring_hash_virtual_nodes_above_max() {
        let cluster = cluster_with_strategy(LoadBalancerStrategy::Parameterised(ParameterisedStrategy::RingHash(
            RingHashOpts {
                header: None,
                hash_function: HashFunction::default(),
                virtual_nodes: 10_001,
            },
        )));
        let err = validate_lb_strategy(&cluster).unwrap_err();
        assert!(err.to_string().contains("virtual_nodes must be <= 10000"), "got: {err}");
    }

    #[test]
    fn reject_zone_aware_pct_above_100() {
        let cluster = cluster_with_strategy(LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ZoneAware(
            ZoneAwareOpts {
                local_zone: "us-east-1a".to_owned(),
                inner_strategy: SimpleStrategy::default(),
                min_local_healthy_pct: 101,
            },
        )));
        let err = validate_lb_strategy(&cluster).unwrap_err();
        assert!(
            err.to_string().contains("min_local_healthy_pct must be <= 100"),
            "got: {err}"
        );
    }

    #[test]
    fn accept_zone_aware_pct_at_100() {
        let cluster = cluster_with_strategy(LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ZoneAware(
            ZoneAwareOpts {
                local_zone: "us-east-1a".to_owned(),
                inner_strategy: SimpleStrategy::default(),
                min_local_healthy_pct: 100,
            },
        )));
        validate_lb_strategy(&cluster).expect("pct=100 should pass");
    }

    #[test]
    fn reject_priority_zero_overprovisioning() {
        let cluster = cluster_with_strategy(LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Priority(
            PriorityOpts {
                inner_strategy: SimpleStrategy::default(),
                overprovisioning_factor: 0,
            },
        )));
        let err = validate_lb_strategy(&cluster).unwrap_err();
        assert!(
            err.to_string().contains("overprovisioning_factor must be >= 100"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_priority_sub_100_overprovisioning() {
        // healthy% >= 100/factor is unsatisfiable for factors below 100, so
        // every request would take the panic path.
        let cluster = cluster_with_strategy(LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Priority(
            PriorityOpts {
                inner_strategy: SimpleStrategy::default(),
                overprovisioning_factor: 99,
            },
        )));
        let err = validate_lb_strategy(&cluster).unwrap_err();
        assert!(
            err.to_string().contains("overprovisioning_factor must be >= 100"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_ring_hash_oversized_ring() {
        let mut cluster = cluster_with_strategy(LoadBalancerStrategy::Parameterised(ParameterisedStrategy::RingHash(
            RingHashOpts {
                hash_function: HashFunction::default(),
                header: None,
                virtual_nodes: 10_000,
            },
        )));
        cluster.endpoints = (0..3)
            .map(|i| crate::config::Endpoint::Weighted {
                address: format!("10.0.0.{i}:80"),
                weight: 1_000,
                metadata: std::collections::HashMap::new(),
                priority: 0,
                zone: None,
            })
            .collect();
        let err = validate_lb_strategy(&cluster).unwrap_err();
        assert!(err.to_string().contains("ring_hash ring would have"), "got: {err}");
    }

    #[test]
    fn accept_priority_valid_overprovisioning() {
        let cluster = cluster_with_strategy(LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Priority(
            PriorityOpts {
                inner_strategy: SimpleStrategy::default(),
                overprovisioning_factor: 140,
            },
        )));
        validate_lb_strategy(&cluster).expect("valid overprovisioning should pass");
    }

    #[test]
    fn reject_subset_empty_selector() {
        let cluster = cluster_with_strategy(LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Subset(
            SubsetOpts {
                fallback_policy: SubsetFallbackPolicy::default(),
                inner_strategy: SimpleStrategy::default(),
                selector: std::collections::HashMap::new(),
            },
        )));
        let err = validate_lb_strategy(&cluster).unwrap_err();
        assert!(
            err.to_string().contains("subset.selector must not be empty"),
            "an empty selector matches all endpoints and must be rejected: {err}"
        );
    }

    #[test]
    fn accept_subset_with_selector() {
        let cluster = cluster_with_strategy(LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Subset(
            SubsetOpts {
                fallback_policy: SubsetFallbackPolicy::default(),
                inner_strategy: SimpleStrategy::default(),
                selector: std::collections::HashMap::from([("zone".to_owned(), "a".to_owned())]),
            },
        )));
        validate_lb_strategy(&cluster).expect("a non-empty selector should pass");
    }

    #[test]
    fn simple_strategy_always_valid() {
        let cluster = Cluster::with_defaults("test", vec!["10.0.0.1:80".into()]);
        validate_lb_strategy(&cluster).expect("simple strategies need no validation");
    }

    fn cluster_with_strategy(strategy: LoadBalancerStrategy) -> Cluster {
        let mut cluster = Cluster::with_defaults("test", vec!["10.0.0.1:80".into()]);
        cluster.load_balancer_strategy = strategy;
        cluster
    }
}
