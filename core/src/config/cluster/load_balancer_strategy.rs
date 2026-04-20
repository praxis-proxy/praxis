// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Load-balancing strategy types for upstream clusters.

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// LoadBalancerStrategy
// -----------------------------------------------------------------------------

/// Load-balancing algorithm used by a cluster.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum LoadBalancerStrategy {
    /// Plain-string strategies: `"round_robin"` or `"least_connections"`.
    Simple(SimpleStrategy),

    /// Consistent-hash strategy with an optional hash-key header.
    Parameterised(ParameterisedStrategy),
}

impl Default for LoadBalancerStrategy {
    fn default() -> Self {
        Self::Simple(SimpleStrategy::RoundRobin)
    }
}

/// String-serialisable load-balancing strategies.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SimpleStrategy {
    /// Cycle through endpoints in order, respecting weights.
    #[default]
    RoundRobin,

    /// Pick the endpoint with the fewest active in-flight requests.
    LeastConnections,
}

/// Load-balancing strategies that carry parameters.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
pub enum ParameterisedStrategy {
    /// Hash a request attribute to route requests to a stable endpoint.
    #[serde(rename = "consistent_hash")]
    ConsistentHash(ConsistentHashOpts),
}

/// Options for the `consistent_hash` load-balancing strategy.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConsistentHashOpts {
    /// Name of the request header to use as the hash key.
    ///
    /// Falls back to the request URI path when the header is absent or when this field is `None`.
    #[serde(default)]
    pub header: Option<String>,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn load_balancer_strategy_defaults_to_round_robin() {
        assert_eq!(
            LoadBalancerStrategy::default(),
            LoadBalancerStrategy::Simple(SimpleStrategy::RoundRobin),
            "default strategy should be round_robin"
        );
    }

    #[test]
    fn load_balancer_strategy_parses_round_robin() {
        let yaml = "round_robin";
        let strategy: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            strategy,
            LoadBalancerStrategy::Simple(SimpleStrategy::RoundRobin),
            "should parse 'round_robin' string"
        );
    }

    #[test]
    fn load_balancer_strategy_parses_least_connections() {
        let yaml = "least_connections";
        let strategy: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            strategy,
            LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections),
            "should parse 'least_connections' string"
        );
    }

    #[test]
    fn load_balancer_strategy_parses_consistent_hash() {
        let yaml = r#"
consistent_hash:
  header: "X-User-Id"
"#;
        let strategy: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            strategy,
            LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ConsistentHash(ConsistentHashOpts {
                header: Some("X-User-Id".into()),
            })),
            "should parse consistent_hash with header"
        );
    }

    #[test]
    fn consistent_hash_without_header() {
        let yaml = "consistent_hash: {}";
        let strategy: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            strategy,
            LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ConsistentHash(ConsistentHashOpts {
                header: None,
            })),
            "should parse consistent_hash with no header"
        );
    }
}
