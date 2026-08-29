// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Load-balancing strategy types for upstream clusters.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// LoadBalancerStrategy
// -----------------------------------------------------------------------------

/// Load-balancing algorithm used by a cluster.
///
/// Serializes untagged (a bare string for [`Simple`], a single-key
/// mapping for [`Parameterised`]). Deserialization is a manual dispatch
/// on the YAML shape rather than `#[serde(untagged)]`: an untagged enum
/// discards the inner variant's error, so a typo like
/// `{ring_hash: {virtual_node: 5}}` would report only "data did not match
/// any variant" instead of naming the unknown field. Dispatching by shape
/// lets the inner `deny_unknown_fields` diagnostic propagate.
///
/// [`Simple`]: LoadBalancerStrategy::Simple
/// [`Parameterised`]: LoadBalancerStrategy::Parameterised
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum LoadBalancerStrategy {
    /// Plain-string strategies: `"round_robin"` or `"least_connections"`.
    Simple(SimpleStrategy),

    /// Consistent-hash strategy with an optional hash-key header.
    Parameterised(ParameterisedStrategy),
}

impl<'de> Deserialize<'de> for LoadBalancerStrategy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let value = serde_yaml::Value::deserialize(deserializer)?;
        match value {
            serde_yaml::Value::String(_) => SimpleStrategy::deserialize(value)
                .map(Self::Simple)
                .map_err(D::Error::custom),
            serde_yaml::Value::Mapping(map) => deserialize_single_key_mapping::<D>(map),
            // The untagged `Serialize` impl emits parameterised variants as
            // a YAML tag (`!ring_hash`); accept that form so a value can
            // round-trip through serialization (config dumps, diffs).
            serde_yaml::Value::Tagged(tagged) => {
                let key = tagged.tag.to_string();
                let key = key.strip_prefix('!').unwrap_or(&key);
                dispatch_parameterised::<D>(key, tagged.value).map(Self::Parameterised)
            },
            serde_yaml::Value::Null
            | serde_yaml::Value::Bool(_)
            | serde_yaml::Value::Number(_)
            | serde_yaml::Value::Sequence(_) => Err(D::Error::custom(
                "load_balancer_strategy must be a strategy name (e.g. round_robin) \
                 or a single-key mapping (e.g. {ring_hash: {...}})",
            )),
        }
    }
}

/// Deserialize the `{strategy_name: opts}` single-key mapping form.
fn deserialize_single_key_mapping<'de, D>(map: serde_yaml::Mapping) -> Result<LoadBalancerStrategy, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;

    let mut entries = map.into_iter();
    let (key, opts) = entries
        .next()
        .ok_or_else(|| D::Error::custom("load_balancer_strategy mapping must name exactly one strategy"))?;
    if entries.next().is_some() {
        return Err(D::Error::custom(
            "load_balancer_strategy mapping must name exactly one strategy",
        ));
    }
    let key = key
        .as_str()
        .ok_or_else(|| D::Error::custom("load_balancer_strategy key must be a string"))?;
    // A simple (parameterless) strategy may also appear in the
    // single-key map form (`least_connections: ~`); accept it
    // when the value is null, matching the previous behavior.
    if let Ok(simple) = serde_yaml::from_str::<SimpleStrategy>(key) {
        if opts.is_null() {
            return Ok(LoadBalancerStrategy::Simple(simple));
        }
        return Err(D::Error::custom(format!(
            "load_balancer_strategy '{key}' takes no options"
        )));
    }
    dispatch_parameterised::<D>(key, opts).map(LoadBalancerStrategy::Parameterised)
}

/// Deserialize a parameterised strategy's options by strategy key.
///
/// Dispatching by hand (rather than re-deserializing the externally-tagged
/// [`ParameterisedStrategy`] from a `Value`, which `serde_yaml` cannot do)
/// preserves each opts struct's `deny_unknown_fields` diagnostics.
fn dispatch_parameterised<'de, D>(key: &str, opts: serde_yaml::Value) -> Result<ParameterisedStrategy, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;

    let param = match key {
        "consistent_hash" => ConsistentHashOpts::deserialize(opts).map(ParameterisedStrategy::ConsistentHash),
        "maglev" => MaglevOpts::deserialize(opts).map(ParameterisedStrategy::Maglev),
        "ring_hash" => RingHashOpts::deserialize(opts).map(ParameterisedStrategy::RingHash),
        "subset" => SubsetOpts::deserialize(opts).map(ParameterisedStrategy::Subset),
        "zone_aware" => ZoneAwareOpts::deserialize(opts).map(ParameterisedStrategy::ZoneAware),
        "priority" => PriorityOpts::deserialize(opts).map(ParameterisedStrategy::Priority),
        other => {
            return Err(D::Error::custom(format!(
                "unknown load_balancer_strategy '{other}' (expected one of: consistent_hash, \
                 maglev, ring_hash, subset, zone_aware, priority)"
            )));
        },
    };
    param.map_err(D::Error::custom)
}

impl Default for LoadBalancerStrategy {
    fn default() -> Self {
        Self::Simple(SimpleStrategy::RoundRobin)
    }
}

/// String-serialisable load-balancing strategies.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SimpleStrategy {
    /// Cycle through endpoints in order, respecting weights.
    #[default]
    RoundRobin,

    /// Pick the endpoint with the fewest active in-flight requests.
    LeastConnections,

    /// Sample two random endpoints; pick the less loaded one.
    #[serde(rename = "p2c")]
    PowerOfTwoChoices,

    /// Uniform random endpoint selection, weighted by endpoint weight.
    Random,
}

/// Load-balancing strategies that carry parameters.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ParameterisedStrategy {
    /// Hash a request attribute to route requests to a stable endpoint.
    #[serde(rename = "consistent_hash")]
    ConsistentHash(ConsistentHashOpts),

    /// Maglev consistent hashing: even distribution with minimal disruption
    /// when endpoints are added or removed.
    #[serde(rename = "maglev")]
    Maglev(MaglevOpts),

    /// Ring-hash with configurable hash function, virtual node count, and ring size.
    #[serde(rename = "ring_hash")]
    RingHash(RingHashOpts),

    /// Subset-based load balancing: filter endpoints by metadata labels, then
    /// apply an inner strategy within the matching subset.
    #[serde(rename = "subset")]
    Subset(SubsetOpts),

    /// Zone-aware routing: prefer same-zone endpoints, spilling to remote zones
    /// when local healthy capacity drops below a threshold.
    #[serde(rename = "zone_aware")]
    ZoneAware(ZoneAwareOpts),

    /// Priority-level tiering: use primary endpoints exclusively until capacity
    /// is insufficient, then spill to failover tiers.
    #[serde(rename = "priority")]
    Priority(PriorityOpts),
}

/// Options for the `consistent_hash` load-balancing strategy.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConsistentHashOpts {
    /// Name of the request header to use as the hash key.
    ///
    /// Falls back to the request URI path when the header is absent or when this field is `None`.
    #[serde(default)]
    pub header: Option<String>,
}

/// Options for the `maglev` load-balancing strategy.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaglevOpts {
    /// Name of the request header to use as the hash key.
    ///
    /// Falls back to the request URI path when the header is absent or when this field is `None`.
    #[serde(default)]
    pub header: Option<String>,
}

// -----------------------------------------------------------------------------
// RingHash
// -----------------------------------------------------------------------------

/// Options for the `ring_hash` load-balancing strategy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RingHashOpts {
    /// Hash function to use for the ring. Defaults to FNV-1a.
    #[serde(default)]
    pub hash_function: HashFunction,

    /// Name of the request header to use as the hash key.
    #[serde(default)]
    pub header: Option<String>,

    /// Number of virtual nodes per unit of endpoint weight. Defaults to 100.
    #[serde(default = "default_virtual_nodes")]
    pub virtual_nodes: u32,
}

/// Hash function choices for ring-hash and related strategies.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HashFunction {
    /// Fowler-Noll-Vo 1a (64-bit). Fast and deterministic.
    #[default]
    Fnv1a,

    /// xxHash 64-bit. Very fast with excellent distribution.
    Xxhash,

    /// `MurmurHash3` (128-bit, lower 64 bits). Good distribution.
    Murmur3,
}

/// Serde default for [`RingHashOpts::virtual_nodes`].
fn default_virtual_nodes() -> u32 {
    100
}

// -----------------------------------------------------------------------------
// Subset
// -----------------------------------------------------------------------------

/// Options for the `subset` load-balancing strategy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubsetOpts {
    /// Behavior when no endpoints match the selector.
    #[serde(default)]
    pub fallback_policy: SubsetFallbackPolicy,

    /// Strategy to apply within the matching subset. Defaults to round-robin.
    #[serde(default)]
    pub inner_strategy: SimpleStrategy,

    /// Metadata key-value pairs that endpoints must match to be included
    /// in the active subset.
    pub selector: HashMap<String, String>,
}

/// What to do when no endpoints match the subset selector.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsetFallbackPolicy {
    /// Use all endpoints regardless of metadata.
    #[default]
    AnyEndpoint,

    /// Return no endpoint (request fails with 503).
    NoEndpoint,
}

// -----------------------------------------------------------------------------
// ZoneAware
// -----------------------------------------------------------------------------

/// Options for the `zone_aware` load-balancing strategy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneAwareOpts {
    /// Strategy to apply within the selected zone group. Defaults to round-robin.
    #[serde(default)]
    pub inner_strategy: SimpleStrategy,

    /// The zone of the proxy itself. Endpoints in this zone are preferred.
    pub local_zone: String,

    /// Minimum percentage of healthy endpoints in the local zone before
    /// traffic spills to remote zones. Defaults to 70.
    #[serde(default = "default_min_local_healthy_pct")]
    pub min_local_healthy_pct: u8,
}

/// Serde default for [`ZoneAwareOpts::min_local_healthy_pct`].
fn default_min_local_healthy_pct() -> u8 {
    70
}

// -----------------------------------------------------------------------------
// Priority
// -----------------------------------------------------------------------------

/// Options for the `priority` load-balancing strategy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorityOpts {
    /// Strategy to apply within each priority tier. Defaults to round-robin.
    #[serde(default)]
    pub inner_strategy: SimpleStrategy,

    /// Overprovisioning factor as a percentage (e.g. 140 = 140%).
    /// Traffic shifts to the next tier when the current tier's healthy
    /// capacity falls below `100 / overprovisioning_factor` of its total.
    /// Defaults to 140.
    #[serde(default = "default_overprovisioning_factor")]
    pub overprovisioning_factor: u32,
}

/// Serde default for [`PriorityOpts::overprovisioning_factor`].
fn default_overprovisioning_factor() -> u32 {
    140
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
    fn load_balancer_strategy_rejects_sequence_value() {
        let err = serde_yaml::from_str::<LoadBalancerStrategy>("[round_robin]").unwrap_err();
        assert!(
            err.to_string().contains("must be a strategy name"),
            "a sequence value must be rejected with the expected-shape message: {err}"
        );
    }

    #[test]
    fn load_balancer_strategy_rejects_multi_key_mapping() {
        let yaml = "consistent_hash:\n  header: \"X-User-Id\"\nring_hash: {}\n";
        let err = serde_yaml::from_str::<LoadBalancerStrategy>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("exactly one strategy"),
            "a mapping naming two strategies must be rejected: {err}"
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
    fn load_balancer_strategy_parses_p2c() {
        let yaml = "p2c";
        let strategy: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            strategy,
            LoadBalancerStrategy::Simple(SimpleStrategy::PowerOfTwoChoices),
            "should parse 'p2c' string"
        );
    }

    #[test]
    fn load_balancer_strategy_parses_random() {
        let yaml = "random";
        let strategy: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            strategy,
            LoadBalancerStrategy::Simple(SimpleStrategy::Random),
            "should parse 'random' string"
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

    #[test]
    fn load_balancer_strategy_parses_maglev() {
        let yaml = r#"
maglev:
  header: "X-User-Id"
"#;
        let strategy: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            strategy,
            LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Maglev(MaglevOpts {
                header: Some("X-User-Id".into()),
            })),
            "should parse maglev with header"
        );
    }

    #[test]
    fn maglev_without_header() {
        let yaml = "maglev: {}";
        let strategy: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            strategy,
            LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Maglev(MaglevOpts { header: None })),
            "should parse maglev with no header"
        );
    }

    #[test]
    fn load_balancer_strategy_parses_ring_hash() {
        let yaml = r#"
ring_hash:
  header: "X-Session-Id"
  hash_function: xxhash
  virtual_nodes: 200
"#;
        let strategy: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            strategy,
            LoadBalancerStrategy::Parameterised(ParameterisedStrategy::RingHash(RingHashOpts {
                header: Some("X-Session-Id".into()),
                hash_function: HashFunction::Xxhash,
                virtual_nodes: 200,
            })),
            "should parse ring_hash with all options"
        );
    }

    #[test]
    fn ring_hash_defaults() {
        let yaml = "ring_hash: {}";
        let strategy: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            strategy,
            LoadBalancerStrategy::Parameterised(ParameterisedStrategy::RingHash(RingHashOpts {
                header: None,
                hash_function: HashFunction::Fnv1a,
                virtual_nodes: 100,
            })),
            "should parse ring_hash with defaults"
        );
    }

    #[test]
    fn load_balancer_strategy_parses_subset() {
        let yaml = r#"
subset:
  selector:
    version: "canary"
  inner_strategy: least_connections
  fallback_policy: no_endpoint
"#;
        let strategy: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            strategy,
            LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Subset(SubsetOpts {
                selector: HashMap::from([("version".to_owned(), "canary".to_owned())]),
                inner_strategy: SimpleStrategy::LeastConnections,
                fallback_policy: SubsetFallbackPolicy::NoEndpoint,
            })),
            "should parse subset with all options"
        );
    }

    #[test]
    fn subset_defaults() {
        let yaml = r#"
subset:
  selector:
    region: "eu"
"#;
        let strategy: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            strategy,
            LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Subset(SubsetOpts {
                selector: HashMap::from([("region".to_owned(), "eu".to_owned())]),
                inner_strategy: SimpleStrategy::RoundRobin,
                fallback_policy: SubsetFallbackPolicy::AnyEndpoint,
            })),
            "should parse subset with defaults for inner_strategy and fallback_policy"
        );
    }

    #[test]
    fn load_balancer_strategy_parses_zone_aware() {
        let yaml = r#"
zone_aware:
  local_zone: "us-east-1a"
  inner_strategy: random
  min_local_healthy_pct: 50
"#;
        let strategy: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            strategy,
            LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ZoneAware(ZoneAwareOpts {
                local_zone: "us-east-1a".to_owned(),
                inner_strategy: SimpleStrategy::Random,
                min_local_healthy_pct: 50,
            })),
            "should parse zone_aware with all options"
        );
    }

    #[test]
    fn zone_aware_defaults() {
        let yaml = r#"
zone_aware:
  local_zone: "eu-west-1b"
"#;
        let strategy: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            strategy,
            LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ZoneAware(ZoneAwareOpts {
                local_zone: "eu-west-1b".to_owned(),
                inner_strategy: SimpleStrategy::RoundRobin,
                min_local_healthy_pct: 70,
            })),
            "should parse zone_aware with defaults"
        );
    }

    #[test]
    fn load_balancer_strategy_parses_priority() {
        let yaml = r#"
priority:
  inner_strategy: p2c
  overprovisioning_factor: 200
"#;
        let strategy: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            strategy,
            LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Priority(PriorityOpts {
                inner_strategy: SimpleStrategy::PowerOfTwoChoices,
                overprovisioning_factor: 200,
            })),
            "should parse priority with all options"
        );
    }

    #[test]
    fn priority_defaults() {
        let yaml = "priority: {}";
        let strategy: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            strategy,
            LoadBalancerStrategy::Parameterised(ParameterisedStrategy::Priority(PriorityOpts {
                inner_strategy: SimpleStrategy::RoundRobin,
                overprovisioning_factor: 140,
            })),
            "should parse priority with defaults"
        );
    }

    #[test]
    fn unknown_strategy_option_names_the_bad_key() {
        // A typo'd option key must be rejected by name, not swallowed by
        // the untagged wrapper into a generic "did not match any variant".
        let yaml = "ring_hash:\n  virtual_node: 5\n";
        let err = serde_yaml::from_str::<LoadBalancerStrategy>(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("virtual_node"),
            "the diagnostic must name the unknown field: {msg}"
        );
        assert!(
            !msg.contains("did not match any variant"),
            "the untagged fallback message must not leak through: {msg}"
        );
    }

    #[test]
    fn unknown_strategy_name_is_rejected() {
        let err = serde_yaml::from_str::<LoadBalancerStrategy>("no_such_strategy: {}\n").unwrap_err();
        assert!(err.to_string().contains("unknown variant") || err.to_string().contains("no_such_strategy"));
    }

    #[test]
    fn simple_string_strategy_still_parses() {
        let strategy: LoadBalancerStrategy = serde_yaml::from_str("least_connections\n").unwrap();
        assert_eq!(strategy, LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections));
    }

    #[test]
    fn simple_strategy_in_map_form_still_parses() {
        // The single-key null-map form (as used by example configs) stays valid.
        let strategy: LoadBalancerStrategy = serde_yaml::from_str("least_connections: ~\n").unwrap();
        assert_eq!(strategy, LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections));
    }

    #[test]
    fn simple_strategy_map_form_rejects_options() {
        let err = serde_yaml::from_str::<LoadBalancerStrategy>("least_connections:\n  foo: bar\n").unwrap_err();
        assert!(err.to_string().contains("takes no options"), "got: {err}");
    }

    #[test]
    fn strategy_round_trips_through_serialize() {
        for yaml in ["round_robin\n", "p2c\n", "consistent_hash:\n  header: x-key\n"] {
            let parsed: LoadBalancerStrategy = serde_yaml::from_str(yaml).unwrap();
            let reserialized = serde_yaml::to_string(&parsed).unwrap();
            let reparsed: LoadBalancerStrategy = serde_yaml::from_str(&reserialized).unwrap();
            assert_eq!(parsed, reparsed, "round-trip mismatch for {yaml:?}");
        }
    }
}
