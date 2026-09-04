// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Filter configuration types: named chains and individual filter entries.
//!
//! Listeners reference chains by name, enabling per-listener pipelines.

use serde::{Deserialize, de::DeserializeOwned};
use tracing::warn;

use super::{Condition, ResponseCondition};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Fields handled by `FilterEntry`'s serde derives.
const KNOWN_FILTER_FIELDS: &[&str] = &[
    "filter",
    "branch_chains",
    "conditions",
    "failure_mode",
    "name",
    "response_conditions",
];

// -----------------------------------------------------------------------------
// FailureMode
// -----------------------------------------------------------------------------

/// Per-filter failure behaviour.
///
/// Controls what happens when a filter returns an error during execution.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FailureMode {
    /// The request is aborted on filter error (default, current behaviour).
    #[default]
    Closed,

    /// The filter error is logged and the request continues to the next filter.
    Open,
}

// -----------------------------------------------------------------------------
// FilterChainConfig
// -----------------------------------------------------------------------------

/// A named, reusable filter chain.
///
/// ```
/// use praxis_core::config::FilterChainConfig;
///
/// let chain: FilterChainConfig = serde_yaml::from_str(
///     r#"
/// name: observability
/// filters:
///   - filter: request_id
///   - filter: access_log
/// "#,
/// )
/// .unwrap();
/// assert_eq!(chain.name, "observability");
/// assert_eq!(chain.filters.len(), 2);
/// ```
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilterChainConfig {
    /// Unique name for this filter chain.
    pub name: String,

    /// Ordered list of filters in this chain.
    #[serde(default)]
    pub filters: Vec<FilterEntry>,
}

// -----------------------------------------------------------------------------
// FilterEntry
// -----------------------------------------------------------------------------

/// Remove an optional typed field from a YAML mapping.
fn take_optional<T: DeserializeOwned>(map: &mut serde_yaml::Mapping, key: &str) -> Result<Option<T>, String> {
    let Some(value) = map.remove(serde_yaml::Value::from(key)) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    serde_yaml::from_value(value).map(Some).map_err(|e| e.to_string())
}

/// Split pipeline `conditions` from `access_log` emit-time `conditions`.
fn split_filter_conditions(
    filter_type: &str,
    conditions_val: Option<serde_yaml::Value>,
) -> Result<(Vec<Condition>, Option<serde_yaml::Value>), String> {
    match conditions_val {
        None => Ok((Vec::new(), None)),
        Some(v) if v.is_sequence() => Ok((serde_yaml::from_value(v).map_err(|e| e.to_string())?, None)),
        Some(v) if filter_type == "access_log" && v.is_mapping() => Ok((Vec::new(), Some(v))),
        Some(_) => Err("conditions must be a sequence of pipeline predicates; \
             access_log emit conditions use a mapping with min_duration_ms, \
             status_classes, and/or paths"
            .to_owned()),
    }
}

/// Deserialize a [`FilterEntry`], routing `access_log` emit-time `conditions`
/// mappings into filter config instead of pipeline request conditions.
#[expect(clippy::too_many_lines, reason = "serde field extraction is linear")]
fn deserialize_filter_entry<'de, D>(deserializer: D) -> Result<FilterEntry, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;

    let mut map = serde_yaml::Value::deserialize(deserializer)?
        .as_mapping()
        .ok_or_else(|| D::Error::custom("filter entry must be a mapping"))?
        .clone();

    let filter_type = match map.remove(serde_yaml::Value::from("filter")) {
        None => return Err(D::Error::missing_field("filter")),
        Some(v) => v
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| D::Error::custom("filter must be a string naming the filter type"))?,
    };

    let branch_chains = take_optional(&mut map, "branch_chains").map_err(D::Error::custom)?;
    let name = take_optional(&mut map, "name").map_err(D::Error::custom)?;
    let failure_mode = take_optional(&mut map, "failure_mode")
        .map_err(D::Error::custom)?
        .unwrap_or_default();
    let response_conditions = take_optional(&mut map, "response_conditions")
        .map_err(D::Error::custom)?
        .unwrap_or_default();

    let conditions_val = map.remove(serde_yaml::Value::from("conditions"));
    let (conditions, access_log_conditions) =
        split_filter_conditions(&filter_type, conditions_val).map_err(D::Error::custom)?;

    if let Some(c) = access_log_conditions {
        map.insert(serde_yaml::Value::from("conditions"), c);
    }

    Ok(FilterEntry {
        filter_type,
        branch_chains,
        conditions,
        name,
        response_conditions,
        failure_mode,
        config: serde_yaml::Value::Mapping(map),
    })
}

/// A single filter in the pipeline.
///
/// ```
/// use praxis_core::config::FilterEntry;
///
/// let entry: FilterEntry = serde_yaml::from_str(
///     r#"
/// filter: router
/// routes:
///   - path_prefix: "/"
///     cluster: web
/// "#,
/// )
/// .unwrap();
/// assert_eq!(entry.filter_type, "router");
/// assert!(entry.conditions.is_empty());
/// assert!(entry.name.is_none());
/// ```
#[derive(Clone, Debug, serde::Serialize)]
pub struct FilterEntry {
    /// Filter type name (e.g. `"router"`, `"load_balancer"`, or a custom name).
    #[serde(rename = "filter")]
    pub filter_type: String,

    /// Optional branch chains evaluated after this filter
    /// based on filter result conditions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_chains: Option<Vec<super::BranchChainConfig>>,

    /// Ordered conditions that gate whether this filter runs on requests.
    /// Empty means the filter always runs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    /// Optional user-assigned name for this filter entry.
    /// Used as a rejoin target by branch chains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Ordered conditions that gate whether this filter runs on responses.
    /// Evaluated against the upstream response (status, headers).
    /// Empty means the filter always runs on responses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_conditions: Vec<ResponseCondition>,

    /// Per-filter failure behaviour (`open` or `closed`).
    #[serde(default)]
    pub failure_mode: FailureMode,

    /// Filter-specific configuration passed to the factory function.
    ///
    /// Populated on deserialize by the hand-written [`Deserialize`] impl
    /// below, which collects every YAML key not handled by the named fields
    /// above (`filter`, `branch_chains`, `conditions`, `name`,
    /// `response_conditions`, `failure_mode`). `#[serde(flatten)]` is retained
    /// only so serialization round-trips those keys back out. A misspelled
    /// known field (e.g., `failuremode`) is silently absorbed here;
    /// [`warn_config_typos`] detects near-matches.
    ///
    /// [`warn_config_typos`]: FilterEntry::warn_config_typos
    #[serde(flatten)]
    pub config: serde_yaml::Value,
}

impl<'de> Deserialize<'de> for FilterEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_filter_entry(deserializer)
    }
}

// -----------------------------------------------------------------------------
// FilterEntry Typo Detection
// -----------------------------------------------------------------------------

impl FilterEntry {
    /// Warn if `config` contains keys that look like typos of known fields.
    ///
    /// Because `FilterEntry` uses `#[serde(flatten)]`, a misspelled
    /// known field (e.g. `failuremode` instead of `failure_mode`) is
    /// silently absorbed into the catch-all `config: Value`. This
    /// method detects near-matches and emits a warning.
    pub fn warn_config_typos(&self) {
        let Some(map) = self.config.as_mapping() else {
            return;
        };
        for key in map.keys() {
            let Some(key_str) = key.as_str() else {
                continue;
            };
            for known in KNOWN_FILTER_FIELDS {
                if edit_distance(key_str, known) <= 2 {
                    warn!(
                        filter = %self.filter_type,
                        key = key_str,
                        suggestion = *known,
                        "filter config key resembles a known field; possible typo"
                    );
                }
            }
        }
    }
}

/// Levenshtein edit distance between two ASCII strings.
#[expect(clippy::indexing_slicing, reason = "indices are bounded by input lengths")]
fn edit_distance(a: &str, b: &str) -> usize {
    let b_bytes = b.as_bytes();
    let mut prev: Vec<usize> = (0..=b_bytes.len()).collect();
    let mut curr = vec![0; b_bytes.len() + 1];
    for (i, ca) in a.bytes().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b_bytes.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(curr[j] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b_bytes.len()]
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
    fn edit_distance_identical() {
        assert_eq!(edit_distance("abc", "abc"), 0, "identical strings");
    }

    #[test]
    fn edit_distance_one_char() {
        assert_eq!(edit_distance("abc", "abd"), 1, "one substitution");
        assert_eq!(edit_distance("abc", "ab"), 1, "one deletion");
        assert_eq!(edit_distance("ab", "abc"), 1, "one insertion");
    }

    #[test]
    fn edit_distance_typo_detection() {
        assert!(
            edit_distance("failuremode", "failure_mode") <= 2,
            "common typo should be within threshold"
        );
        assert!(
            edit_distance("routes", "failure_mode") > 2,
            "unrelated key should exceed threshold"
        );
    }

    #[test]
    fn parse_filter_chain() {
        let yaml = r#"
name: observability
filters:
  - filter: request_id
  - filter: access_log
"#;
        let chain: FilterChainConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(chain.name, "observability", "chain name mismatch");
        assert_eq!(chain.filters.len(), 2, "should have 2 filters");
        assert_eq!(chain.filters[0].filter_type, "request_id", "first filter mismatch");
        assert_eq!(chain.filters[1].filter_type, "access_log", "second filter mismatch");
    }

    #[test]
    fn parse_chain_with_conditions() {
        let yaml = r#"
name: guarded
filters:
  - filter: headers
    conditions:
      - when:
          path_prefix: "/api"
    response_conditions:
      - when:
          status: [200]
    request_add:
      - name: "X-Api"
        value: "true"
"#;
        let chain: FilterChainConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(chain.name, "guarded", "chain name mismatch");
        assert_eq!(chain.filters.len(), 1, "should have 1 filter");
        assert_eq!(chain.filters[0].conditions.len(), 1, "should have 1 request condition");
        assert_eq!(
            chain.filters[0].response_conditions.len(),
            1,
            "should have 1 response condition"
        );
    }

    #[test]
    fn parse_empty_chain() {
        let yaml = "name: empty\n";
        let chain: FilterChainConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(chain.name, "empty", "chain name mismatch");
        assert!(chain.filters.is_empty(), "empty chain should have no filters");
    }

    #[test]
    fn parse_filter_entry() {
        let yaml = r#"
filter: router
routes:
  - path_prefix: "/"
    cluster: "web"
"#;
        let entry: FilterEntry = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(entry.filter_type, "router", "filter_type mismatch");
        assert!(entry.config.get("routes").is_some(), "routes config should be present");
    }

    #[test]
    fn parse_filter_entry_custom_filter() {
        let yaml = r#"
filter: rate_limiter
requests_per_second: 100
"#;
        let entry: FilterEntry = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(entry.filter_type, "rate_limiter", "filter_type mismatch");
        let rps = entry.config.get("requests_per_second").unwrap();
        assert_eq!(rps.as_u64(), Some(100), "requests_per_second should be 100");
    }

    #[test]
    fn parse_filter_entry_with_conditions() {
        let yaml = r#"
filter: headers
conditions:
  - when:
      path_prefix: "/api"
  - unless:
      methods: ["OPTIONS"]
request_add:
  - ["X-Api-Version", "v2"]
"#;
        let entry: FilterEntry = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(entry.filter_type, "headers", "filter_type mismatch");
        assert_eq!(entry.conditions.len(), 2, "should have 2 conditions");
    }

    #[test]
    fn parse_filter_entry_without_conditions() {
        let yaml = r#"
filter: router
routes: []
"#;
        let entry: FilterEntry = serde_yaml::from_str(yaml).unwrap();
        assert!(entry.conditions.is_empty(), "conditions should be empty when omitted");
        assert!(
            entry.response_conditions.is_empty(),
            "response_conditions should be empty when omitted"
        );
    }

    #[test]
    fn parse_failure_mode_defaults_to_closed() {
        let yaml = "filter: router\nroutes: []\n";
        let entry: FilterEntry = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(entry.failure_mode, FailureMode::Closed, "default should be Closed");
    }

    #[test]
    fn parse_failure_mode_open() {
        let yaml = "filter: access_log\nfailure_mode: open\n";
        let entry: FilterEntry = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(entry.failure_mode, FailureMode::Open, "should parse 'open'");
    }

    #[test]
    fn parse_failure_mode_closed_explicit() {
        let yaml = "filter: ext_auth\nfailure_mode: closed\n";
        let entry: FilterEntry = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(entry.failure_mode, FailureMode::Closed, "should parse 'closed'");
    }

    #[test]
    fn parse_chain_with_failure_modes() {
        let yaml = r#"
name: mixed
filters:
  - filter: access_log
    failure_mode: open
  - filter: ext_auth
    failure_mode: closed
  - filter: router
    routes: []
"#;
        let chain: FilterChainConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(chain.filters[0].failure_mode, FailureMode::Open);
        assert_eq!(chain.filters[1].failure_mode, FailureMode::Closed);
        assert_eq!(chain.filters[2].failure_mode, FailureMode::Closed);
    }

    #[test]
    fn parse_filter_entry_with_response_conditions() {
        let yaml = r#"
filter: headers
response_conditions:
  - when:
      status: [200, 201]
  - unless:
      headers:
        x-skip: "true"
response_add:
  - name: X-Processed
    value: "true"
"#;
        let entry: FilterEntry = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(entry.filter_type, "headers", "filter_type mismatch");
        assert!(entry.conditions.is_empty(), "request conditions should be empty");
        assert_eq!(entry.response_conditions.len(), 2, "should have 2 response conditions");
    }

    #[test]
    fn parse_filter_entry_with_name() {
        let yaml = r#"
filter: router
name: routing
routes: []
"#;
        let entry: FilterEntry = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(entry.name.as_deref(), Some("routing"), "name should be 'routing'");
    }

    #[test]
    fn parse_filter_entry_name_defaults_to_none() {
        let yaml = r#"
filter: router
routes: []
"#;
        let entry: FilterEntry = serde_yaml::from_str(yaml).unwrap();
        assert!(entry.name.is_none(), "name should default to None");
    }

    #[test]
    fn parse_filter_entry_with_branch_chains() {
        let yaml = r#"
filter: headers
branch_chains:
  - name: my_branch
    chains:
      - name: inline
        filters:
          - filter: headers
"#;
        let entry: FilterEntry = serde_yaml::from_str(yaml).unwrap();
        assert!(entry.branch_chains.is_some(), "branch_chains should be present");
        let branches = entry.branch_chains.unwrap();
        assert_eq!(branches.len(), 1, "should have 1 branch chain");
        assert_eq!(branches[0].name, "my_branch", "branch name mismatch");
    }

    #[test]
    fn filter_entry_serialize_roundtrip() {
        let yaml = r#"
filter: static_response
status: 200
"#;
        let entry: FilterEntry = serde_yaml::from_str(yaml).unwrap();
        let serialized = serde_yaml::to_string(&entry).expect("serialize");
        let roundtripped: FilterEntry = serde_yaml::from_str(&serialized).expect("deserialize roundtrip");
        assert_eq!(roundtripped.filter_type, entry.filter_type);
    }

    #[test]
    fn parse_filter_entry_access_log_emit_conditions() {
        let yaml = r#"
filter: access_log
sample_rate: 1.0
conditions:
  status_classes: [5xx]
fields: [method, status]
"#;
        let entry: FilterEntry = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(entry.filter_type, "access_log");
        assert!(entry.conditions.is_empty(), "emit conditions belong in config");
        let conditions = entry.config.get("conditions").expect("conditions in config");
        assert!(conditions.is_mapping(), "emit conditions should be a mapping");
    }

    #[test]
    fn parse_filter_entry_branch_chains_defaults_to_none() {
        let yaml = r#"
filter: headers
"#;
        let entry: FilterEntry = serde_yaml::from_str(yaml).unwrap();
        assert!(entry.branch_chains.is_none(), "branch_chains should default to None");
    }

    #[test]
    fn non_string_filter_value_reports_type_error_not_missing() {
        let yaml = "filter: 123\n";
        let err = serde_yaml::from_str::<FilterEntry>(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("filter must be a string"),
            "a present-but-non-string filter key must not be reported as missing: {msg}"
        );
        assert!(
            !msg.contains("missing field"),
            "the key is present, so the error must not say it is missing: {msg}"
        );
    }

    #[test]
    fn missing_filter_key_still_reports_missing() {
        let yaml = "name: x\n";
        let err = serde_yaml::from_str::<FilterEntry>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("missing field"),
            "an absent filter key must still report missing: {err}"
        );
    }
}
