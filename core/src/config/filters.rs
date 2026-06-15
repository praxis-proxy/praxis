// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Filter configuration types: named chains and individual filter entries.
//!
//! Listeners reference chains by name, enabling per-listener pipelines.

use serde::Deserialize;
use tracing::warn;

use super::{Condition, ResponseCondition};

// -----------------------------------------------------------------------------
// FailureMode
// -----------------------------------------------------------------------------

/// Per-filter failure behaviour.
///
/// Controls what happens when a filter returns an error during execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, serde::Serialize)]
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
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
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
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct FilterEntry {
    /// Filter type name (e.g. `"router"`, `"load_balancer"`, or a custom name).
    #[serde(rename = "filter")]
    pub filter_type: String,

    /// Optional branch chains evaluated after this filter
    /// based on filter result conditions.
    #[serde(default)]
    pub branch_chains: Option<Vec<super::BranchChainConfig>>,

    /// Ordered conditions that gate whether this filter runs on requests.
    /// Empty means the filter always runs.
    #[serde(default)]
    pub conditions: Vec<Condition>,

    /// Optional user-assigned name for this filter entry.
    /// Used as a rejoin target by branch chains.
    #[serde(default)]
    pub name: Option<String>,

    /// Ordered conditions that gate whether this filter runs on responses.
    /// Evaluated against the upstream response (status, headers).
    /// Empty means the filter always runs on responses.
    #[serde(default)]
    pub response_conditions: Vec<ResponseCondition>,

    /// Per-filter failure behaviour (`open` or `closed`).
    #[serde(default)]
    pub failure_mode: FailureMode,

    /// Arbitrary YAML config passed to the filter's factory function.
    #[serde(flatten)]
    pub config: serde_yaml::Value,
}

// ---------------------------------------------------------------------------
// FilterEntry Typo Detection
// ---------------------------------------------------------------------------

/// Fields handled by `FilterEntry`'s serde derives.
const KNOWN_FILTER_FIELDS: &[&str] = &[
    "filter",
    "branch_chains",
    "conditions",
    "failure_mode",
    "name",
    "response_conditions",
];

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
#[allow(clippy::indexing_slicing, reason = "indices are bounded by input lengths")]
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
    fn parse_filter_entry_branch_chains_defaults_to_none() {
        let yaml = r#"
filter: headers
"#;
        let entry: FilterEntry = serde_yaml::from_str(yaml).unwrap();
        assert!(entry.branch_chains.is_none(), "branch_chains should default to None");
    }
}
