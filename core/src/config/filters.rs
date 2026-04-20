// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Filter configuration types: named chains and individual filter entries.
//!
//! Listeners reference chains by name, enabling per-listener pipelines.

use serde::Deserialize;

use super::{Condition, ResponseCondition};

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
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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

    /// Arbitrary YAML config passed to the filter's factory function.
    #[serde(flatten)]
    pub config: serde_yaml::Value,
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
