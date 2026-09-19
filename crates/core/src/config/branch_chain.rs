// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Branch chain configuration: conditional branching in filter pipelines.
//!
//! A branch chain lets a filter's outcome steer which filters run next
//! without the filter itself knowing branches exist. Filters record
//! outcomes in a `FilterResultSet`; the pipeline executor reads those
//! results, evaluates each branch's `on_result` condition, and, on a
//! match, runs the branch's chains before resuming at the configured
//! rejoin point (the next filter, a terminal, a named filter, or a
//! re-entrance bounded by an iteration limit).
//!
//! Branch sub-chains run only during the request phase (`on_request`);
//! their `on_request_body`, `on_response_body`, and
//! `on_selected_upstream_request_body` hooks are not executed, so
//! body-transforming filters belong on the main pipeline path.
//!
//! This module defines only the config surface. Validation lives in
//! `crate::config::validate::branch_chain`, execution in
//! `praxis-filter::pipeline`, and filter result feedback in
//! `praxis-filter::FilterResultSet`.

use serde::Deserialize;

use super::chain_ref::ChainRef;

// -----------------------------------------------------------------------------
// BranchChainConfig
// -----------------------------------------------------------------------------

/// A branch chain attached to a filter entry.
///
/// Branches fire after a filter executes and evaluate
/// `on_result` conditions against filter result feedback.
/// When a branch matches, its chains execute and the
/// pipeline resumes at the configured rejoin point.
///
/// ```
/// use praxis_core::config::BranchChainConfig;
///
/// let branch: BranchChainConfig = serde_yaml::from_str(
///     r#"
/// name: cache_hit
/// on_result:
///   filter: cache
///   result: hit
/// rejoin: terminal
/// chains:
///   - serve_cached
/// "#,
/// )
/// .unwrap();
/// assert_eq!(branch.name, "cache_hit");
/// assert!(branch.on_result.is_some());
/// assert_eq!(branch.rejoin, "terminal");
/// ```
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct BranchChainConfig {
    /// Globally unique name for this branch.
    ///
    /// Must be unique across all branches in the entire configuration,
    /// not just within a single listener or filter. Validated at startup
    /// before pipeline construction.
    pub name: String,

    /// Chains to execute when triggered. Named refs
    /// or inline definitions, concatenated in order.
    pub chains: Vec<ChainRef>,

    /// Maximum re-entrance iterations. Required when
    /// `rejoin` targets the branch point or an earlier
    /// filter. Validation rejects backward rejoin
    /// without this field.
    ///
    /// Capped at 100 by validation. When the iteration
    /// count is exhausted, the pipeline resumes at the
    /// rejoin point without executing the branch again.
    #[serde(default)]
    pub max_iterations: Option<u32>,

    /// Condition based on a filter's result output.
    /// When omitted, the branch always fires
    /// (unconditional branch).
    #[serde(default)]
    pub on_result: Option<BranchCondition>,

    /// Where to resume in the parent pipeline after the branch.
    ///
    /// - `"next"` (default): continue at the filter immediately after the branch point, processing the rest of the
    ///   pipeline normally.
    /// - `"terminal"` or `"client"`: stop pipeline execution and return the response to the client without running
    ///   further filters.
    /// - `"<name>"`: skip to a named filter (the `name` field on a [`FilterEntry`], not the filter type). If the
    ///   target appears later in the pipeline, this becomes a forward skip. If earlier, it becomes re-entrance and
    ///   requires [`max_iterations`] to prevent infinite loops.
    ///
    /// Named targets work across chains because all listener
    /// chains are concatenated into one flat pipeline during
    /// startup. Cross-chain rejoin targets use `"chain:filter"`
    /// syntax.
    ///
    /// [`max_iterations`]: BranchChainConfig::max_iterations
    /// [`FilterEntry`]: super::FilterEntry
    #[serde(default = "default_rejoin")]
    pub rejoin: String,
}

/// Serde default for [`BranchChainConfig::rejoin`].
fn default_rejoin() -> String {
    "next".to_owned()
}

// -----------------------------------------------------------------------------
// BranchCondition
// -----------------------------------------------------------------------------

/// Condition that triggers a branch based on a
/// preceding filter's result.
///
/// ```
/// use praxis_core::config::BranchCondition;
///
/// let cond: BranchCondition = serde_yaml::from_str(
///     r#"
/// filter: cache
/// key: status
/// result: hit
/// "#,
/// )
/// .unwrap();
/// assert_eq!(cond.filter, "cache");
/// assert_eq!(cond.key, "status");
/// assert_eq!(cond.value, "hit");
/// ```
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct BranchCondition {
    /// Filter TYPE name whose results to inspect.
    ///
    /// Must match the return value of [`HttpFilter::name()`] (e.g.,
    /// `"guardrails"`, `"json_rpc"`), NOT the user-assigned `name`
    /// on [`FilterEntry`].
    ///
    /// Filters populate results using their type name as the key in
    /// `ctx.filter_results`. See `praxis-filter::FilterResultSet` for
    /// how filters write results and how branches read them.
    ///
    /// [`HttpFilter::name()`]: https://docs.rs/praxis-filter/latest/praxis_filter/trait.HttpFilter.html#tymethod.name
    /// [`FilterEntry`]: super::FilterEntry
    pub filter: String,

    /// Result key to check (default: "status").
    ///
    /// The key identifies which result field to inspect.
    /// Common keys include `"status"`, `"action"`, and `"tier"`,
    /// but the available keys depend on what the target filter
    /// writes to its `FilterResultSet`. Limited to 64 bytes.
    #[serde(default = "default_result_key")]
    pub key: String,

    /// Expected result value. Branch fires when the
    /// filter's result for `key` equals this value
    /// (exact string match).
    ///
    /// In YAML this field is written as `result:`, not `value:`.
    /// Limited to 256 bytes.
    #[serde(rename = "result")]
    pub value: String,
}

/// Serde default for [`BranchCondition::key`].
fn default_result_key() -> String {
    "status".to_owned()
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
    fn parse_branch_with_on_result() {
        let yaml = r#"
name: cache_hit
on_result:
  filter: cache
  result: hit
rejoin: terminal
chains:
  - serve_cached
"#;
        let branch: BranchChainConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(branch.name, "cache_hit", "branch name mismatch");
        assert_eq!(branch.rejoin, "terminal", "rejoin mismatch");
        assert!(branch.on_result.is_some(), "on_result should be present");

        let cond = branch.on_result.unwrap();
        assert_eq!(cond.filter, "cache", "condition filter mismatch");
        assert_eq!(cond.key, "status", "condition key should default to 'status'");
        assert_eq!(cond.value, "hit", "condition value mismatch");
    }

    #[test]
    fn parse_unconditional_branch() {
        let yaml = r#"
name: always_run
chains:
  - utility_chain
"#;
        let branch: BranchChainConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(branch.name, "always_run", "branch name mismatch");
        assert!(
            branch.on_result.is_none(),
            "unconditional branch should have no on_result"
        );
        assert_eq!(branch.rejoin, "next", "default rejoin should be 'next'");
        assert!(branch.max_iterations.is_none(), "max_iterations should default to None");
    }

    #[test]
    fn parse_branch_with_max_iterations() {
        let yaml = r#"
name: retry
on_result:
  filter: auth
  key: action
  result: retry
rejoin: auth
max_iterations: 3
chains:
  - name: refresh
    filters:
      - filter: headers
"#;
        let branch: BranchChainConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(branch.max_iterations, Some(3), "max_iterations should be 3");
        assert_eq!(branch.rejoin, "auth", "rejoin should be 'auth'");
    }

    #[test]
    fn parse_branch_condition_custom_key() {
        let yaml = r#"
filter: classifier
key: tier
result: premium
"#;
        let cond: BranchCondition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cond.filter, "classifier", "filter mismatch");
        assert_eq!(cond.key, "tier", "custom key mismatch");
        assert_eq!(cond.value, "premium", "value mismatch");
    }

    #[test]
    fn parse_branch_condition_default_key() {
        let yaml = r#"
filter: cache
result: miss
"#;
        let cond: BranchCondition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cond.key, "status", "key should default to 'status'");
    }

    #[test]
    fn parse_branch_with_multiple_chains() {
        let yaml = r#"
name: multi
chains:
  - chain_a
  - chain_b
  - name: inline_chain
    filters:
      - filter: headers
"#;
        let branch: BranchChainConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(branch.chains.len(), 3, "should have 3 chain refs");
    }

    #[test]
    fn parse_branch_with_named_rejoin() {
        let yaml = r#"
name: skip_to_routing
rejoin: routing
chains:
  - guardrails
"#;
        let branch: BranchChainConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(branch.rejoin, "routing", "rejoin should be 'routing'");
    }

    #[test]
    fn parse_branch_with_cross_chain_rejoin() {
        let yaml = r#"
name: cross
rejoin: "main:routing"
chains:
  - utility
"#;
        let branch: BranchChainConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(branch.rejoin, "main:routing", "cross-chain rejoin should be preserved");
    }
}
