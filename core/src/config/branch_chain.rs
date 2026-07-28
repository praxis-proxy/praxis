// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Branch chain configuration: conditional branching in filter pipelines.

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
    pub name: String,

    /// Chains to execute when triggered. Named refs
    /// or inline definitions, concatenated in order.
    pub chains: Vec<ChainRef>,

    /// Maximum re-entrance iterations. Required when
    /// `rejoin` targets the branch point or an earlier
    /// filter. Validation rejects backward rejoin
    /// without this field.
    #[serde(default)]
    pub max_iterations: Option<u32>,

    /// Condition based on a filter's result output.
    /// When omitted, the branch always fires
    /// (unconditional branch).
    #[serde(default)]
    pub on_result: Option<BranchCondition>,

    /// Where to resume in the parent pipeline after the branch.
    ///
    /// - `"next"` (default): continue after the branch point
    /// - `"terminal"` or `"client"`: stop the pipeline
    /// - `"<name>"`: skip to a named filter in the pipeline
    ///
    /// Named targets work across chains because all listener
    /// chains are concatenated into one flat pipeline. Forward
    /// targets become `SkipTo`; backward targets become
    /// `ReEnter` (which requires [`max_iterations`]).
    ///
    /// [`max_iterations`]: BranchChainConfig::max_iterations
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
    /// [`HttpFilter::name()`]: https://docs.rs/praxis-filter/latest/praxis_filter/trait.HttpFilter.html#tymethod.name
    /// [`FilterEntry`]: super::FilterEntry
    pub filter: String,

    /// Result key to check (default: "status").
    #[serde(default = "default_result_key")]
    pub key: String,

    /// Expected result value. Branch fires when the
    /// filter's result for `key` equals this value.
    ///
    /// In YAML this field is written as `result:`, not `value:`.
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
