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
/// use praxis_core::config::{BranchCondition, ResultMatch};
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
/// assert_eq!(cond.value, ResultMatch::Exact("hit".to_owned()));
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

    /// Expected result. A plain value fires the branch when the filter's
    /// result for `key` equals it exactly. A single-key mapping picks an
    /// operator instead: `contains` (substring), `not` (any other value, or
    /// no value at all), or `any_of` (equals one of the listed values). See
    /// [`ResultMatch`].
    ///
    /// In YAML this field is written as `result:`, not `value:`.
    /// Each value is limited to 256 bytes.
    #[serde(rename = "result")]
    pub value: ResultMatch,
}

/// Serde default for [`BranchCondition::key`].
fn default_result_key() -> String {
    "status".to_owned()
}

// -----------------------------------------------------------------------------
// ResultMatch
// -----------------------------------------------------------------------------

/// How a branch condition compares a filter's result value.
///
/// Written as a plain scalar for an exact match, or as a single-key mapping
/// naming an operator:
///
/// ```yaml
/// result: "true"                         # exact
/// result: { contains: unsafe }           # substring
/// result: { not: safe }                  # anything but this value, including no value
/// result: { any_of: ["2", "4", "6"] }    # equals one of these values
/// ```
///
/// [`Exact`], [`AnyOf`], and [`Contains`] only match when the filter wrote
/// the key. [`Not`] also matches when the key is missing, so a deny branch
/// written as `not: safe` still fires when a guardrail returned no verdict.
/// Comparisons are case-sensitive. Unquoted numbers and booleans are read as
/// their plain text (`0`, `true`).
///
/// ```
/// use praxis_core::config::ResultMatch;
///
/// let exact: ResultMatch = serde_yaml::from_str("blocked").unwrap();
/// assert_eq!(exact, ResultMatch::Exact("blocked".to_owned()));
///
/// let not: ResultMatch = serde_yaml::from_str("not: safe").unwrap();
/// assert_eq!(
///     not,
///     ResultMatch::Not {
///         not: "safe".to_owned()
///     }
/// );
///
/// let any_of: ResultMatch = serde_yaml::from_str("any_of: [2, 4, 6]").unwrap();
/// assert_eq!(
///     any_of,
///     ResultMatch::AnyOf {
///         any_of: vec!["2".to_owned(), "4".to_owned(), "6".to_owned()]
///     }
/// );
///
/// let err = serde_yaml::from_str::<ResultMatch>("starts_with: un").unwrap_err();
/// assert!(err.to_string().contains("starts_with"));
/// ```
///
/// [`Exact`]: ResultMatch::Exact
/// [`AnyOf`]: ResultMatch::AnyOf
/// [`Contains`]: ResultMatch::Contains
/// [`Not`]: ResultMatch::Not
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub enum ResultMatch {
    /// The result equals this value.
    Exact(String),

    /// The result equals one of these values.
    AnyOf {
        /// Values that fire the branch when the result equals one of them.
        any_of: Vec<String>,
    },

    /// The result contains this substring.
    Contains {
        /// Text that fires the branch when the result contains it.
        contains: String,
    },

    /// The result is missing or differs from this value.
    Not {
        /// The one value that doesn't fire the branch; any other value, or no
        /// value at all, does.
        not: String,
    },
}

// Dispatches on the YAML shape by hand: an untagged derive would report an
// unknown operator as "did not match any variant", and would reject the
// unquoted numbers and booleans this accepts as exact text.
impl<'de> Deserialize<'de> for ResultMatch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let value = serde_yaml::Value::deserialize(deserializer)?;
        if let serde_yaml::Value::Mapping(map) = value {
            return deserialize_operator(map).map_err(D::Error::custom);
        }
        scalar_text(value).map(Self::Exact).ok_or_else(|| {
            D::Error::custom(
                "on_result.result must be a value (e.g. blocked) or a single-key mapping \
                 naming an operator (contains, not, or any_of)",
            )
        })
    }
}

/// Deserialize the `{operator: operand}` form of [`ResultMatch`].
fn deserialize_operator(map: serde_yaml::Mapping) -> Result<ResultMatch, String> {
    let mut entries = map.into_iter();
    let (Some((serde_yaml::Value::String(operator), operand)), None) = (entries.next(), entries.next()) else {
        return Err("on_result.result mapping must name exactly one operator (contains, not, or any_of)".to_owned());
    };
    match operator.as_str() {
        "any_of" => any_of_values(operand).map(|any_of| ResultMatch::AnyOf { any_of }),
        "contains" => operator_text("contains", operand).map(|contains| ResultMatch::Contains { contains }),
        "not" => operator_text("not", operand).map(|not| ResultMatch::Not { not }),
        other => Err(format!(
            "unknown on_result.result operator '{other}' (expected one of: contains, not, any_of)"
        )),
    }
}

/// Read the list of values an `any_of` matcher accepts.
fn any_of_values(operand: serde_yaml::Value) -> Result<Vec<String>, String> {
    let serde_yaml::Value::Sequence(items) = operand else {
        return Err("on_result.result.any_of must be a list of values".to_owned());
    };
    items
        .into_iter()
        .map(|item| scalar_text(item).ok_or_else(|| "on_result.result.any_of entries must be plain values".to_owned()))
        .collect()
}

/// Read the single value a `contains` or `not` matcher takes.
fn operator_text(operator: &str, operand: serde_yaml::Value) -> Result<String, String> {
    scalar_text(operand).ok_or_else(|| format!("on_result.result.{operator} must be a single value"))
}

/// The text of a string, number, or boolean scalar; `None` for anything else.
fn scalar_text(value: serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(text) => Some(text),
        serde_yaml::Value::Bool(flag) => Some(flag.to_string()),
        serde_yaml::Value::Number(number) => Some(number.to_string()),
        serde_yaml::Value::Null
        | serde_yaml::Value::Sequence(_)
        | serde_yaml::Value::Mapping(_)
        | serde_yaml::Value::Tagged(_) => None,
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
        assert_eq!(cond.value, exact("hit"), "condition value mismatch");
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
        assert_eq!(cond.value, exact("premium"), "value mismatch");
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

    #[test]
    fn parse_result_operators() {
        let cases = [
            ("result: unsafe", exact("unsafe")),
            ("result: {contains: unsafe}", contains("unsafe")),
            ("result: {not: safe}", not("safe")),
            ("result: {any_of: [low, high]}", any_of(&["low", "high"])),
        ];
        for (result, expected) in cases {
            let cond: BranchCondition = serde_yaml::from_str(&format!("filter: guard\n{result}")).unwrap();
            assert_eq!(cond.value, expected, "{result} should parse to {expected:?}");
        }
    }

    #[test]
    fn parse_unquoted_scalars_as_exact_text() {
        let zero: ResultMatch = serde_yaml::from_str("0").unwrap();
        let flag: ResultMatch = serde_yaml::from_str("true").unwrap();
        let not_zero: ResultMatch = serde_yaml::from_str("not: 0").unwrap();
        let codes: ResultMatch = serde_yaml::from_str("any_of: [2, 4, 6]").unwrap();

        assert_eq!(zero, exact("0"), "an unquoted number should match its text");
        assert_eq!(flag, exact("true"), "an unquoted boolean should match its text");
        assert_eq!(not_zero, not("0"), "operands read numbers as text");
        assert_eq!(codes, any_of(&["2", "4", "6"]), "any_of entries read numbers as text");
    }

    #[test]
    fn reject_result_mapping_with_two_operators() {
        let err = serde_yaml::from_str::<ResultMatch>("{contains: un, not: safe}").unwrap_err();
        assert!(
            err.to_string()
                .contains("exactly one operator (contains, not, or any_of)"),
            "two operators in one result should be rejected: {err}"
        );
    }

    #[test]
    fn reject_unknown_result_operator_by_name() {
        let err = serde_yaml::from_str::<ResultMatch>("nope: x").unwrap_err();
        assert!(
            err.to_string().contains("unknown on_result.result operator 'nope'"),
            "an unknown operator should be named in the error: {err}"
        );
    }

    #[test]
    fn reject_malformed_result_shapes() {
        let cases = [
            ("~", "must be a value"),
            ("[a, b]", "must be a value"),
            ("{}", "exactly one operator"),
            ("any_of: safe", "any_of must be a list"),
            ("any_of: [[a]]", "any_of entries must be plain values"),
            ("contains: [a]", "contains must be a single value"),
            ("not: {a: b}", "not must be a single value"),
            ("not: ~", "not must be a single value"),
        ];
        for (yaml, expected) in cases {
            let err = serde_yaml::from_str::<ResultMatch>(yaml).unwrap_err();
            assert!(
                err.to_string().contains(expected),
                "{yaml} should be rejected with '{expected}': {err}"
            );
        }
    }

    #[test]
    fn result_serializes_as_scalar_or_single_key_mapping() {
        let cases = [
            (exact("hit"), serde_json::json!("hit")),
            (contains("unsafe"), serde_json::json!({"contains": "unsafe"})),
            (not("safe"), serde_json::json!({"not": "safe"})),
            (any_of(&["2", "4"]), serde_json::json!({"any_of": ["2", "4"]})),
        ];
        for (matcher, expected) in cases {
            assert_eq!(
                serde_json::to_value(&matcher).unwrap(),
                expected,
                "{matcher:?} should serialize to {expected}"
            );
        }
    }

    #[test]
    fn result_round_trips_through_yaml() {
        let matchers = [
            exact("hit"),
            exact("0"),
            contains("unsafe"),
            not("safe"),
            any_of(&["2", "4", "6"]),
        ];
        for matcher in matchers {
            let cond = BranchCondition {
                filter: "guard".to_owned(),
                key: "verdict".to_owned(),
                value: matcher.clone(),
            };
            let yaml = serde_yaml::to_string(&cond).unwrap();
            let parsed: BranchCondition = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(
                parsed.value, matcher,
                "{matcher:?} should survive a YAML round trip:\n{yaml}"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// An exact matcher for `value`.
    fn exact(value: &str) -> ResultMatch {
        ResultMatch::Exact(value.to_owned())
    }

    /// An `any_of` matcher for `values`.
    fn any_of(values: &[&str]) -> ResultMatch {
        ResultMatch::AnyOf {
            any_of: values.iter().map(|value| (*value).to_owned()).collect(),
        }
    }

    /// A `contains` matcher for `needle`.
    fn contains(needle: &str) -> ResultMatch {
        ResultMatch::Contains {
            contains: needle.to_owned(),
        }
    }

    /// A `not` matcher for `rejected`.
    fn not(rejected: &str) -> ResultMatch {
        ResultMatch::Not {
            not: rejected.to_owned(),
        }
    }
}
