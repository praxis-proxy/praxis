// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Deserialized YAML configuration types for the guardrails filter.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// Guardrails Constants
// -----------------------------------------------------------------------------

/// Default maximum body size for body inspection (1 MiB).
pub(super) const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;

/// Maximum allowed regex pattern length (characters).
pub(super) const MAX_REGEX_PATTERN_LEN: usize = 1024;

/// Maximum compiled regex automaton size (bytes, 1 MiB).
pub(super) const MAX_REGEX_SIZE: usize = 1_048_576;

// -----------------------------------------------------------------------------
// GuardrailsAction
// -----------------------------------------------------------------------------

/// What happens when a guardrail rule matches.
///
/// ```
/// use praxis_filter::GuardrailsAction;
///
/// let action: GuardrailsAction = serde_yaml::from_str("reject").unwrap();
/// assert!(matches!(action, GuardrailsAction::Reject));
///
/// let flag: GuardrailsAction = serde_yaml::from_str("flag").unwrap();
/// assert!(matches!(flag, GuardrailsAction::Flag));
/// ```
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GuardrailsAction {
    /// Reject the request immediately with 401 (default).
    #[default]
    Reject,

    /// Write `status=blocked` to [`FilterResultSet`] but
    /// return [`Continue`], allowing branch chains to
    /// decide the response.
    ///
    /// [`FilterResultSet`]: crate::FilterResultSet
    /// [`Continue`]: crate::FilterAction::Continue
    Flag,
}

// -----------------------------------------------------------------------------
// RuleConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for a single guardrail rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuleConfig {
    /// Header name (required when `target` is `"header"`).
    pub name: Option<String>,

    /// What to inspect: `"header"` or `"body"`.
    pub target: String,

    /// Literal substring match (case-sensitive).
    pub contains: Option<String>,

    /// Regex pattern match.
    pub pattern: Option<String>,

    /// Invert the match: reject when the content does NOT
    /// match. For negated header rules, a missing header
    /// also triggers rejection. Defaults to `false`.
    #[serde(default)]
    pub negate: bool,
}

// -----------------------------------------------------------------------------
// GuardrailsConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the guardrails filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GuardrailsConfig {
    /// What to do when a rule matches (default: reject).
    #[serde(default)]
    pub action: GuardrailsAction,

    /// List of rules to evaluate.
    pub rules: Vec<RuleConfig>,
}
