// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Deserialized YAML configuration types for the guardrails filter.

use serde::Deserialize;

use super::pii::PiiKind;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum body size for body inspection (1 MiB).
pub(super) const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;

/// Maximum allowed regex pattern length (characters).
pub(super) const MAX_REGEX_PATTERN_LEN: usize = 1024;

/// Maximum compiled regex automaton size (bytes, 1 MiB).
pub(super) const MAX_REGEX_SIZE: usize = 1_048_576;

// -----------------------------------------------------------------------------
// ContainsValue
// -----------------------------------------------------------------------------

/// The value of a `contains` rule field (either a literal substring or a
/// list of built-in PII categories).
///
/// In YAML the value is untagged: a plain string becomes a [`Literal`] match
/// and a sequence of PII kind names becomes a [`Pii`] match.
///
/// ```yaml
/// # Literal substring
/// contains: "DROP TABLE"
///
/// # PII category list
/// contains: [ssn, credit_card, email]
/// ```
///
/// ```
/// use praxis_filter::ContainsValue;
///
/// // Literal substring — any YAML string
/// let v: ContainsValue = serde_yaml::from_str("\"DROP TABLE\"").unwrap();
/// assert!(matches!(v, ContainsValue::Literal(ref s) if s == "DROP TABLE"));
///
/// // PII category list — a YAML sequence of known kind names
/// let v: ContainsValue = serde_yaml::from_str("[ssn, email]").unwrap();
/// assert!(matches!(v, ContainsValue::Pii(_)));
/// ```
///
/// [`Literal`]: ContainsValue::Literal
/// [`Pii`]: ContainsValue::Pii
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ContainsValue {
    /// Literal substring match (case-insensitive).
    Literal(String),

    /// Built-in PII category detection.
    Pii(Vec<PiiKind>),
}

impl ContainsValue {
    /// Validate the value of a `contains` rule field.
    ///
    /// Returns an error if a bare string matches a PII kind name (case-insensitive).
    pub(super) fn validate(&self) -> Result<(), String> {
        if let ContainsValue::Literal(s) = self
            && serde_yaml::from_str::<PiiKind>(&s.to_lowercase()).is_ok()
        {
            return Err(format!(
                "'{s}' is a PII category name — \
                 use 'contains: [{s}]' for PII detection, \
                 or use a quoted string (e.g. contains: \"{s}\") \
                 for a literal substring match"
            ));
        }
        Ok(())
    }
}

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
    /// Reject the request immediately with 403 (default).
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
// RuleTargetKind
// -----------------------------------------------------------------------------

/// What a guardrail rule inspects at the config level.
///
/// ```
/// use praxis_filter::RuleTargetKind;
///
/// let target: RuleTargetKind = serde_yaml::from_str("header").unwrap();
/// assert!(matches!(target, RuleTargetKind::Header));
///
/// let target: RuleTargetKind = serde_yaml::from_str("body").unwrap();
/// assert!(matches!(target, RuleTargetKind::Body));
/// ```
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleTargetKind {
    /// Inspect a named request header.
    Header,

    /// Inspect the request body.
    Body,
}

// -----------------------------------------------------------------------------
// RuleConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for a single guardrail rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuleConfig {
    /// Header name (required when `target` is [`Header`]).
    ///
    /// [`Header`]: RuleTargetKind::Header
    pub name: Option<String>,

    /// Literal substring (case-insensitive) or PII category list.
    pub contains: Option<ContainsValue>,

    /// Invert the match: reject when the content does NOT
    /// match. For negated header rules, a missing header
    /// also triggers rejection. Defaults to `false`.
    #[serde(default)]
    pub negate: bool,

    /// Regex pattern match.
    pub pattern: Option<String>,

    /// What to inspect: header or body.
    pub target: RuleTargetKind,
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

    /// Reject requests whose body exceeds the inspection buffer limit
    /// (1 MiB) when body rules are active, instead of silently
    /// truncating inspection.
    #[serde(default)]
    pub reject_oversized: bool,

    /// List of rules to evaluate.
    pub rules: Vec<RuleConfig>,
}
