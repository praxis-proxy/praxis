// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Compiled rule types and config-to-rule parsing.

use regex::{Regex, RegexBuilder};

use super::{
    config::{ContainsValue, MAX_REGEX_PATTERN_LEN, MAX_REGEX_SIZE, RuleConfig, RuleTargetKind},
    pii::{self, PiiKind},
};
use crate::FilterError;

// -----------------------------------------------------------------------------
// Rule Types
// -----------------------------------------------------------------------------

/// What a rule inspects.
#[derive(Debug, Clone)]
pub(super) enum RuleTarget {
    /// Inspect a named request header.
    Header(String),

    /// Inspect the request body.
    Body,
}

/// How a rule matches content.
#[derive(Debug, Clone)]
pub(super) enum RuleMatcher {
    /// Literal substring match (case-insensitive).
    Contains(String),

    /// Pre-compiled regex.
    Pattern(Regex),

    /// Built-in PII category detection.
    Pii(Vec<PiiKind>),
}

/// A compiled guardrail rule ready for per-request evaluation.
#[derive(Debug, Clone)]
pub(super) struct CompiledRule {
    /// What to inspect.
    pub target: RuleTarget,

    /// How to match.
    pub matcher: RuleMatcher,

    /// When true, the rule triggers on non-match instead of match.
    pub negate: bool,
}

/// Outcome of evaluating a compiled rule against a string.
#[derive(Debug)]
pub(super) struct RuleEval {
    /// Whether the rule matched the haystack.
    pub matched: bool,
    /// For PII matchers that matched, the first PII kind that triggered.
    pub pii_kind: Option<PiiKind>,
}

impl CompiledRule {
    /// Evaluate the rule against `haystack`, returning both
    /// the match outcome and any PII kind together.
    pub(super) fn eval(&self, haystack: &str) -> RuleEval {
        match &self.matcher {
            RuleMatcher::Contains(needle) => RuleEval {
                matched: haystack.to_lowercase().contains(needle.as_str()),
                pii_kind: None,
            },
            RuleMatcher::Pattern(re) => RuleEval {
                matched: re.is_match(haystack),
                pii_kind: None,
            },
            RuleMatcher::Pii(kinds) => {
                let pii_kind = pii::matches_any(kinds, haystack);
                RuleEval {
                    matched: pii_kind.is_some(),
                    pii_kind,
                }
            },
        }
    }
}

// -----------------------------------------------------------------------------
// Parsing
// -----------------------------------------------------------------------------

/// Parse the target field from a rule config.
pub(super) fn parse_target(rule: &RuleConfig) -> Result<RuleTarget, FilterError> {
    match rule.target {
        RuleTargetKind::Header => {
            let name = rule
                .name
                .as_ref()
                .ok_or_else(|| -> FilterError { "guardrails: 'name' is required for header rules".into() })?;
            if name.is_empty() {
                return Err("guardrails: 'name' must not be empty".into());
            }
            Ok(RuleTarget::Header(name.clone()))
        },
        RuleTargetKind::Body => Ok(RuleTarget::Body),
    }
}

/// Parse the matcher (contains or pattern) from a rule config.
///
/// Regex patterns are subject to length and compiled-size limits
/// to prevent configurations from consuming excessive memory.
pub(super) fn parse_matcher(rule: &RuleConfig) -> Result<RuleMatcher, FilterError> {
    match (&rule.contains, &rule.pattern) {
        (Some(cv), None) => parse_contains(cv),
        (None, Some(p)) => compile_pattern(p),
        (Some(_), Some(_)) => Err("guardrails: use 'contains' or 'pattern', not both".into()),
        (None, None) => Err("guardrails: each rule must have 'contains' or 'pattern'".into()),
    }
}

/// Compile a [`ContainsValue`] into a [`RuleMatcher`].
fn parse_contains(cv: &ContainsValue) -> Result<RuleMatcher, FilterError> {
    cv.validate()
        .map_err(|e| -> FilterError { format!("guardrails: {e}").into() })?;

    match cv {
        ContainsValue::Literal(s) => {
            if s.is_empty() {
                return Err("guardrails: 'contains' must not be empty".into());
            }
            Ok(RuleMatcher::Contains(s.to_lowercase()))
        },
        ContainsValue::Pii(kinds) => {
            if kinds.is_empty() {
                return Err("guardrails: 'contains' PII list must not be empty".into());
            }
            Ok(RuleMatcher::Pii(kinds.clone()))
        },
    }
}

/// Validate and compile a regex pattern string into a [`RuleMatcher`].
fn compile_pattern(p: &str) -> Result<RuleMatcher, FilterError> {
    if p.is_empty() {
        return Err("guardrails: 'pattern' must not be empty".into());
    }
    if p.len() > MAX_REGEX_PATTERN_LEN {
        return Err(format!(
            "guardrails: regex pattern exceeds {MAX_REGEX_PATTERN_LEN} character limit ({} chars)",
            p.len()
        )
        .into());
    }
    RegexBuilder::new(p)
        .size_limit(MAX_REGEX_SIZE)
        .build()
        .map(RuleMatcher::Pattern)
        .map_err(|e| format!("guardrails: invalid regex '{p}': {e}").into())
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
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use regex::Regex;

    use super::{CompiledRule, ContainsValue, RuleMatcher, RuleTarget, parse_contains};

    #[test]
    fn contains_bare_pii_name_errors() {
        for name in &["ssn", "SSN", "credit_card", "Credit_Card", "phone", "email"] {
            let cv = ContainsValue::Literal((*name).to_owned());
            assert!(
                parse_contains(&cv).is_err(),
                "bare PII kind name '{name}' should be rejected by parse_contains"
            );
        }
    }

    #[test]
    fn contains_matcher_matches_substring() {
        let rule = body_contains("DROP TABLE");
        assert!(
            rule.eval("SELECT 1; DROP TABLE users").matched,
            "should match substring"
        );
    }

    #[test]
    fn contains_matcher_rejects_non_match() {
        let rule = body_contains("DROP TABLE");
        assert!(
            !rule.eval("SELECT 1 FROM users").matched,
            "should not match unrelated text"
        );
    }

    #[test]
    fn contains_matcher_is_case_insensitive() {
        let rule = body_contains("DROP TABLE");
        assert!(
            rule.eval("drop table users").matched,
            "contains should match lowercase input"
        );
        assert!(
            rule.eval("Drop Table users").matched,
            "contains should match mixed-case input"
        );
        assert!(
            rule.eval("DROP TABLE users").matched,
            "contains should match uppercase input"
        );
    }

    #[test]
    fn contains_matcher_case_insensitive_mixed_needle() {
        let rule = body_contains("xSs");
        assert!(
            rule.eval("has XSS injection").matched,
            "case-insensitive needle should match"
        );
        assert!(rule.eval("has xss injection").matched, "lowercase needle should match");
    }

    #[test]
    fn pattern_matcher_matches_regex() {
        let rule = body_pattern(r"DROP\s+TABLE");
        assert!(
            rule.eval("DROP   TABLE users").matched,
            "regex should match whitespace variants"
        );
    }

    #[test]
    fn pattern_matcher_rejects_non_match() {
        let rule = body_pattern(r"DROP\s+TABLE");
        assert!(
            !rule.eval("SELECT 1 FROM users").matched,
            "regex should not match unrelated text"
        );
    }

    #[test]
    fn pii_eval_returns_kind_on_match() {
        use super::super::pii::PiiKind;
        let rule = CompiledRule {
            target: RuleTarget::Body,
            matcher: RuleMatcher::Pii(vec![PiiKind::Ssn]),
            negate: false,
        };
        let ev = rule.eval("my ssn is 123-45-6789");
        assert!(ev.matched);
        assert_eq!(ev.pii_kind, Some(PiiKind::Ssn));
    }

    #[test]
    fn pii_eval_returns_none_on_no_match() {
        use super::super::pii::PiiKind;
        let rule = CompiledRule {
            target: RuleTarget::Body,
            matcher: RuleMatcher::Pii(vec![PiiKind::Ssn]),
            negate: false,
        };
        let ev = rule.eval("no sensitive data here");
        assert!(!ev.matched);
        assert_eq!(ev.pii_kind, None);
    }

    #[test]
    fn contains_eval_pii_kind_is_always_none() {
        let rule = body_contains("DROP TABLE");
        let ev = rule.eval("DROP TABLE users");
        assert!(ev.matched);
        assert_eq!(ev.pii_kind, None, "non-PII matchers never produce a pii_kind");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a body-contains rule for testing.
    fn body_contains(needle: &str) -> CompiledRule {
        CompiledRule {
            target: RuleTarget::Body,
            matcher: RuleMatcher::Contains(needle.to_lowercase()),
            negate: false,
        }
    }

    /// Build a body-pattern rule for testing.
    fn body_pattern(re: &str) -> CompiledRule {
        CompiledRule {
            target: RuleTarget::Body,
            matcher: RuleMatcher::Pattern(Regex::new(re).unwrap()),
            negate: false,
        }
    }
}
