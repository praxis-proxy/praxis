// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Compiled rule types and config-to-rule parsing.

use regex::{Regex, RegexBuilder};

use super::config::{MAX_REGEX_PATTERN_LEN, MAX_REGEX_SIZE, RuleConfig};
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

impl CompiledRule {
    /// Check whether `haystack` matches this rule.
    pub(super) fn matches(&self, haystack: &str) -> bool {
        match &self.matcher {
            RuleMatcher::Contains(needle) => haystack.to_lowercase().contains(needle.as_str()),
            RuleMatcher::Pattern(re) => re.is_match(haystack),
        }
    }
}

// -----------------------------------------------------------------------------
// Parsing
// -----------------------------------------------------------------------------

/// Parse the target field from a rule config.
pub(super) fn parse_target(rule: &RuleConfig) -> Result<RuleTarget, FilterError> {
    match rule.target.as_str() {
        "header" => {
            let name = rule
                .name
                .as_ref()
                .ok_or_else(|| -> FilterError { "guardrails: 'name' is required for header rules".into() })?;
            if name.is_empty() {
                return Err("guardrails: 'name' must not be empty".into());
            }
            Ok(RuleTarget::Header(name.clone()))
        },
        "body" => Ok(RuleTarget::Body),
        other => Err(format!("guardrails: unknown target '{other}', expected 'header' or 'body'").into()),
    }
}

/// Parse the matcher (contains or pattern) from a rule config.
///
/// Regex patterns are subject to length and compiled-size limits
/// to prevent configurations from consuming excessive memory.
pub(super) fn parse_matcher(rule: &RuleConfig) -> Result<RuleMatcher, FilterError> {
    match (&rule.contains, &rule.pattern) {
        (Some(s), None) => {
            if s.is_empty() {
                return Err("guardrails: 'contains' must not be empty".into());
            }
            Ok(RuleMatcher::Contains(s.to_lowercase()))
        },
        (None, Some(p)) => {
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
            let re = RegexBuilder::new(p)
                .size_limit(MAX_REGEX_SIZE)
                .build()
                .map_err(|e| -> FilterError { format!("guardrails: invalid regex '{p}': {e}").into() })?;
            Ok(RuleMatcher::Pattern(re))
        },
        (Some(_), Some(_)) => Err("guardrails: use 'contains' or 'pattern', not both".into()),
        (None, None) => Err("guardrails: each rule must have 'contains' or 'pattern'".into()),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use regex::Regex;

    use super::{CompiledRule, RuleMatcher, RuleTarget};

    #[test]
    fn contains_matcher_matches_substring() {
        let rule = body_contains("DROP TABLE");
        assert!(rule.matches("SELECT 1; DROP TABLE users"), "should match substring");
    }

    #[test]
    fn contains_matcher_rejects_non_match() {
        let rule = body_contains("DROP TABLE");
        assert!(!rule.matches("SELECT 1 FROM users"), "should not match unrelated text");
    }

    #[test]
    fn contains_matcher_is_case_insensitive() {
        let rule = body_contains("DROP TABLE");
        assert!(
            rule.matches("drop table users"),
            "contains should match lowercase input"
        );
        assert!(
            rule.matches("Drop Table users"),
            "contains should match mixed-case input"
        );
        assert!(
            rule.matches("DROP TABLE users"),
            "contains should match uppercase input"
        );
    }

    #[test]
    fn contains_matcher_case_insensitive_mixed_needle() {
        let rule = body_contains("xSs");
        assert!(
            rule.matches("has XSS injection"),
            "case-insensitive needle should match"
        );
        assert!(rule.matches("has xss injection"), "lowercase needle should match");
    }

    #[test]
    fn pattern_matcher_matches_regex() {
        let rule = body_pattern(r"DROP\s+TABLE");
        assert!(
            rule.matches("DROP   TABLE users"),
            "regex should match whitespace variants"
        );
    }

    #[test]
    fn pattern_matcher_rejects_non_match() {
        let rule = body_pattern(r"DROP\s+TABLE");
        assert!(
            !rule.matches("SELECT 1 FROM users"),
            "regex should not match unrelated text"
        );
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
