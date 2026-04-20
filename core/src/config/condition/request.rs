// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Request-phase condition predicates that gate filter execution.

use std::collections::HashMap;

use serde::Deserialize;

use super::impl_condition_deserialize;

// -----------------------------------------------------------------------------
// Condition
// -----------------------------------------------------------------------------

/// Gates filter execution: `When` requires a match, `Unless` skips on match.
///
/// ```
/// use praxis_core::config::Condition;
///
/// let conditions: Vec<Condition> = serde_yaml::from_str(
///     r#"
/// - when:
///     path_prefix: "/api"
/// - unless:
///     methods: ["OPTIONS"]
/// "#,
/// )
/// .unwrap();
/// assert_eq!(conditions.len(), 2);
/// ```
#[derive(Debug, Clone)]
pub enum Condition {
    /// Execute the filter only if the predicate matches.
    When(ConditionMatch),

    /// Skip the filter if the predicate matches.
    Unless(ConditionMatch),
}

impl_condition_deserialize!(Condition, ConditionMatch, "condition");

// -----------------------------------------------------------------------------
// ConditionMatch
// -----------------------------------------------------------------------------

/// Match predicate for a condition (AND semantics).
///
/// ```
/// use praxis_core::config::ConditionMatch;
///
/// let m: ConditionMatch = serde_yaml::from_str(
///     r#"
/// path_prefix: "/api"
/// methods: ["GET", "POST"]
/// "#,
/// )
/// .unwrap();
/// assert_eq!(m.path_prefix.as_deref(), Some("/api"));
/// assert_eq!(m.methods.as_ref().unwrap().len(), 2);
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionMatch {
    /// Request URI must match this exact path.
    #[serde(default)]
    pub path: Option<String>,

    /// Request URI must start with this prefix.
    #[serde(default)]
    pub path_prefix: Option<String>,

    /// Request method must be one of these (case-insensitive).
    #[serde(default)]
    pub methods: Option<Vec<String>>,

    /// Headers that must be present and match.
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
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
    fn parse_condition_match_all_fields() {
        let yaml = r#"
path_prefix: "/api"
methods: ["GET", "POST"]
headers:
  x-tenant: "acme"
  x-debug: "true"
"#;
        let m: ConditionMatch = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(m.path_prefix.as_deref(), Some("/api"), "path_prefix mismatch");
        let methods = m.methods.unwrap();
        assert_eq!(methods, vec!["GET", "POST"], "methods mismatch");
        let headers = m.headers.unwrap();
        assert_eq!(headers.get("x-tenant").unwrap(), "acme", "x-tenant header mismatch");
        assert_eq!(headers.get("x-debug").unwrap(), "true", "x-debug header mismatch");
    }

    #[test]
    fn parse_condition_match_partial() {
        let yaml = r#"
path_prefix: "/health"
"#;
        let m: ConditionMatch = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(m.path_prefix.as_deref(), Some("/health"), "path_prefix mismatch");
        assert!(m.methods.is_none(), "methods should be None when omitted");
        assert!(m.headers.is_none(), "headers should be None when omitted");
    }

    #[test]
    fn parse_when_condition() {
        let yaml = r#"
- when:
    path_prefix: "/api"
"#;
        let conditions: Vec<Condition> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(conditions.len(), 1, "should parse 1 condition");
        assert!(
            matches!(&conditions[0], Condition::When(m) if m.path_prefix.as_deref() == Some("/api")),
            "should be When with /api prefix"
        );
    }

    #[test]
    fn parse_unless_condition() {
        let yaml = r#"
- unless:
    methods: ["OPTIONS"]
"#;
        let conditions: Vec<Condition> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(conditions.len(), 1, "should parse 1 condition");
        assert!(
            matches!(&conditions[0], Condition::Unless(m) if m.methods.as_ref().unwrap() == &["OPTIONS"]),
            "should be Unless with OPTIONS method"
        );
    }

    #[test]
    fn parse_mixed_conditions() {
        let yaml = r#"
- when:
    path_prefix: "/api"
- unless:
    headers:
      x-internal: "true"
- when:
    methods: ["POST", "PUT", "DELETE"]
"#;
        let conditions: Vec<Condition> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(conditions.len(), 3, "should parse 3 conditions");
        assert!(matches!(&conditions[0], Condition::When(_)), "first should be When");
        assert!(
            matches!(&conditions[1], Condition::Unless(_)),
            "second should be Unless"
        );
        assert!(matches!(&conditions[2], Condition::When(_)), "third should be When");
    }

    #[test]
    fn parse_empty_conditions() {
        let conditions: Vec<Condition> = serde_yaml::from_str("[]").unwrap();
        assert!(conditions.is_empty(), "empty array should parse to empty vec");
    }

    #[test]
    fn reject_both_when_and_unless() {
        let yaml = r#"
- when:
    path_prefix: "/api"
  unless:
    methods: ["GET"]
"#;
        let err = serde_yaml::from_str::<Vec<Condition>>(yaml).unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn reject_neither_when_nor_unless() {
        let yaml = "- {}";
        let err = serde_yaml::from_str::<Vec<Condition>>(yaml).unwrap_err();
        assert!(err.to_string().contains("either"));
    }

    #[test]
    fn parse_exact_path_condition() {
        let m: ConditionMatch = serde_yaml::from_str(
            r#"
path: "/"
"#,
        )
        .unwrap();
        assert_eq!(m.path.as_deref(), Some("/"), "exact path should be /");
        assert!(
            m.path_prefix.is_none(),
            "path_prefix should be None for exact path match"
        );
    }
}
