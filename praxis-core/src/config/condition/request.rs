//! Request-phase condition predicates that gate filter execution.

use std::collections::HashMap;

use serde::{
    Deserialize,
    de::{self, Deserializer},
};

// -----------------------------------------------------------------------------
// Condition
// -----------------------------------------------------------------------------

/// Gates filter execution: `When` requires a match, `Unless` skips on match.
///
/// ```
/// use praxis_core::config::Condition;
///
/// let conditions: Vec<Condition> = serde_yaml::from_str(r#"
/// - when:
///     path_prefix: "/api"
/// - unless:
///     methods: ["OPTIONS"]
/// "#).unwrap();
/// assert_eq!(conditions.len(), 2);
/// ```
#[derive(Debug, Clone)]

pub enum Condition {
    /// Execute the filter only if the predicate matches.
    When(ConditionMatch),

    /// Skip the filter if the predicate matches.
    Unless(ConditionMatch),
}

impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let helper = ConditionHelper::deserialize(deserializer)?;
        match (helper.when, helper.unless) {
            (Some(m), None) => Ok(Condition::When(m)),
            (None, Some(m)) => Ok(Condition::Unless(m)),
            (Some(_), Some(_)) => Err(de::Error::custom(
                "condition must have exactly one of 'when' or 'unless', not both",
            )),
            (None, None) => Err(de::Error::custom("condition must have either 'when' or 'unless'")),
        }
    }
}

// -----------------------------------------------------------------------------
// ConditionMatch
// -----------------------------------------------------------------------------

/// Match predicate for a condition (AND semantics).
///
/// ```
/// use praxis_core::config::ConditionMatch;
///
/// let m: ConditionMatch = serde_yaml::from_str(r#"
/// path_prefix: "/api"
/// methods: ["GET", "POST"]
/// "#).unwrap();
/// assert_eq!(m.path_prefix.as_deref(), Some("/api"));
/// assert_eq!(m.methods.as_ref().unwrap().len(), 2);
/// ```
#[derive(Debug, Clone, Deserialize)]

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
// ConditionHelper
// -----------------------------------------------------------------------------

/// Helper for deserializing a [`Condition`] from a YAML map with a single
/// `when` or `unless` key.
#[derive(Deserialize)]

struct ConditionHelper {
    /// The `when` predicate, if present.
    #[serde(default)]
    when: Option<ConditionMatch>,

    /// The `unless` predicate, if present.
    #[serde(default)]
    unless: Option<ConditionMatch>,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
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
        assert_eq!(m.path_prefix.as_deref(), Some("/api"));

        let methods = m.methods.unwrap();
        assert_eq!(methods, vec!["GET", "POST"]);

        let headers = m.headers.unwrap();
        assert_eq!(headers.get("x-tenant").unwrap(), "acme");
        assert_eq!(headers.get("x-debug").unwrap(), "true");
    }

    #[test]
    fn parse_condition_match_partial() {
        let yaml = r#"
path_prefix: "/health"
"#;
        let m: ConditionMatch = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(m.path_prefix.as_deref(), Some("/health"));
        assert!(m.methods.is_none());
        assert!(m.headers.is_none());
    }

    #[test]
    fn parse_when_condition() {
        let yaml = r#"
- when:
    path_prefix: "/api"
"#;
        let conditions: Vec<Condition> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(conditions.len(), 1);
        assert!(matches!(&conditions[0], Condition::When(m) if m.path_prefix.as_deref() == Some("/api")));
    }

    #[test]
    fn parse_unless_condition() {
        let yaml = r#"
- unless:
    methods: ["OPTIONS"]
"#;
        let conditions: Vec<Condition> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(conditions.len(), 1);
        assert!(matches!(&conditions[0], Condition::Unless(m) if m.methods.as_ref().unwrap() == &["OPTIONS"]));
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
        assert_eq!(conditions.len(), 3);
        assert!(matches!(&conditions[0], Condition::When(_)));
        assert!(matches!(&conditions[1], Condition::Unless(_)));
        assert!(matches!(&conditions[2], Condition::When(_)));
    }

    #[test]
    fn parse_empty_conditions() {
        let conditions: Vec<Condition> = serde_yaml::from_str("[]").unwrap();
        assert!(conditions.is_empty());
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
        assert_eq!(m.path.as_deref(), Some("/"));
        assert!(m.path_prefix.is_none());
    }
}
