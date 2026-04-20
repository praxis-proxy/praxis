// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Response-phase condition predicates that gate filter execution.

use std::collections::HashMap;

use serde::Deserialize;

use super::impl_condition_deserialize;

// -----------------------------------------------------------------------------
// ResponseCondition
// -----------------------------------------------------------------------------

/// Gates filter execution during the response phase.
///
/// ```
/// use praxis_core::config::ResponseCondition;
///
/// let conditions: Vec<ResponseCondition> = serde_yaml::from_str(
///     r#"
/// - when:
///     status: [200, 201]
/// - unless:
///     headers:
///       x-skip-filter: "true"
/// "#,
/// )
/// .unwrap();
/// assert_eq!(conditions.len(), 2);
/// ```
#[derive(Debug, Clone)]
pub enum ResponseCondition {
    /// Execute the filter only if the response predicate matches.
    When(ResponseConditionMatch),

    /// Skip the filter if the response predicate matches.
    Unless(ResponseConditionMatch),
}

impl_condition_deserialize!(ResponseCondition, ResponseConditionMatch, "response condition");

// -----------------------------------------------------------------------------
// ResponseConditionMatch
// -----------------------------------------------------------------------------

/// Match predicate for a response condition.
///
/// ```
/// use praxis_core::config::ResponseConditionMatch;
///
/// let m: ResponseConditionMatch = serde_yaml::from_str(
///     r#"
/// status: [200, 201]
/// headers:
///   content-type: "application/json"
/// "#,
/// )
/// .unwrap();
/// assert_eq!(m.status.as_ref().unwrap(), &[200, 201]);
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseConditionMatch {
    /// Response status code must be one of these.
    #[serde(default)]
    pub status: Option<Vec<u16>>,

    /// Response headers that must be present and match.
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
    fn parse_response_condition_when_status() {
        let yaml = r#"
- when:
    status: [200, 201]
"#;
        let conds: Vec<ResponseCondition> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(conds.len(), 1, "should parse 1 condition");
        assert!(
            matches!(
                &conds[0],
                ResponseCondition::When(m) if m.status.as_ref().unwrap() == &[200, 201]
            ),
            "should be When condition with status [200, 201]"
        );
    }

    #[test]
    fn parse_response_condition_unless_headers() {
        let yaml = r#"
- unless:
    headers:
      x-skip: "true"
"#;
        let conds: Vec<ResponseCondition> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(conds.len(), 1, "should parse 1 condition");
        assert!(
            matches!(&conds[0], ResponseCondition::Unless(m) if m.headers.is_some()),
            "should be Unless condition with headers"
        );
    }

    #[test]
    fn parse_response_condition_all_fields() {
        let yaml = r#"
status: [500, 502, 503]
headers:
  content-type: "text/html"
"#;
        let m: ResponseConditionMatch = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(m.status.as_ref().unwrap(), &[500, 502, 503], "status codes mismatch");
        assert_eq!(
            m.headers.as_ref().unwrap().get("content-type").unwrap(),
            "text/html",
            "content-type header mismatch"
        );
    }

    #[test]
    fn parse_empty_response_conditions() {
        let conds: Vec<ResponseCondition> = serde_yaml::from_str("[]").unwrap();
        assert!(conds.is_empty(), "empty array should parse to empty vec");
    }

    #[test]
    fn reject_response_condition_neither() {
        let yaml = "- {}";
        let err = serde_yaml::from_str::<Vec<ResponseCondition>>(yaml).unwrap_err();
        assert!(err.to_string().contains("either"));
    }

    #[test]
    fn reject_response_condition_both() {
        let yaml = r#"
- when:
    status: [200]
  unless:
    status: [500]
"#;
        let err = serde_yaml::from_str::<Vec<ResponseCondition>>(yaml).unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }
}
