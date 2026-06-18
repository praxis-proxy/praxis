// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Guardrails filter configuration validation tests.

use praxis_filter::GuardrailsFilter;

// -----------------------------------------------------------------------------
// Guardrail Constants
// -----------------------------------------------------------------------------

/// Maximum regex pattern length accepted by the guardrails filter.
const MAX_REGEX_PATTERN_LEN: usize = 1024;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn from_config_parses_header_contains() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        rules:
          - target: header
            name: User-Agent
            contains: bad-bot
        "#,
    )
    .unwrap();
    let filter = GuardrailsFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "guardrails", "filter name should be guardrails");
}

#[test]
fn from_config_parses_body_pattern() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        rules:
          - target: body
            pattern: "DROP\\s+TABLE"
        "#,
    )
    .unwrap();
    let filter = GuardrailsFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "guardrails", "body pattern config should parse");
}

#[test]
fn from_config_rejects_empty_rules() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("rules: []").unwrap();
    let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("must not be empty"),
        "should reject empty rules, got: {err}"
    );
}

#[test]
fn from_config_rejects_unknown_target() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        rules:
          - target: cookie
            contains: evil
        "#,
    )
    .unwrap();
    let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("unknown variant"),
        "should reject unknown target, got: {err}"
    );
}

#[test]
fn from_config_rejects_header_without_name() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        rules:
          - target: header
            contains: evil
        "#,
    )
    .unwrap();
    let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("'name' is required"),
        "should require name for header rules, got: {err}"
    );
}

#[test]
fn from_config_rejects_empty_name() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        rules:
          - target: header
            name: ""
            contains: evil
        "#,
    )
    .unwrap();
    let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("'name' must not be empty"),
        "should reject empty name, got: {err}"
    );
}

#[test]
fn from_config_rejects_both_contains_and_pattern() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        rules:
          - target: body
            contains: evil
            pattern: "evil.*"
        "#,
    )
    .unwrap();
    let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("not both"),
        "should reject both matchers, got: {err}"
    );
}

#[test]
fn from_config_rejects_no_matcher() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        rules:
          - target: body
        "#,
    )
    .unwrap();
    let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("must have 'contains' or 'pattern'"),
        "should require a matcher, got: {err}"
    );
}

#[test]
fn from_config_rejects_invalid_regex() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        rules:
          - target: body
            pattern: "[invalid"
        "#,
    )
    .unwrap();
    let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("invalid regex"),
        "should report invalid regex, got: {err}"
    );
}

#[test]
fn from_config_rejects_empty_contains() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        rules:
          - target: body
            contains: ""
        "#,
    )
    .unwrap();
    let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("'contains' must not be empty"),
        "should reject empty contains, got: {err}"
    );
}

#[test]
fn from_config_rejects_empty_pattern() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        rules:
          - target: body
            pattern: ""
        "#,
    )
    .unwrap();
    let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("'pattern' must not be empty"),
        "should reject empty pattern, got: {err}"
    );
}

#[test]
fn from_config_rejects_pattern_exceeding_length_limit() {
    let long_pattern = "a".repeat(MAX_REGEX_PATTERN_LEN + 1);
    let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
        r#"
        rules:
          - target: body
            pattern: "{long_pattern}"
        "#,
    ))
    .unwrap();
    let err = GuardrailsFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("character limit"),
        "should reject oversized pattern, got: {err}"
    );
}

#[test]
fn from_config_accepts_pattern_at_length_limit() {
    let pattern = "a".repeat(MAX_REGEX_PATTERN_LEN);
    let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
        r#"
        rules:
          - target: body
            pattern: "{pattern}"
        "#,
    ))
    .unwrap();
    let filter = GuardrailsFilter::from_config(&yaml);
    assert!(filter.is_ok(), "pattern at exact limit should be accepted");
}

#[test]
fn multi_rule_config_with_negate_parses() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        rules:
          - target: header
            name: User-Agent
            pattern: "bad-bot.*"
          - target: body
            contains: "DROP TABLE"
          - target: header
            name: X-Authorized
            contains: "trusted"
            negate: true
          - target: body
            pattern: "^\\{.*\\}$"
            negate: true
        "#,
    )
    .unwrap();
    let filter = GuardrailsFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "guardrails", "mixed negate config should parse");
}

#[test]
fn negate_defaults_to_false() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        rules:
          - target: body
            contains: evil
        "#,
    )
    .unwrap();
    let filter = GuardrailsFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "guardrails", "negate should default to false");
}
