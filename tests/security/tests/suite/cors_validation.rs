// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! CORS configuration security tests.
//!
//! Verifies that dangerous CORS configurations are rejected at
//! filter construction time to prevent credential theft and
//! origin confusion attacks.

use praxis_filter::FilterRegistry;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn null_origin_with_credentials_rejected() {
    let config: serde_yaml::Value = serde_yaml::from_str(
        r#"
        allow_origins: ["https://example.com"]
        allow_null_origin: true
        allow_credentials: true
        "#,
    )
    .unwrap();

    let registry = FilterRegistry::with_builtins();
    let err = registry
        .create("cors", &config)
        .err()
        .expect("null origin + credentials must be rejected");
    assert!(
        err.to_string().contains("incompatible with allow_null_origin"),
        "expected null-origin-credential rejection: {err}"
    );
}

#[test]
fn wildcard_origin_with_credentials_rejected() {
    let config: serde_yaml::Value = serde_yaml::from_str(
        r#"
        allow_origins: ["*"]
        allow_credentials: true
        "#,
    )
    .unwrap();

    let registry = FilterRegistry::with_builtins();
    let err = registry
        .create("cors", &config)
        .err()
        .expect("wildcard origin + credentials must be rejected");
    assert!(
        err.to_string().contains("allow_credentials"),
        "expected credential-wildcard rejection: {err}"
    );
}

#[test]
fn null_literal_in_origins_rejected() {
    let config: serde_yaml::Value = serde_yaml::from_str(
        r#"
        allow_origins: ["null"]
        "#,
    )
    .unwrap();

    let registry = FilterRegistry::with_builtins();
    let err = registry
        .create("cors", &config)
        .err()
        .expect("literal 'null' in allow_origins must be rejected");
    assert!(
        err.to_string().contains("null"),
        "expected null-literal rejection: {err}"
    );
}

#[test]
fn null_literal_case_insensitive_rejected() {
    let config: serde_yaml::Value = serde_yaml::from_str(
        r#"
        allow_origins: ["NULL"]
        "#,
    )
    .unwrap();

    let registry = FilterRegistry::with_builtins();
    let err = registry
        .create("cors", &config)
        .err()
        .expect("case-insensitive 'NULL' in allow_origins must be rejected");
    assert!(
        err.to_string().contains("null"),
        "expected null-literal case-insensitive rejection: {err}"
    );
}

#[test]
fn null_origin_without_credentials_accepted() {
    let config: serde_yaml::Value = serde_yaml::from_str(
        r#"
        allow_origins: ["https://example.com"]
        allow_null_origin: true
        "#,
    )
    .unwrap();

    let registry = FilterRegistry::with_builtins();
    registry
        .create("cors", &config)
        .expect("null origin without credentials should be accepted");
}

#[test]
fn wildcard_methods_with_credentials_rejected() {
    let config: serde_yaml::Value = serde_yaml::from_str(
        r#"
        allow_origins: ["https://example.com"]
        allow_methods: ["*"]
        allow_credentials: true
        "#,
    )
    .unwrap();

    let registry = FilterRegistry::with_builtins();
    let err = registry
        .create("cors", &config)
        .err()
        .expect("wildcard methods + credentials must be rejected");
    assert!(
        err.to_string().contains("allow_credentials"),
        "expected credential-wildcard-methods rejection: {err}"
    );
}

#[test]
fn wildcard_headers_with_credentials_rejected() {
    let config: serde_yaml::Value = serde_yaml::from_str(
        r#"
        allow_origins: ["https://example.com"]
        allow_headers: ["*"]
        allow_credentials: true
        "#,
    )
    .unwrap();

    let registry = FilterRegistry::with_builtins();
    let err = registry
        .create("cors", &config)
        .err()
        .expect("wildcard headers + credentials must be rejected");
    assert!(
        err.to_string().contains("allow_credentials"),
        "expected credential-wildcard-headers rejection: {err}"
    );
}

#[test]
fn null_literal_mixed_with_valid_origins_rejected() {
    let config: serde_yaml::Value = serde_yaml::from_str(
        r#"
        allow_origins:
          - "https://example.com"
          - "null"
          - "https://other.com"
        "#,
    )
    .unwrap();

    let registry = FilterRegistry::with_builtins();
    let err = registry
        .create("cors", &config)
        .err()
        .expect("null mixed with valid origins must be rejected");
    assert!(
        err.to_string().contains("null"),
        "expected null-literal-mixed rejection: {err}"
    );
}
