// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Unit tests for the `anthropic_validate` filter.

use super::*;

// -----------------------------------------------------------------------------
// Validation Logic
// -----------------------------------------------------------------------------

#[test]
fn valid_request_passes() {
    let body = br#"{"model":"claude-opus-4-8","max_tokens":1024,"messages":[{"role":"user","content":"Hi"}]}"#;
    assert!(validate_request(body).is_none(), "valid request should pass");
}

#[test]
fn backend_owned_semantics_pass() {
    let body = br#"{"model":"","max_tokens":0,"messages":[]}"#;
    assert!(
        validate_request(body).is_none(),
        "backend-owned Anthropic semantics should be deferred"
    );
}

#[test]
fn missing_backend_owned_fields_pass() {
    let body = br#"{"metadata":{"tenant":"blue"}}"#;
    assert!(
        validate_request(body).is_none(),
        "required Anthropic fields should be validated by the backend"
    );
}

#[test]
fn invalid_json_rejected() {
    let body = b"not json {{{";
    let rejection = validate_request(body);
    assert!(rejection.is_some(), "invalid JSON should be rejected");
}

#[test]
fn non_object_json_rejected() {
    let body = br#"[]"#;
    let rejection = validate_request(body);
    assert!(rejection.is_some(), "non-object JSON should be rejected");
}

#[tokio::test]
async fn empty_body_rejected_by_filter() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let filter = AnthropicValidateFilter::from_config(&yaml).unwrap();
    let req = Box::leak(Box::new(crate::test_utils::make_request(
        http::Method::POST,
        "/v1/messages",
    )));
    let mut ctx = crate::test_utils::make_filter_context(req);
    let mut body = Some(Bytes::new());

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Reject(_)),
        "empty body should be rejected"
    );
}

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

#[test]
fn default_config_parses() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let filter = AnthropicValidateFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "anthropic_validate",
        "filter name should be anthropic_validate"
    );
}

#[test]
fn zero_max_body_bytes_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("max_body_bytes: 0").unwrap();
    let result = AnthropicValidateFilter::from_config(&yaml);
    assert!(result.is_err(), "zero max_body_bytes should be rejected");
}

#[test]
fn rejects_max_body_bytes_above_ceiling() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("max_body_bytes: 67108865").unwrap();
    let result = AnthropicValidateFilter::from_config(&yaml);

    assert!(
        result.is_err(),
        "max_body_bytes above 64 MiB ceiling should be rejected"
    );
}
