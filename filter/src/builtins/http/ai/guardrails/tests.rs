// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

use super::filter::AiGuardrailsFilter;

// =============================================================================
// General config
// =============================================================================

#[test]
fn valid_config_creates_filter() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
provider:
  type: nemo
  endpoint: "http://nemo:8000/v1/guardrail/checks"
"#,
    )
    .unwrap();

    let filter = AiGuardrailsFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "ai_guardrails");
}

#[test]
fn valid_config_with_all_fields() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
provider:
  type: nemo
  endpoint: "http://nemo:8000/v1/guardrail/checks"
  timeout_ms: 3000
phase:
  request: true
  response: true
"#,
    )
    .unwrap();

    let filter = AiGuardrailsFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "ai_guardrails");
}

#[test]
fn missing_provider_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
phase:
  request: true
",
    )
    .unwrap();

    let result = AiGuardrailsFilter::from_config(&yaml);
    assert!(result.is_err(), "config without provider should fail");
}

#[test]
fn unknown_provider_type_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
provider:
  type: nonexistent
  endpoint: "http://localhost:8000"
"#,
    )
    .unwrap();

    let result = AiGuardrailsFilter::from_config(&yaml);
    assert!(result.is_err(), "unknown provider type should fail");
}

#[test]
fn unknown_field_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
provider:
  type: nemo
  endpoint: "http://nemo:8000/v1/guardrail/checks"
unexpected_field: true
"#,
    )
    .unwrap();

    let result = AiGuardrailsFilter::from_config(&yaml);
    assert!(result.is_err(), "unknown fields should fail with deny_unknown_fields");
}

// =============================================================================
// Pipeline acceptance
// =============================================================================

#[test]
fn registry_creates_filter_by_name() {
    let registry = crate::FilterRegistry::with_builtins();
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
provider:
  type: nemo
  endpoint: "http://nemo:8000/v1/guardrail/checks"
"#,
    )
    .unwrap();

    let filter = registry.create("ai_guardrails", &yaml);
    assert!(filter.is_ok(), "pipeline should accept ai_guardrails filter");
}

// =============================================================================
// NeMo provider config
// =============================================================================

#[test]
fn nemo_missing_endpoint_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
provider:
  type: nemo
",
    )
    .unwrap();

    let result = AiGuardrailsFilter::from_config(&yaml);
    assert!(result.is_err(), "missing endpoint should fail");
}

#[test]
fn nemo_empty_endpoint_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
provider:
  type: nemo
  endpoint: ""
"#,
    )
    .unwrap();

    let result = AiGuardrailsFilter::from_config(&yaml);
    assert!(result.is_err(), "empty endpoint should fail");
}

#[test]
fn nemo_zero_timeout_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
provider:
  type: nemo
  endpoint: "http://nemo:8000/v1/guardrail/checks"
  timeout_ms: 0
"#,
    )
    .unwrap();

    let result = AiGuardrailsFilter::from_config(&yaml);
    assert!(result.is_err(), "zero timeout should fail");
}

// =============================================================================
// HttpFilter trait
// =============================================================================

#[test]
fn body_access_is_read_write() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
provider:
  type: nemo
  endpoint: "http://nemo:8000/v1/guardrail/checks"
"#,
    )
    .unwrap();

    let filter = AiGuardrailsFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.request_body_access(), crate::body::BodyAccess::ReadWrite);
}

#[test]
fn body_mode_is_stream_buffer() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
provider:
  type: nemo
  endpoint: "http://nemo:8000/v1/guardrail/checks"
"#,
    )
    .unwrap();

    let filter = AiGuardrailsFilter::from_config(&yaml).unwrap();
    assert!(
        matches!(
            filter.request_body_mode(),
            crate::body::BodyMode::StreamBuffer { max_bytes: Some(_) }
        ),
        "body mode should be StreamBuffer"
    );
}

#[tokio::test]
async fn on_request_continues() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
provider:
  type: nemo
  endpoint: "http://nemo:8000/v1/guardrail/checks"
"#,
    )
    .unwrap();

    let filter = AiGuardrailsFilter::from_config(&yaml).unwrap();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(matches!(action, crate::FilterAction::Continue));
}

#[tokio::test]
async fn on_request_body_skips_evaluation_when_phase_request_disabled() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
provider:
  type: nemo
  endpoint: "http://nemo:8000/v1/guardrail/checks"
phase:
  request: false
"#,
    )
    .unwrap();

    let filter = AiGuardrailsFilter::from_config(&yaml).unwrap();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{"messages":[{"role":"user","content":"hello"}]}"#;
    let mut body = Some(bytes::Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, crate::FilterAction::Continue),
        "request phase disabled should skip provider and continue"
    );
}

#[tokio::test]
async fn on_request_body_returns_continue_before_end_of_stream() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
provider:
  type: nemo
  endpoint: "http://nemo:8000/v1/guardrail/checks"
"#,
    )
    .unwrap();

    let filter = AiGuardrailsFilter::from_config(&yaml).unwrap();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{"messages":[{"role":"user","content":"hello"}]}"#;
    let mut body = Some(bytes::Bytes::from_static(json));

    // end_of_stream = false: should buffer and continue without calling provider
    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();
    assert!(
        matches!(action, crate::FilterAction::Continue),
        "non-EOS chunk should continue without calling provider"
    );
}
