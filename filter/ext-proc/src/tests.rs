// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]

use praxis_filter::parse_filter_config;

use super::*;

// -----------------------------------------------------------------------------
// Config Parsing
// -----------------------------------------------------------------------------

#[tokio::test]
async fn parse_valid_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
message_timeout_ms: 500
"#,
    )
    .unwrap();

    let filter = ExtProcFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "ext_proc");
}

#[tokio::test]
async fn parse_minimal_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(r#"target: "http://127.0.0.1:50051""#).unwrap();
    let filter = ExtProcFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "ext_proc");
}

#[tokio::test]
async fn parse_full_config_with_processing_mode() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
message_timeout_ms: 500
max_message_timeout_ms: 5000
processing_mode:
  request_header_mode: send
  response_header_mode: send
  request_body_mode: none
  response_body_mode: none
  request_trailer_mode: skip
  response_trailer_mode: skip
"#,
    )
    .unwrap();

    let filter = ExtProcFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "ext_proc");
}

#[test]
fn defaults_core_fields() {
    let cfg = minimal_config();

    assert_eq!(
        cfg.message_timeout_ms, DEFAULT_MESSAGE_TIMEOUT_MS,
        "default message_timeout_ms should be {DEFAULT_MESSAGE_TIMEOUT_MS}"
    );
    assert_eq!(
        cfg.status_on_error, DEFAULT_STATUS_ON_ERROR,
        "default status_on_error should be {DEFAULT_STATUS_ON_ERROR}"
    );
    assert!(
        cfg.max_message_timeout_ms.is_none(),
        "default max_message_timeout_ms should be None"
    );
    assert_eq!(
        cfg.deferred_close_timeout_ms, DEFAULT_DEFERRED_CLOSE_TIMEOUT_MS,
        "default deferred_close_timeout_ms should be {DEFAULT_DEFERRED_CLOSE_TIMEOUT_MS}"
    );
}

#[test]
fn defaults_processing_mode() {
    let cfg = minimal_config();

    assert_eq!(cfg.processing_mode.request_header_mode, HeaderSendMode::Send);
    assert_eq!(cfg.processing_mode.response_header_mode, HeaderSendMode::Send);
    assert_eq!(cfg.processing_mode.request_body_mode, BodySendMode::None);
    assert_eq!(cfg.processing_mode.response_body_mode, BodySendMode::None);
    assert_eq!(cfg.processing_mode.request_trailer_mode, HeaderSendMode::Skip);
    assert_eq!(cfg.processing_mode.response_trailer_mode, HeaderSendMode::Skip);
}

#[test]
fn defaults_feature_flags() {
    let cfg = minimal_config();

    assert!(!cfg.allow_mode_override, "default allow_mode_override should be false");
    assert!(!cfg.observability_mode, "default observability_mode should be false");
    assert!(
        !cfg.disable_immediate_response,
        "default disable_immediate_response should be false"
    );
    assert!(
        !cfg.allow_content_length_header,
        "default allow_content_length_header should be false"
    );
    assert!(
        !cfg.send_body_without_waiting_for_header_response,
        "default send_body_without_waiting should be false"
    );
    assert!(
        cfg.allowed_override_modes.is_empty(),
        "default allowed_override_modes should be empty"
    );
    assert!(cfg.mutation_rules.is_none(), "default mutation_rules should be None");
    assert!(cfg.forward_rules.is_none(), "default forward_rules should be None");
}

#[tokio::test]
async fn missing_target_errors() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("message_timeout_ms: 500").unwrap();
    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("target"),
        "error should mention missing target field: {err}"
    );
}

#[tokio::test]
async fn invalid_target_uri_errors() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "not a valid uri"
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("invalid target URI"),
        "error should mention invalid target URI: {err}"
    );
}

#[tokio::test]
async fn unknown_field_errors() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
bogus_field: true
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("unknown field"),
        "error should mention unknown field: {err}"
    );
}

// -----------------------------------------------------------------------------
// Unsupported Feature Validation
// -----------------------------------------------------------------------------

#[tokio::test]
async fn rejects_request_header_mode_skip() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
processing_mode:
  request_header_mode: skip
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("request_header_mode"),
        "error should mention request_header_mode: {err}"
    );
}

#[tokio::test]
async fn rejects_response_header_mode_skip() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
processing_mode:
  response_header_mode: skip
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("response_header_mode"),
        "error should mention response_header_mode: {err}"
    );
}

#[tokio::test]
async fn rejects_request_trailer_mode_send() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
processing_mode:
  request_trailer_mode: send
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("request_trailer_mode"),
        "error should mention request_trailer_mode: {err}"
    );
}

#[tokio::test]
async fn rejects_response_trailer_mode_send() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
processing_mode:
  response_trailer_mode: send
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("response_trailer_mode"),
        "error should mention response_trailer_mode: {err}"
    );
}

#[tokio::test]
async fn rejects_allow_mode_override() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
allow_mode_override: true
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("allow_mode_override"),
        "error should mention allow_mode_override: {err}"
    );
}

#[tokio::test]
async fn rejects_observability_mode() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
observability_mode: true
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("observability_mode"),
        "error should mention observability_mode: {err}"
    );
}

#[tokio::test]
async fn rejects_disable_immediate_response() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
disable_immediate_response: true
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("disable_immediate_response"),
        "error should mention disable_immediate_response: {err}"
    );
}

#[tokio::test]
async fn rejects_mutation_rules() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
mutation_rules:
  allow: ["x-custom"]
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("mutation_rules"),
        "error should mention mutation_rules: {err}"
    );
}

#[tokio::test]
async fn rejects_forward_rules() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
forward_rules:
  allowed_headers: ["content-type"]
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("forward_rules"),
        "error should mention forward_rules: {err}"
    );
}

#[tokio::test]
async fn rejects_allow_content_length_header() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
allow_content_length_header: true
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("allow_content_length_header"),
        "error should mention allow_content_length_header: {err}"
    );
}

#[tokio::test]
async fn rejects_send_body_without_waiting() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
send_body_without_waiting_for_header_response: true
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string()
            .contains("send_body_without_waiting_for_header_response"),
        "error should mention send_body_without_waiting_for_header_response: {err}"
    );
}

#[tokio::test]
async fn accepts_custom_status_on_error() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
status_on_error: 503
"#,
    )
    .unwrap();

    let filter = ExtProcFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "ext_proc");
}

#[tokio::test]
async fn accepts_custom_deferred_close_timeout() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
deferred_close_timeout_ms: 10000
"#,
    )
    .unwrap();

    let filter = ExtProcFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "ext_proc");
}

#[tokio::test]
async fn rejects_all_request_body_send_mode_variants() {
    for mode in ["streamed", "buffered", "buffered_partial", "full_duplex_streamed"] {
        let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
            r#"
target: "http://127.0.0.1:50051"
processing_mode:
  request_body_mode: {mode}
"#,
        ))
        .unwrap();

        let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
        assert!(
            err.to_string().contains("request_body_mode"),
            "{mode} error should mention request_body_mode: {err}"
        );
        assert!(
            err.to_string().contains("not yet supported"),
            "{mode} should parse but fail validation: {err}"
        );
    }
}

#[tokio::test]
async fn rejects_all_response_body_send_mode_variants() {
    for mode in ["streamed", "buffered", "buffered_partial", "full_duplex_streamed"] {
        let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
            r#"
target: "http://127.0.0.1:50051"
processing_mode:
  response_body_mode: {mode}
"#,
        ))
        .unwrap();

        let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
        assert!(
            err.to_string().contains("response_body_mode"),
            "{mode} error should mention response_body_mode: {err}"
        );
        assert!(
            err.to_string().contains("not yet supported"),
            "{mode} should parse but fail validation: {err}"
        );
    }
}

#[tokio::test]
async fn rejects_status_on_error_zero() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
status_on_error: 0
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("status_on_error"),
        "error should mention status_on_error: {err}"
    );
}

#[tokio::test]
async fn rejects_status_on_error_out_of_range() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
status_on_error: 600
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("status_on_error"),
        "error should mention status_on_error: {err}"
    );
}

#[tokio::test]
async fn rejects_message_timeout_ms_zero() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
message_timeout_ms: 0
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("message_timeout_ms"),
        "error should reject message_timeout_ms set to 0: {err}"
    );
}

#[tokio::test]
async fn rejects_max_message_timeout_ms_zero() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
max_message_timeout_ms: 0
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("max_message_timeout_ms"),
        "error should reject max_message_timeout_ms set to 0: {err}"
    );
}

#[tokio::test]
async fn rejects_max_message_timeout_ms_less_than_message_timeout_ms() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
message_timeout_ms: 500
max_message_timeout_ms: 100
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("max_message_timeout_ms"),
        "error should reject max_message_timeout_ms less than message_timeout_ms: {err}"
    );
}

#[tokio::test]
async fn rejects_allowed_override_modes_with_entries() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
allowed_override_modes:
  - request_header_mode: send
    response_header_mode: send
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("allowed_override_modes"),
        "error should mention allowed_override_modes: {err}"
    );
}

// -----------------------------------------------------------------------------
// Pipeline-Level failure_mode
// -----------------------------------------------------------------------------

#[tokio::test]
async fn failure_mode_in_yaml_is_stripped_by_parse() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
failure_mode: open
"#,
    )
    .unwrap();

    let filter = ExtProcFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "ext_proc",
        "failure_mode should be stripped as a structural key and not cause an unknown-field error"
    );
}

#[tokio::test]
async fn filter_entry_captures_failure_mode_open() {
    let entry: praxis_filter::FilterEntry = serde_yaml::from_str(
        r#"
filter: ext_proc
failure_mode: open
target: "http://127.0.0.1:50051"
"#,
    )
    .unwrap();

    assert_eq!(
        entry.failure_mode,
        praxis_filter::FailureMode::Open,
        "FilterEntry should capture failure_mode: open"
    );

    let filter = ExtProcFilter::from_config(&entry.config).unwrap();
    assert_eq!(
        filter.name(),
        "ext_proc",
        "filter should build from the entry config after structural key stripping"
    );
}

#[tokio::test]
async fn filter_entry_captures_failure_mode_closed() {
    let entry: praxis_filter::FilterEntry = serde_yaml::from_str(
        r#"
filter: ext_proc
failure_mode: closed
target: "http://127.0.0.1:50051"
message_timeout_ms: 300
"#,
    )
    .unwrap();

    assert_eq!(
        entry.failure_mode,
        praxis_filter::FailureMode::Closed,
        "FilterEntry should capture failure_mode: closed"
    );

    let filter = ExtProcFilter::from_config(&entry.config).unwrap();
    assert_eq!(
        filter.name(),
        "ext_proc",
        "filter should build from the entry config after structural key stripping"
    );
}

#[tokio::test]
async fn filter_entry_defaults_failure_mode_to_closed() {
    let entry: praxis_filter::FilterEntry = serde_yaml::from_str(
        r#"
filter: ext_proc
target: "http://127.0.0.1:50051"
"#,
    )
    .unwrap();

    assert_eq!(
        entry.failure_mode,
        praxis_filter::FailureMode::Closed,
        "FilterEntry should default failure_mode to Closed"
    );

    let filter = ExtProcFilter::from_config(&entry.config).unwrap();
    assert_eq!(
        filter.name(),
        "ext_proc",
        "filter should build from the entry config without failure_mode"
    );
}

#[tokio::test]
async fn pipeline_builds_with_ext_proc_and_failure_mode() {
    let mut registry = praxis_filter::FilterRegistry::with_builtins();
    registry
        .register("ext_proc", praxis_filter::http_builtin(ExtProcFilter::from_config))
        .unwrap();

    let mut entries: Vec<praxis_filter::FilterEntry> = serde_yaml::from_str(
        r#"
- filter: ext_proc
  failure_mode: open
  target: "http://127.0.0.1:50051"
- filter: ext_proc
  failure_mode: closed
  target: "http://127.0.0.1:50052"
"#,
    )
    .unwrap();

    let pipeline = praxis_filter::FilterPipeline::build(&mut entries, &registry).unwrap();
    assert_eq!(pipeline.len(), 2, "pipeline should contain both ext_proc filters");
}

#[tokio::test]
async fn rejects_negative_max_message_timeout_ms() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
max_message_timeout_ms: -1
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("max_message_timeout_ms") || err.to_string().contains("integer"),
        "error should reject negative max_message_timeout_ms: {err}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Parse a minimal valid config for default-checking tests.
fn minimal_config() -> ExtProcConfig {
    let yaml: serde_yaml::Value = serde_yaml::from_str(r#"target: "http://127.0.0.1:50051""#).unwrap();
    parse_filter_config("ext_proc", &yaml).unwrap()
}
