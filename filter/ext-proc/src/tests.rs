// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

#![expect(
    clippy::items_after_statements,
    clippy::let_underscore_must_use,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::clone_on_ref_ptr,
    clippy::doc_markdown,
    clippy::significant_drop_tightening,
    clippy::too_many_lines,
    reason = "tests"
)]

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};
use praxis_filter::parse_filter_config;
use praxis_proto::envoy::service::{
    common::v3::{HeaderValue, HeaderValueOption, HttpStatus},
    ext_proc::v3::{CommonResponse, HeaderMutation, HeadersResponse, ImmediateResponse},
};

use super::*;
use crate::duplex::{ExchangeConfig, ExchangeError, ExchangeEvent, ExtProcExchange};

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
    let pm = minimal_config().processing_mode;
    assert_eq!(
        pm.request_header_mode,
        HeaderSendMode::Send,
        "default request_header_mode"
    );
    assert_eq!(
        pm.response_header_mode,
        HeaderSendMode::Send,
        "default response_header_mode"
    );
    assert_eq!(pm.request_body_mode, BodySendMode::None, "default request_body_mode");
    assert_eq!(pm.response_body_mode, BodySendMode::None, "default response_body_mode");
    assert_eq!(
        pm.request_trailer_mode,
        HeaderSendMode::Skip,
        "default request_trailer_mode"
    );
    assert_eq!(
        pm.response_trailer_mode,
        HeaderSendMode::Skip,
        "default response_trailer_mode"
    );
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

#[test]
fn accepts_custom_status_on_error() {
    let cfg: ExtProcConfig = parse_filter_config(
        "ext_proc",
        &serde_yaml::from_str(
            r#"target: "http://127.0.0.1:50051"
status_on_error: 503"#,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(cfg.status_on_error, 503, "custom status_on_error should be preserved");
}

#[test]
fn accepts_custom_deferred_close_timeout() {
    let cfg: ExtProcConfig = parse_filter_config(
        "ext_proc",
        &serde_yaml::from_str(
            r#"target: "http://127.0.0.1:50051"
deferred_close_timeout_ms: 10000"#,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        cfg.deferred_close_timeout_ms, 10000,
        "custom deferred_close_timeout_ms should be preserved"
    );
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
async fn rejects_deferred_close_timeout_less_than_message_timeout() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
target: "http://127.0.0.1:50051"
message_timeout_ms: 500
deferred_close_timeout_ms: 100
"#,
    )
    .unwrap();

    let err = ExtProcFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("deferred_close_timeout_ms"),
        "error should reject deferred_close_timeout_ms < message_timeout_ms: {err}"
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
// Proto Conversion: request_to_proto_headers
// -----------------------------------------------------------------------------

#[test]
fn request_to_proto_headers_includes_method_and_path() {
    let req = make_request(Method::POST, "/api/v1/users");
    let ctx = make_ctx(&req);

    let proto = mutations::request_to_proto_headers(&ctx);
    let headers = proto.headers.unwrap().headers;

    let method = headers
        .iter()
        .find(|h| h.key == ":method")
        .expect("should include :method");
    assert_eq!(method.value, "POST", "method pseudo-header should match request method");

    let path = headers.iter().find(|h| h.key == ":path").expect("should include :path");
    assert_eq!(
        path.value, "/api/v1/users",
        "path pseudo-header should match request URI"
    );
}

#[test]
fn request_to_proto_headers_preserves_query_string() {
    let req = make_request(Method::GET, "/search?q=secret&page=1");
    let ctx = make_ctx(&req);

    let proto = mutations::request_to_proto_headers(&ctx);
    let headers = proto.headers.unwrap().headers;

    let path = headers.iter().find(|h| h.key == ":path").expect("should include :path");
    assert_eq!(
        path.value, "/search?q=secret&page=1",
        "path pseudo-header should include query string"
    );
}

#[test]
fn request_to_proto_headers_includes_scheme() {
    let req = make_request(Method::GET, "/");
    let ctx = make_ctx(&req);

    let proto = mutations::request_to_proto_headers(&ctx);
    let headers = proto.headers.unwrap().headers;

    let scheme = headers
        .iter()
        .find(|h| h.key == ":scheme")
        .expect("should include :scheme");
    assert_eq!(scheme.value, "http", "scheme should default to http");
}

#[test]
fn request_to_proto_headers_includes_https_scheme() {
    let req = make_request(Method::GET, "/");
    let mut ctx = make_ctx(&req);
    ctx.downstream_tls = true;

    let proto = mutations::request_to_proto_headers(&ctx);
    let headers = proto.headers.unwrap().headers;

    let scheme = headers
        .iter()
        .find(|h| h.key == ":scheme")
        .expect("should include :scheme");
    assert_eq!(scheme.value, "https", "scheme should be https when TLS is active");
}

#[test]
fn request_to_proto_headers_includes_authority() {
    let mut req = make_request(Method::GET, "/");
    req.headers.insert("host", "example.com".parse().unwrap());
    let ctx = make_ctx(&req);

    let proto = mutations::request_to_proto_headers(&ctx);
    let headers = proto.headers.unwrap().headers;

    let authority = headers
        .iter()
        .find(|h| h.key == ":authority")
        .expect("should include :authority");
    assert_eq!(authority.value, "example.com", "authority should match host header");
}

#[test]
fn request_to_proto_headers_omits_authority_when_no_host() {
    let req = make_request(Method::GET, "/");
    let ctx = make_ctx(&req);

    let proto = mutations::request_to_proto_headers(&ctx);
    let headers = proto.headers.unwrap().headers;

    assert!(
        headers.iter().all(|h| h.key != ":authority"),
        "should not include :authority when host header is absent"
    );
}

#[test]
fn request_to_proto_headers_includes_request_headers() {
    let mut req = make_request(Method::GET, "/");
    req.headers.insert("content-type", "application/json".parse().unwrap());
    req.headers.insert("x-request-id", "abc-123".parse().unwrap());
    let ctx = make_ctx(&req);

    let proto = mutations::request_to_proto_headers(&ctx);
    let headers = proto.headers.unwrap().headers;

    let ct = headers
        .iter()
        .find(|h| h.key == "content-type")
        .expect("should include content-type");
    assert_eq!(ct.value, "application/json", "content-type should match");

    let rid = headers
        .iter()
        .find(|h| h.key == "x-request-id")
        .expect("should include x-request-id");
    assert_eq!(rid.value, "abc-123", "x-request-id should match");
}

// -----------------------------------------------------------------------------
// Proto Conversion: response_to_proto_headers
// -----------------------------------------------------------------------------

#[test]
fn response_to_proto_headers_includes_status() {
    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    resp.status = StatusCode::NOT_FOUND;
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let proto = mutations::response_to_proto_headers(&ctx);
    let headers = proto.headers.unwrap().headers;

    let status = headers
        .iter()
        .find(|h| h.key == ":status")
        .expect("should include :status");
    assert_eq!(status.value, "404", "status pseudo-header should match response status");
}

#[test]
fn response_to_proto_headers_includes_response_headers() {
    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    resp.headers.insert("x-powered-by", "praxis".parse().unwrap());
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let proto = mutations::response_to_proto_headers(&ctx);
    let headers = proto.headers.unwrap().headers;

    let hdr = headers
        .iter()
        .find(|h| h.key == "x-powered-by")
        .expect("should include x-powered-by");
    assert_eq!(hdr.value, "praxis", "x-powered-by value should match");
}

#[test]
fn response_to_proto_headers_empty_when_no_response() {
    let req = make_request(Method::GET, "/");
    let ctx = make_ctx(&req);

    let proto = mutations::response_to_proto_headers(&ctx);
    let headers = proto.headers.unwrap().headers;
    assert!(
        headers.is_empty(),
        "headers should be empty when response_header is None"
    );
}

// -----------------------------------------------------------------------------
// Mutation: apply_request_header_mutation
// -----------------------------------------------------------------------------

#[test]
fn apply_request_header_mutation_adds_to_extra_headers() {
    let req = make_request(Method::GET, "/");
    let mut ctx = make_ctx(&req);

    let mutation = HeaderMutation {
        set_headers: vec![make_hvo("x-custom", "value1")],
        remove_headers: vec![],
    };

    mutations::apply_request_header_mutation(&mutation, &mut ctx);

    assert_eq!(ctx.extra_request_headers.len(), 1, "should add one header");
    assert_eq!(ctx.extra_request_headers[0].0, "x-custom", "header name should match");
    assert_eq!(ctx.extra_request_headers[0].1, "value1", "header value should match");
}

#[test]
fn apply_request_header_mutation_skips_pseudo_headers() {
    let req = make_request(Method::GET, "/");
    let mut ctx = make_ctx(&req);

    let mutation = HeaderMutation {
        set_headers: vec![
            make_hvo(":method", "POST"),
            make_hvo(":path", "/new"),
            make_hvo("x-real", "kept"),
        ],
        remove_headers: vec![],
    };

    mutations::apply_request_header_mutation(&mutation, &mut ctx);

    assert_eq!(ctx.extra_request_headers.len(), 1, "should skip pseudo-headers");
    assert_eq!(
        ctx.extra_request_headers[0].0, "x-real",
        "only non-pseudo header should be added"
    );
}

#[test]
fn apply_request_header_mutation_removes_header() {
    let mut req = make_request(Method::GET, "/");
    req.headers.insert("x-remove-me", "gone".parse().unwrap());
    let mut ctx = make_ctx(&req);

    let mutation = HeaderMutation {
        set_headers: vec![],
        remove_headers: vec!["x-remove-me".to_owned()],
    };

    mutations::apply_request_header_mutation(&mutation, &mut ctx);

    assert_eq!(
        ctx.request_headers_to_remove.len(),
        1,
        "should queue one header for removal"
    );
    assert_eq!(
        ctx.request_headers_to_remove[0].as_str(),
        "x-remove-me",
        "removed header name should match"
    );
}

#[test]
fn apply_request_header_mutation_removal_skips_pseudo_headers() {
    let req = make_request(Method::GET, "/");
    let mut ctx = make_ctx(&req);

    let mutation = HeaderMutation {
        set_headers: vec![],
        remove_headers: vec![":method".to_owned(), ":path".to_owned()],
    };

    mutations::apply_request_header_mutation(&mutation, &mut ctx);

    assert!(
        ctx.request_headers_to_remove.is_empty(),
        "pseudo-header removals should be skipped"
    );
}

#[test]
fn apply_request_header_mutation_overwrite_uses_set_queue() {
    use praxis_proto::envoy::service::common::v3::header_value_option::HeaderAppendAction;

    let mut req = make_request(Method::GET, "/");
    req.headers.insert("x-existing", "old".parse().unwrap());
    let mut ctx = make_ctx(&req);

    let hvo = make_hvo_with_append(
        "x-existing",
        "new",
        HeaderAppendAction::OverwriteIfExistsOrAdd as i32,
        None,
    );
    let mutation = HeaderMutation {
        set_headers: vec![hvo],
        remove_headers: vec![],
    };

    mutations::apply_request_header_mutation(&mutation, &mut ctx);

    assert!(
        ctx.extra_request_headers.is_empty(),
        "overwrite should not use extra_request_headers"
    );
    assert_eq!(
        ctx.request_headers_to_set.len(),
        1,
        "overwrite should use request_headers_to_set"
    );
    assert_eq!(
        ctx.request_headers_to_set[0].0.as_str(),
        "x-existing",
        "name should match"
    );
    assert_eq!(ctx.request_headers_to_set[0].1, "new", "value should match");
}

#[test]
fn apply_request_header_mutation_overwrite_if_exists_skips_absent() {
    use praxis_proto::envoy::service::common::v3::header_value_option::HeaderAppendAction;

    let req = make_request(Method::GET, "/");
    let mut ctx = make_ctx(&req);

    let hvo = make_hvo_with_append("x-absent", "value", HeaderAppendAction::OverwriteIfExists as i32, None);
    let mutation = HeaderMutation {
        set_headers: vec![hvo],
        remove_headers: vec![],
    };

    mutations::apply_request_header_mutation(&mutation, &mut ctx);

    assert!(
        ctx.request_headers_to_set.is_empty(),
        "overwrite-if-exists should skip absent headers"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "should not fall through to append"
    );
}

#[test]
fn apply_request_header_mutation_overwrite_if_exists_replaces_present() {
    use praxis_proto::envoy::service::common::v3::header_value_option::HeaderAppendAction;

    let mut req = make_request(Method::GET, "/");
    req.headers.insert("x-existing", "old".parse().unwrap());
    let mut ctx = make_ctx(&req);

    let hvo = make_hvo_with_append("x-existing", "new", HeaderAppendAction::OverwriteIfExists as i32, None);
    let mutation = HeaderMutation {
        set_headers: vec![hvo],
        remove_headers: vec![],
    };

    mutations::apply_request_header_mutation(&mutation, &mut ctx);

    assert!(
        ctx.extra_request_headers.is_empty(),
        "overwrite-if-exists should not use extra_request_headers"
    );
    assert_eq!(
        ctx.request_headers_to_set.len(),
        1,
        "overwrite-if-exists should use request_headers_to_set when present"
    );
    assert_eq!(ctx.request_headers_to_set[0].1, "new", "value should match");
}

#[test]
fn apply_request_header_mutation_add_if_absent_skips_existing() {
    use praxis_proto::envoy::service::common::v3::header_value_option::HeaderAppendAction;

    let mut req = make_request(Method::GET, "/");
    req.headers.insert("x-existing", "old".parse().unwrap());
    let mut ctx = make_ctx(&req);

    let hvo = make_hvo_with_append("x-existing", "new", HeaderAppendAction::AddIfAbsent as i32, None);
    let mutation = HeaderMutation {
        set_headers: vec![hvo],
        remove_headers: vec![],
    };

    mutations::apply_request_header_mutation(&mutation, &mut ctx);

    assert!(
        ctx.extra_request_headers.is_empty(),
        "add-if-absent should skip existing headers"
    );
}

#[test]
fn apply_request_header_mutation_add_if_absent_adds_missing() {
    use praxis_proto::envoy::service::common::v3::header_value_option::HeaderAppendAction;

    let req = make_request(Method::GET, "/");
    let mut ctx = make_ctx(&req);

    let hvo = make_hvo_with_append("x-new", "value", HeaderAppendAction::AddIfAbsent as i32, None);
    let mutation = HeaderMutation {
        set_headers: vec![hvo],
        remove_headers: vec![],
    };

    mutations::apply_request_header_mutation(&mutation, &mut ctx);

    assert_eq!(
        ctx.extra_request_headers.len(),
        1,
        "add-if-absent should add missing headers"
    );
    assert_eq!(ctx.extra_request_headers[0].0, "x-new", "header name should match");
}

// -----------------------------------------------------------------------------
// Mutation: apply_response_header_mutation
// -----------------------------------------------------------------------------

#[test]
fn apply_response_header_mutation_modifies_response() {
    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let mutation = HeaderMutation {
        set_headers: vec![make_hvo("x-added", "new-value")],
        remove_headers: vec![],
    };

    mutations::apply_response_header_mutation(&mutation, &mut ctx);

    assert!(ctx.response_headers_modified, "should set response_headers_modified");
    let resp = ctx.response_header.unwrap();
    assert_eq!(
        resp.headers.get("x-added").unwrap(),
        "new-value",
        "header should be inserted"
    );
}

#[test]
fn apply_response_header_mutation_removes_header() {
    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    resp.headers.insert("x-remove-me", "gone".parse().unwrap());
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let mutation = HeaderMutation {
        set_headers: vec![],
        remove_headers: vec!["x-remove-me".to_owned()],
    };

    mutations::apply_response_header_mutation(&mutation, &mut ctx);

    assert!(ctx.response_headers_modified, "should set response_headers_modified");
    let resp = ctx.response_header.unwrap();
    assert!(resp.headers.get("x-remove-me").is_none(), "header should be removed");
}

#[test]
fn apply_response_header_mutation_remove_absent_does_not_mark_modified() {
    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let mutation = HeaderMutation {
        set_headers: vec![],
        remove_headers: vec!["x-nonexistent".to_owned()],
    };

    mutations::apply_response_header_mutation(&mutation, &mut ctx);

    assert!(
        !ctx.response_headers_modified,
        "removing an absent header should not mark response as modified"
    );
}

#[test]
fn apply_response_header_mutation_skips_pseudo_headers() {
    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let mutation = HeaderMutation {
        set_headers: vec![make_hvo(":status", "404")],
        remove_headers: vec![":status".to_owned()],
    };

    mutations::apply_response_header_mutation(&mutation, &mut ctx);

    assert!(
        !ctx.response_headers_modified,
        "pseudo-header mutations should not mark headers as modified"
    );
}

#[test]
fn apply_response_header_mutation_noop_when_no_response() {
    let req = make_request(Method::GET, "/");
    let mut ctx = make_ctx(&req);

    let mutation = HeaderMutation {
        set_headers: vec![make_hvo("x-added", "value")],
        remove_headers: vec![],
    };

    mutations::apply_response_header_mutation(&mutation, &mut ctx);

    assert!(
        !ctx.response_headers_modified,
        "should not modify when response_header is None"
    );
}

// -----------------------------------------------------------------------------
// Mutation: HeaderAppendAction (via set_response_headers)
// -----------------------------------------------------------------------------

#[test]
fn response_header_default_action_appends() {
    use praxis_proto::envoy::service::common::v3::header_value_option::HeaderAppendAction;

    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    resp.headers.insert("x-existing", "original".parse().unwrap());
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let hvo = make_hvo_with_append(
        "x-existing",
        "appended",
        HeaderAppendAction::AppendIfExistsOrAdd as i32,
        None,
    );
    let mutation = HeaderMutation {
        set_headers: vec![hvo],
        remove_headers: vec![],
    };

    mutations::apply_response_header_mutation(&mutation, &mut ctx);

    let resp = ctx.response_header.unwrap();
    let values: Vec<&str> = resp
        .headers
        .get_all("x-existing")
        .iter()
        .map(|v| v.to_str().unwrap_or_default())
        .collect();
    assert_eq!(values, vec!["original", "appended"], "default action should append");
}

#[test]
fn response_header_overwrite_action_replaces() {
    use praxis_proto::envoy::service::common::v3::header_value_option::HeaderAppendAction;

    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    resp.headers.insert("x-existing", "original".parse().unwrap());
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let hvo = make_hvo_with_append(
        "x-existing",
        "replaced",
        HeaderAppendAction::OverwriteIfExistsOrAdd as i32,
        None,
    );
    let mutation = HeaderMutation {
        set_headers: vec![hvo],
        remove_headers: vec![],
    };

    mutations::apply_response_header_mutation(&mutation, &mut ctx);

    let resp = ctx.response_header.unwrap();
    assert_eq!(
        resp.headers.get("x-existing").unwrap(),
        "replaced",
        "overwrite action should replace the existing value"
    );
}

#[test]
fn response_header_zero_action_with_append_true_appends() {
    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    resp.headers.insert("x-existing", "original".parse().unwrap());
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let mutation = HeaderMutation {
        set_headers: vec![make_hvo_with_append("x-existing", "appended", 0, Some(true))],
        remove_headers: vec![],
    };

    mutations::apply_response_header_mutation(&mutation, &mut ctx);

    let resp = ctx.response_header.unwrap();
    let values: Vec<&str> = resp
        .headers
        .get_all("x-existing")
        .iter()
        .map(|v| v.to_str().unwrap_or_default())
        .collect();
    assert_eq!(
        values,
        vec!["original", "appended"],
        "deprecated append=true should append"
    );
}

#[test]
fn response_header_zero_action_with_append_false_overwrites() {
    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    resp.headers.insert("x-existing", "original".parse().unwrap());
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let mutation = HeaderMutation {
        set_headers: vec![make_hvo_with_append("x-existing", "replaced", 0, Some(false))],
        remove_headers: vec![],
    };

    mutations::apply_response_header_mutation(&mutation, &mut ctx);

    let resp = ctx.response_header.unwrap();
    assert_eq!(
        resp.headers.get("x-existing").unwrap(),
        "replaced",
        "deprecated append=false should overwrite"
    );
}

#[test]
fn response_header_both_unset_defaults_to_append() {
    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    resp.headers.insert("x-existing", "original".parse().unwrap());
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let mutation = HeaderMutation {
        set_headers: vec![make_hvo("x-existing", "appended")],
        remove_headers: vec![],
    };

    mutations::apply_response_header_mutation(&mutation, &mut ctx);

    let resp = ctx.response_header.unwrap();
    let values: Vec<&str> = resp
        .headers
        .get_all("x-existing")
        .iter()
        .map(|v| v.to_str().unwrap_or_default())
        .collect();
    assert_eq!(
        values,
        vec!["original", "appended"],
        "both fields unset should default to append per proto3 spec"
    );
}

#[test]
fn response_header_overwrite_if_exists_replaces_present() {
    use praxis_proto::envoy::service::common::v3::header_value_option::HeaderAppendAction;

    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    resp.headers.insert("x-existing", "original".parse().unwrap());
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let hvo = make_hvo_with_append(
        "x-existing",
        "replaced",
        HeaderAppendAction::OverwriteIfExists as i32,
        None,
    );
    let mutation = HeaderMutation {
        set_headers: vec![hvo],
        remove_headers: vec![],
    };

    mutations::apply_response_header_mutation(&mutation, &mut ctx);

    assert!(ctx.response_headers_modified, "should mark as modified");
    let resp = ctx.response_header.unwrap();
    assert_eq!(
        resp.headers.get("x-existing").unwrap(),
        "replaced",
        "overwrite-if-exists should replace present header"
    );
}

#[test]
fn response_header_overwrite_if_exists_skips_absent() {
    use praxis_proto::envoy::service::common::v3::header_value_option::HeaderAppendAction;

    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let hvo = make_hvo_with_append("x-absent", "value", HeaderAppendAction::OverwriteIfExists as i32, None);
    let mutation = HeaderMutation {
        set_headers: vec![hvo],
        remove_headers: vec![],
    };

    mutations::apply_response_header_mutation(&mutation, &mut ctx);

    assert!(
        !ctx.response_headers_modified,
        "overwrite-if-exists should not modify when header is absent"
    );
    let resp = ctx.response_header.unwrap();
    assert!(
        resp.headers.get("x-absent").is_none(),
        "absent header should remain absent"
    );
}

#[test]
fn response_header_add_if_absent_adds_missing() {
    use praxis_proto::envoy::service::common::v3::header_value_option::HeaderAppendAction;

    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let hvo = make_hvo_with_append("x-new", "value", HeaderAppendAction::AddIfAbsent as i32, None);
    let mutation = HeaderMutation {
        set_headers: vec![hvo],
        remove_headers: vec![],
    };

    mutations::apply_response_header_mutation(&mutation, &mut ctx);

    assert!(ctx.response_headers_modified, "should mark as modified");
    let resp = ctx.response_header.unwrap();
    assert_eq!(
        resp.headers.get("x-new").unwrap(),
        "value",
        "add-if-absent should add missing header"
    );
}

#[test]
fn response_header_add_if_absent_skips_existing() {
    use praxis_proto::envoy::service::common::v3::header_value_option::HeaderAppendAction;

    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    resp.headers.insert("x-existing", "original".parse().unwrap());
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let hvo = make_hvo_with_append("x-existing", "new", HeaderAppendAction::AddIfAbsent as i32, None);
    let mutation = HeaderMutation {
        set_headers: vec![hvo],
        remove_headers: vec![],
    };

    mutations::apply_response_header_mutation(&mutation, &mut ctx);

    assert!(
        !ctx.response_headers_modified,
        "add-if-absent should not modify when header exists"
    );
    let resp = ctx.response_header.unwrap();
    assert_eq!(
        resp.headers.get("x-existing").unwrap(),
        "original",
        "existing header should be unchanged"
    );
}

// -----------------------------------------------------------------------------
// Mutation: immediate_to_rejection
// -----------------------------------------------------------------------------

#[test]
fn immediate_to_rejection_maps_status_body_headers() {
    let imm = ImmediateResponse {
        status: Some(HttpStatus { code: 403 }),
        headers: Some(HeaderMutation {
            set_headers: vec![make_hvo("x-reason", "blocked")],
            remove_headers: vec![],
        }),
        body: "forbidden".to_owned(),
        grpc_status: None,
        details: String::new(),
    };

    let action = mutations::immediate_to_rejection(&imm);
    let rejection = match action {
        FilterAction::Reject(r) => r,
        other => panic!("expected Reject, got {other:?}"),
    };

    assert_eq!(rejection.status, 403, "status should match");
    assert_eq!(rejection.body.unwrap(), Bytes::from("forbidden"), "body should match");
    assert_eq!(rejection.headers.len(), 1, "should have one header");
    assert_eq!(rejection.headers[0].0, "x-reason", "header name should match");
    assert_eq!(rejection.headers[0].1, "blocked", "header value should match");
}

#[test]
fn immediate_to_rejection_defaults_status_to_200() {
    let imm = ImmediateResponse {
        status: None,
        headers: None,
        body: String::new(),
        grpc_status: None,
        details: String::new(),
    };

    let action = mutations::immediate_to_rejection(&imm);
    let rejection = match action {
        FilterAction::Reject(r) => r,
        other => panic!("expected Reject, got {other:?}"),
    };

    assert_eq!(rejection.status, 200, "should default to 200 when status absent");
    assert!(rejection.body.is_none(), "empty body should be None");
    assert!(rejection.headers.is_empty(), "should have no headers");
}

#[test]
fn immediate_to_rejection_clamps_invalid_status() {
    let imm = ImmediateResponse {
        status: Some(HttpStatus { code: 999 }),
        headers: None,
        body: String::new(),
        grpc_status: None,
        details: String::new(),
    };

    let action = mutations::immediate_to_rejection(&imm);
    let rejection = match action {
        FilterAction::Reject(r) => r,
        other => panic!("expected Reject, got {other:?}"),
    };

    assert_eq!(rejection.status, 500, "out-of-range status should clamp to 500");
}

// -----------------------------------------------------------------------------
// Utility: header_value_string
// -----------------------------------------------------------------------------

#[test]
fn header_value_string_prefers_raw_value() {
    let hv = HeaderValue {
        key: "x-test".to_owned(),
        value: "text-value".to_owned(),
        raw_value: b"raw-value".to_vec(),
    };

    assert_eq!(
        mutations::header_value_string(&hv),
        "raw-value",
        "should prefer raw_value when non-empty"
    );
}

#[test]
fn header_value_string_falls_back_to_value() {
    let hv = HeaderValue {
        key: "x-test".to_owned(),
        value: "text-value".to_owned(),
        raw_value: Vec::new(),
    };

    assert_eq!(
        mutations::header_value_string(&hv),
        "text-value",
        "should fall back to value when raw_value is empty"
    );
}

// -----------------------------------------------------------------------------
// Utility: is_pseudo_header
// -----------------------------------------------------------------------------

#[test]
fn is_pseudo_header_detects_colon_prefix() {
    assert!(mutations::is_pseudo_header(":method"), ":method is a pseudo-header");
    assert!(mutations::is_pseudo_header(":path"), ":path is a pseudo-header");
    assert!(mutations::is_pseudo_header(":status"), ":status is a pseudo-header");
    assert!(
        !mutations::is_pseudo_header("content-type"),
        "content-type is not a pseudo-header"
    );
    assert!(
        !mutations::is_pseudo_header("x-custom"),
        "x-custom is not a pseudo-header"
    );
}

// -----------------------------------------------------------------------------
// Mutation: apply_headers_response delegates by phase
// -----------------------------------------------------------------------------

#[test]
fn apply_headers_response_delegates_to_request_phase() {
    let req = make_request(Method::GET, "/");
    let mut ctx = make_ctx(&req);

    let hr = HeadersResponse {
        response: Some(CommonResponse {
            status: 0,
            header_mutation: Some(HeaderMutation {
                set_headers: vec![make_hvo("x-from-proc", "req")],
                remove_headers: vec![],
            }),
            body_mutation: None,
            trailers: None,
            clear_route_cache: false,
        }),
    };

    mutations::apply_headers_response(&hr, &mut ctx, Phase::Request);

    assert_eq!(
        ctx.extra_request_headers.len(),
        1,
        "should add to extra request headers"
    );
    assert_eq!(
        ctx.extra_request_headers[0].0, "x-from-proc",
        "header name should match"
    );
}

#[test]
fn apply_headers_response_delegates_to_response_phase() {
    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let hr = HeadersResponse {
        response: Some(CommonResponse {
            status: 0,
            header_mutation: Some(HeaderMutation {
                set_headers: vec![make_hvo("x-from-proc", "resp")],
                remove_headers: vec![],
            }),
            body_mutation: None,
            trailers: None,
            clear_route_cache: false,
        }),
    };

    mutations::apply_headers_response(&hr, &mut ctx, Phase::Response);

    assert!(ctx.response_headers_modified, "should set response_headers_modified");
    let resp = ctx.response_header.unwrap();
    assert_eq!(
        resp.headers.get("x-from-proc").unwrap(),
        "resp",
        "header should be set on response"
    );
}

// -----------------------------------------------------------------------------
// gRPC Callout Integration
// -----------------------------------------------------------------------------

#[tokio::test]
async fn grpc_request_headers_round_trip_applies_mutation() {
    let (addr, _guard) = start_mock_processor(MockBehavior::AddHeader {
        name: "x-injected".to_owned(),
        value: "from-processor".to_owned(),
    })
    .await;

    let channel = connect_channel(addr).await;

    let req = make_request(Method::GET, "/test");
    let mut ctx = make_ctx(&req);
    let timeout = Duration::from_secs(5);

    let action = callout::process_request_headers(channel, &addr.to_string(), timeout, None, &mut ctx)
        .await
        .expect("callout should succeed");

    assert!(
        matches!(action, FilterAction::Continue),
        "action should be Continue after header mutation"
    );
    let injected = ctx.extra_request_headers.iter().find(|(k, _)| k == "x-injected");
    assert!(injected.is_some(), "processor-injected header should be present");
    assert_eq!(
        injected.unwrap().1,
        "from-processor",
        "injected header value should match"
    );
}

#[tokio::test]
async fn grpc_response_headers_round_trip_applies_mutation() {
    let (addr, _guard) = start_mock_processor(MockBehavior::AddHeader {
        name: "x-resp-injected".to_owned(),
        value: "from-processor".to_owned(),
    })
    .await;

    let channel = connect_channel(addr).await;

    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);
    let timeout = Duration::from_secs(5);

    let action = callout::process_response_headers(channel, &addr.to_string(), timeout, None, &mut ctx)
        .await
        .expect("callout should succeed");

    assert!(
        matches!(action, FilterAction::Continue),
        "action should be Continue after response header mutation"
    );
    assert!(ctx.response_headers_modified, "response_headers_modified should be set");
    let resp = ctx.response_header.unwrap();
    assert_eq!(
        resp.headers.get("x-resp-injected").unwrap(),
        "from-processor",
        "response header should be mutated"
    );
}

#[tokio::test]
async fn grpc_immediate_response_returns_rejection() {
    let (addr, _guard) = start_mock_processor(MockBehavior::ImmediateReject {
        status: 403,
        body: "blocked".to_owned(),
    })
    .await;

    let channel = connect_channel(addr).await;

    let req = make_request(Method::GET, "/secret");
    let mut ctx = make_ctx(&req);
    let timeout = Duration::from_secs(5);

    let action = callout::process_request_headers(channel, &addr.to_string(), timeout, None, &mut ctx)
        .await
        .expect("callout should succeed");

    let rejection = match action {
        FilterAction::Reject(r) => r,
        other => panic!("expected Reject, got {other:?}"),
    };
    assert_eq!(rejection.status, 403, "rejection status should match");
    assert_eq!(
        rejection.body.unwrap(),
        Bytes::from("blocked"),
        "rejection body should match"
    );
}

#[tokio::test]
async fn grpc_noop_response_returns_continue() {
    let (addr, _guard) = start_mock_processor(MockBehavior::Noop).await;

    let channel = connect_channel(addr).await;

    let req = make_request(Method::GET, "/");
    let mut ctx = make_ctx(&req);
    let timeout = Duration::from_secs(5);

    let action = callout::process_request_headers(channel, &addr.to_string(), timeout, None, &mut ctx)
        .await
        .expect("callout should succeed");

    assert!(
        matches!(action, FilterAction::Continue),
        "no-op response should produce Continue"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "no headers should be added for no-op response"
    );
}

#[tokio::test]
async fn grpc_unexpected_response_type_returns_error() {
    let (addr, _guard) = start_mock_processor(MockBehavior::UnexpectedBodyResponse).await;

    let channel = connect_channel(addr).await;

    let req = make_request(Method::GET, "/");
    let mut ctx = make_ctx(&req);
    let timeout = Duration::from_secs(5);

    let result = callout::process_request_headers(channel, &addr.to_string(), timeout, None, &mut ctx).await;

    assert!(result.is_err(), "unexpected response type should return Err");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("RequestBody"),
        "error should name the unexpected variant: {err}"
    );
    assert!(err.contains("request"), "error should mention the phase: {err}");
}

#[tokio::test]
async fn grpc_phase_mismatched_response_returns_error() {
    let (addr, _guard) = start_mock_processor(MockBehavior::AlwaysResponseHeaders).await;

    let channel = connect_channel(addr).await;

    let req = make_request(Method::GET, "/");
    let mut ctx = make_ctx(&req);
    let timeout = Duration::from_secs(5);

    let result = callout::process_request_headers(channel, &addr.to_string(), timeout, None, &mut ctx).await;

    assert!(result.is_err(), "phase-mismatched response should return Err");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("ResponseHeaders"),
        "error should name the mismatched variant: {err}"
    );
}

#[tokio::test]
async fn grpc_timeout_returns_error() {
    let (addr, _guard) = start_mock_processor(MockBehavior::Hang).await;

    let channel = connect_channel(addr).await;

    let req = make_request(Method::GET, "/");
    let mut ctx = make_ctx(&req);
    let timeout = Duration::from_millis(50);

    let result = callout::process_request_headers(channel, &addr.to_string(), timeout, None, &mut ctx).await;

    assert!(result.is_err(), "timed-out callout should return Err");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("timeout"), "error should mention timeout: {err}");
}

#[tokio::test]
async fn grpc_timeout_with_filter_returns_status_on_error() {
    let (addr, _guard) = start_mock_processor(MockBehavior::Hang).await;

    let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
        r#"
target: "http://{addr}"
message_timeout_ms: 50
status_on_error: 503
"#,
    ))
    .unwrap();

    let filter = ExtProcFilter::from_config(&yaml).unwrap();

    let req = make_request(Method::GET, "/");
    let mut ctx = make_ctx(&req);

    let action = filter.on_request(&mut ctx).await.expect("should not return Err");

    let rejection = match action {
        FilterAction::Reject(r) => r,
        other => panic!("expected Reject, got {other:?}"),
    };
    assert_eq!(
        rejection.status, 503,
        "rejection status should match configured status_on_error"
    );
}

#[tokio::test]
async fn grpc_timeout_with_filter_returns_status_on_error_on_response() {
    let (addr, _guard) = start_mock_processor(MockBehavior::Hang).await;

    let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
        r#"
target: "http://{addr}"
message_timeout_ms: 50
status_on_error: 502
"#,
    ))
    .unwrap();

    let filter = ExtProcFilter::from_config(&yaml).unwrap();

    let req = make_request(Method::GET, "/");
    let mut resp = make_response();
    let mut ctx = make_ctx(&req);
    ctx.response_header = Some(&mut resp);

    let action = filter.on_response(&mut ctx).await.expect("should not return Err");

    let rejection = match action {
        FilterAction::Reject(r) => r,
        other => panic!("expected Reject, got {other:?}"),
    };
    assert_eq!(
        rejection.status, 502,
        "rejection status should match configured status_on_error"
    );
}

#[tokio::test]
async fn grpc_override_timeout_extends_deadline() {
    let (addr, _guard) = start_mock_processor(MockBehavior::OverrideThenRespond {
        override_ms: 2000,
        delay_ms: 200,
        name: "x-after-override".to_owned(),
        value: "extended".to_owned(),
    })
    .await;

    let channel = connect_channel(addr).await;

    let req = make_request(Method::GET, "/");
    let mut ctx = make_ctx(&req);
    // Original timeout is shorter than the server delay.
    // Without the override replacing the deadline, this would time out.
    let timeout = Duration::from_millis(100);
    let max_timeout = Some(Duration::from_secs(5));

    let action = callout::process_request_headers(channel, &addr.to_string(), timeout, max_timeout, &mut ctx)
        .await
        .expect("override should extend deadline past the server delay");

    assert!(
        matches!(action, FilterAction::Continue),
        "action should be Continue after override + mutation"
    );
    let injected = ctx.extra_request_headers.iter().find(|(k, _)| k == "x-after-override");
    assert!(
        injected.is_some(),
        "header from post-override response should be present"
    );
}

#[tokio::test]
async fn grpc_override_ignored_without_max_timeout() {
    let (addr, _guard) = start_mock_processor(MockBehavior::OverrideThenRespond {
        override_ms: 500,
        delay_ms: 0,
        name: "x-ignored".to_owned(),
        value: "value".to_owned(),
    })
    .await;

    let channel = connect_channel(addr).await;

    let req = make_request(Method::GET, "/");
    let mut ctx = make_ctx(&req);
    let timeout = Duration::from_secs(5);

    let action = callout::process_request_headers(channel, &addr.to_string(), timeout, None, &mut ctx)
        .await
        .expect("callout should succeed");

    assert!(
        matches!(action, FilterAction::Continue),
        "override without max_timeout should return Continue (no-op)"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "no headers should be added when override is ignored"
    );
}

#[tokio::test]
async fn grpc_override_clamped_to_max_timeout() {
    let (addr, _guard) = start_mock_processor(MockBehavior::OverrideThenRespond {
        override_ms: 5000,
        delay_ms: 300,
        name: "x-late".to_owned(),
        value: "value".to_owned(),
    })
    .await;

    let channel = connect_channel(addr).await;

    let req = make_request(Method::GET, "/");
    let mut ctx = make_ctx(&req);
    let timeout = Duration::from_millis(100);
    // max_timeout is shorter than the server delay, so the clamped
    // override (200ms) expires before the 300ms delayed response.
    let max_timeout = Some(Duration::from_millis(200));

    let result = callout::process_request_headers(channel, &addr.to_string(), timeout, max_timeout, &mut ctx).await;

    assert!(result.is_err(), "clamped override should time out");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("timeout"), "error should mention timeout: {err}");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a minimal [`praxis_filter::Request`].
fn make_request(method: Method, path: &str) -> praxis_filter::Request {
    praxis_filter::Request {
        method,
        uri: path.parse::<Uri>().expect("invalid URI in test"),
        headers: HeaderMap::new(),
    }
}

/// Build a minimal OK [`praxis_filter::Response`].
fn make_response() -> praxis_filter::Response {
    praxis_filter::Response {
        headers: HeaderMap::new(),
        status: StatusCode::OK,
    }
}

/// Deterministic ID generator for tests.
static TEST_ID_GENERATOR: std::sync::LazyLock<praxis_core::id::IdGenerator> =
    std::sync::LazyLock::new(|| praxis_core::id::IdGenerator::with_seed(0));

#[expect(clippy::too_many_lines, reason = "unavoidable: single large statement")]
/// Build a minimal [`HttpFilterContext`] for unit tests.
fn make_ctx(req: &praxis_filter::Request) -> HttpFilterContext<'_> {
    HttpFilterContext {
        body_done_indices: Vec::new(),
        branch_iterations: HashMap::new(),
        client_addr: None,
        cluster: None,
        current_filter_id: None,
        downstream_tls: false,
        extensions: praxis_filter::RequestExtensions::default(),
        executed_filter_indices: Vec::new(),
        extra_request_headers: Vec::new(),
        request_headers_to_remove: Vec::new(),
        request_headers_to_set: Vec::new(),
        filter_metadata: HashMap::new(),
        filter_results: HashMap::new(),
        filter_state: HashMap::new(),
        health_registry: None,
        id_generator: &TEST_ID_GENERATOR,
        kv_stores: None,
        request: req,
        request_body_bytes: 0,
        request_body_mode: praxis_filter::BodyMode::Stream,
        request_start: Instant::now(),
        response_body_bytes: 0,
        response_body_mode: praxis_filter::BodyMode::Stream,
        response_header: None,
        response_stores: None,
        response_headers_modified: false,
        rewritten_path: None,
        selected_endpoint_index: None,
        time_source: &praxis_core::time::SystemTimeSource,
        upstream: None,
    }
}

/// Build a [`HeaderValueOption`] with the given key and value.
fn make_hvo(key: &str, value: &str) -> HeaderValueOption {
    HeaderValueOption {
        header: Some(HeaderValue {
            key: key.to_owned(),
            value: value.to_owned(),
            raw_value: Vec::new(),
        }),
        append: None,
        append_action: 0,
    }
}

/// Build a [`HeaderValueOption`] with explicit append control.
fn make_hvo_with_append(key: &str, value: &str, append_action: i32, append: Option<bool>) -> HeaderValueOption {
    HeaderValueOption {
        header: Some(HeaderValue {
            key: key.to_owned(),
            value: value.to_owned(),
            raw_value: Vec::new(),
        }),
        append,
        append_action,
    }
}

/// Connect a tonic [`Channel`] to the given address.
async fn connect_channel(addr: SocketAddr) -> Channel {
    Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap()
}

/// Parse a minimal valid config for default-checking tests.
fn minimal_config() -> ExtProcConfig {
    let yaml: serde_yaml::Value = serde_yaml::from_str(r#"target: "http://127.0.0.1:50051""#).unwrap();
    parse_filter_config("ext_proc", &yaml).unwrap()
}

// -----------------------------------------------------------------------------
// Mock gRPC Server
// -----------------------------------------------------------------------------

use std::{net::SocketAddr, pin::Pin};

use async_trait::async_trait;
use praxis_proto::envoy::service::ext_proc::v3::{
    BodyResponse, ProcessingRequest, ProcessingResponse, ProtocolConfiguration, TrailersResponse,
    external_processor_server::{ExternalProcessor, ExternalProcessorServer},
    processing_request, processing_response,
};
use tokio::sync::oneshot;
use tokio_stream::Stream;

/// Configurable behavior for the mock external processor.
#[derive(Clone)]
enum MockBehavior {
    /// Add a header to the response mutation.
    AddHeader { name: String, value: String },

    /// Return an `ImmediateResponse` rejection.
    ImmediateReject { status: i32, body: String },

    /// Return a response with no mutations.
    Noop,

    /// Never respond (for timeout testing).
    Hang,

    /// Return an unexpected `RequestBody` response type.
    UnexpectedBodyResponse,

    /// Return `ResponseHeaders` regardless of request phase.
    AlwaysResponseHeaders,

    /// Send an `override_message_timeout` first, then the real response.
    OverrideThenRespond {
        override_ms: u64,
        delay_ms: u64,
        name: String,
        value: String,
    },
}

/// Mock implementation of the Envoy `ExternalProcessor` gRPC service.
struct MockProcessor {
    behavior: MockBehavior,
}

#[async_trait]
impl ExternalProcessor for MockProcessor {
    type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

    async fn process(
        &self,
        request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
    ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
        let mut stream = request.into_inner();
        let msg = stream
            .message()
            .await?
            .ok_or_else(|| tonic::Status::internal("empty request stream"))?;

        match &self.behavior {
            MockBehavior::OverrideThenRespond {
                override_ms,
                delay_ms,
                name,
                value,
            } => {
                let override_resp = build_override_response(*override_ms);
                let real_resp = build_add_header_response(&msg, name, value);
                let delay = Duration::from_millis(*delay_ms);
                let (tx, rx) = tokio::sync::mpsc::channel(2);
                tokio::spawn(async move {
                    drop(tx.send(Ok(override_resp)).await);
                    tokio::time::sleep(delay).await;
                    drop(tx.send(Ok(real_resp)).await);
                });
                let output = tokio_stream::wrappers::ReceiverStream::new(rx);
                Ok(tonic::Response::new(Box::pin(output)))
            },
            behavior => {
                let responses = build_mock_responses(behavior, &msg).await;
                let output = futures::stream::iter(responses.into_iter().map(Ok));
                Ok(tonic::Response::new(Box::pin(output)))
            },
        }
    }
}

/// Dispatch mock behavior to response builder(s).
async fn build_mock_responses(behavior: &MockBehavior, msg: &ProcessingRequest) -> Vec<ProcessingResponse> {
    match behavior {
        MockBehavior::Hang => {
            futures::future::pending::<()>().await;
            unreachable!("pending future should never resolve");
        },
        MockBehavior::OverrideThenRespond { .. } => {
            unreachable!("handled directly in process()")
        },
        MockBehavior::Noop => vec![build_noop_response(msg)],
        MockBehavior::AddHeader { name, value } => vec![build_add_header_response(msg, name, value)],
        MockBehavior::ImmediateReject { status, body } => vec![build_immediate_response(*status, body)],
        MockBehavior::UnexpectedBodyResponse => vec![build_unexpected_body_response()],
        MockBehavior::AlwaysResponseHeaders => vec![build_always_response_headers()],
    }
}

/// Build a response that echoes back the phase with no mutations.
fn build_noop_response(req: &ProcessingRequest) -> ProcessingResponse {
    let response = match &req.request {
        Some(processing_request::Request::RequestHeaders(_)) => {
            processing_response::Response::RequestHeaders(HeadersResponse { response: None })
        },
        Some(processing_request::Request::RequestBody(_)) => {
            processing_response::Response::RequestBody(BodyResponse { response: None })
        },
        Some(processing_request::Request::RequestTrailers(_)) => {
            processing_response::Response::RequestTrailers(TrailersResponse { header_mutation: None })
        },
        Some(processing_request::Request::ResponseHeaders(_)) => {
            processing_response::Response::ResponseHeaders(HeadersResponse { response: None })
        },
        Some(processing_request::Request::ResponseBody(_)) => {
            processing_response::Response::ResponseBody(BodyResponse { response: None })
        },
        Some(processing_request::Request::ResponseTrailers(_)) => {
            processing_response::Response::ResponseTrailers(TrailersResponse { header_mutation: None })
        },
        None => processing_response::Response::RequestHeaders(HeadersResponse { response: None }),
    };
    ProcessingResponse {
        response: Some(response),
        ..Default::default()
    }
}

/// Build a response that adds a single header via [`HeaderMutation`].
fn build_add_header_response(req: &ProcessingRequest, name: &str, value: &str) -> ProcessingResponse {
    let mutation = Some(HeaderMutation {
        set_headers: vec![make_hvo(name, value)],
        remove_headers: vec![],
    });
    let common = Some(CommonResponse {
        status: 0,
        header_mutation: mutation,
        body_mutation: None,
        trailers: None,
        clear_route_cache: false,
    });
    let response = match &req.request {
        Some(processing_request::Request::ResponseHeaders(_)) => {
            processing_response::Response::ResponseHeaders(HeadersResponse { response: common })
        },
        _ => processing_response::Response::RequestHeaders(HeadersResponse { response: common }),
    };
    ProcessingResponse {
        response: Some(response),
        ..Default::default()
    }
}

/// Build an [`ImmediateResponse`] rejection.
fn build_immediate_response(status: i32, body: &str) -> ProcessingResponse {
    ProcessingResponse {
        response: Some(processing_response::Response::ImmediateResponse(ImmediateResponse {
            status: Some(HttpStatus { code: status }),
            headers: None,
            body: body.to_owned(),
            grpc_status: None,
            details: String::new(),
        })),
        ..Default::default()
    }
}

/// Build a response with only `override_message_timeout` and no `response` oneof.
fn build_override_response(override_ms: u64) -> ProcessingResponse {
    ProcessingResponse {
        response: None,
        override_message_timeout: Some(prost_types::Duration {
            seconds: i64::try_from(override_ms / 1000).unwrap_or(0),
            nanos: i32::try_from((override_ms % 1000) * 1_000_000).unwrap_or(0),
        }),
        ..Default::default()
    }
}

/// Build a `RequestBody` response to trigger the unexpected-type error path.
fn build_unexpected_body_response() -> ProcessingResponse {
    ProcessingResponse {
        response: Some(processing_response::Response::RequestBody(BodyResponse {
            response: None,
        })),
        ..Default::default()
    }
}

/// Build a `ResponseHeaders` response regardless of the request phase.
fn build_always_response_headers() -> ProcessingResponse {
    ProcessingResponse {
        response: Some(processing_response::Response::ResponseHeaders(HeadersResponse {
            response: None,
        })),
        ..Default::default()
    }
}

/// RAII guard that shuts down the mock gRPC server on drop.
struct MockServerGuard {
    shutdown: Option<oneshot::Sender<()>>,
}

impl Drop for MockServerGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Start a mock `ExternalProcessor` gRPC server on a random port.
///
/// Returns the listen address and an RAII guard that shuts down
/// the server when dropped.
async fn start_mock_processor(behavior: MockBehavior) -> (SocketAddr, MockServerGuard) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let svc = ExternalProcessorServer::new(MockProcessor { behavior });

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    wait_for_server(addr).await;

    let guard = MockServerGuard {
        shutdown: Some(shutdown_tx),
    };
    (addr, guard)
}

/// Poll until the server accepts a TCP connection.
async fn wait_for_server(addr: SocketAddr) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("mock server at {addr} did not become ready");
}

// =============================================================================
// Duplex Exchange Tests
// =============================================================================

fn default_exchange_config() -> ExchangeConfig {
    ExchangeConfig {
        message_timeout: Duration::from_secs(5),
        max_message_timeout: None,
        request_body_mode: BodySendMode::None,
        response_body_mode: BodySendMode::None,
    }
}

fn streamed_body_exchange_config() -> ExchangeConfig {
    ExchangeConfig {
        request_body_mode: BodySendMode::Streamed,
        response_body_mode: BodySendMode::Streamed,
        ..default_exchange_config()
    }
}

fn full_duplex_exchange_config() -> ExchangeConfig {
    ExchangeConfig {
        request_body_mode: BodySendMode::FullDuplexStreamed,
        response_body_mode: BodySendMode::FullDuplexStreamed,
        ..default_exchange_config()
    }
}

// -----------------------------------------------------------------------------
// Duplex Mock Server
// -----------------------------------------------------------------------------

/// Configurable behavior for the duplex mock processor.
///
/// Unlike [`MockBehavior`] which handles one message,
/// this reads the full conversation.
#[derive(Clone)]
enum DuplexBehavior {
    /// Read request headers, respond with header mutation.
    EchoHeaders { name: String, value: String },

    /// Read headers + body chunks. Respond only after body EOS.
    /// Returns header response then body response.
    DelayedRouting { header_name: String, header_value: String },

    /// Respond with ImmediateResponse on request headers.
    ImmediateOnHeaders { status: i32, body: String },

    /// Read headers, then respond with ImmediateResponse on first body chunk.
    ImmediateOnBody { status: i32, body: String },

    /// Read headers + body EOS, respond with multiple StreamedBodyResponse chunks.
    StreamedBodyChunks { chunks: Vec<Vec<u8>> },

    /// Handle full lifecycle: request headers, request body, response headers.
    FullLifecycle {
        req_header_name: String,
        req_header_value: String,
        resp_header_name: String,
        resp_header_value: String,
    },

    /// Never respond (timeout testing).
    Hang,

    /// Close stream immediately without responding.
    CloseEarly,

    /// Send override_message_timeout then delayed header response.
    OverrideTimeout {
        override_ms: u64,
        delay_ms: u64,
        name: String,
        value: String,
    },

    /// Echo headers, respond with unexpected body response type.
    UnexpectedResponseType,

    /// Read headers + body, respond to both. Body response uses
    /// simple BodyMutation (not streamed).
    HeadersAndBody,
}

struct DuplexMockProcessor {
    behavior: DuplexBehavior,
}

#[async_trait]
impl ExternalProcessor for DuplexMockProcessor {
    type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

    async fn process(
        &self,
        request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
    ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
        let mut stream = request.into_inner();
        let behavior = self.behavior.clone();

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            match behavior {
                DuplexBehavior::EchoHeaders { name, value } => {
                    let msg = stream.message().await.unwrap().unwrap();
                    let resp = build_add_header_response(&msg, &name, &value);
                    drop(tx.send(Ok(resp)).await);
                },
                DuplexBehavior::DelayedRouting {
                    header_name,
                    header_value,
                } => {
                    let header_msg = stream.message().await.unwrap().unwrap();
                    loop {
                        let body_msg = stream.message().await.unwrap().unwrap();
                        if let Some(processing_request::Request::RequestBody(b)) = &body_msg.request
                            && b.end_of_stream
                        {
                            break;
                        }
                    }
                    let header_resp = build_add_header_response(&header_msg, &header_name, &header_value);
                    drop(tx.send(Ok(header_resp)).await);
                    use praxis_proto::envoy::service::ext_proc::v3::{
                        BodyMutation, CommonResponse, StreamedBodyResponse, body_mutation,
                    };
                    let body_resp = ProcessingResponse {
                        response: Some(processing_response::Response::RequestBody(BodyResponse {
                            response: Some(CommonResponse {
                                body_mutation: Some(BodyMutation {
                                    mutation: Some(body_mutation::Mutation::StreamedResponse(StreamedBodyResponse {
                                        body: Vec::new(),
                                        end_of_stream: true,
                                    })),
                                }),
                                ..Default::default()
                            }),
                        })),
                        ..Default::default()
                    };
                    drop(tx.send(Ok(body_resp)).await);
                },
                DuplexBehavior::ImmediateOnHeaders { status, body } => {
                    let _msg = stream.message().await.unwrap().unwrap();
                    let resp = build_immediate_response(status, &body);
                    drop(tx.send(Ok(resp)).await);
                },
                DuplexBehavior::ImmediateOnBody { status, body } => {
                    let _headers = stream.message().await.unwrap().unwrap();
                    let header_resp = ProcessingResponse {
                        response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                            response: None,
                        })),
                        ..Default::default()
                    };
                    drop(tx.send(Ok(header_resp)).await);
                    let _body_msg = stream.message().await.unwrap().unwrap();
                    let resp = build_immediate_response(status, &body);
                    drop(tx.send(Ok(resp)).await);
                },
                DuplexBehavior::StreamedBodyChunks { chunks } => {
                    let _headers = stream.message().await.unwrap().unwrap();
                    loop {
                        let body_msg = stream.message().await.unwrap().unwrap();
                        if let Some(processing_request::Request::RequestBody(b)) = &body_msg.request
                            && b.end_of_stream
                        {
                            break;
                        }
                    }
                    let header_resp = ProcessingResponse {
                        response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                            response: None,
                        })),
                        ..Default::default()
                    };
                    drop(tx.send(Ok(header_resp)).await);

                    for (i, chunk) in chunks.iter().enumerate() {
                        let is_last = i == chunks.len() - 1;
                        use praxis_proto::envoy::service::ext_proc::v3::{
                            BodyMutation, CommonResponse, StreamedBodyResponse, body_mutation,
                        };
                        let body_resp = ProcessingResponse {
                            response: Some(processing_response::Response::RequestBody(BodyResponse {
                                response: Some(CommonResponse {
                                    body_mutation: Some(BodyMutation {
                                        mutation: Some(body_mutation::Mutation::StreamedResponse(
                                            StreamedBodyResponse {
                                                body: chunk.clone(),
                                                end_of_stream: is_last,
                                            },
                                        )),
                                    }),
                                    ..Default::default()
                                }),
                            })),
                            ..Default::default()
                        };
                        drop(tx.send(Ok(body_resp)).await);
                    }
                },
                DuplexBehavior::FullLifecycle {
                    req_header_name,
                    req_header_value,
                    resp_header_name,
                    resp_header_value,
                } => {
                    let header_msg = stream.message().await.unwrap().unwrap();
                    let req_resp = build_add_header_response(&header_msg, &req_header_name, &req_header_value);
                    drop(tx.send(Ok(req_resp)).await);

                    while let Ok(Some(msg)) = stream.message().await {
                        if let Some(processing_request::Request::ResponseHeaders(_)) = msg.request {
                            let resp_resp = ProcessingResponse {
                                response: Some(processing_response::Response::ResponseHeaders(HeadersResponse {
                                    response: Some(CommonResponse {
                                        header_mutation: Some(HeaderMutation {
                                            set_headers: vec![make_hvo(&resp_header_name, &resp_header_value)],
                                            remove_headers: vec![],
                                        }),
                                        ..Default::default()
                                    }),
                                })),
                                ..Default::default()
                            };
                            drop(tx.send(Ok(resp_resp)).await);
                            break;
                        }
                    }
                },
                DuplexBehavior::Hang => {
                    futures::future::pending::<()>().await;
                },
                DuplexBehavior::CloseEarly => {},
                DuplexBehavior::OverrideTimeout {
                    override_ms,
                    delay_ms,
                    name,
                    value,
                } => {
                    let msg = stream.message().await.unwrap().unwrap();
                    let override_resp = build_override_response(override_ms);
                    drop(tx.send(Ok(override_resp)).await);
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    let real_resp = build_add_header_response(&msg, &name, &value);
                    drop(tx.send(Ok(real_resp)).await);
                },
                DuplexBehavior::UnexpectedResponseType => {
                    let _msg = stream.message().await.unwrap().unwrap();
                    let resp = build_unexpected_body_response();
                    drop(tx.send(Ok(resp)).await);
                },
                DuplexBehavior::HeadersAndBody => {
                    let header_msg = stream.message().await.unwrap().unwrap();
                    let header_resp = build_noop_response(&header_msg);
                    drop(tx.send(Ok(header_resp)).await);

                    let _body_msg = stream.message().await.unwrap().unwrap();
                    let body_resp = ProcessingResponse {
                        response: Some(processing_response::Response::RequestBody(BodyResponse {
                            response: None,
                        })),
                        ..Default::default()
                    };
                    drop(tx.send(Ok(body_resp)).await);
                },
            }
        });

        let output = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(tonic::Response::new(Box::pin(output)))
    }
}

async fn start_duplex_processor(behavior: DuplexBehavior) -> (SocketAddr, MockServerGuard) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let svc = ExternalProcessorServer::new(DuplexMockProcessor { behavior });

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    wait_for_server(addr).await;

    let guard = MockServerGuard {
        shutdown: Some(shutdown_tx),
    };
    (addr, guard)
}

fn make_request_headers() -> processing_request::Request {
    processing_request::Request::RequestHeaders(praxis_proto::envoy::service::ext_proc::v3::HttpHeaders {
        headers: Some(praxis_proto::envoy::service::ext_proc::v3::HeaderMap {
            headers: vec![HeaderValue {
                key: ":method".to_owned(),
                value: "GET".to_owned(),
                raw_value: Vec::new(),
            }],
        }),
        end_of_stream: false,
    })
}

fn make_request_body(body: &[u8], end_of_stream: bool) -> processing_request::Request {
    processing_request::Request::RequestBody(praxis_proto::envoy::service::ext_proc::v3::HttpBody {
        body: body.to_vec(),
        end_of_stream,
    })
}

fn make_response_headers() -> processing_request::Request {
    processing_request::Request::ResponseHeaders(praxis_proto::envoy::service::ext_proc::v3::HttpHeaders {
        headers: Some(praxis_proto::envoy::service::ext_proc::v3::HeaderMap {
            headers: vec![HeaderValue {
                key: ":status".to_owned(),
                value: "200".to_owned(),
                raw_value: Vec::new(),
            }],
        }),
        end_of_stream: false,
    })
}

fn make_request_trailers() -> processing_request::Request {
    processing_request::Request::RequestTrailers(praxis_proto::envoy::service::ext_proc::v3::HttpTrailers {
        trailers: Some(praxis_proto::envoy::service::ext_proc::v3::HeaderMap { headers: vec![] }),
    })
}

// -----------------------------------------------------------------------------
// Duplex Exchange Test Functions
// -----------------------------------------------------------------------------

/// Mock that records the protocol_config from the first message.
struct ProtocolConfigRecorder {
    recorded: std::sync::Arc<tokio::sync::Mutex<Option<ProtocolConfiguration>>>,
}

#[async_trait]
impl ExternalProcessor for ProtocolConfigRecorder {
    type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

    async fn process(
        &self,
        request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
    ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
        let mut stream = request.into_inner();
        let recorded = self.recorded.clone();

        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let mut first = true;
            while let Ok(Some(msg)) = stream.message().await {
                if first {
                    *recorded.lock().await = msg.protocol_config;
                    first = false;
                }
                let resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(resp)).await);
            }
        });

        let output = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(tonic::Response::new(Box::pin(output)))
    }
}

#[tokio::test]
async fn duplex_first_message_includes_protocol_config() {
    let recorded = std::sync::Arc::new(tokio::sync::Mutex::new(None));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let svc = ExternalProcessorServer::new(ProtocolConfigRecorder {
        recorded: recorded.clone(),
    });
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        request_body_mode: BodySendMode::FullDuplexStreamed,
        response_body_mode: BodySendMode::FullDuplexStreamed,
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _resp = exchange.receive().await.unwrap();

    let pc = recorded.lock().await;
    let pc = pc.as_ref().expect("first message should include protocol_config");
    assert_eq!(
        pc.request_body_mode, 4,
        "request_body_mode should be FULL_DUPLEX_STREAMED"
    );
    assert_eq!(
        pc.response_body_mode, 4,
        "response_body_mode should be FULL_DUPLEX_STREAMED"
    );

    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_second_message_omits_protocol_config() {
    let all_configs: std::sync::Arc<tokio::sync::Mutex<Vec<Option<ProtocolConfiguration>>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    struct AllConfigRecorder {
        configs: std::sync::Arc<tokio::sync::Mutex<Vec<Option<ProtocolConfiguration>>>>,
    }

    #[async_trait]
    impl ExternalProcessor for AllConfigRecorder {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let configs = self.configs.clone();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Ok(Some(msg)) = stream.message().await {
                    configs.lock().await.push(msg.protocol_config);
                    let resp = build_noop_response(&msg);
                    drop(tx.send(Ok(resp)).await);
                }
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let svc = ExternalProcessorServer::new(AllConfigRecorder {
        configs: all_configs.clone(),
    });
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &streamed_body_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _r1 = exchange.receive().await.unwrap();
    exchange.send(make_request_body(b"data", true)).await.unwrap();
    let _r2 = exchange.receive().await.unwrap();

    drop(exchange);
    let _ = shutdown_tx.send(());

    let configs = all_configs.lock().await;
    assert_eq!(configs.len(), 2, "server should have received 2 messages");
    assert!(configs[0].is_some(), "first message should include protocol_config");
    assert!(configs[1].is_none(), "second message should omit protocol_config");
}

#[tokio::test]
async fn duplex_request_headers_round_trip() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::EchoHeaders {
        name: "x-injected".to_owned(),
        value: "from-duplex".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let resp = exchange.receive().await.unwrap();
    assert!(
        matches!(resp, ExchangeEvent::RequestHeaders { .. }),
        "should receive a response with header mutation"
    );
}

#[tokio::test]
async fn duplex_request_body_round_trip() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::HeadersAndBody).await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &streamed_body_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _hdr_resp = exchange.receive().await.unwrap();
    exchange.send(make_request_body(b"hello", true)).await.unwrap();
    let body_resp = exchange.receive().await.unwrap();
    assert!(
        matches!(body_resp, ExchangeEvent::RequestBody { .. }),
        "should receive a body response"
    );
}

#[tokio::test]
async fn duplex_delayed_routing_no_deadlock() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::DelayedRouting {
        header_name: "x-endpoint".to_owned(),
        header_value: "10.0.0.1:8080".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &full_duplex_exchange_config()).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    exchange.send(make_request_body(b"chunk1", false)).await.unwrap();
    exchange.send(make_request_body(b"chunk2", true)).await.unwrap();

    let header_resp = exchange.receive().await.unwrap();
    assert!(
        matches!(header_resp, ExchangeEvent::RequestHeaders { .. }),
        "should receive deferred header response after body EOS"
    );
    let body_resp = exchange.receive().await.unwrap();
    assert!(
        matches!(body_resp, ExchangeEvent::RequestBody { .. }),
        "should receive body response after header response"
    );
}

#[tokio::test]
async fn duplex_multiple_sends_before_any_receive() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::DelayedRouting {
        header_name: "x-ep".to_owned(),
        header_value: "ep1".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &full_duplex_exchange_config()).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    exchange.send(make_request_body(b"all-at-once", true)).await.unwrap();

    let r1 = exchange.receive().await.unwrap();
    let r2 = exchange.receive().await.unwrap();
    assert!(
        matches!(r1, ExchangeEvent::RequestHeaders { .. }),
        "first response should exist"
    );
    assert!(
        matches!(r2, ExchangeEvent::RequestBody { .. }),
        "second response should exist"
    );
}

#[tokio::test]
async fn duplex_response_headers_on_same_stream() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::FullLifecycle {
        req_header_name: "x-req".to_owned(),
        req_header_value: "val".to_owned(),
        resp_header_name: "x-resp".to_owned(),
        resp_header_value: "val".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    let _req_resp = exchange.receive().await.unwrap();

    exchange.send(make_response_headers()).await.unwrap();
    let resp_resp = exchange.receive().await.unwrap();
    assert!(
        matches!(resp_resp, ExchangeEvent::ResponseHeaders { .. }),
        "should receive response headers on the same stream"
    );
}

#[tokio::test]
async fn duplex_streamed_body_chunks() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::StreamedBodyChunks {
        chunks: vec![b"chunk1".to_vec(), b"chunk2".to_vec(), b"chunk3".to_vec()],
    })
    .await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &full_duplex_exchange_config()).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    exchange.send(make_request_body(b"body", true)).await.unwrap();

    let _header_resp = exchange.receive().await.unwrap();

    let mut chunks_received = 0;
    for _ in 0..3 {
        let resp = exchange.receive().await.unwrap();
        assert!(
            matches!(resp, ExchangeEvent::RequestBody { .. }),
            "should receive body response chunk"
        );
        chunks_received += 1;
    }
    assert_eq!(chunks_received, 3, "should receive all 3 streamed body chunks");
}

#[tokio::test]
async fn duplex_immediate_response_on_headers() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::ImmediateOnHeaders {
        status: 403,
        body: "blocked".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    let resp = exchange.receive().await.unwrap();
    assert!(
        matches!(resp, ExchangeEvent::Immediate { .. }),
        "should receive ImmediateResponse during headers"
    );
}

#[tokio::test]
async fn duplex_immediate_response_on_body() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::ImmediateOnBody {
        status: 413,
        body: "too large".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &streamed_body_exchange_config()).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    let _hdr = exchange.receive().await.unwrap();
    exchange.send(make_request_body(b"big", true)).await.unwrap();
    let resp = exchange.receive().await.unwrap();
    assert!(
        matches!(resp, ExchangeEvent::Immediate { .. }),
        "should receive ImmediateResponse during body"
    );
}

#[tokio::test]
async fn duplex_unexpected_response_type_rejected() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::UnexpectedResponseType).await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    let result = exchange.receive().await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "wrong-phase response should be rejected by output validation"
    );
}

#[tokio::test]
async fn duplex_empty_stream_error() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::CloseEarly).await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    let result = exchange.receive().await;
    assert!(
        matches!(result, Err(ExchangeError::EmptyStream)),
        "should return EmptyStream when server closes without responding"
    );
}

#[tokio::test]
async fn duplex_timeout_before_response() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::Hang).await;
    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        message_timeout: Duration::from_millis(50),
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let result = exchange.receive().await;
    assert!(
        matches!(result, Err(ExchangeError::Timeout)),
        "should timeout when server hangs"
    );
}

#[tokio::test]
async fn duplex_timeout_override_accepted() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::OverrideTimeout {
        override_ms: 2000,
        delay_ms: 200,
        name: "x-after".to_owned(),
        value: "override".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        message_timeout: Duration::from_millis(100),
        max_message_timeout: Some(Duration::from_secs(5)),
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let resp = exchange.receive().await.unwrap();
    assert!(
        matches!(resp, ExchangeEvent::RequestHeaders { .. }),
        "override should extend deadline past delay"
    );
}

#[tokio::test]
async fn duplex_timeout_override_clamped() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::OverrideTimeout {
        override_ms: 5000,
        delay_ms: 300,
        name: "x-late".to_owned(),
        value: "val".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        message_timeout: Duration::from_millis(100),
        max_message_timeout: Some(Duration::from_millis(200)),
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let result = exchange.receive().await;
    assert!(
        matches!(result, Err(ExchangeError::Timeout)),
        "clamped override should still timeout"
    );
}

#[tokio::test]
async fn duplex_timeout_override_ignored_without_max() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::OverrideTimeout {
        override_ms: 500,
        delay_ms: 0,
        name: "x-after".to_owned(),
        value: "val".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    // Override envelope is consumed and ignored (no max_timeout
    // configured). The real response follows.
    let event = exchange.receive().await.unwrap();
    assert!(
        matches!(event, ExchangeEvent::RequestHeaders { .. }),
        "override without max_timeout is consumed and ignored; real response returned"
    );
}

#[test]
fn exchange_is_send_and_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<ExtProcExchange>();
    assert_sync::<ExtProcExchange>();
}

#[tokio::test]
async fn duplex_transport_error() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let channel = Endpoint::from_shared(format!("http://{addr}")).unwrap().connect_lazy();

    let config = ExchangeConfig {
        message_timeout: Duration::from_millis(500),
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    let send_result = exchange.send(make_request_headers()).await;
    if send_result.is_err() {
        return;
    }
    let recv_result = exchange.receive().await;
    assert!(recv_result.is_err(), "connecting to closed port should fail on receive");
}

#[tokio::test]
async fn duplex_finish_sending_causes_server_eof() {
    let eof_observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    struct EofObserver {
        eof_observed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait]
    impl ExternalProcessor for EofObserver {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let eof_flag = self.eof_observed.clone();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Ok(Some(msg)) = stream.message().await {
                    let resp = build_noop_response(&msg);
                    drop(tx.send(Ok(resp)).await);
                }
                eof_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let svc = ExternalProcessorServer::new(EofObserver {
        eof_observed: eof_observed.clone(),
    });
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _resp = exchange.receive().await.unwrap();
    exchange.finish_sending();

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        eof_observed.load(std::sync::atomic::Ordering::SeqCst),
        "server should observe EOF on request stream after finish_sending"
    );

    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_receive_after_finish_sending() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::DelayedRouting {
        header_name: "x-ep".to_owned(),
        header_value: "ep1".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &full_duplex_exchange_config()).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    exchange.send(make_request_body(b"data", true)).await.unwrap();
    exchange.finish_sending();

    let r1 = exchange.receive().await.unwrap();
    assert!(
        matches!(r1, ExchangeEvent::RequestHeaders { .. }),
        "should still receive after finish_sending"
    );
    let r2 = exchange.receive().await.unwrap();
    assert!(
        matches!(r2, ExchangeEvent::RequestBody { .. }),
        "should receive second response after finish_sending"
    );
}

#[tokio::test]
async fn duplex_send_after_finish_sending_fails() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::EchoHeaders {
        name: "x-test".to_owned(),
        value: "ok".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();

    exchange.finish_sending();
    let result = exchange.send(make_request_headers()).await;
    assert!(
        matches!(result, Err(ExchangeError::SendFailed)),
        "sending after finish_sending should fail deterministically"
    );
}

#[tokio::test]
async fn duplex_drop_exchange_cleans_up() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::Hang).await;
    let channel = connect_channel(addr).await;
    let exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
    drop(exchange);
}

#[tokio::test]
async fn duplex_concurrent_exchanges_no_crosstalk() {
    struct EchoIdProcessor;

    #[async_trait]
    impl ExternalProcessor for EchoIdProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Ok(Some(msg)) = stream.message().await {
                    if let Some(processing_request::Request::RequestHeaders(h)) = &msg.request {
                        let id_header = h
                            .headers
                            .as_ref()
                            .and_then(|m| m.headers.iter().find(|hv| hv.key == "x-exchange-id"))
                            .map(|hv| hv.value.clone())
                            .unwrap_or_default();
                        let resp = build_add_header_response(&msg, "x-echo-id", &id_header);
                        drop(tx.send(Ok(resp)).await);
                    }
                }
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(EchoIdProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let shared_channel = connect_channel(addr).await;

    let mut handles = Vec::new();
    for i in 0_u64..100 {
        let channel = shared_channel.clone();
        handles.push(tokio::spawn(async move {
            let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
            let unique_id = format!("exchange-{i}");
            let headers =
                processing_request::Request::RequestHeaders(praxis_proto::envoy::service::ext_proc::v3::HttpHeaders {
                    headers: Some(praxis_proto::envoy::service::ext_proc::v3::HeaderMap {
                        headers: vec![
                            HeaderValue {
                                key: ":method".to_owned(),
                                value: "GET".to_owned(),
                                raw_value: Vec::new(),
                            },
                            HeaderValue {
                                key: "x-exchange-id".to_owned(),
                                value: unique_id.clone(),
                                raw_value: Vec::new(),
                            },
                        ],
                    }),
                    end_of_stream: false,
                });
            exchange.send(headers).await.unwrap();
            let resp = exchange.receive().await.unwrap();
            if let ExchangeEvent::RequestHeaders { response: hr, .. } = &resp
                && let Some(common) = &hr.response
                && let Some(mutation) = &common.header_mutation
            {
                let echoed = mutation
                    .set_headers
                    .iter()
                    .find(|hvo| hvo.header.as_ref().is_some_and(|h| h.key == "x-echo-id"))
                    .and_then(|hvo| hvo.header.as_ref())
                    .map(|h| h.value.as_str());
                assert_eq!(
                    echoed,
                    Some(unique_id.as_str()),
                    "exchange {i} should echo back its own unique ID"
                );
                return;
            }
            panic!("exchange {i} did not receive expected echo response");
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_exchange_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ExtProcExchange>();
}

#[tokio::test]
async fn duplex_existing_fd00_tests_unaffected() {
    let (addr, _guard) = start_mock_processor(MockBehavior::AddHeader {
        name: "x-existing".to_owned(),
        value: "works".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let req = make_request(Method::GET, "/test");
    let mut ctx = make_ctx(&req);
    let action = callout::process_request_headers(channel, &addr.to_string(), Duration::from_secs(5), None, &mut ctx)
        .await
        .unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "existing callout should still work alongside duplex module"
    );
}

#[tokio::test]
async fn duplex_terminal_state_after_timeout() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::Hang).await;
    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        message_timeout: Duration::from_millis(50),
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _timeout = exchange.receive().await;
    assert!(exchange.is_terminal(), "exchange should be closed after timeout");

    let send_result = exchange.send(make_request_headers()).await;
    assert!(
        matches!(send_result, Err(ExchangeError::Closed)),
        "send after timeout should return Closed"
    );
    let recv_result = exchange.receive().await;
    assert!(
        matches!(recv_result, Err(ExchangeError::Closed)),
        "receive after timeout should return Closed"
    );
}

#[tokio::test]
async fn duplex_response_body_round_trip() {
    struct ResponseBodyProcessor;

    #[async_trait]
    impl ExternalProcessor for ResponseBodyProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Ok(Some(msg)) = stream.message().await {
                    let resp = match &msg.request {
                        Some(processing_request::Request::RequestHeaders(_)) => ProcessingResponse {
                            response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                                response: None,
                            })),
                            ..Default::default()
                        },
                        Some(processing_request::Request::ResponseHeaders(_)) => ProcessingResponse {
                            response: Some(processing_response::Response::ResponseHeaders(HeadersResponse {
                                response: None,
                            })),
                            ..Default::default()
                        },
                        Some(processing_request::Request::ResponseBody(_)) => ProcessingResponse {
                            response: Some(processing_response::Response::ResponseBody(BodyResponse {
                                response: None,
                            })),
                            ..Default::default()
                        },
                        _ => ProcessingResponse::default(),
                    };
                    drop(tx.send(Ok(resp)).await);
                }
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(ResponseBodyProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &streamed_body_exchange_config()).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    let _req_hdr = exchange.receive().await.unwrap();

    exchange.send(make_response_headers()).await.unwrap();
    let _resp_hdr = exchange.receive().await.unwrap();

    let resp_body = processing_request::Request::ResponseBody(praxis_proto::envoy::service::ext_proc::v3::HttpBody {
        body: b"response body data".to_vec(),
        end_of_stream: true,
    });
    exchange.send(resp_body).await.unwrap();
    let resp = exchange.receive().await.unwrap();
    assert!(
        matches!(resp, ExchangeEvent::ResponseBody { .. }),
        "should receive ResponseBody response"
    );

    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_server_observes_client_cancellation() {
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    struct CancellationObserver {
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait]
    impl ExternalProcessor for CancellationObserver {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let flag = self.cancelled.clone();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                if let Ok(Some(_msg)) = stream.message().await {
                    let resp = ProcessingResponse {
                        response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                            response: None,
                        })),
                        ..Default::default()
                    };
                    drop(tx.send(Ok(resp)).await);
                }
                while let Ok(Some(_msg)) = stream.message().await {}
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                drop(tx);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let svc = ExternalProcessorServer::new(CancellationObserver {
        cancelled: cancelled.clone(),
    });
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _resp = exchange.receive().await.unwrap();
    drop(exchange);

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        cancelled.load(std::sync::atomic::Ordering::SeqCst),
        "server should observe client cancellation when exchange is dropped"
    );

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_repeated_clean_close() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::EchoHeaders {
        name: "x-close".to_owned(),
        value: "test".to_owned(),
    })
    .await;

    let shared_channel = connect_channel(addr).await;

    for i in 0..20 {
        let mut exchange = ExtProcExchange::open(shared_channel.clone(), &default_exchange_config()).unwrap();
        exchange.send(make_request_headers()).await.unwrap();
        let resp = exchange.receive().await.unwrap();
        assert!(
            matches!(resp, ExchangeEvent::RequestHeaders { .. }),
            "exchange {i} should receive a response"
        );
        exchange.finish_sending();
    }
}

// -----------------------------------------------------------------------------
// Directional State and Ordering Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn duplex_request_body_before_headers_rejected() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::EchoHeaders {
        name: "x-t".to_owned(),
        value: "v".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &streamed_body_exchange_config()).unwrap();
    let result = exchange.send(make_request_body(b"data", false)).await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "body before headers should be rejected"
    );
}

#[tokio::test]
async fn duplex_duplicate_request_headers_rejected() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::EchoHeaders {
        name: "x-t".to_owned(),
        value: "v".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let result = exchange.send(make_request_headers()).await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "duplicate request headers should be rejected"
    );
}

#[tokio::test]
async fn duplex_body_after_eos_rejected() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::HeadersAndBody).await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &full_duplex_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    exchange.send(make_request_body(b"data", true)).await.unwrap();
    let result = exchange.send(make_request_body(b"more", false)).await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "body after EOS should be rejected"
    );
}

#[tokio::test]
async fn duplex_legal_response_while_request_open() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::FullLifecycle {
        req_header_name: "x-r".to_owned(),
        req_header_value: "v".to_owned(),
        resp_header_name: "x-s".to_owned(),
        resp_header_value: "v".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _req_resp = exchange.receive().await.unwrap();
    exchange.send(make_response_headers()).await.unwrap();
    let resp_resp = exchange.receive().await.unwrap();
    assert!(
        matches!(resp_resp, ExchangeEvent::ResponseHeaders { .. }),
        "response headers should be legal while request direction has only sent headers"
    );
}

#[tokio::test]
async fn duplex_request_trailers_send_and_classify() {
    struct TrailerProcessor;

    #[async_trait]
    impl ExternalProcessor for TrailerProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Ok(Some(msg)) = stream.message().await {
                    let resp = match &msg.request {
                        Some(processing_request::Request::RequestHeaders(_)) => ProcessingResponse {
                            response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                                response: None,
                            })),
                            ..Default::default()
                        },
                        Some(processing_request::Request::RequestTrailers(_)) => ProcessingResponse {
                            response: Some(processing_response::Response::RequestTrailers(TrailersResponse {
                                header_mutation: None,
                            })),
                            ..Default::default()
                        },
                        _ => ProcessingResponse::default(),
                    };
                    drop(tx.send(Ok(resp)).await);
                }
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(TrailerProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _hdr = exchange.receive().await.unwrap();

    let trailers =
        processing_request::Request::RequestTrailers(praxis_proto::envoy::service::ext_proc::v3::HttpTrailers {
            trailers: Some(praxis_proto::envoy::service::ext_proc::v3::HeaderMap { headers: vec![] }),
        });
    exchange.send(trailers).await.unwrap();
    let event = exchange.receive().await.unwrap();
    assert!(
        matches!(event, ExchangeEvent::RequestTrailers { .. }),
        "should classify request trailers response"
    );
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_dynamic_metadata_preserved() {
    struct MetadataProcessor;

    #[async_trait]
    impl ExternalProcessor for MetadataProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                if let Ok(Some(_msg)) = stream.message().await {
                    let mut fields = HashMap::new();
                    fields.insert(
                        "test_key".to_owned(),
                        prost_wkt_types::Value {
                            kind: Some(prost_wkt_types::value::Kind::StringValue("test_value".to_owned())),
                        },
                    );
                    let resp = ProcessingResponse {
                        response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                            response: None,
                        })),
                        dynamic_metadata: Some(prost_wkt_types::Struct { fields }),
                        ..Default::default()
                    };
                    drop(tx.send(Ok(resp)).await);
                }
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(MetadataProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let event = exchange.receive().await.unwrap();
    match event {
        ExchangeEvent::RequestHeaders { metadata, .. } => {
            let md = metadata.expect("metadata should be present");
            assert!(
                md.fields.contains_key("test_key"),
                "dynamic_metadata should be preserved on typed event"
            );
        },
        other => panic!("expected RequestHeaders, got {other:?}"),
    }
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_full_duplex_no_per_message_timeout() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::DelayedRouting {
        header_name: "x-ep".to_owned(),
        header_value: "ep1".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        message_timeout: Duration::from_millis(50),
        request_body_mode: BodySendMode::FullDuplexStreamed,
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    exchange.send(make_request_body(b"data", true)).await.unwrap();
    let event = exchange.receive().await.unwrap();
    assert!(
        matches!(event, ExchangeEvent::RequestHeaders { .. }),
        "full-duplex receive without timeout should succeed even with low message_timeout"
    );
}

#[tokio::test]
async fn duplex_immediate_response_sets_terminal() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::ImmediateOnHeaders {
        status: 403,
        body: "blocked".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let event = exchange.receive().await.unwrap();
    assert!(
        matches!(event, ExchangeEvent::Immediate { .. }),
        "should be immediate event"
    );
    assert!(
        exchange.is_terminal(),
        "exchange should be terminal after ImmediateResponse"
    );
    let send_result = exchange.send(make_request_body(b"data", true)).await;
    assert!(
        matches!(send_result, Err(ExchangeError::Closed)),
        "send after immediate should return Closed"
    );
}

#[tokio::test]
async fn duplex_override_envelope_ignores_response_data() {
    struct OverrideWithResponseProcessor;

    #[async_trait]
    impl ExternalProcessor for OverrideWithResponseProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                if let Ok(Some(msg)) = stream.message().await {
                    let override_with_response = ProcessingResponse {
                        response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                            response: None,
                        })),
                        override_message_timeout: Some(prost_types::Duration { seconds: 2, nanos: 0 }),
                        ..Default::default()
                    };
                    drop(tx.send(Ok(override_with_response)).await);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let real_resp = build_add_header_response(&msg, "x-real", "response");
                    drop(tx.send(Ok(real_resp)).await);
                }
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(OverrideWithResponseProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        max_message_timeout: Some(Duration::from_secs(5)),
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let event = exchange.receive().await.unwrap();
    match &event {
        ExchangeEvent::RequestHeaders { response, .. } => {
            assert!(
                response.response.is_some(),
                "should receive the REAL response, not the override envelope's response"
            );
        },
        other => panic!("expected RequestHeaders from real response, got {other:?}"),
    }
    drop(exchange);
    let _ = shutdown_tx.send(());
}

// -----------------------------------------------------------------------------
// Duplex Exchange Evidence Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn duplex_body_mode_none_rejects_body_send() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::EchoHeaders {
        name: "x-t".to_owned(),
        value: "v".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _hdr = exchange.receive().await.unwrap();
    let result = exchange.send(make_request_body(b"rejected", false)).await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "body send with BodySendMode::None should be rejected with OrderingViolation"
    );
}

#[tokio::test]
async fn duplex_non_full_duplex_body_creates_active_state() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::HeadersAndBody).await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &streamed_body_exchange_config()).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    let hdr_resp = exchange.receive().await.unwrap();
    assert!(
        matches!(hdr_resp, ExchangeEvent::RequestHeaders { .. }),
        "should receive header response before sending body"
    );

    exchange.send(make_request_body(b"chunk1", true)).await.unwrap();
    let body_resp = exchange.receive().await.unwrap();
    assert!(
        matches!(body_resp, ExchangeEvent::RequestBody { .. }),
        "non-full-duplex body chunk must receive body response before sending another"
    );
}

#[tokio::test]
async fn duplex_second_non_fd_send_while_active_rejected() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::HeadersAndBody).await;
    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &streamed_body_exchange_config()).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    let result = exchange.send(make_request_body(b"chunk", false)).await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "sending body before headers response should fail because active state is already outstanding"
    );
}

#[tokio::test]
async fn duplex_response_trailers_send_and_classify() {
    struct ResponseTrailerProcessor;

    #[async_trait]
    impl ExternalProcessor for ResponseTrailerProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Ok(Some(msg)) = stream.message().await {
                    let resp = match &msg.request {
                        Some(processing_request::Request::RequestHeaders(_)) => ProcessingResponse {
                            response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                                response: None,
                            })),
                            ..Default::default()
                        },
                        Some(processing_request::Request::ResponseHeaders(_)) => ProcessingResponse {
                            response: Some(processing_response::Response::ResponseHeaders(HeadersResponse {
                                response: None,
                            })),
                            ..Default::default()
                        },
                        Some(processing_request::Request::ResponseTrailers(_)) => ProcessingResponse {
                            response: Some(processing_response::Response::ResponseTrailers(TrailersResponse {
                                header_mutation: None,
                            })),
                            ..Default::default()
                        },
                        _ => ProcessingResponse::default(),
                    };
                    drop(tx.send(Ok(resp)).await);
                }
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(ResponseTrailerProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    let _req_hdr = exchange.receive().await.unwrap();

    exchange.send(make_response_headers()).await.unwrap();
    let _resp_hdr = exchange.receive().await.unwrap();

    let trailers =
        processing_request::Request::ResponseTrailers(praxis_proto::envoy::service::ext_proc::v3::HttpTrailers {
            trailers: Some(praxis_proto::envoy::service::ext_proc::v3::HeaderMap { headers: vec![] }),
        });
    exchange.send(trailers).await.unwrap();
    let event = exchange.receive().await.unwrap();
    assert!(
        matches!(event, ExchangeEvent::ResponseTrailers { .. }),
        "should classify response trailers response"
    );
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_metadata_on_body_event() {
    struct BodyMetadataProcessor;

    #[async_trait]
    impl ExternalProcessor for BodyMetadataProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Ok(Some(msg)) = stream.message().await {
                    let resp = match &msg.request {
                        Some(processing_request::Request::RequestHeaders(_)) => ProcessingResponse {
                            response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                                response: None,
                            })),
                            ..Default::default()
                        },
                        Some(processing_request::Request::RequestBody(_)) => {
                            let mut fields = HashMap::new();
                            fields.insert(
                                "body_key".to_owned(),
                                prost_wkt_types::Value {
                                    kind: Some(prost_wkt_types::value::Kind::StringValue("body_value".to_owned())),
                                },
                            );
                            ProcessingResponse {
                                response: Some(processing_response::Response::RequestBody(BodyResponse {
                                    response: None,
                                })),
                                dynamic_metadata: Some(prost_wkt_types::Struct { fields }),
                                ..Default::default()
                            }
                        },
                        _ => ProcessingResponse::default(),
                    };
                    drop(tx.send(Ok(resp)).await);
                }
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(BodyMetadataProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &streamed_body_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _hdr = exchange.receive().await.unwrap();
    exchange.send(make_request_body(b"data", true)).await.unwrap();
    let event = exchange.receive().await.unwrap();
    match event {
        ExchangeEvent::RequestBody { metadata, .. } => {
            let md = metadata.expect("metadata should be present on body event");
            assert!(
                md.fields.contains_key("body_key"),
                "dynamic_metadata should be preserved on ExchangeEvent::RequestBody"
            );
        },
        other => panic!("expected RequestBody, got {other:?}"),
    }
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_metadata_on_immediate_event() {
    struct ImmediateMetadataProcessor;

    #[async_trait]
    impl ExternalProcessor for ImmediateMetadataProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                if let Ok(Some(_msg)) = stream.message().await {
                    let mut fields = HashMap::new();
                    fields.insert(
                        "imm_key".to_owned(),
                        prost_wkt_types::Value {
                            kind: Some(prost_wkt_types::value::Kind::StringValue("imm_value".to_owned())),
                        },
                    );
                    let resp = ProcessingResponse {
                        response: Some(processing_response::Response::ImmediateResponse(ImmediateResponse {
                            status: Some(HttpStatus { code: 429 }),
                            headers: None,
                            body: "rate limited".to_owned(),
                            grpc_status: None,
                            details: String::new(),
                        })),
                        dynamic_metadata: Some(prost_wkt_types::Struct { fields }),
                        ..Default::default()
                    };
                    drop(tx.send(Ok(resp)).await);
                }
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(ImmediateMetadataProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let event = exchange.receive().await.unwrap();
    match event {
        ExchangeEvent::Immediate { metadata, .. } => {
            let md = metadata.expect("metadata should be present on immediate event");
            assert!(
                md.fields.contains_key("imm_key"),
                "dynamic_metadata should be preserved on ExchangeEvent::Immediate"
            );
        },
        other => panic!("expected Immediate, got {other:?}"),
    }
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_override_ignored_in_full_duplex() {
    struct FullDuplexOverrideProcessor;

    #[async_trait]
    impl ExternalProcessor for FullDuplexOverrideProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move {
                let _headers = stream.message().await.unwrap().unwrap();
                let override_envelope = build_override_response(5000);
                drop(tx.send(Ok(override_envelope)).await);
                let header_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(header_resp)).await);

                let _body = stream.message().await.unwrap().unwrap();
                use praxis_proto::envoy::service::ext_proc::v3::{
                    BodyMutation, CommonResponse, StreamedBodyResponse, body_mutation,
                };
                let body_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestBody(BodyResponse {
                        response: Some(CommonResponse {
                            body_mutation: Some(BodyMutation {
                                mutation: Some(body_mutation::Mutation::StreamedResponse(StreamedBodyResponse {
                                    body: b"data".to_vec(),
                                    end_of_stream: true,
                                })),
                            }),
                            ..Default::default()
                        }),
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(body_resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(FullDuplexOverrideProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        max_message_timeout: Some(Duration::from_secs(10)),
        ..full_duplex_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let hdr_event = exchange.receive().await.unwrap();
    assert!(
        matches!(hdr_event, ExchangeEvent::RequestHeaders { .. }),
        "override envelope ignored; real header response returned"
    );

    exchange.send(make_request_body(b"data", true)).await.unwrap();
    let body_event = exchange.receive().await.unwrap();
    assert!(
        matches!(body_event, ExchangeEvent::RequestBody { .. }),
        "should receive body response in full-duplex mode"
    );

    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_repeated_override_ignored() {
    struct DoubleOverrideProcessor;

    #[async_trait]
    impl ExternalProcessor for DoubleOverrideProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move {
                let msg = stream.message().await.unwrap().unwrap();
                let override1 = build_override_response(2000);
                drop(tx.send(Ok(override1)).await);
                let override2 = build_override_response(3000);
                drop(tx.send(Ok(override2)).await);
                let real_resp = build_add_header_response(&msg, "x-real", "response");
                drop(tx.send(Ok(real_resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(DoubleOverrideProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        max_message_timeout: Some(Duration::from_secs(10)),
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let event = exchange.receive().await.unwrap();
    match &event {
        ExchangeEvent::RequestHeaders { response, .. } => {
            assert!(
                response.response.is_some(),
                "should receive the real response with header mutation, not an override envelope"
            );
        },
        other => panic!("expected RequestHeaders from real response, got {other:?}"),
    }
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_zero_duration_override_ignored() {
    struct ZeroOverrideProcessor;

    #[async_trait]
    impl ExternalProcessor for ZeroOverrideProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                let msg = stream.message().await.unwrap().unwrap();
                let zero_override = ProcessingResponse {
                    override_message_timeout: Some(prost_types::Duration { seconds: 0, nanos: 0 }),
                    ..Default::default()
                };
                drop(tx.send(Ok(zero_override)).await);
                let real_resp = build_add_header_response(&msg, "x-real", "response");
                drop(tx.send(Ok(real_resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(ZeroOverrideProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        max_message_timeout: Some(Duration::from_secs(10)),
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let event = exchange.receive().await.unwrap();
    match &event {
        ExchangeEvent::RequestHeaders { response, .. } => {
            assert!(
                response.response.is_some(),
                "should receive the real response, not the zero-override envelope"
            );
        },
        other => panic!("expected RequestHeaders from real response, got {other:?}"),
    }
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_backpressure_deterministic() {
    struct BarrierProcessor {
        barrier: std::sync::Arc<tokio::sync::Barrier>,
    }

    #[async_trait]
    impl ExternalProcessor for BarrierProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let barrier = self.barrier.clone();
            let (tx, rx) = tokio::sync::mpsc::channel(16);
            tokio::spawn(async move {
                let _msg = stream.message().await.unwrap().unwrap();
                barrier.wait().await;
                while let Ok(Some(msg)) = stream.message().await {
                    let resp = build_noop_response(&msg);
                    drop(tx.send(Ok(resp)).await);
                }
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(BarrierProcessor {
        barrier: barrier.clone(),
    });
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &full_duplex_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();

    let chunk_size = 16_384; // 16 KiB
    let big_chunk = vec![0xAB_u8; chunk_size];
    let max_attempts = 256;
    let mut sent_count = 0_usize;
    for _ in 0..max_attempts {
        let send_fut = exchange.send(make_request_body(&big_chunk, false));
        let result = tokio::time::timeout(Duration::from_millis(200), send_fut).await;
        if result.is_err() {
            break;
        }
        result.unwrap().unwrap();
        sent_count += 1;
    }
    assert!(
        sent_count < max_attempts,
        "sends should eventually block due to backpressure; sent all {max_attempts} without blocking"
    );

    barrier.wait().await;

    let resume_send = exchange.send(make_request_body(b"after-release", true));
    let result = tokio::time::timeout(Duration::from_secs(2), resume_send).await;
    assert!(result.is_ok(), "sends should resume after barrier is released");

    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_deadline_starts_at_send_commit() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::Hang).await;
    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        message_timeout: Duration::from_millis(50),
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();

    let before_send = tokio::time::Instant::now();
    exchange.send(make_request_headers()).await.unwrap();

    tokio::time::sleep(Duration::from_millis(30)).await;

    let result = exchange.receive().await;
    let elapsed = before_send.elapsed();
    assert!(
        matches!(result, Err(ExchangeError::Timeout)),
        "should timeout when server hangs"
    );
    assert!(
        elapsed < Duration::from_millis(100),
        "deadline should be ~50ms from send, not from receive; elapsed: {elapsed:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(40),
        "deadline should not expire before the configured timeout; elapsed: {elapsed:?}"
    );
}

#[tokio::test]
async fn duplex_unsolicited_response_rejected() {
    struct UnsolicitedResponseProcessor;

    #[async_trait]
    impl ExternalProcessor for UnsolicitedResponseProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                let _msg = stream.message().await.unwrap().unwrap();
                let resp = ProcessingResponse {
                    response: Some(processing_response::Response::ResponseHeaders(HeadersResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(UnsolicitedResponseProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let result = exchange.receive().await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "unsolicited response for direction with no outbound headers should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("expected") || err.contains("unsolicited"),
        "error should indicate wrong response type: {err}"
    );
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_full_duplex_headers_no_timeout() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::OverrideTimeout {
        override_ms: 0,
        delay_ms: 200,
        name: "x-delayed".to_owned(),
        value: "ok".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        message_timeout: Duration::from_millis(50),
        request_body_mode: BodySendMode::FullDuplexStreamed,
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let event = exchange.receive().await.unwrap();
    assert!(
        matches!(event, ExchangeEvent::RequestHeaders { .. }),
        "full-duplex headers should not timeout even when response is delayed past message_timeout"
    );
}

#[tokio::test]
async fn duplex_full_duplex_trailers_while_deferred() {
    struct DeferredTrailerProcessor;

    #[async_trait]
    impl ExternalProcessor for DeferredTrailerProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(16);
            tokio::spawn(async move {
                let mut messages = Vec::new();
                while let Ok(Some(msg)) = stream.message().await {
                    let is_trailers = matches!(msg.request, Some(processing_request::Request::RequestTrailers(_)));
                    messages.push(msg);
                    if is_trailers {
                        break;
                    }
                }
                for msg in &messages {
                    let resp = match &msg.request {
                        Some(processing_request::Request::RequestHeaders(_)) => ProcessingResponse {
                            response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                                response: None,
                            })),
                            ..Default::default()
                        },
                        Some(processing_request::Request::RequestBody(_)) => {
                            use praxis_proto::envoy::service::ext_proc::v3::{
                                BodyMutation, CommonResponse, StreamedBodyResponse, body_mutation,
                            };
                            ProcessingResponse {
                                response: Some(processing_response::Response::RequestBody(BodyResponse {
                                    response: Some(CommonResponse {
                                        body_mutation: Some(BodyMutation {
                                            mutation: Some(body_mutation::Mutation::StreamedResponse(
                                                StreamedBodyResponse {
                                                    body: Vec::new(),
                                                    end_of_stream: false,
                                                },
                                            )),
                                        }),
                                        ..Default::default()
                                    }),
                                })),
                                ..Default::default()
                            }
                        },
                        Some(processing_request::Request::RequestTrailers(_)) => ProcessingResponse {
                            response: Some(processing_response::Response::RequestTrailers(TrailersResponse {
                                header_mutation: None,
                            })),
                            ..Default::default()
                        },
                        _ => ProcessingResponse::default(),
                    };
                    drop(tx.send(Ok(resp)).await);
                }
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(DeferredTrailerProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &full_duplex_exchange_config()).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    exchange.send(make_request_body(b"chunk1", false)).await.unwrap();
    exchange.send(make_request_body(b"chunk2", false)).await.unwrap();

    let trailers =
        processing_request::Request::RequestTrailers(praxis_proto::envoy::service::ext_proc::v3::HttpTrailers {
            trailers: Some(praxis_proto::envoy::service::ext_proc::v3::HeaderMap { headers: vec![] }),
        });
    exchange.send(trailers).await.unwrap();

    let r1 = exchange.receive().await.unwrap();
    assert!(
        matches!(r1, ExchangeEvent::RequestHeaders { .. }),
        "should receive deferred header response"
    );
    let r2 = exchange.receive().await.unwrap();
    assert!(
        matches!(r2, ExchangeEvent::RequestBody { .. }),
        "should receive body response"
    );
    let r3 = exchange.receive().await.unwrap();
    assert!(
        matches!(r3, ExchangeEvent::RequestBody { .. }),
        "should receive second body response"
    );
    let r4 = exchange.receive().await.unwrap();
    assert!(
        matches!(r4, ExchangeEvent::RequestTrailers { .. }),
        "should receive trailer response"
    );

    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_streamed_body_response_in_non_fd_rejected() {
    struct StreamedInNonFdProcessor;

    #[async_trait]
    impl ExternalProcessor for StreamedInNonFdProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                let _headers = stream.message().await.unwrap().unwrap();
                let header_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(header_resp)).await);

                let _body = stream.message().await.unwrap().unwrap();
                use praxis_proto::envoy::service::ext_proc::v3::{
                    BodyMutation, CommonResponse, StreamedBodyResponse, body_mutation,
                };
                let body_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestBody(BodyResponse {
                        response: Some(CommonResponse {
                            body_mutation: Some(BodyMutation {
                                mutation: Some(body_mutation::Mutation::StreamedResponse(StreamedBodyResponse {
                                    body: b"streamed".to_vec(),
                                    end_of_stream: true,
                                })),
                            }),
                            ..Default::default()
                        }),
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(body_resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(StreamedInNonFdProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &streamed_body_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _hdr = exchange.receive().await.unwrap();
    exchange.send(make_request_body(b"data", true)).await.unwrap();
    let result = exchange.receive().await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "StreamedBodyResponse mutation in non-full-duplex mode should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("StreamedBodyResponse"),
        "error should mention StreamedBodyResponse: {err}"
    );
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_non_streamed_body_response_in_fd_rejected() {
    struct NonStreamedInFdProcessor;

    #[async_trait]
    impl ExternalProcessor for NonStreamedInFdProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                let _headers = stream.message().await.unwrap().unwrap();
                let header_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(header_resp)).await);

                let _body = stream.message().await.unwrap().unwrap();
                let body_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestBody(BodyResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(body_resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(NonStreamedInFdProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &full_duplex_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _hdr = exchange.receive().await.unwrap();
    exchange.send(make_request_body(b"data", true)).await.unwrap();
    let result = exchange.receive().await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "non-StreamedBodyResponse mutation in full-duplex mode should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(err.contains("full-duplex"), "error should mention full-duplex: {err}");
    drop(exchange);
    let _ = shutdown_tx.send(());
}

// -----------------------------------------------------------------------------
// Duplex Exchange Regression Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn duplex_request_body_response_without_body_send_rejected() {
    struct HeadersOnlyFdProcessor;

    #[async_trait]
    impl ExternalProcessor for HeadersOnlyFdProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                let _headers = stream.message().await.unwrap().unwrap();
                let header_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(header_resp)).await);
                use praxis_proto::envoy::service::ext_proc::v3::{
                    BodyMutation, CommonResponse, StreamedBodyResponse, body_mutation,
                };
                let body_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestBody(BodyResponse {
                        response: Some(CommonResponse {
                            body_mutation: Some(BodyMutation {
                                mutation: Some(body_mutation::Mutation::StreamedResponse(StreamedBodyResponse {
                                    body: b"unsolicited".to_vec(),
                                    end_of_stream: true,
                                })),
                            }),
                            ..Default::default()
                        }),
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(body_resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(HeadersOnlyFdProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &full_duplex_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _hdr = exchange.receive().await.unwrap();
    let result = exchange.receive().await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "body response without any body send should be rejected in full-duplex"
    );
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_request_trailer_response_without_trailer_send_rejected() {
    struct HeadersBodyNoTrailerFdProcessor;

    #[async_trait]
    impl ExternalProcessor for HeadersBodyNoTrailerFdProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move {
                let _headers = stream.message().await.unwrap().unwrap();
                let header_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(header_resp)).await);

                let _body = stream.message().await.unwrap().unwrap();
                use praxis_proto::envoy::service::ext_proc::v3::{
                    BodyMutation, CommonResponse, StreamedBodyResponse, body_mutation,
                };
                let body_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestBody(BodyResponse {
                        response: Some(CommonResponse {
                            body_mutation: Some(BodyMutation {
                                mutation: Some(body_mutation::Mutation::StreamedResponse(StreamedBodyResponse {
                                    body: b"data".to_vec(),
                                    end_of_stream: true,
                                })),
                            }),
                            ..Default::default()
                        }),
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(body_resp)).await);

                let trailer_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestTrailers(TrailersResponse {
                        header_mutation: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(trailer_resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(HeadersBodyNoTrailerFdProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &full_duplex_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    exchange.send(make_request_body(b"data", true)).await.unwrap();
    let _hdr = exchange.receive().await.unwrap();
    let _body = exchange.receive().await.unwrap();
    let result = exchange.receive().await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "trailer response without trailer send should be rejected in full-duplex"
    );
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_response_body_response_without_body_send_rejected() {
    struct ResponseHeadersOnlyFdProcessor;

    #[async_trait]
    impl ExternalProcessor for ResponseHeadersOnlyFdProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                let _req_hdrs = stream.message().await.unwrap().unwrap();
                let req_hdr_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(req_hdr_resp)).await);

                let _resp_hdrs = stream.message().await.unwrap().unwrap();
                let resp_hdr_resp = ProcessingResponse {
                    response: Some(processing_response::Response::ResponseHeaders(HeadersResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(resp_hdr_resp)).await);

                use praxis_proto::envoy::service::ext_proc::v3::{
                    BodyMutation, CommonResponse, StreamedBodyResponse, body_mutation,
                };
                let body_resp = ProcessingResponse {
                    response: Some(processing_response::Response::ResponseBody(BodyResponse {
                        response: Some(CommonResponse {
                            body_mutation: Some(BodyMutation {
                                mutation: Some(body_mutation::Mutation::StreamedResponse(StreamedBodyResponse {
                                    body: b"unsolicited".to_vec(),
                                    end_of_stream: true,
                                })),
                            }),
                            ..Default::default()
                        }),
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(body_resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(ResponseHeadersOnlyFdProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &full_duplex_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _req_hdr = exchange.receive().await.unwrap();
    exchange.send(make_response_headers()).await.unwrap();
    let _resp_hdr = exchange.receive().await.unwrap();
    let result = exchange.receive().await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "response body response without body send should be rejected in full-duplex"
    );
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_response_trailer_response_without_trailer_send_rejected() {
    struct ResponseHeadersOnlyTrailerProcessor;

    #[async_trait]
    impl ExternalProcessor for ResponseHeadersOnlyTrailerProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                let _req_hdrs = stream.message().await.unwrap().unwrap();
                let req_hdr_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(req_hdr_resp)).await);

                let _resp_hdrs = stream.message().await.unwrap().unwrap();
                let resp_hdr_resp = ProcessingResponse {
                    response: Some(processing_response::Response::ResponseHeaders(HeadersResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(resp_hdr_resp)).await);

                let trailer_resp = ProcessingResponse {
                    response: Some(processing_response::Response::ResponseTrailers(TrailersResponse {
                        header_mutation: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(trailer_resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(ResponseHeadersOnlyTrailerProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &full_duplex_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _req_hdr = exchange.receive().await.unwrap();
    exchange.send(make_response_headers()).await.unwrap();
    let _resp_hdr = exchange.receive().await.unwrap();
    let result = exchange.receive().await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "response trailer response without trailer send should be rejected in full-duplex"
    );
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_duplicate_non_fd_body_response_rejected() {
    struct DuplicateBodyResponseProcessor;

    #[async_trait]
    impl ExternalProcessor for DuplicateBodyResponseProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move {
                let _headers = stream.message().await.unwrap().unwrap();
                let header_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(header_resp)).await);

                let _body = stream.message().await.unwrap().unwrap();
                let body_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestBody(BodyResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(body_resp)).await);

                let dup_body_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestBody(BodyResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(dup_body_resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(DuplicateBodyResponseProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &streamed_body_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _hdr = exchange.receive().await.unwrap();
    exchange.send(make_request_body(b"data", true)).await.unwrap();
    let _body = exchange.receive().await.unwrap();
    let result = exchange.receive().await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "duplicate body response in non-full-duplex mode should be rejected (no active state)"
    );
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_cross_direction_non_fd_response_without_active_match_rejected() {
    struct CrossDirectionProcessor;

    #[async_trait]
    impl ExternalProcessor for CrossDirectionProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                let _headers = stream.message().await.unwrap().unwrap();
                let resp = ProcessingResponse {
                    response: Some(processing_response::Response::ResponseHeaders(HeadersResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(CrossDirectionProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let result = exchange.receive().await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "cross-direction ResponseHeaders without response headers committed should be rejected"
    );
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_unsolicited_immediate_before_first_send_rejected() {
    struct ImmediateBeforeSendProcessor;

    #[async_trait]
    impl ExternalProcessor for ImmediateBeforeSendProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            _request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                let resp = ProcessingResponse {
                    response: Some(processing_response::Response::ImmediateResponse(ImmediateResponse {
                        status: Some(HttpStatus { code: 500 }),
                        headers: None,
                        body: "unsolicited".to_owned(),
                        grpc_status: None,
                        details: String::new(),
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(ImmediateBeforeSendProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
    let result = exchange.receive().await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "immediate response before first send should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("before first send"),
        "error should mention 'before first send': {err}"
    );
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_rejected_response_does_not_advance_output_phase() {
    struct WrongThenCorrectProcessor;

    #[async_trait]
    impl ExternalProcessor for WrongThenCorrectProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move {
                let _headers = stream.message().await.unwrap().unwrap();
                let wrong_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestBody(BodyResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(wrong_resp)).await);
                let correct_resp = ProcessingResponse {
                    response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                        response: None,
                    })),
                    ..Default::default()
                };
                drop(tx.send(Ok(correct_resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(WrongThenCorrectProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        request_body_mode: BodySendMode::Streamed,
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();

    let (req_before, resp_before) = exchange.output_phases();

    let result = exchange.receive().await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "RequestBody response before RequestHeaders output should be rejected"
    );

    let (req_after, resp_after) = exchange.output_phases();
    assert_eq!(
        req_before, req_after,
        "request output phase should be unchanged after rejection"
    );
    assert_eq!(
        resp_before, resp_after,
        "response output phase should be unchanged after rejection"
    );

    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_negative_override_ignored() {
    struct NegativeOverrideProcessor;

    #[async_trait]
    impl ExternalProcessor for NegativeOverrideProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                let msg = stream.message().await.unwrap().unwrap();
                let bad_override = ProcessingResponse {
                    override_message_timeout: Some(prost_types::Duration { seconds: -1, nanos: 0 }),
                    ..Default::default()
                };
                drop(tx.send(Ok(bad_override)).await);
                let real_resp = build_add_header_response(&msg, "x-real", "response");
                drop(tx.send(Ok(real_resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(NegativeOverrideProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        max_message_timeout: Some(Duration::from_secs(10)),
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let event = exchange.receive().await.unwrap();
    assert!(
        matches!(event, ExchangeEvent::RequestHeaders { .. }),
        "negative seconds override should be consumed and ignored; real response returned"
    );
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_negative_nanos_override_ignored() {
    struct NegativeNanosOverrideProcessor;

    #[async_trait]
    impl ExternalProcessor for NegativeNanosOverrideProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                let msg = stream.message().await.unwrap().unwrap();
                let bad_override = ProcessingResponse {
                    override_message_timeout: Some(prost_types::Duration { seconds: 1, nanos: -1 }),
                    ..Default::default()
                };
                drop(tx.send(Ok(bad_override)).await);
                let real_resp = build_add_header_response(&msg, "x-real", "response");
                drop(tx.send(Ok(real_resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(NegativeNanosOverrideProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        max_message_timeout: Some(Duration::from_secs(10)),
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let event = exchange.receive().await.unwrap();
    assert!(
        matches!(event, ExchangeEvent::RequestHeaders { .. }),
        "negative nanos override should be consumed and ignored; real response returned"
    );
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_out_of_range_nanos_override_ignored() {
    struct OutOfRangeNanosProcessor;

    #[async_trait]
    impl ExternalProcessor for OutOfRangeNanosProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                let msg = stream.message().await.unwrap().unwrap();
                let bad_override = ProcessingResponse {
                    override_message_timeout: Some(prost_types::Duration {
                        seconds: 1,
                        nanos: 2_000_000_000,
                    }),
                    ..Default::default()
                };
                drop(tx.send(Ok(bad_override)).await);
                let real_resp = build_add_header_response(&msg, "x-real", "response");
                drop(tx.send(Ok(real_resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(OutOfRangeNanosProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        max_message_timeout: Some(Duration::from_secs(10)),
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let event = exchange.receive().await.unwrap();
    assert!(
        matches!(event, ExchangeEvent::RequestHeaders { .. }),
        "out-of-range nanos override should be consumed and ignored; real response returned"
    );
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_sub_millisecond_override_ignored() {
    struct SubMsOverrideProcessor;

    #[async_trait]
    impl ExternalProcessor for SubMsOverrideProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                let msg = stream.message().await.unwrap().unwrap();
                let bad_override = ProcessingResponse {
                    override_message_timeout: Some(prost_types::Duration {
                        seconds: 0,
                        nanos: 500_000, // 0.5ms, below MIN_OVERRIDE
                    }),
                    ..Default::default()
                };
                drop(tx.send(Ok(bad_override)).await);
                let real_resp = build_add_header_response(&msg, "x-real", "response");
                drop(tx.send(Ok(real_resp)).await);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(SubMsOverrideProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        max_message_timeout: Some(Duration::from_secs(10)),
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let event = exchange.receive().await.unwrap();
    assert!(
        matches!(event, ExchangeEvent::RequestHeaders { .. }),
        "sub-millisecond override (0.5ms) should be consumed and ignored; real response returned"
    );
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_deadline_overflow_returns_error_not_panic() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::EchoHeaders {
        name: "x-overflow".to_owned(),
        value: "test".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let config = ExchangeConfig {
        message_timeout: Duration::MAX,
        ..default_exchange_config()
    };
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    let result = exchange.send(make_request_headers()).await;
    assert!(
        matches!(result, Err(ExchangeError::DeadlineOverflow)),
        "Duration::MAX should fail at send with deadline overflow, not panic"
    );
}

#[tokio::test]
async fn duplex_trailer_metadata_preserved() {
    struct TrailerMetadataProcessor;

    #[async_trait]
    impl ExternalProcessor for TrailerMetadataProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Ok(Some(msg)) = stream.message().await {
                    let resp = match &msg.request {
                        Some(processing_request::Request::RequestHeaders(_)) => ProcessingResponse {
                            response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                                response: None,
                            })),
                            ..Default::default()
                        },
                        Some(processing_request::Request::RequestTrailers(_)) => {
                            let mut fields = HashMap::new();
                            fields.insert(
                                "trailer_key".to_owned(),
                                prost_wkt_types::Value {
                                    kind: Some(prost_wkt_types::value::Kind::StringValue("trailer_value".to_owned())),
                                },
                            );
                            ProcessingResponse {
                                response: Some(processing_response::Response::RequestTrailers(TrailersResponse {
                                    header_mutation: None,
                                })),
                                dynamic_metadata: Some(prost_wkt_types::Struct { fields }),
                                ..Default::default()
                            }
                        },
                        _ => ProcessingResponse::default(),
                    };
                    drop(tx.send(Ok(resp)).await);
                }
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(TrailerMetadataProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _hdr = exchange.receive().await.unwrap();
    exchange.send(make_request_trailers()).await.unwrap();
    let event = exchange.receive().await.unwrap();
    match event {
        ExchangeEvent::RequestTrailers { metadata, .. } => {
            let md = metadata.expect("metadata should be present on trailer event");
            assert!(
                md.fields.contains_key("trailer_key"),
                "dynamic_metadata should be preserved on ExchangeEvent::RequestTrailers"
            );
        },
        other => panic!("expected RequestTrailers, got {other:?}"),
    }
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_cancelled_blocked_send_leaves_state_unchanged() {
    use crate::duplex::commit_message;

    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let timeout = Duration::from_millis(200);

    let fill_msg = ProcessingRequest {
        request: Some(make_request_headers()),
        ..Default::default()
    };
    tx.send(fill_msg).await.unwrap();

    {
        let cancelled_msg = ProcessingRequest {
            request: Some(make_request_body(b"CANCELLED_ID", false)),
            ..Default::default()
        };
        let blocked = commit_message(&tx, cancelled_msg, Some(timeout));
        let poll_result = tokio::time::timeout(Duration::from_millis(50), blocked).await;
        assert!(poll_result.is_err(), "send should be pending while channel is full");
    }

    let first = rx.recv().await.unwrap();
    assert!(
        matches!(first.request, Some(processing_request::Request::RequestHeaders(_))),
        "first received should be the fill message, not the cancelled body"
    );

    assert!(
        rx.try_recv().is_err(),
        "channel should be empty after removing the fill message; cancelled message must not be present"
    );

    let followup_msg = ProcessingRequest {
        request: Some(make_request_body(b"FOLLOWUP_ID", true)),
        ..Default::default()
    };
    let result = commit_message(&tx, followup_msg, None).await;
    assert!(result.is_ok(), "follow-up should succeed after cancelled send");

    let received = rx.recv().await.unwrap();
    if let Some(processing_request::Request::RequestBody(body)) = &received.request {
        assert_eq!(
            body.body, b"FOLLOWUP_ID",
            "should receive follow-up, not cancelled message"
        );
    } else {
        panic!("expected RequestBody follow-up");
    }
}

#[tokio::test]
async fn duplex_repeated_close_with_eof_count() {
    let eof_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    struct EofCountingProcessor {
        eof_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl ExternalProcessor for EofCountingProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let eof_count = self.eof_count.clone();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Ok(Some(msg)) = stream.message().await {
                    let resp = build_noop_response(&msg);
                    drop(tx.send(Ok(resp)).await);
                }
                eof_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(EofCountingProcessor {
        eof_count: eof_count.clone(),
    });
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let shared_channel = connect_channel(addr).await;

    for i in 0..100 {
        let mut exchange = ExtProcExchange::open(shared_channel.clone(), &default_exchange_config()).unwrap();
        exchange.send(make_request_headers()).await.unwrap();
        let resp = exchange.receive().await.unwrap();
        assert!(
            matches!(resp, ExchangeEvent::RequestHeaders { .. }),
            "exchange {i} should receive a response"
        );
        exchange.finish_sending();
        drop(exchange);
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let observed = eof_count.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(observed, 100, "server should observe exactly 100 EOFs, got {observed}");

    let mut final_exchange = ExtProcExchange::open(shared_channel.clone(), &default_exchange_config()).unwrap();
    final_exchange.send(make_request_headers()).await.unwrap();
    let resp = final_exchange.receive().await.unwrap();
    assert!(
        matches!(resp, ExchangeEvent::RequestHeaders { .. }),
        "final exchange on same channel should succeed"
    );
    final_exchange.finish_sending();

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_cross_direction_started_non_fd_duplicate_body_rejected() {
    struct WrongTypeProcessor;

    #[async_trait]
    impl ExternalProcessor for WrongTypeProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(16);
            tokio::spawn(async move {
                let mut msg_count = 0_u32;
                while let Ok(Some(msg)) = stream.message().await {
                    msg_count += 1;
                    let resp = if msg_count == 5 {
                        ProcessingResponse {
                            response: Some(processing_response::Response::ResponseBody(BodyResponse {
                                response: None,
                            })),
                            ..Default::default()
                        }
                    } else {
                        build_noop_response(&msg)
                    };
                    drop(tx.send(Ok(resp)).await);
                }
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ExternalProcessorServer::new(WrongTypeProcessor);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let config = streamed_body_exchange_config();
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _rh = exchange.receive().await.unwrap();

    exchange.send(make_request_body(b"chunk1", false)).await.unwrap();
    let _rb = exchange.receive().await.unwrap();

    exchange.send(make_response_headers()).await.unwrap();
    let _resh = exchange.receive().await.unwrap();

    exchange
        .send(processing_request::Request::ResponseBody(
            praxis_proto::envoy::service::ext_proc::v3::HttpBody {
                body: b"resp_body".to_vec(),
                end_of_stream: false,
            },
        ))
        .await
        .unwrap();
    let _resb = exchange.receive().await.unwrap();

    exchange.send(make_request_body(b"chunk2", false)).await.unwrap();
    let result = exchange.receive().await;
    assert!(
        matches!(result, Err(ExchangeError::OrderingViolation(_))),
        "ResponseBody when active expects RequestBody must be rejected"
    );
    drop(exchange);
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn duplex_blocked_send_deadline_starts_after_commit() {
    use std::pin::pin;

    use crate::duplex::commit_message;

    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let timeout = Duration::from_millis(200);

    let fill_msg = ProcessingRequest {
        request: Some(make_request_headers()),
        ..Default::default()
    };
    tx.send(fill_msg).await.unwrap();

    let target_msg = ProcessingRequest {
        request: Some(make_request_body(b"target", false)),
        ..Default::default()
    };
    let mut blocked_future = pin!(commit_message(&tx, target_msg, Some(timeout)));

    let poll_result = tokio::time::timeout(Duration::from_millis(250), &mut blocked_future).await;
    assert!(poll_result.is_err(), "send should remain pending while channel is full");

    let _first = rx.recv().await.unwrap();

    let result = blocked_future.await;
    let deadline = result.unwrap().unwrap();

    let remaining = deadline.duration_since(tokio::time::Instant::now());
    assert!(
        remaining > Duration::from_millis(150),
        "deadline should have ~200ms remaining since it started at commit, not at reserve: {remaining:?}"
    );
}

// -------------------------------------------------------------------------
// Single-Owner Pending-Process Driver Tests
// -------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn driver_delayed_response_headers_current_thread() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::DelayedRouting {
        header_name: "x-ep".to_owned(),
        header_value: "ep1".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let config = full_duplex_exchange_config();
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    exchange.send(make_request_body(b"chunk1", false)).await.unwrap();
    exchange.send(make_request_body(b"chunk2", false)).await.unwrap();
    exchange.send(make_request_body(b"", true)).await.unwrap();

    let event = tokio::time::timeout(Duration::from_secs(5), exchange.receive())
        .await
        .expect("should not timeout")
        .expect("should receive headers response");
    assert!(
        matches!(event, ExchangeEvent::RequestHeaders { .. }),
        "first event should be request headers response"
    );
}

#[tokio::test]
async fn driver_one_process_invocation() {
    let invocation_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    struct CountingProcessor {
        count: std::sync::Arc<std::sync::atomic::AtomicU32>,
    }

    #[async_trait]
    impl ExternalProcessor for CountingProcessor {
        type ProcessStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

        async fn process(
            &self,
            request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
        ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut stream = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Ok(Some(_msg)) = stream.message().await {
                    let resp = ProcessingResponse {
                        response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
                            response: None,
                        })),
                        ..Default::default()
                    };
                    drop(tx.send(Ok(resp)).await);
                }
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        }
    }

    let svc = ExternalProcessorServer::new(CountingProcessor {
        count: invocation_count.clone(),
    });
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    wait_for_server(addr).await;

    let channel = connect_channel(addr).await;
    let mut exchange = ExtProcExchange::open(channel, &default_exchange_config()).unwrap();
    exchange.send(make_request_headers()).await.unwrap();
    let _resp = exchange.receive().await.unwrap();
    drop(exchange.send(make_request_headers()).await);
    drop(exchange);

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        invocation_count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "exactly one Process invocation per exchange"
    );

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn driver_outbound_half_close_preserves_drain() {
    let (addr, _guard) = start_duplex_processor(DuplexBehavior::ImmediateOnBody {
        status: 403,
        body: "blocked".to_owned(),
    })
    .await;
    let channel = connect_channel(addr).await;
    let config = full_duplex_exchange_config();
    let mut exchange = ExtProcExchange::open(channel, &config).unwrap();

    exchange.send(make_request_headers()).await.unwrap();
    let _hdr = exchange.receive().await.unwrap();
    exchange.send(make_request_body(b"data", true)).await.unwrap();

    let event = tokio::time::timeout(Duration::from_secs(5), exchange.receive())
        .await
        .expect("should not timeout")
        .expect("should receive immediate response");
    assert!(
        matches!(&event, ExchangeEvent::Immediate { response, .. } if response.status.as_ref().is_some_and(|s| s.code == 403)),
        "should receive ImmediateResponse with exact 403 status"
    );
}
