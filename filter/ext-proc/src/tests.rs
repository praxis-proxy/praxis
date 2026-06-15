// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
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

/// Build a minimal [`HttpFilterContext`] for unit tests.
fn make_ctx(req: &praxis_filter::Request) -> HttpFilterContext<'_> {
    HttpFilterContext {
        body_done_indices: Vec::new(),
        branch_iterations: HashMap::new(),
        client_addr: None,
        cluster: None,
        downstream_tls: false,
        executed_filter_indices: Vec::new(),
        extra_request_headers: Vec::new(),
        request_headers_to_remove: Vec::new(),
        request_headers_to_set: Vec::new(),
        filter_metadata: HashMap::new(),
        filter_results: HashMap::new(),
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
    BodyResponse, ProcessingRequest, ProcessingResponse,
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
        Some(processing_request::Request::ResponseHeaders(_)) => {
            processing_response::Response::ResponseHeaders(HeadersResponse { response: None })
        },
        _ => processing_response::Response::RequestHeaders(HeadersResponse { response: None }),
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
