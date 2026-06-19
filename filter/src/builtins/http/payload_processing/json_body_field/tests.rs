// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the JSON body field filter.

use bytes::Bytes;

use super::{JsonBodyFieldFilter, extract::contains_control_chars};
use crate::{FilterAction, filter::HttpFilter as _};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn parse_single_field_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        field: model
        header: X-Model
        "#,
    )
    .unwrap();
    let filter = JsonBodyFieldFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "json_body_field", "single-field config should parse");
}

#[test]
fn parse_multi_field_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        fields:
          - field: model
            header: X-Model
          - field: user_id
            header: X-User-Id
        "#,
    )
    .unwrap();
    let filter = JsonBodyFieldFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "json_body_field", "multi-field config should parse");
}

#[test]
fn reject_both_syntaxes() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        field: model
        header: X-Model
        fields:
          - field: user_id
            header: X-User-Id
        "#,
    )
    .unwrap();
    let err = JsonBodyFieldFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("not both"),
        "should reject mixed syntax, got: {err}"
    );
}

#[test]
fn reject_empty_fields_list() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("fields: []").unwrap();
    let err = JsonBodyFieldFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("must not be empty"),
        "should reject empty fields list, got: {err}"
    );
}

#[test]
fn reject_empty_field_in_list() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        fields:
          - field: ""
            header: X-Model
        "#,
    )
    .unwrap();
    let err = JsonBodyFieldFilter::from_config(&yaml).err().expect("should fail");
    assert!(err.to_string().contains("'field' must not be empty"), "got: {err}");
}

#[test]
fn reject_empty_field() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("field: ''\nheader: X-Model").unwrap();
    let err = JsonBodyFieldFilter::from_config(&yaml).err().expect("should fail");
    assert!(err.to_string().contains("'field' must not be empty"), "got: {err}");
}

#[test]
fn reject_empty_header() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("field: model\nheader: ''").unwrap();
    let err = JsonBodyFieldFilter::from_config(&yaml).err().expect("should fail");
    assert!(err.to_string().contains("'header' must not be empty"), "got: {err}");
}

#[test]
fn reject_missing_both() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let err = JsonBodyFieldFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("'field' is required"),
        "should require field, got: {err}"
    );
}

#[tokio::test]
async fn extracts_field_from_complete_json() {
    let filter = make_filter("model", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{"model":"claude-sonnet-4-5","prompt":"hi"}"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "should release after extracting field"
    );
}

#[tokio::test]
async fn extracts_multiple_fields_in_single_parse() {
    let filter = make_multi_filter(&[("model", "X-Model"), ("user_id", "X-User-Id")]);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{"model":"claude-sonnet-4-5","user_id":"u-42","prompt":"hi"}"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "should release after extracting fields"
    );
    assert_eq!(ctx.extra_request_headers.len(), 2, "should add two headers");
    let (n0, v0) = &ctx.extra_request_headers[0];
    assert_eq!(n0, "X-Model", "first mapping should extract model name");
    assert_eq!(v0, "claude-sonnet-4-5", "first mapping should extract model value");
    let (n1, v1) = &ctx.extra_request_headers[1];
    assert_eq!(n1, "X-User-Id", "second mapping should extract user_id name");
    assert_eq!(v1, "u-42", "second mapping should extract user_id value");
}

#[tokio::test]
async fn partial_multi_field_match_still_releases() {
    let filter = make_multi_filter(&[("model", "X-Model"), ("user_id", "X-User-Id")]);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{"model":"claude-sonnet-4-5","prompt":"hi"}"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "should release when at least one field matches"
    );
    assert_eq!(ctx.extra_request_headers.len(), 1, "should add only matched header");
    let (name, value) = &ctx.extra_request_headers[0];
    assert_eq!(name, "X-Model", "only model name should be extracted");
    assert_eq!(value, "claude-sonnet-4-5", "only model value should be extracted");
}

#[tokio::test]
async fn no_multi_field_match_continues() {
    let filter = make_multi_filter(&[("model", "X-Model"), ("user_id", "X-User-Id")]);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{"prompt":"hi","temperature":0.7}"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "should continue when no fields match"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "no headers should be added when no fields match"
    );
}

#[tokio::test]
async fn returns_continue_on_incomplete_json() {
    let filter = make_filter("model", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let partial = br#"{"model":"claude-sonnet-4-5","pro"#;
    let mut body = Some(Bytes::from_static(partial));

    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "incomplete JSON should continue"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "no headers should be added for incomplete JSON"
    );
}

#[tokio::test]
async fn returns_continue_when_field_missing() {
    let filter = make_filter("model", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{"prompt":"hello","temperature":0.7}"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "missing field should continue"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "no headers should be added when field missing"
    );
}

#[tokio::test]
async fn promotes_to_configured_header() {
    let filter = make_filter("user_id", "X-User-Id");
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{"user_id":"abc-123","data":"payload"}"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "should release after promoting field"
    );
    assert_eq!(ctx.extra_request_headers.len(), 1, "should add exactly one header");
    let (name, value) = &ctx.extra_request_headers[0];
    assert_eq!(name, "X-User-Id", "promoted header name should match");
    assert_eq!(value, "abc-123", "promoted header value should match field value");
}

#[tokio::test]
async fn on_request_is_noop() {
    let filter = make_filter("model", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "on_request should be a no-op");
}

#[tokio::test]
async fn returns_continue_on_none_body() {
    let filter = make_filter("model", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body: Option<Bytes> = None;

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "None body should continue");
}

#[tokio::test]
async fn numeric_field_promoted_as_string() {
    let filter = make_filter("count", "X-Count");
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{"count":42}"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "numeric field should trigger release"
    );
    assert_eq!(ctx.extra_request_headers.len(), 1, "should add exactly one header");
    let (name, value) = &ctx.extra_request_headers[0];
    assert_eq!(name, "X-Count", "header name should match");
    assert_eq!(value, "42", "numeric value should be stringified");
}

#[test]
fn body_access_is_read_only() {
    let filter = make_filter("f", "H");
    assert_eq!(
        filter.request_body_access(),
        crate::body::BodyAccess::ReadOnly,
        "body access should be read-only"
    );
}

#[test]
fn body_mode_is_stream_buffer_with_default_limit() {
    let filter = make_filter("f", "H");
    assert_eq!(
        filter.request_body_mode(),
        crate::body::BodyMode::StreamBuffer {
            max_bytes: Some(crate::body::DEFAULT_JSON_BODY_MAX_BYTES)
        },
        "body mode should be StreamBuffer with 10 MiB default limit"
    );
}

#[tokio::test]
async fn rejects_value_with_newline() {
    let filter = make_filter("model", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = b"{\"model\":\"bad\\nvalue\",\"prompt\":\"hi\"}";
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "should continue when value contains control chars"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "header should not be injected for value with newline"
    );
}

#[tokio::test]
async fn rejects_value_with_carriage_return() {
    let filter = make_filter("model", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = b"{\"model\":\"bad\\rvalue\",\"prompt\":\"hi\"}";
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "should continue when value contains carriage return"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "header should not be injected for value with CR"
    );
}

#[tokio::test]
async fn rejects_value_with_null_byte() {
    let filter = make_filter("model", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = b"{\"model\":\"bad\\u0000value\",\"prompt\":\"hi\"}";
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "should continue when value contains null byte"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "header should not be injected for value with null byte"
    );
}

#[tokio::test]
async fn allows_value_with_tab() {
    let filter = make_filter("model", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = b"{\"model\":\"with\\ttab\",\"prompt\":\"hi\"}";
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "tab character should be allowed in header values"
    );
    assert_eq!(
        ctx.extra_request_headers.len(),
        1,
        "header should be injected for value with tab"
    );
}

#[tokio::test]
async fn multi_field_skips_only_control_char_values() {
    let filter = make_multi_filter(&[("model", "X-Model"), ("user_id", "X-User-Id")]);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = b"{\"model\":\"bad\\nvalue\",\"user_id\":\"u-42\"}";
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "should release when at least one clean field found"
    );
    assert_eq!(
        ctx.extra_request_headers.len(),
        1,
        "only clean field should be promoted"
    );
    let (name, value) = &ctx.extra_request_headers[0];
    assert_eq!(name, "X-User-Id", "clean field should be promoted");
    assert_eq!(value, "u-42", "clean value should be promoted");
}

#[test]
fn contains_control_chars_rejects_unit_separator() {
    assert!(
        contains_control_chars("\x1F"),
        "0x1F (unit separator) should be rejected"
    );
}

#[test]
fn contains_control_chars_allows_space() {
    assert!(!contains_control_chars(" "), "0x20 (space) should be allowed");
}

#[test]
fn contains_control_chars_allows_printable_ascii() {
    assert!(
        !contains_control_chars("hello world!"),
        "printable ASCII should be allowed"
    );
}

#[test]
fn contains_control_chars_rejects_esc() {
    assert!(contains_control_chars("\x1B"), "ESC (0x1B) should be rejected");
}

#[test]
fn contains_control_chars_rejects_del() {
    assert!(contains_control_chars("\x7F"), "DEL (0x7F) should be rejected");
}

#[test]
fn contains_control_chars_allows_tab() {
    assert!(!contains_control_chars("\t"), "horizontal tab should be allowed");
}

#[tokio::test]
async fn boolean_field_promoted_as_string() {
    let filter = make_filter("flag", "X-Flag");
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{"flag":true}"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "boolean field should trigger release"
    );
    assert_eq!(ctx.extra_request_headers.len(), 1, "should add exactly one header");
    let (name, value) = &ctx.extra_request_headers[0];
    assert_eq!(name, "X-Flag", "header name should match");
    assert_eq!(value, "true", "boolean value should be stringified");
}

#[tokio::test]
async fn nested_object_field_promoted_as_json() {
    let filter = make_filter("metadata", "X-Metadata");
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{"metadata":{"key":"val"}}"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "nested object field should trigger release"
    );
    assert_eq!(ctx.extra_request_headers.len(), 1, "should add exactly one header");
    let (name, value) = &ctx.extra_request_headers[0];
    assert_eq!(name, "X-Metadata", "header name should match");
    assert!(
        value.contains("key") && value.contains("val"),
        "nested object should be serialized as JSON string: {value}"
    );
}

#[tokio::test]
async fn empty_json_body_continues() {
    let filter = make_filter("model", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{}"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "empty JSON object should continue"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "no headers should be added for empty JSON"
    );
}

#[tokio::test]
async fn non_json_body_continues() {
    let filter = make_filter("model", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"not json at all"));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "non-JSON body should continue"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "no headers should be added for non-JSON body"
    );
}

#[tokio::test]
async fn array_root_json_continues() {
    let filter = make_filter("model", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"[1,2,3]"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "array root JSON should continue since fields cannot be extracted"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "no headers should be added for array root JSON"
    );
}

#[tokio::test]
async fn scalar_root_json_continues() {
    let filter = make_filter("model", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#""hello""#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "scalar root JSON should continue since fields cannot be extracted"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "no headers should be added for scalar root JSON"
    );
}

#[tokio::test]
async fn null_field_value_promoted_as_string() {
    let filter = make_filter("model", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{"model":null}"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "null field value should trigger release"
    );
    assert_eq!(ctx.extra_request_headers.len(), 1, "should add exactly one header");
    let (name, value) = &ctx.extra_request_headers[0];
    assert_eq!(name, "X-Model", "header name should match");
    assert_eq!(value, "null", "null value should be stringified as 'null'");
}

#[tokio::test]
async fn deeply_nested_with_null_continues() {
    let filter = make_filter("metadata", "X-Metadata");
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{"metadata":{"inner":null}}"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "nested object with null inner should trigger release"
    );
    assert_eq!(ctx.extra_request_headers.len(), 1, "should add exactly one header");
    let (name, value) = &ctx.extra_request_headers[0];
    assert_eq!(name, "X-Metadata", "header name should match");
    assert!(
        value.contains("inner") && value.contains("null"),
        "nested object with null should be serialized as JSON string: {value}"
    );
}

#[tokio::test]
async fn field_name_with_dot() {
    let filter = make_filter("my.model", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{"my.model":"gpt-4o"}"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "dotted field name should be extractable"
    );
    assert_eq!(ctx.extra_request_headers.len(), 1, "should add exactly one header");
    let (name, value) = &ctx.extra_request_headers[0];
    assert_eq!(name, "X-Model", "header name should match");
    assert_eq!(value, "gpt-4o", "dotted field value should match");
}

#[tokio::test]
async fn field_name_with_unicode() {
    let filter = make_filter("mod\u{00e9}le", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = "{\"mod\u{00e9}le\":\"claude\"}";
    let mut body = Some(Bytes::from(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "unicode field name should be extractable"
    );
    assert_eq!(ctx.extra_request_headers.len(), 1, "should add exactly one header");
    let (name, value) = &ctx.extra_request_headers[0];
    assert_eq!(name, "X-Model", "header name should match");
    assert_eq!(value, "claude", "unicode field value should match");
}

#[tokio::test]
async fn empty_string_field_value_promoted() {
    let filter = make_filter("model", "X-Model");
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{"model":""}"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "empty string field should trigger release"
    );
    assert_eq!(ctx.extra_request_headers.len(), 1, "should add exactly one header");
    let (name, value) = &ctx.extra_request_headers[0];
    assert_eq!(name, "X-Model", "header name should match");
    assert_eq!(value, "", "empty string value should be promoted as empty header");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a single-mapping filter for testing.
fn make_filter(field: &str, header: &str) -> JsonBodyFieldFilter {
    JsonBodyFieldFilter {
        max_body_bytes: crate::body::DEFAULT_JSON_BODY_MAX_BYTES,
        mappings: vec![(field.to_owned(), header.to_owned())],
    }
}

/// Build a multi-mapping filter for testing.
fn make_multi_filter(mappings: &[(&str, &str)]) -> JsonBodyFieldFilter {
    JsonBodyFieldFilter {
        max_body_bytes: crate::body::DEFAULT_JSON_BODY_MAX_BYTES,
        mappings: mappings
            .iter()
            .map(|(f, h)| ((*f).to_owned(), (*h).to_owned()))
            .collect(),
    }
}
