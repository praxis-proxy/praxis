// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the JSON body pointer filter.

use bytes::Bytes;
use serde_json::json;

use super::{JsonBodyFilter, JsonBodyOps};
use crate::{
    FilterAction,
    json_ops::{JsonOps, JsonValue},
};

fn parse_filter(yaml: &str) -> Box<dyn crate::HttpFilter> {
    let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
    JsonBodyFilter::from_config(&value).unwrap()
}

fn parse_err(yaml: &str) -> String {
    let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
    JsonBodyFilter::from_config(&value).err().unwrap().to_string()
}

/// JSON nested deeper than the tokenizer depth limit (128 levels).
fn depth_exceeded_body() -> Bytes {
    let mut nested = String::from("1");
    for _ in 0..130 {
        nested = format!("[{nested}]");
    }
    Bytes::from(nested)
}

#[test]
fn parses_header_like_config() {
    let filter = parse_filter(
        r#"
        request_add:
          - pointer: /tenant
            value: acme
        request_remove:
          - /password
        request_replace:
          - pointer: /model
            value: forced-model
        "#,
    );
    assert_eq!(filter.name(), "json_body", "filter type name");
}

#[test]
fn parses_documented_extract_and_header_combo() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
          - pointer: /stream
            header: X-Stream
        request_add:
          - pointer: /tenant
            value: acme
          - pointer: /original_model
            metadata: original.model
        request_remove:
          - /password
        request_replace:
          - pointer: /model
            value: forced-model
        response_remove:
          - /internal
        "#,
    );
    assert_eq!(filter.name(), "json_body");
    assert_eq!(filter.request_body_access(), crate::BodyAccess::ReadWrite);
}

#[test]
fn from_ops_constructs_without_yaml() {
    let request = JsonOps::builder()
        .replace("/model", JsonValue::static_json(json!("forced-model")).unwrap())
        .unwrap()
        .build()
        .unwrap();
    let filter = JsonBodyFilter::from_ops(JsonBodyOps {
        request,
        ..JsonBodyOps::default()
    })
    .unwrap();
    assert_eq!(filter.name(), "json_body");
    assert_eq!(filter.request_body_access(), crate::BodyAccess::ReadWrite);
}

#[test]
fn from_ops_rejects_empty() {
    let err = JsonBodyFilter::from_ops(JsonBodyOps::default())
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("at least one"), "got: {err}");
}

#[test]
fn rejects_empty_ops() {
    let err = parse_err("{}");
    assert!(err.contains("at least one"), "got: {err}");
}

#[test]
fn rejects_response_add() {
    let err = parse_err(
        r#"
        response_add:
          - pointer: /x
            value: 1
        "#,
    );
    assert!(err.contains("response_add"), "got: {err}");
    assert!(err.contains("not supported"), "got: {err}");
}

#[test]
fn rejects_response_replace() {
    let err = parse_err(
        r#"
        response_replace:
          - pointer: /x
            value: 1
        "#,
    );
    assert!(err.contains("response_replace"), "got: {err}");
    assert!(err.contains("not supported"), "got: {err}");
}

#[test]
fn rejects_overlapping_pointers() {
    let err = parse_err(
        r#"
        request_remove:
          - /a
          - /a/b
        "#,
    );
    assert!(err.contains("overlapping"), "got: {err}");
}

#[test]
fn rejects_same_pointer_twice() {
    let err = parse_err(
        r#"
        request_add:
          - pointer: /a
            value: 1
        request_remove:
          - /a
        "#,
    );
    assert!(err.contains("overlapping"), "got: {err}");
}

#[test]
fn rejects_root_remove() {
    let err = parse_err("request_remove:\n  - \"\"");
    assert!(err.contains("document root"), "got: {err}");
}

#[test]
fn rejects_missing_value_source() {
    let err = parse_err(
        r#"
        request_add:
          - pointer: /a
        "#,
    );
    assert!(err.contains("exactly one"), "got: {err}");
}

#[test]
fn rejects_both_value_and_metadata() {
    let err = parse_err(
        r#"
        request_add:
          - pointer: /a
            value: 1
            metadata: foo
        "#,
    );
    assert!(
        err.contains("exactly one") || err.contains("unknown field") || err.contains("data did not match"),
        "got: {err}"
    );
}

#[test]
fn rejects_both_value_and_env_var() {
    let err = parse_err(
        r#"
        request_add:
          - pointer: /a
            value: 1
            env_var: TENANT
        "#,
    );
    assert!(err.contains("exactly one"), "got: {err}");
}

#[test]
fn rejects_missing_env_var_at_config() {
    let err = parse_err(
        r#"
        request_add:
          - pointer: /tenant
            env_var: PRAXIS_JSON_BODY_ENV_MISSING
        "#,
    );
    assert!(err.contains("not set"), "got: {err}");
}

// -----------------------------------------------------------------------------
// Tokenizer: objects
// -----------------------------------------------------------------------------

#[tokio::test]
async fn request_rewrite_at_eos() {
    let filter = parse_filter(
        r#"
        request_replace:
          - pointer: /model
            value: forced-model
        request_remove:
          - /secret
        request_add:
          - pointer: /tenant
            value: acme
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"old","secret":"x"}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone), "EOS rewrite returns BodyDone");
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(got, json!({"model":"forced-model","tenant":"acme"}));
}

#[tokio::test]
async fn request_continues_before_eos() {
    let filter = parse_filter(
        r#"
        request_remove:
          - /a
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"a":1}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "partial chunks pass through");
    assert_eq!(body.as_ref().unwrap().as_ref(), br#"{"a":1}"#);
}

#[tokio::test]
async fn metadata_value_is_injected_as_json_string() {
    let filter = parse_filter(
        r#"
        request_add:
          - pointer: /method
            metadata: json_rpc.method
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("json_rpc.method", "eth_blockNumber");
    let mut body = Some(Bytes::from_static(br#"{"jsonrpc":"2.0"}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(got["method"], "eth_blockNumber");
}

#[tokio::test]
async fn missing_metadata_skips_op() {
    let filter = parse_filter(
        r#"
        request_add:
          - pointer: /rpc/method
            metadata: json_rpc.method
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"jsonrpc":"2.0"}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(got, json!({"jsonrpc":"2.0"}));
}

#[tokio::test]
async fn structured_metadata_injected_as_json() {
    let filter = parse_filter(
        r#"
        request_add:
          - pointer: /ext
            structured_metadata:
              namespace: ext
              key: payload
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_structured_metadata("ext", "payload", json!({"k": 1}));
    let mut body = Some(Bytes::from_static(br#"{"a":1}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(got, json!({"a":1,"ext":{"k":1}}));
}

#[tokio::test]
async fn invalid_json_continue_leaves_body() {
    let filter = parse_filter(
        r#"
        on_invalid: continue
        request_remove:
          - /a
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"not-json"));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Continue));
    assert_eq!(body.as_ref().unwrap().as_ref(), b"not-json");
}

#[tokio::test]
async fn invalid_json_reject() {
    let filter = parse_filter(
        r#"
        on_invalid: reject
        request_remove:
          - /a
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"{"));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 400),
        "invalid JSON with on_invalid reject"
    );
}

#[tokio::test]
async fn invalid_json_error() {
    let filter = parse_filter(
        r#"
        on_invalid: error
        request_remove:
          - /a
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"{"));
    let err = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect_err("on_invalid: error should return FilterError");
    assert!(err.to_string().contains("invalid JSON"), "got: {err}");
}

#[tokio::test]
async fn depth_exceeded_reject() {
    let filter = parse_filter(
        r#"
        on_invalid: reject
        request_remove:
          - /a
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(depth_exceeded_body());
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 400),
        "depth exceeded with on_invalid reject"
    );
}

#[tokio::test]
async fn depth_exceeded_error() {
    let filter = parse_filter(
        r#"
        on_invalid: error
        request_remove:
          - /a
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(depth_exceeded_body());
    let err = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect_err("on_invalid: error should return FilterError");
    assert!(
        err.to_string().contains("JSON nesting exceeds maximum depth"),
        "got: {err}"
    );
}

#[test]
fn response_shrink_is_padded() {
    let filter = parse_filter(
        r#"
        response_remove:
          - /secret
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let original = Bytes::from_static(br#"{"keep":1,"secret":"x"}"#);
    let orig_len = original.len();
    let mut body = Some(original);
    let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    let out = body.unwrap();
    assert_eq!(out.len(), orig_len, "padded to original Content-Length");
    assert!(out.starts_with(br#"{"keep":1}"#), "secret removed");
    assert!(
        out.iter().rev().take_while(|b| **b == b' ').count() > 0,
        "trailing spaces"
    );
}

#[test]
fn fit_response_refuses_growth() {
    assert!(
        super::fit_response(4, b"12345".to_vec()).is_none(),
        "longer rewrite cannot be framed"
    );
}

#[test]
fn request_body_access_none_when_only_response_ops() {
    let filter = parse_filter(
        r#"
        response_remove:
          - /a
        "#,
    );
    assert_eq!(filter.request_body_access(), crate::BodyAccess::None);
    assert_eq!(filter.response_body_access(), crate::BodyAccess::ReadWrite);
}

#[test]
fn rejects_duplicate_extract_pointers() {
    let err = parse_err(
        r#"
        request_extract:
          - pointer: /a
            metadata: one
          - pointer: /a
            metadata: two
        "#,
    );
    assert!(err.contains("overlapping"), "got: {err}");
}

#[test]
fn allows_nested_extract_pointers() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /user
            structured_metadata:
              namespace: ext
              key: user
          - pointer: /user/id
            metadata: user.id
        "#,
    );
    assert_eq!(filter.request_body_access(), crate::BodyAccess::ReadOnly);
}

#[test]
fn rejects_extract_without_dest() {
    let err = parse_err(
        r#"
        request_extract:
          - pointer: /a
        "#,
    );
    assert!(err.contains("exactly one"), "got: {err}");
}

#[test]
fn extract_only_is_read_only() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        "#,
    );
    assert_eq!(filter.request_body_access(), crate::BodyAccess::ReadOnly);
    assert_eq!(filter.response_body_access(), crate::BodyAccess::None);
}

#[test]
fn extract_plus_replace_is_read_write() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        request_replace:
          - pointer: /model
            value: forced-model
        "#,
    );
    assert_eq!(filter.request_body_access(), crate::BodyAccess::ReadWrite);
}

#[tokio::test]
async fn extract_string_to_header() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            header: X-Model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"old","n":1}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(ctx.extra_request_headers.len(), 1);
    assert_eq!(ctx.extra_request_headers[0].0, "X-Model");
    assert_eq!(ctx.extra_request_headers[0].1, "old");
    assert_eq!(body.as_ref().unwrap().as_ref(), br#"{"model":"old","n":1}"#);
}

#[tokio::test]
async fn extract_object_to_header_uses_raw_json() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /user
            header: X-User
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"user":{"id":1}}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(ctx.extra_request_headers.len(), 1);
    assert_eq!(ctx.extra_request_headers[0].1, r#"{"id":1}"#);
}

#[tokio::test]
async fn extract_oversized_header_is_skipped() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            header: X-Model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let long = "a".repeat(crate::builtins::http::payload_processing::MAX_DYNAMIC_VALUE_LEN + 1);
    let payload = format!(r#"{{"model":"{long}"}}"#);
    let mut body = Some(Bytes::from(payload));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert!(ctx.extra_request_headers.is_empty(), "256-byte header cap");
}

#[tokio::test]
async fn extract_header_skips_control_characters() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            header: X-Model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"bad\nvalue"}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert!(
        ctx.extra_request_headers.is_empty(),
        "control characters must not reach headers"
    );
}

#[tokio::test]
async fn extract_header_trailing_junk_does_not_promote() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            header: X-Model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"premium"} garbage"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Continue));
    assert!(
        ctx.extra_request_headers.is_empty(),
        "no header from a body with trailing junk"
    );
}

#[tokio::test]
async fn extract_only_trailing_junk_does_not_promote_metadata() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"old","x":1} not-json"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Continue));
    assert!(ctx.get_metadata("original.model").is_none());
}

#[tokio::test]
async fn extract_only_trailing_junk_blocks_structured_metadata() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /user
            structured_metadata:
              namespace: ext
              key: user
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"user":{"id":1}} garbage"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Continue));
    assert!(ctx.get_structured_metadata("ext", "user").is_none());
}

#[tokio::test]
async fn extract_only_trailing_junk_on_invalid_continue() {
    let filter = parse_filter(
        r#"
        on_invalid: continue
        request_extract:
          - pointer: /model
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"old"} garbage"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Continue));
    assert!(ctx.get_metadata("original.model").is_none());
}

#[tokio::test]
async fn extract_only_trailing_junk_on_invalid_reject() {
    let filter = parse_filter(
        r#"
        on_invalid: reject
        request_extract:
          - pointer: /model
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"old"} garbage"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 400),
        "trailing junk with on_invalid reject"
    );
    assert!(ctx.get_metadata("original.model").is_none());
}

#[tokio::test]
async fn extract_header_trailing_whitespace_still_promotes() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            header: X-Model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"{\"model\":\"premium\"}\n  \t\r\n"));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(ctx.extra_request_headers.len(), 1);
    assert_eq!(ctx.extra_request_headers[0].1, "premium");
}

#[test]
fn rejects_invalid_extract_header_name() {
    let err = parse_err(
        r#"
        request_extract:
          - pointer: /model
            header: "bad name"
        "#,
    );
    assert!(
        err.contains("invalid header name") && err.contains("bad name"),
        "got: {err}"
    );
}

#[test]
fn rejects_response_extract_header() {
    let err = parse_err(
        r#"
        response_extract:
          - pointer: /model
            header: X-Model
        "#,
    );
    assert!(err.contains("cannot use 'header'"), "got: {err}");
}

#[test]
fn rejects_extract_with_multiple_dests() {
    let err = parse_err(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
            header: X-Model
        "#,
    );
    assert!(err.contains("exactly one"), "got: {err}");
}

#[tokio::test]
async fn extract_string_to_metadata() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"old","n":1}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(ctx.get_metadata("original.model"), Some("old"));
    assert_eq!(body.as_ref().unwrap().as_ref(), br#"{"model":"old","n":1}"#);
}

#[tokio::test]
async fn extract_object_to_structured_metadata() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /user
            structured_metadata:
              namespace: ext
              key: user
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"user":{"id":1}}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(ctx.get_structured_metadata("ext", "user"), Some(&json!({"id": 1})));
}

#[tokio::test]
async fn nested_extract_walks_parent() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /user
            structured_metadata:
              namespace: ext
              key: user
          - pointer: /user/id
            metadata: user.id
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"user":{"id":1,"n":2}}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(
        ctx.get_structured_metadata("ext", "user"),
        Some(&json!({"id": 1, "n": 2}))
    );
    assert_eq!(ctx.get_metadata("user.id"), Some("1"));
}

#[tokio::test]
async fn extract_missing_pointer_skips() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /missing
            metadata: gone
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"a":1}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert!(ctx.get_metadata("gone").is_none(), "missing pointer skips");
}

#[tokio::test]
async fn extract_only_incomplete_before_eos_continues() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"#));
    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();
    assert!(matches!(action, FilterAction::Continue));
    assert!(ctx.get_metadata("original.model").is_none());
}

#[tokio::test]
async fn extract_only_complete_before_eos_continues() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"old"}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();
    assert!(matches!(action, FilterAction::Continue));
    assert!(ctx.get_metadata("original.model").is_none());
}

#[tokio::test]
async fn extract_only_promotes_at_eos() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"old"}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(ctx.get_metadata("original.model"), Some("old"));
}

#[tokio::test]
async fn extract_then_add_from_metadata() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        request_replace:
          - pointer: /model
            value: forced-model
        request_add:
          - pointer: /original_model
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"old"}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(got, json!({"model":"forced-model","original_model":"old"}));
}

#[tokio::test]
async fn extract_oversized_metadata_is_skipped() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /v
            metadata: big
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let long = "a".repeat(257);
    let payload = format!(r#"{{"v":"{long}"}}"#);
    let mut body = Some(Bytes::from(payload));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert!(ctx.get_metadata("big").is_none(), "256-byte metadata cap");
}

#[tokio::test]
async fn metadata_add_skipped_when_extract_late_in_wire_order() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        request_add:
          - pointer: /meta/extra
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"meta":{},"model":"old"}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(ctx.get_metadata("original.model"), Some("old"));
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(got, json!({"meta": {}, "model": "old"}));
}

#[tokio::test]
async fn same_key_extract_before_replace() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        request_replace:
          - pointer: /model
            value: forced-model
        request_add:
          - pointer: /original_model
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"old"}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(ctx.get_metadata("original.model"), Some("old"));
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(got, json!({"model": "forced-model", "original_model": "old"}));
}

#[tokio::test]
async fn external_metadata_still_works() {
    let filter = parse_filter(
        r#"
        request_add:
          - pointer: /tenant
            metadata: tenant.id
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("tenant.id".to_owned(), "acme".to_owned());
    let mut body = Some(Bytes::from_static(br#"{"n":1}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(got, json!({"n": 1, "tenant": "acme"}));
}

#[tokio::test]
async fn missing_metadata_on_existing_replace_keeps_original() {
    let filter = parse_filter(
        r#"
        request_replace:
          - pointer: /model
            metadata: missing.key
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"keep-me","n":1}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(
        got,
        json!({"model": "keep-me", "n": 1}),
        "missing context must skip the replace, not delete the existing member"
    );
}

#[tokio::test]
async fn extract_duplicate_keys_keeps_last() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /a
            metadata: a
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"a":1,"a":2}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(ctx.get_metadata("a"), Some("2"), "extract last duplicate");
    assert_eq!(body.as_ref().unwrap().as_ref(), br#"{"a":1,"a":2}"#);
}
