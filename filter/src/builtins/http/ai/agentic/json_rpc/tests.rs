// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for the JSON-RPC filter.

use bytes::Bytes;

use super::{
    JsonRpcFilter,
    config::{BatchPolicy, InvalidJsonRpcBehavior, JsonRpcHeaders},
    envelope::{JsonRpcIdKind, JsonRpcKind, parse_json_rpc_envelope},
};
use crate::{FilterAction, filter::HttpFilter};

// -----------------------------------------------------------------------------
// Config Tests
// -----------------------------------------------------------------------------

#[test]
fn parse_minimal_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let filter = JsonRpcFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "json_rpc",
        "minimal config should produce json_rpc filter"
    );
}

#[test]
fn parse_full_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        max_body_bytes: 2097152
        batch_policy: first
        on_invalid: reject
        headers:
          method: X-Method
          id: X-Id
          kind: X-Kind
        "#,
    )
    .unwrap();
    let filter = JsonRpcFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "json_rpc", "full config should produce json_rpc filter");
}

#[test]
fn reject_zero_max_body_bytes() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("max_body_bytes: 0").unwrap();
    let err = JsonRpcFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("must be greater than 0"),
        "error should mention max_body_bytes constraint"
    );
}

#[test]
fn reject_empty_header_names() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        headers:
          method: ""
        "#,
    )
    .unwrap();
    let err = JsonRpcFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("must not be empty"),
        "error should mention empty header name"
    );
}

#[test]
fn reject_invalid_header_names() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        headers:
          method: "bad header"
        "#,
    )
    .unwrap();
    let err = JsonRpcFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("not a valid HTTP header name"),
        "error should mention invalid header name"
    );
}

#[test]
fn default_headers_config_parses() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let filter = JsonRpcFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "json_rpc", "default headers config should parse");
}

// -----------------------------------------------------------------------------
// Envelope Parser Tests
// -----------------------------------------------------------------------------

#[test]
fn parses_request_with_string_id() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"tools/call","id":"req-123"}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Request, "kind should be request");
    assert_eq!(
        envelope.method,
        Some("tools/call".to_owned()),
        "method should be tools/call"
    );
    assert_eq!(envelope.id, Some("req-123".to_owned()), "id should be req-123");
    assert_eq!(envelope.id_kind, JsonRpcIdKind::String, "id_kind should be string");
    assert_eq!(envelope.batch_len, None, "batch_len should be None");
}

#[test]
fn parses_request_with_integer_id() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"SendMessage","id":42}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Request, "kind should be request");
    assert_eq!(
        envelope.method,
        Some("SendMessage".to_owned()),
        "method should be SendMessage"
    );
    assert_eq!(envelope.id, Some("42".to_owned()), "id should be 42");
    assert_eq!(envelope.id_kind, JsonRpcIdKind::Integer, "id_kind should be integer");
}

#[test]
fn parses_request_with_float_id() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"test","id":3.14}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Request, "kind should be request");
    assert_eq!(
        envelope.id_kind,
        JsonRpcIdKind::Number,
        "float id should be Number kind"
    );
}

#[test]
fn parses_request_with_null_id() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"test","id":null}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Request, "kind should be request");
    assert_eq!(
        envelope.id,
        Some("null".to_owned()),
        "null id should be stored as string"
    );
    assert_eq!(envelope.id_kind, JsonRpcIdKind::Null, "id_kind should be Null");
}

#[test]
fn parses_notification() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Notification, "kind should be notification");
    assert_eq!(
        envelope.method,
        Some("notifications/tools/list_changed".to_owned()),
        "method should be extracted"
    );
    assert_eq!(envelope.id, None, "notification should have no id");
    assert_eq!(envelope.id_kind, JsonRpcIdKind::Missing, "id_kind should be Missing");
}

#[test]
fn parses_response_with_result() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","id":"req-123","result":{"tools":[]}}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Response, "kind should be response");
    assert_eq!(envelope.method, None, "response should have no method");
    assert_eq!(envelope.id, Some("req-123".to_owned()), "id should be req-123");
    assert_eq!(envelope.id_kind, JsonRpcIdKind::String, "id_kind should be String");
}

#[test]
fn parses_response_with_error() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Response, "kind should be response");
    assert_eq!(envelope.method, None, "error response should have no method");
    assert_eq!(envelope.id, Some("1".to_owned()), "id should be 1");
}

#[test]
fn rejects_missing_jsonrpc_field() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = br#"{"method":"test","id":1}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("missing 'jsonrpc'"),
        "error should mention missing jsonrpc"
    );
}

#[test]
fn continues_on_missing_jsonrpc_when_configured() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"method":"test","id":1}"#;
    let result = parse_json_rpc_envelope(json, &config).unwrap();
    assert!(
        result.is_none(),
        "missing jsonrpc should return None when on_invalid: continue"
    );
}

#[test]
fn rejects_wrong_jsonrpc_version() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = br#"{"jsonrpc":"1.0","method":"test","id":1}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("wrong jsonrpc version"),
        "error should mention wrong version"
    );
}

#[test]
fn rejects_missing_method_for_request() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = br#"{"jsonrpc":"2.0","id":1}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("missing 'method'"),
        "error should mention missing method"
    );
}

#[test]
fn rejects_non_string_method() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = br#"{"jsonrpc":"2.0","method":123,"id":1}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("must be a string"),
        "error should mention string requirement"
    );
}

#[test]
fn rejects_boolean_id() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = br#"{"jsonrpc":"2.0","method":"test","id":true}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("must be string, number, or null"),
        "error should mention valid id types"
    );
}

#[test]
fn rejects_object_id() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = br#"{"jsonrpc":"2.0","method":"test","id":{"key":"value"}}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("must be string, number, or null"),
        "error should mention valid id types"
    );
}

#[test]
fn rejects_array_id() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = br#"{"jsonrpc":"2.0","method":"test","id":[1,2,3]}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("must be string, number, or null"),
        "error should mention valid id types"
    );
}

#[test]
fn handles_params_object() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"test","params":{"arg1":"val1"},"id":1}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();
    assert_eq!(
        envelope.method,
        Some("test".to_owned()),
        "method should be extracted with params object"
    );
}

#[test]
fn handles_params_array() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"test","params":["arg1","arg2"],"id":1}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();
    assert_eq!(
        envelope.method,
        Some("test".to_owned()),
        "method should be extracted with params array"
    );
}

#[test]
fn handles_reserved_rpc_method() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"rpc.discovery","id":1}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();
    assert_eq!(
        envelope.method,
        Some("rpc.discovery".to_owned()),
        "reserved rpc. method should be accepted"
    );
}

#[test]
fn batch_reject_policy_rejects_array() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = br#"[{"jsonrpc":"2.0","method":"test1","id":1},{"jsonrpc":"2.0","method":"test2","id":2}]"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("not supported"),
        "error should mention batch not supported"
    );
}

#[test]
fn batch_first_policy_uses_first_item() {
    let config = make_config(BatchPolicy::First, InvalidJsonRpcBehavior::Continue);
    let json = br#"[{"jsonrpc":"2.0","method":"first","id":1},{"jsonrpc":"2.0","method":"second","id":2}]"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Batch, "kind should be batch");
    assert_eq!(
        envelope.method,
        Some("first".to_owned()),
        "should use first item method"
    );
    assert_eq!(envelope.id, Some("1".to_owned()), "should use first item id");
    assert_eq!(envelope.batch_len, Some(2), "batch_len should be 2");
}

#[test]
fn batch_first_policy_skips_invalid_items() {
    let config = make_config(BatchPolicy::First, InvalidJsonRpcBehavior::Continue);
    let json = br#"[{"not":"jsonrpc"},{"jsonrpc":"2.0","method":"valid","id":2}]"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(
        envelope.method,
        Some("valid".to_owned()),
        "should skip invalid and use valid item"
    );
    assert_eq!(envelope.batch_len, Some(2), "batch_len should be 2");
}

#[test]
fn empty_batch_array_fails() {
    let config = make_config(BatchPolicy::First, InvalidJsonRpcBehavior::Continue);
    let json = br#"[]"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(err.to_string().contains("empty"), "error should mention empty batch");
}

#[test]
fn invalid_json_fails() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = b"not json at all";
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("invalid JSON"),
        "error should mention invalid JSON"
    );
}

#[test]
fn non_object_json_continues_when_configured() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#""just a string""#;
    let result = parse_json_rpc_envelope(json, &config).unwrap();
    assert!(result.is_none(), "non-object JSON should return None when continuing");
}

// -----------------------------------------------------------------------------
// Filter Behavior Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn extracts_method_from_request() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/mcp");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let json = br#"{"jsonrpc":"2.0","method":"tools/call","id":"req-123"}"#;
    let mut body = Some(Bytes::from_static(json));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release on valid JSON-RPC"
    );
    assert_eq!(ctx.extra_request_headers.len(), 3, "should promote 3 headers");
    assert_promoted_header(&ctx, "X-Json-Rpc-Method", "tools/call");
    assert_promoted_header(&ctx, "X-Json-Rpc-Id", "req-123");
    assert_promoted_header(&ctx, "X-Json-Rpc-Kind", "request");
    let results = ctx.filter_results.get("json_rpc").unwrap();
    assert_eq!(results.get("method"), Some("tools/call"), "method result");
    assert_eq!(results.get("id"), Some("req-123"), "id result");
    assert_eq!(results.get("kind"), Some("request"), "kind result");
    assert_eq!(results.get("id_kind"), Some("string"), "id_kind result");
}

#[tokio::test]
async fn extracts_notification() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/mcp");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let json = br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
    let mut body = Some(Bytes::from_static(json));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Release), "notification should release");
    assert_promoted_header(&ctx, "X-Json-Rpc-Method", "notifications/tools/list_changed");
    assert_promoted_header(&ctx, "X-Json-Rpc-Kind", "notification");
    assert_no_promoted_header(&ctx, "X-Json-Rpc-Id");
    let results = ctx.filter_results.get("json_rpc").unwrap();
    assert_eq!(
        results.get("kind"),
        Some("notification"),
        "kind result should be notification"
    );
    assert_eq!(
        results.get("id_kind"),
        Some("missing"),
        "id_kind result should be missing"
    );
}

#[tokio::test]
async fn continues_on_incomplete_json() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let partial = br#"{"jsonrpc":"2.0","method":"test""#;
    let mut body = Some(Bytes::from_static(partial));

    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "incomplete JSON should continue"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "no headers should be promoted for incomplete JSON"
    );
}

#[tokio::test]
async fn continues_on_non_json_body_by_default() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"not json"));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "non-JSON should continue by default"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "no headers should be promoted for non-JSON"
    );
}

#[tokio::test]
async fn rejects_invalid_json_when_configured() {
    let filter = make_reject_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"not json"));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Reject(r) if r.status == 400));
}

#[tokio::test]
async fn errors_invalid_json_when_configured() {
    let filter = make_error_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"not json"));

    let err = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect_err("on_invalid: error should return FilterError");

    assert!(err.to_string().contains("invalid JSON"));
}

#[tokio::test]
async fn batch_rejection_overrides_default_on_invalid_continue() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"[{"jsonrpc":"2.0","method":"test1","id":1},{"jsonrpc":"2.0","method":"test2","id":2}]"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Reject(r) if r.status == 400));
}

#[tokio::test]
async fn on_request_is_noop() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "on_request should continue");
}

#[tokio::test]
async fn returns_continue_on_none_body() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body: Option<Bytes> = None;

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "None body should continue");
}

#[tokio::test]
async fn skips_header_with_control_chars() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = b"{\"jsonrpc\":\"2.0\",\"method\":\"bad\\nmethod\",\"id\":1}";
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "should release even with control chars"
    );

    let headers: std::collections::HashMap<_, _> =
        ctx.extra_request_headers.iter().map(|(k, v)| (k.as_ref(), v)).collect();
    assert!(
        !headers.contains_key("X-Json-Rpc-Method"),
        "control char method should not be promoted to header"
    );
    assert!(
        headers.contains_key("X-Json-Rpc-Kind"),
        "kind header should still be promoted"
    );
}

#[tokio::test]
async fn allows_tab_character() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = b"{\"jsonrpc\":\"2.0\",\"method\":\"with\\ttab\",\"id\":1}";
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "tab character should be allowed"
    );

    let headers: std::collections::HashMap<_, _> =
        ctx.extra_request_headers.iter().map(|(k, v)| (k.as_ref(), v)).collect();
    assert_eq!(
        headers.get("X-Json-Rpc-Method").map(|s| s.as_str()),
        Some("with\ttab"),
        "tab in method should be promoted"
    );
}

#[test]
fn body_access_is_read_only() {
    let filter = make_filter();
    assert_eq!(
        filter.request_body_access(),
        crate::body::BodyAccess::ReadOnly,
        "JSON-RPC filter should use ReadOnly body access"
    );
}

#[test]
fn body_mode_is_stream_buffer() {
    use super::config::DEFAULT_MAX_BODY_BYTES;

    let filter = make_filter();
    assert_eq!(
        filter.request_body_mode(),
        crate::body::BodyMode::StreamBuffer {
            max_bytes: Some(DEFAULT_MAX_BODY_BYTES)
        },
        "JSON-RPC filter should use StreamBuffer with default max bytes"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn make_config(batch_policy: BatchPolicy, on_invalid: InvalidJsonRpcBehavior) -> super::config::JsonRpcConfig {
    super::config::JsonRpcConfig {
        batch_policy,
        headers: JsonRpcHeaders::default(),
        max_body_bytes: 1_048_576,
        on_invalid,
    }
}

fn make_filter() -> JsonRpcFilter {
    JsonRpcFilter {
        config: make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue),
        max_body_bytes: 1_048_576,
    }
}

fn make_reject_filter() -> JsonRpcFilter {
    JsonRpcFilter {
        config: make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject),
        max_body_bytes: 1_048_576,
    }
}

fn make_error_filter() -> JsonRpcFilter {
    JsonRpcFilter {
        config: make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Error),
        max_body_bytes: 1_048_576,
    }
}

/// Assert that a specific promoted header has the expected value.
fn assert_promoted_header(ctx: &crate::filter::HttpFilterContext<'_>, name: &str, expected: &str) {
    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();
    assert_eq!(
        headers.get(name).copied(),
        Some(expected),
        "promoted header '{name}' should be '{expected}'"
    );
}

/// Assert that a promoted header is absent.
fn assert_no_promoted_header(ctx: &crate::filter::HttpFilterContext<'_>, name: &str) {
    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();
    assert!(!headers.contains_key(name), "promoted header '{name}' should be absent");
}
