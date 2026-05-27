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
    assert_eq!(filter.name(), "json_rpc");
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
    assert_eq!(filter.name(), "json_rpc");
}

#[test]
fn reject_zero_max_body_bytes() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("max_body_bytes: 0").unwrap();
    let err = JsonRpcFilter::from_config(&yaml).err().expect("should fail");
    assert!(err.to_string().contains("must be greater than 0"));
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
    assert!(err.to_string().contains("must not be empty"));
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
    assert!(err.to_string().contains("not a valid HTTP header name"));
}

#[test]
fn default_headers_config_parses() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let filter = JsonRpcFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "json_rpc");
}

// -----------------------------------------------------------------------------
// Envelope Parser Tests
// -----------------------------------------------------------------------------

#[test]
fn parses_request_with_string_id() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"tools/call","id":"req-123"}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Request);
    assert_eq!(envelope.method, Some("tools/call".to_owned()));
    assert_eq!(envelope.id, Some("req-123".to_owned()));
    assert_eq!(envelope.id_kind, JsonRpcIdKind::String);
    assert_eq!(envelope.batch_len, None);
}

#[test]
fn parses_request_with_integer_id() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"SendMessage","id":42}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Request);
    assert_eq!(envelope.method, Some("SendMessage".to_owned()));
    assert_eq!(envelope.id, Some("42".to_owned()));
    assert_eq!(envelope.id_kind, JsonRpcIdKind::Integer);
}

#[test]
fn parses_request_with_float_id() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"test","id":3.14}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Request);
    assert_eq!(envelope.id_kind, JsonRpcIdKind::Number);
}

#[test]
fn parses_request_with_null_id() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"test","id":null}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Request);
    assert_eq!(envelope.id, Some("null".to_owned()));
    assert_eq!(envelope.id_kind, JsonRpcIdKind::Null);
}

#[test]
fn parses_notification() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Notification);
    assert_eq!(envelope.method, Some("notifications/tools/list_changed".to_owned()));
    assert_eq!(envelope.id, None);
    assert_eq!(envelope.id_kind, JsonRpcIdKind::Missing);
}

#[test]
fn parses_response_with_result() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","id":"req-123","result":{"tools":[]}}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Response);
    assert_eq!(envelope.method, None);
    assert_eq!(envelope.id, Some("req-123".to_owned()));
    assert_eq!(envelope.id_kind, JsonRpcIdKind::String);
}

#[test]
fn parses_response_with_error() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Response);
    assert_eq!(envelope.method, None);
    assert_eq!(envelope.id, Some("1".to_owned()));
}

#[test]
fn rejects_missing_jsonrpc_field() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = br#"{"method":"test","id":1}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(err.to_string().contains("missing 'jsonrpc'"));
}

#[test]
fn continues_on_missing_jsonrpc_when_configured() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"method":"test","id":1}"#;
    let result = parse_json_rpc_envelope(json, &config).unwrap();
    assert!(result.is_none());
}

#[test]
fn rejects_wrong_jsonrpc_version() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = br#"{"jsonrpc":"1.0","method":"test","id":1}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(err.to_string().contains("wrong jsonrpc version"));
}

#[test]
fn rejects_missing_method_for_request() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = br#"{"jsonrpc":"2.0","id":1}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(err.to_string().contains("missing 'method'"));
}

#[test]
fn rejects_non_string_method() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = br#"{"jsonrpc":"2.0","method":123,"id":1}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(err.to_string().contains("must be a string"));
}

#[test]
fn rejects_boolean_id() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = br#"{"jsonrpc":"2.0","method":"test","id":true}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(err.to_string().contains("must be string, number, or null"));
}

#[test]
fn rejects_object_id() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = br#"{"jsonrpc":"2.0","method":"test","id":{"key":"value"}}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(err.to_string().contains("must be string, number, or null"));
}

#[test]
fn rejects_array_id() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = br#"{"jsonrpc":"2.0","method":"test","id":[1,2,3]}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(err.to_string().contains("must be string, number, or null"));
}

#[test]
fn handles_params_object() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"test","params":{"arg1":"val1"},"id":1}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();
    assert_eq!(envelope.method, Some("test".to_owned()));
}

#[test]
fn handles_params_array() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"test","params":["arg1","arg2"],"id":1}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();
    assert_eq!(envelope.method, Some("test".to_owned()));
}

#[test]
fn handles_reserved_rpc_method() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"rpc.discovery","id":1}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();
    assert_eq!(envelope.method, Some("rpc.discovery".to_owned()));
}

#[test]
fn batch_reject_policy_rejects_array() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = br#"[{"jsonrpc":"2.0","method":"test1","id":1},{"jsonrpc":"2.0","method":"test2","id":2}]"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(err.to_string().contains("not supported"));
}

#[test]
fn batch_first_policy_uses_first_item() {
    let config = make_config(BatchPolicy::First, InvalidJsonRpcBehavior::Continue);
    let json = br#"[{"jsonrpc":"2.0","method":"first","id":1},{"jsonrpc":"2.0","method":"second","id":2}]"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Batch);
    assert_eq!(envelope.method, Some("first".to_owned()));
    assert_eq!(envelope.id, Some("1".to_owned()));
    assert_eq!(envelope.batch_len, Some(2));
}

#[test]
fn batch_first_policy_skips_invalid_items() {
    let config = make_config(BatchPolicy::First, InvalidJsonRpcBehavior::Continue);
    let json = br#"[{"not":"jsonrpc"},{"jsonrpc":"2.0","method":"valid","id":2}]"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.method, Some("valid".to_owned()));
    assert_eq!(envelope.batch_len, Some(2));
}

#[test]
fn empty_batch_array_fails() {
    let config = make_config(BatchPolicy::First, InvalidJsonRpcBehavior::Continue);
    let json = br#"[]"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(err.to_string().contains("empty"));
}

#[test]
fn invalid_json_fails() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject);
    let json = b"not json at all";
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(err.to_string().contains("invalid JSON"));
}

#[test]
fn non_object_json_continues_when_configured() {
    let config = make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue);
    let json = br#""just a string""#;
    let result = parse_json_rpc_envelope(json, &config).unwrap();
    assert!(result.is_none());
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

    assert!(matches!(action, FilterAction::Release));

    assert_eq!(ctx.extra_request_headers.len(), 3);
    let headers: std::collections::HashMap<_, _> =
        ctx.extra_request_headers.iter().map(|(k, v)| (k.as_ref(), v)).collect();
    assert_eq!(headers.get("X-Json-Rpc-Method").map(|s| s.as_str()), Some("tools/call"));
    assert_eq!(headers.get("X-Json-Rpc-Id").map(|s| s.as_str()), Some("req-123"));
    assert_eq!(headers.get("X-Json-Rpc-Kind").map(|s| s.as_str()), Some("request"));

    let results = ctx.filter_results.get("json_rpc").unwrap();
    assert_eq!(results.get("method"), Some("tools/call"));
    assert_eq!(results.get("id"), Some("req-123"));
    assert_eq!(results.get("kind"), Some("request"));
    assert_eq!(results.get("id_kind"), Some("string"));
}

#[tokio::test]
async fn extracts_notification() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/mcp");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release));

    let headers: std::collections::HashMap<_, _> =
        ctx.extra_request_headers.iter().map(|(k, v)| (k.as_ref(), v)).collect();
    assert_eq!(
        headers.get("X-Json-Rpc-Method").map(|s| s.as_str()),
        Some("notifications/tools/list_changed")
    );
    assert_eq!(headers.get("X-Json-Rpc-Kind").map(|s| s.as_str()), Some("notification"));
    assert!(!headers.contains_key("X-Json-Rpc-Id"));

    let results = ctx.filter_results.get("json_rpc").unwrap();
    assert_eq!(results.get("kind"), Some("notification"));
    assert_eq!(results.get("id_kind"), Some("missing"));
}

#[tokio::test]
async fn continues_on_incomplete_json() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let partial = br#"{"jsonrpc":"2.0","method":"test""#;
    let mut body = Some(Bytes::from_static(partial));

    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();

    assert!(matches!(action, FilterAction::Continue));
    assert!(ctx.extra_request_headers.is_empty());
}

#[tokio::test]
async fn continues_on_non_json_body_by_default() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"not json"));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Continue));
    assert!(ctx.extra_request_headers.is_empty());
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

    assert!(matches!(action, FilterAction::Continue));
}

#[tokio::test]
async fn returns_continue_on_none_body() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body: Option<Bytes> = None;

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Continue));
}

#[tokio::test]
async fn skips_header_with_control_chars() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = b"{\"jsonrpc\":\"2.0\",\"method\":\"bad\\nmethod\",\"id\":1}";
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release));

    let headers: std::collections::HashMap<_, _> =
        ctx.extra_request_headers.iter().map(|(k, v)| (k.as_ref(), v)).collect();
    assert!(!headers.contains_key("X-Json-Rpc-Method"));
    assert!(headers.contains_key("X-Json-Rpc-Kind"));
}

#[tokio::test]
async fn allows_tab_character() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let json = b"{\"jsonrpc\":\"2.0\",\"method\":\"with\\ttab\",\"id\":1}";
    let mut body = Some(Bytes::from_static(json));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release));

    let headers: std::collections::HashMap<_, _> =
        ctx.extra_request_headers.iter().map(|(k, v)| (k.as_ref(), v)).collect();
    assert_eq!(headers.get("X-Json-Rpc-Method").map(|s| s.as_str()), Some("with\ttab"));
}

#[test]
fn body_access_is_read_only() {
    let filter = make_filter();
    assert_eq!(filter.request_body_access(), crate::body::BodyAccess::ReadOnly);
}

#[test]
fn body_mode_is_stream_buffer() {
    use super::config::DEFAULT_MAX_BODY_BYTES;

    let filter = make_filter();
    assert_eq!(
        filter.request_body_mode(),
        crate::body::BodyMode::StreamBuffer {
            max_bytes: Some(DEFAULT_MAX_BODY_BYTES)
        }
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn make_config(batch_policy: BatchPolicy, on_invalid: InvalidJsonRpcBehavior) -> super::config::JsonRpcConfig {
    super::config::JsonRpcConfig {
        max_body_bytes: 1_048_576,
        batch_policy,
        on_invalid,
        headers: JsonRpcHeaders::default(),
    }
}

fn make_filter() -> JsonRpcFilter {
    JsonRpcFilter {
        max_body_bytes: 1_048_576,
        config: make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Continue),
    }
}

fn make_reject_filter() -> JsonRpcFilter {
    JsonRpcFilter {
        max_body_bytes: 1_048_576,
        config: make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Reject),
    }
}

fn make_error_filter() -> JsonRpcFilter {
    JsonRpcFilter {
        max_body_bytes: 1_048_576,
        config: make_config(BatchPolicy::Reject, InvalidJsonRpcBehavior::Error),
    }
}
