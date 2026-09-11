// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the JSON-RPC filter.

use bytes::Bytes;

use super::{
    super::OnInvalidBehavior,
    JsonRpcFilter,
    config::{BatchPolicy, DEFAULT_MAX_BATCH_SIZE, JsonRpcHeaders, MAX_BATCH_SIZE},
    envelope::{JsonRpcIdKind, JsonRpcKind, parse_json_rpc_envelope},
};
use crate::{FilterAction, HttpFilter as _};

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
fn rejects_max_body_bytes_above_ceiling() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("max_body_bytes: 67108865").unwrap();
    let err = JsonRpcFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("exceeds maximum"),
        "error should mention exceeds maximum"
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
fn parse_config_with_max_batch_size() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        batch_policy: first
        max_batch_size: 50
        "#,
    )
    .unwrap();
    let filter = JsonRpcFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "json_rpc",
        "config with explicit max_batch_size should parse"
    );
}

#[test]
fn reject_zero_max_batch_size() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("max_batch_size: 0").unwrap();
    let err = JsonRpcFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("must be greater than 0"),
        "error should mention max_batch_size constraint"
    );
}

#[test]
fn reject_max_batch_size_above_ceiling() {
    // The limit is also the parser's per-request capture retention
    // bound, so an unbounded value would put peak memory in the hands
    // of whoever wrote the config. Reject it at config time.
    let yaml: serde_yaml::Value = serde_yaml::from_str(&format!("max_batch_size: {}", MAX_BATCH_SIZE + 1)).unwrap();
    let err = JsonRpcFilter::from_config(&yaml)
        .err()
        .expect("above-ceiling max_batch_size should fail");
    assert!(
        err.to_string().contains("exceeds maximum"),
        "error should mention the max_batch_size ceiling, got: {err}"
    );
}

#[test]
fn accept_max_batch_size_at_ceiling() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(&format!("max_batch_size: {MAX_BATCH_SIZE}")).unwrap();
    JsonRpcFilter::from_config(&yaml).expect("max_batch_size exactly at the ceiling should be accepted");
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
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"service/invoke","id":"req-123"}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Request, "kind should be request");
    assert_eq!(
        envelope.method,
        Some("service/invoke".to_owned()),
        "method should be service/invoke"
    );
    assert_eq!(envelope.id, Some("req-123".to_owned()), "id should be req-123");
    assert_eq!(envelope.id_kind, JsonRpcIdKind::String, "id_kind should be string");
    assert_eq!(envelope.batch_len, None, "batch_len should be None");
}

#[test]
fn parses_request_with_integer_id() {
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"ProcessRequest","id":42}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Request, "kind should be request");
    assert_eq!(
        envelope.method,
        Some("ProcessRequest".to_owned()),
        "method should be ProcessRequest"
    );
    assert_eq!(envelope.id, Some("42".to_owned()), "id should be 42");
    assert_eq!(envelope.id_kind, JsonRpcIdKind::Integer, "id_kind should be integer");
}

#[test]
fn parses_request_with_float_id() {
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
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
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
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
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","method":"notifications/catalog/updated"}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Notification, "kind should be notification");
    assert_eq!(
        envelope.method,
        Some("notifications/catalog/updated".to_owned()),
        "method should be extracted"
    );
    assert_eq!(envelope.id, None, "notification should have no id");
    assert_eq!(envelope.id_kind, JsonRpcIdKind::Missing, "id_kind should be Missing");
}

#[test]
fn parses_response_with_result() {
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","id":"req-123","result":{"tools":[]}}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Response, "kind should be response");
    assert_eq!(envelope.method, None, "response should have no method");
    assert_eq!(envelope.id, Some("req-123".to_owned()), "id should be req-123");
    assert_eq!(envelope.id_kind, JsonRpcIdKind::String, "id_kind should be String");
}

#[test]
fn parses_response_with_error() {
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    let json = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();

    assert_eq!(envelope.kind, JsonRpcKind::Response, "kind should be response");
    assert_eq!(envelope.method, None, "error response should have no method");
    assert_eq!(envelope.id, Some("1".to_owned()), "id should be 1");
}

#[test]
fn rejects_missing_jsonrpc_field() {
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Reject);
    let json = br#"{"method":"test","id":1}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("missing 'jsonrpc'"),
        "error should mention missing jsonrpc"
    );
}

#[test]
fn continues_on_missing_jsonrpc_when_configured() {
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    let json = br#"{"method":"test","id":1}"#;
    let result = parse_json_rpc_envelope(json, &config).unwrap();
    assert!(
        result.is_none(),
        "missing jsonrpc should return None when on_invalid: continue"
    );
}

#[test]
fn rejects_wrong_jsonrpc_version() {
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Reject);
    let json = br#"{"jsonrpc":"1.0","method":"test","id":1}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("wrong jsonrpc version"),
        "error should mention wrong version"
    );
}

#[test]
fn rejects_missing_method_for_request() {
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Reject);
    let json = br#"{"jsonrpc":"2.0","id":1}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("missing 'method'"),
        "error should mention missing method"
    );
}

#[test]
fn rejects_non_string_method() {
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Reject);
    let json = br#"{"jsonrpc":"2.0","method":123,"id":1}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("must be a string"),
        "error should mention string requirement"
    );
}

#[test]
fn rejects_boolean_id() {
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Reject);
    let json = br#"{"jsonrpc":"2.0","method":"test","id":true}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("must be string, number, or null"),
        "error should mention valid id types"
    );
}

#[test]
fn rejects_object_id() {
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Reject);
    let json = br#"{"jsonrpc":"2.0","method":"test","id":{"key":"value"}}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("must be string, number, or null"),
        "error should mention valid id types"
    );
}

#[test]
fn rejects_array_id() {
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Reject);
    let json = br#"{"jsonrpc":"2.0","method":"test","id":[1,2,3]}"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("must be string, number, or null"),
        "error should mention valid id types"
    );
}

#[test]
fn handles_params_object() {
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
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
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
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
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
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
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Reject);
    let json = br#"[{"jsonrpc":"2.0","method":"test1","id":1},{"jsonrpc":"2.0","method":"test2","id":2}]"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("not supported"),
        "error should mention batch not supported"
    );
}

#[test]
fn batch_first_policy_uses_first_item() {
    let config = make_config(BatchPolicy::First, OnInvalidBehavior::Continue);
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
    let config = make_config(BatchPolicy::First, OnInvalidBehavior::Continue);
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
    let config = make_config(BatchPolicy::First, OnInvalidBehavior::Continue);
    let json = br#"[]"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(err.to_string().contains("empty"), "error should mention empty batch");
}

#[test]
fn invalid_json_fails() {
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Reject);
    let json = b"not json at all";
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("invalid JSON"),
        "error should mention invalid JSON"
    );
}

#[test]
fn non_object_json_continues_when_configured() {
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    let json = br#""just a string""#;
    let result = parse_json_rpc_envelope(json, &config).unwrap();
    assert!(result.is_none(), "non-object JSON should return None when continuing");
}

#[test]
fn batch_within_max_size_allowed() {
    let config = make_config_with_batch_limit(5);
    let json = br#"[
        {"jsonrpc":"2.0","method":"a","id":1},
        {"jsonrpc":"2.0","method":"b","id":2}
    ]"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();
    assert_eq!(envelope.kind, JsonRpcKind::Batch, "kind should be batch");
    assert_eq!(envelope.batch_len, Some(2), "batch_len should be 2");
}

#[test]
fn batch_at_exact_max_size_allowed() {
    let config = make_config_with_batch_limit(2);
    let json = br#"[
        {"jsonrpc":"2.0","method":"a","id":1},
        {"jsonrpc":"2.0","method":"b","id":2}
    ]"#;
    let envelope = parse_json_rpc_envelope(json, &config).unwrap().unwrap();
    assert_eq!(envelope.batch_len, Some(2), "batch at exact limit should pass");
}

#[test]
fn batch_exceeding_max_size_rejected() {
    let config = make_config_with_batch_limit(1);
    let json = br#"[
        {"jsonrpc":"2.0","method":"a","id":1},
        {"jsonrpc":"2.0","method":"b","id":2}
    ]"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    assert!(
        err.to_string().contains("exceeds maximum"),
        "error should mention exceeds maximum: got '{err}'"
    );
}

#[test]
fn oversized_batch_reports_exact_count_without_retaining_items() {
    // A batch far larger than max_batch_size must be rejected with the
    // true element count, and the parser must not retain a capture per
    // element on the way there: `[0,0,...]` is ~2 bytes per element but
    // each retained capture is an order of magnitude larger, so an
    // unbounded push amplifies the buffered body into a much larger
    // transient allocation for a request that is rejected anyway.
    let config = make_config_with_batch_limit(1);
    let body = scalar_batch_body(OVERSIZED_BATCH_ITEMS);

    let err = parse_json_rpc_envelope(body.as_bytes(), &config).expect_err("oversized batch must be rejected");
    assert!(
        matches!(
            err,
            super::envelope::JsonRpcParseError::BatchTooLarge(actual, max)
                if actual == OVERSIZED_BATCH_ITEMS && max == 1
        ),
        "oversized batch must report the exact element count and limit: got {err:?}"
    );

    // Structural half of the guard: the capture the rejection is made
    // from holds at most max_batch_size items regardless of array size.
    let (items, len) = capture_batch(&body, &config);
    assert_eq!(len, OVERSIZED_BATCH_ITEMS, "the true element count must be preserved");
    assert_eq!(
        items, config.max_batch_size,
        "captured items must stay bounded by max_batch_size, not by the element count"
    );
}

#[test]
fn batch_capture_is_bounded_at_every_limit() {
    // The bound holds for any limit, and an in-limit batch is still
    // captured in full so the first-valid scan has every item.
    for max_batch_size in [1, 2, 4, 5, 6, 10] {
        let config = make_config_with_batch_limit(max_batch_size);
        let (items, len) = capture_batch(&scalar_batch_body(5), &config);
        assert_eq!(
            len, 5,
            "the true element count must be preserved (limit {max_batch_size})"
        );
        assert_eq!(
            items,
            std::cmp::min(5, max_batch_size),
            "captures must be min(elements, max_batch_size) (limit {max_batch_size})"
        );
    }
}

#[test]
fn reject_policy_retains_no_batch_captures() {
    // BatchPolicy::Reject decides on the element count alone and never
    // reads a capture, so retaining any is pure attacker-controlled
    // memory cost, the very amplification this guard exists to stop.
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Reject);
    let (items, len) = capture_batch(&scalar_batch_body(OVERSIZED_BATCH_ITEMS), &config);

    assert_eq!(len, OVERSIZED_BATCH_ITEMS, "the true element count must be preserved");
    assert_eq!(
        items, 0,
        "the reject policy reads no captures, so none may be retained (max_batch_size was {})",
        config.max_batch_size
    );
}

#[test]
fn reject_policy_still_rejects_batches_without_captures() {
    // Retaining nothing must not change what the reject policy does:
    // a non-empty batch is still UnsupportedBatch and an empty one is
    // still EmptyBatch, both decided on the element count.
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Reject);

    let err = parse_json_rpc_envelope(br#"[{"jsonrpc":"2.0","method":"a","id":1}]"#, &config)
        .expect_err("a batch must be rejected under the reject policy");
    assert!(
        matches!(err, super::envelope::JsonRpcParseError::UnsupportedBatch),
        "a non-empty batch must still be UnsupportedBatch: got {err:?}"
    );

    let err = parse_json_rpc_envelope(b"[]", &config).expect_err("an empty batch must be rejected");
    assert!(
        matches!(err, super::envelope::JsonRpcParseError::EmptyBatch),
        "an empty batch must still be EmptyBatch: got {err:?}"
    );
}

#[test]
fn batch_at_exact_max_size_keeps_its_last_item() {
    // Behavioural boundary for the retention bound: at exactly
    // max_batch_size the LAST capture is the one an off-by-one drops,
    // so make it the only valid JSON-RPC message in the batch. A test
    // whose first item is valid short-circuits at index 0 and cannot
    // see a dropped tail.
    const LIMIT: usize = 8;
    let config = make_config_with_batch_limit(LIMIT);

    let mut body = String::from("[");
    for _ in 0..LIMIT - 1 {
        body.push_str(r#"{"not":"jsonrpc"},"#);
    }
    body.push_str(r#"{"jsonrpc":"2.0","method":"last","id":9}]"#);

    let envelope = parse_json_rpc_envelope(body.as_bytes(), &config)
        .expect("a batch at exactly the limit must be accepted")
        .expect("the trailing valid message must be found");

    assert_eq!(
        envelope.method,
        Some("last".to_owned()),
        "the item at index max_batch_size - 1 must still be captured"
    );
    assert_eq!(envelope.id, Some("9".to_owned()), "the last item's id must be promoted");
    assert_eq!(envelope.kind, JsonRpcKind::Batch, "kind should be batch");
    assert_eq!(envelope.batch_len, Some(LIMIT), "batch_len must be the true count");
}

#[test]
fn oversized_batch_of_objects_is_rejected_by_count() {
    // The bound must not depend on item shape: nested objects and
    // arrays past the cap are drained rather than retained, and the
    // element count stays exact.
    let config = make_config_with_batch_limit(2);
    let item = r#"{"jsonrpc":"2.0","method":"m","id":1,"params":{"a":[1,2,{"b":3}]}}"#;
    let body = format!("[{}]", vec![item; 50].join(","));

    let err = parse_json_rpc_envelope(body.as_bytes(), &config).expect_err("oversized batch must be rejected");
    assert!(
        matches!(
            err,
            super::envelope::JsonRpcParseError::BatchTooLarge(actual, max) if actual == 50 && max == 2
        ),
        "nested batch items must be counted exactly and not retained: got {err:?}"
    );

    let (items, len) = capture_batch(&body, &config);
    assert_eq!(len, 50, "every nested item must be counted");
    assert_eq!(items, 2, "only max_batch_size nested items may be retained");
}

#[test]
fn oversized_batch_with_trailing_content_is_still_invalid_json() {
    // Draining past the cap must keep scanning every byte: trailing
    // content after the array is still caught by `de.end()`, so a
    // truncating short-circuit cannot smuggle a malformed body through.
    let config = make_config_with_batch_limit(1);
    let body = format!("{} trailing", scalar_batch_body(64));

    let err = parse_json_rpc_envelope(body.as_bytes(), &config).expect_err("trailing content must be rejected");
    assert!(
        matches!(err, super::envelope::JsonRpcParseError::InvalidJson(_)),
        "trailing content after an over-sized batch must still be invalid JSON: got {err:?}"
    );
}

#[test]
fn batch_too_large_error_includes_counts() {
    let config = make_config_with_batch_limit(1);
    let json = br#"[
        {"jsonrpc":"2.0","method":"a","id":1},
        {"jsonrpc":"2.0","method":"b","id":2},
        {"jsonrpc":"2.0","method":"c","id":3}
    ]"#;
    let err = parse_json_rpc_envelope(json, &config).expect_err("should fail");
    let msg = err.to_string();
    assert!(msg.contains("3"), "error should include actual batch size: got '{msg}'");
    assert!(msg.contains("1"), "error should include max batch size: got '{msg}'");
}

// -----------------------------------------------------------------------------
// Filter Behavior Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn extracts_method_from_request() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/rpc");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let json = br#"{"jsonrpc":"2.0","method":"service/invoke","id":"req-123"}"#;
    let mut body = Some(Bytes::from_static(json));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release on valid JSON-RPC"
    );
    assert_eq!(ctx.extra_request_headers.len(), 3, "should promote 3 headers");
    assert_promoted_header(&ctx, "X-Json-Rpc-Method", "service/invoke");
    assert_promoted_header(&ctx, "X-Json-Rpc-Id", "req-123");
    assert_promoted_header(&ctx, "X-Json-Rpc-Kind", "request");
    let results = ctx.filter_results.get("json_rpc").unwrap();
    assert_eq!(results.get("method"), Some("service/invoke"), "method result");
    assert_eq!(results.get("id"), Some("req-123"), "id result");
    assert_eq!(results.get("kind"), Some("request"), "kind result");
    assert_eq!(results.get("id_kind"), Some("string"), "id_kind result");
}

#[tokio::test]
async fn promotes_once_across_chunk_and_eos() {
    // A body delivered as a pre-EOS chunk then the full body at EOS must
    // promote exactly one set of headers, not one per invocation.
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/rpc");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let json = br#"{"jsonrpc":"2.0","method":"service/invoke","id":"req-123"}"#;

    // Pre-EOS pass: buffering, no promotion.
    let mut partial = Some(Bytes::from_static(json));
    let a1 = filter.on_request_body(&mut ctx, &mut partial, false).await.unwrap();
    assert!(matches!(a1, FilterAction::Continue), "pre-EOS should continue");
    assert!(ctx.extra_request_headers.is_empty(), "no promotion before EOS");

    // EOS pass with the full buffer: promote exactly once.
    let mut full = Some(Bytes::from_static(json));
    let a2 = filter.on_request_body(&mut ctx, &mut full, true).await.unwrap();
    assert!(matches!(a2, FilterAction::Release), "EOS should release");
    assert_eq!(ctx.extra_request_headers.len(), 3, "exactly 3 headers, no duplicates");
}

#[tokio::test]
async fn extracts_notification() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/rpc");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let json = br#"{"jsonrpc":"2.0","method":"notifications/catalog/updated"}"#;
    let mut body = Some(Bytes::from_static(json));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Release), "notification should release");
    assert_promoted_header(&ctx, "X-Json-Rpc-Method", "notifications/catalog/updated");
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

#[tokio::test]
async fn rejects_batch_exceeding_max_size_through_filter() {
    let filter = JsonRpcFilter {
        config: make_config_with_batch_limit(1),
        max_body_bytes: 1_048_576,
    };
    let req = crate::test_utils::make_request(http::Method::POST, "/rpc");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let json = br#"[{"jsonrpc":"2.0","method":"a","id":1},{"jsonrpc":"2.0","method":"b","id":2}]"#;
    let mut body = Some(Bytes::from_static(json));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 400),
        "batch exceeding max_batch_size should be rejected with 400"
    );
}

#[tokio::test]
async fn batch_too_large_rejects_regardless_of_on_invalid() {
    let filter = JsonRpcFilter {
        config: super::config::JsonRpcConfig {
            batch_policy: BatchPolicy::First,
            headers: JsonRpcHeaders::default(),
            max_batch_size: 1,
            max_body_bytes: 1_048_576,
            on_invalid: OnInvalidBehavior::Continue,
        },
        max_body_bytes: 1_048_576,
    };
    let req = crate::test_utils::make_request(http::Method::POST, "/rpc");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let json = br#"[{"jsonrpc":"2.0","method":"a","id":1},{"jsonrpc":"2.0","method":"b","id":2}]"#;
    let mut body = Some(Bytes::from_static(json));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 400),
        "batch_too_large must reject with 400 even when on_invalid is continue"
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

/// Element count for the oversized-batch regression bodies: far above
/// any plausible `max_batch_size`, small enough to stay a fast unit test.
const OVERSIZED_BATCH_ITEMS: usize = 100_000;

/// A batch body of `count` scalar elements: `[0,0,...,0]`.
fn scalar_batch_body(count: usize) -> String {
    let mut body = String::with_capacity(count * 2 + 2); // "0," per item, plus brackets
    body.push('[');
    for i in 0..count {
        if i > 0 {
            body.push(',');
        }
        body.push('0');
    }
    body.push(']');
    body
}

/// Capture `body` as a batch under `config` and report
/// `(retained captures, true element count)`.
///
/// Goes through [`capture_top`], the same entry point
/// [`parse_json_rpc_envelope`] uses, so these assertions cover how the
/// configuration is turned into the retention bound and not just the
/// visitor that applies it.
///
/// [`capture_top`]: super::raw_envelope::capture_top
fn capture_batch(body: &str, config: &super::config::JsonRpcConfig) -> (usize, usize) {
    let top = super::raw_envelope::capture_top(body.as_bytes(), config).expect("batch body must deserialize");
    match top {
        super::raw_envelope::RawTop::Batch { items, len } => (items.len(), len),
        other => panic!("expected a batch capture, got {other:?}"),
    }
}

fn make_config(batch_policy: BatchPolicy, on_invalid: OnInvalidBehavior) -> super::config::JsonRpcConfig {
    super::config::JsonRpcConfig {
        batch_policy,
        headers: JsonRpcHeaders::default(),
        max_batch_size: DEFAULT_MAX_BATCH_SIZE,
        max_body_bytes: 1_048_576,
        on_invalid,
    }
}

fn make_config_with_batch_limit(max_batch_size: usize) -> super::config::JsonRpcConfig {
    super::config::JsonRpcConfig {
        batch_policy: BatchPolicy::First,
        headers: JsonRpcHeaders::default(),
        max_batch_size,
        max_body_bytes: 1_048_576,
        on_invalid: OnInvalidBehavior::Continue,
    }
}

fn make_filter() -> JsonRpcFilter {
    JsonRpcFilter {
        config: make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue),
        max_body_bytes: 1_048_576,
    }
}

fn make_reject_filter() -> JsonRpcFilter {
    JsonRpcFilter {
        config: make_config(BatchPolicy::Reject, OnInvalidBehavior::Reject),
        max_body_bytes: 1_048_576,
    }
}

fn make_error_filter() -> JsonRpcFilter {
    JsonRpcFilter {
        config: make_config(BatchPolicy::Reject, OnInvalidBehavior::Error),
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

// -----------------------------------------------------------------------------
// Nesting-depth bound: streaming envelope parity with the old DOM parser
// -----------------------------------------------------------------------------

/// A JSON-RPC request whose `params` is an array nested `depth` levels deep.
fn deep_params_body(depth: usize) -> Vec<u8> {
    let mut s = String::from(r#"{"jsonrpc":"2.0","method":"m","id":1,"params":"#);
    s.push_str(&"[".repeat(depth));
    s.push_str(&"]".repeat(depth));
    s.push('}');
    s.into_bytes()
}

#[test]
fn shallow_nested_params_accepted() {
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    let body = deep_params_body(8);
    let envelope = parse_json_rpc_envelope(&body, &config)
        .expect("shallow nesting must parse")
        .expect("must be a JSON-RPC message");
    assert_eq!(envelope.method.as_deref(), Some("m"), "method must still be captured");
}

#[test]
fn deep_nested_params_rejected() {
    // The streaming parser caps ignored-subtree nesting at MAX_ENVELOPE_DEPTH,
    // matching the recursion limit the old `from_slice::<Value>` DOM parser
    // enforced. Without the bound, `IgnoredAny` accepted arbitrarily deep
    // `params` and promoted the envelope; a security-adjacent classifier must
    // fail closed on pathological input instead.
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    let body = deep_params_body(300);
    let err = parse_json_rpc_envelope(&body, &config).expect_err("deep nesting must be rejected");
    assert!(
        matches!(err, super::envelope::JsonRpcParseError::InvalidJson(_)),
        "over-deep nesting should surface as InvalidJson: {err:?}"
    );
}

#[test]
fn deep_nested_params_streaming_matches_dom() {
    // Regression guard for the IgnoredAny-unbounded divergence: a body the DOM
    // path rejects for excessive depth must also be rejected by the streaming
    // path, so the two JSON-RPC parse paths agree on accept/reject.
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    let body = deep_params_body(300);
    let dom_rejects = serde_json::from_slice::<serde_json::Value>(&body).is_err();
    let streaming_rejects = parse_json_rpc_envelope(&body, &config).is_err();
    assert!(dom_rejects, "the DOM parser must reject 300-deep nesting");
    assert!(
        streaming_rejects,
        "the streaming parser must reject the same body the DOM parser rejects"
    );
}

#[test]
fn deep_nested_id_rejected() {
    // A container-valued `id` nested past the cap is bounded on the id path too.
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    let mut s = String::from(r#"{"jsonrpc":"2.0","method":"m","id":"#);
    s.push_str(&"[".repeat(300));
    s.push_str(&"]".repeat(300));
    s.push('}');
    let err = parse_json_rpc_envelope(s.as_bytes(), &config).expect_err("deep id must be rejected");
    assert!(
        matches!(err, super::envelope::JsonRpcParseError::InvalidJson(_)),
        "deep id nesting should surface as InvalidJson: {err:?}"
    );
}

#[test]
fn deep_nested_object_params_rejected() {
    // Exercises BoundedIgnore::visit_map's depth guard (objects, not arrays).
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    let mut s = String::from(r#"{"jsonrpc":"2.0","method":"m","id":1,"params":"#);
    s.push_str(&r#"{"a":"#.repeat(300));
    s.push('1');
    s.push_str(&"}".repeat(300));
    s.push('}');
    assert!(
        parse_json_rpc_envelope(s.as_bytes(), &config).is_err(),
        "deeply nested object params must be rejected"
    );
}

#[test]
fn ignored_params_scalars_and_containers_are_accepted() {
    // Exercises every reachable BoundedIgnore arm (bool, i64, u64, f64, str,
    // unit/null, map, seq) via the ignored `params` value.
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    for params in [
        "true",
        "42",
        "-7",
        "1.5",
        r#""s""#,
        "null",
        r#"{"a":1,"b":[2,3]}"#,
        "[1,2,3]",
    ] {
        let body = format!(r#"{{"jsonrpc":"2.0","method":"m","id":1,"params":{params}}}"#);
        let env = parse_json_rpc_envelope(body.as_bytes(), &config)
            .unwrap_or_else(|e| panic!("params {params} should parse: {e:?}"))
            .expect("a JSON-RPC message");
        assert_eq!(
            env.method.as_deref(),
            Some("m"),
            "method must still be captured with params={params}"
        );
    }
}

#[test]
fn id_variants_are_classified() {
    // Exercises IdVisitor scalar arms (str, i64, u64, f64, unit).
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    for (id, kind) in [
        (r#""abc""#, JsonRpcIdKind::String),
        ("7", JsonRpcIdKind::Integer),
        ("-7", JsonRpcIdKind::Integer),
        ("18446744073709551615", JsonRpcIdKind::Integer),
        ("1.5", JsonRpcIdKind::Number),
        ("null", JsonRpcIdKind::Null),
    ] {
        let body = format!(r#"{{"jsonrpc":"2.0","method":"m","id":{id}}}"#);
        let env = parse_json_rpc_envelope(body.as_bytes(), &config)
            .unwrap()
            .expect("a JSON-RPC message");
        assert_eq!(env.id_kind, kind, "id {id} classification");
    }
}

#[test]
fn container_and_bool_ids_are_invalid() {
    // Exercises IdVisitor::visit_map / visit_seq / visit_bool -> RawId::Invalid.
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    for id in [r#"{"a":1}"#, "[1,2]", "true"] {
        let body = format!(r#"{{"jsonrpc":"2.0","method":"m","id":{id}}}"#);
        let err = parse_json_rpc_envelope(body.as_bytes(), &config).unwrap_err();
        assert!(
            matches!(err, super::envelope::JsonRpcParseError::InvalidId),
            "id {id} must be InvalidId, got {err:?}"
        );
    }
}

#[test]
fn non_string_version_is_treated_as_missing() {
    // Exercises VersionVisitor non-string arms (i64, bool, map, seq) ->
    // RawVersion::Missing -> handle_non_json_rpc (Continue -> Ok(None)).
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    for v in ["2", "true", r#"{"x":1}"#, "[1]"] {
        let body = format!(r#"{{"jsonrpc":{v},"method":"m","id":1}}"#);
        let out = parse_json_rpc_envelope(body.as_bytes(), &config).unwrap();
        assert!(out.is_none(), "a non-string jsonrpc={v} is not a JSON-RPC message");
    }
}

#[test]
fn non_string_method_variants_are_invalid() {
    // Exercises MethodVisitor non-string arms (i64, bool, map, seq, unit) ->
    // RawMethod::NotString -> InvalidMethod.
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    for m in ["1", "true", r#"{"x":1}"#, "[1]", "null"] {
        let body = format!(r#"{{"jsonrpc":"2.0","method":{m},"id":1}}"#);
        let err = parse_json_rpc_envelope(body.as_bytes(), &config).unwrap_err();
        assert!(
            matches!(err, super::envelope::JsonRpcParseError::InvalidMethod),
            "method {m} must be InvalidMethod, got {err:?}"
        );
    }
}

#[test]
fn batch_first_skips_non_object_items() {
    // Exercises ItemVisitor scalar/seq arms: non-object batch items are
    // captured as None and skipped; the first valid object wins.
    let config = make_config(BatchPolicy::First, OnInvalidBehavior::Continue);
    let body = br#"[1, "x", [1,2], {"jsonrpc":"2.0","method":"picked","id":1}]"#;
    let env = parse_json_rpc_envelope(body, &config)
        .unwrap()
        .expect("the first valid object");
    assert_eq!(env.method.as_deref(), Some("picked"), "first valid batch object wins");
    assert_eq!(env.kind, JsonRpcKind::Batch, "kind should be batch");
}

#[test]
fn escaped_strings_hit_owned_visit_string_arms() {
    // serde_json yields an owned String (visit_string, not the borrowed
    // visit_str) when a JSON string carries an escape sequence. Use escaped
    // jsonrpc/method/id so the *_string visitor arms are exercised.
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    // 2.0 unescapes to an owned "2.0"; method "a\nb"; id "x\ty" -- each
    // carries an escape so serde_json calls visit_string, not visit_str.
    let body = br#"{"jsonrpc":"2.0","method":"a\nb","id":"x\ty"}"#;
    let env = parse_json_rpc_envelope(body, &config)
        .unwrap()
        .expect("escaped-string envelope must parse");
    assert_eq!(env.method.as_deref(), Some("a\nb"), "escaped method captured");
    assert_eq!(env.id.as_deref(), Some("x\ty"), "escaped id captured");
    assert_eq!(env.id_kind, JsonRpcIdKind::String, "escaped id is a string id");
}

#[test]
fn root_scalars_are_not_json_rpc() {
    // Exercises TopVisitor scalar arms -> RawTop::Other -> handle_non_json_rpc.
    let config = make_config(BatchPolicy::Reject, OnInvalidBehavior::Continue);
    for root in [r#""s""#, "42", "1.5", "true", "null"] {
        let out = parse_json_rpc_envelope(root.as_bytes(), &config).unwrap();
        assert!(out.is_none(), "root scalar {root} is not JSON-RPC");
    }
}

// -----------------------------------------------------------------------------
// Header Forgery Prevention Tests (#1057)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn strips_forged_headers_on_valid_json_rpc() {
    // A classified JSON-RPC request must remove any client-supplied copies
    // of the promotion headers before adding the body-derived values.
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/rpc");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let json = br#"{"jsonrpc":"2.0","method":"service/invoke","id":"req-123"}"#;
    let mut body = Some(Bytes::from_static(json));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Release));

    // The configured header names should appear in the remove list so
    // client-supplied copies are stripped before the promoted values
    // are added.
    let remove_names: Vec<&str> = ctx
        .request_headers_to_remove
        .iter()
        .map(|h| h.as_str())
        .collect();
    assert!(
        remove_names.contains(&"x-json-rpc-method"),
        "X-Json-Rpc-Method should be in the remove list: {remove_names:?}"
    );
    assert!(
        remove_names.contains(&"x-json-rpc-id"),
        "X-Json-Rpc-Id should be in the remove list: {remove_names:?}"
    );
    assert!(
        remove_names.contains(&"x-json-rpc-kind"),
        "X-Json-Rpc-Kind should be in the remove list: {remove_names:?}"
    );

    // Promoted values should still be present in extra_request_headers.
    assert_promoted_header(&ctx, "X-Json-Rpc-Method", "service/invoke");
    assert_promoted_header(&ctx, "X-Json-Rpc-Id", "req-123");
    assert_promoted_header(&ctx, "X-Json-Rpc-Kind", "request");
}

#[tokio::test]
async fn strips_forged_headers_on_non_json_rpc_body() {
    // A non-JSON-RPC request must strip the configured promotion headers
    // even though the classifier does not promote anything. Without this,
    // a forged X-Json-Rpc-Method passes through unchanged.
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"not json at all"));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "non-JSON body should continue"
    );

    // Even though no promotion happened, the remove list should contain
    // the configured header names to strip any client-supplied forgeries.
    let remove_names: Vec<&str> = ctx
        .request_headers_to_remove
        .iter()
        .map(|h| h.as_str())
        .collect();
    assert!(
        remove_names.contains(&"x-json-rpc-method"),
        "non-JSON-RPC request must still strip X-Json-Rpc-Method: {remove_names:?}"
    );
    assert!(
        remove_names.contains(&"x-json-rpc-id"),
        "non-JSON-RPC request must still strip X-Json-Rpc-Id: {remove_names:?}"
    );
    assert!(
        remove_names.contains(&"x-json-rpc-kind"),
        "non-JSON-RPC request must still strip X-Json-Rpc-Kind: {remove_names:?}"
    );

    // No promotion should have occurred.
    assert!(
        ctx.extra_request_headers.is_empty(),
        "non-JSON body should not promote any headers"
    );
}

#[tokio::test]
async fn strips_forged_headers_on_none_body() {
    // Even with no body at all, configured headers should be stripped.
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body: Option<Bytes> = None;
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Continue));

    let remove_names: Vec<&str> = ctx
        .request_headers_to_remove
        .iter()
        .map(|h| h.as_str())
        .collect();
    assert!(
        remove_names.contains(&"x-json-rpc-method"),
        "None body must still strip configured headers: {remove_names:?}"
    );
}

#[tokio::test]
async fn strips_forged_headers_with_custom_header_names() {
    // Custom header names configured by the operator should also be
    // stripped from inbound requests.
    let filter = JsonRpcFilter {
        config: super::config::JsonRpcConfig {
            batch_policy: BatchPolicy::Reject,
            headers: JsonRpcHeaders {
                id: Some("X-Custom-Id".to_owned()),
                kind: Some("X-Custom-Kind".to_owned()),
                method: Some("X-Custom-Method".to_owned()),
            },
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            max_body_bytes: 1_048_576,
            on_invalid: OnInvalidBehavior::Continue,
        },
        max_body_bytes: 1_048_576,
    };
    let req = crate::test_utils::make_request(http::Method::POST, "/test");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"not json"));
    let _action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    let remove_names: Vec<&str> = ctx
        .request_headers_to_remove
        .iter()
        .map(|h| h.as_str())
        .collect();
    assert!(
        remove_names.contains(&"x-custom-method"),
        "custom method header should be stripped: {remove_names:?}"
    );
    assert!(
        remove_names.contains(&"x-custom-id"),
        "custom id header should be stripped: {remove_names:?}"
    );
    assert!(
        remove_names.contains(&"x-custom-kind"),
        "custom kind header should be stripped: {remove_names:?}"
    );
}

#[tokio::test]
async fn no_strip_before_end_of_stream() {
    // Pre-EOS calls should not strip headers (the strip happens at EOS).
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/rpc");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let json = br#"{"jsonrpc":"2.0","method":"service/invoke","id":"req-123"}"#;
    let mut partial = Some(Bytes::from_static(json));
    let _action = filter.on_request_body(&mut ctx, &mut partial, false).await.unwrap();

    assert!(
        ctx.request_headers_to_remove.is_empty(),
        "pre-EOS should not modify the remove list"
    );
}
