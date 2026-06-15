// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Unit tests for the A2A classifier filter.

use std::{collections::BTreeMap, sync::Arc};

use bytes::Bytes;
use http::HeaderMap;

use super::{
    A2aFilter,
    config::{A2aConfig, build_config},
    envelope::{A2aFamily, A2aMethod, extract_a2a_envelope},
    task_routing::LocalTaskRouteStore,
};
use crate::{FilterAction, filter::HttpFilter};

// -----------------------------------------------------------------------------
// Config Tests
// -----------------------------------------------------------------------------

#[test]
fn parse_minimal_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let filter = A2aFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "a2a", "minimal config should produce a2a filter");
}

#[test]
fn parse_full_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        max_body_bytes: 131072
        on_invalid: continue
        method_aliases:
          message/send: SendMessage
          message/stream: SendStreamingMessage
          tasks/get: GetTask
          tasks/cancel: CancelTask
        headers:
          method: x-a2a-method
          family: x-a2a-family
          task_id: x-a2a-task-id
          kind: x-a2a-kind
          streaming: x-a2a-streaming
          version: x-a2a-version
        "#,
    )
    .unwrap();
    let filter = A2aFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "a2a", "full config should produce a2a filter");
}

#[test]
fn reject_zero_max_body_bytes() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("max_body_bytes: 0").unwrap();
    let err = A2aFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("must be greater than 0"),
        "error should mention max_body_bytes constraint"
    );
}

#[test]
fn rejects_max_body_bytes_above_ceiling() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("max_body_bytes: 67108865").unwrap();
    let err = A2aFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("exceeds maximum"),
        "error should mention exceeds maximum"
    );
}

#[test]
fn reject_invalid_alias_target() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        method_aliases:
          message/send: UnknownMethod
        "#,
    )
    .unwrap();
    let err = A2aFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("not a known A2A method"),
        "error should mention unknown A2A method"
    );
}

#[test]
fn reject_empty_alias_key() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        method_aliases:
          "": SendMessage
        "#,
    )
    .unwrap();
    let err = A2aFilter::from_config(&yaml).err().expect("should fail");
    assert!(err.to_string().contains("alias key"), "error should mention alias key");
}

#[test]
fn reject_empty_alias_value() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        method_aliases:
          message/send: ""
        "#,
    )
    .unwrap();
    let err = A2aFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("alias value"),
        "error should mention alias value"
    );
}

#[test]
fn reject_empty_header_name() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        headers:
          method: ""
        "#,
    )
    .unwrap();
    let err = A2aFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("must not be empty"),
        "error should mention empty header name"
    );
}

#[test]
fn reject_invalid_header_name() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        headers:
          method: "invalid header name with spaces"
        "#,
    )
    .unwrap();
    let err = A2aFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("not a valid HTTP header name"),
        "error should mention invalid header name"
    );
}

// -----------------------------------------------------------------------------
// Method Classification Tests
// -----------------------------------------------------------------------------

#[test]
fn canonical_method_classification() {
    let no_aliases = BTreeMap::new();

    for (input, expected) in canonical_method_cases() {
        assert_eq!(
            A2aMethod::from_method_str(input, &no_aliases),
            expected,
            "canonical method mismatch for {input}"
        );
    }
}

#[test]
fn unknown_method_classification() {
    let no_aliases = BTreeMap::new();
    assert_eq!(
        A2aMethod::from_method_str("UnknownMethod", &no_aliases),
        A2aMethod::Unknown("UnknownMethod".to_owned()),
        "unrecognized method should be Unknown"
    );
}

#[test]
fn method_classification_is_case_sensitive() {
    let no_aliases = BTreeMap::new();
    assert_eq!(
        A2aMethod::from_method_str("sendmessage", &no_aliases),
        A2aMethod::Unknown("sendmessage".to_owned()),
        "A2A method classification should not normalize method casing"
    );
}

#[test]
fn family_classification_message_and_task() {
    assert_eq!(
        A2aMethod::SendMessage.family(),
        A2aFamily::Message,
        "SendMessage should be Message family"
    );
    assert_eq!(
        A2aMethod::SendStreamingMessage.family(),
        A2aFamily::Message,
        "SendStreamingMessage should be Message family"
    );
    assert_eq!(
        A2aMethod::GetTask.family(),
        A2aFamily::Task,
        "GetTask should be Task family"
    );
    assert_eq!(
        A2aMethod::ListTasks.family(),
        A2aFamily::Task,
        "ListTasks should be Task family"
    );
    assert_eq!(
        A2aMethod::CancelTask.family(),
        A2aFamily::Task,
        "CancelTask should be Task family"
    );
    assert_eq!(
        A2aMethod::SubscribeToTask.family(),
        A2aFamily::Task,
        "SubscribeToTask should be Task family"
    );
}

#[test]
fn family_classification_push_notification_and_other() {
    assert_eq!(
        A2aMethod::CreateTaskPushNotificationConfig.family(),
        A2aFamily::PushNotification,
        "push notification config methods should be PushNotification family"
    );
    assert_eq!(
        A2aMethod::GetTaskPushNotificationConfig.family(),
        A2aFamily::PushNotification,
        "push notification config methods should be PushNotification family"
    );
    assert_eq!(
        A2aMethod::ListTaskPushNotificationConfigs.family(),
        A2aFamily::PushNotification,
        "push notification config methods should be PushNotification family"
    );
    assert_eq!(
        A2aMethod::DeleteTaskPushNotificationConfig.family(),
        A2aFamily::PushNotification,
        "push notification config methods should be PushNotification family"
    );
    assert_eq!(
        A2aMethod::GetExtendedAgentCard.family(),
        A2aFamily::AgentCard,
        "GetExtendedAgentCard should be AgentCard family"
    );
    assert_eq!(
        A2aMethod::Unknown("test".to_owned()).family(),
        A2aFamily::Unknown,
        "unknown method should be Unknown family"
    );
}

#[test]
fn streaming_detection() {
    assert!(
        A2aMethod::SendStreamingMessage.is_streaming(),
        "SendStreamingMessage should be streaming"
    );
    assert!(
        A2aMethod::SubscribeToTask.is_streaming(),
        "SubscribeToTask should be streaming"
    );
    assert!(
        !A2aMethod::SendMessage.is_streaming(),
        "SendMessage should not be streaming"
    );
    assert!(!A2aMethod::GetTask.is_streaming(), "GetTask should not be streaming");
    assert!(
        !A2aMethod::ListTasks.is_streaming(),
        "ListTasks should not be streaming"
    );
    assert!(
        !A2aMethod::CancelTask.is_streaming(),
        "CancelTask should not be streaming"
    );
    assert!(
        !A2aMethod::GetExtendedAgentCard.is_streaming(),
        "GetExtendedAgentCard should not be streaming"
    );
}

#[test]
fn alias_resolution() {
    let mut aliases = BTreeMap::new();
    aliases.insert("message/send".to_owned(), "SendMessage".to_owned());
    aliases.insert("message/stream".to_owned(), "SendStreamingMessage".to_owned());
    aliases.insert("tasks/get".to_owned(), "GetTask".to_owned());
    aliases.insert("tasks/cancel".to_owned(), "CancelTask".to_owned());

    assert_eq!(
        A2aMethod::from_method_str("message/send", &aliases),
        A2aMethod::SendMessage,
        "message/send should resolve to SendMessage"
    );
    assert_eq!(
        A2aMethod::from_method_str("message/stream", &aliases),
        A2aMethod::SendStreamingMessage,
        "message/stream should resolve to SendStreamingMessage"
    );
    assert_eq!(
        A2aMethod::from_method_str("tasks/get", &aliases),
        A2aMethod::GetTask,
        "tasks/get should resolve to GetTask"
    );
    assert_eq!(
        A2aMethod::from_method_str("tasks/cancel", &aliases),
        A2aMethod::CancelTask,
        "tasks/cancel should resolve to CancelTask"
    );

    assert_eq!(
        A2aMethod::from_method_str("SendMessage", &aliases),
        A2aMethod::SendMessage,
        "canonical SendMessage should still work with aliases present"
    );
}

// -----------------------------------------------------------------------------
// Envelope Extraction Tests
// -----------------------------------------------------------------------------

#[test]
fn task_id_extraction_from_params_id() {
    let json = serde_json::json!({
        "jsonrpc": "2.0", "method": "GetTask",
        "params": { "id": "task-123" }, "id": 1
    });
    let envelope = extract_a2a_envelope(&json, "GetTask", &BTreeMap::new(), &HeaderMap::new());
    assert_eq!(
        envelope.task_id,
        Some("task-123".to_owned()),
        "GetTask should extract task ID from params.id"
    );
}

#[test]
fn task_id_extraction_from_params_task_id() {
    let json = serde_json::json!({
        "jsonrpc": "2.0", "method": "CreateTaskPushNotificationConfig",
        "params": { "taskId": "task-456", "config": {} }, "id": 1
    });
    let envelope = extract_a2a_envelope(
        &json,
        "CreateTaskPushNotificationConfig",
        &BTreeMap::new(),
        &HeaderMap::new(),
    );
    assert_eq!(
        envelope.task_id,
        Some("task-456".to_owned()),
        "push notification config methods should extract from params.taskId"
    );
}

#[test]
fn missing_task_id_left_unset() {
    let json = serde_json::json!({
        "jsonrpc": "2.0", "method": "GetTask",
        "params": {}, "id": 1
    });
    let envelope = extract_a2a_envelope(&json, "GetTask", &BTreeMap::new(), &HeaderMap::new());
    assert_eq!(envelope.task_id, None, "missing params.id should leave task_id unset");
}

#[test]
fn non_string_task_id_left_unset() {
    let json = serde_json::json!({
        "jsonrpc": "2.0", "method": "GetTask",
        "params": { "id": 123 }, "id": 1
    });
    let envelope = extract_a2a_envelope(&json, "GetTask", &BTreeMap::new(), &HeaderMap::new());
    assert_eq!(
        envelope.task_id, None,
        "non-string params.id should leave task_id unset"
    );
}

#[test]
fn no_task_id_for_message_methods() {
    let json = serde_json::json!({
        "jsonrpc": "2.0", "method": "SendMessage",
        "params": { "id": "some-id", "taskId": "some-task-id" }, "id": 1
    });
    let envelope = extract_a2a_envelope(&json, "SendMessage", &BTreeMap::new(), &HeaderMap::new());
    assert_eq!(envelope.task_id, None, "SendMessage should not extract task ID");
}

#[test]
fn version_extraction() {
    let mut headers = HeaderMap::new();
    headers.insert("a2a-version", "1.0".parse().unwrap());

    let json = serde_json::json!({"jsonrpc": "2.0", "method": "SendMessage"});
    let envelope = extract_a2a_envelope(&json, "SendMessage", &BTreeMap::new(), &headers);
    assert_eq!(
        envelope.version,
        Some("1.0".to_owned()),
        "A2A-Version header should be extracted"
    );
}

#[test]
fn original_method_tracking() {
    let mut aliases = BTreeMap::new();
    aliases.insert("message/send".to_owned(), "SendMessage".to_owned());

    let json = serde_json::json!({"jsonrpc": "2.0", "method": "message/send"});
    let envelope = extract_a2a_envelope(&json, "message/send", &aliases, &HeaderMap::new());

    assert_eq!(
        envelope.method,
        A2aMethod::SendMessage,
        "should resolve alias to canonical"
    );
    assert_eq!(
        envelope.original_method,
        Some("message/send".to_owned()),
        "original method should be tracked when alias resolved"
    );
}

#[test]
fn no_original_method_for_canonical() {
    let json = serde_json::json!({"jsonrpc": "2.0", "method": "SendMessage"});
    let envelope = extract_a2a_envelope(&json, "SendMessage", &BTreeMap::new(), &HeaderMap::new());

    assert_eq!(
        envelope.method,
        A2aMethod::SendMessage,
        "canonical method should resolve directly"
    );
    assert_eq!(
        envelope.original_method, None,
        "canonical method should not set original_method"
    );
}

#[test]
fn a2a_method_round_trips() {
    let no_aliases = BTreeMap::new();
    let cases = [
        A2aMethod::SendMessage,
        A2aMethod::SendStreamingMessage,
        A2aMethod::GetTask,
        A2aMethod::ListTasks,
        A2aMethod::CancelTask,
        A2aMethod::SubscribeToTask,
        A2aMethod::CreateTaskPushNotificationConfig,
        A2aMethod::GetTaskPushNotificationConfig,
        A2aMethod::ListTaskPushNotificationConfigs,
        A2aMethod::DeleteTaskPushNotificationConfig,
        A2aMethod::GetExtendedAgentCard,
        A2aMethod::Unknown("custom_method".to_owned()),
    ];

    for method in &cases {
        assert_eq!(
            A2aMethod::from_method_str(method.as_str(), &no_aliases),
            *method,
            "round-trip failed for {}",
            method.as_str()
        );
    }
}

// -----------------------------------------------------------------------------
// Filter Behavior Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn send_message_extracts_metadata() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":"Hello"}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "should release on valid A2A");
    assert_eq!(ctx.get_metadata("a2a.method"), Some("SendMessage"));
    assert_eq!(ctx.get_metadata("a2a.family"), Some("message"));
    assert_eq!(ctx.get_metadata("a2a.streaming"), Some("false"));
}

#[tokio::test]
async fn streaming_message_sets_streaming_true() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"SendStreamingMessage","params":{}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "streaming message should release"
    );
    assert_eq!(
        ctx.get_metadata("a2a.streaming"),
        Some("true"),
        "streaming should be true"
    );
    assert_eq!(
        ctx.get_metadata("a2a.family"),
        Some("message"),
        "family should be message"
    );
}

#[tokio::test]
async fn get_task_extracts_task_id() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"task-999"}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "GetTask should release");
    assert_eq!(
        ctx.get_metadata("a2a.method"),
        Some("GetTask"),
        "method should be GetTask"
    );
    assert_eq!(ctx.get_metadata("a2a.family"), Some("task"), "family should be task");
    assert_eq!(
        ctx.get_metadata("a2a.task_id"),
        Some("task-999"),
        "task_id should be extracted"
    );
}

#[tokio::test]
async fn push_notification_config_extracts_task_id_from_params() {
    let filter = make_default_filter();
    let body_str =
        r#"{"jsonrpc":"2.0","id":1,"method":"GetTaskPushNotificationConfig","params":{"taskId":"task-abc"}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "push notification config should release"
    );
    assert_eq!(
        ctx.get_metadata("a2a.family"),
        Some("push_notification"),
        "family should be push_notification"
    );
    assert_eq!(
        ctx.get_metadata("a2a.task_id"),
        Some("task-abc"),
        "task_id should be extracted from params"
    );
}

#[tokio::test]
async fn alias_resolves_and_sets_original_method() {
    let filter = make_filter(r#"{"method_aliases": {"message/send": "SendMessage"}, "on_invalid": "continue"}"#);
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release));
    assert_eq!(
        ctx.get_metadata("a2a.method"),
        Some("SendMessage"),
        "canonical method should be promoted"
    );
    assert_eq!(
        ctx.get_metadata("a2a.original_method"),
        Some("message/send"),
        "original aliased method should be stored"
    );
}

#[tokio::test]
async fn unknown_method_classifies_as_family_unknown() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"CustomUnknown","params":{}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "unknown methods should still be classified, not rejected"
    );
    assert_eq!(
        ctx.get_metadata("a2a.method"),
        Some("CustomUnknown"),
        "unknown method should be promoted"
    );
    assert_eq!(
        ctx.get_metadata("a2a.family"),
        Some("unknown"),
        "unknown method family should be unknown"
    );
}

#[tokio::test]
async fn version_header_extracted_to_metadata() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}"#;
    let mut req = make_a2a_request(&[]);
    req.headers.insert("a2a-version", "1.0".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "should release with version");
    assert_eq!(
        ctx.get_metadata("a2a.version"),
        Some("1.0"),
        "A2A-Version header should be promoted to metadata"
    );
}

#[tokio::test]
async fn non_json_rpc_rejected_by_default() {
    let filter = make_default_filter();
    let body_str = r#"{"message":"hello"}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Reject(_)),
        "non-A2A should be rejected by default"
    );
}

#[tokio::test]
async fn non_json_rpc_continues_when_configured() {
    let filter = make_filter(r#"{"on_invalid": "continue"}"#);
    let body_str = r#"{"message":"hello"}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "non-A2A should continue with on_invalid: continue"
    );
}

#[tokio::test]
async fn batch_rejected_even_with_on_invalid_continue() {
    let filter = make_filter(r#"{"on_invalid": "continue"}"#);
    let body_str = r#"[{"jsonrpc":"2.0","id":1,"method":"SendMessage"}]"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Reject(_)),
        "batch should be rejected regardless of on_invalid: \
         A2A routing is a single classification decision per request, \
         and batches can contain mixed methods/task IDs/streaming semantics"
    );
}

#[tokio::test]
async fn on_request_is_noop() {
    let filter = make_default_filter();
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "on_request should be a no-op");
}

#[tokio::test]
async fn returns_continue_on_none_body() {
    let filter = make_default_filter();
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body: Option<Bytes> = None;

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "None body should continue");
}

#[test]
fn body_access_is_read_only() {
    let filter = make_default_filter();
    assert_eq!(
        filter.request_body_access(),
        crate::body::BodyAccess::ReadOnly,
        "A2A filter should use ReadOnly body access"
    );
}

#[test]
fn body_mode_is_stream_buffer() {
    let filter = make_default_filter();
    assert_eq!(
        filter.request_body_mode(),
        crate::body::BodyMode::StreamBuffer {
            max_bytes: Some(super::config::DEFAULT_MAX_BODY_BYTES)
        },
        "A2A filter should use StreamBuffer with default max bytes"
    );
}

// -----------------------------------------------------------------------------
// StreamBuffer / EOS Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn complete_json_before_eos_still_continues() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "complete JSON-RPC before EOS should continue, not release"
    );
}

#[tokio::test]
async fn complete_json_at_eos_releases() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "complete JSON-RPC at EOS should release"
    );
}

// -----------------------------------------------------------------------------
// Promotion Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn promotes_filter_results() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"task-42"}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "should release on valid A2A");

    let results = ctx.filter_results.get("a2a").unwrap();
    assert_eq!(
        results.get("method"),
        Some("GetTask"),
        "method should be in filter results"
    );
    assert_eq!(
        results.get("family"),
        Some("task"),
        "family should be in filter results"
    );
    assert_eq!(
        results.get("streaming"),
        Some("false"),
        "streaming should be in filter results"
    );
    assert_eq!(results.get("kind"), Some("request"), "kind should be in filter results");
    assert_eq!(
        results.get("task_id"),
        Some("task-42"),
        "task_id should be in filter results"
    );
}

#[tokio::test]
async fn promotes_method_and_family_headers() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"SendStreamingMessage","params":{}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "should release on valid A2A");

    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();

    assert_eq!(
        headers.get("x-praxis-a2a-method"),
        Some(&"SendStreamingMessage"),
        "method header should be promoted"
    );
    assert_eq!(
        headers.get("x-praxis-a2a-family"),
        Some(&"message"),
        "family header should be promoted"
    );
}

#[tokio::test]
async fn promotes_kind_and_streaming_headers() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"SendStreamingMessage","params":{}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "should release on valid A2A");

    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();

    assert_eq!(
        headers.get("x-praxis-a2a-kind"),
        Some(&"request"),
        "kind header should be promoted"
    );
    assert_eq!(
        headers.get("x-praxis-a2a-streaming"),
        Some(&"true"),
        "streaming header should be true"
    );
}

#[tokio::test]
async fn notification_sets_kind() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","method":"SendMessage","params":{}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "notification should release");
    assert_eq!(
        ctx.get_metadata("json_rpc.kind"),
        Some("notification"),
        "message without id should be a notification"
    );
}

#[tokio::test]
async fn version_promoted_to_headers_and_results() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}"#;
    let mut req = make_a2a_request(&[]);
    req.headers.insert("a2a-version", "1.0".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "should release with version");

    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();
    assert_eq!(
        headers.get("x-praxis-a2a-version"),
        Some(&"1.0"),
        "version header should be promoted"
    );

    let results = ctx.filter_results.get("a2a").unwrap();
    assert_eq!(
        results.get("version"),
        Some("1.0"),
        "version should be in filter results"
    );
}

// -----------------------------------------------------------------------------
// Control Character Safety Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn control_char_method_skips_all_promotions() {
    let filter = make_default_filter();
    let body_str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"Send\\nMessage\"}";
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "control char method should still release"
    );

    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();
    assert!(
        !headers.contains_key("x-praxis-a2a-method"),
        "method with control chars should not be promoted to header"
    );

    let results = ctx.filter_results.get("a2a").unwrap();
    assert_eq!(
        results.get("method"),
        None,
        "method with control chars should not be set in filter results"
    );

    assert_eq!(
        ctx.get_metadata("a2a.method"),
        None,
        "method with control chars should not be set in durable metadata"
    );
}

#[tokio::test]
async fn control_char_task_id_skips_promotion() {
    let filter = make_default_filter();
    let body_str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"GetTask\",\"params\":{\"id\":\"task\\n123\"}}";
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "control char task ID should still release"
    );
    assert_eq!(
        ctx.get_metadata("a2a.task_id"),
        None,
        "task ID with control chars should not be promoted to metadata"
    );
}

#[tokio::test]
async fn too_long_task_id_not_promoted() {
    let filter = make_default_filter();
    let long_id = "x".repeat(257);
    let body_str = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{{"id":"{long_id}"}}}}"#);
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "too-long task ID should still release"
    );
    assert_eq!(
        ctx.get_metadata("a2a.task_id"),
        None,
        "task ID exceeding 256 bytes should not be promoted"
    );

    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();
    assert!(
        !headers.contains_key("x-praxis-a2a-task-id"),
        "too-long task ID should not be promoted to header"
    );
}

#[tokio::test]
async fn too_long_version_not_promoted() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}"#;
    let mut req = make_a2a_request(&[]);
    let long_version = "v".repeat(257);
    req.headers.insert("a2a-version", long_version.parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "too-long version should still release"
    );
    assert_eq!(
        ctx.get_metadata("a2a.version"),
        None,
        "version exceeding 256 bytes should not be promoted"
    );
}

#[tokio::test]
async fn too_long_unknown_method_releases_without_error() {
    let filter = make_default_filter();
    let long_method = "X".repeat(257);
    let body_str = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{long_method}","params":{{}}}}"#);
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "257-byte unknown method should still release, not error"
    );
    assert_eq!(ctx.get_metadata("a2a.method"), None, "too-long method skips metadata");

    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();
    assert!(
        !headers.contains_key("x-praxis-a2a-method"),
        "too-long method skips header"
    );

    let results = ctx.filter_results.get("a2a").unwrap();
    assert_eq!(results.get("method"), None, "too-long method skips filter results");
    assert_eq!(results.get("family"), Some("unknown"), "family still classified");
}

#[tokio::test]
async fn alias_stores_original_in_json_rpc_method() {
    let filter = make_filter(r#"{"method_aliases": {"message/send": "SendMessage"}, "on_invalid": "continue"}"#);
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release));
    assert_eq!(
        ctx.get_metadata("json_rpc.method"),
        Some("message/send"),
        "json_rpc.method should store the original wire method"
    );
    assert_eq!(
        ctx.get_metadata("a2a.method"),
        Some("SendMessage"),
        "a2a.method should store the canonical method"
    );
    assert_eq!(
        ctx.get_metadata("a2a.original_method"),
        Some("message/send"),
        "a2a.original_method should track the alias input"
    );
}

#[tokio::test]
async fn canonical_method_stores_same_in_json_rpc_method() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "canonical method should release"
    );
    assert_eq!(
        ctx.get_metadata("json_rpc.method"),
        Some("SendMessage"),
        "json_rpc.method should match body method when no alias"
    );
    assert_eq!(
        ctx.get_metadata("a2a.method"),
        Some("SendMessage"),
        "a2a.method should match canonical"
    );
    assert_eq!(
        ctx.get_metadata("a2a.original_method"),
        None,
        "a2a.original_method should be absent for canonical methods"
    );
}

// -----------------------------------------------------------------------------
// Task Routing Config Tests
// -----------------------------------------------------------------------------

#[test]
fn task_routing_disabled_by_default() {
    let cfg: A2aConfig = serde_yaml::from_str("{}").unwrap();
    assert!(!cfg.task_routing.enabled, "task routing should be disabled by default");
}

#[test]
fn task_routing_enabled_parses_defaults() {
    let cfg: A2aConfig = serde_yaml::from_str(
        r#"
        task_routing:
          enabled: true
        "#,
    )
    .unwrap();
    let validated = build_config(cfg).unwrap();
    assert!(validated.task_routing.enabled, "task routing should be enabled");
    assert_eq!(
        validated.task_routing.route_cluster_header, "x-praxis-a2a-route-cluster",
        "default route cluster header"
    );
    assert_eq!(validated.task_routing.ttl_seconds, 3600, "default TTL is 1 hour");
    assert_eq!(
        validated.task_routing.terminal_ttl_seconds, 300,
        "default terminal TTL is 5 minutes"
    );
    assert_eq!(
        validated.task_routing.max_response_body_bytes, 65_536,
        "default max response body bytes is 64 KiB"
    );
}

#[test]
fn task_routing_rejects_unknown_store() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        task_routing:
          enabled: true
          store: redis
        "#,
    )
    .unwrap();
    let err = A2aFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("unknown variant"),
        "unknown store should be rejected: {err}"
    );
}

#[test]
fn task_routing_rejects_invalid_route_cluster_header() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        task_routing:
          enabled: true
          route_cluster_header: "invalid header with spaces"
        "#,
    )
    .unwrap();
    let err = A2aFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("not a valid HTTP header name"),
        "invalid header name should be rejected: {err}"
    );
}

#[test]
fn task_routing_rejects_zero_ttl() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        task_routing:
          enabled: true
          ttl_seconds: 0
        "#,
    )
    .unwrap();
    let err = A2aFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("ttl_seconds must be greater than 0"),
        "zero TTL should be rejected: {err}"
    );
}

#[test]
fn task_routing_rejects_zero_max_response_body_bytes() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        task_routing:
          enabled: true
          max_response_body_bytes: 0
        "#,
    )
    .unwrap();
    let err = A2aFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string()
            .contains("max_response_body_bytes must be greater than 0"),
        "zero max_response_body_bytes should be rejected: {err}"
    );
}

#[test]
fn task_routing_rejects_non_reserved_route_cluster_header() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        task_routing:
          enabled: true
          route_cluster_header: "x-custom-route"
        "#,
    )
    .unwrap();
    let err = A2aFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("must start with 'x-praxis-a2a-'"),
        "non-reserved route cluster header should be rejected: {err}"
    );
}

#[test]
fn task_routing_allows_zero_terminal_ttl() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        task_routing:
          enabled: true
          terminal_ttl_seconds: 0
        "#,
    )
    .unwrap();
    let filter = A2aFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "a2a", "zero terminal_ttl_seconds should be valid");
}

// -----------------------------------------------------------------------------
// Task Route Lookup Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn task_route_hit_injects_route_cluster_header() {
    let filter = make_task_routing_filter();
    let store = filter.task_route_store.as_ref().unwrap();
    store.put("task-123", "agent-a", std::time::Duration::from_secs(60));

    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"task-123"}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Release), "should release");

    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();

    assert_eq!(
        headers.get("x-praxis-a2a-route-cluster"),
        Some(&"agent-a"),
        "task route hit should inject route cluster header"
    );
}

#[tokio::test]
async fn task_route_miss_continues_without_route_cluster_header() {
    let filter = make_task_routing_filter();

    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"unknown-task"}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Release), "should release");

    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();

    assert!(
        !headers.contains_key("x-praxis-a2a-route-cluster"),
        "task route miss should not inject route cluster header"
    );
}

#[tokio::test]
async fn task_route_hit_records_bounded_route_metadata() {
    let filter = make_task_routing_filter();
    let store = filter.task_route_store.as_ref().unwrap();
    store.put("task-abc", "agent-b", std::time::Duration::from_secs(60));

    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"task-abc"}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    drop(filter.on_request_body(&mut ctx, &mut body, true).await.unwrap());

    assert_eq!(
        ctx.get_metadata("a2a.route_decision"),
        Some("task_route_hit"),
        "route decision metadata should be set"
    );
    assert_eq!(
        ctx.get_metadata("a2a.route_cluster"),
        Some("agent-b"),
        "route cluster metadata should be set"
    );
}

// -----------------------------------------------------------------------------
// Response Body Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn json_response_split_across_chunks_captures_opportunistically() {
    let filter = make_task_routing_filter();
    let store = filter.task_route_store.as_ref().unwrap();
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_response_capture(&mut ctx);

    let json =
        r#"{"jsonrpc":"2.0","id":1,"result":{"task":{"id":"task-split","status":{"state":"TASK_STATE_WORKING"}}}}"#;
    let (chunk1, chunk2) = json.split_at(40);

    let mut body1 = Some(Bytes::from(chunk1.to_owned()));
    drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());
    assert!(
        store.get_by_task_id("task-split").is_none(),
        "incomplete JSON should not capture"
    );

    let mut body2 = Some(Bytes::from(chunk2.to_owned()));
    drop(filter.on_response_body(&mut ctx, &mut body2, false).unwrap());

    assert_eq!(
        store.get_by_task_id("task-split").as_deref(),
        Some("agent-a"),
        "route should be captured as soon as JSON is complete, before EOS"
    );
    assert_capture_scratch_cleared(&ctx);
}

#[tokio::test]
async fn multibyte_char_split_across_chunks_still_captures_route() {
    let filter = make_task_routing_filter();
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_response_capture(&mut ctx);

    // "é" is U+00E9, encoded as [0xC3, 0xA9] in UTF-8.
    // Split the chunk boundary inside that two-byte sequence.
    let json_bytes: Vec<u8> = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"task":{{"id":"task-mb","status":{{"state":"TASK_STATE_WORKING"}},"note":"caf{}"}}}}}}"#,
        "é"
    ).into_bytes();

    let split = json_bytes.iter().position(|&b| b == 0xA9).expect("should contain 0xA9");

    let mut body1 = Some(Bytes::from(json_bytes[..split].to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());

    let mut body2 = Some(Bytes::from(json_bytes[split..].to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body2, true).unwrap());

    assert_eq!(
        store.get_by_task_id("task-mb").as_deref(),
        Some("agent-a"),
        "chunk split inside multibyte UTF-8 character should not prevent route capture"
    );
}

#[tokio::test]
async fn oversized_response_passes_through_without_route_capture() {
    let filter = make_task_routing_filter_with_config(
        r#"{"on_invalid": "continue", "task_routing": {"enabled": true, "max_response_body_bytes": 32}}"#,
    );
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_response_capture(&mut ctx);

    let large_json = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"task":{{"id":"task-big","status":{{"state":"TASK_STATE_WORKING"}}}},"padding":"{}"}}}}"#,
        "x".repeat(64)
    );
    let mut body = Some(Bytes::from(large_json));
    drop(filter.on_response_body(&mut ctx, &mut body, true).unwrap());

    assert!(
        store.get_by_task_id("task-big").is_none(),
        "oversized response should skip route capture"
    );
    assert_capture_scratch_cleared(&ctx);
}

#[tokio::test]
async fn invalid_json_response_body_does_not_error() {
    let filter = make_task_routing_filter();
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_response_capture(&mut ctx);

    let mut body = Some(Bytes::from("not valid json at all"));
    let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();

    assert!(matches!(action, FilterAction::Continue), "should continue");
    assert_eq!(
        body.as_deref(),
        Some(b"not valid json at all".as_slice()),
        "response bytes should not be modified"
    );
    assert!(store.get_by_task_id("anything").is_none(), "no route should be stored");
    assert_capture_scratch_cleared(&ctx);
}

#[tokio::test]
async fn on_response_enables_capture_for_success_non_sse_send_message() {
    let filter = make_task_routing_filter();
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("agent-a"));
    ctx.filter_metadata
        .insert("a2a.method".to_owned(), "SendMessage".to_owned());

    let mut resp = crate::context::Response {
        status: http::StatusCode::OK,
        headers: HeaderMap::new(),
    };
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());
    ctx.response_header = None;

    assert_eq!(
        ctx.get_metadata("a2a.response.capture_enabled"),
        Some("true"),
        "capture enabled"
    );
    assert_eq!(
        ctx.get_metadata("a2a.response.cluster"),
        Some("agent-a"),
        "cluster recorded"
    );
}

#[tokio::test]
async fn sse_response_skips_task_route_capture() {
    let filter = make_task_routing_filter();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("agent-a"));
    ctx.filter_metadata
        .insert("a2a.method".to_owned(), "SendMessage".to_owned());

    let mut resp = crate::context::Response {
        status: http::StatusCode::OK,
        headers: HeaderMap::new(),
    };
    resp.headers
        .insert("content-type", "text/event-stream".parse().unwrap());
    ctx.response_header = Some(&mut resp);

    drop(filter.on_response(&mut ctx).await.unwrap());
    ctx.response_header = None;

    assert_eq!(
        ctx.get_metadata("a2a.response.is_sse"),
        Some("true"),
        "SSE response should be flagged"
    );
    assert!(
        ctx.get_metadata("a2a.response.capture_enabled").is_none(),
        "SSE response should not enable capture"
    );
}

#[tokio::test]
async fn mixed_case_sse_content_type_skips_capture() {
    let filter = make_task_routing_filter();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("agent-a"));
    ctx.filter_metadata
        .insert("a2a.method".to_owned(), "SendMessage".to_owned());

    let mut resp = crate::context::Response {
        status: http::StatusCode::OK,
        headers: HeaderMap::new(),
    };
    resp.headers
        .insert("content-type", "Text/Event-Stream; charset=utf-8".parse().unwrap());
    ctx.response_header = Some(&mut resp);

    drop(filter.on_response(&mut ctx).await.unwrap());
    ctx.response_header = None;

    assert_eq!(
        ctx.get_metadata("a2a.response.is_sse"),
        Some("true"),
        "mixed-case SSE content-type should be detected"
    );
    assert!(
        ctx.get_metadata("a2a.response.capture_enabled").is_none(),
        "mixed-case SSE should not enable capture"
    );
}

// -----------------------------------------------------------------------------
// Task Routable Method Tests
// -----------------------------------------------------------------------------

#[test]
fn task_routable_methods() {
    let routable = [
        A2aMethod::GetTask,
        A2aMethod::CancelTask,
        A2aMethod::SubscribeToTask,
        A2aMethod::CreateTaskPushNotificationConfig,
        A2aMethod::GetTaskPushNotificationConfig,
        A2aMethod::ListTaskPushNotificationConfigs,
        A2aMethod::DeleteTaskPushNotificationConfig,
    ];
    for method in &routable {
        assert!(method.is_task_routable(), "{} should be task-routable", method.as_str());
    }
}

#[test]
fn non_task_routable_methods() {
    let non_routable = [
        A2aMethod::SendMessage,
        A2aMethod::SendStreamingMessage,
        A2aMethod::ListTasks,
        A2aMethod::GetExtendedAgentCard,
        A2aMethod::Unknown("custom".to_owned()),
    ];
    for method in &non_routable {
        assert!(
            !method.is_task_routable(),
            "{} should not be task-routable",
            method.as_str()
        );
    }
}

// -----------------------------------------------------------------------------
// Push Notification Task ID Extraction Tests
// -----------------------------------------------------------------------------

#[test]
fn list_task_push_notification_configs_extracts_task_id() {
    let json = serde_json::json!({
        "jsonrpc": "2.0", "method": "ListTaskPushNotificationConfigs",
        "params": { "taskId": "task-pn-list" }, "id": 1
    });
    let envelope = extract_a2a_envelope(
        &json,
        "ListTaskPushNotificationConfigs",
        &BTreeMap::new(),
        &HeaderMap::new(),
    );
    assert_eq!(
        envelope.task_id,
        Some("task-pn-list".to_owned()),
        "ListTaskPushNotificationConfigs requires params.taskId per A2A spec"
    );
    assert!(
        envelope.method.is_task_routable(),
        "ListTaskPushNotificationConfigs should be task-routable"
    );
}

// -----------------------------------------------------------------------------
// SSE Streaming Capture Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn sse_streaming_response_enables_capture_for_send_streaming_message() {
    let filter = make_task_routing_filter();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("agent-a"));
    ctx.filter_metadata
        .insert("a2a.method".to_owned(), "SendStreamingMessage".to_owned());

    let mut resp = crate::context::Response {
        status: http::StatusCode::OK,
        headers: HeaderMap::new(),
    };
    resp.headers
        .insert("content-type", "text/event-stream".parse().unwrap());
    ctx.response_header = Some(&mut resp);

    drop(filter.on_response(&mut ctx).await.unwrap());
    ctx.response_header = None;

    assert_eq!(
        ctx.get_metadata("a2a.response.sse_capture_enabled"),
        Some("true"),
        "SSE capture should be enabled for SendStreamingMessage"
    );
    assert_eq!(
        ctx.get_metadata("a2a.response.cluster"),
        Some("agent-a"),
        "cluster should be recorded for SSE capture"
    );
    assert!(
        ctx.get_metadata("a2a.response.capture_enabled").is_none(),
        "non-streaming capture should NOT be enabled"
    );
}

#[tokio::test]
async fn sse_streaming_capture_single_frame() {
    let filter = make_task_routing_filter();
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    let sse_data = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"task\":{\"id\":\"task-sse-1\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\n\n";
    let mut body = Some(Bytes::from(sse_data.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());

    assert_eq!(
        store.get_by_task_id("task-sse-1").as_deref(),
        Some("agent-a"),
        "SSE frame should capture task route"
    );
}

#[tokio::test]
async fn sse_streaming_capture_split_across_chunks() {
    let filter = make_task_routing_filter();
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    let full = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"task\":{\"id\":\"task-split\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\n\n";
    let (chunk1, chunk2) = full.split_at(30);

    let mut body1 = Some(Bytes::from(chunk1.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());
    assert!(
        store.get_by_task_id("task-split").is_none(),
        "incomplete SSE should not capture"
    );

    let mut body2 = Some(Bytes::from(chunk2.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body2, false).unwrap());
    assert_eq!(
        store.get_by_task_id("task-split").as_deref(),
        Some("agent-a"),
        "completed SSE frame should capture after second chunk"
    );
}

#[tokio::test]
async fn sse_streaming_capture_line_split_across_chunks() {
    let filter = make_task_routing_filter();
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    // Split in the middle of "data:" field name
    let mut body1 = Some(Bytes::from("da"));
    drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());

    let mut body2 = Some(Bytes::from(
        "ta: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"task\":{\"id\":\"task-line-split\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\n\n",
    ));
    drop(filter.on_response_body(&mut ctx, &mut body2, false).unwrap());

    assert_eq!(
        store.get_by_task_id("task-line-split").as_deref(),
        Some("agent-a"),
        "line split across chunks should still capture"
    );
}

#[tokio::test]
async fn sse_streaming_capture_multiline_data() {
    let filter = make_task_routing_filter();
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    // JSON split across multiple data: lines
    let sse_data = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\n\
                     data: \"result\":{\"task\":{\"id\":\"task-multi\",\n\
                     data: \"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\n\n";
    let mut body = Some(Bytes::from(sse_data.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());

    assert_eq!(
        store.get_by_task_id("task-multi").as_deref(),
        Some("agent-a"),
        "multi-line data should be joined and parsed for task route"
    );
}

#[tokio::test]
async fn sse_streaming_capture_crlf_line_endings() {
    let filter = make_task_routing_filter();
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    let sse_data = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"task\":{\"id\":\"task-crlf\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\r\n\r\n";
    let mut body = Some(Bytes::from(sse_data.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());

    assert_eq!(
        store.get_by_task_id("task-crlf").as_deref(),
        Some("agent-a"),
        "CRLF line endings should work for SSE capture"
    );
}

#[tokio::test]
async fn sse_streaming_capture_ignores_comments_and_unknown_fields() {
    let filter = make_task_routing_filter();
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    let sse_data = b": this is a comment\nevent: task_update\nid: 42\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"task\":{\"id\":\"task-ignore\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\nretry: 5000\n\n";
    let mut body = Some(Bytes::from(sse_data.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());

    assert_eq!(
        store.get_by_task_id("task-ignore").as_deref(),
        Some("agent-a"),
        "comments and unknown fields should be ignored"
    );
}

#[tokio::test]
async fn sse_streaming_capture_invalid_json_does_not_fail() {
    let filter = make_task_routing_filter();
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    let sse_data = b"data: not valid json at all\n\n";
    let mut body = Some(Bytes::from(sse_data.to_vec()));
    let action = filter.on_response_body(&mut ctx, &mut body, false).unwrap();

    assert!(matches!(action, FilterAction::Continue), "invalid JSON should not fail");
    assert!(
        store.get_by_task_id("anything").is_none(),
        "invalid JSON should not create mapping"
    );
    assert_eq!(
        ctx.get_metadata("a2a.response.sse_capture_enabled"),
        Some("true"),
        "capture should remain enabled after invalid JSON"
    );
}

#[tokio::test]
async fn sse_streaming_capture_oversized_scratch_clears_state() {
    let filter = make_task_routing_filter_with_config(
        r#"{"on_invalid": "continue", "task_routing": {"enabled": true, "max_response_body_bytes": 32}}"#,
    );
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    let sse_data = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"task\":{\"id\":\"task-big\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\n\n";
    let mut body = Some(Bytes::from(sse_data.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());

    assert!(
        store.get_by_task_id("task-big").is_none(),
        "oversized SSE scratch should skip capture"
    );
    assert_sse_capture_cleared(&ctx);
}

#[tokio::test]
async fn sse_streaming_capture_terminal_state_uses_terminal_ttl() {
    let filter = make_task_routing_filter_with_config(
        r#"{"on_invalid": "continue", "task_routing": {"enabled": true, "terminal_ttl_seconds": 0}}"#,
    );
    let store = filter.task_route_store.as_ref().unwrap();

    // First, capture a working task
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    let working = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"task\":{\"id\":\"task-term\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\n\n";
    let mut body = Some(Bytes::from(working.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());
    assert!(
        store.get_by_task_id("task-term").is_some(),
        "working task should be stored"
    );

    // Then see a terminal state (terminal_ttl_seconds=0 means remove immediately)
    let completed = b"data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"task\":{\"id\":\"task-term\",\"status\":{\"state\":\"TASK_STATE_COMPLETED\"}}}}\n\n";
    let mut body = Some(Bytes::from(completed.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());
    assert!(
        store.get_by_task_id("task-term").is_none(),
        "terminal task with ttl=0 should be removed"
    );
}

#[tokio::test]
async fn sse_streaming_capture_clears_on_eos() {
    let filter = make_task_routing_filter();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    let mut body: Option<Bytes> = None;
    drop(filter.on_response_body(&mut ctx, &mut body, true).unwrap());

    assert_sse_capture_cleared(&ctx);
}

#[tokio::test]
async fn non_sse_response_does_not_enter_sse_capture_path() {
    let filter = make_task_routing_filter();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("agent-a"));
    ctx.filter_metadata
        .insert("a2a.method".to_owned(), "SendStreamingMessage".to_owned());

    let mut resp = crate::context::Response {
        status: http::StatusCode::OK,
        headers: HeaderMap::new(),
    };
    resp.headers.insert("content-type", "application/json".parse().unwrap());
    ctx.response_header = Some(&mut resp);

    drop(filter.on_response(&mut ctx).await.unwrap());
    ctx.response_header = None;

    assert!(
        ctx.get_metadata("a2a.response.sse_capture_enabled").is_none(),
        "non-SSE response for SendStreamingMessage should not enable SSE capture"
    );
}

#[tokio::test]
async fn wrong_method_does_not_enter_sse_capture() {
    let filter = make_task_routing_filter();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("agent-a"));
    ctx.filter_metadata
        .insert("a2a.method".to_owned(), "GetTask".to_owned());

    let mut resp = crate::context::Response {
        status: http::StatusCode::OK,
        headers: HeaderMap::new(),
    };
    resp.headers
        .insert("content-type", "text/event-stream".parse().unwrap());
    ctx.response_header = Some(&mut resp);

    drop(filter.on_response(&mut ctx).await.unwrap());
    ctx.response_header = None;

    assert!(
        ctx.get_metadata("a2a.response.sse_capture_enabled").is_none(),
        "GetTask with SSE should not enable SSE capture"
    );
}

#[tokio::test]
async fn error_sse_response_does_not_enable_capture() {
    for method in ["SendStreamingMessage", "SubscribeToTask"] {
        let filter = make_task_routing_filter();

        let req = make_a2a_request(&[]);
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some(Arc::from("agent-a"));
        ctx.filter_metadata.insert("a2a.method".to_owned(), method.to_owned());

        let mut resp = crate::context::Response {
            status: http::StatusCode::INTERNAL_SERVER_ERROR,
            headers: HeaderMap::new(),
        };
        resp.headers
            .insert("content-type", "text/event-stream".parse().unwrap());
        ctx.response_header = Some(&mut resp);

        drop(filter.on_response(&mut ctx).await.unwrap());
        ctx.response_header = None;

        assert!(
            ctx.get_metadata("a2a.response.sse_capture_enabled").is_none(),
            "{method} with 500 + text/event-stream should not enable SSE capture"
        );
        assert!(
            ctx.get_metadata("a2a.response.cluster").is_none(),
            "{method} with 500 should not record cluster"
        );
    }
}

#[tokio::test]
async fn sse_streaming_bytes_pass_through_unchanged() {
    let filter = make_task_routing_filter();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    let original = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"task\":{\"id\":\"task-pass\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\n\n";
    let mut body = Some(Bytes::from(original.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());

    assert_eq!(
        body.as_deref(),
        Some(original.as_slice()),
        "SSE response bytes must pass through unchanged"
    );
}

#[tokio::test]
async fn sse_streaming_capture_mixed_case_content_type() {
    let filter = make_task_routing_filter();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("agent-a"));
    ctx.filter_metadata
        .insert("a2a.method".to_owned(), "SendStreamingMessage".to_owned());

    let mut resp = crate::context::Response {
        status: http::StatusCode::OK,
        headers: HeaderMap::new(),
    };
    resp.headers
        .insert("content-type", "Text/Event-Stream; charset=utf-8".parse().unwrap());
    ctx.response_header = Some(&mut resp);

    drop(filter.on_response(&mut ctx).await.unwrap());
    ctx.response_header = None;

    assert_eq!(
        ctx.get_metadata("a2a.response.sse_capture_enabled"),
        Some("true"),
        "mixed-case text/event-stream should enable SSE capture"
    );
}

#[tokio::test]
async fn sse_streaming_capture_direct_result_shape() {
    let filter = make_task_routing_filter();
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    let sse_data =
        b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"id\":\"task-direct\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}\n\n";
    let mut body = Some(Bytes::from(sse_data.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());

    assert_eq!(
        store.get_by_task_id("task-direct").as_deref(),
        Some("agent-a"),
        "direct result shape (result.id + result.status) should also capture from SSE"
    );
}

// -----------------------------------------------------------------------------
// SSE Stream Event Shape Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn sse_streaming_capture_status_update_event() {
    let filter = make_task_routing_filter();
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    let sse_data =
        b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"statusUpdate\":{\"taskId\":\"task-su\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\n\n";
    let mut body = Some(Bytes::from(sse_data.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());

    assert_eq!(
        store.get_by_task_id("task-su").as_deref(),
        Some("agent-a"),
        "statusUpdate event should capture task route"
    );
}

#[tokio::test]
async fn sse_streaming_capture_terminal_status_update() {
    let filter = make_task_routing_filter_with_config(
        r#"{"on_invalid": "continue", "task_routing": {"enabled": true, "terminal_ttl_seconds": 0}}"#,
    );
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    // First event creates the route.
    let working =
        b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"task\":{\"id\":\"task-su-term\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\n\n";
    let mut body = Some(Bytes::from(working.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());
    assert!(
        store.get_by_task_id("task-su-term").is_some(),
        "working task should be stored"
    );

    // Terminal statusUpdate removes it (terminal_ttl_seconds=0).
    let completed =
        b"data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"statusUpdate\":{\"taskId\":\"task-su-term\",\"status\":{\"state\":\"TASK_STATE_COMPLETED\"}}}}\n\n";
    let mut body = Some(Bytes::from(completed.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());
    assert!(
        store.get_by_task_id("task-su-term").is_none(),
        "terminal statusUpdate with ttl=0 should remove the route"
    );
}

#[tokio::test]
async fn sse_streaming_capture_artifact_update_event() {
    let filter = make_task_routing_filter();
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    let sse_data =
        b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"artifactUpdate\":{\"taskId\":\"task-au\",\"contextId\":\"ctx-1\",\"artifact\":{\"artifactId\":\"a1\",\"parts\":[{\"text\":\"chunk\"}]}}}}\n\n";
    let mut body = Some(Bytes::from(sse_data.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());

    assert_eq!(
        store.get_by_task_id("task-au").as_deref(),
        Some("agent-a"),
        "artifactUpdate event should capture task route"
    );
}

// -----------------------------------------------------------------------------
// Overflow Payload Preservation Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn valid_task_before_oversized_sse_frame_stores_route_and_clears_capture() {
    let filter = make_task_routing_filter_with_config(
        r#"{"on_invalid": "continue", "task_routing": {"enabled": true, "max_response_body_bytes": 128}}"#,
    );
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    // First event (~110 bytes) fits within 128-byte limit.
    // Second event (~200+ bytes) overflows.
    let padding = "x".repeat(100);
    let sse = format!(
        "data: {{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"task\":{{\"id\":\"task-pre-overflow\",\"status\":{{\"state\":\"TASK_STATE_WORKING\"}}}}}}}}\n\n\
         data: {{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"task\":{{\"id\":\"task-big\",\"status\":{{\"state\":\"TASK_STATE_WORKING\"}},\"padding\":\"{padding}\"}}}}}}\n\n"
    );
    let sse_data = sse.as_bytes();
    let mut body = Some(Bytes::from(sse_data.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());

    assert_eq!(
        store.get_by_task_id("task-pre-overflow").as_deref(),
        Some("agent-a"),
        "completed event before overflow should still be captured"
    );
    assert_sse_capture_cleared(&ctx);
}

// -----------------------------------------------------------------------------
// SubscribeToTask SSE Capture Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn on_response_enables_capture_for_success_sse_subscribe_to_task() {
    let filter = make_task_routing_filter();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("agent-a"));
    ctx.filter_metadata
        .insert("a2a.method".to_owned(), "SubscribeToTask".to_owned());

    let mut resp = crate::context::Response {
        status: http::StatusCode::OK,
        headers: HeaderMap::new(),
    };
    resp.headers
        .insert("content-type", "text/event-stream".parse().unwrap());
    ctx.response_header = Some(&mut resp);

    drop(filter.on_response(&mut ctx).await.unwrap());
    ctx.response_header = None;

    assert_eq!(
        ctx.get_metadata("a2a.response.sse_capture_enabled"),
        Some("true"),
        "SSE capture should be enabled for SubscribeToTask"
    );
    assert_eq!(
        ctx.get_metadata("a2a.response.cluster"),
        Some("agent-a"),
        "cluster should be recorded for SubscribeToTask SSE capture"
    );
}

#[tokio::test]
async fn subscribe_to_task_sse_status_update_stores_route() {
    let filter = make_task_routing_filter();
    let store = filter.task_route_store.as_ref().unwrap();

    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    seed_sse_capture(&mut ctx);

    let sse_data =
        b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"statusUpdate\":{\"taskId\":\"task-sub-1\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\n\n";
    let mut body = Some(Bytes::from(sse_data.to_vec()));
    drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());

    assert_eq!(
        store.get_by_task_id("task-sub-1").as_deref(),
        Some("agent-a"),
        "SubscribeToTask SSE statusUpdate should capture/refresh task route"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn make_default_filter() -> A2aFilter {
    make_filter("{}")
}

fn make_filter(yaml: &str) -> A2aFilter {
    let cfg: A2aConfig = serde_yaml::from_str(yaml).unwrap();
    let validated_config = build_config(cfg).unwrap();
    let max_body_bytes = validated_config.max_body_bytes;
    let json_rpc_config = super::build_json_rpc_config(max_body_bytes);
    A2aFilter {
        config: validated_config,
        json_rpc_config,
        max_body_bytes,
        task_route_store: None,
    }
}

fn canonical_method_cases() -> Vec<(&'static str, A2aMethod)> {
    vec![
        ("SendMessage", A2aMethod::SendMessage),
        ("SendStreamingMessage", A2aMethod::SendStreamingMessage),
        ("GetTask", A2aMethod::GetTask),
        ("ListTasks", A2aMethod::ListTasks),
        ("CancelTask", A2aMethod::CancelTask),
        ("SubscribeToTask", A2aMethod::SubscribeToTask),
        (
            "CreateTaskPushNotificationConfig",
            A2aMethod::CreateTaskPushNotificationConfig,
        ),
        (
            "GetTaskPushNotificationConfig",
            A2aMethod::GetTaskPushNotificationConfig,
        ),
        (
            "ListTaskPushNotificationConfigs",
            A2aMethod::ListTaskPushNotificationConfigs,
        ),
        (
            "DeleteTaskPushNotificationConfig",
            A2aMethod::DeleteTaskPushNotificationConfig,
        ),
        ("GetExtendedAgentCard", A2aMethod::GetExtendedAgentCard),
    ]
}

fn seed_response_capture(ctx: &mut crate::filter::HttpFilterContext<'_>) {
    ctx.filter_metadata
        .insert("a2a.response.capture_enabled".to_owned(), "true".to_owned());
    ctx.filter_metadata
        .insert("a2a.response.cluster".to_owned(), "agent-a".to_owned());
}

fn assert_capture_scratch_cleared(ctx: &crate::filter::HttpFilterContext<'_>) {
    assert!(
        !ctx.filter_metadata.contains_key("a2a.response.capture_enabled"),
        "capture_enabled not cleared"
    );
    assert!(
        !ctx.filter_metadata.contains_key("a2a.response.buffer_hex"),
        "buffer_hex not cleared"
    );
    assert!(
        !ctx.filter_metadata.contains_key("a2a.response.buffer_bytes"),
        "buffer_bytes not cleared"
    );
    assert!(
        !ctx.filter_metadata.contains_key("a2a.response.cluster"),
        "cluster not cleared"
    );
}

fn make_task_routing_filter() -> A2aFilter {
    make_task_routing_filter_with_config(r#"{"on_invalid": "continue", "task_routing": {"enabled": true}}"#)
}

fn make_task_routing_filter_with_config(yaml: &str) -> A2aFilter {
    let cfg: A2aConfig = serde_yaml::from_str(yaml).unwrap();
    let validated_config = build_config(cfg).unwrap();
    let max_body_bytes = validated_config.max_body_bytes;
    let json_rpc_config = super::build_json_rpc_config(max_body_bytes);
    let task_route_store = if validated_config.task_routing.enabled {
        Some(Arc::new(LocalTaskRouteStore::new()))
    } else {
        None
    };
    A2aFilter {
        config: validated_config,
        json_rpc_config,
        max_body_bytes,
        task_route_store,
    }
}

fn make_a2a_request(extra_headers: &[(&str, &str)]) -> crate::context::Request {
    let mut req = crate::test_utils::make_request(http::Method::POST, "/a2a");
    req.headers.insert("content-type", "application/json".parse().unwrap());
    for (name, value) in extra_headers {
        req.headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    req
}

fn seed_sse_capture(ctx: &mut crate::filter::HttpFilterContext<'_>) {
    ctx.filter_metadata
        .insert("a2a.response.sse_capture_enabled".to_owned(), "true".to_owned());
    ctx.filter_metadata
        .insert("a2a.response.cluster".to_owned(), "agent-a".to_owned());
}

fn assert_sse_capture_cleared(ctx: &crate::filter::HttpFilterContext<'_>) {
    assert!(
        !ctx.filter_metadata.contains_key("a2a.response.sse_capture_enabled"),
        "sse_capture_enabled not cleared"
    );
    assert!(
        !ctx.filter_metadata.contains_key("a2a.response.sse_line_buf_hex"),
        "sse_line_buf_hex not cleared"
    );
    assert!(
        !ctx.filter_metadata.contains_key("a2a.response.sse_data_hex"),
        "sse_data_hex not cleared"
    );
    assert!(
        !ctx.filter_metadata.contains_key("a2a.response.sse_has_data"),
        "sse_has_data not cleared"
    );
    assert!(
        !ctx.filter_metadata.contains_key("a2a.response.sse_prev_cr"),
        "sse_prev_cr not cleared"
    );
    assert!(
        !ctx.filter_metadata.contains_key("a2a.response.sse_scratch_bytes"),
        "sse_scratch_bytes not cleared"
    );
    assert!(
        !ctx.filter_metadata.contains_key("a2a.response.cluster"),
        "cluster not cleared"
    );
}
