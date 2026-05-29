// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Unit tests for the A2A classifier filter.

use std::collections::BTreeMap;

use bytes::Bytes;
use http::HeaderMap;

use super::{
    A2aFilter,
    config::{A2aConfig, build_config},
    envelope::{A2aFamily, A2aMethod, extract_a2a_envelope},
};
use crate::{FilterAction, filter::HttpFilter};

// -----------------------------------------------------------------------------
// Config Tests
// -----------------------------------------------------------------------------

#[test]
fn parse_minimal_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let filter = A2aFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "a2a");
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
    assert_eq!(filter.name(), "a2a");
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
    assert_eq!(A2aMethod::SendMessage.family(), A2aFamily::Message);
    assert_eq!(A2aMethod::SendStreamingMessage.family(), A2aFamily::Message);
    assert_eq!(A2aMethod::GetTask.family(), A2aFamily::Task);
    assert_eq!(A2aMethod::ListTasks.family(), A2aFamily::Task);
    assert_eq!(A2aMethod::CancelTask.family(), A2aFamily::Task);
    assert_eq!(A2aMethod::SubscribeToTask.family(), A2aFamily::Task);
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

    assert_eq!(envelope.method, A2aMethod::SendMessage);
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

    assert!(matches!(action, FilterAction::Release));
    assert_eq!(ctx.get_metadata("a2a.streaming"), Some("true"));
    assert_eq!(ctx.get_metadata("a2a.family"), Some("message"));
}

#[tokio::test]
async fn get_task_extracts_task_id() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"task-999"}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release));
    assert_eq!(ctx.get_metadata("a2a.method"), Some("GetTask"));
    assert_eq!(ctx.get_metadata("a2a.family"), Some("task"));
    assert_eq!(ctx.get_metadata("a2a.task_id"), Some("task-999"));
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

    assert!(matches!(action, FilterAction::Release));
    assert_eq!(ctx.get_metadata("a2a.family"), Some("push_notification"));
    assert_eq!(ctx.get_metadata("a2a.task_id"), Some("task-abc"));
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
    assert_eq!(ctx.get_metadata("a2a.method"), Some("CustomUnknown"));
    assert_eq!(ctx.get_metadata("a2a.family"), Some("unknown"));
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

    assert!(matches!(action, FilterAction::Release));
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

    // A2A routing is a single classification decision per HTTP request. A
    // batch can contain mixed methods, task IDs, and streaming semantics, so
    // reject it even when invalid non-A2A requests otherwise pass through.
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Reject(_)),
        "batch should be rejected regardless of on_invalid"
    );
}

#[tokio::test]
async fn on_request_is_noop() {
    let filter = make_default_filter();
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();

    assert!(matches!(action, FilterAction::Continue));
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

    assert!(matches!(action, FilterAction::Release));

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

    assert!(matches!(action, FilterAction::Release));

    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();

    assert_eq!(headers.get("x-praxis-a2a-method"), Some(&"SendStreamingMessage"));
    assert_eq!(headers.get("x-praxis-a2a-family"), Some(&"message"));
}

#[tokio::test]
async fn promotes_kind_and_streaming_headers() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"SendStreamingMessage","params":{}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release));

    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();

    assert_eq!(headers.get("x-praxis-a2a-kind"), Some(&"request"));
    assert_eq!(headers.get("x-praxis-a2a-streaming"), Some(&"true"));
}

#[tokio::test]
async fn notification_sets_kind() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","method":"SendMessage","params":{}}"#;
    let req = make_a2a_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release));
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

    assert!(matches!(action, FilterAction::Release));

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

    assert!(matches!(action, FilterAction::Release));

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

    assert!(matches!(action, FilterAction::Release));
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

    assert!(matches!(action, FilterAction::Release));
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

    assert!(matches!(action, FilterAction::Release));
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

    assert!(matches!(action, FilterAction::Release));
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
// Test Utilities
// -----------------------------------------------------------------------------

fn make_default_filter() -> A2aFilter {
    make_filter("{}")
}

fn make_filter(yaml: &str) -> A2aFilter {
    let cfg: A2aConfig = serde_yaml::from_str(yaml).unwrap();
    let validated_config = build_config(cfg).unwrap();
    let json_rpc_config = super::build_json_rpc_config(validated_config.max_body_bytes);
    A2aFilter {
        max_body_bytes: validated_config.max_body_bytes,
        config: validated_config,
        json_rpc_config,
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
