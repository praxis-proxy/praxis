// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

use std::sync::Arc;

use bytes::Bytes;
use serde_json::json;

use super::*;
use crate::{
    FilterAction, FilterEntry, FilterPipeline, FilterRegistry,
    builtins::http::ai::store::{
        ConversationRecord, ResponseRecord, ResponseStore, ResponseStoreRegistry, SqliteResponseStore, StoreError,
    },
};

// -----------------------------------------------------------------------------
// from_config
// -----------------------------------------------------------------------------

#[test]
fn from_config_succeeds() {
    let filter = RehydrateFilter::from_config(&serde_yaml::Value::Null).unwrap();
    assert_eq!(
        filter.name(),
        "openai_responses_rehydrate",
        "filter name should match convention"
    );
}

#[test]
fn unknown_field_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("unexpected: true").unwrap();
    let result = RehydrateFilter::from_config(&yaml);
    assert!(
        result.is_err(),
        "unknown fields should be rejected by deny_unknown_fields"
    );
}

#[test]
fn body_access_is_read_only() {
    let filter = RehydrateFilter;
    assert_eq!(
        filter.request_body_access(),
        BodyAccess::ReadOnly,
        "filter should use read-only body access"
    );
}

// -----------------------------------------------------------------------------
// Bypass
// -----------------------------------------------------------------------------

#[tokio::test]
async fn skips_non_post_request() {
    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::GET, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(r#"{"input":"test"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "non-POST should continue");
}

#[tokio::test]
async fn skips_non_responses_format() {
    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat/completions");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_chat_completions");
    let mut body = Some(Bytes::from(r#"{"messages":[]}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "non-responses format should release"
    );
}

#[tokio::test]
async fn continues_on_non_end_of_stream() {
    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(r#"{"input":"partial"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "non-end-of-stream should continue"
    );
}

#[tokio::test]
async fn skips_cancel_request_without_parsing_empty_body() {
    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses/resp_123/cancel");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::new());

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "cancel request should bypass rehydrate even with an empty stream-buffer body"
    );
    assert_eq!(body.as_ref().unwrap().len(), 0, "empty body should stay unchanged");
    assert!(
        ctx.extensions.get::<ResponsesState>().is_none(),
        "ResponsesState should not be set for cancel requests"
    );
}

// -----------------------------------------------------------------------------
// Passthrough
// -----------------------------------------------------------------------------

#[tokio::test]
async fn passthrough_when_no_previous_response_id() {
    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let original = r#"{"model":"gpt-4.1","input":"Hello"}"#;
    let mut body = Some(Bytes::from(original));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release when no previous_response_id"
    );
    assert_eq!(
        body.as_ref().unwrap().as_ref(),
        original.as_bytes(),
        "body should be unchanged"
    );
    assert!(
        ctx.extensions.get::<ResponsesState>().is_none(),
        "ResponsesState should not be set without previous_response_id"
    );
}

#[tokio::test]
async fn passthrough_when_previous_response_id_is_null() {
    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(
        r#"{"model":"gpt-4.1","input":"Hello","previous_response_id":null}"#,
    ));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release when previous_response_id is null"
    );
}

// -----------------------------------------------------------------------------
// Validation + Metadata
// -----------------------------------------------------------------------------

#[tokio::test]
async fn validates_previous_response_and_sets_metadata() {
    let messages = json!([
        {"role": "user", "content": "Hello"},
        {"role": "assistant", "content": "Hi there"}
    ]);
    let store = MockStore::with_completed_response("resp_prev", json!("Hello"), messages);
    let registry = setup_registry(store);

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let original = r#"{"model":"gpt-4.1","input":"What next?","previous_response_id":"resp_prev"}"#;
    let mut body = Some(Bytes::from(original));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release after validation"
    );

    assert_eq!(
        body.as_ref().unwrap().as_ref(),
        original.as_bytes(),
        "body should not be modified"
    );
    assert_eq!(
        ctx.get_metadata("responses.previous_response_id"),
        Some("resp_prev"),
        "should set previous_response_id metadata"
    );

    let state = ctx
        .extensions
        .get::<ResponsesState>()
        .expect("ResponsesState should be populated");
    assert_eq!(
        state.messages.len(),
        3,
        "messages should contain 2 stored + 1 current input"
    );
    assert_eq!(state.messages[0]["role"], "user", "first stored message");
    assert_eq!(state.messages[1]["role"], "assistant", "second stored message");
    assert_eq!(
        state.messages[2]["content"], "What next?",
        "current input should be last"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_validates_during_cold_request_body_pre_read() {
    let (db_url, db_path) = temp_sqlite_url("rehydrate_cold_pre_read");
    let seeded_store = SqliteResponseStore::new(&db_url, "test_responses", "test_conversations", None)
        .await
        .unwrap();
    seeded_store
        .upsert_response(&ResponseRecord {
            id: "resp_prev".to_owned(),
            tenant_id: "default".to_owned(),
            created_at: 1000,
            model: "gpt-4.1".to_owned(),
            response_object: json!({
                "id": "resp_prev",
                "status": "completed",
                "output": [{"type": "message", "role": "assistant", "content": "Hi"}]
            }),
            input: json!("Hello"),
            messages: json!([
                {"type": "message", "role": "user", "content": "Hello"},
                {"type": "message", "role": "assistant", "content": "Hi"}
            ]),
        })
        .await
        .unwrap();
    drop(seeded_store);

    let mut entries: Vec<FilterEntry> = serde_yaml::from_str(&format!(
        r#"
- filter: openai_responses_format
- filter: openai_response_store
  backend: sqlite
  database_url: "{db_url}"
  responses_table: test_responses
  conversations_table: test_conversations
- filter: openai_responses_rehydrate
"#
    ))
    .unwrap();
    let registry = FilterRegistry::with_builtins();
    let mut pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    pipeline.set_response_stores(ResponseStoreRegistry::new());

    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    if let Some(stores) = pipeline.response_stores() {
        ctx.extensions.insert(stores.clone());
    }

    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

    let original = r#"{"model":"gpt-4.1","input":"What next?","previous_response_id":"resp_prev"}"#;
    let mut body = Some(Bytes::from(original));

    let action = pipeline
        .execute_http_request_body(&mut ctx, &mut body, true)
        .await
        .unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "on_request should register store so rehydrate finds it in on_request_body"
    );

    assert_eq!(
        body.as_ref().unwrap().as_ref(),
        original.as_bytes(),
        "body should not be modified by rehydrate filter"
    );
    assert_eq!(
        ctx.get_metadata("responses.previous_response_id"),
        Some("resp_prev"),
        "previous_response_id should be promoted to metadata"
    );

    let state = ctx
        .extensions
        .get::<ResponsesState>()
        .expect("ResponsesState should be populated in pipeline");
    assert_eq!(
        state.messages.len(),
        3,
        "messages should contain 2 stored + 1 current input"
    );
    assert_eq!(state.messages[0]["role"], "user", "first stored message");
    assert_eq!(state.messages[1]["role"], "assistant", "second stored message");
    assert_eq!(
        state.messages[2]["content"], "What next?",
        "current input should be last"
    );

    drop(pipeline);
    cleanup_sqlite_file(&db_path);
}

// -----------------------------------------------------------------------------
// Rejections
// -----------------------------------------------------------------------------

#[tokio::test]
async fn rejects_when_previous_response_not_found() {
    let store = MockStore::empty();
    let registry = setup_registry(store);

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(r#"{"input":"Hi","previous_response_id":"resp_missing"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    match action {
        FilterAction::Reject(r) => assert_eq!(r.status, 400, "should reject with 400"),
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_when_status_not_completed() {
    let store = MockStore::with_status("resp_123", "in_progress");
    let registry = setup_registry(store);

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(r#"{"input":"Hi","previous_response_id":"resp_123"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    match action {
        FilterAction::Reject(r) => assert_eq!(r.status, 400, "should reject non-completed status"),
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_when_status_incomplete() {
    let store = MockStore::with_status("resp_123", "incomplete");
    let registry = setup_registry(store);

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(r#"{"input":"Hi","previous_response_id":"resp_123"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    match action {
        FilterAction::Reject(r) => assert_eq!(r.status, 400, "should reject incomplete status"),
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_when_status_failed() {
    let store = MockStore::with_status("resp_123", "failed");
    let registry = setup_registry(store);

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(r#"{"input":"Hi","previous_response_id":"resp_123"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    match action {
        FilterAction::Reject(r) => assert_eq!(r.status, 400, "should reject failed status"),
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_when_store_unavailable() {
    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(r#"{"input":"Hi","previous_response_id":"resp_123"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    match action {
        FilterAction::Reject(r) => assert_eq!(r.status, 500, "should reject with 500 when store unavailable"),
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_when_store_not_registered() {
    let registry = ResponseStoreRegistry::new();

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(r#"{"input":"Hi","previous_response_id":"resp_123"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    match action {
        FilterAction::Reject(r) => assert_eq!(r.status, 500, "should reject with 500 when store not registered"),
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_invalid_json_body() {
    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from("not json"));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    match action {
        FilterAction::Reject(r) => assert_eq!(r.status, 400, "should reject invalid JSON"),
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_non_string_previous_response_id() {
    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(r#"{"input":"Hi","previous_response_id":123}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    match action {
        FilterAction::Reject(r) => assert_eq!(r.status, 400, "should reject non-string previous_response_id"),
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_when_store_fetch_fails() {
    let store = MockStore::failing();
    let registry = setup_registry(store);

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(r#"{"input":"Hi","previous_response_id":"resp_123"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    match action {
        FilterAction::Reject(r) => assert_eq!(r.status, 500, "should reject with 500 on store error"),
        other => panic!("expected Reject, got {other:?}"),
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

struct MockStore {
    records: std::collections::HashMap<String, ResponseRecord>,
    should_fail: bool,
}

impl MockStore {
    fn with_completed_response(id: &str, input: Value, messages: Value) -> Self {
        let mut records = std::collections::HashMap::new();
        records.insert(
            id.to_owned(),
            ResponseRecord {
                id: id.to_owned(),
                tenant_id: "default".to_owned(),
                created_at: 1000,
                model: "gpt-4.1".to_owned(),
                response_object: json!({
                    "id": id,
                    "status": "completed",
                    "output": [{"type": "message", "content": [{"type": "output_text", "text": "Hi"}]}]
                }),
                input,
                messages,
            },
        );
        Self {
            records,
            should_fail: false,
        }
    }

    fn with_status(id: &str, status: &str) -> Self {
        let mut records = std::collections::HashMap::new();
        records.insert(
            id.to_owned(),
            ResponseRecord {
                id: id.to_owned(),
                tenant_id: "default".to_owned(),
                created_at: 1000,
                model: "gpt-4.1".to_owned(),
                response_object: json!({"id": id, "status": status}),
                input: json!("Hello"),
                messages: json!([]),
            },
        );
        Self {
            records,
            should_fail: false,
        }
    }

    fn empty() -> Self {
        Self {
            records: std::collections::HashMap::new(),
            should_fail: false,
        }
    }

    fn failing() -> Self {
        Self {
            records: std::collections::HashMap::new(),
            should_fail: true,
        }
    }
}

#[async_trait::async_trait]
impl ResponseStore for MockStore {
    async fn upsert_response(&self, _record: &ResponseRecord) -> Result<(), StoreError> {
        Ok(())
    }

    async fn get_response(&self, _tenant_id: &str, id: &str) -> Result<Option<ResponseRecord>, StoreError> {
        if self.should_fail {
            return Err(StoreError::Unavailable("mock failure".to_owned()));
        }
        Ok(self.records.get(id).cloned())
    }

    async fn delete_response(&self, _tenant_id: &str, _id: &str) -> Result<bool, StoreError> {
        Ok(false)
    }

    async fn upsert_conversation(&self, _record: &ConversationRecord) -> Result<(), StoreError> {
        Ok(())
    }

    async fn get_conversation(
        &self,
        _tenant_id: &str,
        _conversation_id: &str,
    ) -> Result<Option<ConversationRecord>, StoreError> {
        Ok(None)
    }

    async fn delete_conversation(&self, _tenant_id: &str, _conversation_id: &str) -> Result<bool, StoreError> {
        Ok(false)
    }
}

fn setup_registry(store: MockStore) -> ResponseStoreRegistry {
    let registry = ResponseStoreRegistry::new();
    let name: Arc<str> = Arc::from("default");
    registry.register(&name, Arc::new(store)).unwrap();
    registry
}

fn temp_sqlite_url(test_name: &str) -> (String, std::path::PathBuf) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let db_path = std::env::temp_dir().join(format!("praxis_{test_name}_{}_{}.db", std::process::id(), nanos));
    (format!("sqlite://{}?mode=rwc", db_path.display()), db_path)
}

fn cleanup_sqlite_file(db_path: &std::path::Path) {
    drop(std::fs::remove_file(db_path));
    drop(std::fs::remove_file(format!("{}-shm", db_path.display())));
    drop(std::fs::remove_file(format!("{}-wal", db_path.display())));
}
