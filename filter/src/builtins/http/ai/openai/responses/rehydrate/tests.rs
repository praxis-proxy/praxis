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
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();

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
// MCP Tool Recovery
// -----------------------------------------------------------------------------

#[tokio::test]
async fn extracts_mcp_tools_from_previous_response() {
    let output = json!([
        {"type": "message", "content": [{"type": "output_text", "text": "Hi"}]},
        {
            "id": "mcpl_abc",
            "type": "mcp_list_tools",
            "server_label": "my-server",
            "tools": [
                {"name": "get_weather", "description": "Get weather", "input_schema": {}},
                {"name": "search", "description": "Search docs", "input_schema": {}}
            ]
        }
    ]);
    let usage = json!({"input_tokens": 100, "output_tokens": 50, "total_tokens": 150});
    let store = MockStore::with_output_and_usage("resp_mcp", output, usage);
    let registry = setup_registry(store);

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(
        r#"{"input":"Follow up","previous_response_id":"resp_mcp"}"#,
    ));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release after rehydration"
    );

    let state = ctx
        .extensions
        .get::<ResponsesState>()
        .expect("ResponsesState should be populated");
    assert_eq!(state.previous_tools.len(), 1, "should store full previous tool listing");
    assert_eq!(
        state.previous_tools[0]["server_label"], "my-server",
        "server label should match"
    );
    assert_eq!(
        state.previous_tools[0]["tools"].as_array().unwrap().len(),
        2,
        "should preserve both tools"
    );
    assert_eq!(
        state.previous_tools[0]["tools"][0]["description"], "Get weather",
        "ResponsesState should preserve full tool definitions"
    );
}

#[tokio::test]
async fn no_previous_tools_when_output_has_no_mcp_items() {
    let output = json!([
        {"type": "message", "content": [{"type": "output_text", "text": "Hi"}]}
    ]);
    let usage = json!({"input_tokens": 10, "output_tokens": 5, "total_tokens": 15});
    let store = MockStore::with_output_and_usage("resp_no_mcp", output, usage);
    let registry = setup_registry(store);

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(r#"{"input":"Hi","previous_response_id":"resp_no_mcp"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release after rehydration"
    );
    let state = ctx
        .extensions
        .get::<ResponsesState>()
        .expect("ResponsesState should be populated");
    assert!(
        state.previous_tools.is_empty(),
        "should not store previous tools when no mcp_list_tools items"
    );
}

#[tokio::test]
async fn extracts_mcp_tools_from_multiple_servers() {
    let output = json!([
        {
            "id": "mcpl_1",
            "type": "mcp_list_tools",
            "server_label": "weather-server",
            "tools": [{"name": "get_weather", "description": "d", "input_schema": {}}]
        },
        {"type": "message", "content": [{"type": "output_text", "text": "Hi"}]},
        {
            "id": "mcpl_2",
            "type": "mcp_list_tools",
            "server_label": "search-server",
            "tools": [
                {"name": "search", "description": "d", "input_schema": {}},
                {"name": "index", "description": "d", "input_schema": {}}
            ]
        }
    ]);
    let store = MockStore::with_output_and_usage("resp_multi", output, Value::Null);
    let registry = setup_registry(store);

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(r#"{"input":"Hi","previous_response_id":"resp_multi"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release after rehydration"
    );

    let state = ctx
        .extensions
        .get::<ResponsesState>()
        .expect("ResponsesState should be populated");
    assert_eq!(state.previous_tools.len(), 2, "should have two server entries");
    assert_eq!(
        state.previous_tools[0]["server_label"], "weather-server",
        "first server label"
    );
    assert_eq!(
        state.previous_tools[1]["server_label"], "search-server",
        "second server label"
    );
    assert_eq!(
        state.previous_tools[1]["tools"].as_array().unwrap().len(),
        2,
        "second server should have two tools"
    );
}

#[tokio::test]
async fn deduplicates_mcp_tools_independent_of_tool_order() {
    let mut records = std::collections::HashMap::new();
    records.insert(
        "resp_dedupe".to_owned(),
        ResponseRecord {
            id: "resp_dedupe".to_owned(),
            tenant_id: "default".to_owned(),
            created_at: 1000,
            model: "gpt-4.1".to_owned(),
            response_object: json!({
                "id": "resp_dedupe",
                "status": "completed",
                "output": [{
                    "id": "mcpl_output",
                    "type": "mcp_list_tools",
                    "server_label": "shared-server",
                    "tools": [
                        {"name": "beta", "description": "d", "input_schema": {}},
                        {"name": "alpha", "description": "d", "input_schema": {}}
                    ]
                }]
            }),
            input: json!("Hello"),
            messages: json!([
                {
                    "id": "mcpl_history",
                    "type": "mcp_list_tools",
                    "server_label": "shared-server",
                    "tools": [
                        {"name": "alpha", "description": "d", "input_schema": {}},
                        {"name": "beta", "description": "d", "input_schema": {}}
                    ]
                }
            ]),
        },
    );
    let store = MockStore {
        records,
        should_fail: false,
    };
    let registry = setup_registry(store);

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(r#"{"input":"Next","previous_response_id":"resp_dedupe"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release after rehydration"
    );

    let state = ctx
        .extensions
        .get::<ResponsesState>()
        .expect("ResponsesState should be populated");
    assert_eq!(
        state.previous_tools.len(),
        1,
        "ResponsesState should not retain duplicate MCP listings"
    );
}

#[tokio::test]
async fn extracts_mcp_tools_from_stored_history_when_latest_output_has_none() {
    let mut records = std::collections::HashMap::new();
    records.insert(
        "resp_chain".to_owned(),
        ResponseRecord {
            id: "resp_chain".to_owned(),
            tenant_id: "default".to_owned(),
            created_at: 1000,
            model: "gpt-4.1".to_owned(),
            response_object: json!({
                "id": "resp_chain",
                "status": "completed",
                "output": [
                    {"type": "message", "content": [{"type": "output_text", "text": "Latest turn"}]}
                ]
            }),
            input: json!("Second turn"),
            messages: json!([
                {"type": "message", "role": "user", "content": "First turn"},
                {
                    "id": "mcpl_earlier",
                    "type": "mcp_list_tools",
                    "server_label": "weather-server",
                    "tools": [{"name": "get_weather", "description": "d", "input_schema": {}}]
                },
                {"type": "message", "role": "assistant", "content": "Latest turn"}
            ]),
        },
    );
    let store = MockStore {
        records,
        should_fail: false,
    };
    let registry = setup_registry(store);

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(
        r#"{"input":"Third turn","previous_response_id":"resp_chain"}"#,
    ));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release after chained rehydration"
    );

    let state = ctx
        .extensions
        .get::<ResponsesState>()
        .expect("ResponsesState should be populated");
    assert_eq!(state.previous_tools.len(), 1, "should recover one earlier server entry");
    assert_eq!(
        state.previous_tools[0]["server_label"], "weather-server",
        "server label should match"
    );
    let tools = state.previous_tools[0]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1, "should recover one earlier tool");
    assert_eq!(tools[0]["name"], "get_weather", "tool name should match");
    assert!(
        state
            .messages
            .iter()
            .all(|item| item.get("type").and_then(Value::as_str) != Some("mcp_list_tools")),
        "stored MCP list items should not be replayed as request input"
    );
    assert_eq!(
        state.persisted_messages.len(),
        4,
        "persistence history should keep stored MCP metadata plus current input"
    );
    assert_eq!(
        state.persisted_messages[1]["type"], "mcp_list_tools",
        "persistence history should preserve stored MCP metadata"
    );
}

#[tokio::test]
async fn large_mcp_tool_listing_is_preserved_in_state() {
    let many_tools: Vec<Value> = (0..30)
        .map(|i| json!({"name": format!("very_long_tool_name_number_{i}"), "description": "d", "input_schema": {}}))
        .collect();
    let output = json!([{
        "id": "mcpl_big",
        "type": "mcp_list_tools",
        "server_label": "big-server",
        "tools": many_tools,
    }]);
    let store = MockStore::with_output_and_usage("resp_big", output, Value::Null);
    let registry = setup_registry(store);

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(r#"{"input":"Hi","previous_response_id":"resp_big"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release after rehydration"
    );
    let state = ctx
        .extensions
        .get::<ResponsesState>()
        .expect("ResponsesState should be populated");
    assert_eq!(
        state.previous_tools.len(),
        1,
        "large listing should not drop previous tools from state"
    );
    assert_eq!(
        state.previous_tools[0]["tools"].as_array().unwrap().len(),
        30,
        "large listing should preserve every tool definition"
    );
}

// -----------------------------------------------------------------------------
// Usage Extraction
// -----------------------------------------------------------------------------

#[tokio::test]
async fn extracts_usage_from_previous_response() {
    let output = json!([{"type": "message", "content": [{"type": "output_text", "text": "Hi"}]}]);
    let usage = json!({"input_tokens": 500, "output_tokens": 200, "total_tokens": 700});
    let store = MockStore::with_output_and_usage("resp_usage", output, usage.clone());
    let registry = setup_registry(store);

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(r#"{"input":"Hi","previous_response_id":"resp_usage"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release after rehydration"
    );
    assert_eq!(
        ctx.get_metadata("responses.previous_usage_input_tokens"),
        Some("500"),
        "input tokens"
    );
    assert_eq!(
        ctx.get_metadata("responses.previous_usage_output_tokens"),
        Some("200"),
        "output tokens"
    );
    assert_eq!(
        ctx.get_metadata("responses.previous_usage_total_tokens"),
        Some("700"),
        "total tokens"
    );

    let state = ctx
        .extensions
        .get::<ResponsesState>()
        .expect("ResponsesState should be populated");
    assert_eq!(
        state.previous_usage.as_ref(),
        Some(&usage),
        "previous usage should be stored in ResponsesState"
    );
}

#[tokio::test]
async fn no_usage_metadata_when_usage_missing() {
    let output = json!([{"type": "message", "content": [{"type": "output_text", "text": "Hi"}]}]);
    let store = MockStore::with_output_and_usage("resp_no_usage", output, Value::Null);
    let registry = setup_registry(store);

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(r#"{"input":"Hi","previous_response_id":"resp_no_usage"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release after rehydration"
    );
    assert!(
        ctx.get_metadata("responses.previous_usage_input_tokens").is_none(),
        "should not set input tokens"
    );
    assert!(
        ctx.get_metadata("responses.previous_usage_output_tokens").is_none(),
        "should not set output tokens"
    );
    assert!(
        ctx.get_metadata("responses.previous_usage_total_tokens").is_none(),
        "should not set total tokens"
    );

    let state = ctx
        .extensions
        .get::<ResponsesState>()
        .expect("ResponsesState should be populated");
    assert!(
        state.previous_usage.is_none(),
        "missing usage should not populate previous_usage"
    );
}

#[tokio::test]
async fn extracts_partial_usage_fields() {
    let output = json!([{"type": "message", "content": [{"type": "output_text", "text": "Hi"}]}]);
    let usage = json!({"input_tokens": 42});
    let store = MockStore::with_output_and_usage("resp_partial", output, usage);
    let registry = setup_registry(store);

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(r#"{"input":"Hi","previous_response_id":"resp_partial"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release after rehydration"
    );
    assert_eq!(
        ctx.get_metadata("responses.previous_usage_input_tokens"),
        Some("42"),
        "should set input tokens"
    );
    assert!(
        ctx.get_metadata("responses.previous_usage_output_tokens").is_none(),
        "should not set output tokens when missing"
    );
    assert!(
        ctx.get_metadata("responses.previous_usage_total_tokens").is_none(),
        "should not set total tokens when missing"
    );
}

// -----------------------------------------------------------------------------
// Fallback + MCP
// -----------------------------------------------------------------------------

#[tokio::test]
async fn fallback_reconstruction_excludes_mcp_list_tools_but_preserves_outputs() {
    let mut records = std::collections::HashMap::new();
    records.insert(
        "resp_mcp_fb".to_owned(),
        ResponseRecord {
            id: "resp_mcp_fb".to_owned(),
            tenant_id: "default".to_owned(),
            created_at: 1000,
            model: "gpt-4.1".to_owned(),
            response_object: json!({
                "id": "resp_mcp_fb",
                "status": "completed",
                "output": [
                    {
                        "id": "mcpl_fb",
                        "type": "mcp_list_tools",
                        "server_label": "fb-server",
                        "tools": [{"name": "fb_tool", "description": "d", "input_schema": {}}]
                    },
                    {"id": "ws_fb", "type": "web_search_call", "status": "completed"},
                    {"type": "message", "content": [{"type": "output_text", "text": "result"}]}
                ]
            }),
            input: json!("Hello"),
            messages: json!([]),
        },
    );
    let store = MockStore {
        records,
        should_fail: false,
    };
    let registry = setup_registry(store);

    let filter = RehydrateFilter;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extensions.insert(registry.clone());
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from(r#"{"input":"Next","previous_response_id":"resp_mcp_fb"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release after fallback rehydration"
    );

    let state = ctx
        .extensions
        .get::<ResponsesState>()
        .expect("ResponsesState should be populated");
    assert_eq!(
        state.messages.len(),
        4,
        "fallback should reconstruct previous replay items before current input"
    );
    assert_eq!(state.messages[0]["content"], "Hello", "previous input should be first");
    assert!(
        state
            .messages
            .iter()
            .all(|item| item.get("type").and_then(Value::as_str) != Some("mcp_list_tools")),
        "fallback should not replay output-only MCP list items as request input"
    );
    assert_eq!(
        state.messages[1]["type"], "web_search_call",
        "non-MCP previous output should be preserved"
    );
    assert_eq!(
        state.messages[2]["type"], "message",
        "previous message output should follow"
    );
    assert_eq!(state.messages[3]["content"], "Next", "current input should be last");
    assert_eq!(
        state.persisted_messages.len(),
        5,
        "persistence history should keep previous input, all output items, and current input"
    );
    assert_eq!(
        state.persisted_messages[1]["type"], "mcp_list_tools",
        "fallback persistence history should preserve MCP list metadata"
    );
    assert_eq!(state.previous_tools.len(), 1, "fallback should populate previous tools");
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

    fn with_output_and_usage(id: &str, output: Value, usage: Value) -> Self {
        let mut records = std::collections::HashMap::new();
        let mut response_object = json!({
            "id": id,
            "status": "completed",
            "output": output,
        });
        if !usage.is_null() {
            response_object
                .as_object_mut()
                .expect("response_object should be an object")
                .insert("usage".to_owned(), usage);
        }
        records.insert(
            id.to_owned(),
            ResponseRecord {
                id: id.to_owned(),
                tenant_id: "default".to_owned(),
                created_at: 1000,
                model: "gpt-4.1".to_owned(),
                response_object,
                input: json!("Hello"),
                messages: json!([
                    {"role": "user", "content": "Hello"},
                    {"role": "assistant", "content": "Hi"}
                ]),
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

    async fn get_conversation(
        &self,
        _tenant_id: &str,
        _conversation_id: &str,
    ) -> Result<Option<ConversationRecord>, StoreError> {
        Ok(None)
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
