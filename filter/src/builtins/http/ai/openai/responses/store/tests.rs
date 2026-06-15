// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Unit tests for the `openai_response_store` filter.

use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use serde_json::json;

use super::{
    ResponseStoreFilter,
    config::{ResponseStoreConfig, validate_config},
};
use crate::{
    FilterAction, FilterEntry, FilterPipeline, FilterRegistry,
    body::{BodyAccess, BodyMode},
    builtins::http::ai::store::{ResponseStore, SqliteResponseStore},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// from_config
// -----------------------------------------------------------------------------

#[test]
fn valid_config_parses() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
backend: sqlite
database_url: "sqlite::memory:"
responses_table: responses
conversations_table: conversations
"#,
    )
    .unwrap();
    let filter = ResponseStoreFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "openai_response_store",
        "filter should parse successfully"
    );
}

#[test]
fn empty_database_url_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
backend: sqlite
database_url: ""
responses_table: responses
conversations_table: conversations
"#,
    )
    .unwrap();
    let result = ResponseStoreFilter::from_config(&yaml);
    assert!(result.is_err(), "empty database_url should be rejected");
}

#[test]
fn database_url_path_traversal_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
backend: sqlite
database_url: "sqlite://../responses.db?mode=rwc"
responses_table: responses
conversations_table: conversations
"#,
    )
    .unwrap();
    let result = ResponseStoreFilter::from_config(&yaml);
    assert!(result.is_err(), "database_url with .. traversal should be rejected");
}

#[test]
fn database_url_encoded_path_traversal_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
backend: sqlite
database_url: "sqlite://data/%2e%2e/responses.db?mode=rwc"
responses_table: responses
conversations_table: conversations
"#,
    )
    .unwrap();
    let result = ResponseStoreFilter::from_config(&yaml);
    assert!(
        result.is_err(),
        "database_url with percent-encoded .. traversal should be rejected"
    );
}

#[test]
fn missing_backend_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
database_url: "sqlite::memory:"
responses_table: responses
conversations_table: conversations
"#,
    )
    .unwrap();
    let result = ResponseStoreFilter::from_config(&yaml);
    assert!(result.is_err(), "missing backend should be rejected");
}

#[test]
fn invalid_responses_table_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
backend: sqlite
database_url: "sqlite::memory:"
responses_table: bad-name
conversations_table: conversations
"#,
    )
    .unwrap();
    let result = ResponseStoreFilter::from_config(&yaml);
    assert!(result.is_err(), "invalid responses_table should be rejected");
}

#[test]
fn invalid_conversations_table_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
backend: sqlite
database_url: "sqlite::memory:"
responses_table: responses
conversations_table: bad-name
"#,
    )
    .unwrap();
    let result = ResponseStoreFilter::from_config(&yaml);
    assert!(result.is_err(), "invalid conversations_table should be rejected");
}

#[test]
fn duplicate_table_names_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
backend: sqlite
database_url: "sqlite::memory:"
responses_table: same_table
conversations_table: same_table
"#,
    )
    .unwrap();
    let result = ResponseStoreFilter::from_config(&yaml);
    assert!(result.is_err(), "duplicate table names should be rejected");
}

#[test]
fn duplicate_table_names_rejected_case_insensitively() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
backend: sqlite
database_url: "sqlite::memory:"
responses_table: Responses
conversations_table: responses
"#,
    )
    .unwrap();
    let result = ResponseStoreFilter::from_config(&yaml);
    assert!(
        result.is_err(),
        "case-insensitive duplicate table names should be rejected"
    );
}

#[test]
fn unknown_field_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
backend: sqlite
database_url: "sqlite::memory:"
responses_table: responses
conversations_table: conversations
unknown_extra_field: true
"#,
    )
    .unwrap();
    let result = ResponseStoreFilter::from_config(&yaml);
    assert!(
        result.is_err(),
        "unknown field should be rejected by deny_unknown_fields"
    );
}

// -----------------------------------------------------------------------------
// Filter Trait Declarations
// -----------------------------------------------------------------------------

#[test]
fn name_returns_openai_response_store() {
    let filter = make_filter();
    assert_eq!(
        filter.name(),
        "openai_response_store",
        "name should be openai_response_store"
    );
}

#[test]
fn response_body_access_is_read_only() {
    let filter = make_filter();
    assert_eq!(
        filter.response_body_access(),
        BodyAccess::ReadOnly,
        "response body access should be ReadOnly"
    );
}

#[test]
fn response_body_mode_is_bounded_stream_buffer() {
    let filter = make_filter();
    assert_eq!(
        filter.response_body_mode(),
        BodyMode::StreamBuffer {
            max_bytes: Some(67_108_864) // 64 MiB
        },
        "response body mode should be StreamBuffer capped at 64 MiB"
    );
}

// -----------------------------------------------------------------------------
// on_request Bypass
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_request_skips_when_format_metadata_absent() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should skip when format metadata is absent"
    );
    assert!(
        filter.store.get().is_none(),
        "store should not be initialized when skipped"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_request_skips_when_format_is_openai_chat_completions() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat/completions");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_chat_completions");

    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should skip when format is openai_chat_completions"
    );
    assert!(
        filter.store.get().is_none(),
        "store should not be initialized for non-responses format"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_request_skips_when_store_is_false() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    ctx.set_metadata("openai_responses_format.store", "false");

    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should skip when store is false"
    );
    assert!(
        filter.store.get().is_none(),
        "store should not be initialized when store=false"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_request_skips_when_stream_is_true() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    ctx.set_metadata("openai_responses_format.stream", "true");

    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should skip when stream is true"
    );
    assert!(
        filter.store.get().is_none(),
        "store should not be initialized for streaming requests"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_request_skips_for_get_to_unrelated_path() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::GET, "/v1/models");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");

    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should skip for GET to unrelated path"
    );
    assert!(
        filter.store.get().is_none(),
        "store should not be initialized for non-responses GET paths"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_request_skips_delete_on_unrelated_path() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::DELETE, "/v1/chat/completions");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "DELETE to unrelated path should continue"
    );
    assert!(
        filter.store.get().is_none(),
        "store should not be initialized for unrelated DELETE"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_request_initializes_store_for_openai_responses_format() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");

    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should continue after initializing store"
    );
    let store_opt = filter.store.get().expect("store OnceCell should be initialized");
    assert!(
        store_opt.is_some(),
        "store should be Some for valid sqlite::memory: config"
    );
}

// -----------------------------------------------------------------------------
// on_response
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_skips_when_format_metadata_absent() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_response(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should skip when format metadata is absent"
    );
    assert_eq!(
        ctx.response_body_mode,
        BodyMode::Stream,
        "body mode should remain Stream when skipped"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_sets_skip_persist_for_non_2xx() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    run_request_phase(&filter, &mut ctx).await;

    let mut resp = crate::test_utils::make_response();
    resp.status = http::StatusCode::INTERNAL_SERVER_ERROR;
    ctx.response_header = Some(&mut resp);

    let action = filter.on_response(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "should continue for non-2xx");
    assert_eq!(
        ctx.get_metadata("responses.skip_persist"),
        Some("true"),
        "should set skip_persist for non-2xx responses"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_sets_skip_persist_for_non_json_content_type() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    run_request_phase(&filter, &mut ctx).await;

    let mut resp = crate::test_utils::make_response();
    resp.headers
        .insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
    ctx.response_header = Some(&mut resp);

    let action = filter.on_response(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should continue for non-JSON content type"
    );
    assert_eq!(
        ctx.get_metadata("responses.skip_persist"),
        Some("true"),
        "should set skip_persist for non-JSON responses"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_continues_for_json_200() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    run_request_phase(&filter, &mut ctx).await;

    let mut resp = crate::test_utils::make_response();
    resp.headers
        .insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());
    ctx.response_header = Some(&mut resp);

    let action = filter.on_response(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "should continue for JSON 200");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_accepts_mixed_case_json_content_type() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    run_request_phase(&filter, &mut ctx).await;

    let mut resp = crate::test_utils::make_response();
    resp.headers.insert(
        http::header::CONTENT_TYPE,
        "Application/JSON; charset=utf-8".parse().unwrap(),
    );
    ctx.response_header = Some(&mut resp);

    let action = filter.on_response(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should continue for mixed-case JSON content type"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_does_not_buffer_when_store_unavailable() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
backend: sqlite
database_url: "sqlite:///nonexistent/path/that/will/fail.db"
responses_table: responses
conversations_table: conversations
"#,
    )
    .unwrap();
    let cfg: ResponseStoreConfig = parse_filter_config("openai_response_store", &yaml).unwrap();
    validate_config(&cfg).unwrap();
    let filter = ResponseStoreFilter::new(cfg);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    run_request_phase(&filter, &mut ctx).await;

    let mut resp = crate::test_utils::make_response();
    resp.headers
        .insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());
    ctx.response_header = Some(&mut resp);

    let action = filter.on_response(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should continue when store init fails"
    );
    assert_eq!(
        ctx.response_body_mode,
        BodyMode::Stream,
        "body mode should remain Stream when store is unavailable"
    );
    assert_eq!(
        ctx.get_metadata("responses.skip_persist"),
        Some("true"),
        "should mark persistence skipped when store is unavailable"
    );
}

// -----------------------------------------------------------------------------
// on_response_body
// -----------------------------------------------------------------------------

#[test]
fn on_response_body_releases_skipped_non_end_of_stream() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    let mut body = Some(Bytes::from_static(b"partial"));

    let action = filter.on_response_body(&mut ctx, &mut body, false).unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release non-persisted non-end-of-stream chunks"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_body_releases_when_skip_persist_is_true() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    run_request_phase(&filter, &mut ctx).await;
    ctx.set_metadata("responses.skip_persist", "true");
    let mut body = Some(Bytes::from_static(b"{}"));

    let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "should release when skip_persist is true"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_body_releases_streaming_request_before_eos() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    ctx.set_metadata("openai_responses_format.stream", "true");
    let request_action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(request_action, FilterAction::Continue),
        "streaming request should pass request phase"
    );

    let mut body = Some(Bytes::from_static(b"event: response.output_text.delta\n\n"));
    let action = filter.on_response_body(&mut ctx, &mut body, false).unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "streaming response chunks should release before EOS"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_body_buffers_persistable_non_end_of_stream() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    run_request_phase(&filter, &mut ctx).await;

    let mut body = Some(Bytes::from_static(b"{\"id\":\"resp_partial\""));
    let action = filter.on_response_body(&mut ctx, &mut body, false).unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "persistable response should remain buffered before EOS"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_body_skips_when_body_is_none() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    run_request_phase(&filter, &mut ctx).await;
    let mut body: Option<Bytes> = None;

    let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should skip when body is None"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_body_continues_when_terminal_body_is_none() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");

    drop(filter.on_request(&mut ctx).await.unwrap());

    let mut resp = crate::test_utils::make_response();
    resp.headers
        .insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());

    let mut body: Option<Bytes> = None;
    let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should skip terminal response with no body"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_body_skips_when_body_is_empty() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    run_request_phase(&filter, &mut ctx).await;
    let mut body = Some(Bytes::new());

    let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should skip when body is empty"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_body_skips_when_body_is_invalid_json() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    run_request_phase(&filter, &mut ctx).await;
    let mut body = Some(Bytes::from_static(b"not json {{{"));

    let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should skip when body is invalid JSON"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_body_skips_when_id_field_missing() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    run_request_phase(&filter, &mut ctx).await;
    let body_json = json!({"created_at": 1000, "model": "gpt-4.1"});
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));

    let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should skip when id field is missing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_body_skips_when_created_at_field_missing() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    run_request_phase(&filter, &mut ctx).await;
    let body_json = json!({"id": "resp_test", "model": "gpt-4.1"});
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));

    let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should skip when created_at field is missing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_body_skips_when_model_field_missing() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");
    run_request_phase(&filter, &mut ctx).await;
    let body_json = json!({"id": "resp_test", "created_at": 1000});
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));

    let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should skip when model field is missing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_response_body_persists_valid_response() {
    let filter = make_filter();
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");

    drop(filter.on_request(&mut ctx).await.unwrap());

    let store_opt = filter.store.get().expect("store OnceCell should be initialized");
    assert!(store_opt.is_some(), "store should be initialized");

    let body_json = json!({
        "id": "resp_test123",
        "created_at": 1_719_900_000,
        "model": "gpt-4.1",
        "status": "completed",
        "input": [{"role": "user", "content": "Hello"}],
        "output": [{"type": "message", "content": "Hello"}]
    });
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));

    let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should continue after spawning persist task"
    );


    let store = store_opt.as_ref().unwrap();
    let record = store
        .get_response("default", "resp_test123")
        .await
        .expect("get_response should succeed")
        .expect("record should exist after persist");

    assert_eq!(record.id, "resp_test123", "persisted ID should match");
    assert_eq!(record.created_at, 1_719_900_000, "persisted created_at should match");
    assert_eq!(record.model, "gpt-4.1", "persisted model should match");
    assert_eq!(record.tenant_id, "default", "persisted tenant_id should be default");
    assert_eq!(
        record.response_object, body_json,
        "persisted response_object should match the full JSON"
    );
    assert_eq!(
        record.input, body_json["input"],
        "persisted input should be extracted from the response"
    );
    assert_eq!(
        record.messages, body_json["output"],
        "persisted messages should be extracted from the response output"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_persists_after_format_request_body_classification() {
    let (db_url, db_path) = temp_sqlite_url("pipeline_persists_after_format_request_body_classification");

    let mut entries: Vec<FilterEntry> = serde_yaml::from_str(&format!(
        r#"
- filter: openai_responses_format
- filter: openai_response_store
  backend: sqlite
  database_url: "{db_url}"
  responses_table: test_responses
  conversations_table: test_conversations
"#
    ))
    .unwrap();
    let registry = FilterRegistry::with_builtins();
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();

    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let request_json = json!({
        "model": "gpt-4.1",
        "input": [{"role": "user", "content": "Hello"}]
    });
    let mut request_body = Some(Bytes::from(serde_json::to_vec(&request_json).unwrap()));
    let request_body_action = pipeline
        .execute_http_request_body(&mut ctx, &mut request_body, true)
        .await
        .unwrap();
    assert!(
        matches!(request_body_action, FilterAction::Release),
        "format classifier should release the buffered request body"
    );
    assert_eq!(
        ctx.get_metadata("openai_responses_format.format"),
        Some("openai_responses"),
        "format classifier should write metadata before store filter runs"
    );

    let request_action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert!(
        matches!(request_action, FilterAction::Continue),
        "request phase should continue after initializing the store"
    );

    let mut resp = crate::test_utils::make_response();
    resp.headers
        .insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());
    ctx.response_header = Some(&mut resp);
    let response_action = pipeline.execute_http_response(&mut ctx).await.unwrap();
    assert!(
        matches!(response_action, FilterAction::Continue),
        "response phase should continue and arm persistence buffering"
    );
    ctx.response_header = None;

    let response_json = json!({
        "id": "resp_pipeline",
        "created_at": 1_719_900_000,
        "model": "gpt-4.1",
        "status": "completed",
        "input": [{"role": "user", "content": "Hello"}],
        "output": []
    });
    let mut response_body = Some(Bytes::from(serde_json::to_vec(&response_json).unwrap()));
    let response_body_action = pipeline
        .execute_http_response_body(&mut ctx, &mut response_body, true)
        .unwrap();
    assert!(
        matches!(response_body_action, FilterAction::Continue),
        "response body phase should persist and continue"
    );


    let store = SqliteResponseStore::new(&db_url, "test_responses", "test_conversations")
        .await
        .unwrap();
    let record = store
        .get_response("default", "resp_pipeline")
        .await
        .unwrap()
        .expect("pipeline should persist the response after body classification");
    assert_eq!(record.response_object, response_json);
    assert_eq!(record.input, response_json["input"]);

    drop(store);
    drop(pipeline);
    cleanup_sqlite_file(&db_path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_init_failure_is_permanent() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
backend: sqlite
database_url: "sqlite:///nonexistent/path/that/will/fail.db"
responses_table: responses
conversations_table: conversations
"#,
    )
    .unwrap();
    let cfg: ResponseStoreConfig = parse_filter_config("openai_response_store", &yaml).unwrap();
    validate_config(&cfg).unwrap();
    let filter = ResponseStoreFilter::new(cfg);

    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("openai_responses_format.format", "openai_responses");

    drop(filter.on_request(&mut ctx).await.unwrap());

    let store_opt = filter
        .store
        .get()
        .expect("store OnceCell should be initialized after first attempt");
    assert!(store_opt.is_none(), "store should be None after failed init");

    let mut ctx2 = crate::test_utils::make_filter_context(&req);
    ctx2.set_metadata("openai_responses_format.format", "openai_responses");

    drop(filter.on_request(&mut ctx2).await.unwrap());

    let store_opt2 = filter.store.get().expect("store OnceCell should still be initialized");
    assert!(
        store_opt2.is_none(),
        "store should remain None on second request (failure is permanent)"
    );
}

// -----------------------------------------------------------------------------
// GET /v1/responses/{id}
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_response_returns_200_when_found() {
    let filter = make_filter();
    init_store_and_seed(
        &filter,
        "resp_found",
        "default",
        json!([{"id": "item_1", "type": "message"}]),
    )
    .await;

    let req = crate::test_utils::make_request(http::Method::GET, "/v1/responses/resp_found");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    let rejection = expect_reject(action);
    assert_eq!(rejection.status, 200, "should return 200 for found response");
    assert_has_json_content_type(&rejection);

    let body: serde_json::Value = serde_json::from_slice(rejection.body.as_deref().unwrap()).unwrap();
    assert_eq!(
        body["status"], "completed",
        "body should contain the stored response_object"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_response_returns_404_when_not_found() {
    let filter = make_filter();
    init_store(&filter).await;

    let req = crate::test_utils::make_request(http::Method::GET, "/v1/responses/resp_nonexistent");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    let rejection = expect_reject(action);
    assert_eq!(rejection.status, 404, "should return 404 for missing response");
    assert_has_json_content_type(&rejection);

    let body: serde_json::Value = serde_json::from_slice(rejection.body.as_deref().unwrap()).unwrap();
    assert_eq!(
        body["error"]["type"], "invalid_request_error",
        "error type should be invalid_request_error"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_response_tenant_isolation() {
    let filter = make_filter();
    init_store_and_seed(&filter, "resp_tenant", "tenant_a", json!([])).await;

    let req = crate::test_utils::make_request(http::Method::GET, "/v1/responses/resp_tenant");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    let rejection = expect_reject(action);
    assert_eq!(
        rejection.status, 404,
        "should return 404 when response belongs to a different tenant"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_response_trailing_slash_handled() {
    let filter = make_filter();
    init_store_and_seed(&filter, "resp_slash", "default", json!([])).await;

    let req = crate::test_utils::make_request(http::Method::GET, "/v1/responses/resp_slash/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    let rejection = expect_reject(action);
    assert_eq!(
        rejection.status, 200,
        "trailing slash should be stripped and response found"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_unrelated_path_continues() {
    let filter = make_filter();

    let req = crate::test_utils::make_request(http::Method::GET, "/v1/chat/completions");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "GET to unrelated path should continue"
    );
}

// -----------------------------------------------------------------------------
// GET /v1/responses/{id}/input_items
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_input_items_returns_200_when_found() {
    let filter = make_filter();
    init_store_and_seed(
        &filter,
        "resp_items",
        "default",
        json!([
            {"id": "item_1", "type": "message", "content": "hello"},
            {"id": "item_2", "type": "message", "content": "world"}
        ]),
    )
    .await;

    let req = crate::test_utils::make_request(http::Method::GET, "/v1/responses/resp_items/input_items");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    let rejection = expect_reject(action);
    assert_eq!(rejection.status, 200, "should return 200 for input items");
    assert_has_json_content_type(&rejection);

    let body: serde_json::Value = serde_json::from_slice(rejection.body.as_deref().unwrap()).unwrap();
    assert_eq!(body["object"], "list", "should have list object type");
    assert_eq!(body["data"].as_array().unwrap().len(), 2, "should have 2 items");
    assert_eq!(body["has_more"], false, "should have no more items");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_input_items_returns_404_when_not_found() {
    let filter = make_filter();
    init_store(&filter).await;

    let req = crate::test_utils::make_request(http::Method::GET, "/v1/responses/resp_missing/input_items");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    let rejection = expect_reject(action);
    assert_eq!(
        rejection.status, 404,
        "should return 404 when response not found for input_items"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_input_items_with_limit_and_order() {
    let filter = make_filter();
    init_store_and_seed(
        &filter,
        "resp_page",
        "default",
        json!([
            {"id": "item_1", "type": "message"},
            {"id": "item_2", "type": "message"},
            {"id": "item_3", "type": "message"},
            {"id": "item_4", "type": "message"}
        ]),
    )
    .await;

    let req = crate::test_utils::make_request(
        http::Method::GET,
        "/v1/responses/resp_page/input_items?limit=2&order=asc",
    );
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    let rejection = expect_reject(action);
    assert_eq!(rejection.status, 200, "should return 200 for paginated input items");

    let body: serde_json::Value = serde_json::from_slice(rejection.body.as_deref().unwrap()).unwrap();
    assert_eq!(body["data"].as_array().unwrap().len(), 2, "should limit to 2 items");
    assert_eq!(body["has_more"], true, "should indicate more items exist");
    assert_eq!(
        body["first_id"], "item_1",
        "first_id should be item_1 in ascending order"
    );
    assert_eq!(body["last_id"], "item_2", "last_id should be item_2 in ascending order");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_input_items_with_cursor() {
    let filter = make_filter();
    init_store_and_seed(
        &filter,
        "resp_cursor",
        "default",
        json!([
            {"id": "item_1", "type": "message"},
            {"id": "item_2", "type": "message"},
            {"id": "item_3", "type": "message"},
            {"id": "item_4", "type": "message"}
        ]),
    )
    .await;

    let req = crate::test_utils::make_request(
        http::Method::GET,
        "/v1/responses/resp_cursor/input_items?after=item_2&limit=2&order=asc",
    );
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    let rejection = expect_reject(action);
    assert_eq!(rejection.status, 200, "should return 200 for cursor-based pagination");

    let body: serde_json::Value = serde_json::from_slice(rejection.body.as_deref().unwrap()).unwrap();
    let data = body["data"].as_array().unwrap();
    assert_eq!(data.len(), 2, "should return 2 items after cursor");
    assert_eq!(data[0]["id"], "item_3", "first item should be item_3 after item_2");
    assert_eq!(data[1]["id"], "item_4", "second item should be item_4");
    assert_eq!(body["has_more"], false, "should indicate no more items after this page");
}

// -----------------------------------------------------------------------------
// DELETE
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_existing_response_returns_200() {
    let filter = make_filter();
    init_store_and_seed(&filter, "resp_del1", "default", json!([])).await;

    let req = crate::test_utils::make_request(http::Method::DELETE, "/v1/responses/resp_del1");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    let rejection = expect_reject(action);
    assert_eq!(rejection.status, 200, "existing response should return 200");
    assert_has_json_content_type(&rejection);

    let body: serde_json::Value = serde_json::from_slice(rejection.body.as_deref().expect("body should be present"))
        .expect("body should be valid JSON");
    assert_eq!(body["id"], "resp_del1", "body should contain the response id");
    assert_eq!(
        body["object"], "response.deleted",
        "body should have object=response.deleted"
    );
    assert_eq!(body["deleted"], true, "body should have deleted=true");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_nonexistent_response_returns_404() {
    let filter = make_filter();
    init_store_and_seed(&filter, "resp_exists", "default", json!([])).await;

    let req = crate::test_utils::make_request(http::Method::DELETE, "/v1/responses/resp_missing");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    let rejection = expect_reject(action);
    assert_eq!(rejection.status, 404, "nonexistent response should return 404");
    assert_has_json_content_type(&rejection);

    let body: serde_json::Value = serde_json::from_slice(rejection.body.as_deref().expect("body should be present"))
        .expect("body should be valid JSON");
    assert_eq!(
        body["error"]["type"], "invalid_request_error",
        "error type should be invalid_request_error"
    );
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("resp_missing")),
        "error message should reference the missing id"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_is_idempotent() {
    let filter = make_filter();
    init_store_and_seed(&filter, "resp_idem", "default", json!([])).await;

    let req = crate::test_utils::make_request(http::Method::DELETE, "/v1/responses/resp_idem");
    let mut ctx1 = crate::test_utils::make_filter_context(&req);
    let action1 = filter.on_request(&mut ctx1).await.unwrap();
    let r1 = expect_reject(action1);
    assert_eq!(r1.status, 200, "first delete should return 200");

    let mut ctx2 = crate::test_utils::make_filter_context(&req);
    let action2 = filter.on_request(&mut ctx2).await.unwrap();
    let r2 = expect_reject(action2);
    assert_eq!(r2.status, 404, "second delete should return 404");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_cross_tenant_returns_404() {
    let filter = make_filter();
    init_store_and_seed(&filter, "resp_tenant", "tenant_a", json!([])).await;

    let req = crate::test_utils::make_request(http::Method::DELETE, "/v1/responses/resp_tenant");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    let rejection = expect_reject(action);
    assert_eq!(rejection.status, 404, "delete from wrong tenant should return 404");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_uses_tenant_metadata() {
    let filter = make_filter();
    init_store_and_seed(&filter, "resp_tmeta", "tenant_x", json!([])).await;

    let req = crate::test_utils::make_request(http::Method::DELETE, "/v1/responses/resp_tmeta");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("responses.tenant_id", "tenant_x");

    let action = filter.on_request(&mut ctx).await.unwrap();
    let rejection = expect_reject(action);
    assert_eq!(
        rejection.status, 200,
        "delete with matching tenant metadata should return 200"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_continues_when_store_unavailable() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
backend: sqlite
database_url: "sqlite:///nonexistent/path/that/will/fail.db"
responses_table: responses
conversations_table: conversations
"#,
    )
    .unwrap();
    let cfg: ResponseStoreConfig = parse_filter_config("openai_response_store", &yaml).unwrap();
    validate_config(&cfg).unwrap();
    let filter = ResponseStoreFilter::new(cfg);

    let req = crate::test_utils::make_request(http::Method::DELETE, "/v1/responses/resp_gone");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "DELETE should continue when store is unavailable"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_response_has_json_content_type() {
    let filter = make_filter();
    init_store_and_seed(&filter, "resp_ct", "default", json!([])).await;

    let req = crate::test_utils::make_request(http::Method::DELETE, "/v1/responses/resp_ct");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    let rejection = expect_reject(action);
    assert_has_json_content_type(&rejection);
}

// -----------------------------------------------------------------------------
// extract_response_id
// -----------------------------------------------------------------------------

#[test]
fn extract_response_id_valid() {
    assert_eq!(
        super::filter::extract_response_id("/v1/responses/resp_abc"),
        Some("resp_abc"),
        "should extract ID from valid path"
    );
}

#[test]
fn extract_response_id_trailing_slash() {
    assert_eq!(
        super::filter::extract_response_id("/v1/responses/resp_abc/"),
        Some("resp_abc"),
        "should extract ID with trailing slash"
    );
}

#[test]
fn extract_response_id_no_id() {
    assert_eq!(
        super::filter::extract_response_id("/v1/responses"),
        None,
        "should return None without ID segment"
    );
}

#[test]
fn extract_response_id_sub_resource() {
    assert_eq!(
        super::filter::extract_response_id("/v1/responses/resp_abc/input_items"),
        None,
        "should return None for sub-resource path"
    );
}

#[test]
fn extract_response_id_unrelated_path() {
    assert_eq!(
        super::filter::extract_response_id("/v1/chat/completions"),
        None,
        "should return None for unrelated path"
    );
}

#[test]
fn extract_response_id_empty_id_segment() {
    assert_eq!(
        super::filter::extract_response_id("/v1/responses/"),
        None,
        "should return None for empty ID segment"
    );
}

// -----------------------------------------------------------------------------
// parse_query_params
// -----------------------------------------------------------------------------

#[test]
fn parse_query_params_empty() {
    let params = super::filter::parse_query_params(None);
    assert!(params.cursor.is_none(), "cursor should be None for empty query");
    assert_eq!(params.limit, 20, "limit should default to 20");
    assert_eq!(
        params.order,
        super::Order::Descending,
        "order should default to Descending"
    );
}

#[test]
fn parse_query_params_all_fields() {
    let params = super::filter::parse_query_params(Some("after=5&limit=10&order=asc"));
    assert_eq!(
        params.cursor.as_deref(),
        Some("5"),
        "cursor should be parsed from after param"
    );
    assert_eq!(params.limit, 10, "limit should be parsed from query");
    assert_eq!(
        params.order,
        super::Order::Ascending,
        "order should be parsed as Ascending"
    );
}

#[test]
fn parse_query_params_invalid_limit_ignored() {
    let params = super::filter::parse_query_params(Some("limit=abc"));
    assert_eq!(params.limit, 20, "invalid limit should keep default");
}

#[test]
fn parse_query_params_decodes_percent_encoded_cursor() {
    let params = super::filter::parse_query_params(Some("after=item%5F1"));
    assert_eq!(
        params.cursor.as_deref(),
        Some("item_1"),
        "percent-encoded cursor should be decoded"
    );
}

#[test]
fn parse_query_params_unknown_order_ignored() {
    let params = super::filter::parse_query_params(Some("order=random"));
    assert_eq!(
        params.order,
        super::Order::Descending,
        "unknown order value should keep default"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn make_filter() -> ResponseStoreFilter {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
backend: sqlite
database_url: "sqlite::memory:"
responses_table: test_responses
conversations_table: test_conversations
"#,
    )
    .unwrap();
    let cfg: ResponseStoreConfig = parse_filter_config("openai_response_store", &yaml).unwrap();
    validate_config(&cfg).unwrap();
    ResponseStoreFilter::new(cfg)
}

async fn run_request_phase(filter: &ResponseStoreFilter, ctx: &mut HttpFilterContext<'_>) {
    let action = filter.on_request(ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "request phase should continue"
    );
}

fn temp_sqlite_url(test_name: &str) -> (String, PathBuf) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let db_path = std::env::temp_dir().join(format!("praxis_{test_name}_{}_{}.db", std::process::id(), nanos));
    (format!("sqlite://{}?mode=rwc", db_path.display()), db_path)
}

fn cleanup_sqlite_file(db_path: &PathBuf) {
    drop(std::fs::remove_file(db_path));
    drop(std::fs::remove_file(format!("{}-shm", db_path.display())));
    drop(std::fs::remove_file(format!("{}-wal", db_path.display())));
}

async fn init_store(filter: &ResponseStoreFilter) {
    filter.store.get_or_init(|| async { filter.init_store().await }).await;
}

async fn init_store_and_seed(filter: &ResponseStoreFilter, id: &str, tenant_id: &str, input: serde_json::Value) {
    let store_opt = filter.store.get_or_init(|| async { filter.init_store().await }).await;
    let store = store_opt.as_ref().expect("store should be initialized");
    let record = crate::builtins::http::ai::store::ResponseRecord {
        id: id.to_owned(),
        tenant_id: tenant_id.to_owned(),
        created_at: 1000,
        model: "gpt-4.1".to_owned(),
        response_object: json!({"status": "completed"}),
        input,
        messages: json!([{"role": "user", "content": "hello"}]),
    };
    store
        .upsert_response(&record)
        .await
        .expect("seed response should succeed");
}

fn expect_reject(action: FilterAction) -> crate::Rejection {
    match action {
        FilterAction::Reject(r) => r,
        other => panic!("expected Reject, got {other:?}"),
    }
}

fn assert_has_json_content_type(rejection: &crate::Rejection) {
    let has_ct = rejection
        .headers
        .iter()
        .any(|(k, v)| k == "content-type" && v == "application/json");
    assert!(has_ct, "rejection should have application/json content-type");
}
