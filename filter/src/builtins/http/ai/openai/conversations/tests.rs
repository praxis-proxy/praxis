// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

use bytes::Bytes;
use http::Method;
use serde_json::Value;

use super::{
    config::{ConversationsConfig, validate_config},
    filter::OpenaiConversationsFilter,
    validate::validate_metadata,
};
use crate::{
    FilterAction,
    body::BodyMode,
    factory::parse_filter_config,
    filter::HttpFilter,
    test_utils::{make_filter_context, make_request},
};

fn rejection_body(rejection: &crate::Rejection) -> Value {
    serde_json::from_slice(rejection.body.as_deref().unwrap()).unwrap()
}

// -----------------------------------------------------------------------------
// Config Tests
// -----------------------------------------------------------------------------

#[test]
fn parse_valid_sqlite_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        backend: sqlite
        database_url: "sqlite::memory:"
        conversations_table: conversations
        items_table: conversation_items
        "#,
    )
    .unwrap();
    let cfg: ConversationsConfig = parse_filter_config("openai_conversations", &yaml).unwrap();
    validate_config(&cfg).unwrap();
}

#[test]
fn parse_valid_postgres_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        backend: postgres
        database_url: "postgres://1.2.3.4:5432/conversations"
        conversations_table: conversations
        items_table: conversation_items
        "#,
    )
    .unwrap();
    let cfg: ConversationsConfig = parse_filter_config("openai_conversations", &yaml).unwrap();
    validate_config(&cfg).unwrap();
}

#[test]
fn reject_empty_database_url() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        backend: sqlite
        database_url: ""
        conversations_table: conversations
        items_table: conversation_items
        "#,
    )
    .unwrap();
    let cfg: ConversationsConfig = parse_filter_config("openai_conversations", &yaml).unwrap();
    let err = validate_config(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("must not be empty"),
        "expected empty URL error: {err}"
    );
}

#[test]
fn reject_duplicate_table_names() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        backend: sqlite
        database_url: "sqlite::memory:"
        conversations_table: same_name
        items_table: same_name
        "#,
    )
    .unwrap();
    let cfg: ConversationsConfig = parse_filter_config("openai_conversations", &yaml).unwrap();
    let err = validate_config(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("distinct"),
        "expected distinct table names error: {err}"
    );
}

#[test]
fn reject_items_table_matching_generated_responses_table() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        backend: sqlite
        database_url: "sqlite::memory:"
        conversations_table: conversations
        items_table: conversations_unused_responses
        "#,
    )
    .unwrap();
    let cfg: ConversationsConfig = parse_filter_config("openai_conversations", &yaml).unwrap();
    let err = validate_config(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("generated responses and items table names"),
        "expected generated response table collision error: {err}"
    );
}

#[test]
fn reject_invalid_table_name() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        backend: sqlite
        database_url: "sqlite::memory:"
        conversations_table: "1invalid"
        items_table: conversation_items
        "#,
    )
    .unwrap();
    let cfg: ConversationsConfig = parse_filter_config("openai_conversations", &yaml).unwrap();
    let err = validate_config(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("invalid conversations_table"),
        "expected invalid table name error: {err}"
    );
}

#[test]
fn reject_postgres_items_table_above_index_safe_length() {
    let items_table = "i".repeat(64);
    let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
        r#"
        backend: postgres
        database_url: "postgres://1.2.3.4:5432/conversations"
        conversations_table: conversations
        items_table: {items_table}
        "#
    ))
    .unwrap();
    let cfg: ConversationsConfig = parse_filter_config("openai_conversations", &yaml).unwrap();
    let err = validate_config(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("items table name"),
        "expected postgres items table length error: {err}"
    );
}

#[test]
fn reject_sqlite_path_traversal() {
    for database_url in [
        "sqlite://../../etc/data.db",
        "sqlite://..%2F..%2Fetc%2Fdata.db?mode=rwc",
    ] {
        let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
            r#"
            backend: sqlite
            database_url: "{database_url}"
            conversations_table: conversations
            items_table: conversation_items
            "#
        ))
        .unwrap();
        let cfg: ConversationsConfig = parse_filter_config("openai_conversations", &yaml).unwrap();
        let err = validate_config(&cfg).unwrap_err();
        assert!(
            err.to_string().contains("path traversal"),
            "expected path traversal error for {database_url}: {err}"
        );
    }
}

#[test]
fn reject_ssl_mode_on_sqlite() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        backend: sqlite
        database_url: "sqlite::memory:"
        conversations_table: conversations
        items_table: conversation_items
        ssl_mode: require
        "#,
    )
    .unwrap();
    let cfg: ConversationsConfig = parse_filter_config("openai_conversations", &yaml).unwrap();
    let err = validate_config(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("only valid with the 'postgres' backend"),
        "expected postgres-only error: {err}"
    );
}

#[test]
fn reject_unknown_fields() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        backend: sqlite
        database_url: "sqlite::memory:"
        conversations_table: conversations
        items_table: conversation_items
        unknown_field: true
        "#,
    )
    .unwrap();
    let result = parse_filter_config::<ConversationsConfig>("openai_conversations", &yaml);
    assert!(result.is_err(), "should reject unknown fields");
}

#[test]
fn reject_postgres_without_scheme() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        backend: postgres
        database_url: "1.2.3.4:5432/conversations"
        conversations_table: conversations
        items_table: conversation_items
        "#,
    )
    .unwrap();
    let cfg: ConversationsConfig = parse_filter_config("openai_conversations", &yaml).unwrap();
    let err = validate_config(&cfg).unwrap_err();
    assert!(
        err.to_string().contains("must start with"),
        "expected scheme error: {err}"
    );
}

// -----------------------------------------------------------------------------
// Metadata Validation Tests
// -----------------------------------------------------------------------------

#[test]
fn valid_metadata() {
    let metadata = serde_json::json!({"key1": "value1", "key2": "value2"});
    validate_metadata(&metadata).unwrap();
}

#[test]
fn null_metadata_is_valid() {
    validate_metadata(&Value::Null).unwrap();
}

#[test]
fn reject_non_object_metadata() {
    let metadata = serde_json::json!("string");
    let err = validate_metadata(&metadata).unwrap_err();
    assert!(err.contains("must be a JSON object"), "got: {err}");
}

#[test]
fn reject_too_many_keys() {
    let mut map = serde_json::Map::new();
    for i in 0..17 {
        map.insert(format!("key{i}"), Value::String("val".to_owned()));
    }
    let err = validate_metadata(&Value::Object(map)).unwrap_err();
    assert!(err.contains("at most 16 keys"), "got: {err}");
}

#[test]
fn reject_long_key() {
    let long_key = "k".repeat(65);
    let metadata = serde_json::json!({long_key: "value"});
    let err = validate_metadata(&metadata).unwrap_err();
    assert!(err.contains("exceeds 64 bytes"), "got: {err}");
}

#[test]
fn reject_long_value() {
    let long_value = "v".repeat(513);
    let metadata = serde_json::json!({"key": long_value});
    let err = validate_metadata(&metadata).unwrap_err();
    assert!(err.contains("exceeds 512 bytes"), "got: {err}");
}

#[test]
fn reject_non_string_value() {
    let metadata = serde_json::json!({"key": 42});
    let err = validate_metadata(&metadata).unwrap_err();
    assert!(err.contains("must be a string"), "got: {err}");
}

// -----------------------------------------------------------------------------
// Filter Factory Tests
// -----------------------------------------------------------------------------

#[test]
fn from_config_creates_filter() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        backend: sqlite
        database_url: "sqlite::memory:"
        conversations_table: conversations
        items_table: conversation_items
        "#,
    )
    .unwrap();
    let filter = OpenaiConversationsFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "openai_conversations");
}

// -----------------------------------------------------------------------------
// Handler Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn create_and_get_conversation() {
    let filter = build_test_filter();

    let req = make_request(Method::POST, "/v1/conversations");
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());

    let body_json = serde_json::json!({"metadata": {"env": "test"}});
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject, got {action:?}");
    };
    assert_eq!(rejection.status, 200);
    let resp = rejection_body(&rejection);
    assert_eq!(resp["object"], "conversation");
    let conv_id = resp["id"].as_str().unwrap();
    assert!(conv_id.starts_with("conv_"));

    let req = make_request(Method::GET, &format!("/v1/conversations/{conv_id}"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();

    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject, got {action:?}");
    };
    assert_eq!(rejection.status, 200);
    let resp = rejection_body(&rejection);
    assert_eq!(resp["id"], conv_id);
    assert_eq!(resp["metadata"]["env"], "test");
}

#[tokio::test]
async fn get_nonexistent_conversation_returns_404() {
    let filter = build_test_filter();

    let req = make_request(Method::GET, "/v1/conversations/conv_nonexistent");
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();

    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject, got {action:?}");
    };
    assert_eq!(rejection.status, 404);
}

#[tokio::test]
async fn update_conversation() {
    let filter = build_test_filter();
    let conv_id = create_test_conversation(filter.as_ref(), serde_json::json!({"v": "1"})).await;

    let req = make_request(Method::POST, &format!("/v1/conversations/{conv_id}"));
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());

    let body_json = serde_json::json!({"metadata": {"v": "2"}});
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject, got {action:?}");
    };
    assert_eq!(rejection.status, 200);
    let resp = rejection_body(&rejection);
    assert_eq!(resp["metadata"]["v"], "2");

    let req = make_request(Method::GET, &format!("/v1/conversations/{conv_id}"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from get after update");
    };
    let resp = rejection_body(&rejection);
    assert_eq!(resp["metadata"]["v"], "2", "updated metadata should be persisted");
}

#[tokio::test]
async fn update_conversation_without_metadata_preserves_existing_metadata() {
    let filter = build_test_filter();
    let conv_id = create_test_conversation(filter.as_ref(), serde_json::json!({"v": "1"})).await;

    let req = make_request(Method::POST, &format!("/v1/conversations/{conv_id}"));
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());

    let mut body = Some(Bytes::from_static(b"{}"));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject, got {action:?}");
    };
    assert_eq!(rejection.status, 200);
    let resp = rejection_body(&rejection);
    assert_eq!(
        resp["metadata"]["v"], "1",
        "missing metadata should preserve existing value"
    );

    let req = make_request(Method::GET, &format!("/v1/conversations/{conv_id}"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from get after update");
    };
    let resp = rejection_body(&rejection);
    assert_eq!(resp["metadata"]["v"], "1", "preserved metadata should be persisted");
}

#[tokio::test]
async fn delete_conversation() {
    let filter = build_test_filter();
    let conv_id = create_test_conversation(filter.as_ref(), serde_json::json!({})).await;

    let req = make_request(Method::DELETE, &format!("/v1/conversations/{conv_id}"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();

    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject, got {action:?}");
    };
    assert_eq!(rejection.status, 200);
    let resp = rejection_body(&rejection);
    assert!(resp["deleted"].as_bool().unwrap());

    let req = make_request(Method::GET, &format!("/v1/conversations/{conv_id}"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject");
    };
    assert_eq!(rejection.status, 404);
}

#[tokio::test]
async fn delete_conversation_preserves_item_rows() {
    let filter = build_test_filter();

    let req = make_request(Method::POST, "/v1/conversations");
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());

    let body_json = serde_json::json!({
        "metadata": {},
        "items": [
            {"id": "item_keep", "type": "message", "role": "user", "content": "keep me"}
        ]
    });
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from create conversation");
    };
    assert_eq!(rejection.status, 200, "create should return 200");
    let resp = rejection_body(&rejection);
    let conv_id = resp["id"].as_str().unwrap();

    let req = make_request(Method::DELETE, &format!("/v1/conversations/{conv_id}"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from delete conversation");
    };
    assert_eq!(rejection.status, 200, "delete conversation should return 200");

    let req = make_request(Method::GET, &format!("/v1/conversations/{conv_id}/items/item_keep"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from get retained item");
    };
    assert_eq!(rejection.status, 200, "conversation delete should not delete item row");
    let resp = rejection_body(&rejection);
    assert_eq!(resp["id"], "item_keep");
    assert_eq!(resp["content"][0]["text"], "keep me");
}

#[tokio::test]
async fn unmatched_path_continues() {
    let filter = build_test_filter();

    let req = make_request(Method::GET, "/v1/chat/completions");
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue));
}

#[tokio::test]
async fn post_routes_use_stream_buffer_body_mode() {
    let filter = build_test_filter();
    assert!(
        matches!(
            filter.request_body_mode(),
            BodyMode::StreamBuffer { max_bytes: Some(_) }
        ),
        "conversation POST routes require buffered bodies for local handling"
    );

    let req = make_request(Method::POST, "/v1/conversations");
    let mut ctx = make_filter_context(&req);
    ctx.request_body_mode = filter.request_body_mode();
    let action = filter.on_request(&mut ctx).await.unwrap();

    assert!(matches!(action, FilterAction::Continue));
    assert!(
        matches!(ctx.request_body_mode, BodyMode::StreamBuffer { max_bytes: Some(_) }),
        "matched POST should keep buffering enabled for request-body handling"
    );
}

#[tokio::test]
async fn unmatched_post_path_continues() {
    let filter = build_test_filter();

    let req = make_request(Method::POST, "/v1/chat/completions");
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();

    assert!(matches!(action, FilterAction::Continue));
    assert!(
        matches!(
            filter.request_body_mode(),
            BodyMode::StreamBuffer { max_bytes: Some(_) }
        ),
        "body mode declaration is static; unmatched path handling remains a local Continue"
    );
}

#[tokio::test]
async fn early_body_pre_read_defers_store_write_until_request_filters_run() {
    let filter = build_test_filter();

    let req = make_request(Method::POST, "/v1/conversations");
    let mut ctx = make_filter_context(&req);
    ctx.current_filter_id = Some(7);

    let body_json = serde_json::json!({"metadata": {"phase": "deferred"}});
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Release),
        "early body hook should not write the store before request filters run"
    );

    let action = filter.on_request(&mut ctx).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected deferred body to be handled during on_request, got {action:?}");
    };
    assert_eq!(rejection.status, 200);
    let resp = rejection_body(&rejection);
    assert_eq!(resp["metadata"]["phase"], "deferred");
}

#[tokio::test]
async fn create_conversation_with_invalid_metadata() {
    let filter = build_test_filter();

    let req = make_request(Method::POST, "/v1/conversations");
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());

    let body_json = serde_json::json!({"metadata": "not-an-object"});
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject for invalid metadata, got {action:?}");
    };
    assert_eq!(rejection.status, 400, "invalid metadata should return 400");
}

#[tokio::test]
async fn create_conversation_with_invalid_json_returns_400() {
    let filter = build_test_filter();

    let req = make_request(Method::POST, "/v1/conversations");
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());

    let mut body = Some(Bytes::from_static(b"{not-json"));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject for invalid JSON, got {action:?}");
    };
    assert_eq!(rejection.status, 400, "invalid JSON should return 400");
    let resp = rejection_body(&rejection);
    assert_eq!(
        resp["error"]["type"], "invalid_request_error",
        "invalid JSON should be a client error"
    );
}

#[tokio::test]
async fn create_conversation_with_non_object_json_returns_400() {
    let filter = build_test_filter();

    let req = make_request(Method::POST, "/v1/conversations");
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());

    let mut body = Some(Bytes::from_static(b"[]"));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject for non-object JSON, got {action:?}");
    };
    assert_eq!(rejection.status, 400, "non-object JSON should return 400");
    let resp = rejection_body(&rejection);
    assert_eq!(
        resp["error"]["type"], "invalid_request_error",
        "non-object JSON should be a client error"
    );
}

#[tokio::test]
async fn update_conversation_with_non_object_json_preserves_metadata() {
    let filter = build_test_filter();
    let conv_id = create_test_conversation(filter.as_ref(), serde_json::json!({"v": "1"})).await;

    let req = make_request(Method::POST, &format!("/v1/conversations/{conv_id}"));
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());

    let mut body = Some(Bytes::from_static(b"[]"));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject for non-object JSON, got {action:?}");
    };
    assert_eq!(rejection.status, 400, "non-object JSON should return 400");

    let req = make_request(Method::GET, &format!("/v1/conversations/{conv_id}"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from get after invalid update");
    };
    let resp = rejection_body(&rejection);
    assert_eq!(resp["metadata"]["v"], "1", "invalid update should not reset metadata");
}

#[tokio::test]
async fn initial_items_can_be_listed_and_retrieved() {
    let filter = build_test_filter();

    let req = make_request(Method::POST, "/v1/conversations");
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());

    let body_json = serde_json::json!({
        "metadata": {},
        "items": [
            {"id": "item_explicit", "type": "message", "role": "user", "content": "hello"},
            {"type": "message", "role": "assistant", "content": "hi"}
        ]
    });
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from create conversation");
    };
    assert_eq!(rejection.status, 200, "create should return 200");
    let resp = rejection_body(&rejection);
    let conv_id = resp["id"].as_str().unwrap();

    let req = make_request(Method::GET, &format!("/v1/conversations/{conv_id}/items?order=asc"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from list items");
    };
    assert_eq!(rejection.status, 200, "list items should return 200");
    let resp = rejection_body(&rejection);
    assert_eq!(resp["data"][0]["id"], "item_explicit");
    assert_eq!(resp["data"][0]["status"], "completed");
    assert_eq!(resp["data"][0]["content"][0]["type"], "input_text");
    assert_eq!(resp["data"][0]["content"][0]["text"], "hello");
    let generated_id = resp["data"][1]["id"].as_str().unwrap();
    assert!(generated_id.starts_with("item_"), "missing item ID should be generated");
    assert_eq!(resp["data"][1]["status"], "completed");
    assert_eq!(resp["data"][1]["content"][0]["type"], "output_text");
    assert_eq!(resp["data"][1]["content"][0]["text"], "hi");
    assert_eq!(resp["data"][1]["content"][0]["annotations"], serde_json::json!([]));

    let req = make_request(Method::GET, &format!("/v1/conversations/{conv_id}/items/item_explicit"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from get item");
    };
    assert_eq!(rejection.status, 200, "get item should return 200");
    let resp = rejection_body(&rejection);
    assert_eq!(resp["status"], "completed");
    assert_eq!(resp["content"][0]["type"], "input_text");
    assert_eq!(resp["content"][0]["text"], "hello");
}

#[tokio::test]
async fn empty_item_list_returns_string_pagination_ids() {
    let filter = build_test_filter();
    let conv_id = create_test_conversation(filter.as_ref(), serde_json::json!({})).await;

    let req = make_request(Method::GET, &format!("/v1/conversations/{conv_id}/items"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();

    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from list items");
    };
    assert_eq!(rejection.status, 200, "list empty items should return 200");
    let resp = rejection_body(&rejection);
    assert_eq!(resp["data"], serde_json::json!([]));
    assert_eq!(resp["first_id"], "");
    assert_eq!(resp["last_id"], "");
    assert_eq!(resp["has_more"], false);
}

#[tokio::test]
async fn create_conversation_rejects_duplicate_initial_item_ids() {
    let filter = build_test_filter();

    let req = make_request(Method::POST, "/v1/conversations");
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());

    let body_json = serde_json::json!({
        "metadata": {},
        "items": [
            {"id": "item_dup", "type": "message", "role": "user", "content": "first"},
            {"id": "item_dup", "type": "message", "role": "assistant", "content": "second"}
        ]
    });
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject for duplicate item id");
    };
    assert_eq!(rejection.status, 400, "duplicate initial item IDs should return 400");
    let resp = rejection_body(&rejection);
    assert!(
        resp["error"]["message"].as_str().unwrap().contains("duplicate item id"),
        "duplicate error should mention item id"
    );
}

#[tokio::test]
async fn create_and_delete_item_endpoints_are_local() {
    let filter = build_test_filter();
    let conv_id = create_test_conversation(filter.as_ref(), serde_json::json!({})).await;

    let req = make_request(Method::POST, &format!("/v1/conversations/{conv_id}/items"));
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());

    let body_json = serde_json::json!({
        "items": [
            {"id": "item_new", "type": "message", "role": "user", "content": "new"}
        ]
    });
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from create items");
    };
    assert_eq!(rejection.status, 200, "create items should return 200");
    let resp = rejection_body(&rejection);
    assert_eq!(resp["data"][0]["id"], "item_new");
    assert_eq!(resp["data"][0]["status"], "completed");
    assert_eq!(resp["data"][0]["content"][0]["type"], "input_text");
    assert_eq!(resp["data"][0]["content"][0]["text"], "new");

    let req = make_request(Method::DELETE, &format!("/v1/conversations/{conv_id}/items/item_new"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from delete item");
    };
    assert_eq!(rejection.status, 200, "delete item should return 200");

    let req = make_request(Method::GET, &format!("/v1/conversations/{conv_id}/items/item_new"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from get deleted item");
    };
    assert_eq!(rejection.status, 404, "deleted item should return 404");
}

#[tokio::test]
async fn item_subresource_routes_do_not_fall_through_upstream() {
    let filter = build_test_filter();
    let conv_id = create_test_conversation(filter.as_ref(), serde_json::json!({})).await;

    let req = make_request(Method::POST, &format!("/v1/conversations/{conv_id}/items"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "POST item route should continue only until request-body handling"
    );
    assert!(
        matches!(ctx.request_body_mode, BodyMode::StreamBuffer { max_bytes: Some(_) }),
        "POST item route should keep body buffering so it cannot reach upstream"
    );

    let body_json = serde_json::json!({
        "items": [
            {"id": "item_local", "type": "message", "role": "user", "content": "local"}
        ]
    });
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected local Reject from POST item body");
    };
    assert_eq!(rejection.status, 200, "POST item route should be handled locally");

    for (method, path) in [
        (Method::GET, format!("/v1/conversations/{conv_id}/items")),
        (Method::GET, format!("/v1/conversations/{conv_id}/items/item_local")),
        (Method::DELETE, format!("/v1/conversations/{conv_id}/items/item_local")),
    ] {
        let req = make_request(method.clone(), &path);
        let mut ctx = make_filter_context(&req);
        let action = filter.on_request(&mut ctx).await.unwrap();
        let FilterAction::Reject(rejection) = action else {
            panic!("{method} {path} should be handled locally, got {action:?}");
        };
        assert!(
            matches!(rejection.status, 200 | 404),
            "{method} {path} should return a local item response, got {}",
            rejection.status
        );
    }
}

#[tokio::test]
async fn encoded_item_id_path_segments_are_decoded() {
    let filter = build_test_filter();
    let conv_id = create_test_conversation(filter.as_ref(), serde_json::json!({})).await;

    let req = make_request(Method::POST, &format!("/v1/conversations/{conv_id}/items"));
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());

    let body_json = serde_json::json!({
        "items": [
            {"id": "item with space", "type": "message", "role": "user", "content": "encoded"}
        ]
    });
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from create items");
    };
    assert_eq!(rejection.status, 200, "create items should return 200");

    let req = make_request(
        Method::GET,
        &format!("/v1/conversations/{conv_id}/items/item%20with%20space"),
    );
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from get encoded item");
    };
    assert_eq!(rejection.status, 200, "encoded item ID should be retrievable");
    let resp = rejection_body(&rejection);
    assert_eq!(resp["id"], "item with space");
    assert_eq!(resp["content"][0]["text"], "encoded");

    let req = make_request(
        Method::DELETE,
        &format!("/v1/conversations/{conv_id}/items/item%20with%20space"),
    );
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from delete encoded item");
    };
    assert_eq!(rejection.status, 200, "encoded item ID should be deletable");
}

#[tokio::test]
async fn item_list_after_cursor_decodes_query_plus_as_space() {
    let filter = build_test_filter();

    let req = make_request(Method::POST, "/v1/conversations");
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());

    let body_json = serde_json::json!({
        "items": [
            {"id": "item with space", "type": "message", "role": "user", "content": "first"},
            {"id": "item_next", "type": "message", "role": "assistant", "content": "second"}
        ]
    });
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from create conversation");
    };
    assert_eq!(rejection.status, 200, "create should return 200");
    let resp = rejection_body(&rejection);
    let conv_id = resp["id"].as_str().unwrap();

    let req = make_request(
        Method::GET,
        &format!("/v1/conversations/{conv_id}/items?order=asc&after=item+with+space"),
    );
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from list after cursor");
    };
    assert_eq!(rejection.status, 200, "list items should return 200");
    let resp = rejection_body(&rejection);
    assert_eq!(resp["data"].as_array().unwrap().len(), 1);
    assert_eq!(resp["data"][0]["id"], "item_next");
    assert_eq!(resp["data"][0]["content"][0]["text"], "second");
}

#[tokio::test]
async fn create_items_rejects_duplicate_ids_in_request() {
    let filter = build_test_filter();
    let conv_id = create_test_conversation(filter.as_ref(), serde_json::json!({})).await;

    let req = make_request(Method::POST, &format!("/v1/conversations/{conv_id}/items"));
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());

    let body_json = serde_json::json!({
        "items": [
            {"id": "item_dup", "type": "message", "role": "user", "content": "first"},
            {"id": "item_dup", "type": "message", "role": "assistant", "content": "second"}
        ]
    });
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject for duplicate item id");
    };
    assert_eq!(rejection.status, 400, "duplicate request item IDs should return 400");
}

#[tokio::test]
async fn create_items_rejects_existing_id_without_overwrite() {
    let filter = build_test_filter();
    let conv_id = create_test_conversation(filter.as_ref(), serde_json::json!({})).await;

    let req = make_request(Method::POST, &format!("/v1/conversations/{conv_id}/items"));
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    let body_json = serde_json::json!({
        "items": [
            {"id": "item_existing", "type": "message", "role": "user", "content": "original"}
        ]
    });
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from initial item create");
    };
    assert_eq!(rejection.status, 200, "initial item create should succeed");

    let req = make_request(Method::POST, &format!("/v1/conversations/{conv_id}/items"));
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    let body_json = serde_json::json!({
        "items": [
            {"id": "item_existing", "type": "message", "role": "assistant", "content": "overwrite"}
        ]
    });
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject for existing item id");
    };
    assert_eq!(rejection.status, 400, "existing item ID should return 400");

    let req = make_request(Method::GET, &format!("/v1/conversations/{conv_id}/items/item_existing"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from get existing item");
    };
    assert_eq!(rejection.status, 200, "original item should still exist");
    let resp = rejection_body(&rejection);
    assert_eq!(
        resp["content"][0]["text"], "original",
        "duplicate create must not overwrite item data"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn build_test_filter() -> Box<dyn HttpFilter> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        backend: sqlite
        database_url: "sqlite::memory:"
        conversations_table: test_conversations
        items_table: test_items
        "#,
    )
    .unwrap();
    OpenaiConversationsFilter::from_config(&yaml).unwrap()
}

async fn create_test_conversation(filter: &dyn HttpFilter, metadata: Value) -> String {
    let req = make_request(Method::POST, "/v1/conversations");
    let mut ctx = make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());

    let body_json = serde_json::json!({"metadata": metadata});
    let mut body = Some(Bytes::from(serde_json::to_vec(&body_json).unwrap()));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject from create conversation");
    };
    let resp = rejection_body(&rejection);
    resp["id"].as_str().unwrap().to_owned()
}
