// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for the response store persistence layer.

use std::sync::Arc;

use serde_json::json;

use super::{
    ConversationRecord, PostgresResponseStore, ResponseRecord, ResponseStoreRegistry, SqliteResponseStore, SslMode,
    StoreError, trait_def::ResponseStore,
};
use crate::builtins::http::ai::openai::responses::store::{ListParams, Order, list_input_items};

// -----------------------------------------------------------------------------
// Schema Initialization
// -----------------------------------------------------------------------------

#[tokio::test]
async fn sqlite_store_initializes_schema() {
    let store = SqliteResponseStore::new("sqlite::memory:", "test_responses", "test_conversation_messages")
        .await
        .expect("store creation should succeed");

    let result = store
        .get_response("tenant_a", "nonexistent")
        .await
        .expect("get should succeed");

    assert!(result.is_none(), "empty store should return None");
}

// -----------------------------------------------------------------------------
// Response CRUD
// -----------------------------------------------------------------------------

#[tokio::test]
async fn upsert_and_get_response() {
    let store = make_store().await;
    let record = make_response_record("resp_1", "tenant_a", 1000);

    store.upsert_response(&record).await.expect("upsert should succeed");

    let fetched = store
        .get_response("tenant_a", "resp_1")
        .await
        .expect("get should succeed")
        .expect("record should exist");

    assert_eq!(fetched.id, "resp_1", "ID should match");
    assert_eq!(fetched.tenant_id, "tenant_a", "tenant should match");
    assert_eq!(fetched.created_at, 1000, "created_at should match");
    assert_eq!(fetched.model, "gpt-4.1", "model should match");
    assert_eq!(
        fetched.response_object,
        json!({"status": "completed"}),
        "response_object should match"
    );
    assert_eq!(
        fetched.input,
        json!("test input"),
        "input should survive JSON round-trip"
    );
    assert_eq!(
        fetched.messages,
        json!([{"role": "user", "content": "hello"}]),
        "messages should survive JSON round-trip"
    );
}

#[tokio::test]
async fn upsert_overwrites_existing_response() {
    let store = make_store().await;
    let record = make_response_record("resp_1", "tenant_a", 1000);
    store
        .upsert_response(&record)
        .await
        .expect("first upsert should succeed");

    let updated = ResponseRecord {
        model: "gpt-4.1-mini".to_owned(),
        response_object: json!({"status": "incomplete"}),
        ..make_response_record("resp_1", "tenant_a", 1000)
    };
    store
        .upsert_response(&updated)
        .await
        .expect("second upsert should succeed");

    let fetched = store
        .get_response("tenant_a", "resp_1")
        .await
        .expect("get should succeed")
        .expect("record should exist");

    assert_eq!(fetched.model, "gpt-4.1-mini", "model should be updated");
    assert_eq!(
        fetched.response_object,
        json!({"status": "incomplete"}),
        "response_object should be updated"
    );
}

#[tokio::test]
async fn get_missing_response_returns_none() {
    let store = make_store().await;

    let result = store
        .get_response("tenant_a", "nonexistent")
        .await
        .expect("get should succeed");

    assert!(result.is_none(), "missing record should return None");
}

#[tokio::test]
async fn delete_existing_response() {
    let store = make_store().await;
    let record = make_response_record("resp_1", "tenant_a", 1000);
    store.upsert_response(&record).await.expect("upsert should succeed");

    let deleted = store
        .delete_response("tenant_a", "resp_1")
        .await
        .expect("delete should succeed");

    assert!(deleted, "delete should return true for existing record");

    let fetched = store
        .get_response("tenant_a", "resp_1")
        .await
        .expect("get should succeed");

    assert!(fetched.is_none(), "deleted record should not be retrievable");
}

#[tokio::test]
async fn delete_missing_response_returns_false() {
    let store = make_store().await;

    let deleted = store
        .delete_response("tenant_a", "nonexistent")
        .await
        .expect("delete should succeed");

    assert!(!deleted, "delete should return false for missing record");
}

// -----------------------------------------------------------------------------
// Tenant Isolation
// -----------------------------------------------------------------------------

#[tokio::test]
async fn tenant_isolation_on_get() {
    let store = make_store().await;
    let record = make_response_record("resp_1", "tenant_a", 1000);
    store.upsert_response(&record).await.expect("upsert should succeed");

    let result = store
        .get_response("tenant_b", "resp_1")
        .await
        .expect("get should succeed");

    assert!(result.is_none(), "tenant_b should not see tenant_a records");
}

#[tokio::test]
async fn tenant_isolation_on_delete() {
    let store = make_store().await;
    let record = make_response_record("resp_1", "tenant_a", 1000);
    store.upsert_response(&record).await.expect("upsert should succeed");

    let deleted = store
        .delete_response("tenant_b", "resp_1")
        .await
        .expect("delete should succeed");

    assert!(!deleted, "tenant_b should not be able to delete tenant_a records");

    let still_exists = store
        .get_response("tenant_a", "resp_1")
        .await
        .expect("get should succeed");

    assert!(
        still_exists.is_some(),
        "record should still exist after cross-tenant delete attempt"
    );
}

#[tokio::test]
async fn same_response_id_can_exist_in_multiple_tenants() {
    let store = make_store().await;
    store
        .upsert_response(&make_response_record("resp_shared", "tenant_a", 1000))
        .await
        .expect("tenant_a upsert should succeed");
    store
        .upsert_response(&make_response_record("resp_shared", "tenant_b", 2000))
        .await
        .expect("tenant_b upsert should succeed");

    let tenant_a = store
        .get_response("tenant_a", "resp_shared")
        .await
        .expect("tenant_a get should succeed")
        .expect("tenant_a record should exist");
    let tenant_b = store
        .get_response("tenant_b", "resp_shared")
        .await
        .expect("tenant_b get should succeed")
        .expect("tenant_b record should exist");

    assert_eq!(tenant_a.tenant_id, "tenant_a", "tenant_a record should be isolated");
    assert_eq!(tenant_b.tenant_id, "tenant_b", "tenant_b record should be isolated");
    assert_eq!(tenant_a.created_at, 1000, "tenant_a record should not be overwritten");
    assert_eq!(tenant_b.created_at, 2000, "tenant_b record should not be overwritten");
}

// -----------------------------------------------------------------------------
// Input Items
// -----------------------------------------------------------------------------

#[test]
fn input_items_from_array_input() {
    let record = ResponseRecord {
        input: json!([
            {"type": "message", "role": "user", "content": "Hello"},
            {"type": "message", "role": "user", "content": "World"},
            {"type": "message", "role": "user", "content": "!"}
        ]),
        ..make_response_record("resp_1", "tenant_a", 1000)
    };

    let page = list_input_items(
        &record,
        &ListParams {
            limit: 2,
            ..ListParams::default()
        },
    )
    .expect("list should succeed");

    assert_eq!(page.data.len(), 2, "should return 2 items");
    assert!(page.has_more, "should have more items");
    assert_eq!(
        page.next_cursor.as_deref(),
        Some("2"),
        "cursor should be the next offset"
    );

    let page2 = list_input_items(
        &record,
        &ListParams {
            cursor: page.next_cursor,
            limit: 2,
            ..ListParams::default()
        },
    )
    .expect("list should succeed");

    assert_eq!(page2.data.len(), 1, "should return remaining 1 item");
    assert!(!page2.has_more, "should have no more items");
}

#[test]
fn input_items_uses_item_id_cursor() {
    let record = ResponseRecord {
        input: json!([
            {"id": "item_1", "type": "message", "role": "user", "content": "Hello"},
            {"id": "item_2", "type": "message", "role": "user", "content": "World"},
            {"id": "item_3", "type": "message", "role": "user", "content": "!"}
        ]),
        ..make_response_record("resp_1", "tenant_a", 1000)
    };

    let page = list_input_items(
        &record,
        &ListParams {
            limit: 2,
            order: Order::Ascending,
            ..ListParams::default()
        },
    )
    .expect("list should succeed");

    assert_eq!(
        page.next_cursor.as_deref(),
        Some("item_2"),
        "cursor should use the last item ID"
    );

    let page2 = list_input_items(
        &record,
        &ListParams {
            cursor: page.next_cursor,
            limit: 2,
            order: Order::Ascending,
        },
    )
    .expect("list should succeed");

    assert_eq!(page2.data.len(), 1, "second page should return remaining item");
    assert_eq!(page2.data[0]["id"], "item_3", "second page should start after item_2");
    assert!(!page2.has_more, "second page should complete pagination");
}

#[test]
fn input_items_from_string_input() {
    let record = ResponseRecord {
        input: json!("Hello, world!"),
        ..make_response_record("resp_1", "tenant_a", 1000)
    };

    let page = list_input_items(&record, &ListParams::default()).expect("list should succeed");

    assert_eq!(page.data.len(), 1, "string input should yield 1 item");
    assert_eq!(page.data[0], json!("Hello, world!"), "item should be the string");
}

#[test]
fn input_items_honors_sort_order() {
    let record = ResponseRecord {
        input: json!(["first", "second", "third"]),
        ..make_response_record("resp_1", "tenant_a", 1000)
    };

    let ascending = list_input_items(
        &record,
        &ListParams {
            order: Order::Ascending,
            ..ListParams::default()
        },
    )
    .expect("ascending list should succeed");
    let descending = list_input_items(&record, &ListParams::default()).expect("descending list should succeed");

    assert_eq!(
        ascending.data,
        vec![json!("first"), json!("second"), json!("third")],
        "ascending order should preserve input order"
    );
    assert_eq!(
        descending.data,
        vec![json!("third"), json!("second"), json!("first")],
        "descending order should reverse input order"
    );
}

#[test]
fn input_items_limit_zero_clamps_to_one() {
    let record = ResponseRecord {
        input: json!([
            {"type": "message", "role": "user", "content": "Hello"},
            {"type": "message", "role": "user", "content": "World"}
        ]),
        ..make_response_record("resp_1", "tenant_a", 1000)
    };

    let page1 = list_input_items(
        &record,
        &ListParams {
            limit: 0,
            ..ListParams::default()
        },
    )
    .expect("list should succeed");

    assert_eq!(page1.data.len(), 1, "limit 0 should clamp to one item");
    assert!(page1.has_more, "first page should indicate remaining items");
    assert_eq!(page1.next_cursor.as_deref(), Some("1"), "cursor should advance by one");

    let page2 = list_input_items(
        &record,
        &ListParams {
            cursor: page1.next_cursor,
            limit: 0,
            ..ListParams::default()
        },
    )
    .expect("list should succeed");

    assert_eq!(page2.data.len(), 1, "second page should return the remaining item");
    assert!(!page2.has_more, "second page should complete pagination");
    assert!(page2.next_cursor.is_none(), "second page should not provide a cursor");
}

#[test]
fn input_items_rejects_overflowing_cursor() {
    let record = ResponseRecord {
        input: json!([{"type": "message", "role": "user", "content": "Hello"}]),
        ..make_response_record("resp_1", "tenant_a", 1000)
    };

    let result = list_input_items(
        &record,
        &ListParams {
            cursor: Some(usize::MAX.to_string()),
            limit: 1,
            ..ListParams::default()
        },
    );

    let Err(err) = result else {
        panic!("overflowing cursor should be rejected");
    };

    assert!(
        err.to_string().contains("overflow"),
        "error should explain cursor overflow: {err}"
    );
}

#[test]
fn input_items_from_empty_array() {
    let record = ResponseRecord {
        input: json!([]),
        ..make_response_record("resp_1", "tenant_a", 1000)
    };

    let page = list_input_items(&record, &ListParams::default()).expect("list should succeed");

    assert!(page.data.is_empty(), "empty array should return no items");
    assert!(!page.has_more, "should have no more items");
    assert!(page.next_cursor.is_none(), "should have no cursor");
}

// -----------------------------------------------------------------------------
// Conversation CRUD
// -----------------------------------------------------------------------------

#[tokio::test]
async fn upsert_and_get_conversation() {
    let store = make_store().await;
    let record = ConversationRecord {
        conversation_id: "conv_1".to_owned(),
        tenant_id: "tenant_a".to_owned(),
        messages: json!([{"role": "user", "content": "Hi"}]),
    };

    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let fetched = store
        .get_conversation("tenant_a", "conv_1")
        .await
        .expect("get should succeed")
        .expect("record should exist");

    assert_eq!(fetched.conversation_id, "conv_1", "conversation_id should match");
    assert_eq!(
        fetched.messages,
        json!([{"role": "user", "content": "Hi"}]),
        "messages should match"
    );
}

#[tokio::test]
async fn upsert_conversation_overwrites() {
    let store = make_store().await;
    let record = ConversationRecord {
        conversation_id: "conv_1".to_owned(),
        tenant_id: "tenant_a".to_owned(),
        messages: json!([{"role": "user", "content": "v1"}]),
    };
    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let updated = ConversationRecord {
        messages: json!([{"role": "user", "content": "v2"}]),
        ..record
    };
    store
        .upsert_conversation(&updated)
        .await
        .expect("second upsert should succeed");

    let fetched = store
        .get_conversation("tenant_a", "conv_1")
        .await
        .expect("get should succeed")
        .expect("record should exist");

    assert_eq!(
        fetched.messages,
        json!([{"role": "user", "content": "v2"}]),
        "messages should be updated"
    );
}

#[tokio::test]
async fn get_missing_conversation_returns_none() {
    let store = make_store().await;

    let result = store
        .get_conversation("tenant_a", "nonexistent")
        .await
        .expect("get should succeed");

    assert!(result.is_none(), "missing conversation should return None");
}

#[tokio::test]
async fn conversation_tenant_isolation() {
    let store = make_store().await;
    let record = ConversationRecord {
        conversation_id: "conv_1".to_owned(),
        tenant_id: "tenant_a".to_owned(),
        messages: json!([]),
    };
    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let result = store
        .get_conversation("tenant_b", "conv_1")
        .await
        .expect("get should succeed");

    assert!(result.is_none(), "tenant_b should not see tenant_a conversation");
}

#[tokio::test]
async fn delete_existing_conversation() {
    let store = make_store().await;
    let record = ConversationRecord {
        conversation_id: "conv_1".to_owned(),
        tenant_id: "tenant_a".to_owned(),
        messages: json!([]),
    };
    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let deleted = store
        .delete_conversation("tenant_a", "conv_1")
        .await
        .expect("delete should succeed");

    assert!(deleted, "delete should return true for existing conversation");

    let fetched = store
        .get_conversation("tenant_a", "conv_1")
        .await
        .expect("get should succeed");

    assert!(fetched.is_none(), "deleted conversation should not be retrievable");
}

#[tokio::test]
async fn delete_missing_conversation_returns_false() {
    let store = make_store().await;

    let deleted = store
        .delete_conversation("tenant_a", "nonexistent")
        .await
        .expect("delete should succeed");

    assert!(!deleted, "delete should return false for missing conversation");
}

#[tokio::test]
async fn delete_conversation_tenant_isolation() {
    let store = make_store().await;
    let record = ConversationRecord {
        conversation_id: "conv_1".to_owned(),
        tenant_id: "tenant_a".to_owned(),
        messages: json!([]),
    };
    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let deleted = store
        .delete_conversation("tenant_b", "conv_1")
        .await
        .expect("delete should succeed");

    assert!(!deleted, "tenant_b should not be able to delete tenant_a conversation");

    let still_exists = store
        .get_conversation("tenant_a", "conv_1")
        .await
        .expect("get should succeed");

    assert!(
        still_exists.is_some(),
        "conversation should still exist after cross-tenant delete attempt"
    );
}

// -----------------------------------------------------------------------------
// Registry
// -----------------------------------------------------------------------------

#[tokio::test]
async fn registry_register_and_get() {
    let registry = ResponseStoreRegistry::new();
    let store: Arc<dyn ResponseStore> = Arc::new(make_store().await);
    registry
        .register(&Arc::from("primary"), Arc::clone(&store))
        .expect("register should succeed");

    let fetched = registry.get("primary");
    assert!(fetched.is_some(), "registered store should be retrievable");
}

#[test]
fn registry_get_missing_returns_none() {
    let registry = ResponseStoreRegistry::new();
    assert!(
        registry.get("nonexistent").is_none(),
        "get on empty registry should return None"
    );
}

#[tokio::test]
async fn registry_duplicate_registration_fails() {
    let registry = ResponseStoreRegistry::new();
    let store: Arc<dyn ResponseStore> = Arc::new(make_store().await);
    let name = Arc::from("dup");
    registry
        .register(&name, Arc::clone(&store))
        .expect("first register should succeed");

    let result = registry.register(&name, store);
    assert!(
        matches!(result, Err(StoreError::Unavailable(_))),
        "duplicate registration should return StoreError::Unavailable"
    );
}

#[test]
fn registry_default_is_empty() {
    let registry = ResponseStoreRegistry::default();
    assert!(
        registry.get("anything").is_none(),
        "default registry should have no stores"
    );
}

// -----------------------------------------------------------------------------
// PostgreSQL Backend (requires running instance, DATABASE_URL env var)
// -----------------------------------------------------------------------------

fn pg_database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for Postgres tests")
}

fn pg_unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tid = std::thread::current().id();
    format!("{id}_{tid:?}").replace(|c: char| !c.is_ascii_alphanumeric() && c != '_', "_")
}

#[test]
fn pg_ssl_mode_deserializes_verified_modes() {
    let verify_ca: SslMode = serde_json::from_str("\"verify-ca\"").expect("verify-ca should deserialize");
    let verify_full: SslMode = serde_json::from_str("\"verify-full\"").expect("verify-full should deserialize");

    assert!(matches!(verify_ca, SslMode::VerifyCa), "verify-ca should be supported");
    assert!(
        matches!(verify_full, SslMode::VerifyFull),
        "verify-full should be supported"
    );
}

#[test]
fn pg_ssl_mode_converts_to_pg_ssl_mode() {
    use sqlx::postgres::PgSslMode;

    assert!(
        matches!(PgSslMode::from(SslMode::Disable), PgSslMode::Disable),
        "Disable should map"
    );
    assert!(
        matches!(PgSslMode::from(SslMode::Prefer), PgSslMode::Prefer),
        "Prefer should map"
    );
    assert!(
        matches!(PgSslMode::from(SslMode::Require), PgSslMode::Require),
        "Require should map"
    );
    assert!(
        matches!(PgSslMode::from(SslMode::VerifyCa), PgSslMode::VerifyCa),
        "VerifyCa should map"
    );
    assert!(
        matches!(PgSslMode::from(SslMode::VerifyFull), PgSslMode::VerifyFull),
        "VerifyFull should map"
    );
}

#[tokio::test]
#[ignore]
async fn pg_nonexistent_ssl_root_cert_fails() {
    let url = pg_database_url();
    let suffix = pg_unique_suffix();
    let result = PostgresResponseStore::new(
        &url,
        &format!("test_responses_{suffix}"),
        &format!("test_conversations_{suffix}"),
        Some(SslMode::VerifyCa),
        Some("/nonexistent/ca.pem"),
    )
    .await;

    let Err(err) = result else {
        panic!("nonexistent ssl_root_cert should fail");
    };
    assert!(
        matches!(err, StoreError::Database(_)),
        "error should be StoreError::Database: {err}"
    );
}

async fn make_pg_store() -> PostgresResponseStore {
    let url = pg_database_url();
    let suffix = pg_unique_suffix();
    PostgresResponseStore::new(
        &url,
        &format!("test_responses_{suffix}"),
        &format!("test_conversations_{suffix}"),
        Some(SslMode::Disable),
        None,
    )
    .await
    .expect("postgres store creation should succeed")
}

#[tokio::test]
#[ignore]
async fn pg_store_initializes_schema() {
    let store = make_pg_store().await;


    let result = store
        .get_response("tenant_a", "nonexistent")
        .await
        .expect("get should succeed");

    assert!(result.is_none(), "empty store should return None");
}

#[tokio::test]
#[ignore]
async fn pg_upsert_and_get_response() {
    let store = make_pg_store().await;

    let record = make_response_record("resp_1", "tenant_a", 1000);

    store.upsert_response(&record).await.expect("upsert should succeed");

    let fetched = store
        .get_response("tenant_a", "resp_1")
        .await
        .expect("get should succeed")
        .expect("record should exist");

    assert_eq!(fetched.id, "resp_1", "ID should match");
    assert_eq!(fetched.tenant_id, "tenant_a", "tenant should match");
    assert_eq!(fetched.created_at, 1000, "created_at should match");
    assert_eq!(fetched.model, "gpt-4.1", "model should match");
    assert_eq!(
        fetched.response_object,
        json!({"status": "completed"}),
        "response_object should match"
    );
}

#[tokio::test]
#[ignore]
async fn pg_upsert_overwrites_existing_response() {
    let store = make_pg_store().await;

    let record = make_response_record("resp_1", "tenant_a", 1000);
    store
        .upsert_response(&record)
        .await
        .expect("first upsert should succeed");

    let updated = ResponseRecord {
        model: "gpt-4.1-mini".to_owned(),
        response_object: json!({"status": "incomplete"}),
        ..make_response_record("resp_1", "tenant_a", 1000)
    };
    store
        .upsert_response(&updated)
        .await
        .expect("second upsert should succeed");

    let fetched = store
        .get_response("tenant_a", "resp_1")
        .await
        .expect("get should succeed")
        .expect("record should exist");

    assert_eq!(fetched.model, "gpt-4.1-mini", "model should be updated");
    assert_eq!(
        fetched.response_object,
        json!({"status": "incomplete"}),
        "response_object should be updated"
    );
}

#[tokio::test]
#[ignore]
async fn pg_delete_existing_response() {
    let store = make_pg_store().await;

    let record = make_response_record("resp_1", "tenant_a", 1000);
    store.upsert_response(&record).await.expect("upsert should succeed");

    let deleted = store
        .delete_response("tenant_a", "resp_1")
        .await
        .expect("delete should succeed");

    assert!(deleted, "delete should return true for existing record");

    let fetched = store
        .get_response("tenant_a", "resp_1")
        .await
        .expect("get should succeed");

    assert!(fetched.is_none(), "deleted record should not be retrievable");
}

#[tokio::test]
#[ignore]
async fn pg_delete_missing_response_returns_false() {
    let store = make_pg_store().await;


    let deleted = store
        .delete_response("tenant_a", "nonexistent")
        .await
        .expect("delete should succeed");

    assert!(!deleted, "delete should return false for missing record");
}

#[tokio::test]
#[ignore]
async fn pg_tenant_isolation_on_get() {
    let store = make_pg_store().await;

    let record = make_response_record("resp_1", "tenant_a", 1000);
    store.upsert_response(&record).await.expect("upsert should succeed");

    let result = store
        .get_response("tenant_b", "resp_1")
        .await
        .expect("get should succeed");

    assert!(result.is_none(), "tenant_b should not see tenant_a records");
}

#[tokio::test]
#[ignore]
async fn pg_tenant_isolation_on_delete() {
    let store = make_pg_store().await;

    let record = make_response_record("resp_1", "tenant_a", 1000);
    store.upsert_response(&record).await.expect("upsert should succeed");

    let deleted = store
        .delete_response("tenant_b", "resp_1")
        .await
        .expect("delete should succeed");

    assert!(!deleted, "tenant_b should not be able to delete tenant_a records");

    let still_exists = store
        .get_response("tenant_a", "resp_1")
        .await
        .expect("get should succeed");

    assert!(
        still_exists.is_some(),
        "record should still exist after cross-tenant delete attempt"
    );
}

#[tokio::test]
#[ignore]
async fn pg_same_response_id_can_exist_in_multiple_tenants() {
    let store = make_pg_store().await;

    store
        .upsert_response(&make_response_record("resp_shared", "tenant_a", 1000))
        .await
        .expect("tenant_a upsert should succeed");
    store
        .upsert_response(&make_response_record("resp_shared", "tenant_b", 2000))
        .await
        .expect("tenant_b upsert should succeed");

    let tenant_a = store
        .get_response("tenant_a", "resp_shared")
        .await
        .expect("tenant_a get should succeed")
        .expect("tenant_a record should exist");
    let tenant_b = store
        .get_response("tenant_b", "resp_shared")
        .await
        .expect("tenant_b get should succeed")
        .expect("tenant_b record should exist");

    assert_eq!(tenant_a.tenant_id, "tenant_a", "tenant_a record should be isolated");
    assert_eq!(tenant_b.tenant_id, "tenant_b", "tenant_b record should be isolated");
    assert_eq!(tenant_a.created_at, 1000, "tenant_a record should not be overwritten");
    assert_eq!(tenant_b.created_at, 2000, "tenant_b record should not be overwritten");
}

#[tokio::test]
#[ignore]
async fn pg_upsert_and_get_conversation() {
    let store = make_pg_store().await;

    let record = ConversationRecord {
        conversation_id: "conv_1".to_owned(),
        tenant_id: "tenant_a".to_owned(),
        messages: json!([{"role": "user", "content": "Hi"}]),
    };

    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let fetched = store
        .get_conversation("tenant_a", "conv_1")
        .await
        .expect("get should succeed")
        .expect("record should exist");

    assert_eq!(fetched.conversation_id, "conv_1", "conversation_id should match");
    assert_eq!(
        fetched.messages,
        json!([{"role": "user", "content": "Hi"}]),
        "messages should match"
    );
}

#[tokio::test]
#[ignore]
async fn pg_upsert_conversation_overwrites() {
    let store = make_pg_store().await;

    let record = ConversationRecord {
        conversation_id: "conv_1".to_owned(),
        tenant_id: "tenant_a".to_owned(),
        messages: json!([{"role": "user", "content": "v1"}]),
    };
    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let updated = ConversationRecord {
        messages: json!([{"role": "user", "content": "v2"}]),
        ..record
    };
    store
        .upsert_conversation(&updated)
        .await
        .expect("second upsert should succeed");

    let fetched = store
        .get_conversation("tenant_a", "conv_1")
        .await
        .expect("get should succeed")
        .expect("record should exist");

    assert_eq!(
        fetched.messages,
        json!([{"role": "user", "content": "v2"}]),
        "messages should be updated"
    );
}

#[tokio::test]
#[ignore]
async fn pg_delete_existing_conversation() {
    let store = make_pg_store().await;

    let record = ConversationRecord {
        conversation_id: "conv_1".to_owned(),
        tenant_id: "tenant_a".to_owned(),
        messages: json!([]),
    };
    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let deleted = store
        .delete_conversation("tenant_a", "conv_1")
        .await
        .expect("delete should succeed");

    assert!(deleted, "delete should return true for existing conversation");

    let fetched = store
        .get_conversation("tenant_a", "conv_1")
        .await
        .expect("get should succeed");

    assert!(fetched.is_none(), "deleted conversation should not be retrievable");
}

#[tokio::test]
#[ignore]
async fn pg_conversation_tenant_isolation() {
    let store = make_pg_store().await;

    let record = ConversationRecord {
        conversation_id: "conv_1".to_owned(),
        tenant_id: "tenant_a".to_owned(),
        messages: json!([]),
    };
    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let result = store
        .get_conversation("tenant_b", "conv_1")
        .await
        .expect("get should succeed");

    assert!(result.is_none(), "tenant_b should not see tenant_a conversation");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

async fn make_store() -> SqliteResponseStore {
    SqliteResponseStore::new("sqlite::memory:", "test_responses", "test_conversation_messages")
        .await
        .expect("store creation should succeed")
}

fn make_response_record(id: &str, tenant_id: &str, created_at: i64) -> ResponseRecord {
    ResponseRecord {
        id: id.to_owned(),
        tenant_id: tenant_id.to_owned(),
        created_at,
        model: "gpt-4.1".to_owned(),
        response_object: json!({"status": "completed"}),
        input: json!("test input"),
        messages: json!([{"role": "user", "content": "hello"}]),
    }
}
