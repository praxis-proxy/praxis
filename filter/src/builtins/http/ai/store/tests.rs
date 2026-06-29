// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for the response store persistence layer.

use std::sync::Arc;

use serde_json::json;

use super::{
    ConversationItemRecord, ConversationRecord, PostgresResponseStore, ResponseRecord, ResponseStoreRegistry,
    SqliteResponseStore, SslMode, StoreError,
    trait_def::{ConversationItemStore, ResponseStore},
};
use crate::builtins::http::ai::openai::responses::store::{ListParams, Order, list_input_items};

// -----------------------------------------------------------------------------
// Schema Initialization
// -----------------------------------------------------------------------------

#[tokio::test]
async fn sqlite_store_initializes_schema() {
    let store = SqliteResponseStore::new("sqlite::memory:", "test_responses", "test_conversation_messages", None)
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
        created_at: 1000,
        metadata: json!({}),
        messages: json!([{"role": "user", "content": "Hi"}]),
    };

    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let fetched = ResponseStore::get_conversation(&store, "tenant_a", "conv_1")
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
        created_at: 1000,
        metadata: json!({}),
        messages: json!([{"role": "user", "content": "v1"}]),
    };
    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let updated = ConversationRecord {
        conversation_id: "conv_1".to_owned(),
        tenant_id: "tenant_a".to_owned(),
        created_at: 2000,
        metadata: json!({"topic": "updated"}),
        messages: json!([{"role": "user", "content": "v2"}]),
    };
    store
        .upsert_conversation(&updated)
        .await
        .expect("second upsert should succeed");

    let fetched = ConversationItemStore::get_conversation(&store, "tenant_a", "conv_1")
        .await
        .expect("get should succeed")
        .expect("record should exist");

    assert_eq!(
        fetched.messages,
        json!([{"role": "user", "content": "v2"}]),
        "messages should be updated"
    );
    assert_eq!(
        fetched.metadata,
        json!({"topic": "updated"}),
        "metadata should be updated"
    );
    assert_eq!(fetched.created_at, 1000, "created_at should preserve creation time");
}

#[tokio::test]
async fn get_missing_conversation_returns_none() {
    let store = make_store().await;

    let result = ConversationItemStore::get_conversation(&store, "tenant_a", "nonexistent")
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
        created_at: 1000,
        metadata: json!({}),
        messages: json!([]),
    };
    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let result = ConversationItemStore::get_conversation(&store, "tenant_b", "conv_1")
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
        created_at: 1000,
        metadata: json!({}),
        messages: json!([]),
    };
    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let deleted = store
        .delete_conversation("tenant_a", "conv_1")
        .await
        .expect("delete should succeed");

    assert!(deleted, "delete should return true for existing conversation");

    let fetched = ConversationItemStore::get_conversation(&store, "tenant_a", "conv_1")
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
        created_at: 1000,
        metadata: json!({}),
        messages: json!([]),
    };
    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let deleted = store
        .delete_conversation("tenant_b", "conv_1")
        .await
        .expect("delete should succeed");

    assert!(!deleted, "tenant_b should not be able to delete tenant_a conversation");

    let still_exists = ConversationItemStore::get_conversation(&store, "tenant_a", "conv_1")
        .await
        .expect("get should succeed");

    assert!(
        still_exists.is_some(),
        "conversation should still exist after cross-tenant delete attempt"
    );
}

// -----------------------------------------------------------------------------
// Conversation Item CRUD (SQLite)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn conversation_items_paginate_ascending_and_descending() {
    let store = make_store_with_items().await;
    let items = [
        make_conversation_item("item_1", "tenant_a", "conv_1", 1),
        make_conversation_item("item_2", "tenant_a", "conv_1", 2),
        make_conversation_item("item_3", "tenant_a", "conv_1", 3),
        make_conversation_item("item_4", "tenant_a", "conv_1", 4),
    ];
    store
        .create_conversation_items(&items)
        .await
        .expect("item insert should succeed");

    let asc = store
        .list_conversation_items("tenant_a", "conv_1", None, 2, true)
        .await
        .expect("ascending list should succeed");
    assert_item_ids(&asc, &["item_1", "item_2"]);

    let asc_page2 = store
        .list_conversation_items("tenant_a", "conv_1", Some("item_2"), 2, true)
        .await
        .expect("ascending page 2 should succeed");
    assert_item_ids(&asc_page2, &["item_3", "item_4"]);

    let desc = store
        .list_conversation_items("tenant_a", "conv_1", None, 2, false)
        .await
        .expect("descending list should succeed");
    assert_item_ids(&desc, &["item_4", "item_3"]);

    let desc_page2 = store
        .list_conversation_items("tenant_a", "conv_1", Some("item_3"), 2, false)
        .await
        .expect("descending page 2 should succeed");
    assert_item_ids(&desc_page2, &["item_2", "item_1"]);
}

#[tokio::test]
async fn conversation_items_paginate_duplicate_positions() {
    let store = make_store_with_items().await;
    let items = [
        make_conversation_item("item_a", "tenant_a", "conv_1", 1),
        make_conversation_item("item_b", "tenant_a", "conv_1", 1),
        make_conversation_item("item_c", "tenant_a", "conv_1", 1),
        make_conversation_item("item_d", "tenant_a", "conv_1", 2),
    ];
    store
        .create_conversation_items(&items)
        .await
        .expect("item insert should succeed");

    let page1 = store
        .list_conversation_items("tenant_a", "conv_1", None, 2, true)
        .await
        .expect("page 1 should succeed");
    assert_item_ids(&page1, &["item_a", "item_b"]);

    let page2 = store
        .list_conversation_items("tenant_a", "conv_1", Some("item_b"), 2, true)
        .await
        .expect("page 2 should succeed");
    assert_item_ids(&page2, &["item_c", "item_d"]);
}

#[tokio::test]
async fn conversation_item_single_ops_scope_to_conversation() {
    let store = make_store_with_items().await;
    let item_conv1 = make_conversation_item("item_1", "tenant_a", "conv_1", 1);
    let item_conv2 = make_conversation_item("item_2", "tenant_a", "conv_2", 1);
    store
        .create_conversation_items(&[item_conv1, item_conv2])
        .await
        .expect("item insert should succeed");

    let get_wrong_conv = store
        .get_conversation_item("tenant_a", "conv_2", "item_1")
        .await
        .expect("get should succeed");
    assert!(get_wrong_conv.is_none(), "item_1 should not be visible in conv_2");

    let delete_wrong_conv = store
        .delete_conversation_item("tenant_a", "conv_2", "item_1")
        .await
        .expect("delete should succeed");
    assert!(!delete_wrong_conv, "deleting item_1 from conv_2 should return false");

    let still_exists = store
        .get_conversation_item("tenant_a", "conv_1", "item_1")
        .await
        .expect("get should succeed");
    assert!(still_exists.is_some(), "item_1 should still exist in conv_1");
}

#[tokio::test]
async fn max_item_position_returns_zero_when_empty() {
    let store = make_store_with_items().await;
    let max = store
        .max_item_position("tenant_a", "conv_1")
        .await
        .expect("max_item_position should succeed");
    assert_eq!(max, 0, "empty conversation should have max position 0");
}

#[tokio::test]
async fn max_item_position_returns_highest() {
    let store = make_store_with_items().await;
    let items = [
        make_conversation_item("item_1", "tenant_a", "conv_1", 5),
        make_conversation_item("item_2", "tenant_a", "conv_1", 10),
        make_conversation_item("item_3", "tenant_a", "conv_1", 3),
    ];
    store
        .create_conversation_items(&items)
        .await
        .expect("item insert should succeed");

    let max = store
        .max_item_position("tenant_a", "conv_1")
        .await
        .expect("max_item_position should succeed");
    assert_eq!(max, 10, "max position should be 10");
}

#[tokio::test]
async fn delete_conversation_items_removes_all() {
    let store = make_store_with_items().await;
    let items = [
        make_conversation_item("item_1", "tenant_a", "conv_1", 1),
        make_conversation_item("item_2", "tenant_a", "conv_1", 2),
    ];
    store
        .create_conversation_items(&items)
        .await
        .expect("item insert should succeed");

    store
        .delete_conversation_items("tenant_a", "conv_1")
        .await
        .expect("delete_conversation_items should succeed");

    let remaining = store
        .list_conversation_items("tenant_a", "conv_1", None, 100, true)
        .await
        .expect("list should succeed");
    assert!(remaining.is_empty(), "all items should be deleted");
}

#[tokio::test]
async fn conversation_item_tenant_isolation() {
    let store = make_store_with_items().await;
    let item = make_conversation_item("item_1", "tenant_a", "conv_1", 1);
    store
        .create_conversation_items(&[item])
        .await
        .expect("item insert should succeed");

    let cross_tenant = store
        .get_conversation_item("tenant_b", "conv_1", "item_1")
        .await
        .expect("cross-tenant get should succeed");
    assert!(cross_tenant.is_none(), "tenant_b should not see tenant_a items");

    let cross_tenant_list = store
        .list_conversation_items("tenant_b", "conv_1", None, 100, true)
        .await
        .expect("cross-tenant list should succeed");
    assert!(cross_tenant_list.is_empty(), "tenant_b should see no items");
}

#[tokio::test]
async fn conversation_item_upsert_updates_existing() {
    let store = make_store_with_items().await;
    let original = make_conversation_item("item_1", "tenant_a", "conv_1", 1);
    let updated = ConversationItemRecord {
        item_data: json!({"type": "message", "role": "assistant", "content": "updated"}),
        created_at: 2000,
        position: 2,
        ..make_conversation_item("item_1", "tenant_a", "conv_1", 1)
    };

    store
        .create_conversation_items(&[original])
        .await
        .expect("initial item insert should succeed");
    store
        .create_conversation_items(&[updated])
        .await
        .expect("duplicate item insert should upsert");

    let fetched = store
        .get_conversation_item("tenant_a", "conv_1", "item_1")
        .await
        .expect("get should succeed")
        .expect("item should exist after upsert");

    assert_eq!(fetched.position, 2, "upsert should update position");
    assert_eq!(fetched.created_at, 2000, "upsert should update created_at");
    assert_eq!(
        fetched.item_data,
        json!({"type": "message", "role": "assistant", "content": "updated"}),
        "upsert should update item data"
    );
}

#[tokio::test]
async fn conversation_item_upsert_allows_same_item_id_in_different_conversations() {
    let store = make_store_with_items().await;
    let item_conv1 = ConversationItemRecord {
        item_data: json!({"conversation": "conv_1"}),
        ..make_conversation_item("item_shared", "tenant_a", "conv_1", 1)
    };
    let item_conv2 = ConversationItemRecord {
        item_data: json!({"conversation": "conv_2"}),
        ..make_conversation_item("item_shared", "tenant_a", "conv_2", 1)
    };

    store
        .create_conversation_items(&[item_conv1])
        .await
        .expect("initial item insert should succeed");
    store
        .create_conversation_items(&[item_conv2])
        .await
        .expect("same item_id in another conversation should insert");

    let conv1_item = store
        .get_conversation_item("tenant_a", "conv_1", "item_shared")
        .await
        .expect("conv_1 get should succeed")
        .expect("conv_1 item should still exist");
    let conv2_item = store
        .get_conversation_item("tenant_a", "conv_2", "item_shared")
        .await
        .expect("conv_2 get should succeed")
        .expect("conv_2 item should exist");

    assert_eq!(conv1_item.conversation_id, "conv_1", "conv_1 row should remain scoped");
    assert_eq!(conv2_item.conversation_id, "conv_2", "conv_2 row should be inserted");
    assert_eq!(
        conv1_item.item_data,
        json!({"conversation": "conv_1"}),
        "conv_1 item data should not be overwritten"
    );
    assert_eq!(
        conv2_item.item_data,
        json!({"conversation": "conv_2"}),
        "conv_2 item data should be stored separately"
    );

    let conv1_items = store
        .list_conversation_items("tenant_a", "conv_1", None, 100, true)
        .await
        .expect("conv_1 list should succeed");
    let conv2_items = store
        .list_conversation_items("tenant_a", "conv_2", None, 100, true)
        .await
        .expect("conv_2 list should succeed");
    assert_item_ids(&conv1_items, &["item_shared"]);
    assert_item_ids(&conv2_items, &["item_shared"]);
}

#[tokio::test]
async fn get_conversation_item_returns_all_fields() {
    let store = make_store_with_items().await;
    let item = ConversationItemRecord {
        item_id: "item_99".to_owned(),
        tenant_id: "tenant_a".to_owned(),
        conversation_id: "conv_1".to_owned(),
        item_data: json!({"type": "function_call", "name": "search"}),
        created_at: 5000,
        position: 42,
    };
    store
        .create_conversation_items(&[item])
        .await
        .expect("item insert should succeed");

    let fetched = store
        .get_conversation_item("tenant_a", "conv_1", "item_99")
        .await
        .expect("get should succeed")
        .expect("item should exist");

    assert_eq!(fetched.item_id, "item_99", "item_id should match");
    assert_eq!(fetched.tenant_id, "tenant_a", "tenant_id should match");
    assert_eq!(fetched.conversation_id, "conv_1", "conversation_id should match");
    assert_eq!(
        fetched.item_data,
        json!({"type": "function_call", "name": "search"}),
        "item_data should round-trip"
    );
    assert_eq!(fetched.created_at, 5000, "created_at should match");
    assert_eq!(fetched.position, 42, "position should match");
}

#[tokio::test]
async fn list_conversation_items_nonexistent_cursor_returns_empty() {
    let store = make_store_with_items().await;
    let item = make_conversation_item("item_1", "tenant_a", "conv_1", 1);
    store
        .create_conversation_items(&[item])
        .await
        .expect("item insert should succeed");

    let result = store
        .list_conversation_items("tenant_a", "conv_1", Some("nonexistent"), 10, true)
        .await
        .expect("list with nonexistent cursor should succeed");

    assert!(result.is_empty(), "nonexistent cursor item should return empty list");
}

#[tokio::test]
async fn delete_conversation_cascades_to_items() {
    let store = make_store_with_items().await;
    let conv = ConversationRecord {
        conversation_id: "conv_1".to_owned(),
        tenant_id: "tenant_a".to_owned(),
        created_at: 1000,
        metadata: json!({}),
        messages: json!([]),
    };
    store
        .upsert_conversation(&conv)
        .await
        .expect("conversation upsert should succeed");

    let items = [
        make_conversation_item("item_1", "tenant_a", "conv_1", 1),
        make_conversation_item("item_2", "tenant_a", "conv_1", 2),
    ];
    store
        .create_conversation_items(&items)
        .await
        .expect("item insert should succeed");

    let deleted = store
        .delete_conversation("tenant_a", "conv_1")
        .await
        .expect("delete_conversation should succeed");
    assert!(deleted, "conversation should have been deleted");

    let remaining = store
        .list_conversation_items("tenant_a", "conv_1", None, 100, true)
        .await
        .expect("list should succeed");
    assert!(
        remaining.is_empty(),
        "items should be cascade-deleted with conversation"
    );
}

#[tokio::test]
async fn conversation_item_methods_fail_without_items_table() {
    let store = make_store().await;
    let item = make_conversation_item("item_1", "tenant_a", "conv_1", 1);

    let err = store.create_conversation_items(&[item]).await.unwrap_err();
    assert!(
        matches!(err, StoreError::Unavailable(_)),
        "create should return Unavailable"
    );

    let err = store
        .list_conversation_items("tenant_a", "conv_1", None, 10, true)
        .await
        .unwrap_err();
    assert!(
        matches!(err, StoreError::Unavailable(_)),
        "list should return Unavailable"
    );

    let err = store
        .get_conversation_item("tenant_a", "conv_1", "item_1")
        .await
        .unwrap_err();
    assert!(
        matches!(err, StoreError::Unavailable(_)),
        "get should return Unavailable"
    );

    let err = store
        .delete_conversation_item("tenant_a", "conv_1", "item_1")
        .await
        .unwrap_err();
    assert!(
        matches!(err, StoreError::Unavailable(_)),
        "delete_item should return Unavailable"
    );

    let err = store
        .conversation_item_position("tenant_a", "conv_1", "item_1")
        .await
        .unwrap_err();
    assert!(
        matches!(err, StoreError::Unavailable(_)),
        "position should return Unavailable"
    );

    let err = store.max_item_position("tenant_a", "conv_1").await.unwrap_err();
    assert!(
        matches!(err, StoreError::Unavailable(_)),
        "max_position should return Unavailable"
    );

    let err = store.delete_conversation_items("tenant_a", "conv_1").await.unwrap_err();
    assert!(
        matches!(err, StoreError::Unavailable(_)),
        "delete_items should return Unavailable"
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

#[test]
fn registry_clone_shares_storage() {
    let registry = ResponseStoreRegistry::new();
    let cloned = registry.clone();
    assert!(
        registry.shares_storage_with(&cloned),
        "cloned registry handles should share backing storage"
    );
}

#[test]
fn registry_new_has_independent_storage() {
    let first = ResponseStoreRegistry::new();
    let second = ResponseStoreRegistry::new();
    assert!(
        !first.shares_storage_with(&second),
        "independent registries should not share backing storage"
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
    let result = Box::pin(PostgresResponseStore::new(
        &url,
        &format!("test_responses_{suffix}"),
        &format!("test_conversations_{suffix}"),
        None,
        Some(SslMode::VerifyCa),
        Some("/nonexistent/ca.pem"),
    ))
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
    Box::pin(PostgresResponseStore::new(
        &url,
        &format!("test_responses_{suffix}"),
        &format!("test_conversations_{suffix}"),
        None,
        Some(SslMode::Disable),
        None,
    ))
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
        created_at: 1000,
        metadata: json!({}),
        messages: json!([{"role": "user", "content": "Hi"}]),
    };

    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let fetched = ResponseStore::get_conversation(&store, "tenant_a", "conv_1")
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
        created_at: 1000,
        metadata: json!({}),
        messages: json!([{"role": "user", "content": "v1"}]),
    };
    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let updated = ConversationRecord {
        conversation_id: "conv_1".to_owned(),
        tenant_id: "tenant_a".to_owned(),
        created_at: 2000,
        metadata: json!({"topic": "updated"}),
        messages: json!([{"role": "user", "content": "v2"}]),
    };
    store
        .upsert_conversation(&updated)
        .await
        .expect("second upsert should succeed");

    let fetched = ConversationItemStore::get_conversation(&store, "tenant_a", "conv_1")
        .await
        .expect("get should succeed")
        .expect("record should exist");

    assert_eq!(
        fetched.messages,
        json!([{"role": "user", "content": "v2"}]),
        "messages should be updated"
    );
    assert_eq!(
        fetched.metadata,
        json!({"topic": "updated"}),
        "metadata should be updated"
    );
    assert_eq!(fetched.created_at, 1000, "created_at should preserve creation time");
}

#[tokio::test]
#[ignore]
async fn pg_delete_existing_conversation() {
    let store = make_pg_store().await;

    let record = ConversationRecord {
        conversation_id: "conv_1".to_owned(),
        tenant_id: "tenant_a".to_owned(),
        created_at: 1000,
        metadata: json!({}),
        messages: json!([]),
    };
    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let deleted = store
        .delete_conversation("tenant_a", "conv_1")
        .await
        .expect("delete should succeed");

    assert!(deleted, "delete should return true for existing conversation");

    let fetched = ConversationItemStore::get_conversation(&store, "tenant_a", "conv_1")
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
        created_at: 1000,
        metadata: json!({}),
        messages: json!([]),
    };
    store.upsert_conversation(&record).await.expect("upsert should succeed");

    let result = ConversationItemStore::get_conversation(&store, "tenant_b", "conv_1")
        .await
        .expect("get should succeed");

    assert!(result.is_none(), "tenant_b should not see tenant_a conversation");
}

// -----------------------------------------------------------------------------
// Conversation Item CRUD (PostgreSQL)
// -----------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn pg_conversation_items_paginate_ascending_and_descending() {
    let store = make_pg_store_with_items().await;
    let items = [
        make_conversation_item("item_1", "tenant_a", "conv_1", 1),
        make_conversation_item("item_2", "tenant_a", "conv_1", 2),
        make_conversation_item("item_3", "tenant_a", "conv_1", 3),
        make_conversation_item("item_4", "tenant_a", "conv_1", 4),
    ];
    store
        .create_conversation_items(&items)
        .await
        .expect("item insert should succeed");

    let asc = store
        .list_conversation_items("tenant_a", "conv_1", None, 2, true)
        .await
        .expect("ascending list should succeed");
    assert_item_ids(&asc, &["item_1", "item_2"]);

    let asc_page2 = store
        .list_conversation_items("tenant_a", "conv_1", Some("item_2"), 2, true)
        .await
        .expect("ascending page 2 should succeed");
    assert_item_ids(&asc_page2, &["item_3", "item_4"]);

    let desc = store
        .list_conversation_items("tenant_a", "conv_1", None, 2, false)
        .await
        .expect("descending list should succeed");
    assert_item_ids(&desc, &["item_4", "item_3"]);

    let desc_page2 = store
        .list_conversation_items("tenant_a", "conv_1", Some("item_3"), 2, false)
        .await
        .expect("descending page 2 should succeed");
    assert_item_ids(&desc_page2, &["item_2", "item_1"]);
}

#[tokio::test]
#[ignore]
async fn pg_conversation_items_paginate_duplicate_positions() {
    let store = make_pg_store_with_items().await;
    let items = [
        make_conversation_item("item_a", "tenant_a", "conv_1", 1),
        make_conversation_item("item_b", "tenant_a", "conv_1", 1),
        make_conversation_item("item_c", "tenant_a", "conv_1", 1),
        make_conversation_item("item_d", "tenant_a", "conv_1", 2),
    ];
    store
        .create_conversation_items(&items)
        .await
        .expect("item insert should succeed");

    let page1 = store
        .list_conversation_items("tenant_a", "conv_1", None, 2, true)
        .await
        .expect("page 1 should succeed");
    assert_item_ids(&page1, &["item_a", "item_b"]);

    let page2 = store
        .list_conversation_items("tenant_a", "conv_1", Some("item_b"), 2, true)
        .await
        .expect("page 2 should succeed");
    assert_item_ids(&page2, &["item_c", "item_d"]);
}

#[tokio::test]
#[ignore]
async fn pg_conversation_item_single_ops_scope_to_conversation() {
    let store = make_pg_store_with_items().await;
    let item_conv1 = make_conversation_item("item_1", "tenant_a", "conv_1", 1);
    let item_conv2 = make_conversation_item("item_2", "tenant_a", "conv_2", 1);
    store
        .create_conversation_items(&[item_conv1, item_conv2])
        .await
        .expect("item insert should succeed");

    let get_wrong_conv = store
        .get_conversation_item("tenant_a", "conv_2", "item_1")
        .await
        .expect("get should succeed");
    assert!(get_wrong_conv.is_none(), "item_1 should not be visible in conv_2");

    let delete_wrong_conv = store
        .delete_conversation_item("tenant_a", "conv_2", "item_1")
        .await
        .expect("delete should succeed");
    assert!(!delete_wrong_conv, "deleting item_1 from conv_2 should return false");

    let still_exists = store
        .get_conversation_item("tenant_a", "conv_1", "item_1")
        .await
        .expect("get should succeed");
    assert!(still_exists.is_some(), "item_1 should still exist in conv_1");
}

#[tokio::test]
#[ignore]
async fn pg_max_item_position_returns_zero_when_empty() {
    let store = make_pg_store_with_items().await;
    let max = store
        .max_item_position("tenant_a", "conv_1")
        .await
        .expect("max_item_position should succeed");
    assert_eq!(max, 0, "empty conversation should have max position 0");
}

#[tokio::test]
#[ignore]
async fn pg_max_item_position_returns_highest() {
    let store = make_pg_store_with_items().await;
    let items = [
        make_conversation_item("item_1", "tenant_a", "conv_1", 5),
        make_conversation_item("item_2", "tenant_a", "conv_1", 10),
        make_conversation_item("item_3", "tenant_a", "conv_1", 3),
    ];
    store
        .create_conversation_items(&items)
        .await
        .expect("item insert should succeed");

    let max = store
        .max_item_position("tenant_a", "conv_1")
        .await
        .expect("max_item_position should succeed");
    assert_eq!(max, 10, "max position should be 10");
}

#[tokio::test]
#[ignore]
async fn pg_delete_conversation_items_removes_all() {
    let store = make_pg_store_with_items().await;
    let items = [
        make_conversation_item("item_1", "tenant_a", "conv_1", 1),
        make_conversation_item("item_2", "tenant_a", "conv_1", 2),
    ];
    store
        .create_conversation_items(&items)
        .await
        .expect("item insert should succeed");

    store
        .delete_conversation_items("tenant_a", "conv_1")
        .await
        .expect("delete_conversation_items should succeed");

    let remaining = store
        .list_conversation_items("tenant_a", "conv_1", None, 100, true)
        .await
        .expect("list should succeed");
    assert!(remaining.is_empty(), "all items should be deleted");
}

#[tokio::test]
#[ignore]
async fn pg_conversation_item_tenant_isolation() {
    let store = make_pg_store_with_items().await;
    let item = make_conversation_item("item_1", "tenant_a", "conv_1", 1);
    store
        .create_conversation_items(&[item])
        .await
        .expect("item insert should succeed");

    let cross_tenant = store
        .get_conversation_item("tenant_b", "conv_1", "item_1")
        .await
        .expect("cross-tenant get should succeed");
    assert!(cross_tenant.is_none(), "tenant_b should not see tenant_a items");

    let cross_tenant_list = store
        .list_conversation_items("tenant_b", "conv_1", None, 100, true)
        .await
        .expect("cross-tenant list should succeed");
    assert!(cross_tenant_list.is_empty(), "tenant_b should see no items");
}

#[tokio::test]
#[ignore]
async fn pg_conversation_item_upsert_updates_existing() {
    let store = make_pg_store_with_items().await;
    let original = make_conversation_item("item_1", "tenant_a", "conv_1", 1);
    let updated = ConversationItemRecord {
        item_data: json!({"type": "message", "role": "assistant", "content": "updated"}),
        created_at: 2000,
        position: 2,
        ..make_conversation_item("item_1", "tenant_a", "conv_1", 1)
    };

    store
        .create_conversation_items(&[original])
        .await
        .expect("initial item insert should succeed");
    store
        .create_conversation_items(&[updated])
        .await
        .expect("duplicate item insert should upsert");

    let fetched = store
        .get_conversation_item("tenant_a", "conv_1", "item_1")
        .await
        .expect("get should succeed")
        .expect("item should exist after upsert");

    assert_eq!(fetched.position, 2, "upsert should update position");
    assert_eq!(fetched.created_at, 2000, "upsert should update created_at");
    assert_eq!(
        fetched.item_data,
        json!({"type": "message", "role": "assistant", "content": "updated"}),
        "upsert should update item data"
    );
}

#[tokio::test]
#[ignore]
async fn pg_conversation_item_upsert_allows_same_item_id_in_different_conversations() {
    let store = make_pg_store_with_items().await;
    let item_conv1 = ConversationItemRecord {
        item_data: json!({"conversation": "conv_1"}),
        ..make_conversation_item("item_shared", "tenant_a", "conv_1", 1)
    };
    let item_conv2 = ConversationItemRecord {
        item_data: json!({"conversation": "conv_2"}),
        ..make_conversation_item("item_shared", "tenant_a", "conv_2", 1)
    };

    store
        .create_conversation_items(&[item_conv1])
        .await
        .expect("initial item insert should succeed");
    store
        .create_conversation_items(&[item_conv2])
        .await
        .expect("same item_id in another conversation should insert");

    let conv1_item = store
        .get_conversation_item("tenant_a", "conv_1", "item_shared")
        .await
        .expect("conv_1 get should succeed")
        .expect("conv_1 item should still exist");
    let conv2_item = store
        .get_conversation_item("tenant_a", "conv_2", "item_shared")
        .await
        .expect("conv_2 get should succeed")
        .expect("conv_2 item should exist");

    assert_eq!(conv1_item.conversation_id, "conv_1", "conv_1 row should remain scoped");
    assert_eq!(conv2_item.conversation_id, "conv_2", "conv_2 row should be inserted");
    assert_eq!(
        conv1_item.item_data,
        json!({"conversation": "conv_1"}),
        "conv_1 item data should not be overwritten"
    );
    assert_eq!(
        conv2_item.item_data,
        json!({"conversation": "conv_2"}),
        "conv_2 item data should be stored separately"
    );

    let conv1_items = store
        .list_conversation_items("tenant_a", "conv_1", None, 100, true)
        .await
        .expect("conv_1 list should succeed");
    let conv2_items = store
        .list_conversation_items("tenant_a", "conv_2", None, 100, true)
        .await
        .expect("conv_2 list should succeed");
    assert_item_ids(&conv1_items, &["item_shared"]);
    assert_item_ids(&conv2_items, &["item_shared"]);
}

#[tokio::test]
#[ignore]
async fn pg_get_conversation_item_returns_all_fields() {
    let store = make_pg_store_with_items().await;
    let item = ConversationItemRecord {
        item_id: "item_99".to_owned(),
        tenant_id: "tenant_a".to_owned(),
        conversation_id: "conv_1".to_owned(),
        item_data: json!({"type": "function_call", "name": "search"}),
        created_at: 5000,
        position: 42,
    };
    store
        .create_conversation_items(&[item])
        .await
        .expect("item insert should succeed");

    let fetched = store
        .get_conversation_item("tenant_a", "conv_1", "item_99")
        .await
        .expect("get should succeed")
        .expect("item should exist");

    assert_eq!(fetched.item_id, "item_99", "item_id should match");
    assert_eq!(fetched.tenant_id, "tenant_a", "tenant_id should match");
    assert_eq!(fetched.conversation_id, "conv_1", "conversation_id should match");
    assert_eq!(
        fetched.item_data,
        json!({"type": "function_call", "name": "search"}),
        "item_data should round-trip"
    );
    assert_eq!(fetched.created_at, 5000, "created_at should match");
    assert_eq!(fetched.position, 42, "position should match");
}

#[tokio::test]
#[ignore]
async fn pg_list_conversation_items_nonexistent_cursor_returns_empty() {
    let store = make_pg_store_with_items().await;
    let item = make_conversation_item("item_1", "tenant_a", "conv_1", 1);
    store
        .create_conversation_items(&[item])
        .await
        .expect("item insert should succeed");

    let result = store
        .list_conversation_items("tenant_a", "conv_1", Some("nonexistent"), 10, true)
        .await
        .expect("list with nonexistent cursor should succeed");

    assert!(result.is_empty(), "nonexistent cursor item should return empty list");
}

#[tokio::test]
#[ignore]
async fn pg_delete_conversation_cascades_to_items() {
    let store = make_pg_store_with_items().await;
    let conv = ConversationRecord {
        conversation_id: "conv_1".to_owned(),
        tenant_id: "tenant_a".to_owned(),
        created_at: 1000,
        metadata: json!({}),
        messages: json!([]),
    };
    store
        .upsert_conversation(&conv)
        .await
        .expect("conversation upsert should succeed");

    let items = [
        make_conversation_item("item_1", "tenant_a", "conv_1", 1),
        make_conversation_item("item_2", "tenant_a", "conv_1", 2),
    ];
    store
        .create_conversation_items(&items)
        .await
        .expect("item insert should succeed");

    let deleted = store
        .delete_conversation("tenant_a", "conv_1")
        .await
        .expect("delete_conversation should succeed");
    assert!(deleted, "conversation should have been deleted");

    let remaining = store
        .list_conversation_items("tenant_a", "conv_1", None, 100, true)
        .await
        .expect("list should succeed");
    assert!(
        remaining.is_empty(),
        "items should be cascade-deleted with conversation"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

async fn make_store() -> SqliteResponseStore {
    SqliteResponseStore::new("sqlite::memory:", "test_responses", "test_conversation_messages", None)
        .await
        .expect("store creation should succeed")
}

async fn make_store_with_items() -> SqliteResponseStore {
    SqliteResponseStore::new(
        "sqlite::memory:",
        "test_responses",
        "test_conversation_messages",
        Some("test_conversation_items"),
    )
    .await
    .expect("store creation should succeed")
}

async fn make_pg_store_with_items() -> PostgresResponseStore {
    let url = pg_database_url();
    let suffix = pg_unique_suffix();
    let responses_table = format!("test_responses_{suffix}");
    let conversations_table = format!("test_conversations_{suffix}");
    let items_table = format!("test_conversation_items_{suffix}");
    PostgresResponseStore::new(
        &url,
        &responses_table,
        &conversations_table,
        Some(&items_table),
        Some(SslMode::Disable),
        None,
    )
    .await
    .expect("postgres store creation should succeed")
}

fn make_conversation_item(
    item_id: &str,
    tenant_id: &str,
    conversation_id: &str,
    position: i64,
) -> ConversationItemRecord {
    ConversationItemRecord {
        item_id: item_id.to_owned(),
        tenant_id: tenant_id.to_owned(),
        conversation_id: conversation_id.to_owned(),
        item_data: json!({"type": "message", "role": "user", "content": "test"}),
        created_at: 1000,
        position,
    }
}

fn assert_item_ids(items: &[ConversationItemRecord], expected: &[&str]) {
    let ids: Vec<&str> = items.iter().map(|i| i.item_id.as_str()).collect();
    assert_eq!(ids, expected, "item IDs should match expected order");
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
