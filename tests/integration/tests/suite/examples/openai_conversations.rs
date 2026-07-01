// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the `openai_conversations` example config.

use std::collections::HashMap;

use praxis_test_utils::{
    example_config_path, free_port, http_send, json_post, parse_body, parse_status, patch_yaml, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_and_get_conversation() {
    let proxy = start_test_proxy();

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/conversations", r#"{"metadata":{"env":"test"}}"#),
    );
    assert_eq!(parse_status(&raw), 200, "create should return 200");
    let body: serde_json::Value = serde_json::from_str(&parse_body(&raw)).unwrap();
    assert_eq!(body["object"], "conversation");
    let conv_id = body["id"].as_str().unwrap();
    assert!(conv_id.starts_with("conv_"), "ID should have conv_ prefix");

    let raw = http_send(
        proxy.addr(),
        &format!("GET /v1/conversations/{conv_id} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    );
    assert_eq!(parse_status(&raw), 200, "GET should return 200");
    let body: serde_json::Value = serde_json::from_str(&parse_body(&raw)).unwrap();
    assert_eq!(body["id"], conv_id);
    assert_eq!(body["metadata"]["env"], "test");
}

#[test]
fn get_nonexistent_conversation_returns_404() {
    let proxy = start_test_proxy();

    let raw = http_send(
        proxy.addr(),
        "GET /v1/conversations/conv_nonexistent HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_conversation_metadata() {
    let proxy = start_test_proxy();
    let conv_id = create_conversation(&proxy, r#"{"metadata":{"v":"1"}}"#);

    let raw = http_send(
        proxy.addr(),
        &json_post(&format!("/v1/conversations/{conv_id}"), r#"{"metadata":{"v":"2"}}"#),
    );
    assert_eq!(parse_status(&raw), 200, "update should return 200");
    let body: serde_json::Value = serde_json::from_str(&parse_body(&raw)).unwrap();
    assert_eq!(body["metadata"]["v"], "2");

    let raw = http_send(
        proxy.addr(),
        &format!("GET /v1/conversations/{conv_id} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    );
    assert_eq!(parse_status(&raw), 200, "GET after update should return 200");
    let body: serde_json::Value = serde_json::from_str(&parse_body(&raw)).unwrap();
    assert_eq!(body["metadata"]["v"], "2");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_conversation_without_metadata_preserves_existing_metadata() {
    let proxy = start_test_proxy();
    let conv_id = create_conversation(&proxy, r#"{"metadata":{"v":"1"}}"#);

    let raw = http_send(
        proxy.addr(),
        &json_post(&format!("/v1/conversations/{conv_id}"), r#"{}"#),
    );
    assert_eq!(parse_status(&raw), 200, "update should return 200");
    let body: serde_json::Value = serde_json::from_str(&parse_body(&raw)).unwrap();
    assert_eq!(body["metadata"]["v"], "1");

    let raw = http_send(
        proxy.addr(),
        &format!("GET /v1/conversations/{conv_id} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    );
    assert_eq!(parse_status(&raw), 200, "GET after update should return 200");
    let body: serde_json::Value = serde_json::from_str(&parse_body(&raw)).unwrap();
    assert_eq!(body["metadata"]["v"], "1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_conversation() {
    let proxy = start_test_proxy();
    let conv_id = create_conversation(&proxy, r#"{"metadata":{}}"#);

    let raw = http_send(
        proxy.addr(),
        &format!("DELETE /v1/conversations/{conv_id} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    );
    assert_eq!(parse_status(&raw), 200, "delete should return 200");
    let body: serde_json::Value = serde_json::from_str(&parse_body(&raw)).unwrap();
    assert!(body["deleted"].as_bool().unwrap());

    let raw = http_send(
        proxy.addr(),
        &format!("GET /v1/conversations/{conv_id} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    );
    assert_eq!(parse_status(&raw), 404, "deleted conversation should 404");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_conversation_preserves_item_rows() {
    let proxy = start_test_proxy();
    let conv_id = create_conversation(
        &proxy,
        r#"{"metadata":{},"items":[{"id":"item_keep","type":"message","role":"user","content":"keep me"}]}"#,
    );

    let raw = http_send(
        proxy.addr(),
        &format!("DELETE /v1/conversations/{conv_id} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    );
    assert_eq!(parse_status(&raw), 200, "delete should return 200");

    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET /v1/conversations/{conv_id}/items/item_keep HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "conversation delete should not delete item row"
    );
    let body: serde_json::Value = serde_json::from_str(&parse_body(&raw)).unwrap();
    assert_eq!(body["id"], "item_keep");
    assert_eq!(body["content"][0]["text"], "keep me");
}

#[test]
fn delete_nonexistent_conversation_returns_404() {
    let proxy = start_test_proxy();

    let raw = http_send(
        proxy.addr(),
        "DELETE /v1/conversations/conv_nonexistent HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 404);
}

#[test]
fn create_conversation_with_invalid_metadata_returns_error() {
    let proxy = start_test_proxy();

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/conversations", r#"{"metadata":"not-an-object"}"#),
    );
    assert_eq!(parse_status(&raw), 400, "invalid metadata should return 400");
}

#[test]
fn create_conversation_with_invalid_json_returns_error() {
    let proxy = start_test_proxy();

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/conversations", r#"{"metadata":{"env":"test"}"#),
    );
    assert_eq!(parse_status(&raw), 400, "invalid JSON should return 400");
}

#[test]
fn create_conversation_with_non_object_json_returns_error() {
    let proxy = start_test_proxy();

    let raw = http_send(proxy.addr(), &json_post("/v1/conversations", r#"[]"#));
    assert_eq!(parse_status(&raw), 400, "non-object JSON should return 400");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conversation_items_are_handled_locally() {
    let proxy = start_test_proxy();
    let conv_id = create_conversation(
        &proxy,
        r#"{"metadata":{},"items":[{"id":"item_initial","type":"message","role":"user","content":"hello"}]}"#,
    );

    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET /v1/conversations/{conv_id}/items?order=asc HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(parse_status(&raw), 200, "list items should return 200");
    let body: serde_json::Value = serde_json::from_str(&parse_body(&raw)).unwrap();
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    assert_eq!(body["data"][0]["id"], "item_initial");
    assert_eq!(body["data"][0]["status"], "completed");
    assert_eq!(body["data"][0]["content"][0]["type"], "input_text");
    assert_eq!(body["data"][0]["content"][0]["text"], "hello");

    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET /v1/conversations/{conv_id}/items/item_initial HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(parse_status(&raw), 200, "get item should return 200");
    let body: serde_json::Value = serde_json::from_str(&parse_body(&raw)).unwrap();
    assert_eq!(body["id"], "item_initial");
    assert_eq!(body["status"], "completed");
    assert_eq!(body["content"][0]["type"], "input_text");
    assert_eq!(body["content"][0]["text"], "hello");

    let raw = http_send(
        proxy.addr(),
        &json_post(
            &format!("/v1/conversations/{conv_id}/items"),
            r#"{"items":[{"id":"item_second","type":"message","role":"assistant","content":"hi"}]}"#,
        ),
    );
    assert_eq!(parse_status(&raw), 200, "create item should return 200");
    let body: serde_json::Value = serde_json::from_str(&parse_body(&raw)).unwrap();
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    assert_eq!(body["data"][0]["id"], "item_second");
    assert_eq!(body["data"][0]["status"], "completed");
    assert_eq!(body["data"][0]["content"][0]["type"], "output_text");
    assert_eq!(body["data"][0]["content"][0]["text"], "hi");
    assert_eq!(body["data"][0]["content"][0]["annotations"], serde_json::json!([]));

    let raw = http_send(
        proxy.addr(),
        &format!(
            "DELETE /v1/conversations/{conv_id}/items/item_second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(parse_status(&raw), 200, "delete item should return 200");

    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET /v1/conversations/{conv_id}/items/item_second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(parse_status(&raw), 404, "deleted item should return 404");
}

#[test]
fn unmatched_path_passes_through() {
    let backend_guard = praxis_test_utils::Backend::fixed("ok")
        .header("content-type", "text/plain")
        .start_with_shutdown();
    let proxy_port = free_port();

    let yaml = std::fs::read_to_string(example_config_path("ai/openai/conversations/conversations.yaml"))
        .expect("example config should exist");
    let patched = patch_yaml(
        &yaml.replace("sqlite://conversations.db?mode=rwc", "sqlite::memory:"),
        proxy_port,
        &HashMap::from([("127.0.0.1:8000", backend_guard.port())]),
    );
    let config = praxis_core::config::Config::from_yaml(&patched).expect("patched config should parse");
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "unmatched path should pass through");
    assert_eq!(parse_body(&raw), "ok");
}

// -----------------------------------------------------------------------------
// Test Helpers
// -----------------------------------------------------------------------------

fn start_test_proxy() -> praxis_test_utils::ProxyGuard {
    let proxy_port = free_port();

    let yaml = std::fs::read_to_string(example_config_path("ai/openai/conversations/conversations.yaml"))
        .expect("example config should exist");
    let patched = patch_yaml(
        &yaml.replace("sqlite://conversations.db?mode=rwc", "sqlite::memory:"),
        proxy_port,
        &HashMap::new(),
    );
    let config = praxis_core::config::Config::from_yaml(&patched).expect("patched config should parse");
    start_proxy(&config)
}

fn create_conversation(proxy: &praxis_test_utils::ProxyGuard, body: &str) -> String {
    let raw = http_send(proxy.addr(), &json_post("/v1/conversations", body));
    assert_eq!(parse_status(&raw), 200, "create conversation should succeed");
    let json: serde_json::Value = serde_json::from_str(&parse_body(&raw)).unwrap();
    json["id"].as_str().unwrap().to_owned()
}
