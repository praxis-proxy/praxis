// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the `openai_response_store` example config.

use std::collections::HashMap;

use praxis_test_utils::{
    Backend, example_config_path, free_port, http_get, http_send, json_post, parse_body, parse_status, patch_yaml,
    start_proxy,
};
use sqlx::Row;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Backend response matching a real Responses API shape with `input`
/// and `output` fields the store extracts for persistence.
const RESPONSE_JSON: &str = r#"{"id":"resp_abc","created_at":1000,"model":"gpt-4.1","object":"response","input":"Hello","output":[{"type":"message","content":[{"type":"output_text","text":"Hi there"}]}]}"#;

/// Table name from the example config.
const RESPONSES_TABLE: &str = "openai_responses";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_store_persists_response_to_sqlite() {
    let backend_guard = Backend::fixed(RESPONSE_JSON)
        .header("content-type", "application/json")
        .start_with_shutdown();
    let proxy_port = free_port();

    let (db_url, db_path) = temp_sqlite_url("persist");
    let yaml = std::fs::read_to_string(example_config_path("ai/openai/responses/response-store.yaml"))
        .expect("example config should exist");
    let patched = patch_yaml(
        &yaml.replace("sqlite://responses.db?mode=rwc", &db_url),
        proxy_port,
        &HashMap::from([("127.0.0.1:8000", backend_guard.port())]),
    );
    let config = praxis_core::config::Config::from_yaml(&patched).expect("patched config should parse");
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/responses", r#"{"model":"gpt-4.1","input":"Hello"}"#),
    );

    assert_eq!(parse_status(&raw), 200, "Responses API POST should return 200");
    assert_eq!(
        parse_body(&raw),
        RESPONSE_JSON,
        "response body should match the backend's JSON"
    );

    let pool = sqlx::SqlitePool::connect(&db_url)
        .await
        .expect("should connect to test database");
    let sql = format!("SELECT id, tenant_id, created_at, model, input, messages FROM {RESPONSES_TABLE} WHERE id = ?");
    let row: sqlx::sqlite::SqliteRow = sqlx::query(&sql)
        .bind("resp_abc")
        .fetch_one(&pool)
        .await
        .expect("persisted record should exist in database");
    pool.close().await;

    let id: String = row.get("id");
    let tenant_id: String = row.get("tenant_id");
    let created_at: i64 = row.get("created_at");
    let model: String = row.get("model");

    assert_eq!(id, "resp_abc", "persisted id should match response");
    assert_eq!(tenant_id, "default", "default tenant should be used");
    assert_eq!(created_at, 1000, "persisted created_at should match response");
    assert_eq!(model, "gpt-4.1", "persisted model should match response");

    let input_raw: String = row.get("input");
    let input: serde_json::Value = serde_json::from_str(&input_raw).expect("input column should be valid JSON");
    assert_eq!(
        input,
        serde_json::json!("Hello"),
        "input should match the response's input field"
    );

    let messages_raw: String = row.get("messages");
    let messages: serde_json::Value =
        serde_json::from_str(&messages_raw).expect("messages column should be valid JSON");
    let items = messages.as_array().expect("messages should be an array");
    assert_eq!(items.len(), 1, "messages should have one output item");

    drop(proxy);
    cleanup_sqlite_files(&db_path);
}

#[test]
fn response_store_passes_through_non_responses_traffic() {
    let backend_guard = Backend::fixed("fallback")
        .header("content-type", "text/plain")
        .start_with_shutdown();
    let proxy_port = free_port();

    let yaml = std::fs::read_to_string(example_config_path("ai/openai/responses/response-store.yaml"))
        .expect("example config should exist");
    let patched = patch_yaml(
        &yaml.replace("sqlite://responses.db?mode=rwc", "sqlite::memory:"),
        proxy_port,
        &HashMap::from([("127.0.0.1:8000", backend_guard.port())]),
    );
    let config = praxis_core::config::Config::from_yaml(&patched).expect("patched config should parse");
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post(
            "/v1/responses",
            r#"{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}"#,
        ),
    );

    assert_eq!(
        parse_status(&raw),
        200,
        "Chat Completions body should still route through"
    );
}

// -----------------------------------------------------------------------------
// GET Retrieval
// -----------------------------------------------------------------------------

#[test]
fn get_missing_response_returns_404() {
    let proxy_port = free_port();

    let yaml = std::fs::read_to_string(example_config_path("ai/openai/responses/response-store.yaml"))
        .expect("example config should exist");
    let patched = patch_yaml(
        &yaml.replace("sqlite://responses.db?mode=rwc", "sqlite::memory:"),
        proxy_port,
        &HashMap::new(),
    );
    let config = praxis_core::config::Config::from_yaml(&patched).expect("patched config should parse");
    let proxy = start_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/v1/responses/resp_nonexistent", None);

    assert_eq!(status, 404, "GET for missing response should return 404");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("body should be valid JSON");
    assert_eq!(
        parsed["error"]["type"].as_str(),
        Some("invalid_request_error"),
        "404 body should use invalid_request_error type"
    );
}

#[test]
fn get_missing_input_items_returns_404() {
    let proxy_port = free_port();

    let yaml = std::fs::read_to_string(example_config_path("ai/openai/responses/response-store.yaml"))
        .expect("example config should exist");
    let patched = patch_yaml(
        &yaml.replace("sqlite://responses.db?mode=rwc", "sqlite::memory:"),
        proxy_port,
        &HashMap::new(),
    );
    let config = praxis_core::config::Config::from_yaml(&patched).expect("patched config should parse");
    let proxy = start_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/v1/responses/resp_nonexistent/input_items", None);

    assert_eq!(status, 404, "input_items for missing response should return 404");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("body should be valid JSON");
    assert!(
        parsed["error"]["message"]
            .as_str()
            .expect("error message should be a string")
            .contains("resp_nonexistent"),
        "error message should include the missing ID"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Generate a unique file-backed SQLite URL for test isolation.
fn temp_sqlite_url(test_name: &str) -> (String, std::path::PathBuf) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let db_path = std::env::temp_dir().join(format!("praxis_integ_{test_name}_{}_{nanos}.db", std::process::id()));
    (format!("sqlite://{}?mode=rwc", db_path.display()), db_path)
}

/// Remove a SQLite database file and its WAL/SHM companions.
fn cleanup_sqlite_files(db_path: &std::path::Path) {
    drop(std::fs::remove_file(db_path));
    drop(std::fs::remove_file(format!("{}-shm", db_path.display())));
    drop(std::fs::remove_file(format!("{}-wal", db_path.display())));
}
