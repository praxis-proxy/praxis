// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the `openai_response_store` example config
//! with PostgreSQL backend.

use std::collections::HashMap;

use praxis_test_utils::{
    Backend, example_config_path, free_port, http_send, json_post, parse_body, parse_status, patch_yaml,
    start_postgres, start_proxy,
};
use sqlx::Row;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Backend response matching a real Responses API shape with `input`
/// and `output` fields the store extracts for persistence.
const RESPONSE_JSON: &str = r#"{"id":"resp_pg_abc","created_at":2000,"model":"gpt-4.1","object":"response","input":"Hello from postgres","output":[{"type":"message","content":[{"type":"output_text","text":"Hi there from pg"}]}]}"#;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires container engine (podman or docker)"]
async fn response_store_persists_response_to_postgres() {
    let pg = start_postgres();

    let backend_guard = Backend::fixed(RESPONSE_JSON)
        .header("content-type", "application/json")
        .start_with_shutdown();
    let proxy_port = free_port();

    let suffix = unique_suffix();
    let responses_table = format!("openai_responses_{suffix}");
    let conversations_table = format!("openai_conversations_{suffix}");

    let yaml = std::fs::read_to_string(example_config_path("ai/openai/responses/response-store.yaml"))
        .expect("example config should exist");
    let patched = patch_yaml(
        &yaml
            .replace("backend: sqlite", "backend: postgres")
            .replace(
                "database_url: \"sqlite://responses.db?mode=rwc\"",
                &format!("database_url: \"{}\"", pg.url()),
            )
            .replace(
                "        responses_table: openai_responses",
                &format!("        responses_table: {responses_table}"),
            )
            .replace(
                "        conversations_table: openai_conversations",
                &format!(
                    "        conversations_table: {conversations_table}\n        allow_private_database_url: true"
                ),
            ),
        proxy_port,
        &HashMap::from([("127.0.0.1:8000", backend_guard.port())]),
    );

    let config = praxis_core::config::Config::from_yaml(&patched).expect("patched config should parse");
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/responses", r#"{"model":"gpt-4.1","input":"Hello from postgres"}"#),
    );

    assert_eq!(parse_status(&raw), 200, "Responses API POST should return 200");
    assert_eq!(
        parse_body(&raw),
        RESPONSE_JSON,
        "response body should match the backend's JSON"
    );

    let pool = sqlx::PgPool::connect(&pg.url())
        .await
        .expect("should connect to test database");
    let sql = format!("SELECT id, tenant_id, created_at, model, input, messages FROM {responses_table} WHERE id = $1");
    let row: sqlx::postgres::PgRow = sqlx::query(&sql)
        .bind("resp_pg_abc")
        .fetch_one(&pool)
        .await
        .expect("persisted record should exist in database");
    pool.close().await;

    let id: String = row.get("id");
    let tenant_id: String = row.get("tenant_id");
    let created_at: i64 = row.get("created_at");
    let model: String = row.get("model");

    assert_eq!(id, "resp_pg_abc", "persisted id should match response");
    assert_eq!(tenant_id, "default", "default tenant should be used");
    assert_eq!(created_at, 2000, "persisted created_at should match response");
    assert_eq!(model, "gpt-4.1", "persisted model should match response");

    let input_raw: String = row.get("input");
    let input: serde_json::Value = serde_json::from_str(&input_raw).expect("input column should be valid JSON");
    assert_eq!(
        input,
        serde_json::json!("Hello from postgres"),
        "input should match the response's input field"
    );

    let messages_raw: String = row.get("messages");
    let messages: serde_json::Value =
        serde_json::from_str(&messages_raw).expect("messages column should be valid JSON");
    let items = messages.as_array().expect("messages should be an array");
    assert_eq!(items.len(), 1, "messages should have one output item");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires container engine (podman or docker)"]
async fn response_store_postgres_passes_through_non_responses_traffic() {
    let pg = start_postgres();

    let backend_guard = Backend::fixed("fallback")
        .header("content-type", "text/plain")
        .start_with_shutdown();
    let proxy_port = free_port();

    let suffix = unique_suffix();
    let responses_table = format!("openai_responses_{suffix}");
    let conversations_table = format!("openai_conversations_{suffix}");

    let yaml = std::fs::read_to_string(example_config_path("ai/openai/responses/response-store.yaml"))
        .expect("example config should exist");
    let patched = patch_yaml(
        &yaml
            .replace("backend: sqlite", "backend: postgres")
            .replace(
                "database_url: \"sqlite://responses.db?mode=rwc\"",
                &format!("database_url: \"{}\"", pg.url()),
            )
            .replace(
                "        responses_table: openai_responses",
                &format!("        responses_table: {responses_table}"),
            )
            .replace(
                "        conversations_table: openai_conversations",
                &format!(
                    "        conversations_table: {conversations_table}\n        allow_private_database_url: true"
                ),
            ),
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
// Test Utilities
// -----------------------------------------------------------------------------

/// Generate a unique suffix for table names to allow parallel test
/// execution against a shared PostgreSQL instance.
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tid = std::thread::current().id();
    format!("{id}_{tid:?}").replace(|c: char| !c.is_ascii_alphanumeric() && c != '_', "_")
}
