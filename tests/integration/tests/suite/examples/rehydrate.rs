// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the `rehydrate` example config.

use std::collections::HashMap;

use praxis_test_utils::{
    Backend, example_config_path, free_port, http_send, json_post, parse_body, parse_status, patch_yaml,
    start_echo_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Backend response for the first turn — stored by response_store.
const FIRST_RESPONSE_JSON: &str = r#"{"id":"resp_first","created_at":1000,"model":"gpt-4.1","object":"response","status":"completed","input":"Hello","output":[{"type":"message","content":[{"type":"output_text","text":"Hi there"}]}]}"#;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rehydrate_validates_previous_response_and_passes_body_through() {
    let backend_guard = Backend::fixed(FIRST_RESPONSE_JSON)
        .header("content-type", "application/json")
        .start_with_shutdown();
    let proxy_port = free_port();

    let (db_url, db_path) = temp_sqlite_url("rehydrate");
    let yaml = std::fs::read_to_string(example_config_path("ai/openai/responses/rehydrate.yaml"))
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
    assert_eq!(parse_status(&raw), 200, "first request should succeed");
    assert_eq!(
        parse_body(&raw),
        FIRST_RESPONSE_JSON,
        "first response body should match backend"
    );

    drop(backend_guard);

    let backend_guard2 = start_echo_backend();
    let patched2 = patch_yaml(
        &yaml.replace("sqlite://responses.db?mode=rwc", &db_url),
        proxy_port,
        &HashMap::from([("127.0.0.1:8000", backend_guard2.port())]),
    );
    let config2 = praxis_core::config::Config::from_yaml(&patched2).expect("second patched config should parse");
    drop(proxy);

    let proxy2 = start_proxy(&config2);

    let raw2 = http_send(
        proxy2.addr(),
        &json_post(
            "/v1/responses",
            r#"{"model":"gpt-4.1","input":"What next?","previous_response_id":"resp_first"}"#,
        ),
    );
    let status2 = parse_status(&raw2);
    let body2 = parse_body(&raw2);
    assert_eq!(
        status2, 200,
        "second request with previous_response_id should succeed (validation passed), body: {body2}"
    );
    let echoed: serde_json::Value = serde_json::from_str(&body2).expect("echoed request should be valid JSON");
    assert_eq!(
        echoed["input"], "What next?",
        "body should pass through unchanged — input stays as original string"
    );
    assert_eq!(
        echoed["previous_response_id"], "resp_first",
        "body should pass through unchanged — previous_response_id preserved"
    );

    drop(proxy2);
    cleanup_sqlite_files(&db_path);
}

#[test]
fn rehydrate_passes_through_non_responses_traffic() {
    let backend_guard = Backend::fixed("fallback")
        .header("content-type", "text/plain")
        .start_with_shutdown();
    let proxy_port = free_port();

    let yaml = std::fs::read_to_string(example_config_path("ai/openai/responses/rehydrate.yaml"))
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

    assert_eq!(parse_status(&raw), 200, "non-Responses body should pass through");
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
