// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the Responses API full-flow example config.

use std::collections::HashMap;

use praxis_test_utils::{
    Backend, example_config_path, free_port, http_send, json_post, load_example_config, parse_body, parse_status,
    patch_yaml, start_backend_with_shutdown, start_echo_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Backend response for the first turn — stored by response_store.
const FIRST_RESPONSE_JSON: &str = r#"{"id":"resp_first","created_at":1000,"model":"gpt-4.1","object":"response","status":"completed","input":"Hello","output":[{"type":"message","content":[{"type":"output_text","text":"Hi there"}]}]}"#;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn full_flow_stateful_valid_request_reaches_backend() {
    let backend_guard = start_backend_with_shutdown("inference-backend");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/full-flow.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/responses", r#"{"model":"gpt-4.1","input":"Hello, world!"}"#),
    );

    assert_eq!(
        parse_status(&raw),
        200,
        "stateful request should pass validation and reach the backend"
    );
    assert_eq!(
        parse_body(&raw),
        "inference-backend",
        "stateful request should route to the shared inference backend"
    );
}

#[test]
fn full_flow_stateless_valid_request_reaches_same_backend() {
    let backend_guard = start_backend_with_shutdown("inference-backend");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/full-flow.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/responses", r#"{"model":"gpt-4.1","input":"Hello","store":false}"#),
    );

    assert_eq!(
        parse_status(&raw),
        200,
        "stateless request should pass validation and reach the backend"
    );
    assert_eq!(
        parse_body(&raw),
        "inference-backend",
        "stateless request should route to the shared inference backend"
    );
}

#[test]
fn full_flow_chat_completions_body_on_responses_path_does_not_reach_backend() {
    let backend_guard = start_backend_with_shutdown("inference-backend");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/full-flow.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", backend_guard.port())]),
    );
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
        404,
        "chat completions bodies should not match the Responses-only route"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_flow_previous_response_id_rebuilds_body_with_history() {
    let backend_guard = Backend::fixed(FIRST_RESPONSE_JSON)
        .header("content-type", "application/json")
        .start_with_shutdown();
    let proxy_port = free_port();

    let (db_url, db_path) = temp_sqlite_url("full_flow_prev");
    let yaml = std::fs::read_to_string(example_config_path("ai/openai/responses/full-flow.yaml"))
        .expect("example config should exist");
    let patched = patch_yaml(
        &yaml.replace("sqlite://responses.db?mode=rwc", &db_url),
        proxy_port,
        &HashMap::from([("127.0.0.1:3001", backend_guard.port())]),
    );
    let config = praxis_core::config::Config::from_yaml(&patched).expect("patched config should parse");
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/responses", r#"{"model":"gpt-4.1","input":"Hello"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "first request should succeed");

    drop(backend_guard);

    let echo_backend = start_echo_backend();
    let patched2 = patch_yaml(
        &yaml.replace("sqlite://responses.db?mode=rwc", &db_url),
        proxy_port,
        &HashMap::from([("127.0.0.1:3001", echo_backend.port())]),
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
        "second request with previous_response_id should succeed, body: {body2}"
    );

    let echoed: serde_json::Value = serde_json::from_str(&body2).expect("echoed request body should be valid JSON");

    assert_eq!(echoed["model"], "gpt-4.1", "model should be preserved");

    let input = echoed["input"]
        .as_array()
        .expect("input should be an array after body rebuild");
    assert!(
        input.len() >= 2,
        "input should contain stored history + new message, got {input_len}",
        input_len = input.len()
    );

    let last = input.last().expect("input should not be empty");
    assert_eq!(last["content"], "What next?", "last message should be the new input");

    assert!(
        echoed.get("previous_response_id").is_none(),
        "previous_response_id should be stripped from outbound body"
    );

    drop(proxy2);
    cleanup_sqlite_files(&db_path);
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
