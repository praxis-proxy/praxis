// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the `openai_response_store` example config.

use std::collections::HashMap;

use praxis_test_utils::{
    Backend, example_config_path, free_port, http_send, json_post, parse_body, parse_status, patch_yaml, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn response_store_forwards_responses_api_request_to_backend() {
    let response_json = r#"{"id":"resp_abc","created_at":1000,"model":"gpt-4.1","object":"response","output":[]}"#;
    let backend_guard = Backend::fixed(response_json)
        .header("content-type", "application/json")
        .start_with_shutdown();
    let proxy_port = free_port();

    let yaml = std::fs::read_to_string(example_config_path("ai/openai/responses/response-store.yaml"))
        .expect("example config should exist");
    let patched = patch_yaml(
        &yaml.replace("sqlite://responses.db?mode=rwc", "sqlite::memory:"),
        proxy_port,
        &HashMap::from([("127.0.0.1:3001", backend_guard.port())]),
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
        response_json,
        "response body should match the backend's JSON"
    );
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
        &HashMap::from([("127.0.0.1:3001", backend_guard.port())]),
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
