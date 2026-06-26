// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional test for the model-rewrite example config.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_send, json_post, load_example_config, parse_body, parse_status, start_backend_with_shutdown,
    start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn example_config_wildcard_alias_routes_to_llama_backend() {
    let llama_guard = start_backend_with_shutdown("llama-backend");
    let qwen_guard = start_backend_with_shutdown("qwen-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/model-rewrite.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", llama_guard.port()),
            ("127.0.0.1:3002", qwen_guard.port()),
            ("127.0.0.1:3003", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let body = r#"{"model":"codex-mini-2026-06-24","input":"Hello from example test"}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "example config should route successfully");
    assert_eq!(
        parse_body(&raw),
        "llama-backend",
        "codex-* should route to llama-backend via effective model header"
    );
}

#[test]
fn example_config_default_model_routes_to_llama_backend() {
    let llama_guard = start_backend_with_shutdown("llama-backend");
    let qwen_guard = start_backend_with_shutdown("qwen-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/model-rewrite.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", llama_guard.port()),
            ("127.0.0.1:3002", qwen_guard.port()),
            ("127.0.0.1:3003", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let body = r#"{"input":"No model specified"}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "default model injection should succeed");
    assert_eq!(
        parse_body(&raw),
        "llama-backend",
        "default_model llama-3.3-70b should route to llama-backend"
    );
}

#[test]
fn example_config_qwen_alias_routes_to_qwen_backend() {
    let llama_guard = start_backend_with_shutdown("llama-backend");
    let qwen_guard = start_backend_with_shutdown("qwen-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/model-rewrite.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", llama_guard.port()),
            ("127.0.0.1:3002", qwen_guard.port()),
            ("127.0.0.1:3003", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4.1-mini","input":"Route to qwen"}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "qwen alias should route successfully");
    assert_eq!(
        parse_body(&raw),
        "qwen-backend",
        "gpt-4.1-mini should route to qwen-backend via effective model header"
    );
}

#[test]
fn example_config_non_responses_routes_to_default() {
    let llama_guard = start_backend_with_shutdown("llama-backend");
    let qwen_guard = start_backend_with_shutdown("qwen-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/model-rewrite.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", llama_guard.port()),
            ("127.0.0.1:3002", qwen_guard.port()),
            ("127.0.0.1:3003", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/chat/completions", body));

    assert_eq!(parse_status(&raw), 200, "chat completions should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "non-responses traffic should route to default"
    );
}
