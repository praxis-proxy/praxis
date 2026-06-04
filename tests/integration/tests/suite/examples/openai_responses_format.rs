// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the OpenAI Responses format-routing example config.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_send, json_post, load_example_config, parse_body, parse_status, start_backend_with_shutdown,
    start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn openai_responses_format_routing_example_routes_responses_input() {
    let responses_guard = start_backend_with_shutdown("responses-backend");
    let chat_guard = start_backend_with_shutdown("chat-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/format-routing.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", responses_guard.port()),
            ("127.0.0.1:3002", chat_guard.port()),
            ("127.0.0.1:3003", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4.1-mini","input":"Hello, world!"}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "responses request should return 200");
    assert_eq!(
        parse_body(&raw),
        "responses-backend",
        "responses input should route to responses-backend cluster"
    );
}

#[test]
fn openai_responses_format_routing_example_routes_chat_completions() {
    let responses_guard = start_backend_with_shutdown("responses-backend");
    let chat_guard = start_backend_with_shutdown("chat-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/format-routing.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", responses_guard.port()),
            ("127.0.0.1:3002", chat_guard.port()),
            ("127.0.0.1:3003", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/chat/completions", body));

    assert_eq!(parse_status(&raw), 200, "chat completions should return 200");
    assert_eq!(
        parse_body(&raw),
        "chat-backend",
        "chat completions should route to chat-backend cluster"
    );
}

#[test]
fn openai_responses_format_routing_example_unknown_falls_to_default() {
    let responses_guard = start_backend_with_shutdown("responses-backend");
    let chat_guard = start_backend_with_shutdown("chat-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/format-routing.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", responses_guard.port()),
            ("127.0.0.1:3002", chat_guard.port()),
            ("127.0.0.1:3003", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let body = r#"{"prompt":"hello"}"#;
    let raw = http_send(proxy.addr(), &json_post("/other/path", body));

    assert_eq!(parse_status(&raw), 200, "unknown path should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "unrecognized path should fall to default cluster"
    );
}
