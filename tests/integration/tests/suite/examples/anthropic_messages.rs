// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for Anthropic Messages example configs.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_send, json_post, parse_body, parse_status, start_backend_with_shutdown, start_proxy,
};

use super::load_example_config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn unified_gateway_routes_anthropic_to_correct_backend() {
    let anthropic_guard = start_backend_with_shutdown("anthropic-backend");
    let openai_guard = start_backend_with_shutdown("openai-backend");
    let responses_guard = start_backend_with_shutdown("responses-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/anthropic/unified-gateway.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", anthropic_guard.port()),
            ("127.0.0.1:3002", openai_guard.port()),
            ("127.0.0.1:3003", responses_guard.port()),
            ("127.0.0.1:3004", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let anthropic_body = r#"{"model":"claude-opus-4-8","max_tokens":1024,"messages":[{"role":"user","content":"Hi"}]}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/messages", anthropic_body));
    assert_eq!(parse_status(&raw), 200, "anthropic request should return 200");
    assert_eq!(
        parse_body(&raw),
        "anthropic-backend",
        "anthropic should route to anthropic-backend"
    );
}

#[test]
fn unified_gateway_routes_openai_to_correct_backend() {
    let anthropic_guard = start_backend_with_shutdown("anthropic-backend");
    let openai_guard = start_backend_with_shutdown("openai-backend");
    let responses_guard = start_backend_with_shutdown("responses-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/anthropic/unified-gateway.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", anthropic_guard.port()),
            ("127.0.0.1:3002", openai_guard.port()),
            ("127.0.0.1:3003", responses_guard.port()),
            ("127.0.0.1:3004", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let openai_body = r#"{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/chat/completions", openai_body));
    assert_eq!(parse_status(&raw), 200, "openai request should return 200");
    assert_eq!(
        parse_body(&raw),
        "openai-backend",
        "openai should route to openai-backend"
    );
}

#[test]
fn unified_gateway_routes_responses_to_correct_backend() {
    let anthropic_guard = start_backend_with_shutdown("anthropic-backend");
    let openai_guard = start_backend_with_shutdown("openai-backend");
    let responses_guard = start_backend_with_shutdown("responses-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/anthropic/unified-gateway.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", anthropic_guard.port()),
            ("127.0.0.1:3002", openai_guard.port()),
            ("127.0.0.1:3003", responses_guard.port()),
            ("127.0.0.1:3004", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let responses_body = r#"{"model":"gpt-4","input":"What is 2+2?"}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", responses_body));
    assert_eq!(parse_status(&raw), 200, "responses request should return 200");
    assert_eq!(
        parse_body(&raw),
        "responses-backend",
        "responses should route to responses-backend"
    );
}

#[test]
fn unified_gateway_routes_unknown_to_default_backend() {
    let anthropic_guard = start_backend_with_shutdown("anthropic-backend");
    let openai_guard = start_backend_with_shutdown("openai-backend");
    let responses_guard = start_backend_with_shutdown("responses-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/anthropic/unified-gateway.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", anthropic_guard.port()),
            ("127.0.0.1:3002", openai_guard.port()),
            ("127.0.0.1:3003", responses_guard.port()),
            ("127.0.0.1:3004", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/unknown", r#"{"foo":"bar"}"#));
    assert_eq!(parse_status(&raw), 200, "unknown path should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "unknown path should route to default-backend"
    );
}
