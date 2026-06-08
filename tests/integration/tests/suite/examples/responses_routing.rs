// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the OpenAI Responses routing example config.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_send, json_post, load_example_config, parse_body, parse_status, start_echo_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn responses_routing_example_forwards_stateless_to_backend() {
    let backend_guard = start_echo_backend();
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/responses-routing.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", backend_guard.port())]),
    );

    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4.1","input":"Hello","store":false}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "stateless should return 200");
    assert_eq!(
        parse_body(&raw),
        body,
        "stateless should forward request body unchanged"
    );
}

#[test]
fn responses_routing_example_forwards_stateful_to_backend() {
    let backend_guard = start_echo_backend();
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/responses-routing.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", backend_guard.port())]),
    );

    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4.1","input":"Hello"}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "stateful should return 200");
    assert_eq!(
        parse_body(&raw),
        body,
        "stateful should also reach the backend (same backend, different filter path)"
    );
}
