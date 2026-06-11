// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the Responses API full-flow example config.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_send, json_post, load_example_config, parse_body, parse_status, start_backend_with_shutdown,
    start_proxy,
};

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
