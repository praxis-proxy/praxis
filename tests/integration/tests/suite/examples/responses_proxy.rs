// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the Responses proxy example config.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_send, json_post, load_example_config, parse_body, parse_status, start_backend_with_shutdown,
    start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn responses_proxy_example_forwards_to_backend() {
    let backend_guard = start_backend_with_shutdown("inference-ok");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/responses-proxy.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4.1-mini","input":"Hello, world!","stream":false}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "proxied request should return 200");
    assert_eq!(
        parse_body(&raw),
        "inference-ok",
        "response body should be relayed from inference backend"
    );
}

#[test]
fn responses_proxy_example_preserves_json_response() {
    let json_response = r#"{"id":"resp_abc","object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"Hi!"}]}]}"#;
    let backend_guard = start_backend_with_shutdown(json_response);
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/responses-proxy.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4.1-mini","input":"Hello","stream":false}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "JSON response should return 200");
    assert_eq!(
        parse_body(&raw),
        json_response,
        "JSON response body should be preserved exactly"
    );
}

#[test]
fn responses_proxy_example_forwards_subresource_paths() {
    let backend_guard = start_backend_with_shutdown("subresource-ok");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/responses-proxy.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /v1/responses/resp_abc/input_items HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "subresource request should return 200");
    assert_eq!(
        parse_body(&raw),
        "subresource-ok",
        "subresource path should be proxied to inference backend"
    );
}
