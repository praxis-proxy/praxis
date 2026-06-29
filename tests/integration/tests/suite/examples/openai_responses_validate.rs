// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the request-validate example config.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_send, json_post, load_example_config, parse_body, parse_header, parse_status,
    start_backend_with_shutdown, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn openai_responses_validate_example_forwards_valid_responses_request() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/request-validate.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:8000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/responses", r#"{"model":"gpt-4.1","input":"Hello, world!"}"#),
    );

    assert_eq!(parse_status(&raw), 200, "valid responses request should be forwarded");
    assert_eq!(parse_body(&raw), "ok", "request should reach the backend");
}

#[test]
fn openai_responses_validate_example_rejects_stream_and_background() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/request-validate.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:8000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post(
            "/v1/responses",
            r#"{"model":"gpt-4.1","input":"test","stream":true,"background":true}"#,
        ),
    );

    assert_eq!(parse_status(&raw), 400, "stream + background should be rejected");
    assert_eq!(
        parse_header(&raw, "content-type").as_deref(),
        Some("text/event-stream"),
        "streaming rejection should use SSE content type"
    );
    let body = parse_body(&raw);
    let data_line = body
        .lines()
        .find(|l| l.starts_with("data: "))
        .expect("SSE body should contain a data line");
    let parsed: serde_json::Value =
        serde_json::from_str(data_line.strip_prefix("data: ").unwrap()).expect("SSE data should be valid JSON");
    assert_eq!(parsed["type"].as_str(), Some("error"), "SSE event type should be error");
    assert_eq!(
        parsed["sequence_number"].as_i64(),
        Some(0),
        "SSE error event should include sequence number"
    );
    assert_eq!(
        parsed["error"]["code"].as_str(),
        Some("invalid_request_error"),
        "error code should be invalid_request_error"
    );
    assert_eq!(
        parsed["error"]["message"].as_str(),
        Some("stream and background cannot both be true"),
        "error message should describe the validation failure"
    );
    assert!(parsed["error"]["param"].is_null(), "error param should be null");
}

#[test]
fn openai_responses_validate_example_accepts_minimal_request() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/request-validate.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:8000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/responses", r#"{"input":"Hello"}"#));

    assert_eq!(
        parse_status(&raw),
        200,
        "minimal request (input only) should be accepted"
    );
}
