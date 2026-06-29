// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for Anthropic Messages API filters.
//!
//! Tests validate the full request/response cycle through Praxis with
//! passthrough and transform filter chains. Response data is loaded
//! from recording fixtures in `tests/integration/fixtures/anthropic/messages/`.

use praxis_core::config::Config;
use praxis_test_utils::{
    Backend, Recording, free_port, http_send, parse_body, parse_status, start_backend_with_shutdown, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn non_streaming_basic() {
    let recording = Recording::load("anthropic/messages/basic.json");
    let response_body = recording.response_body();
    let request_body = recording.request_body();
    let backend = Backend::fixed(&response_body)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &anthropic_post("/v1/messages", &request_body));
    let status = parse_status(&raw);
    let body = parse_body(&raw);
    let data: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(status, 200, "expected 200");
    assert_eq!(data["type"], "message", "type should be message");
    assert_eq!(data["role"], "assistant", "role should be assistant");
    assert!(
        data["id"].as_str().unwrap().starts_with("msg_"),
        "id should start with msg_"
    );
    let content = data["content"].as_array().unwrap();
    assert!(!content.is_empty(), "content should not be empty");
    let text_blocks: Vec<_> = content.iter().filter(|b| b["type"] == "text").collect();
    assert!(!text_blocks.is_empty(), "should have at least one text block");
    assert!(
        !text_blocks[0]["text"].as_str().unwrap().is_empty(),
        "text should not be empty"
    );
    assert!(
        ["end_turn", "max_tokens"].contains(&data["stop_reason"].as_str().unwrap()),
        "stop_reason should be end_turn or max_tokens"
    );
    assert!(
        data["usage"]["input_tokens"].as_u64().unwrap() > 0,
        "input_tokens should be > 0"
    );
    assert!(
        data["usage"]["output_tokens"].as_u64().unwrap() > 0,
        "output_tokens should be > 0"
    );
    for block in content {
        assert!(
            ["text", "thinking", "tool_use"].contains(&block["type"].as_str().unwrap()),
            "block type should be text, thinking, or tool_use"
        );
    }
}

#[test]
fn non_streaming_with_system() {
    let recording = Recording::load("anthropic/messages/system.json");
    let response_body = recording.response_body();
    let request_body = recording.request_body();
    let backend = Backend::fixed(&response_body)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &anthropic_post("/v1/messages", &request_body));
    let status = parse_status(&raw);
    let body = parse_body(&raw);
    let data: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(status, 200, "expected 200");
    assert_eq!(data["type"], "message", "type should be message");
    let content = data["content"].as_array().unwrap();
    assert!(!content.is_empty(), "content should not be empty");
    let text_blocks: Vec<_> = content.iter().filter(|b| b["type"] == "text").collect();
    assert!(!text_blocks.is_empty(), "should have at least one text block");
    assert!(
        !text_blocks[0]["text"].as_str().unwrap().is_empty(),
        "text should not be empty"
    );
}

#[test]
fn non_streaming_multi_turn() {
    let recording = Recording::load("anthropic/messages/multi_turn.json");
    let response_body = recording.response_body();
    let request_body = recording.request_body();
    let backend = Backend::fixed(&response_body)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &anthropic_post("/v1/messages", &request_body));
    let status = parse_status(&raw);
    let body = parse_body(&raw);
    let data: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(status, 200, "expected 200");
    assert_eq!(data["type"], "message", "type should be message");
    let content = data["content"].as_array().unwrap();
    assert!(!content.is_empty(), "content should not be empty");
    let text_blocks: Vec<_> = content.iter().filter(|b| b["type"] == "text").collect();
    assert!(!text_blocks.is_empty(), "should have at least one text block");
    let text = text_blocks[0]["text"].as_str().unwrap().to_lowercase();
    assert!(text.contains("alice"), "response should mention Alice");
}

#[test]
fn streaming_basic() {
    let recording = Recording::load("anthropic/messages/streaming_basic.json");
    let response_body = recording.response_body();
    let request_body = recording.request_body();
    let backend = Backend::fixed(&response_body)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &anthropic_post("/v1/messages", &request_body));
    let body = parse_body(&raw);

    let events = parse_sse_events(&body);
    let event_types: Vec<&str> = events.iter().filter_map(|e| e["_event_type"].as_str()).collect();

    assert!(event_types.contains(&"message_start"), "should have message_start");
    assert!(event_types.contains(&"message_stop"), "should have message_stop");

    let msg_start = events.iter().find(|e| e["_event_type"] == "message_start").unwrap();
    assert_eq!(
        msg_start["message"]["role"], "assistant",
        "message_start role should be assistant"
    );

    let content_deltas: Vec<_> = events
        .iter()
        .filter(|e| e["_event_type"] == "content_block_delta")
        .collect();
    assert!(
        !content_deltas.is_empty(),
        "should have at least one content_block_delta"
    );

    for delta in &content_deltas {
        assert!(
            ["text_delta", "thinking_delta"].contains(&delta["delta"]["type"].as_str().unwrap()),
            "delta type should be text_delta or thinking_delta"
        );
    }
}

#[test]
fn streaming_collects_full_text() {
    let recording = Recording::load("anthropic/messages/streaming_basic.json");
    let response_body = recording.response_body();
    let backend = Backend::fixed(&response_body)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &anthropic_post(
            "/v1/messages",
            r#"{"model":"mock-model","messages":[{"role":"user","content":"Count from 1 to 5, separated by commas."}],"max_tokens":64,"stream":true}"#,
        ),
    );
    let body = parse_body(&raw);
    let events = parse_sse_events(&body);

    let full_text: String = events
        .iter()
        .filter(|e| e["_event_type"] == "content_block_delta")
        .filter(|e| e["delta"]["type"] == "text_delta")
        .filter_map(|e| e["delta"]["text"].as_str())
        .collect();

    assert!(!full_text.is_empty(), "collected text should not be empty");
}

#[test]
fn non_streaming_with_temperature() {
    let recording = Recording::load("anthropic/messages/temperature.json");
    let response_body = recording.response_body();
    let request_body = recording.request_body();
    let backend = Backend::fixed(&response_body)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &anthropic_post("/v1/messages", &request_body));
    let status = parse_status(&raw);
    let body = parse_body(&raw);
    let data: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(status, 200, "expected 200");
    assert_eq!(data["type"], "message", "type should be message");
    assert!(
        !data["content"].as_array().unwrap().is_empty(),
        "content should not be empty"
    );
}

#[test]
fn non_streaming_with_stop_sequences() {
    let recording = Recording::load("anthropic/messages/stop_sequences.json");
    let response_body = recording.response_body();
    let request_body = recording.request_body();
    let backend = Backend::fixed(&response_body)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &anthropic_post("/v1/messages", &request_body));
    let status = parse_status(&raw);
    let body = parse_body(&raw);
    let data: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(status, 200, "expected 200");
    assert_eq!(data["type"], "message", "type should be message");
}

#[test]
fn with_tool_definitions() {
    let recording = Recording::load("anthropic/messages/tool_defs.json");
    let response_body = recording.response_body();
    let request_body = recording.request_body();
    let backend = Backend::fixed(&response_body)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &anthropic_post("/v1/messages", &request_body));
    let status = parse_status(&raw);
    let body = parse_body(&raw);
    let data: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(status, 200, "expected 200");
    assert_eq!(data["type"], "message", "type should be message");
    let content = data["content"].as_array().unwrap();
    assert!(!content.is_empty(), "content should not be empty");

    for block in content {
        assert!(
            ["text", "tool_use", "thinking"].contains(&block["type"].as_str().unwrap()),
            "block type should be text, tool_use, or thinking"
        );
        if block["type"] == "tool_use" {
            assert!(block["id"].is_string(), "tool_use should have id");
            assert_eq!(block["name"], "get_weather", "tool name should be get_weather");
            assert!(block["input"].is_object(), "tool_use should have input");
        }
    }
}

#[test]
fn tool_use_round_trip() {
    let recording = Recording::load("anthropic/messages/tool_result.json");
    let response_body = recording.response_body();
    let request_body = recording.request_body();
    let backend = Backend::fixed(&response_body)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &anthropic_post("/v1/messages", &request_body));
    let status = parse_status(&raw);
    let body = parse_body(&raw);
    let data: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(status, 200, "expected 200");
    assert_eq!(data["type"], "message", "type should be message");
    assert!(
        !data["content"].as_array().unwrap().is_empty(),
        "content should not be empty"
    );
}

#[test]
fn backend_owned_missing_model_reaches_backend() {
    let backend = start_backend_with_shutdown("backend-owned");
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &anthropic_post(
            "/v1/messages",
            r#"{"messages":[{"role":"user","content":"Hello"}],"max_tokens":64}"#,
        ),
    );
    let status = parse_status(&raw);

    assert_eq!(status, 200, "backend-owned missing model semantics should be forwarded");
    assert_eq!(parse_body(&raw), "backend-owned", "request should reach the backend");
}

#[test]
fn backend_owned_empty_messages_reaches_backend() {
    let backend = start_backend_with_shutdown("backend-owned");
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &anthropic_post(
            "/v1/messages",
            r#"{"model":"mock-model","messages":[],"max_tokens":64}"#,
        ),
    );
    let status = parse_status(&raw);

    assert_eq!(
        status, 200,
        "backend-owned empty messages semantics should be forwarded"
    );
    assert_eq!(parse_body(&raw), "backend-owned", "request should reach the backend");
}

#[test]
fn response_headers() {
    let recording = Recording::load("anthropic/messages/response_headers.json");
    let response_body = recording.response_body();
    let request_body = recording.request_body();
    let backend = Backend::fixed(&response_body)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &anthropic_post("/v1/messages", &request_body));
    let status = parse_status(&raw);

    assert_eq!(status, 200, "expected 200");
    let raw_lower = raw.to_lowercase();
    assert!(
        raw_lower.contains("anthropic-version: 2023-06-01"),
        "response should include anthropic-version header"
    );
}

#[test]
fn content_block_array() {
    let recording = Recording::load("anthropic/messages/content_block.json");
    let response_body = recording.response_body();
    let request_body = recording.request_body();
    let backend = Backend::fixed(&response_body)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &anthropic_post("/v1/messages", &request_body));
    let status = parse_status(&raw);
    let body = parse_body(&raw);
    let data: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(status, 200, "expected 200");
    assert_eq!(data["type"], "message", "type should be message");
    assert!(
        !data["content"].as_array().unwrap().is_empty(),
        "content should not be empty"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn passthrough_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: test
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [passthrough]

filter_chains:
  - name: passthrough
    filters:
      - filter: anthropic_messages_format
        on_invalid: continue
      - filter: anthropic_validate
      - filter: anthropic_messages_protocol
        default_version: "2023-06-01"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: mock
      - filter: load_balancer
        clusters:
          - name: mock
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    )
}

fn anthropic_post(path: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         anthropic-version: 2023-06-01\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    )
}

fn parse_sse_events(body: &str) -> Vec<serde_json::Value> {
    let mut events = Vec::new();
    let mut current_event_type = None;

    for line in body.lines() {
        if let Some(event_type) = line.strip_prefix("event: ") {
            current_event_type = Some(event_type.to_owned());
        } else if let Some(data) = line.strip_prefix("data: ")
            && let Ok(mut value) = serde_json::from_str::<serde_json::Value>(data)
        {
            if let Some(et) = &current_event_type {
                value["_event_type"] = serde_json::Value::String(et.clone());
            }
            events.push(value);
            current_event_type = None;
        }
    }

    events
}
