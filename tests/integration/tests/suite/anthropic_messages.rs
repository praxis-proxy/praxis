// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for Anthropic Messages API filters.
//!
//! Ported from OGX's `test_messages.py`, with proxy-boundary tests
//! for backend-owned validation cases. Tests validate the full
//! request/response cycle through Praxis with passthrough and transform
//! filter chains.

use praxis_core::config::Config;
use praxis_test_utils::{
    Backend, free_port, http_send, parse_body, parse_status, start_backend_with_shutdown, start_proxy,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const BASIC_RESPONSE: &str = r#"{"id":"msg_test123","type":"message","role":"assistant","model":"mock-model","content":[{"type":"text","text":"The answer is 4."}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":15,"output_tokens":8}}"#;

const SYSTEM_RESPONSE: &str = r#"{"id":"msg_test456","type":"message","role":"assistant","model":"mock-model","content":[{"type":"text","text":"Arrr, I be a helpful pirate assistant!"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":25,"output_tokens":12}}"#;

const MULTI_TURN_RESPONSE: &str = r#"{"id":"msg_test789","type":"message","role":"assistant","model":"mock-model","content":[{"type":"text","text":"Your name is Alice."}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":30,"output_tokens":6}}"#;

const TEMPERATURE_RESPONSE: &str = r#"{"id":"msg_temp01","type":"message","role":"assistant","model":"mock-model","content":[{"type":"text","text":"Hello!"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":3}}"#;

const STOP_SEQUENCES_RESPONSE: &str = r#"{"id":"msg_stop01","type":"message","role":"assistant","model":"mock-model","content":[{"type":"text","text":"Count: 1"}],"stop_reason":"stop_sequence","stop_sequence":",","usage":{"input_tokens":20,"output_tokens":4}}"#;

const TOOL_DEFS_RESPONSE: &str = r#"{"id":"msg_tool01","type":"message","role":"assistant","model":"mock-model","content":[{"type":"tool_use","id":"toolu_test01","name":"get_weather","input":{"location":"San Francisco, CA"}}],"stop_reason":"tool_use","stop_sequence":null,"usage":{"input_tokens":40,"output_tokens":20}}"#;

const TOOL_RESULT_RESPONSE: &str = r#"{"id":"msg_tool02","type":"message","role":"assistant","model":"mock-model","content":[{"type":"text","text":"15 times 7 equals 105."}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":50,"output_tokens":10}}"#;

const CONTENT_BLOCK_RESPONSE: &str = r#"{"id":"msg_block01","type":"message","role":"assistant","model":"mock-model","content":[{"type":"text","text":"2"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":12,"output_tokens":2}}"#;

const SSE_RESPONSE: &str = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_stream01\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"mock-model\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" there\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

// OGX: test_messages_non_streaming_basic
#[test]
fn non_streaming_basic() {
    let backend = Backend::fixed(BASIC_RESPONSE)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &anthropic_post(
            "/v1/messages",
            r#"{"model":"mock-model","messages":[{"role":"user","content":"What is 2+2? Reply with just the number."}],"max_tokens":64}"#,
        ),
    );
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

// OGX: test_messages_non_streaming_with_system
#[test]
fn non_streaming_with_system() {
    let backend = Backend::fixed(SYSTEM_RESPONSE)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &anthropic_post(
            "/v1/messages",
            r#"{"model":"mock-model","messages":[{"role":"user","content":"What are you?"}],"system":"You are a helpful pirate. Always respond in pirate speak.","max_tokens":128}"#,
        ),
    );
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

// OGX: test_messages_non_streaming_multi_turn
#[test]
fn non_streaming_multi_turn() {
    let backend = Backend::fixed(MULTI_TURN_RESPONSE)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &anthropic_post(
            "/v1/messages",
            r#"{"model":"mock-model","messages":[{"role":"user","content":"My name is Alice."},{"role":"assistant","content":"Hello Alice! Nice to meet you."},{"role":"user","content":"What is my name?"}],"max_tokens":64}"#,
        ),
    );
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

// OGX: test_messages_streaming_basic
#[test]
fn streaming_basic() {
    let backend = Backend::fixed(SSE_RESPONSE)
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
            r#"{"model":"mock-model","messages":[{"role":"user","content":"Say hello in one sentence."}],"max_tokens":64,"stream":true}"#,
        ),
    );
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

// OGX: test_messages_streaming_collects_full_text
#[test]
fn streaming_collects_full_text() {
    let backend = Backend::fixed(SSE_RESPONSE)
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

// OGX: test_messages_non_streaming_with_temperature
#[test]
fn non_streaming_with_temperature() {
    let backend = Backend::fixed(TEMPERATURE_RESPONSE)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &anthropic_post(
            "/v1/messages",
            r#"{"model":"mock-model","messages":[{"role":"user","content":"Say hello."}],"max_tokens":32,"temperature":0.0}"#,
        ),
    );
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

// OGX: test_messages_non_streaming_with_stop_sequences
#[test]
fn non_streaming_with_stop_sequences() {
    let backend = Backend::fixed(STOP_SEQUENCES_RESPONSE)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &anthropic_post(
            "/v1/messages",
            r#"{"model":"mock-model","messages":[{"role":"user","content":"Count: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10"}],"max_tokens":128,"stop_sequences":[","]}"#,
        ),
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);
    let data: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(status, 200, "expected 200");
    assert_eq!(data["type"], "message", "type should be message");
}

// OGX: test_messages_with_tool_definitions
#[test]
fn with_tool_definitions() {
    let backend = Backend::fixed(TOOL_DEFS_RESPONSE)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &anthropic_post(
            "/v1/messages",
            r#"{"model":"mock-model","messages":[{"role":"user","content":"What's the weather in San Francisco?"}],"tools":[{"name":"get_weather","description":"Get the current weather in a given location","input_schema":{"type":"object","properties":{"location":{"type":"string","description":"The city and state"}},"required":["location"]}}],"max_tokens":256}"#,
        ),
    );
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

// OGX: test_messages_tool_use_round_trip
#[test]
fn tool_use_round_trip() {
    let backend = Backend::fixed(TOOL_RESULT_RESPONSE)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &anthropic_post(
            "/v1/messages",
            r#"{"model":"mock-model","messages":[{"role":"user","content":"Use the calculator tool to compute 15 * 7."},{"role":"assistant","content":[{"type":"tool_use","id":"toolu_test01","name":"calculator","input":{"expression":"15 * 7"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_test01","content":"105"}]}],"tools":[{"name":"calculator","description":"Perform basic arithmetic.","input_schema":{"type":"object","properties":{"expression":{"type":"string"}},"required":["expression"]}}],"max_tokens":256}"#,
        ),
    );
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

// OGX: test_messages_response_headers
#[test]
fn response_headers() {
    let backend = Backend::fixed(BASIC_RESPONSE)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &anthropic_post(
            "/v1/messages",
            r#"{"model":"mock-model","messages":[{"role":"user","content":"Hi"}],"max_tokens":16}"#,
        ),
    );
    let status = parse_status(&raw);

    assert_eq!(status, 200, "expected 200");
    let raw_lower = raw.to_lowercase();
    assert!(
        raw_lower.contains("anthropic-version: 2023-06-01"),
        "response should include anthropic-version header"
    );
}

// OGX: test_messages_content_block_array
#[test]
fn content_block_array() {
    let backend = Backend::fixed(CONTENT_BLOCK_RESPONSE)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&passthrough_yaml(proxy_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &anthropic_post(
            "/v1/messages",
            r#"{"model":"mock-model","messages":[{"role":"user","content":[{"type":"text","text":"What is 1+1? Reply with just the number."}]}],"max_tokens":32}"#,
        ),
    );
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
