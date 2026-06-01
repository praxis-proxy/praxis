// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the `openai_responses_format` classifier filter.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, json_post, parse_body, parse_status, start_backend_with_shutdown,
    start_echo_backend_with_shutdown, start_header_echo_backend_with_shutdown, start_proxy,
};

// -----------------------------------------------------------------------------
// Classification and Routing Tests
// -----------------------------------------------------------------------------

#[test]
fn responses_request_routes_to_responses_cluster() {
    let responses_guard = start_backend_with_shutdown("responses-backend");
    let chat_guard = start_backend_with_shutdown("chat-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = routing_yaml(
        proxy_port,
        responses_guard.port(),
        chat_guard.port(),
        default_guard.port(),
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4.1-mini","input":"Hello, world!"}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "responses request should return 200");
    assert_eq!(
        parse_body(&raw),
        "responses-backend",
        "responses request should route to responses cluster"
    );
}

#[test]
fn responses_array_input_routes_to_responses_cluster() {
    let responses_guard = start_backend_with_shutdown("responses-backend");
    let chat_guard = start_backend_with_shutdown("chat-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = routing_yaml(
        proxy_port,
        responses_guard.port(),
        chat_guard.port(),
        default_guard.port(),
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4.1","input":[{"type":"message","role":"user","content":"Hi"}]}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "array input should return 200");
    assert_eq!(
        parse_body(&raw),
        "responses-backend",
        "array input request should route to responses cluster"
    );
}

#[test]
fn chat_completions_routes_to_chat_cluster() {
    let responses_guard = start_backend_with_shutdown("responses-backend");
    let chat_guard = start_backend_with_shutdown("chat-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = routing_yaml(
        proxy_port,
        responses_guard.port(),
        chat_guard.port(),
        default_guard.port(),
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/chat/completions", body));

    assert_eq!(parse_status(&raw), 200, "chat completions should return 200");
    assert_eq!(
        parse_body(&raw),
        "chat-backend",
        "chat completions should route to chat cluster"
    );
}

#[test]
fn unknown_json_routes_to_default_cluster() {
    let responses_guard = start_backend_with_shutdown("responses-backend");
    let chat_guard = start_backend_with_shutdown("chat-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = routing_yaml(
        proxy_port,
        responses_guard.port(),
        chat_guard.port(),
        default_guard.port(),
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4","prompt":"hello"}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "unknown JSON should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "unknown JSON should route to default cluster"
    );
}

#[test]
fn non_json_continues_by_default() {
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = continue_yaml(proxy_port, default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "POST /v1/responses HTTP/1.1\r\n\
         Host: localhost:{proxy_port}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: 11\r\n\
         \r\n\
         hello world"
    );
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200, "non-JSON should continue to default cluster");
    assert_eq!(parse_body(&raw), "default-backend", "non-JSON should reach backend");
}

#[test]
fn unknown_json_rejected_when_configured() {
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = reject_yaml(proxy_port, default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4","prompt":"hello"}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(
        parse_status(&raw),
        400,
        "unknown JSON should be rejected when on_invalid: reject"
    );
    let response_body = parse_body(&raw);
    assert!(
        response_body.contains("unrecognized AI API format"),
        "rejection should mention unrecognized format, got: {response_body}"
    );
}

#[test]
fn invalid_json_rejected_when_configured() {
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = reject_yaml(proxy_port, default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/responses", "not valid json {{{"));

    assert_eq!(parse_status(&raw), 400, "invalid JSON should be rejected");
    let body = parse_body(&raw);
    assert!(
        body.contains("invalid JSON body") || body.contains("invalid_request_error"),
        "rejection should mention invalid JSON, got: {body}"
    );
}

#[test]
fn non_json_rejected_when_configured() {
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = reject_yaml(proxy_port, default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "POST /v1/responses HTTP/1.1\r\n\
         Host: localhost:{proxy_port}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: 11\r\n\
         \r\n\
         hello world"
    );
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(
        parse_status(&raw),
        400,
        "non-JSON should be rejected when on_invalid: reject"
    );
    let body = parse_body(&raw);
    assert!(
        body.contains("not JSON") || body.contains("invalid_request_error"),
        "rejection should mention non-JSON, got: {body}"
    );
}

// -----------------------------------------------------------------------------
// Header Promotion for Routing
// -----------------------------------------------------------------------------

#[test]
fn model_header_routes_to_specific_backend() {
    let model_a_guard = start_backend_with_shutdown("model-a-backend");
    let model_b_guard = start_backend_with_shutdown("model-b-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = model_routing_yaml(
        proxy_port,
        model_a_guard.port(),
        model_b_guard.port(),
        default_guard.port(),
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"model":"model-a","input":"test"}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "model-a should return 200");
    assert_eq!(
        parse_body(&raw),
        "model-a-backend",
        "model-a should route to model-a-backend via promoted x-praxis-ai-model header"
    );

    let body_b = r#"{"model":"model-b","input":"test"}"#;
    let raw_b = http_send(proxy.addr(), &json_post("/v1/responses", body_b));

    assert_eq!(parse_status(&raw_b), 200, "model-b should return 200");
    assert_eq!(
        parse_body(&raw_b),
        "model-b-backend",
        "model-b should route to model-b-backend via promoted x-praxis-ai-model header"
    );
}

#[test]
fn stream_header_routes_streaming_traffic() {
    let stream_guard = start_backend_with_shutdown("stream-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = stream_routing_yaml(proxy_port, stream_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4.1","input":"test","stream":true}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "streaming request should return 200");
    assert_eq!(
        parse_body(&raw),
        "stream-backend",
        "stream:true should route to stream-backend via promoted x-praxis-ai-stream header"
    );

    let body_no_stream = r#"{"model":"gpt-4.1","input":"test"}"#;
    let raw_no_stream = http_send(proxy.addr(), &json_post("/v1/responses", body_no_stream));

    assert_eq!(parse_status(&raw_no_stream), 200, "non-streaming should return 200");
    assert_eq!(
        parse_body(&raw_no_stream),
        "default-backend",
        "request without stream should route to default-backend"
    );
}

#[test]
fn reserved_headers_stripped_before_upstream() {
    let backend_guard = start_header_echo_backend_with_shutdown();
    let proxy_port = free_port();

    let yaml = header_echo_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4.1","input":"test","stream":true}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "should return 200");
    let echoed = parse_body(&raw).to_lowercase();
    assert!(
        !echoed.contains("x-praxis-ai-format"),
        "x-praxis-ai-format should be stripped before upstream (reserved header)"
    );
    assert!(
        !echoed.contains("x-praxis-ai-model"),
        "x-praxis-ai-model should be stripped before upstream (reserved header)"
    );
    assert!(
        !echoed.contains("x-praxis-ai-stream"),
        "x-praxis-ai-stream should be stripped before upstream (reserved header)"
    );
}

// -----------------------------------------------------------------------------
// Bounded Value Promotion Tests
// -----------------------------------------------------------------------------

#[test]
fn oversized_model_not_promoted_to_header() {
    let model_guard = start_backend_with_shutdown("model-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let long_model = "x".repeat(300);
    let yaml = model_routing_yaml(proxy_port, model_guard.port(), model_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = format!(r#"{{"model":"{long_model}","input":"test"}}"#);
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", &body));

    assert_eq!(parse_status(&raw), 200, "oversized model should still return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "oversized model (>256 bytes) should not match a route, falling to default"
    );
}

#[test]
fn control_char_model_not_promoted_to_header() {
    let model_guard = start_backend_with_shutdown("model-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = model_routing_yaml(proxy_port, model_guard.port(), model_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"model":"bad\nmodel","input":"test"}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "control-char model should still return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "model with control chars should not be promoted, falling to default"
    );
}

// -----------------------------------------------------------------------------
// Filter Results Branch Tests
// -----------------------------------------------------------------------------

#[test]
fn filter_results_enable_branch_routing() {
    let responses_guard = start_backend_with_shutdown("responses-branch-hit");
    let default_guard = start_backend_with_shutdown("default-branch-miss");
    let proxy_port = free_port();

    let yaml = branch_yaml(proxy_port, responses_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4.1","input":"test"}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "responses request should return 200");
    assert_eq!(
        parse_body(&raw),
        "responses-branch-hit",
        "branch on_result should fire for responses format and route to branch cluster"
    );

    let chat_body = r#"{"model":"gpt-4","messages":[]}"#;
    let raw_chat = http_send(proxy.addr(), &json_post("/v1/chat/completions", chat_body));

    assert_eq!(parse_status(&raw_chat), 200, "chat request should return 200");
    assert_eq!(
        parse_body(&raw_chat),
        "default-branch-miss",
        "branch should not fire for openai_chat_completions, falling through to default"
    );
}

#[test]
fn background_filter_result_enables_branch_routing() {
    let background_guard = start_backend_with_shutdown("background-branch-hit");
    let default_guard = start_backend_with_shutdown("default-branch-miss");
    let proxy_port = free_port();

    let yaml = background_branch_yaml(proxy_port, background_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4.1","input":"test","background":true,"store":false,"stream":true}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(
        parse_status(&raw),
        200,
        "background request should route without protocol validation"
    );
    assert_eq!(
        parse_body(&raw),
        "background-branch-hit",
        "branch on_result should fire for background:true"
    );

    let foreground_body = r#"{"model":"gpt-4.1","input":"test","background":false}"#;
    let foreground_raw = http_send(proxy.addr(), &json_post("/v1/responses", foreground_body));

    assert_eq!(
        parse_status(&foreground_raw),
        200,
        "foreground request should return 200"
    );
    assert_eq!(
        parse_body(&foreground_raw),
        "default-branch-miss",
        "background:false should not match the background:true branch"
    );
}

// -----------------------------------------------------------------------------
// Body Preservation Tests
// -----------------------------------------------------------------------------

#[test]
fn body_unchanged_after_classification() {
    let backend_guard = start_echo_backend_with_shutdown();
    let proxy_port = free_port();

    let yaml = echo_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4.1-mini","input":"Hello, world!","stream":false,"store":true}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "should return 200");
    let echoed = parse_body(&raw);
    assert_eq!(
        echoed, body,
        "body should be byte-for-byte unchanged after classification"
    );
}

#[test]
fn large_body_over_64k_classified_and_forwarded() {
    let backend_guard = start_echo_backend_with_shutdown();
    let proxy_port = free_port();

    let yaml = echo_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let padding = "x".repeat(65_536); // 64 KiB of padding
    let body = format!(r#"{{"model":"gpt-4.1","input":"{padding}"}}"#);
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", &body));

    assert_eq!(parse_status(&raw), 200, "large body should return 200");
    let echoed = parse_body(&raw);
    assert_eq!(echoed, body, "large body should be byte-for-byte unchanged");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// YAML config for routing by classified format using header matching.
fn routing_yaml(proxy_port: u16, responses_port: u16, chat_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: openai_responses_format
        on_invalid: continue
      - filter: router
        routes:
          - path: "/v1/responses"
            headers:
              x-praxis-ai-format: "openai_responses"
            cluster: "responses"
          - path: "/v1/chat/completions"
            headers:
              x-praxis-ai-format: "openai_chat_completions"
            cluster: "chat"
          - path_prefix: "/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "responses"
            endpoints:
              - "127.0.0.1:{responses_port}"
          - name: "chat"
            endpoints:
              - "127.0.0.1:{chat_port}"
          - name: "default"
            endpoints:
              - "127.0.0.1:{default_port}"
"#
    )
}

/// YAML config with on_invalid: continue and a catch-all default backend.
fn continue_yaml(proxy_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: openai_responses_format
        on_invalid: continue
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "default"
            endpoints:
              - "127.0.0.1:{default_port}"
"#
    )
}

/// YAML config with on_invalid: reject.
fn reject_yaml(proxy_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: openai_responses_format
        on_invalid: reject
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "default"
            endpoints:
              - "127.0.0.1:{default_port}"
"#
    )
}

/// YAML config that routes all traffic to a header-echo backend.
fn header_echo_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: openai_responses_format
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    )
}

/// YAML config that routes all traffic to an echo (body) backend.
fn echo_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: openai_responses_format
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    )
}

/// YAML config for branch-based routing using filter results.
fn branch_yaml(proxy_port: u16, responses_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: openai_responses_format
        branch_chains:
          - name: responses_branch
            on_result:
              filter: openai_responses_format
              key: format
              result: openai_responses
            rejoin: terminal
            chains:
              - name: responses_chain
                filters:
                  - filter: router
                    routes:
                      - path_prefix: "/"
                        cluster: "responses"
                  - filter: load_balancer
                    clusters:
                      - name: "responses"
                        endpoints:
                          - "127.0.0.1:{responses_port}"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "default"
            endpoints:
              - "127.0.0.1:{default_port}"
"#
    )
}

/// YAML config for branch-based routing using the background filter result.
fn background_branch_yaml(proxy_port: u16, background_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: openai_responses_format
        branch_chains:
          - name: background_branch
            on_result:
              filter: openai_responses_format
              key: background
              result: true
            rejoin: terminal
            chains:
              - name: background_chain
                filters:
                  - filter: router
                    routes:
                      - path_prefix: "/"
                        cluster: "background"
                  - filter: load_balancer
                    clusters:
                      - name: "background"
                        endpoints:
                          - "127.0.0.1:{background_port}"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "default"
            endpoints:
              - "127.0.0.1:{default_port}"
"#
    )
}

/// YAML config for routing by promoted model header.
fn model_routing_yaml(proxy_port: u16, model_a_port: u16, model_b_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: openai_responses_format
      - filter: router
        routes:
          - path_prefix: "/"
            headers:
              x-praxis-ai-model: "model-a"
            cluster: "model-a"
          - path_prefix: "/"
            headers:
              x-praxis-ai-model: "model-b"
            cluster: "model-b"
          - path_prefix: "/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "model-a"
            endpoints:
              - "127.0.0.1:{model_a_port}"
          - name: "model-b"
            endpoints:
              - "127.0.0.1:{model_b_port}"
          - name: "default"
            endpoints:
              - "127.0.0.1:{default_port}"
"#
    )
}

/// YAML config for routing by promoted stream header.
fn stream_routing_yaml(proxy_port: u16, stream_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: openai_responses_format
      - filter: router
        routes:
          - path_prefix: "/"
            headers:
              x-praxis-ai-stream: "true"
            cluster: "stream"
          - path_prefix: "/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "stream"
            endpoints:
              - "127.0.0.1:{stream_port}"
          - name: "default"
            endpoints:
              - "127.0.0.1:{default_port}"
"#
    )
}
