// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the `prompt_enrich` filter.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, json_post, parse_body, parse_status, start_echo_backend, start_header_echo_backend,
    start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn prompt_enrichment_prepends_system_message() {
    let backend_guard = start_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = prepend_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post(
            "/v1/chat/completions",
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#,
        ),
    );

    assert_eq!(parse_status(&raw), 200, "enrichment should return 200");
    let body = parse_body(&raw);
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("backend should echo valid JSON");
    let messages = parsed["messages"].as_array().expect("messages should be an array");
    assert_eq!(messages.len(), 2, "should have injected + original message");
    assert_eq!(messages[0]["role"], "system", "injected message should be first");
    assert_eq!(
        messages[0]["content"], "You are a helpful assistant.",
        "injected content should match config"
    );
    assert_eq!(messages[1]["role"], "user", "original user message should follow");
    assert_eq!(messages[1]["content"], "Hello", "original content should be preserved");
    assert_eq!(parsed["model"], "gpt-4o", "model field should be preserved");
}

#[test]
fn prompt_enrichment_appends_user_message() {
    let backend_guard = start_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = append_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post(
            "/v1/chat/completions",
            r#"{"messages":[{"role":"user","content":"Hi"}]}"#,
        ),
    );

    assert_eq!(parse_status(&raw), 200, "append enrichment should return 200");
    let body = parse_body(&raw);
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("backend should echo valid JSON");
    let messages = parsed["messages"].as_array().expect("messages should be an array");
    assert_eq!(messages.len(), 2, "should have original + appended message");
    assert_eq!(messages[0]["content"], "Hi", "original message should be first");
    assert_eq!(messages[1]["role"], "user", "appended message should be last");
    assert_eq!(
        messages[1]["content"], "Cite your sources.",
        "appended content should match config"
    );
}

#[test]
fn prompt_enrichment_preserves_non_chat_traffic_when_continue() {
    let backend_guard = start_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = prepend_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /v1/chat/completions HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: 11\r\n\
         Connection: close\r\n\r\n\
         hello world",
    );

    assert_eq!(parse_status(&raw), 200, "non-JSON body should pass through");
    let body = parse_body(&raw);
    assert!(
        body.contains("hello world"),
        "backend should receive original body: {body}"
    );
}

#[test]
fn prompt_enrichment_rejects_invalid_json_when_configured() {
    let backend_guard = start_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = reject_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /v1/chat HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: 11\r\n\
         Connection: close\r\n\r\n\
         not json!!!",
    );

    assert_eq!(
        parse_status(&raw),
        400,
        "invalid JSON should return 400 when on_invalid: reject"
    );
}

#[test]
fn prompt_enrichment_updates_content_length() {
    let echo_guard = start_echo_backend();
    let echo_port = echo_guard.port();
    let header_guard = start_header_echo_backend();
    let header_port = header_guard.port();
    let proxy_port_echo = free_port();
    let proxy_port_header = free_port();
    let input_body = r#"{"messages":[{"role":"user","content":"Hi"}]}"#;

    let echo_yaml = prepend_yaml(proxy_port_echo, echo_port);
    let echo_config = Config::from_yaml(&echo_yaml).unwrap();
    let echo_proxy = start_proxy(&echo_config);
    let echo_raw = http_send(echo_proxy.addr(), &json_post("/v1/chat/completions", input_body));
    assert_eq!(parse_status(&echo_raw), 200, "echo proxy should return 200");
    let enriched_body = parse_body(&echo_raw);
    let enriched_len = enriched_body.len();

    let header_yaml = prepend_yaml(proxy_port_header, header_port);
    let header_config = Config::from_yaml(&header_yaml).unwrap();
    let header_proxy = start_proxy(&header_config);
    let header_raw = http_send(header_proxy.addr(), &json_post("/v1/chat/completions", input_body));
    assert_eq!(parse_status(&header_raw), 200, "header proxy should return 200");
    let headers_body = parse_body(&header_raw);
    let echoed_cl = headers_body
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().to_owned())
        })
        .expect("backend should echo content-length header");
    let echoed_len: usize = echoed_cl
        .parse()
        .expect("echoed content-length should be a valid number");

    assert_eq!(
        echoed_len, enriched_len,
        "echoed content-length ({echoed_len}) should match enriched body size ({enriched_len})"
    );
}

#[test]
fn prompt_enrichment_conditions_enable_per_route_behavior() {
    let backend_guard = start_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = conditions_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let code_raw = http_send(
        proxy.addr(),
        &json_post("/code/chat", r#"{"messages":[{"role":"user","content":"Hi"}]}"#),
    );
    assert_eq!(parse_status(&code_raw), 200, "code route should return 200");
    let code_body = parse_body(&code_raw);
    let code_parsed: serde_json::Value = serde_json::from_str(&code_body).expect("code route should echo valid JSON");
    let code_messages = code_parsed["messages"].as_array().expect("messages should be an array");
    assert_eq!(
        code_messages[0]["content"], "You are a code review assistant.",
        "code route should get code-specific prompt"
    );

    let general_raw = http_send(
        proxy.addr(),
        &json_post("/general/chat", r#"{"messages":[{"role":"user","content":"Hi"}]}"#),
    );
    assert_eq!(parse_status(&general_raw), 200, "general route should return 200");
    let general_body = parse_body(&general_raw);
    let general_parsed: serde_json::Value =
        serde_json::from_str(&general_body).expect("general route should echo valid JSON");
    let general_messages = general_parsed["messages"]
        .as_array()
        .expect("messages should be an array");
    assert_eq!(
        general_messages[0]["content"], "You are a general assistant.",
        "general route should get general prompt"
    );
}

#[test]
fn prompt_enrichment_before_model_to_header_composes() {
    let header_guard = start_header_echo_backend();
    let header_port = header_guard.port();
    let proxy_port = free_port();
    let yaml = compose_yaml(proxy_port, header_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post(
            "/v1/chat/completions",
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}"#,
        ),
    );

    assert_eq!(parse_status(&raw), 200, "compose test should return 200");
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-model: gpt-4o"),
        "model_to_header should still extract the model; prompt_enrich composition needs StreamBuffer to keep buffering after early Release: {body}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn prepend_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: prompt_enrich
        prepend:
          - role: system
            content: "You are a helpful assistant."
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

fn append_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: prompt_enrich
        append:
          - role: user
            content: "Cite your sources."
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

fn reject_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: prompt_enrich
        on_invalid: reject
        prepend:
          - role: system
            content: "You are a helpful assistant."
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

fn conditions_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: prompt_enrich
        prepend:
          - role: system
            content: "You are a code review assistant."
        conditions:
          - when:
              path_prefix: "/code/"
      - filter: prompt_enrich
        prepend:
          - role: system
            content: "You are a general assistant."
        conditions:
          - unless:
              path_prefix: "/code/"
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

fn compose_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: prompt_enrich
        prepend:
          - role: system
            content: "You are a helpful assistant."
      - filter: model_to_header
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
