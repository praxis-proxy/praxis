// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the `openai_responses_format` mode routing.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, json_post, parse_body, parse_status, start_backend_with_shutdown, start_echo_backend,
    start_proxy,
};

// -----------------------------------------------------------------------------
// Mode Routing
// -----------------------------------------------------------------------------

#[test]
fn mode_branch_routes_stateful_conditions_to_stateful_path() {
    let cases = [
        (
            "store omitted (defaults to true)",
            r#"{"model":"gpt-4.1","input":"Hello"}"#,
        ),
        ("store=true", r#"{"model":"gpt-4.1","input":"Hello","store":true}"#),
        (
            "previous_response_id",
            r#"{"model":"gpt-4.1","input":"Hello","store":false,"previous_response_id":"resp_abc"}"#,
        ),
        (
            "non-empty tools",
            r#"{"model":"gpt-4.1","input":"Hello","store":false,"tools":[{"type":"function","function":{"name":"get_weather"}}]}"#,
        ),
        (
            "background=true",
            r#"{"model":"gpt-4.1","input":"Hello","store":false,"background":true}"#,
        ),
        (
            "conversation present",
            r#"{"model":"gpt-4.1","input":"Hello","store":false,"conversation":{"id":"conv_123"}}"#,
        ),
        (
            "prompt.id present",
            r#"{"model":"gpt-4.1","input":"Hello","store":false,"prompt":{"id":"pmpt_123"}}"#,
        ),
    ];

    for (label, body) in cases {
        assert_routes_to("stateful-path", label, body);
    }
}

#[test]
fn mode_branch_routes_stateless_conditions_to_default_path() {
    let cases = [
        (
            "store=false, no stateful markers",
            r#"{"model":"gpt-4.1","input":"Hello","store":false}"#,
        ),
        (
            "store=false with empty tools",
            r#"{"model":"gpt-4.1","input":"Hello","store":false,"tools":[]}"#,
        ),
    ];

    for (label, body) in cases {
        assert_routes_to("stateless-path", label, body);
    }
}

#[test]
fn mode_branch_stateless_body_not_mutated() {
    let echo_guard = start_echo_backend();
    let stateful_guard = start_backend_with_shutdown("stateful-path");
    let proxy_port = free_port();

    let config = Config::from_yaml(&mode_branch_yaml(proxy_port, stateful_guard.port(), echo_guard.port())).unwrap();

    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4.1","input":"Hello, world!","store":false,"temperature":0.7}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "echo should return 200");
    assert_eq!(
        parse_body(&raw),
        body,
        "stateless should forward request body unchanged"
    );
}

#[test]
fn mode_branch_chat_completions_skips_branch() {
    let stateless_guard = start_backend_with_shutdown("stateless-path");
    let stateful_guard = start_backend_with_shutdown("stateful-path");
    let proxy_port = free_port();

    let config = Config::from_yaml(&mode_branch_yaml(
        proxy_port,
        stateful_guard.port(),
        stateless_guard.port(),
    ))
    .unwrap();

    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/chat/completions", body));

    assert_eq!(parse_status(&raw), 200, "default should return 200");
    assert_eq!(
        parse_body(&raw),
        "stateless-path",
        "chat completions should skip mode branch (no mode set) and fall through"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Assert that a request body routes to the expected backend.
fn assert_routes_to(expected_backend: &str, label: &str, body: &str) {
    let stateless_guard = start_backend_with_shutdown("stateless-path");
    let stateful_guard = start_backend_with_shutdown("stateful-path");
    let proxy_port = free_port();

    let config = Config::from_yaml(&mode_branch_yaml(
        proxy_port,
        stateful_guard.port(),
        stateless_guard.port(),
    ))
    .unwrap();

    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "{label}: expected 200");
    assert_eq!(
        parse_body(&raw),
        expected_backend,
        "{label}: expected {expected_backend} routing"
    );
}

/// YAML config with mode-based branch chain routing.
///
/// Stateful requests (mode=stateful) enter the branch chain and route
/// to `stateful_port`. Stateless requests (mode=stateless) or
/// non-Responses requests fall through to `default_port`.
fn mode_branch_yaml(proxy_port: u16, stateful_port: u16, default_port: u16) -> String {
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
        branch_chains:
          - name: stateful_branch
            on_result:
              filter: openai_responses_format
              key: mode
              result: stateful
            rejoin: terminal
            chains:
              - name: stateful_chain
                filters:
                  - filter: router
                    routes:
                      - path_prefix: "/"
                        cluster: "stateful"
                  - filter: load_balancer
                    clusters:
                      - name: "stateful"
                        endpoints:
                          - "127.0.0.1:{stateful_port}"
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
