// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! End-to-end tests for OPA and CEL rules over the parsed inference request.

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    BackendGuard, example_config_path, free_port, http_get, http_send, parse_body, parse_header, parse_status,
    patch_yaml, start_echo_backend, start_proxy, start_stateful_backend,
};

const FIXTURE_ISSUER: &str = "https://idp.example.com";
const FIXTURE_AUDIENCE: &str = "praxis-policy-example";
const FIXTURE_SECRET: &str = "REPLACE-WITH-A-PROPERLY-RANDOM-SHARED-SECRET-DO-NOT-COMMIT";

/// Response the probe backend returns to its first caller.
const FIRST_HIT: &str = "first-hit";

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Mint a JWT accepted by the fixture.
fn mint_fixture_jwt(subject: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs();
    let claims = serde_json::json!({
        "iss": FIXTURE_ISSUER,
        "aud": FIXTURE_AUDIENCE,
        "sub": subject,
        "iat": now,
        "exp": now + 300,
    });
    super::jwt::hs256(&claims, None, FIXTURE_SECRET.as_bytes())
}

/// Load the inference example against the structured-input fixture.
fn load_example(proxy_port: u16, backend_port: u16, max_request_bytes: Option<usize>) -> Config {
    let praxis_yaml_path = example_config_path("security/policy-llm.yaml");
    let policy_yaml_path = format!("{}/fixtures/llm-request-policy.yaml", env!("CARGO_MANIFEST_DIR"));

    let raw = std::fs::read_to_string(&praxis_yaml_path).unwrap_or_else(|e| panic!("read {praxis_yaml_path}: {e}"));
    let mut yaml = raw.replace("/etc/praxis/llm-policy.yaml", &policy_yaml_path);
    if let Some(limit) = max_request_bytes {
        yaml = yaml.replace(
            "require_model: true",
            &format!("require_model: true\n          max_request_bytes: {limit}"),
        );
    }
    let port_map = HashMap::from([("127.0.0.1:3000", backend_port)]);
    let patched = patch_yaml(&yaml, proxy_port, &port_map);
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse security/policy-llm.yaml: {e}"))
}

/// Send an authenticated JSON `POST` and return the raw response.
fn post_json(addr: &str, path: &str, body: &str) -> String {
    let token = mint_fixture_jwt("agent");
    http_send(
        addr,
        &format!(
            "POST {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Authorization: Bearer {token}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len(),
        ),
    )
}

/// A backend that answers [`FIRST_HIT`] only to the first request it sees.
fn start_probe_backend() -> BackendGuard {
    start_stateful_backend(vec![(200, FIRST_HIT.to_owned())])
}

/// Assert that nothing reached `backend` by claiming its first response.
fn assert_backend_untouched(backend: &BackendGuard) {
    let (status, body) = http_get(&format!("127.0.0.1:{}", backend.port()), "/", None);
    assert_eq!(
        (status, body.as_str()),
        (200, FIRST_HIT),
        "the probe must still hold its first response, so no request reached upstream",
    );
}

/// Assert an allowed request reached upstream byte for byte.
fn assert_forwarded_unchanged(path: &str, body: &str) {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let proxy = start_proxy(&load_example(proxy_port, backend.port(), None));

    let raw = post_json(proxy.addr(), path, body);
    assert_eq!(parse_status(&raw), 200, "raw response:\n{raw}");
    assert_eq!(parse_body(&raw), body, "upstream must receive the exact request bytes");
}

/// Assert a request is denied with 403 and never forwarded.
fn assert_denied_unforwarded(path: &str, body: &str) -> String {
    let backend = start_probe_backend();
    let proxy_port = free_port();
    let proxy = start_proxy(&load_example(proxy_port, backend.port(), None));

    let raw = post_json(proxy.addr(), path, body);
    assert_eq!(parse_status(&raw), 403, "raw response:\n{raw}");
    assert_backend_untouched(&backend);
    raw
}

/// A Chat Completions body for `model` whose tools are named `tools`.
fn chat_body(model: &str, tools: &[&str]) -> String {
    let tools: Vec<_> = tools
        .iter()
        .map(|name| serde_json::json!({"type": "function", "function": {"name": name}}))
        .collect();
    serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": "pay the invoice"}],
        "tools": tools,
    })
    .to_string()
}

/// A Chat Completions body for `model` using the legacy `functions` list.
fn legacy_functions_body(model: &str, functions: &[&str]) -> String {
    let functions: Vec<_> = functions.iter().map(|name| serde_json::json!({"name": name})).collect();
    serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": "pay the invoice"}],
        "functions": functions,
    })
    .to_string()
}

/// A Responses body whose `input` is one user message and whose tools are flat.
fn responses_body(tools: &[&str]) -> String {
    let tools: Vec<_> = tools
        .iter()
        .map(|name| serde_json::json!({"type": "function", "name": name}))
        .collect();
    serde_json::json!({
        "model": "responses-cel",
        "input": [{"role": "user", "content": [{"type": "input_text", "text": "pay the invoice"}]}],
        "tools": tools,
    })
    .to_string()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn a_cel_rule_denies_a_forbidden_second_tool_before_upstream() {
    assert_denied_unforwarded(
        "/v1/chat/completions",
        &chat_body("chat-cel", &["lookup", "transfer_funds"]),
    );
}

#[test]
fn an_opa_rule_denies_a_forbidden_second_tool_before_upstream() {
    assert_denied_unforwarded(
        "/v1/chat/completions",
        &chat_body("chat-opa", &["lookup", "transfer_funds"]),
    );
}

#[test]
fn a_cel_rule_forwards_permitted_tools_unchanged() {
    assert_forwarded_unchanged("/v1/chat/completions", &chat_body("chat-cel", &["lookup", "weather"]));
}

#[test]
fn an_opa_rule_forwards_permitted_tools_unchanged() {
    assert_forwarded_unchanged("/v1/chat/completions", &chat_body("chat-opa", &["lookup", "weather"]));
}

#[test]
fn a_responses_request_is_authorized_on_its_input_and_forwarded_unchanged() {
    assert_forwarded_unchanged("/v1/responses", &responses_body(&["lookup"]));
}

#[test]
fn a_responses_request_with_a_forbidden_tool_is_denied_before_upstream() {
    assert_denied_unforwarded("/v1/responses", &responses_body(&["lookup", "transfer_funds"]));
}

#[test]
fn a_denial_does_not_echo_request_content() {
    for model in ["chat-cel", "chat-opa"] {
        let body = serde_json::json!({
            "model": model,
            "messages": [{"role": "user", "content": "SECRET-MARKER"}],
            "tools": [
                {"type": "function", "function": {"name": "lookup", "description": "SECRET-MARKER"}},
                {"type": "function", "function": {"name": "transfer_funds", "description": "SECRET-MARKER"}},
            ],
        })
        .to_string();
        let raw = assert_denied_unforwarded("/v1/chat/completions", &body);

        let violation = parse_header(&raw, "x-policy-violation");
        assert!(
            violation.is_some(),
            "a denial must name its violation; raw response:\n{raw}"
        );
        assert!(
            !violation.unwrap_or_default().contains("SECRET-MARKER"),
            "the violation header must not carry request content",
        );
        assert!(
            !parse_body(&raw).contains("SECRET-MARKER"),
            "the {model} denial body must not carry request content; raw response:\n{raw}",
        );
        assert!(!raw.contains("SECRET-MARKER"), "raw response:\n{raw}");
    }
}

#[test]
fn an_oversized_body_is_rejected_before_policy_or_upstream() {
    let backend = start_probe_backend();
    let proxy_port = free_port();
    let proxy = start_proxy(&load_example(proxy_port, backend.port(), Some(256)));

    let padding = "x".repeat(1024);
    let body = serde_json::json!({
        "model": "chat-cel",
        "messages": [{"role": "user", "content": padding}],
    })
    .to_string();
    let raw = post_json(proxy.addr(), "/v1/chat/completions", &body);

    assert_eq!(parse_status(&raw), 413, "raw response:\n{raw}");
    assert_backend_untouched(&backend);
}

#[test]
fn legacy_functions_are_guarded_like_tools() {
    for model in ["chat-cel", "chat-opa"] {
        assert_denied_unforwarded(
            "/v1/chat/completions",
            &legacy_functions_body(model, &["lookup", "transfer_funds"]),
        );
        assert_forwarded_unchanged(
            "/v1/chat/completions",
            &legacy_functions_body(model, &["lookup", "weather"]),
        );
    }
}

#[test]
fn a_body_repeating_a_key_is_rejected_before_policy_or_upstream() {
    for body in [
        r#"{"model":"chat-cel","tools":[{"type":"function","function":{"name":"transfer_funds"}}],"tools":[]}"#,
        r#"{"model":"chat-opa","tools":[{"type":"function","function":{"name":"lookup","name":"transfer_funds"}}]}"#,
        r#"{"model":"chat-cel","model":"chat-opa","messages":[]}"#,
    ] {
        let backend = start_probe_backend();
        let proxy_port = free_port();
        let proxy = start_proxy(&load_example(proxy_port, backend.port(), None));

        let raw = post_json(proxy.addr(), "/v1/chat/completions", body);
        assert_eq!(parse_status(&raw), 400, "body {body}; raw response:\n{raw}");
        assert_eq!(
            parse_header(&raw, "x-policy-violation").as_deref(),
            Some("llm.duplicate_key"),
            "raw response:\n{raw}",
        );
        assert!(
            !parse_body(&raw).contains("transfer_funds"),
            "the rejection must not echo request content; raw response:\n{raw}",
        );
        assert_backend_untouched(&backend);
    }
}
