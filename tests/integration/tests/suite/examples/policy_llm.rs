// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the inference authorization example.

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    example_config_path, free_port, http_send, parse_status, patch_yaml, start_backend_with_shutdown, start_proxy,
};

const FIXTURE_ISSUER: &str = "https://idp.example.com";
const FIXTURE_AUDIENCE: &str = "praxis-policy-example";
const FIXTURE_SECRET: &str = "REPLACE-WITH-A-PROPERLY-RANDOM-SHARED-SECRET-DO-NOT-COMMIT";

/// Mint a JWT accepted by the inference policy fixture.
fn mint_fixture_jwt(subject: &str, roles: &[&str]) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs();
    let claims = serde_json::json!({
        "iss": FIXTURE_ISSUER,
        "aud": FIXTURE_AUDIENCE,
        "sub": subject,
        "roles": roles,
        "iat": now,
        "exp": now + 300,
    });
    super::jwt::hs256(&claims, None, FIXTURE_SECRET.as_bytes())
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Load the inference example with test paths and ports.
#[expect(clippy::needless_pass_by_value, reason = "callers construct the map inline")]
fn load_example(proxy_port: u16, port_map: HashMap<&str, u16>) -> Config {
    let praxis_yaml_path = example_config_path("security/policy-llm.yaml");
    let policy_yaml_path = format!("{}/fixtures/llm-policy.yaml", env!("CARGO_MANIFEST_DIR"));

    let raw = std::fs::read_to_string(&praxis_yaml_path).unwrap_or_else(|e| panic!("read {praxis_yaml_path}: {e}"));
    let with_policy = raw.replace("/etc/praxis/llm-policy.yaml", &policy_yaml_path);
    let patched = patch_yaml(&with_policy, proxy_port, &port_map);
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse security/policy-llm.yaml: {e}"))
}

fn backend_map(port: u16) -> HashMap<&'static str, u16> {
    HashMap::from([("127.0.0.1:3000", port)])
}

/// Send a chat-completions request and return the raw response.
fn post_completion(addr: &str, token: Option<&str>, body: &str) -> String {
    let authorization = token.map_or_else(String::new, |t| format!("Authorization: Bearer {t}\r\n"));
    http_send(
        addr,
        &format!(
            "POST /v1/chat/completions HTTP/1.1\r\n\
             Host: localhost\r\n\
             {authorization}\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len(),
        ),
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn an_allowed_model_reaches_the_backend() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("support-bot", &["support"]);
    let raw = post_completion(
        proxy.addr(),
        Some(&token),
        r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}"#,
    );

    assert_eq!(
        parse_status(&raw),
        200,
        "a model the policy admits must reach the backend with no classifier in the chain; \
         raw response:\n{raw}",
    );
    assert!(
        raw.contains("ok"),
        "the upstream body should reach the client on the allow path; raw response:\n{raw}",
    );
}

#[test]
fn a_reserved_model_passes_for_a_caller_with_the_role() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("research-bot", &["research"]);
    let raw = post_completion(proxy.addr(), Some(&token), r#"{"model":"gpt-4o","messages":[]}"#);

    assert_eq!(
        parse_status(&raw),
        200,
        "the role-gated route must admit a caller carrying the role; raw response:\n{raw}",
    );
}

#[test]
fn a_reserved_model_is_denied_for_a_caller_without_the_role() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("support-bot", &["support"]);
    let raw = post_completion(proxy.addr(), Some(&token), r#"{"model":"gpt-4o","messages":[]}"#);

    assert_eq!(
        parse_status(&raw),
        403,
        "the same model must be refused without the role; raw response:\n{raw}",
    );
    assert!(
        raw.to_lowercase().contains("x-policy-violation:"),
        "a denial must name the rule that fired; raw response:\n{raw}",
    );
    assert!(
        !raw.contains("\"jsonrpc\""),
        "an inference client must not be answered with a JSON-RPC envelope; raw response:\n{raw}",
    );
}

#[test]
fn every_model_a_list_route_names_is_selected() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("research-bot", &["research"]);
    let raw = post_completion(proxy.addr(), Some(&token), r#"{"model":"o3","messages":[]}"#);

    assert_eq!(
        parse_status(&raw),
        200,
        "the second name in the list route must select it too; raw response:\n{raw}",
    );
}

#[test]
fn a_model_no_route_names_is_denied_by_the_catch_all() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("support-bot", &["support"]);
    let raw = post_completion(
        proxy.addr(),
        Some(&token),
        r#"{"model":"some-unlisted-model","messages":[]}"#,
    );

    assert_eq!(parse_status(&raw), 403, "raw response:\n{raw}");
    assert!(
        raw.to_lowercase().contains("x-policy-violation: model_not_allowed"),
        "the catch-all's violation code must reach the response; raw response:\n{raw}",
    );
    assert!(
        raw.to_lowercase().contains("x-authz-denied: model-not-allowed"),
        "the policy's denyWith headers must reach the client; raw response:\n{raw}",
    );
    assert!(
        raw.contains(r#""code":"model_not_allowed""#),
        "and its denyWith body; raw response:\n{raw}",
    );
}

#[test]
fn a_promoted_sampling_parameter_is_enforceable() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("support-bot", &["support"]);
    let raw = post_completion(
        proxy.addr(),
        Some(&token),
        r#"{"model":"gpt-4o-mini","stream":true,"messages":[]}"#,
    );

    assert_eq!(
        parse_status(&raw),
        403,
        "a rule over `custom.llm.stream` must see the promoted request parameter; raw response:\n{raw}",
    );
    assert!(
        raw.to_lowercase().contains("x-policy-violation: stream_not_allowed"),
        "raw response:\n{raw}",
    );
}

#[test]
fn a_body_with_no_model_fails_closed() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("support-bot", &["support"]);
    let raw = post_completion(proxy.addr(), Some(&token), r#"{"messages":[]}"#);

    assert_eq!(
        parse_status(&raw),
        403,
        "a request the filter cannot attribute to a model must not reach the backend; \
         raw response:\n{raw}",
    );
    assert!(
        raw.to_lowercase().contains("x-policy-violation: llm.model_missing"),
        "raw response:\n{raw}",
    );
}

#[test]
fn a_discovery_call_reaches_the_backend() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("support-bot", &["support"]);
    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET /v1/models HTTP/1.1\r\n\
             Host: localhost\r\n\
             Authorization: Bearer {token}\r\n\
             Connection: close\r\n\
             \r\n",
        ),
    );

    assert_eq!(
        parse_status(&raw),
        200,
        "a bodyless discovery call must not be denied for carrying no model; raw response:\n{raw}",
    );
}

#[test]
fn streaming_is_refused_for_every_model() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("research-bot", &["research"]);
    let raw = post_completion(
        proxy.addr(),
        Some(&token),
        r#"{"model":"gpt-4o","stream":true,"messages":[]}"#,
    );

    assert_eq!(
        parse_status(&raw),
        403,
        "the role-gated route must refuse a stream as well; raw response:\n{raw}",
    );
    assert!(
        raw.to_lowercase().contains("x-policy-violation: stream_not_allowed"),
        "raw response:\n{raw}",
    );
}

#[test]
fn a_string_spelled_stream_flag_is_also_refused() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("support-bot", &["support"]);
    let raw = post_completion(
        proxy.addr(),
        Some(&token),
        r#"{"model":"gpt-4o-mini","stream":"true","messages":[]}"#,
    );

    assert_eq!(
        parse_status(&raw),
        403,
        "`\"true\"` streams on a lax backend, so policy has to refuse it; raw response:\n{raw}",
    );
    assert!(
        raw.to_lowercase().contains("x-policy-violation: stream_not_allowed"),
        "raw response:\n{raw}",
    );
}

#[test]
fn an_unauthenticated_request_is_rejected_before_the_body_matters() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let raw = post_completion(proxy.addr(), None, r#"{"model":"gpt-4o-mini","messages":[]}"#);

    assert_eq!(
        parse_status(&raw),
        401,
        "the identity gate runs first, whatever the body says; raw response:\n{raw}",
    );
    assert!(
        raw.to_lowercase().contains("www-authenticate: bearer"),
        "raw response:\n{raw}",
    );
}
