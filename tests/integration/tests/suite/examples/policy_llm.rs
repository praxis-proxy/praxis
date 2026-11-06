// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the inference authorization example.

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    BackendGuard, example_config_path, free_port, http_get, http_send, http_send_on_connection, parse_body,
    parse_status, patch_yaml, start_backend_with_shutdown, start_header_echo_backend, start_proxy,
    start_stateful_backend,
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
fn load_example(proxy_port: u16, port_map: HashMap<&str, u16>) -> Config {
    load_example_with(proxy_port, port_map, &fixture_path())
}

/// The inference policy fixture.
fn fixture_path() -> String {
    format!("{}/fixtures/llm-policy.yaml", env!("CARGO_MANIFEST_DIR"))
}

/// Load the inference example against `policy_yaml_path`.
#[expect(clippy::needless_pass_by_value, reason = "callers construct the map inline")]
fn load_example_with(proxy_port: u16, port_map: HashMap<&str, u16>, policy_yaml_path: &str) -> Config {
    let praxis_yaml_path = example_config_path("security/policy-llm.yaml");

    let raw = std::fs::read_to_string(&praxis_yaml_path).unwrap_or_else(|e| panic!("read {praxis_yaml_path}: {e}"));
    let with_policy = raw.replace("/etc/praxis/llm-policy.yaml", policy_yaml_path);
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

// -----------------------------------------------------------------------------
// Bodyless requests
// -----------------------------------------------------------------------------

/// The fixture's global rule, which every bodyless request runs.
const GLOBAL_RULE: &str = "  authorization:\n    pre_invocation:\n      - \"require(authenticated)\"\n  # Every";

/// Write a fixture variant whose global rules are `global_rules` (indented
/// under `global:`), and return its directory and path.
fn fixture_with_global(global_rules: &str) -> (tempfile::TempDir, String) {
    let fixture = std::fs::read_to_string(fixture_path()).expect("read fixture");
    assert!(fixture.contains(GLOBAL_RULE), "the fixture's global rule moved");
    let variant = fixture.replace(GLOBAL_RULE, &format!("{global_rules}\n  # Every"));
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("llm-policy.yaml");
    std::fs::write(&path, variant).expect("write variant");
    (dir, path.to_str().expect("utf8 path").to_owned())
}

/// Send an authenticated bodyless `method` request with `extra` headers.
fn bodyless(method: &str, path: &str, token: &str, extra: &str) -> String {
    format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: Bearer {token}\r\n\
         {extra}\
         Connection: close\r\n\
         \r\n",
    )
}

/// The body a probe backend answers its first request with.
const FIRST_HIT: &str = "first-hit";

/// Assert nothing reached `backend` by claiming its first response.
fn assert_backend_untouched(backend: &BackendGuard) {
    let (status, body) = http_get(&format!("127.0.0.1:{}", backend.port()), "/", None);
    assert_eq!(
        (status, body.as_str()),
        (200, FIRST_HIT),
        "no request may reach the upstream"
    );
}

#[test]
fn a_global_http_rule_denies_discovery_before_the_backend() {
    let (_dir, policy) =
        fixture_with_global("  authorization:\n    pre_invocation:\n      - \"require(role.research)\"");
    let backend = start_stateful_backend(vec![(200, FIRST_HIT.to_owned())]);
    let proxy_port = free_port();
    let proxy = start_proxy(&load_example_with(proxy_port, backend_map(backend.port()), &policy));

    let token = mint_fixture_jwt("support-bot", &["support"]);
    let raw = http_send(proxy.addr(), &bodyless("GET", "/v1/models", &token, ""));
    assert_eq!(
        parse_status(&raw),
        403,
        "a valid identity the global rule refuses;\n{raw}"
    );
    assert_backend_untouched(&backend);
}

#[test]
fn a_global_rule_requiring_the_inference_request_denies_discovery() {
    let (_dir, policy) = fixture_with_global(
        "  pdp:\n    - kind: cel\n  authorization:\n    pre_invocation:\n      - cel: { expr: \"has(llm.request)\" }",
    );
    let backend = start_stateful_backend(vec![(200, FIRST_HIT.to_owned())]);
    let proxy_port = free_port();
    let proxy = start_proxy(&load_example_with(proxy_port, backend_map(backend.port()), &policy));

    let token = mint_fixture_jwt("support-bot", &["support"]);
    let raw = http_send(proxy.addr(), &bodyless("GET", "/v1/models", &token, ""));
    assert_eq!(
        parse_status(&raw),
        403,
        "a bodyless request carries no inference request; move such rules into `llm:` routes;\n{raw}",
    );
    assert_backend_untouched(&backend);
}

#[test]
fn an_admitted_discovery_call_reaches_the_backend_under_the_assertions() {
    let (_dir, policy) = fixture_with_global(
        "  authorization:\n    pre_invocation:\n      - \"require(authenticated)\"\n  \
         assertions:\n    request:\n      headers:\n        - name: x-auth-user-id\n          \
         from: subject.id\n      strip:\n        - authorization\n        - x-api-key",
    );
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let proxy = start_proxy(&load_example_with(proxy_port, backend_map(backend.port()), &policy));

    let token = mint_fixture_jwt("support-bot", &["support"]);
    let raw = http_send(
        proxy.addr(),
        &bodyless(
            "GET",
            "/v1/models",
            &token,
            "X-Api-Key: sk-inbound\r\nX-Auth-User-Id: root\r\n",
        ),
    );
    assert_eq!(parse_status(&raw), 200, "{raw}");
    let seen: HashMap<String, String> = parse_body(&raw)
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    assert_eq!(
        seen.get("x-auth-user-id").map(String::as_str),
        Some("support-bot"),
        "{raw}"
    );
    assert!(
        !seen.contains_key("authorization"),
        "the caller's token is withheld;\n{raw}"
    );
    assert!(!seen.contains_key("x-api-key"), "the caller's key is withheld;\n{raw}");
}

#[test]
fn head_and_get_discovery_keep_framing_on_one_connection() {
    let backend = start_backend_with_shutdown("models");
    let proxy_port = free_port();
    let proxy = start_proxy(&load_example(proxy_port, backend_map(backend.port())));

    let token = mint_fixture_jwt("support-bot", &["support"]);
    let mut stream = std::net::TcpStream::connect(proxy.addr()).expect("connect");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("read timeout");
    let keep_alive = |method: &str| {
        bodyless(method, "/v1/models", &token, "").replace("Connection: close", "Connection: keep-alive")
    };
    let head = http_send_on_connection(&mut stream, &keep_alive("HEAD"));
    assert_eq!(parse_status(&head), 200, "{head}");
    assert!(parse_body(&head).is_empty(), "HEAD carries no body;\n{head}");
    let get = http_send_on_connection(&mut stream, &keep_alive("GET"));
    assert_eq!(parse_status(&get), 200, "{get}");
    assert_eq!(parse_body(&get), "models", "{get}");
}
