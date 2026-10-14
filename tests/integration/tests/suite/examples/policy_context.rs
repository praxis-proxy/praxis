// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration test for the context-surface policy example.
//!
//! Exercises the `examples/configs/security/policy-context.yaml` filter
//! chain end-to-end.  The example adds `context_headers` (mapping
//! reserved-prefix headers to typed extension fields) and
//! `context_meta` (operator-defined scope, tags, properties) on top of
//! the baseline policy filter.
//!
//! Two cases:
//!
//! * **Deny** — a request with no `Authorization` header is rejected with HTTP 401 (identity gate).
//! * **Allow** — a valid HS256 JWT resolves identity and passes through to the backend (HTTP 200).
//!
//! Together these prove the example config loads, the filter constructs
//! with the `context_headers` / `context_meta` surface, and the chain
//! works.  APL-level context_headers behavior and scope-based routing
//! are covered by the unit tests in `crates/filter/.../policy/tests.rs`.

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

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

#[expect(clippy::needless_pass_by_value, reason = "callers construct the map inline")]
fn load_example(proxy_port: u16, port_map: HashMap<&str, u16>) -> Config {
    let praxis_yaml_path = example_config_path("security/policy-context.yaml");
    let policy_yaml_path = format!("{}/fixtures/policy.yaml", env!("CARGO_MANIFEST_DIR"),);

    let raw = std::fs::read_to_string(&praxis_yaml_path).unwrap_or_else(|e| panic!("read {praxis_yaml_path}: {e}"));
    let with_policy = raw.replace("/etc/praxis/policy.yaml", &policy_yaml_path);
    let patched = patch_yaml(&with_policy, proxy_port, &port_map);
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse security/policy-context.yaml: {e}"))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn policy_context_missing_authorization_rejects_401() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, HashMap::from([("127.0.0.1:3000", backend_guard.port())]));
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{}}}"#;
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len(),
        ),
    );

    assert_eq!(
        parse_status(&raw),
        401,
        "missing Authorization should hit the identity gate; raw:\n{raw}",
    );
}

#[test]
fn policy_context_valid_jwt_passes_through() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, HashMap::from([("127.0.0.1:3000", backend_guard.port())]));
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("alice");
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{}}}"#;
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\n\
             Host: localhost\r\n\
             Authorization: Bearer {token}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len(),
        ),
    );

    assert_eq!(
        parse_status(&raw),
        200,
        "valid JWT should pass through to the backend; raw:\n{raw}",
    );
}
