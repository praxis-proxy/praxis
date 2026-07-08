// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Teryl Taylor

//! Functional integration test for the policy example config.
//!
//! Exercises the `examples/configs/security/policy.yaml` filter chain
//! end-to-end: praxis is configured with the `policy` → `router` →
//! `load_balancer` chain. Two cases:
//!
//! * **Deny** — a request with no `Authorization` header is rejected with HTTP 401 (the policy identity gate's
//!   `auth_rejection` path).
//! * **Allow** — a request carrying a valid HS256 JWT (signed with the fixture's shared secret) resolves identity,
//!   finds no APL route to gate it, and passes through to the backend (HTTP 200).
//!
//! Together these prove the example config loads, the filter
//! constructs from the policy YAML, and the chain both blocks
//! unauthenticated traffic and forwards authenticated traffic — the
//! CLAUDE.md "Adding a Filter" end-to-end functional requirement.

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use praxis_core::config::Config;
use praxis_test_utils::{
    example_config_path, free_port, http_send, parse_status, patch_yaml, start_backend_with_shutdown, start_proxy,
};

// Identity parameters mirrored from `tests/integration/fixtures/cpex-policy.yaml`.
// The happy-path JWT must match the fixture's trusted issuer, audience,
// algorithm, and shared secret for the `jwt-user` identity plugin to
// accept it.
const FIXTURE_ISSUER: &str = "https://idp.example.com";
const FIXTURE_AUDIENCE: &str = "praxis-cpex-example";
const FIXTURE_SECRET: &str = "REPLACE-WITH-A-PROPERLY-RANDOM-SHARED-SECRET-DO-NOT-COMMIT";

/// Mint an HS256 JWT accepted by the fixture's `jwt-user` plugin: the
/// fixture's issuer/audience, the given subject, and a fresh `exp`.
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
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(FIXTURE_SECRET.as_bytes()),
    )
    .expect("sign fixture JWT")
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Load the policy praxis example, patch the relative `config_path`
/// reference into an absolute path, then patch ports. Returns a
/// fully-parsed [`Config`] ready for [`start_proxy`].
#[expect(clippy::needless_pass_by_value, reason = "callers construct the map inline")]
fn load_policy_example(proxy_port: u16, port_map: HashMap<&str, u16>) -> Config {
    let praxis_yaml_path = example_config_path("security/policy.yaml");
    let policy_yaml_path = format!("{}/fixtures/cpex-policy.yaml", env!("CARGO_MANIFEST_DIR"));

    let raw = std::fs::read_to_string(&praxis_yaml_path).unwrap_or_else(|e| panic!("read {praxis_yaml_path}: {e}"));
    // The example points `config_path` at an operator-supplied
    // deployment path (the policy is not shipped under examples/). The
    // test rewrites it to the minimal in-repo fixture so the filter
    // constructs regardless of the test's working directory.
    let with_policy = raw.replace("/etc/praxis/cpex-policy.yaml", &policy_yaml_path);
    let patched = patch_yaml(&with_policy, proxy_port, &port_map);
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse security/policy.yaml: {e}"))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn policy_example_missing_authorization_rejects_401() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_policy_example(proxy_port, HashMap::from([("127.0.0.1:3000", backend_guard.port())]));
    let proxy = start_proxy(&config);

    // POST with a well-formed JSON-RPC body but no Authorization header.
    // The identity hook chain denies, the policy filter returns
    // auth_rejection (401 with WWW-Authenticate + X-Policy-Violation).
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"service/invoke","params":{"name":"echo","arguments":{}}}"#;
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST /rpc HTTP/1.1\r\n\
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
        "missing Authorization should hit the policy identity gate; raw response:\n{raw}",
    );
    assert!(
        raw.to_lowercase().contains("www-authenticate: bearer"),
        "401 must carry WWW-Authenticate; raw response:\n{raw}",
    );
    assert!(
        raw.to_lowercase().contains("x-policy-violation:"),
        "rejection should surface the violation code via X-Policy-Violation; raw response:\n{raw}",
    );
}

#[test]
fn policy_example_valid_jwt_passes_through() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_policy_example(proxy_port, HashMap::from([("127.0.0.1:3000", backend_guard.port())]));
    let proxy = start_proxy(&config);

    // Same well-formed JSON-RPC body as the deny case, but now carrying
    // a valid HS256 JWT. The policy identity gate resolves it, the
    // fixture declares no APL routes so policy dispatch is a no-op, and
    // the request reaches the backend (HTTP 200, body "ok").
    let token = mint_fixture_jwt("alice");
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"service/invoke","params":{"name":"echo","arguments":{}}}"#;
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST /rpc HTTP/1.1\r\n\
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
        "a valid JWT should resolve identity and pass through to the backend; raw response:\n{raw}",
    );
    assert!(
        raw.contains("ok"),
        "the upstream backend body should reach the client on the allow path; raw response:\n{raw}",
    );
}
