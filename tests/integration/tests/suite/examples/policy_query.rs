// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration test for the HTTP query-string policy
//! authorization example (`examples/configs/security/policy-query.yaml`).
//!
//! Exercises the `policy` filter in its pure-L7 (`http_global`) shape
//! end-to-end against the policy's `global` block (admit only the
//! `action=read` query). Three cases prove the full chain:
//!
//! * **Allow** — a request whose query is `action=read`, with a valid HS256 JWT, resolves identity, the global policy
//!   admits the query, and the request reaches the backend (HTTP 200).
//! * **Deny (authz)** — the same path with a different query (`action=write`) and a valid JWT is denied by the global
//!   policy; the `denyWith` produces a plain HTTP 403 with the custom body + header.
//! * **Deny (identity)** — a request with no `Authorization` header is rejected at the identity gate (HTTP 401).
//!
//! Together these prove the query string reaches policy as `http.query`
//! end-to-end: the same path is admitted or denied by its query alone.

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    example_config_path, free_port, http_send, parse_status, patch_yaml, start_backend_with_shutdown, start_proxy,
};

// Identity parameters mirrored from
// `tests/integration/fixtures/query-policy.yaml`.
const FIXTURE_ISSUER: &str = "https://idp.example.com";
const FIXTURE_AUDIENCE: &str = "praxis-policy-example";
const FIXTURE_SECRET: &str = "REPLACE-WITH-A-PROPERLY-RANDOM-SHARED-SECRET-DO-NOT-COMMIT";

/// Mint an HS256 JWT accepted by the fixture's `jwt-user` plugin.
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

/// Load the policy-query example, rewrite the operator `config_path` to
/// the in-repo fixture, and patch ports.
#[expect(clippy::needless_pass_by_value, reason = "callers construct the map inline")]
fn load_example(proxy_port: u16, port_map: HashMap<&str, u16>) -> Config {
    let praxis_yaml_path = example_config_path("security/policy-query.yaml");
    let policy_yaml_path = format!("{}/fixtures/query-policy.yaml", env!("CARGO_MANIFEST_DIR"));

    let raw = std::fs::read_to_string(&praxis_yaml_path).unwrap_or_else(|e| panic!("read {praxis_yaml_path}: {e}"));
    let with_policy = raw.replace("/etc/praxis/query-policy.yaml", &policy_yaml_path);
    let patched = patch_yaml(&with_policy, proxy_port, &port_map);
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse security/policy-query.yaml: {e}"))
}

fn backend_map(port: u16) -> HashMap<&'static str, u16> {
    HashMap::from([("127.0.0.1:3000", port)])
}

#[test]
fn policy_query_matching_query_with_valid_jwt_passes_through() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("alice");
    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET /resource?action=read HTTP/1.1\r\n\
             Host: localhost\r\n\
             Authorization: Bearer {token}\r\n\
             Connection: close\r\n\
             \r\n",
        ),
    );

    assert_eq!(
        parse_status(&raw),
        200,
        "the matching query with a valid JWT should be admitted by the global policy and reach the backend;\n{raw}",
    );
    assert!(
        raw.contains("ok"),
        "backend body should reach the client on allow;\n{raw}"
    );
}

#[test]
fn policy_query_different_query_denied_with_custom_response() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    // Valid identity and the same path, but a different query is denied by the
    // global policy (which admits only `action=read`).
    let token = mint_fixture_jwt("alice");
    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET /resource?action=write HTTP/1.1\r\n\
             Host: localhost\r\n\
             Authorization: Bearer {token}\r\n\
             Connection: close\r\n\
             \r\n",
        ),
    );

    assert_eq!(
        parse_status(&raw),
        403,
        "a different query should be denied by the global policy with the custom denyWith status;\n{raw}",
    );
    let lower = raw.to_lowercase();
    assert!(
        lower.contains("x-authz-denied: query-not-allowed"),
        "custom denyWith header expected;\n{raw}"
    );
    assert!(
        raw.contains("query not permitted"),
        "custom denyWith body expected;\n{raw}"
    );
}

#[test]
fn policy_query_missing_authorization_rejects_401() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /resource?action=read HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n",
    );

    assert_eq!(
        parse_status(&raw),
        401,
        "a request with no Authorization should hit the identity gate;\n{raw}",
    );
    assert!(
        raw.to_lowercase().contains("www-authenticate: bearer"),
        "401 must carry WWW-Authenticate;\n{raw}",
    );
}
