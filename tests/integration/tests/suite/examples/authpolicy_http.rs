// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional integration test for the experimental AuthPolicy HTTP
//! authorization example (`examples/configs/security/authpolicy-http.yaml`).
//!
//! Exercises the `policy` filter in `enforcement: http` mode end-to-end
//! against the CPEX `global` policy (admit only GET). Three cases prove the
//! full Phase B chain:
//!
//! * **Allow** — GET with a valid HS256 JWT resolves identity, the global policy admits GET, and the request reaches
//!   the backend (HTTP 200).
//! * **Deny (authz)** — POST with a valid JWT is denied by the global policy; the transpiled `denyWith` produces a
//!   plain HTTP 403 with the custom body + header (not a JSON-RPC envelope).
//! * **Deny (identity)** — a request with no `Authorization` header is rejected at the identity gate (HTTP 401).
//!
//! Together these exercise the request-line attributes (U1), the structured
//! denyWith carrier (U2), the CPEX non-entity authz path (U3), and the
//! Praxis `http` enforcement mode + deny mapping (U6/U7).

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use praxis_core::config::Config;
use praxis_test_utils::{
    example_config_path, free_port, http_send, parse_status, patch_yaml, start_backend_with_shutdown, start_proxy,
};

// Identity parameters mirrored from
// `tests/integration/fixtures/authpolicy-http-cpex-policy.yaml`.
const FIXTURE_ISSUER: &str = "https://idp.example.com";
const FIXTURE_AUDIENCE: &str = "praxis-cpex-example";
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
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(FIXTURE_SECRET.as_bytes()),
    )
    .expect("sign fixture JWT")
}

/// Load the authpolicy-http example, rewrite the operator `config_path` to
/// the in-repo fixture, and patch ports.
#[expect(clippy::needless_pass_by_value, reason = "callers construct the map inline")]
fn load_example(proxy_port: u16, port_map: HashMap<&str, u16>) -> Config {
    let praxis_yaml_path = example_config_path("security/authpolicy-http.yaml");
    let policy_yaml_path = format!(
        "{}/fixtures/authpolicy-http-cpex-policy.yaml",
        env!("CARGO_MANIFEST_DIR")
    );

    let raw = std::fs::read_to_string(&praxis_yaml_path).unwrap_or_else(|e| panic!("read {praxis_yaml_path}: {e}"));
    let with_policy = raw.replace("/etc/praxis/authpolicy-http-cpex-policy.yaml", &policy_yaml_path);
    let patched = patch_yaml(&with_policy, proxy_port, &port_map);
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse security/authpolicy-http.yaml: {e}"))
}

fn backend_map(port: u16) -> HashMap<&'static str, u16> {
    HashMap::from([("127.0.0.1:3000", port)])
}

#[test]
fn authpolicy_http_get_with_valid_jwt_passes_through() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("alice");
    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET /widgets HTTP/1.1\r\n\
             Host: localhost\r\n\
             Authorization: Bearer {token}\r\n\
             Connection: close\r\n\
             \r\n",
        ),
    );

    assert_eq!(
        parse_status(&raw),
        200,
        "GET with a valid JWT should be admitted by the global policy and reach the backend;\n{raw}",
    );
    assert!(
        raw.contains("ok"),
        "backend body should reach the client on allow;\n{raw}"
    );
}

#[test]
fn authpolicy_http_post_denied_with_custom_response() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    // Valid identity, but POST is denied by the global policy (GET-only).
    let token = mint_fixture_jwt("alice");
    let body = "{}";
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST /widgets HTTP/1.1\r\n\
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
        403,
        "POST should be denied by the global policy with the custom denyWith status;\n{raw}",
    );
    let lower = raw.to_lowercase();
    assert!(
        lower.contains("x-authz-denied: method-not-allowed"),
        "custom denyWith header expected;\n{raw}"
    );
    assert!(
        raw.contains("only GET is permitted"),
        "custom denyWith body expected;\n{raw}"
    );
    assert!(
        lower.contains("x-policy-violation:"),
        "violation code header expected;\n{raw}"
    );
}

#[test]
fn authpolicy_http_missing_authorization_rejects_401() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /widgets HTTP/1.1\r\n\
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
