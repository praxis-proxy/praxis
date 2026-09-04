// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration test for the experimental identity-assertions
//! example (`examples/configs/security/policy-assertions.yaml`).
//!
//! The policy engine renders an `assertions:` contract into the result it hands
//! back rather than onto any wire, because it holds no socket. The `policy`
//! filter is what puts the map on the upstream request, so this is the test that
//! the two halves meet: without the filter's half the block loads, validates,
//! and reaches nothing.
//!
//! A header-echoing backend reflects what it received, so every assertion below
//! is about the request that left the proxy rather than about the policy's own
//! bookkeeping:
//!
//! * **Injection** — the resolved subject, a claim, a collection under its declared encoding, and a composed members
//!   object all arrive.
//! * **No forgery** — a caller who sends `x-auth-user-id` himself has it replaced with the resolved subject, because an
//!   entry removes its target before injecting.
//! * **`strip:`** — the caller's own credential header and a named extra do not reach the upstream.
//! * **No contract, no effect** — covered by the sibling `policy_http` example, whose policy declares none and whose
//!   backend sees the request unchanged.

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use praxis_core::config::Config;
use praxis_test_utils::{
    example_config_path, free_port, http_send, parse_status, patch_yaml, start_header_echo_backend, start_proxy,
};

// Identity parameters mirrored from
// `tests/integration/fixtures/assertions-policy.yaml`.
const FIXTURE_ISSUER: &str = "https://idp.example.com";
const FIXTURE_AUDIENCE: &str = "praxis-policy-example";
const FIXTURE_SECRET: &str = "REPLACE-WITH-A-PROPERLY-RANDOM-SHARED-SECRET-DO-NOT-COMMIT";

/// Mint an HS256 JWT accepted by the fixture's `jwt-user` plugin, carrying the
/// claims the contract asserts from.
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
        // Sources for the contract: a promoted set and a custom claim.
        "roles": ["writer", "admin"],
        "teams": ["platform"],
        "tenant": "acme",
    });
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(FIXTURE_SECRET.as_bytes()),
    )
    .expect("sign fixture JWT")
}

/// Load the assertions example, rewrite the operator `config_path` to the
/// in-repo fixture, and patch ports.
#[expect(clippy::needless_pass_by_value, reason = "callers construct the map inline")]
fn load_example(proxy_port: u16, port_map: HashMap<&str, u16>) -> Config {
    let praxis_yaml_path = example_config_path("security/policy-assertions.yaml");
    let policy_yaml_path = format!("{}/fixtures/assertions-policy.yaml", env!("CARGO_MANIFEST_DIR"));

    let raw = std::fs::read_to_string(&praxis_yaml_path).unwrap_or_else(|e| panic!("read {praxis_yaml_path}: {e}"));
    let with_policy = raw.replace("/etc/praxis/assertions-policy.yaml", &policy_yaml_path);
    let patched = patch_yaml(&with_policy, proxy_port, &port_map);
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse security/policy-assertions.yaml: {e}"))
}

fn backend_map(port: u16) -> HashMap<&'static str, u16> {
    HashMap::from([("127.0.0.1:3000", port)])
}

/// The headers the backend reports having received, lowercased and keyed by
/// name. The echo backend writes one `Name: value` per line into the body.
fn upstream_headers(raw: &str) -> HashMap<String, String> {
    let body = raw.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    body.lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect()
}

#[test]
fn assertions_reach_the_upstream_request() {
    let backend = start_header_echo_backend();
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
        "an authenticated request is admitted and reaches the backend;\n{raw}",
    );
    let seen = upstream_headers(&raw);

    assert_eq!(
        seen.get("x-auth-user-id").map(String::as_str),
        Some("alice"),
        "the resolved subject must reach the upstream;\n{raw}"
    );
    assert_eq!(
        seen.get("x-auth-tenant").map(String::as_str),
        Some("acme"),
        "a claim source renders as its value;\n{raw}"
    );
    assert_eq!(
        seen.get("x-auth-roles").map(String::as_str),
        Some("admin,writer"),
        "a collection renders under its declared encoding, sorted;\n{raw}"
    );
    assert_eq!(
        seen.get("x-auth-context").map(String::as_str),
        Some(r#"{"teams":["platform"]}"#),
        "a members entry renders one JSON object;\n{raw}"
    );
}

#[test]
fn a_caller_cannot_forge_an_asserted_header() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let config = load_example(proxy_port, backend_map(backend.port()));
    let proxy = start_proxy(&config);

    // The caller names a header the contract also targets. An entry removes its
    // target before injecting, so the upstream must see the resolved subject.
    let token = mint_fixture_jwt("alice");
    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET /widgets HTTP/1.1\r\n\
             Host: localhost\r\n\
             Authorization: Bearer {token}\r\n\
             X-Auth-User-Id: root\r\n\
             Connection: close\r\n\
             \r\n",
        ),
    );

    assert_eq!(parse_status(&raw), 200, "the request is still admitted;\n{raw}");
    let seen = upstream_headers(&raw);
    assert_eq!(
        seen.get("x-auth-user-id").map(String::as_str),
        Some("alice"),
        "a client-supplied value must not be forwarded under an asserted name;\n{raw}"
    );
    assert!(
        !raw.contains("root"),
        "the forged value must not survive anywhere on the upstream request;\n{raw}"
    );
}

#[test]
fn stripped_headers_do_not_reach_the_upstream() {
    let backend = start_header_echo_backend();
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
             X-Internal-Hint: keep-this-private\r\n\
             Connection: close\r\n\
             \r\n",
        ),
    );

    assert_eq!(parse_status(&raw), 200, "the request is still admitted;\n{raw}");
    let seen = upstream_headers(&raw);
    assert!(
        !seen.contains_key("authorization"),
        "the caller's own credential is stripped, so an upstream on a delegated \
         credential never sees it;\n{raw}"
    );
    assert!(
        !seen.contains_key("x-internal-hint"),
        "a named `strip:` entry removes a header no header entry targets;\n{raw}"
    );
    // The floor is what keeps `strip:` from breaking the message itself.
    assert!(
        seen.contains_key("host"),
        "`host` is in the request protocol floor and must survive;\n{raw}"
    );
}
