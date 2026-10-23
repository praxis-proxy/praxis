// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration test for the context-surface policy example
//! (`examples/configs/security/policy-context.yaml`).
//!
//! Exercises the `policy` filter in its pure-L7 (`http_global`) shape
//! with `context_headers` (mapping reserved-prefix headers to typed
//! extension fields) and `context_meta` (operator-defined scope, tags,
//! properties).
//!
//! The dedicated fixture (`fixtures/context-policy.yaml`) declares two
//! CEL predicates in its `global` authorization:
//!
//!   1. `agent.agent_id` (fed by `context_headers`) must not equal `blocked-agent`.
//!   2. `meta.properties.region` (fed by `context_meta`) must equal `us-east-1`.
//!
//! Four cases:
//!
//! * **Allow** — the example ships `planner-v2` / `us-east-1`, so both predicates pass and the request reaches the
//!   backend (200).
//! * **Deny (identity)** — no JWT → 401 from the identity gate.
//! * **Deny (agent_id)** — patching the agent header value to `blocked-agent` fires the first predicate (403).
//! * **Deny (region)** — patching the region property to `eu-west-1` fires the second predicate (403).

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    example_config_path, free_port, http_send, parse_header, parse_status, patch_yaml, start_backend_with_shutdown,
    start_proxy,
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

/// Read the example, rewrite the operator `config_path` to the
/// dedicated fixture, and patch ports.  Returns the raw YAML string
/// *before* `Config::from_yaml` so callers can apply additional
/// patches (e.g. changing a header value to trigger a deny).
fn raw_example_yaml(proxy_port: u16, port_map: &HashMap<&str, u16>) -> String {
    let praxis_yaml_path = example_config_path("security/policy-context.yaml");
    let policy_yaml_path = format!("{}/fixtures/context-policy.yaml", env!("CARGO_MANIFEST_DIR"),);
    let raw = std::fs::read_to_string(&praxis_yaml_path).unwrap_or_else(|e| panic!("read {praxis_yaml_path}: {e}"));
    let with_policy = raw.replace("/etc/praxis/policy.yaml", &policy_yaml_path);
    patch_yaml(&with_policy, proxy_port, port_map)
}

fn parse_config(yaml: &str) -> Config {
    Config::from_yaml(yaml).unwrap_or_else(|e| panic!("parse security/policy-context.yaml: {e}"))
}

fn backend_map(port: u16) -> HashMap<&'static str, u16> {
    HashMap::from([("127.0.0.1:3000", port)])
}

/// Send a GET with an optional Bearer token and return the raw
/// response.
fn get(addr: &str, token: Option<&str>) -> String {
    let auth = token.map_or_else(String::new, |t| format!("Authorization: Bearer {t}\r\n"));
    http_send(
        addr,
        &format!(
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             {auth}\
             Connection: close\r\n\
             \r\n",
        ),
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// The example as shipped passes both CEL predicates and reaches the
/// backend.
#[test]
fn policy_context_as_shipped_passes_through() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let yaml = raw_example_yaml(proxy_port, &backend_map(backend.port()));
    let config = parse_config(&yaml);
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("alice");
    let raw = get(proxy.addr(), Some(&token));

    assert_eq!(
        parse_status(&raw),
        200,
        "as-shipped values should pass both CEL predicates; raw:\n{raw}",
    );
}

/// No Authorization → 401 from the identity gate.
#[test]
fn policy_context_missing_authorization_rejects_401() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let yaml = raw_example_yaml(proxy_port, &backend_map(backend.port()));
    let config = parse_config(&yaml);
    let proxy = start_proxy(&config);

    let raw = get(proxy.addr(), None);

    assert_eq!(
        parse_status(&raw),
        401,
        "missing Authorization should hit the identity gate; raw:\n{raw}",
    );
}

/// Patching `x-ext-agent-id` from `planner-v2` to `blocked-agent`
/// fires the first CEL predicate (`agent.agent_id != 'blocked-agent'`).
#[test]
fn policy_context_blocked_agent_id_denied() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let yaml = raw_example_yaml(proxy_port, &backend_map(backend.port()));
    let patched = yaml.replace("value: \"planner-v2\"", "value: \"blocked-agent\"");
    let config = parse_config(&patched);
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("alice");
    let raw = get(proxy.addr(), Some(&token));

    assert_eq!(
        parse_status(&raw),
        403,
        "blocked-agent should be denied by the context_headers CEL predicate; raw:\n{raw}",
    );
    assert_eq!(
        parse_header(&raw, "x-context-deny"),
        Some("true".to_owned()),
        "custom deny header from the fixture's response block expected; raw:\n{raw}",
    );
}

/// Patching `context_meta.properties.region` from `us-east-1` to
/// `eu-west-1` fires the second CEL predicate.
#[test]
fn policy_context_region_mismatch_denied() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let yaml = raw_example_yaml(proxy_port, &backend_map(backend.port()));
    let patched = yaml.replace("region: us-east-1", "region: eu-west-1");
    let config = parse_config(&patched);
    let proxy = start_proxy(&config);

    let token = mint_fixture_jwt("alice");
    let raw = get(proxy.addr(), Some(&token));

    assert_eq!(
        parse_status(&raw),
        403,
        "eu-west-1 should be denied by the context_meta CEL predicate; raw:\n{raw}",
    );
    assert_eq!(
        parse_header(&raw, "x-context-deny"),
        Some("true".to_owned()),
        "custom deny header from the fixture's response block expected; raw:\n{raw}",
    );
}
