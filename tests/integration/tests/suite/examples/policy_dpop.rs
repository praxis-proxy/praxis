// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! DPoP through the MCP policy example
//! (`examples/configs/security/policy.yaml`).
//!
//! A tool call resolves identity at the header-phase gate and again for its
//! `tool:` route. The filter threads one Policy context table through both,
//! so the second resolution reuses the proof the first verified; a new
//! request presenting the same proof is a replay.

use std::{collections::HashMap, sync::Arc};

use praxis_core::config::Config;
use praxis_filter::{FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext};
use praxis_test_utils::{
    example_config_path, free_port, http_send, parse_status, patch_yaml, start_backend_with_shutdown,
    start_full_proxy_with_registry, wait_for_tcp,
};
use serde_json::json;

use super::jwt;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The DPoP issuer in the fixture.
const ISSUER: &str = "https://dpop.idp.test";

/// The audience the fixture expects.
const AUDIENCE: &str = "praxis-fips-example";

/// The URL DPoP clients address, `dpop.external_base_url` in the fixture.
const EXTERNAL_BASE_URL: &str = "https://api.praxis.test";

/// The MCP endpoint the request targets.
const PATH: &str = "/mcp";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn a_dpop_proof_survives_both_identity_resolutions_and_cannot_be_replayed() {
    let backend = start_backend_with_shutdown("ok");
    let dir = tempfile::TempDir::new().expect("create tempdir");
    let config = load_example(&dir, free_port(), backend.port());
    let proxy = start_full_proxy_with_registry(&config, &tagging_registry());
    wait_for_tcp(proxy.addr());

    let client = fixture("dpop-p256-key.pem");
    let token = dpop_token(&client);
    let proof = jwt::dpop_proof(&client, "POST", &format!("{EXTERNAL_BASE_URL}{PATH}"), &token);
    let first = post(proxy.addr(), &token, &proof);
    assert_eq!(
        parse_status(&first),
        200,
        "the gate and the tool route both accept one proof; got:\n{first}"
    );

    let replay = post(proxy.addr(), &token, &proof);
    assert_eq!(
        parse_status(&replay),
        401,
        "a new request reusing the proof; got:\n{replay}"
    );
    assert!(
        replay
            .to_ascii_lowercase()
            .contains("x-policy-violation: auth.dpop_replay"),
        "got:\n{replay}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Stands in for the protocol classifier at the header phase, so `policy`
/// runs its early gate before the body phase resolves the tool route.
struct ToolTagger;

#[async_trait::async_trait]
impl HttpFilter for ToolTagger {
    fn name(&self) -> &'static str {
        "tool_tagger"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        ctx.set_metadata("mcp.method", "tools/call");
        ctx.set_metadata("mcp.name", "echo");
        Ok(FilterAction::Continue)
    }
}

/// The builtins plus `tool_tagger`.
fn tagging_registry() -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "tool_tagger",
            FilterFactory::Http(Arc::new(|_| Ok(Box::new(ToolTagger)))),
        )
        .expect("register the tagger");
    registry
}

/// `POST` an `echo` tool call with `token` and `proof`.
fn post(addr: &str, token: &str, proof: &str) -> String {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#;
    http_send(
        addr,
        &format!(
            "POST {PATH} HTTP/1.1\r\nHost: localhost\r\nAuthorization: DPoP {token}\r\nDPoP: {proof}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

/// An ES256 access token bound to `client`.
fn dpop_token(client: &[u8]) -> String {
    let now = i64::try_from(jwt::now()).expect("a 64-bit clock");
    let claims = json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "alice",
        "iat": now,
        "exp": now + 300,
        "jti": jwt::fresh_jti(),
        "cnf": { "jkt": jwt::jwk_thumbprint(client) },
    });
    jwt::es256(&claims, None, &fixture("p256-key.pem"))
}

/// The path of a test-only key in `fixtures/policy-fips/`.
fn fixture_path(name: &str) -> String {
    format!("{}/fixtures/policy-fips/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// The bytes of a test-only key in `fixtures/policy-fips/`.
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name)).unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

/// The MCP policy example over the DPoP fixture, with `tool_tagger` ahead of
/// `policy`.
fn load_example(dir: &tempfile::TempDir, proxy_port: u16, backend_port: u16) -> Config {
    let fixture = format!("{}/fixtures/dpop-mcp-policy.yaml", env!("CARGO_MANIFEST_DIR"));
    let policy = std::fs::read_to_string(&fixture)
        .expect("read the fixture policy")
        .replace("EC_PUBLIC_KEY", &fixture_path("p256-pub.pem"))
        .replace("EXTERNAL_BASE_URL", EXTERNAL_BASE_URL);
    let policy_path = dir.path().join("dpop-mcp-policy.yaml");
    std::fs::write(&policy_path, policy).expect("write policy");
    let example = example_config_path("security/policy.yaml");
    let raw = std::fs::read_to_string(&example).unwrap_or_else(|e| panic!("read {example}: {e}"));
    let yaml = raw
        .replace("/etc/praxis/policy.yaml", policy_path.to_str().expect("utf8 path"))
        .replace(
            "      - filter: policy\n",
            "      - filter: tool_tagger\n      - filter: policy\n",
        );
    assert!(yaml.contains("filter: tool_tagger"), "the tagger precedes policy");
    let patched = patch_yaml(&yaml, proxy_port, &HashMap::from([("127.0.0.1:3000", backend_port)]));
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse security/policy.yaml: {e}"))
}
