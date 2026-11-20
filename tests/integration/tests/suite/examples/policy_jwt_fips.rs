// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration test for the FIPS JWT example
//! (`examples/configs/security/policy-jwt-fips.yaml`).
//!
//! Drives the `policy` filter end to end in a build whose JWT plugin verifies
//! through OpenSSL (`policy-jwt-fips`). Tokens and DPoP proofs are signed at
//! test time with the test-only keys in `fixtures/policy-fips/`. RS256 keys
//! come from a local JWKS that also lists an HMAC and an Ed25519 key, which a
//! FIPS build must skip; ES256 keys come from a PEM file. HMAC algorithms and
//! shared-secret keys are refused when the filter is built.
//!
//! Every case needs a FIPS provider: without one the filter refuses to build,
//! which `a_fips_build_without_a_fips_provider_refuses_the_policy` checks.
//! `make test-fips-provider` and `make test-fips-host` supply one.

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use praxis_core::config::Config;
use praxis_test_utils::{
    Backend, BackendGuard, ProxyGuard, example_config_path, expect_approved_mode, free_port, http_send, parse_status,
    patch_yaml, start_backend_with_shutdown, start_proxy,
};
use serde_json::{Value, json};

use super::jwt;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The audience every fixture issuer expects.
const AUDIENCE: &str = "praxis-fips-example";

/// Issuer whose RS256 keys come from the JWKS.
const RSA_ISSUER: &str = "https://rsa.idp.test";

/// Issuer whose ES256 key comes from a PEM file.
const EC_ISSUER: &str = "https://ec.idp.test";

/// Issuer whose ES256 tokens are DPoP-bound.
const DPOP_ISSUER: &str = "https://dpop.idp.test";

/// The URL DPoP clients address, `dpop.external_base_url` in the fixture.
const EXTERNAL_BASE_URL: &str = "https://api.praxis.test";

/// The RSA key's id in the JWKS.
const RSA_KID: &str = "praxis-fips-test-rsa";

/// The HMAC key's id in the JWKS, which a FIPS build skips.
const HMAC_KID: &str = "praxis-fips-test-hmac";

/// The HMAC key's secret, as the JWKS publishes it.
const HMAC_SECRET: &[u8] = b"praxis-fips-test-hmac-secret-not-for-production";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn an_rs256_token_from_the_jwks_reaches_the_backend() {
    let Some(proxy) = Proxy::start() else { return };
    let token = jwt::rs256(
        &claims(RSA_ISSUER, AUDIENCE, 300),
        Some(RSA_KID),
        &fixture("rsa2048-key.pem"),
    );
    let raw = proxy.get("/widgets", &format!("Bearer {token}"), None);
    assert_eq!(parse_status(&raw), 200, "an RS256 token must verify; got:\n{raw}");
    assert!(
        raw.contains("ok"),
        "the backend body must reach the client; got:\n{raw}"
    );
}

#[test]
fn an_es256_token_from_a_pem_key_reaches_the_backend() {
    let Some(proxy) = Proxy::start() else { return };
    let token = jwt::es256(&claims(EC_ISSUER, AUDIENCE, 300), None, &fixture("p256-key.pem"));
    let raw = proxy.get("/widgets", &format!("Bearer {token}"), None);
    assert_eq!(parse_status(&raw), 200, "an ES256 token must verify; got:\n{raw}");
}

#[test]
fn expired_wrong_issuer_and_wrong_audience_tokens_are_rejected() {
    let Some(proxy) = Proxy::start() else { return };
    let key = fixture("p256-key.pem");
    for (claims, code) in [
        (claims(EC_ISSUER, AUDIENCE, -600), "auth.token_expired"),
        (claims("https://other.idp.test", AUDIENCE, 300), "auth.untrusted_issuer"),
        (claims(EC_ISSUER, "another-audience", 300), "auth.audience_mismatch"),
    ] {
        let raw = proxy.get("/widgets", &format!("Bearer {}", jwt::es256(&claims, None, &key)), None);
        assert_eq!(parse_status(&raw), 401, "{code}: must be rejected; got:\n{raw}");
        assert!(
            raw.to_ascii_lowercase()
                .contains(&format!("x-policy-violation: {code}")),
            "{code}: got:\n{raw}"
        );
    }
}

#[test]
fn a_missing_token_is_rejected() {
    let Some(proxy) = Proxy::start() else { return };
    let raw = proxy.send("GET /widgets HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(
        parse_status(&raw),
        401,
        "a request without a token is rejected; got:\n{raw}"
    );
    assert!(
        raw.to_ascii_lowercase()
            .contains("x-policy-violation: auth.missing_credential"),
        "got:\n{raw}"
    );
}

#[test]
fn the_mixed_jwks_keeps_only_the_keys_fips_supports() {
    let Some(proxy) = Proxy::start() else { return };
    let token = jwt::hs256(&claims(RSA_ISSUER, AUDIENCE, 300), Some(HMAC_KID), HMAC_SECRET);
    let raw = proxy.get("/widgets", &format!("Bearer {token}"), None);
    assert_eq!(
        parse_status(&raw),
        401,
        "a token for the skipped HMAC key is rejected; got:\n{raw}"
    );
    assert!(
        raw.to_ascii_lowercase()
            .contains("x-policy-violation: auth.unknown_kid"),
        "the HMAC key was dropped from the set, so its kid is unknown; got:\n{raw}"
    );
    let rsa = jwt::rs256(
        &claims(RSA_ISSUER, AUDIENCE, 300),
        Some(RSA_KID),
        &fixture("rsa2048-key.pem"),
    );
    let raw = proxy.get("/widgets", &format!("Bearer {rsa}"), None);
    assert_eq!(
        parse_status(&raw),
        200,
        "the RSA key from the same set still verifies; got:\n{raw}"
    );
}

#[test]
fn a_dpop_bound_token_with_a_valid_proof_reaches_the_backend_once() {
    let Some(proxy) = Proxy::start() else { return };
    let client = fixture("dpop-p256-key.pem");
    let token = dpop_token(&client);
    let proof = jwt::dpop_proof(&client, "GET", &format!("{EXTERNAL_BASE_URL}/widgets"), &token);
    let raw = proxy.get("/widgets", &format!("DPoP {token}"), Some(&proof));
    assert_eq!(parse_status(&raw), 200, "a valid proof must verify; got:\n{raw}");
    let replay = proxy.get("/widgets", &format!("DPoP {token}"), Some(&proof));
    assert_eq!(
        parse_status(&replay),
        401,
        "a second request with the proof is a replay; got:\n{replay}"
    );
    assert!(
        replay
            .to_ascii_lowercase()
            .contains("x-policy-violation: auth.dpop_replay"),
        "got:\n{replay}"
    );
}

#[test]
fn a_dpop_proof_for_another_method_url_token_or_key_is_rejected() {
    let Some(proxy) = Proxy::start() else { return };
    let client = fixture("dpop-p256-key.pem");
    let token = dpop_token(&client);
    let url = format!("{EXTERNAL_BASE_URL}/widgets");
    let other_token = dpop_token(&client);
    for (proof, code, case) in [
        (
            jwt::dpop_proof(&client, "POST", &url, &token),
            "auth.dpop_invalid",
            "method",
        ),
        (
            jwt::dpop_proof(&client, "GET", &format!("{EXTERNAL_BASE_URL}/gadgets"), &token),
            "auth.dpop_invalid",
            "URL",
        ),
        (
            jwt::dpop_proof(&client, "GET", &url, &other_token),
            "auth.dpop_invalid",
            "ath",
        ),
        (
            jwt::dpop_proof(&fixture("p256-key.pem"), "GET", &url, &token),
            "auth.dpop_key_mismatch",
            "key",
        ),
    ] {
        let raw = proxy.get("/widgets", &format!("DPoP {token}"), Some(&proof));
        assert_eq!(
            parse_status(&raw),
            401,
            "a proof with the wrong {case} is rejected; got:\n{raw}"
        );
        assert!(
            raw.to_ascii_lowercase()
                .contains(&format!("x-policy-violation: {code}")),
            "wrong {case}: got:\n{raw}"
        );
    }
}

#[test]
fn hmac_algorithms_and_shared_secret_keys_are_refused_at_load() {
    if !expect_approved_mode() {
        return;
    }
    for (decoding_key, algorithm, needle) in [
        ("kind: pem_file\n            path: \"EC_PUBLIC_KEY\"", "HS256", "HS256"),
        (
            "kind: secret\n            secret: \"praxis-fips-test-secret\"",
            "RS256",
            "secret",
        ),
    ] {
        let jwks = JwksEndpoint::start();
        let policy = std::fs::read_to_string(fixture_path("jwt-policy.yaml"))
            .expect("read the fixture policy")
            .replace(
                "algorithms: [\"ES256\"]\n          decoding_key:\n            kind: pem_file\n            path: \"EC_PUBLIC_KEY\"\n        - issuer: \"https://dpop",
                &format!("algorithms: [\"{algorithm}\"]\n          decoding_key:\n            {decoding_key}\n        - issuer: \"https://dpop"),
            );
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let config = load_example(&dir, &policy, jwks.address, free_port(), free_port());
        let error = resolve(&config).expect_err("the policy must be refused at load");
        assert!(
            error.contains(needle) && error.contains("jwt-openssl-fips"),
            "{algorithm} with {decoding_key}: the error names the refusal: {error}"
        );
    }
}

#[test]
fn a_fips_build_without_a_fips_provider_refuses_the_policy() {
    if expect_approved_mode() {
        return;
    }
    let jwks = JwksEndpoint::start();
    let dir = tempfile::TempDir::new().expect("create tempdir");
    let config = load_example(&dir, &fixture_policy(), jwks.address, free_port(), free_port());
    let error = resolve(&config).expect_err("without the FIPS provider the policy must not load");
    assert!(
        error.contains("policy.crypto_failed"),
        "the refusal names the crypto failure: {error}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// A proxy built from the example, with its backend and JWKS server.
struct Proxy {
    /// The running proxy.
    proxy: ProxyGuard,
    /// Kept alive for the proxy's lifetime.
    _backend: BackendGuard,
    /// Kept alive for the proxy's lifetime.
    _jwks: JwksEndpoint,
    /// Holds the rewritten policy document.
    _dir: tempfile::TempDir,
}

impl Proxy {
    /// Start the example, or `None` without a FIPS provider (the policy
    /// cannot load there; the refusal has its own test).
    fn start() -> Option<Self> {
        if !expect_approved_mode() {
            eprintln!("policy_jwt_fips: skipped, no FIPS provider (run make test-fips-provider)");
            return None;
        }
        let backend = start_backend_with_shutdown("ok");
        let jwks = JwksEndpoint::start();
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let config = load_example(&dir, &fixture_policy(), jwks.address, free_port(), backend.port());
        let proxy = start_proxy(&config);
        Some(Self {
            proxy,
            _backend: backend,
            _jwks: jwks,
            _dir: dir,
        })
    }

    /// `GET path` with `authorization` and an optional `DPoP` header.
    fn get(&self, path: &str, authorization: &str, dpop: Option<&str>) -> String {
        let dpop = dpop.map_or_else(String::new, |proof| format!("DPoP: {proof}\r\n"));
        self.send(&format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {authorization}\r\n{dpop}Connection: close\r\n\r\n"
        ))
    }

    /// Send a raw request.
    fn send(&self, request: &str) -> String {
        http_send(self.proxy.addr(), request)
    }
}

/// Access-token claims for `issuer` and `audience`, expiring `ttl` seconds
/// from now (negative for an expired token).
fn claims(issuer: &str, audience: &str, ttl: i64) -> Value {
    let now = i64::try_from(jwt::now()).expect("a 64-bit clock");
    json!({ "iss": issuer, "aud": audience, "sub": "alice", "iat": now, "exp": now + ttl })
}

/// An ES256 access token from the DPoP issuer, bound to `client`.
fn dpop_token(client: &[u8]) -> String {
    let mut claims = claims(DPOP_ISSUER, AUDIENCE, 300);
    claims["cnf"] = json!({ "jkt": jwt::jwk_thumbprint(client) });
    claims["jti"] = json!(jwt::fresh_jti());
    jwt::es256(&claims, None, &fixture("p256-key.pem"))
}

/// The path of a file in `fixtures/policy-fips/`.
fn fixture_path(name: &str) -> String {
    format!("{}/fixtures/policy-fips/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// The bytes of a file in `fixtures/policy-fips/`.
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name)).unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

/// The fixture policy document, unmodified.
fn fixture_policy() -> String {
    std::fs::read_to_string(fixture_path("jwt-policy.yaml")).expect("read the fixture policy")
}

/// Load the example with `policy` (placeholders filled in) as its policy
/// document.
fn load_example(dir: &tempfile::TempDir, policy: &str, jwks: SocketAddr, proxy_port: u16, backend_port: u16) -> Config {
    let policy = policy
        .replace("JWKS_URL", &format!("http://{jwks}/jwks"))
        .replace("EC_PUBLIC_KEY", &fixture_path("p256-pub.pem"))
        .replace("EXTERNAL_BASE_URL", EXTERNAL_BASE_URL);
    let policy_path = dir.path().join("jwt-fips-policy.yaml");
    std::fs::write(&policy_path, policy).expect("write policy");
    let example = example_config_path("security/policy-jwt-fips.yaml");
    let raw = std::fs::read_to_string(&example).unwrap_or_else(|e| panic!("read {example}: {e}"));
    let with_policy = raw
        .replace(
            "/etc/praxis/jwt-fips-policy.yaml",
            policy_path.to_str().expect("utf8 path"),
        )
        .replace(
            "        config_path: ",
            "        allow_private_idp: true\n        config_path: ",
        );
    let patched = patch_yaml(
        &with_policy,
        proxy_port,
        &HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse security/policy-jwt-fips.yaml: {e}"))
}

/// Build the config's pipelines as startup does; `Err` carries the refusal.
fn resolve(config: &Config) -> Result<(), String> {
    praxis::resolve_pipelines(
        config,
        &praxis::build_full_registry(),
        &praxis_core::health::build_health_registry(&config.clusters),
        &praxis_core::kv::KvStoreRegistry::new(),
        &Arc::new(praxis_filter::SessionStoreRegistry::new()),
        &praxis::build_subrequest_client(config).map_err(|error| error.to_string())?,
    )
    .map(drop)
    .map_err(|error| error.to_string())
}

/// A local server answering every request with the fixture JWKS; dropping it
/// closes the listener.
struct JwksEndpoint {
    /// Listening address.
    address: SocketAddr,
    /// Stops the listener on drop.
    _guard: BackendGuard,
}

impl JwksEndpoint {
    /// Start serving `fixtures/policy-fips/jwks.json`.
    fn start() -> Self {
        let document = String::from_utf8(fixture("jwks.json")).expect("utf8 JWKS");
        let guard = Backend::fixed(&document)
            .header("Content-Type", "application/json")
            .start_with_shutdown();
        let address = SocketAddr::from(([127, 0, 0, 1], guard.port()));
        Self { address, _guard: guard }
    }
}
