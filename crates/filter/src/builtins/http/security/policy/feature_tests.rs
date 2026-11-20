// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests that hold under every Policy feature selection: which plugin kinds a
//! build registers, and the limiter warning.

use std::sync::{Arc, Mutex};

use tempfile::TempDir;

use super::{
    config::{BodyAccessMode, ContextMetaConfig, PolicyFilterConfig},
    filter::{PolicyFilter, declares_rate_limits},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// A JWT identity policy; its key, RFC 7515 appendix A.3's P-256 public
/// key, never verifies anything here. ES256 loads on every JWT backend.
const JWT_POLICY: &str = r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    config:
      header: Authorization
      trusted_issuers:
        - issuer: "https://idp.test.local"
          audiences: ["test-api"]
          algorithms: ["ES256"]
          decoding_key:
            kind: jwk
            jwk:
              kty: EC
              crv: P-256
              x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
              y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
      claim_mapper: standard
global:
  authentication: [jwt-user]
"#;

/// An API-key identity policy; `{keys}` is the key file path.
const API_KEY_POLICY: &str = r#"plugins:
  - name: api-keys
    kind: identity/api-key
    hooks: [identity.resolve]
    config:
      credential:
        kind: header
        name: Authorization
      provider:
        kind: file
        path: "{keys}"
        index: sha256
      record_map:
        subject:
          id: user
global:
  authentication: [api-keys]
"#;

/// A pre-identity limiter on the client address, listed globally.
const LIMITER_POLICY: &str = "plugins:
  - name: edge-limits
    kind: ratelimit/limitador
    hooks: [ratelimit.pre_identity]
    capabilities: [read_headers]
    config:
      namespace: edge
      bindings:
        client: http.client_address
      limits:
        - max: 50
          seconds: 1
          variables: [client]
global:
  rate_limits: [edge-limits]
";

/// A plugin named `l` for the layer fixtures to list; parsing alone never
/// instantiates it.
const LIMITER_PLUGIN: &str =
    "plugins:\n  - name: l\n    kind: ratelimit/limitador\n    hooks: [ratelimit.post_identity]\n";

/// A policy with no plugin at all, which every selection can load.
const EMPTY_POLICY: &str = "plugins: []\n";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn every_selection_loads_a_policy_without_plugins() {
    let (_dir, path) = write_policy(EMPTY_POLICY);
    PolicyFilter::new(filter_config(path), None).expect("a plugin-free policy loads in every Policy build");
}

#[cfg(not(any(
    feature = "policy-builtins",
    feature = "policy-jwt",
    feature = "policy-jwt-openssl-fips"
)))]
#[test]
fn a_build_without_jwt_rejects_a_jwt_policy_by_kind() {
    let (_dir, path) = write_policy(JWT_POLICY);
    let error = construction_error(path);
    assert!(
        error.contains("identity/jwt") && error.contains("no factory registered"),
        "a policy naming a kind the build lacks must fail to load and name the kind: {error}"
    );
}

#[cfg(any(
    feature = "policy-builtins",
    feature = "policy-jwt",
    feature = "policy-jwt-openssl-fips"
))]
#[test]
fn a_build_with_jwt_loads_a_jwt_policy() {
    let (_dir, path) = write_policy(JWT_POLICY);
    PolicyFilter::new(filter_config(path), None).expect("a JWT build must register `identity/jwt`");
}

#[cfg(feature = "policy-jwt-openssl-fips")]
#[test]
fn a_fips_jwt_build_refuses_a_shared_secret_key() {
    let hs256 = JWT_POLICY
        .replace(r#"algorithms: ["ES256"]"#, r#"algorithms: ["HS256"]"#)
        .replace(
            "kind: jwk\n            jwk:\n              kty: EC\n              crv: P-256\n              x: \"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"\n              y: \"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"",
            "kind: secret\n            secret: \"praxis-feature-test-secret-not-for-production-use\"",
        );
    assert!(hs256.contains("kind: secret"), "the fixture rewrite applied: {hs256}");
    let (_dir, path) = write_policy(&hs256);
    let error = construction_error(path);
    assert!(
        error.contains("jwt-openssl-fips") && (error.contains("HS256") || error.contains("secret")),
        "an HMAC key must be refused when the FIPS JWT plugin loads: {error}"
    );
}

#[cfg(not(any(feature = "policy-builtins", feature = "policy-api-key")))]
#[test]
fn a_build_without_api_key_rejects_an_api_key_policy_by_kind() {
    let (_dir, path) = write_api_key_policy();
    let error = construction_error(path);
    assert!(
        error.contains("identity/api-key") && error.contains("no factory registered"),
        "a policy naming a kind the build lacks must fail to load and name the kind: {error}"
    );
}

#[cfg(any(feature = "policy-builtins", feature = "policy-api-key"))]
#[test]
fn a_build_with_api_key_loads_an_api_key_policy() {
    let (_dir, path) = write_api_key_policy();
    PolicyFilter::new(filter_config(path), None).expect("an API-key build must register `identity/api-key`");
}

#[cfg(feature = "policy-experimental-ratelimit")]
#[test]
fn a_build_with_the_limiter_loads_a_limiter_policy_and_warns() {
    let (_dir, path) = write_policy(LIMITER_POLICY);
    let (result, warnings) = capture_warnings(|| PolicyFilter::new(filter_config(path), None));
    result.expect("a limiter build must register `ratelimit/limitador`");
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("rate_limits") && warning.contains("experimental")),
        "loading a policy with `rate_limits:` must warn that the limiter is experimental: {warnings:?}"
    );
}

#[cfg(not(feature = "policy-experimental-ratelimit"))]
#[test]
fn a_build_without_the_limiter_rejects_a_limiter_policy_by_kind() {
    let (_dir, path) = write_policy(LIMITER_POLICY);
    let error = construction_error(path);
    assert!(
        error.contains("ratelimit/limitador"),
        "a policy naming the limiter kind must fail to load without it: {error}"
    );
}

#[test]
fn a_policy_without_rate_limits_does_not_warn_about_the_limiter() {
    let (_dir, path) = write_policy(EMPTY_POLICY);
    let (result, warnings) = capture_warnings(|| PolicyFilter::new(filter_config(path), None));
    result.expect("a plugin-free policy loads");
    assert!(
        !warnings.iter().any(|warning| warning.contains("rate_limits")),
        "a policy with no `rate_limits:` must not warn about the limiter: {warnings:?}"
    );
}

#[test]
fn rate_limits_are_found_at_every_layer() {
    for (layer, yaml) in [
        ("global", "global:\n  rate_limits: [l]\n"),
        ("route", "routes:\n  - tool: echo\n    rate_limits: [l]\n"),
        ("group", "groups:\n  g:\n    rate_limits: [l]\n"),
        ("defaults", "global:\n  defaults:\n    tool:\n      rate_limits: [l]\n"),
    ] {
        let yaml = format!("{LIMITER_PLUGIN}{yaml}");
        let parsed = ppe::praxis_policy_core::config::parse_config(&yaml)
            .unwrap_or_else(|error| panic!("the {layer} fixture must parse: {error}"));
        assert!(
            declares_rate_limits(&parsed),
            "`rate_limits:` on the {layer} layer must be found"
        );
    }
    let parsed = ppe::praxis_policy_core::config::parse_config(EMPTY_POLICY).expect("the empty policy parses");
    assert!(
        !declares_rate_limits(&parsed),
        "a policy without `rate_limits:` must report none"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Write `yaml` as a policy document in a fresh directory.
pub(super) fn write_policy(yaml: &str) -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, yaml).expect("write the policy document");
    let path = path.to_str().expect("a UTF-8 tempdir path").to_owned();
    (dir, path)
}

/// Write [`API_KEY_POLICY`] beside an empty key file.
///
/// [`API_KEY_POLICY`]: API_KEY_POLICY
fn write_api_key_policy() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let keys = dir.path().join("keys.yaml");
    std::fs::write(&keys, "keys: []\n").expect("write the key file");
    let policy = dir.path().join("policy.yaml");
    let yaml = API_KEY_POLICY.replace("{keys}", keys.to_str().expect("a UTF-8 tempdir path"));
    std::fs::write(&policy, yaml).expect("write the policy document");
    let path = policy.to_str().expect("a UTF-8 tempdir path").to_owned();
    (dir, path)
}

/// The filter config pointing at `config_path`, with test-friendly defaults.
pub(super) fn filter_config(config_path: String) -> PolicyFilterConfig {
    PolicyFilterConfig {
        config_path,
        allow_private_idp: false,
        trusted_private_endpoints: vec![],
        trusted_proxies: vec![],
        body_access: BodyAccessMode::ReadOnly,
        require_protocol_metadata: true,
        init_timeout_secs: 5,
        max_buffer_bytes: 1_048_576, // 1 MiB
        llm: super::config::LlmOptions::default(),
        context_headers: std::collections::HashMap::default(),
        context_meta: ContextMetaConfig::default(),
    }
}

/// The construction error for `config_path`, which must fail to build.
#[cfg_attr(
    feature = "policy-builtins",
    expect(dead_code, reason = "only the narrow-build rejection tests call it")
)]
fn construction_error(config_path: String) -> String {
    match PolicyFilter::new(filter_config(config_path), None) {
        Ok(_) => panic!("the policy must fail to load in this build"),
        Err(error) => error.to_string(),
    }
}

/// Run `run` with a subscriber that records the message of every warning.
pub(super) fn capture_warnings<T>(run: impl FnOnce() -> T) -> (T, Vec<String>) {
    use tracing_subscriber::layer::SubscriberExt as _;

    let messages = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(WarningCapture(Arc::clone(&messages)));
    let result = tracing::subscriber::with_default(subscriber, run);
    let warnings = std::mem::take(&mut *messages.lock().expect("warning sink lock"));
    (result, warnings)
}

/// Layer recording the `message` field of every WARN event.
struct WarningCapture(Arc<Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarningCapture {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        if *event.metadata().level() == tracing::Level::WARN {
            let mut visitor = MessageVisitor(String::new());
            event.record(&mut visitor);
            self.0.lock().expect("warning sink lock").push(visitor.0);
        }
    }
}

/// Field visitor keeping the `message` field.
struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}
