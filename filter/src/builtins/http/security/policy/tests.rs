// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for the CPEX security filter.
//!
//! Uses HMAC (HS256) JWTs throughout for setup simplicity — the
//! identity validation pipeline is symmetric across signing
//! algorithms, and HS256 lets us skip RSA keypair generation. Real
//! deployments use RS256 with JWKS endpoints; the YAML schema
//! supports both via the `decoding_key.kind` discriminant.

use http::{HeaderValue, Method};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use tempfile::TempDir;

use super::{config::PolicyFilterConfig, filter::PolicyFilter};
use crate::{
    FilterAction,
    filter::HttpFilter as _,
    test_utils::{make_filter_context, make_request},
};

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

const TEST_SECRET: &str = "praxis-cpex-test-secret-not-for-production-use";
const TEST_ISSUER: &str = "https://idp.test.local";
const TEST_AUDIENCE: &str = "test-api";

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock should not be before unix epoch")
        .as_secs()
}

/// Mint an HS256 JWT signed with [`TEST_SECRET`].
fn mint_jwt(claims: &serde_json::Value) -> String {
    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(TEST_SECRET.as_bytes());
    encode(&header, claims, &key).expect("sign JWT")
}

/// Standard token claims: test issuer + audience, fresh `exp`.
fn standard_claims(subject: &str) -> serde_json::Value {
    json!({
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "sub": subject,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    })
}

/// Claims for a workload / agent token. Includes `azp` (authorized
/// party) so the `client`-role claim mapper can populate the
/// caller-workload identity slot.
fn agent_claims(client_id: &str) -> serde_json::Value {
    json!({
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "sub": client_id,
        "azp": client_id,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    })
}

/// Write a single-plugin CPEX YAML referencing the HS256 test secret.
fn write_single_plugin_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");

    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
    mode: sequential
    priority: 10
    on_error: fail
    config:
      header: Authorization
      trusted_issuers:
        - issuer: "{TEST_ISSUER}"
          audiences: ["{TEST_AUDIENCE}"]
          algorithms: ["HS256"]
          decoding_key:
            kind: secret
            secret: "{TEST_SECRET}"
          leeway_seconds: 60
      claim_mapper: standard
"#
    );

    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let path_str = cfg_path.to_str().expect("utf8 path").to_owned();
    (dir, path_str)
}

/// Write a CPEX YAML that gates the `echo` tool through a CEL PDP step.
/// Single HS256 identity plugin (so `subject.id` resolves from the JWT
/// `sub`), a `kind: cel` PDP declared globally, and a route whose `cel:`
/// expression allows only `alice`. Exercises the `apl-pdp-cel` backend
/// end-to-end through the filter's CMF dispatch.
#[expect(
    clippy::too_many_lines,
    reason = "test fixture — the YAML literal is the bulk; splitting helpers would obscure the shape under test"
)]
fn write_cel_policy_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");

    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
    mode: sequential
    priority: 10
    on_error: fail
    config:
      header: Authorization
      trusted_issuers:
        - issuer: "{TEST_ISSUER}"
          audiences: ["{TEST_AUDIENCE}"]
          algorithms: ["HS256"]
          decoding_key:
            kind: secret
            secret: "{TEST_SECRET}"
          leeway_seconds: 60
      claim_mapper: standard
global:
  apl:
    pdp:
      - kind: cel
routes:
  - tool: echo
    apl:
      policy:
        - cel:
            expr: |
              subject.id == "alice"
"#
    );

    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let path_str = cfg_path.to_str().expect("utf8 path").to_owned();
    (dir, path_str)
}

/// Run a `service/invoke` for the `echo` tool as `subject`, returning the
/// filter's body-phase action. Shared by the CEL allow/deny cases.
async fn dispatch_echo_as(filter: &PolicyFilter, subject: &str) -> FilterAction {
    let token = mint_jwt(&standard_claims(subject));
    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);
    ctx.set_metadata("protocol.method", "service/invoke");
    ctx.set_metadata("protocol.name", "echo");
    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"service/invoke","params":{"name":"echo","arguments":{}}}"#,
    );
    filter
        .on_request_body(&mut ctx, &mut Some(body), true)
        .await
        .expect("filter ran")
}

/// Write a CPEX YAML demonstrating session tainting: a `read-secret`
/// tool taints the session, and a `send-out` tool denies when the
/// session carries that taint. Identity is the HS256 jwt plugin so
/// `subject.id` resolves; the taint persists in the in-process session
/// store keyed by the resolved session id.
#[expect(
    clippy::too_many_lines,
    reason = "test fixture — the YAML literal is the bulk; splitting helpers would obscure the shape under test"
)]
fn write_taint_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");

    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
    mode: sequential
    priority: 10
    on_error: fail
    config:
      header: Authorization
      trusted_issuers:
        - issuer: "{TEST_ISSUER}"
          audiences: ["{TEST_AUDIENCE}"]
          algorithms: ["HS256"]
          decoding_key:
            kind: secret
            secret: "{TEST_SECRET}"
          leeway_seconds: 60
      claim_mapper: standard
routes:
  - tool: read-secret
    apl:
      policy:
        - "taint(secret, session)"
  - tool: send-out
    apl:
      policy:
        - "security.labels contains \"secret\": deny('session accessed secret data', 'session_tainted_secret')"
"#
    );

    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let path_str = cfg_path.to_str().expect("utf8 path").to_owned();
    (dir, path_str)
}

/// Dispatch a `service/invoke` for `tool` as `subject` with the given
/// `X-Session-Id`. Returns the filter's body-phase action. Threads the
/// session header so cpex's session-scoped taint store can persist /
/// hydrate labels across calls.
async fn dispatch_tool_session(filter: &PolicyFilter, subject: &str, tool: &str, session_id: &str) -> FilterAction {
    let token = mint_jwt(&standard_claims(subject));
    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    req.headers.insert(
        "X-Session-Id",
        HeaderValue::from_str(session_id).expect("session header"),
    );
    let mut ctx = make_filter_context(&req);
    ctx.set_metadata("protocol.method", "service/invoke");
    ctx.set_metadata("protocol.name", tool);
    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"service/invoke","params":{"name":"t","arguments":{}}}"#,
    );
    filter
        .on_request_body(&mut ctx, &mut Some(body), true)
        .await
        .expect("filter ran")
}

/// Write a CPEX YAML with two identity plugins, each reading its own
/// header. Demonstrates the multi-source agentic identity story PR1
/// targets — one request can carry user + agent JWTs simultaneously,
/// both validated, both contributing to a typed `Extensions` context.
#[expect(
    clippy::too_many_lines,
    reason = "test fixture — the YAML literal is the bulk; splitting helpers would obscure the shape under test"
)]
fn write_multi_source_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");

    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
    mode: sequential
    priority: 10
    on_error: fail
    config:
      header: Authorization
      role: user
      trusted_issuers:
        - issuer: "{TEST_ISSUER}"
          audiences: ["{TEST_AUDIENCE}"]
          algorithms: ["HS256"]
          decoding_key:
            kind: secret
            secret: "{TEST_SECRET}"
      claim_mapper: standard
  - name: jwt-agent
    kind: identity/jwt
    hooks:
      - identity.resolve
    mode: sequential
    priority: 20
    on_error: fail
    config:
      header: X-Agent-Token
      role: client
      trusted_issuers:
        - issuer: "{TEST_ISSUER}"
          audiences: ["{TEST_AUDIENCE}"]
          algorithms: ["HS256"]
          decoding_key:
            kind: secret
            secret: "{TEST_SECRET}"
      claim_mapper: standard
"#
    );

    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let path_str = cfg_path.to_str().expect("utf8 path").to_owned();
    (dir, path_str)
}

/// Write a CPEX YAML selecting the Valkey-backed session store via a
/// flat `global.session_store` block. The `valkey` factory connects
/// lazily (the pool dials on first request), so this config loads
/// without a running Valkey — it pins that the factory is registered
/// and the flat `session_store` block parses and resolves.
#[expect(
    clippy::too_many_lines,
    reason = "test fixture — the YAML literal is the bulk; splitting helpers would obscure the shape under test"
)]
fn write_valkey_session_store_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");

    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
    mode: sequential
    priority: 10
    on_error: fail
    config:
      header: Authorization
      trusted_issuers:
        - issuer: "{TEST_ISSUER}"
          audiences: ["{TEST_AUDIENCE}"]
          algorithms: ["HS256"]
          decoding_key:
            kind: secret
            secret: "{TEST_SECRET}"
          leeway_seconds: 60
      claim_mapper: standard
global:
  session_store:
    kind: valkey
    endpoint: localhost:6379
routes:
  - tool: read-secret
    apl:
      policy:
        - "taint(secret, session)"
"#
    );

    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let path_str = cfg_path.to_str().expect("utf8 path").to_owned();
    (dir, path_str)
}

/// Build a `PolicyFilter` from a YAML config path. Defaults
/// `require_protocol_metadata` to true so the test surface matches the
/// production default; individual tests that want to test the
/// fail-open knob construct their own config.
fn build_filter(config_path: String) -> PolicyFilter {
    let cfg = PolicyFilterConfig {
        config_path,
        body_access: super::config::BodyAccessMode::ReadOnly,
        require_protocol_metadata: true,
        init_timeout_secs: 30,
        max_buffer_bytes: 10_485_760,
    };
    PolicyFilter::new(cfg).expect("filter should construct")
}

// -----------------------------------------------------------------------------
// Config parsing
// -----------------------------------------------------------------------------

/// The minimal valid config carries only `config_path:`; all other
/// fields (`body_access`, `require_protocol_metadata`, `init_timeout_secs`,
/// `max_buffer_bytes`) take their documented defaults.
#[test]
fn config_parses_minimal_yaml() {
    let yaml = "config_path: /etc/praxis/cpex.yaml";
    let cfg: PolicyFilterConfig = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(cfg.config_path, "/etc/praxis/cpex.yaml", "config_path round-trips",);
    assert_eq!(cfg.max_buffer_bytes, 10_485_760, "max_buffer_bytes defaults to 10 MiB",);
}

/// `max_buffer_bytes` is operator-tunable; an explicit value overrides
/// the 10 MiB default so deployments can bound `ReadWrite` buffering.
#[test]
fn config_max_buffer_bytes_override() {
    let yaml = "config_path: /etc/praxis/cpex.yaml\nmax_buffer_bytes: 1048576";
    let cfg: PolicyFilterConfig = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(cfg.max_buffer_bytes, 1_048_576, "explicit max_buffer_bytes wins");
}

/// `config_path:` is mandatory — there's no default that would let
/// the filter load a CPEX policy document, so an empty config block
/// must fail at deserialize time rather than at first request.
#[test]
fn config_requires_config_path() {
    let yaml = "{}";
    let res: Result<PolicyFilterConfig, _> = serde_yaml::from_str(yaml);
    assert!(res.is_err(), "config_path is mandatory");
}

// -----------------------------------------------------------------------------
// Identity-resolution scenarios
// -----------------------------------------------------------------------------

/// A YAML config carrying a single identity plugin should construct
/// without error. Pins the schema we ship — any drift in the
/// identity/jwt plugin's config shape will surface here.
#[tokio::test(flavor = "multi_thread")]
async fn filter_constructs_from_valid_yaml() {
    let (_dir, path) = write_single_plugin_config();
    let _filter = build_filter(path);
}

/// A config selecting the Valkey session store (`global.session_store`,
/// flat form) loads without a running Valkey: the `valkey` factory is
/// registered and its pool dials lazily on first request. Proves the
/// factory wiring and that the flat `session_store` block resolves.
#[tokio::test(flavor = "multi_thread")]
async fn valkey_session_store_config_builds() {
    let (_dir, path) = write_valkey_session_store_config();
    let _filter = build_filter(path);
}

/// A request with no `Authorization` header has no token for the JWT
/// plugin to validate; the identity hook chain denies and the filter
/// emits HTTP 401.
#[tokio::test(flavor = "multi_thread")]
async fn request_without_auth_header_rejects_401() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);

    let req = make_request(Method::POST, "/");
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.expect("filter ran");

    match action {
        FilterAction::Reject(rej) => assert_eq!(rej.status, 401),
        other => panic!("expected Reject(401); got {other:?}"),
    }
}

/// A valid HS256 JWT in the configured header passes the identity
/// chain and the filter emits Continue.
#[tokio::test(flavor = "multi_thread")]
async fn valid_hs256_jwt_continues() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);

    let token = mint_jwt(&standard_claims("alice"));
    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.expect("filter ran");
    assert!(
        matches!(action, FilterAction::Continue),
        "expected Continue; got {action:?}"
    );
}

/// A JWT whose signature byte has been flipped fails verification and
/// the filter emits HTTP 401.
#[tokio::test(flavor = "multi_thread")]
async fn tampered_jwt_signature_rejects_401() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);

    // Flip the final character of the signature segment.
    let mut token = mint_jwt(&standard_claims("alice"));
    let last = token.pop().unwrap_or('A');
    token.push(if last == 'A' { 'B' } else { 'A' });

    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.expect("filter ran");
    assert!(
        matches!(&action, FilterAction::Reject(rej) if rej.status == 401),
        "expected Reject(401); got {action:?}"
    );
}

/// Auth rejections must carry the `WWW-Authenticate: Bearer` header
/// so clients know to retry with credentials, plus our
/// `X-Policy-Violation` diagnostic header.
#[tokio::test(flavor = "multi_thread")]
async fn auth_rejection_carries_diagnostic_headers() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);

    let req = make_request(Method::POST, "/");
    let mut ctx = make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.expect("filter ran");
    let FilterAction::Reject(rej) = action else {
        panic!("expected Reject; got {action:?}");
    };

    let www_auth = rej
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("WWW-Authenticate"));
    assert!(www_auth.is_some(), "WWW-Authenticate header is required");

    let violation = rej
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("X-Policy-Violation"));
    assert!(violation.is_some(), "X-Policy-Violation header is expected");
}

/// The PR1 multi-source story: one request carries a user JWT in
/// `Authorization` and an agent JWT in `X-Agent-Token`. Both plugins
/// validate their respective headers and the request passes.
#[tokio::test(flavor = "multi_thread")]
async fn multi_source_both_identities_continue() {
    let (_dir, path) = write_multi_source_config();
    let filter = build_filter(path);

    let user_token = mint_jwt(&standard_claims("alice"));
    let agent_token = mint_jwt(&agent_claims("agent-007"));

    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {user_token}")).expect("header"),
    );
    req.headers.insert(
        "X-Agent-Token",
        HeaderValue::from_str(&format!("Bearer {agent_token}")).expect("header"),
    );
    let mut ctx = make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.expect("filter ran");
    assert!(
        matches!(action, FilterAction::Continue),
        "expected Continue with both identities; got {action:?}"
    );
}

/// `block_in_place` (used by the response phase) panics on a
/// current-thread runtime, so the filter refuses to run there. Pins
/// the rejection so a future change can't silently re-introduce the
/// panic path. The default `#[tokio::test]` flavor is current-thread,
/// which is exactly the runtime praxis configures when
/// `work_stealing: false`.
#[tokio::test]
async fn current_thread_runtime_is_rejected() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);

    let req = make_request(Method::POST, "/");
    let mut ctx = make_filter_context(&req);

    let err = filter
        .on_request(&mut ctx)
        .await
        .expect_err("current-thread runtime must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("multi-threaded tokio runtime"),
        "error message should point at the work_stealing config; got: {msg}",
    );
}

// -----------------------------------------------------------------------------
// Config-schema guards
// -----------------------------------------------------------------------------

/// `#[serde(deny_unknown_fields)]` must reject typos like `body_acces`
/// — without this, the misspelled field is silently dropped, the
/// default `ReadOnly` mode wins, and `redact()` policies become a
/// no-op. The typo would be invisible to operators until they checked
/// upstream traffic and noticed redaction wasn't happening.
#[test]
fn config_rejects_unknown_fields() {
    let yaml = "
config_path: /etc/praxis/cpex.yaml
body_acces: read_write
";
    let res: Result<PolicyFilterConfig, _> = serde_yaml::from_str(yaml);
    assert!(res.is_err(), "deny_unknown_fields must reject `body_acces` typo",);
    let msg = format!("{}", res.unwrap_err());
    assert!(
        msg.contains("body_acces") || msg.contains("unknown field"),
        "error should name the bad field; got: {msg}",
    );
}

/// `require_protocol_metadata` defaults to `true` — the safer fail-closed
/// posture. Operators must explicitly opt in to identity-only
/// pass-through for non-classified traffic.
#[test]
fn config_require_protocol_metadata_defaults_to_true() {
    let yaml = "config_path: /etc/praxis/cpex.yaml";
    let cfg: PolicyFilterConfig = serde_yaml::from_str(yaml).expect("parse");
    assert!(cfg.require_protocol_metadata, "default must be fail-closed");
}

/// `init_timeout_secs` defaults to 30s when omitted. Operators don't
/// have to think about it; the bound is just present.
#[test]
fn config_init_timeout_defaults_to_30s() {
    let yaml = "config_path: /etc/praxis/cpex.yaml";
    let cfg: PolicyFilterConfig = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(cfg.init_timeout_secs, 30);
}

/// An operator-supplied `init_timeout_secs` round-trips. Pins the
/// knob exists at the YAML surface, not just in the struct.
#[test]
fn config_init_timeout_honors_override() {
    let yaml = "config_path: /etc/praxis/cpex.yaml\ninit_timeout_secs: 5";
    let cfg: PolicyFilterConfig = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(cfg.init_timeout_secs, 5);
}

// End-to-end exercise of the `init_timeout_secs` knob via the JWKS
// path is intentionally NOT a unit test: the bundled identity-jwt
// plugin has its own JWKS connect/request timeouts plus soft-fail-at-
// boot, so a hung JWKS endpoint never propagates a hang through
// `PluginManager::initialize` in the first place. The wrap-timeout in
// `PolicyFilter::new` is defense-in-depth for OTHER init paths (custom
// plugins, future hooks) where a future could legitimately stall.
// The unit tests above pin the surface; the timeout's behavior is
// exercised by `tokio::time::timeout` itself.

// -----------------------------------------------------------------------------
// Fail-closed policy gate (require_protocol_metadata)
// -----------------------------------------------------------------------------

/// When `require_protocol_metadata: true` (default) and `protocol.method` is
/// absent from filter metadata, `on_request_body` rejects with
/// HTTP 500 + `X-Policy-Violation: config.missing_protocol_metadata`. This
/// catches a misconfigured chain (protocol classifier filter missing or ordered
/// after policy) loudly at the first body-phase request.
#[tokio::test(flavor = "multi_thread")]
async fn missing_protocol_metadata_rejects_when_required() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);

    let token = mint_jwt(&standard_claims("alice"));
    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);

    let action = filter
        .on_request_body(&mut ctx, &mut Some(bytes::Bytes::new()), true)
        .await
        .expect("filter ran");
    match action {
        FilterAction::Reject(rej) => {
            assert_eq!(rej.status, 500);
            let violation = rej
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("X-Policy-Violation"));
            assert!(violation.is_some(), "violation header expected");
            assert_eq!(
                violation.unwrap().1,
                "config.missing_protocol_metadata",
                "violation code should name the missing metadata",
            );
        },
        other => panic!("expected Reject(500); got {other:?}"),
    }
}

/// When `require_protocol_metadata: false` and `protocol.method` is absent,
/// `on_request_body` passes the request through (identity-only mode
/// for non-classified traffic). Pins the opt-out behavior.
#[tokio::test(flavor = "multi_thread")]
async fn missing_protocol_metadata_passes_when_not_required() {
    let (_dir, path) = write_single_plugin_config();
    let cfg = PolicyFilterConfig {
        config_path: path,
        body_access: super::config::BodyAccessMode::ReadOnly,
        require_protocol_metadata: false,
        init_timeout_secs: 30,
        max_buffer_bytes: 10_485_760,
    };
    let filter = PolicyFilter::new(cfg).expect("filter should construct");

    let token = mint_jwt(&standard_claims("alice"));
    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);

    let action = filter
        .on_request_body(&mut ctx, &mut Some(bytes::Bytes::new()), true)
        .await
        .expect("filter ran");
    assert!(
        matches!(action, FilterAction::BodyDone),
        "expected BodyDone passthrough; got {action:?}",
    );
}

// -----------------------------------------------------------------------------
// Post-phase deny envelope (json_rpc_error_envelope_bytes)
// -----------------------------------------------------------------------------

/// The post-phase deny path replaces the response body with this
/// envelope when an APL `result:` pipeline denies. The envelope shape
/// must match the JSON-RPC error format so clients can parse it the
/// same way they parse upstream errors.
#[test]
fn json_rpc_error_envelope_has_expected_shape() {
    use cpex::cpex_core::error::PluginViolation;

    use super::error::json_rpc_error_envelope_bytes;

    let violation = PluginViolation::new("test.deny", "policy says no");
    let id = serde_json::json!(42);
    let bytes = json_rpc_error_envelope_bytes(Some(&violation), &id);

    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("envelope must be valid JSON");

    assert_eq!(parsed["jsonrpc"], "2.0");
    assert_eq!(parsed["id"], 42);
    assert_eq!(parsed["error"]["code"], -32001);
    assert_eq!(parsed["error"]["message"], "policy says no");
    assert_eq!(parsed["error"]["data"]["violation"], "test.deny");
}

/// `request_id` should round-trip preserving the JSON type the client
/// sent — string id stays a string, numeric stays numeric, etc.
/// Pins compliance with the JSON-RPC 2.0 spec.
#[test]
fn json_rpc_error_envelope_preserves_string_request_id() {
    use super::error::json_rpc_error_envelope_bytes;
    let id = serde_json::json!("req-abc-123");
    let bytes = json_rpc_error_envelope_bytes(None, &id);
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    assert_eq!(parsed["id"], "req-abc-123");
}

/// When no violation is provided (defensive null path), the envelope
/// still parses and carries the sentinel `gateway.unknown` code.
#[test]
fn json_rpc_error_envelope_handles_missing_violation() {
    use super::error::json_rpc_error_envelope_bytes;
    let id = serde_json::json!(null);
    let bytes = json_rpc_error_envelope_bytes(None, &id);
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    assert_eq!(parsed["error"]["data"]["violation"], "gateway.unknown");
    assert_eq!(parsed["error"]["message"], "denied by gateway");
}

// -----------------------------------------------------------------------------
// auth_rejection (transport-level 401)
// -----------------------------------------------------------------------------

/// `auth_rejection` builds an HTTP 401 with `WWW-Authenticate: Bearer`
/// and `X-Policy-Violation:` reflecting the violation code so audit /
/// middleware can classify without parsing the body. Body carries the
/// short `code: reason` diagnostic.
#[test]
fn auth_rejection_shape_when_violation_present() {
    use cpex::cpex_core::error::PluginViolation;

    use super::error::auth_rejection;

    let violation = PluginViolation::new("auth.invalid_token", "bad signature");
    let rej = auth_rejection(Some(&violation));
    assert_eq!(rej.status, 401);

    let www_auth = rej
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("WWW-Authenticate"));
    assert_eq!(www_auth.expect("WWW-Authenticate header").1, "Bearer");

    let viol = rej
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("X-Policy-Violation"));
    assert_eq!(viol.expect("X-Policy-Violation header").1, "auth.invalid_token");

    let body_bytes = rej.body.as_ref().expect("body present");
    let body = std::str::from_utf8(body_bytes).expect("utf8 body");
    assert!(
        body.contains("auth.invalid_token") && body.contains("bad signature"),
        "body should surface both code and reason; got {body:?}",
    );
}

/// No violation surfaced still produces a usable 401 with the sentinel
/// `auth.unknown` code — clients always get a structured response.
#[test]
fn auth_rejection_falls_back_to_sentinel_when_no_violation() {
    use super::error::auth_rejection;
    let rej = auth_rejection(None);
    assert_eq!(rej.status, 401);
    let viol = rej
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("X-Policy-Violation"));
    assert_eq!(viol.expect("X-Policy-Violation header").1, "auth.unknown");
}

// -----------------------------------------------------------------------------
// fit_to_original_length (request/response body framing)
// -----------------------------------------------------------------------------

/// On shrink, `fit_to_original_length` pads the new body with trailing
/// ASCII spaces so the wire length equals the original `Content-Length`.
/// JSON parsers ignore trailing whitespace, so a downstream consumer
/// sees the rewritten envelope without a framing desync.
#[test]
fn fit_to_original_length_pads_on_shrink() {
    use super::filter::fit_to_original_length;
    let new = bytes::Bytes::from_static(b"abc");
    let out = fit_to_original_length(new, 8, "service/invoke", "test");
    assert_eq!(out.len(), 8, "padded length must match original");
    assert_eq!(&out[..3], b"abc");
    assert!(
        out[3..].iter().all(|b| *b == b' '),
        "shrink padding must be ASCII spaces; got {:?}",
        &out[3..],
    );
}

/// On equal-length rewrite, the original bytes pass through unchanged.
/// No allocation, no padding — the common steady-state case for
/// in-place mutations like `redact(value)` swapping a same-width token.
#[test]
fn fit_to_original_length_passes_through_on_equal() {
    use super::filter::fit_to_original_length;
    let new = bytes::Bytes::from_static(b"redacted");
    let out = fit_to_original_length(new.clone(), 8, "service/invoke", "test");
    assert_eq!(out, new);
}

/// On grow, the body is truncated to exactly the original
/// `Content-Length`. The downstream response length is already committed
/// by the time `on_response_body` runs, so emitting more bytes would let
/// the overflow be parsed as the next response (a smuggling primitive).
/// Truncation corrupts the JSON but preserves HTTP/1.1 framing — the
/// safe failure mode.
#[test]
fn fit_to_original_length_truncates_on_grow() {
    use super::filter::fit_to_original_length;
    let new = bytes::Bytes::from_static(b"a much longer rewritten payload");
    let out = fit_to_original_length(new.clone(), 4, "service/invoke", "test");
    assert_eq!(out.len(), 4, "grow path must truncate to the original length");
    assert_eq!(&*out, &new[..4], "truncation keeps the leading bytes");
}

// -----------------------------------------------------------------------------
// cmf.rs — JSON-RPC method → entity coords
// -----------------------------------------------------------------------------

/// Pre-phase mapping returns `(entity_type, pre_hook_name)` for
/// methods that carry an entity, `None` for the no-entity methods.
#[test]
fn entity_for_protocol_method_covers_known_methods() {
    use super::common_message_format::entity_for_protocol_method;
    assert!(entity_for_protocol_method("service/invoke").is_some());
    assert!(entity_for_protocol_method("template/get").is_some());
    assert!(entity_for_protocol_method("resource/read").is_some());
    assert!(entity_for_protocol_method("service/list").is_none());
    assert!(entity_for_protocol_method("initialize").is_none());
    assert!(entity_for_protocol_method("unknown/method").is_none());
}

/// Post-phase mirror — same set of methods, different hooks.
#[test]
fn entity_for_protocol_method_post_covers_known_methods() {
    use super::common_message_format::entity_for_protocol_method_post;
    assert!(entity_for_protocol_method_post("service/invoke").is_some());
    assert!(entity_for_protocol_method_post("template/get").is_some());
    assert!(entity_for_protocol_method_post("resource/read").is_some());
    assert!(entity_for_protocol_method_post("service/list").is_none());
    assert!(entity_for_protocol_method_post("initialize").is_none());
}

// -----------------------------------------------------------------------------
// json_rpc.rs — id extraction + content builders + re-serializers
// -----------------------------------------------------------------------------

/// `json_rpc_id` returns the `id` as a string for both string and
/// numeric ids (CMF correlation needs a single canonical key), and
/// falls back to the empty string when the body is missing or malformed.
#[test]
fn json_rpc_id_handles_string_numeric_and_malformed() {
    use super::json_rpc::json_rpc_id;
    let str_id = bytes::Bytes::from_static(br#"{"jsonrpc":"2.0","id":"req-1","method":"x"}"#);
    let num_id = bytes::Bytes::from_static(br#"{"jsonrpc":"2.0","id":42,"method":"x"}"#);
    let no_id = bytes::Bytes::from_static(br#"{"jsonrpc":"2.0","method":"x"}"#);
    let bad = bytes::Bytes::from_static(b"not json");
    assert_eq!(json_rpc_id(&str_id), "req-1");
    assert_eq!(json_rpc_id(&num_id), "42");
    assert_eq!(json_rpc_id(&no_id), "");
    assert_eq!(json_rpc_id(&bad), "");
}

/// `json_rpc_id_value` preserves the original JSON type so an error
/// envelope echoes back exactly what the client sent (string stays a
/// string; numeric stays numeric). Missing/malformed → `Value::Null`.
#[test]
fn json_rpc_id_value_preserves_json_type() {
    use super::json_rpc::json_rpc_id_value;
    let str_id = bytes::Bytes::from_static(br#"{"id":"req-1"}"#);
    let num_id = bytes::Bytes::from_static(br#"{"id":42}"#);
    let bad = bytes::Bytes::from_static(b"{");
    assert_eq!(json_rpc_id_value(&str_id), serde_json::json!("req-1"));
    assert_eq!(json_rpc_id_value(&num_id), serde_json::json!(42));
    assert_eq!(json_rpc_id_value(&bad), serde_json::Value::Null);
}

/// `service/invoke` parses `params.arguments` into a `ToolCall` content
/// part so APL `args.<field>` predicates have something to read.
#[test]
fn build_content_for_method_tools_call() {
    use cpex::cpex_core::cmf::ContentPart;

    use super::json_rpc::build_content_for_method;

    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"service/invoke",
             "params":{"name":"echo","arguments":{"text":"hi","n":7}}}"#,
    );
    let parts = build_content_for_method("service/invoke", "echo", "corr-1", &body);
    assert_eq!(parts.len(), 1);
    match &parts[0] {
        ContentPart::ToolCall { content } => {
            assert_eq!(content.name, "echo");
            assert_eq!(content.tool_call_id, "corr-1");
            assert_eq!(content.arguments.get("text"), Some(&serde_json::json!("hi")));
            assert_eq!(content.arguments.get("n"), Some(&serde_json::json!(7)));
        },
        other => panic!("expected ToolCall; got {other:?}"),
    }
}

/// `resource/read` produces a `ResourceRef` keyed off `params.uri`
/// so route resolution and APL `resource.*` predicates work.
#[test]
fn build_content_for_method_resources_read() {
    use cpex::cpex_core::cmf::ContentPart;

    use super::json_rpc::build_content_for_method;

    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"resource/read",
             "params":{"uri":"file:///etc/example"}}"#,
    );
    let parts = build_content_for_method("resource/read", "file:///etc/example", "corr-1", &body);
    assert_eq!(parts.len(), 1);
    match &parts[0] {
        ContentPart::ResourceRef { content } => {
            assert_eq!(content.uri, "file:///etc/example");
            assert_eq!(content.resource_request_id, "corr-1");
        },
        other => panic!("expected ResourceRef; got {other:?}"),
    }
}

/// Unknown / no-entity methods produce an empty content list — CMF
/// dispatch still routes by entity coords but predicates over
/// `args.*` see nothing, which is the correct behavior.
#[test]
fn build_content_for_method_unknown_method_yields_empty() {
    use super::json_rpc::build_content_for_method;
    let body = bytes::Bytes::from_static(br#"{"method":"service/list"}"#);
    let parts = build_content_for_method("service/list", "n/a", "corr-1", &body);
    assert!(parts.is_empty());
}

/// `reserialize_json_rpc_body` mutates only `params.arguments` (for
/// `service/invoke`), leaving `jsonrpc`, `id`, `method`, `params.name`
/// untouched. Operators who hash the envelope only see deltas when
/// APL actually mutated.
#[test]
fn reserialize_tools_call_round_trips_with_mutated_args() {
    use cpex::cpex_core::cmf::{ContentPart, Message, Role, ToolCall};

    use super::json_rpc::reserialize_json_rpc_body;

    let original = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"service/invoke",
             "params":{"name":"echo","arguments":{"a":1}}}"#,
    );
    let mut new_args: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
    new_args.insert("a".to_owned(), serde_json::json!("[REDACTED]"));
    let message = Message::with_content(
        Role::User,
        vec![ContentPart::ToolCall {
            content: ToolCall {
                tool_call_id: String::new(),
                name: "echo".to_owned(),
                arguments: new_args,
                namespace: None,
            },
        }],
    );
    let new_bytes = reserialize_json_rpc_body(&original, "service/invoke", &message).expect("rewrite Some");
    let parsed: serde_json::Value = serde_json::from_slice(&new_bytes).expect("valid JSON");
    assert_eq!(parsed["jsonrpc"], "2.0");
    assert_eq!(parsed["id"], 1);
    assert_eq!(parsed["method"], "service/invoke");
    assert_eq!(parsed["params"]["name"], "echo");
    assert_eq!(parsed["params"]["arguments"]["a"], "[REDACTED]");
}

/// Response-side: text-only content (no `structuredContent`) is parsed
/// out of the first text block. JSON-string contents resolve to typed
/// `content`; non-JSON text wraps as `{ "text": "<raw>" }`. The
/// `isError` flag round-trips.
#[test]
fn build_response_content_for_method_text_fallback() {
    use cpex::cpex_core::cmf::ContentPart;

    use super::json_rpc::build_response_content_for_method;

    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"result":{
             "content":[{"type":"text","text":"{\"k\":\"v\"}"}],
             "isError":false}}"#,
    );
    let parts = build_response_content_for_method("service/invoke", "echo", "corr-1", &body);
    assert_eq!(parts.len(), 1);
    match &parts[0] {
        ContentPart::ToolResult { content } => {
            assert!(!content.is_error);
            assert_eq!(content.content, serde_json::json!({"k":"v"}));
        },
        other => panic!("expected ToolResult; got {other:?}"),
    }
}

/// `structuredContent` takes precedence over the text-block fallback
/// when present.
#[test]
fn build_response_content_for_method_prefers_structured_content() {
    use cpex::cpex_core::cmf::ContentPart;

    use super::json_rpc::build_response_content_for_method;

    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"result":{
             "content":[{"type":"text","text":"ignored"}],
             "structuredContent":{"hi":"there"},
             "isError":true}}"#,
    );
    let parts = build_response_content_for_method("service/invoke", "echo", "corr-1", &body);
    assert_eq!(parts.len(), 1);
    match &parts[0] {
        ContentPart::ToolResult { content } => {
            assert!(content.is_error);
            assert_eq!(content.content, serde_json::json!({"hi":"there"}));
        },
        other => panic!("expected ToolResult; got {other:?}"),
    }
}

/// Response-side: when `result.content` has MULTIPLE text blocks and no
/// `structuredContent`, every block must end up in APL's view — not just
/// the first. Otherwise a later block carries data the policy never
/// inspected and the re-serializer never rewrites, leaking it. The
/// folded view exposes all blocks under `text`.
#[test]
fn build_response_content_for_method_folds_all_text_blocks() {
    use cpex::cpex_core::cmf::ContentPart;

    use super::json_rpc::build_response_content_for_method;

    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"result":{
             "content":[
               {"type":"text","text":"first secret"},
               {"type":"text","text":"second secret"}
             ],
             "isError":false}}"#,
    );
    let parts = build_response_content_for_method("service/invoke", "echo", "corr-1", &body);
    assert_eq!(parts.len(), 1);
    match &parts[0] {
        ContentPart::ToolResult { content } => {
            let text = content.content["text"].as_str().expect("text field present");
            assert!(
                text.contains("first secret") && text.contains("second secret"),
                "folded view must include every text block; got {text:?}",
            );
        },
        other => panic!("expected ToolResult; got {other:?}"),
    }
}

/// Response-side emit: when APL mutates the result, the entire
/// `result.content` array is collapsed to a single canonical text block
/// holding the vetted payload. Any other blocks (extra text, non-text)
/// are dropped so nothing the policy didn't vet survives, and
/// `structuredContent` is mirrored when the original had it.
#[test]
fn reserialize_response_collapses_to_single_vetted_block() {
    use cpex::cpex_core::cmf::{ContentPart, Message, Role, ToolResult};

    use super::json_rpc::reserialize_json_rpc_response_body;

    let original = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"old one"},{"type":"text","text":"old two"},{"type":"image","data":"B64","mimeType":"image/png"}],"structuredContent":{"ssn":"555-12-3456"},"isError":false}}"#,
    );
    let vetted = serde_json::json!({ "ssn": "[REDACTED]" });
    let message = Message::with_content(
        Role::Assistant,
        vec![ContentPart::ToolResult {
            content: ToolResult {
                tool_call_id: String::new(),
                tool_name: "echo".to_owned(),
                content: vetted.clone(),
                is_error: false,
            },
        }],
    );
    let out = reserialize_json_rpc_response_body(&original, "service/invoke", &message).expect("Some");
    let parsed: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
    let content = parsed["result"]["content"].as_array().expect("content array");
    assert_eq!(content.len(), 1, "extra blocks must be dropped; got {content:?}");
    let inner: serde_json::Value =
        serde_json::from_str(content[0]["text"].as_str().expect("text")).expect("vetted JSON");
    assert_eq!(inner, vetted, "emitted block must hold exactly the vetted value");
    assert_eq!(
        parsed["result"]["structuredContent"], vetted,
        "structuredContent mirrors vetted"
    );
}

/// Fail-closed sizing: a deny envelope substituted on the
/// response-rewrite-overflow / identity-failure paths is fitted to the
/// committed `Content-Length` — never longer. Pins the composition the
/// filter relies on so an oversized rewrite can never become a framing
/// desync.
#[test]
fn deny_envelope_fits_committed_length() {
    use cpex::cpex_core::error::PluginViolation;

    use super::{error::json_rpc_error_envelope_bytes, filter::fit_to_original_length};

    let violation = PluginViolation::new("gateway.response_rewrite_overflow", "too large to fit");
    let envelope = json_rpc_error_envelope_bytes(Some(&violation), &serde_json::json!(1));
    let original_len = envelope.len() + 64;
    let fitted = fit_to_original_length(envelope, original_len, "service/invoke", "overflow");
    assert_eq!(
        fitted.len(),
        original_len,
        "deny envelope must be padded to exactly the committed length",
    );
}

// -----------------------------------------------------------------------------
// on_request_body — CMF dispatch path (identity-only policy, no routes)
// -----------------------------------------------------------------------------

/// `on_request_body` happy path: valid JWT, `protocol.method=service/invoke`,
/// `protocol.name` set. The identity-only policy has no APL routes, so the
/// CMF dispatch finds no matching handler and the request continues.
/// Pins the "CMF dispatch runs without crashing and returns
/// `BodyDone`" branch the reviewer flagged as untested.
#[tokio::test(flavor = "multi_thread")]
async fn on_request_body_dispatches_cmf_when_metadata_present() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);

    let token = mint_jwt(&standard_claims("alice"));
    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);
    ctx.set_metadata("protocol.method", "service/invoke");
    ctx.set_metadata("protocol.name", "echo");

    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"service/invoke",
             "params":{"name":"echo","arguments":{}}}"#,
    );

    let action = filter
        .on_request_body(&mut ctx, &mut Some(body), true)
        .await
        .expect("filter ran");
    assert!(
        matches!(action, FilterAction::BodyDone),
        "no APL route should yield BodyDone; got {action:?}",
    );
}

/// A `cel:` route step gates the call through the `apl-pdp-cel` backend.
/// `alice` satisfies `subject.id == "alice"` → Allow (`BodyDone`); any
/// other subject fails the predicate → fail-closed Deny (`Reject`).
/// Proves praxis registers `CelPdpFactory` and the CEL PDP decision
/// flows through CMF dispatch alongside Cedar.
#[tokio::test(flavor = "multi_thread")]
async fn cel_route_allows_matching_subject_and_denies_others() {
    let (_dir, path) = write_cel_policy_config();
    let filter = build_filter(path);

    let allow = dispatch_echo_as(&filter, "alice").await;
    assert!(
        matches!(allow, FilterAction::BodyDone),
        "alice satisfies the CEL predicate; expected BodyDone, got {allow:?}",
    );

    let deny = dispatch_echo_as(&filter, "eve").await;
    assert!(
        matches!(deny, FilterAction::Reject(_)),
        "eve fails the CEL predicate; expected Reject, got {deny:?}",
    );
}

/// Session tainting end-to-end through the filter: reading the secret
/// taints the session (`taint(secret, session)`), and a later call in
/// the SAME session is denied (`security.labels contains "secret"`). A
/// DIFFERENT session id is unaffected — taint is session-scoped. Proves
/// the `X-Session-Id` → `agent.session_id` wiring + the cpex session
/// store's hydrate/persist round-trip across requests.
#[tokio::test(flavor = "multi_thread")]
async fn session_taint_persists_and_denies_within_the_same_session() {
    let (_dir, path) = write_taint_config();
    let filter = build_filter(path);

    let taint = dispatch_tool_session(&filter, "alice", "read-secret", "sess-1").await;
    assert!(
        matches!(taint, FilterAction::BodyDone),
        "tainting call should pass; got {taint:?}",
    );

    let denied = dispatch_tool_session(&filter, "alice", "send-out", "sess-1").await;
    assert!(
        matches!(denied, FilterAction::Reject(_)),
        "send-out in the tainted session must be denied; got {denied:?}",
    );

    let clean = dispatch_tool_session(&filter, "alice", "send-out", "sess-2").await;
    assert!(
        matches!(clean, FilterAction::BodyDone),
        "send-out in a fresh session must pass; got {clean:?}",
    );
}

/// Cross-principal isolation: session taint is keyed by the resolved
/// subject, so the SAME `X-Session-Id` under a different subject is a
/// different bucket. `eve` taints `shared`, but `bob` reusing `shared`
/// is unaffected — `H(eve:shared) != H(bob:shared)`.
#[tokio::test(flavor = "multi_thread")]
async fn session_taint_is_isolated_across_principals() {
    let (_dir, path) = write_taint_config();
    let filter = build_filter(path);

    let taint = dispatch_tool_session(&filter, "eve", "read-secret", "shared").await;
    assert!(
        matches!(taint, FilterAction::BodyDone),
        "eve's tainting call should pass; got {taint:?}",
    );

    let bob = dispatch_tool_session(&filter, "bob", "send-out", "shared").await;
    assert!(
        matches!(bob, FilterAction::BodyDone),
        "bob reusing eve's session id must NOT inherit her taint; got {bob:?}",
    );
}

/// Non-EOS chunks must pass through untouched — CMF dispatch waits
/// for the full body so the upstream protocol classifier filter has finished parsing
/// and writing metadata. Pins the streaming-chunk fast path.
#[tokio::test(flavor = "multi_thread")]
async fn on_request_body_continues_on_partial_chunks() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);
    let req = make_request(Method::POST, "/");
    let mut ctx = make_filter_context(&req);
    let mut chunk = Some(bytes::Bytes::from_static(br#"{"jsonrpc":"2.0""#));
    let action = filter
        .on_request_body(&mut ctx, &mut chunk, /* end_of_stream= */ false)
        .await
        .expect("filter ran");
    assert!(
        matches!(action, FilterAction::Continue),
        "non-EOS chunk must Continue without touching body; got {action:?}",
    );
}

// -----------------------------------------------------------------------------
// on_response_body — early returns
// -----------------------------------------------------------------------------

/// In default `body_access: read_only`, `on_response_body` returns
/// `Continue` without doing any work — the operator hasn't opted into
/// response rewriting, and the post-phase deny envelope path is gated
/// on `read_write`. Pins the early-return that keeps the sync hook
/// from blocking on `block_in_place` for read-only chains.
#[test]
fn on_response_body_in_read_only_is_a_no_op() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);
    let req = make_request(Method::POST, "/");
    let mut ctx = make_filter_context(&req);
    let mut body = Some(bytes::Bytes::from_static(b"some upstream body"));
    let action = filter
        .on_response_body(&mut ctx, &mut body, /* end_of_stream= */ true)
        .expect("hook ran");
    assert!(
        matches!(action, FilterAction::Continue),
        "ReadOnly response phase must Continue without rewriting; got {action:?}",
    );
    assert_eq!(
        body.as_deref(),
        Some(b"some upstream body".as_slice()),
        "body bytes must be untouched in ReadOnly",
    );
}

/// `on_response_body` returns `Continue` on non-EOS chunks regardless
/// of `body_access`. Mirror of the request-side partial-chunk test.
#[test]
fn on_response_body_continues_on_partial_chunks() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);
    let req = make_request(Method::POST, "/");
    let mut ctx = make_filter_context(&req);
    let mut chunk = Some(bytes::Bytes::from_static(b"partial"));
    let action = filter
        .on_response_body(&mut ctx, &mut chunk, /* end_of_stream= */ false)
        .expect("hook ran");
    assert!(matches!(action, FilterAction::Continue));
}

/// The response phase rebuilds `Extensions` from the identity resolved
/// in the request phase (stashed in `ctx.extensions`) rather than
/// re-running the identity hook. With no request-phase identity stashed
/// it fails closed with a deny envelope instead of re-resolving — so a
/// token that expires between the request and the already-served
/// response can never produce a false deny on a request that was
/// authorized.
#[tokio::test(flavor = "multi_thread")]
#[expect(
    clippy::too_many_lines,
    reason = "linear setup + assertions for the fail-closed response path"
)]
async fn response_phase_without_request_identity_fails_closed() {
    let (_dir, path) = write_single_plugin_config();
    let cfg = PolicyFilterConfig {
        config_path: path,
        body_access: super::config::BodyAccessMode::ReadWrite,
        require_protocol_metadata: true,
        init_timeout_secs: 30,
        max_buffer_bytes: 10_485_760,
    };
    let filter = PolicyFilter::new(cfg).expect("filter should construct");

    let req = make_request(Method::POST, "/");
    let mut ctx = make_filter_context(&req);
    ctx.set_metadata("protocol.method", "service/invoke");
    ctx.set_metadata("protocol.name", "echo");

    // No `on_request_body` ran on this ctx, so no `ResolvedIdentity` is
    // stashed. The response body is comfortably larger than the deny
    // envelope so the envelope fits within the committed length.
    let original = bytes::Bytes::from(format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"content":[{{"type":"text","text":"{}"}}]}}}}"#,
        "x".repeat(256)
    ));
    let original_len = original.len();
    let mut body = Some(original);

    let action = filter
        .on_response_body(&mut ctx, &mut body, /* end_of_stream= */ true)
        .expect("hook ran");

    assert!(matches!(action, FilterAction::Continue));
    let out = body.expect("response body present");
    assert_eq!(
        out.len(),
        original_len,
        "deny envelope must be fitted to the committed length"
    );
    assert!(
        String::from_utf8_lossy(&out).contains("identity.post_phase_unavailable"),
        "response body must be the fail-closed deny envelope; got: {}",
        String::from_utf8_lossy(&out),
    );
}

// -----------------------------------------------------------------------------
// attach_delegated_tokens — outbound header collision handling
// -----------------------------------------------------------------------------

/// Two delegated tokens that both target the same outbound header
/// are a policy-layering mistake (overlapping delegators). Praxis's
/// `request_headers_to_set` is overwrite-semantics and `HashMap`
/// iteration order is non-deterministic, so the naive path would
/// silently pick one. The filter applies first-writer-wins keyed by
/// `(outbound_header_lc, audience)`: only the alphabetically lowest
/// audience attaches, the other is logged and skipped, and the
/// returned count reflects what actually went on the wire.
#[test]
#[expect(clippy::too_many_lines, reason = "test fixture construction")]
fn attach_delegated_tokens_first_writer_wins_per_outbound_header() {
    use std::sync::Arc;

    use chrono::{Duration, Utc};
    use cpex::cpex_core::extensions::{
        container::Extensions,
        raw_credentials::{DelegationKey, DelegationMode, RawCredentialsExtension, RawDelegatedToken},
    };

    use super::filter::attach_delegated_tokens;

    let expires = Utc::now() + Duration::hours(1);
    let tok_a = RawDelegatedToken::new("token-a", "Authorization", "aud-a", Vec::<String>::new(), expires);
    let tok_b = RawDelegatedToken::new("token-b", "Authorization", "aud-b", Vec::<String>::new(), expires);
    let key_a = DelegationKey {
        subject_id: "alice".to_owned(),
        audience: "aud-a".to_owned(),
        scopes: Vec::new(),
        mode: DelegationMode::OnBehalfOfUser,
    };
    let key_b = DelegationKey {
        audience: "aud-b".to_owned(),
        ..key_a.clone()
    };
    let mut creds = RawCredentialsExtension::default();
    creds.delegated_tokens.insert(key_a, tok_a);
    creds.delegated_tokens.insert(key_b, tok_b);
    let ext = Extensions {
        raw_credentials: Some(Arc::new(creds)),
        ..Extensions::default()
    };

    let req = make_request(Method::POST, "/");
    let mut ctx = make_filter_context(&req);
    let count = attach_delegated_tokens(&mut ctx, Some(&ext));

    assert_eq!(count, 1, "exactly one token attaches for a colliding header");
    assert_eq!(ctx.request_headers_to_set.len(), 1, "exactly one header push");
    let (name, value) = &ctx.request_headers_to_set[0];
    assert_eq!(name.as_str(), "authorization");
    assert_eq!(
        value.to_str().expect("ASCII header value"),
        "Bearer token-a",
        "first-writer-wins by audience asc must pick aud-a",
    );
}

/// Sanity: non-colliding tokens for distinct outbound headers all
/// attach. Pins that the collision guard doesn't drop legitimate
/// multi-audience flows (the common case for routes that delegate
/// to multiple upstream APIs simultaneously).
#[test]
#[expect(clippy::too_many_lines, reason = "test fixture construction")]
fn attach_delegated_tokens_distinct_outbound_headers_all_attach() {
    use std::sync::Arc;

    use chrono::{Duration, Utc};
    use cpex::cpex_core::extensions::{
        container::Extensions,
        raw_credentials::{DelegationKey, DelegationMode, RawCredentialsExtension, RawDelegatedToken},
    };

    use super::filter::attach_delegated_tokens;

    let expires = Utc::now() + Duration::hours(1);
    let tok_auth = RawDelegatedToken::new("token-auth", "Authorization", "aud-auth", Vec::<String>::new(), expires);
    let tok_x = RawDelegatedToken::new("token-x", "X-Upstream-Token", "aud-x", Vec::<String>::new(), expires);
    let key_auth = DelegationKey {
        subject_id: "alice".to_owned(),
        audience: "aud-auth".to_owned(),
        scopes: Vec::new(),
        mode: DelegationMode::OnBehalfOfUser,
    };
    let key_x = DelegationKey {
        audience: "aud-x".to_owned(),
        ..key_auth.clone()
    };
    let mut creds = RawCredentialsExtension::default();
    creds.delegated_tokens.insert(key_auth, tok_auth);
    creds.delegated_tokens.insert(key_x, tok_x);
    let ext = Extensions {
        raw_credentials: Some(Arc::new(creds)),
        ..Extensions::default()
    };

    let req = make_request(Method::POST, "/");
    let mut ctx = make_filter_context(&req);
    let count = attach_delegated_tokens(&mut ctx, Some(&ext));

    assert_eq!(count, 2, "two distinct headers must both attach");
    assert_eq!(ctx.request_headers_to_set.len(), 2);
}
