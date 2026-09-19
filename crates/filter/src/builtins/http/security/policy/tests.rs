// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the `policy` security filter.
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
    AuthenticatedIdentity, BodyAccess, BodyMode, FilterAction, FilterEntry, FilterFactory, FilterPipeline,
    FilterRegistry,
    filter::HttpFilter as _,
    test_utils::{make_filter_context, make_request},
};

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

/// Write a single-plugin policy document referencing the HS256 test secret.
#[expect(clippy::too_many_lines, reason = "test fixture: the YAML literal is the bulk")]
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
  # Under `dispatch: policy` a plugin runs only where a policy names it, so an
  # identity plugin no `authentication:` list reaches fails the load.
  authentication:
    - jwt-user
"#
    );

    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let path_str = cfg_path.to_str().expect("utf8 path").to_owned();
    (dir, path_str)
}

/// Write a policy document with a single entity route (`echo` tool) gated by a
/// native `require(authenticated)` and no global HTTP policy. The filter
/// derives `entity_routes = true`, so it authorizes at the body phase and
/// requires classifier metadata.
fn write_tool_route_config() -> (TempDir, String) {
    write_tool_route_config_for_header("Authorization")
}

/// Variant used to prove that temporary gate results stay isolated when a
/// pipeline contains multiple policy instances with different credentials.
#[expect(clippy::too_many_lines, reason = "test fixture: the YAML literal is the bulk")]
fn write_tool_route_config_for_header(header: &str) -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
    on_error: fail
    config:
      header: {header}
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
  - tool: echo
    authorization:
      pre_invocation:
        - "require(authenticated)"
global:
  # Under `dispatch: policy` a plugin runs only where a policy names it, so an
  # identity plugin no `authentication:` list reaches fails the load.
  authentication:
    - jwt-user
"#
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().expect("utf8 path").to_owned())
}

/// Write a policy document whose `echo` tool route rule references BOTH `http.*`
/// and identity attributes in one CEL step. Proves the body-phase entity
/// evaluation sees the HTTP request line alongside entity/identity
/// attributes (the enrichment). `entity_routes = true`.
#[expect(
    clippy::too_many_lines,
    reason = "test fixture — the YAML literal is the bulk; splitting helpers would obscure the shape under test"
)]
fn write_http_entity_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
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
  # Under `dispatch: policy` a plugin runs only where a policy names it, so an
  # identity plugin no `authentication:` list reaches fails the load. This is
  # the list that reaches it.
  authentication:
    - jwt-user
  pdp:
    - kind: cel
routes:
  - tool: echo
    authorization:
      pre_invocation:
        - cel:
            expr: |
              http.method == "POST" && subject.id == "alice"
"#
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().expect("utf8 path").to_owned())
}

/// Write a policy document with only a `global` HTTP policy and no entity routes —
/// the pure L7 shape. The filter derives `http_global = true`,
/// `entity_routes = false`, and authorizes at `on_request` with no
/// classifier.
#[expect(
    clippy::too_many_lines,
    reason = "test fixture — the YAML literal is the bulk; splitting helpers would obscure the shape under test"
)]
fn write_l7_global_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
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
  authentication:
    - jwt-user
  authorization:
    pre_invocation:
      - "require(authenticated)"
      - cel: {{ expr: "http.method == 'GET'" }}
  pdp:
    - kind: cel
"#
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().expect("utf8 path").to_owned())
}

/// Write a policy document that declares BOTH a `global` HTTP policy (canonical
/// `authentication:`/`authorization:` form, admitting only GET) AND an entity
/// route (the `echo` tool). Derives the combined shape
/// `(http_global = true, entity_routes = true)`.
#[expect(
    clippy::too_many_lines,
    reason = "test fixture — the YAML literal is the bulk; splitting helpers would obscure the shape under test"
)]
fn write_combined_global_and_routes_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
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
  authentication:
    - jwt-user
  authorization:
    pre_invocation:
      - "require(authenticated)"
      - cel: {{ expr: "http.method == 'GET'" }}
  pdp:
    - kind: cel
routes:
  - tool: echo
    authorization:
      pre_invocation:
        - cel:
            expr: |
              subject.id == "alice"
"#
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().expect("utf8 path").to_owned())
}

/// Write a policy document that gates the `echo` tool through a CEL PDP step.
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
  # Under `dispatch: policy` a plugin runs only where a policy names it, so an
  # identity plugin no `authentication:` list reaches fails the load. This is
  # the list that reaches it.
  authentication:
    - jwt-user
  pdp:
    - kind: cel
routes:
  - tool: echo
    authorization:
      pre_invocation:
        - cel:
            expr: |
              subject.id == "alice"
"#
    );

    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let path_str = cfg_path.to_str().expect("utf8 path").to_owned();
    (dir, path_str)
}

/// Run a `tools/call` for the `echo` tool as `subject`, returning the
/// filter's body-phase action. Shared by the CEL allow/deny cases.
async fn dispatch_echo_as(filter: &PolicyFilter, subject: &str) -> FilterAction {
    dispatch_echo_method(filter, subject, Method::POST).await
}

/// Like [`dispatch_echo_as`] but with a caller-chosen HTTP method, so a test
/// can vary `http.method` and observe an entity route's `http.*` predicate.
async fn dispatch_echo_method(filter: &PolicyFilter, subject: &str, method: Method) -> FilterAction {
    let token = mint_jwt(&standard_claims(subject));
    let mut req = make_request(method, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);
    ctx.set_metadata("mcp.method", "tools/call");
    ctx.set_metadata("mcp.name", "echo");
    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#,
    );
    filter
        .on_request_body(&mut ctx, &mut Some(body), true)
        .await
        .expect("filter ran")
}

/// Write a policy document demonstrating session tainting: a `read-secret`
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
    authorization:
      pre_invocation:
        - "taint(secret, session)"
  - tool: send-out
    authorization:
      pre_invocation:
        - "security.labels contains \"secret\": deny('session accessed secret data', 'session_tainted_secret')"
global:
  # Under `dispatch: policy` a plugin runs only where a policy names it, so an
  # identity plugin no `authentication:` list reaches fails the load.
  authentication:
    - jwt-user
"#
    );

    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let path_str = cfg_path.to_str().expect("utf8 path").to_owned();
    (dir, path_str)
}

/// Dispatch a `tools/call` for `tool` as `subject` with the given
/// `X-Session-Id`. Returns the filter's body-phase action. Threads the
/// session header so the engine's session-scoped taint store can persist /
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
    ctx.set_metadata("mcp.method", "tools/call");
    ctx.set_metadata("mcp.name", tool);
    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{}}}"#,
    );
    filter
        .on_request_body(&mut ctx, &mut Some(body), true)
        .await
        .expect("filter ran")
}

/// Write a policy document with two identity plugins, each reading its own
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
global:
  # Under `dispatch: policy` a plugin runs only where a policy names it, so an
  # identity plugin no `authentication:` list reaches fails the load.
  authentication:
    - jwt-user
    - jwt-agent
"#
    );

    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let path_str = cfg_path.to_str().expect("utf8 path").to_owned();
    (dir, path_str)
}

/// Write a policy document that exercises ROUTE-SCOPED identity. A global
/// resolver (`id-global`, reads `Authorization`) is listed in
/// `global.authentication`; a second resolver (`id-route`, reads
/// `X-Route-Token`) is bound ONLY to the `scoped-tool` route via a
/// `replace_inherited` `authentication:` block. `open-tool` carries no
/// route-level `authentication:`, so it inherits the global resolver.
/// Both plugins validate the same HS256 material — only the HEADER each
/// reads and the route each is bound to differ, which is precisely what
/// route-scoping must select on.
#[expect(
    clippy::too_many_lines,
    reason = "test fixture — the YAML literal is the bulk; splitting helpers would obscure the shape under test"
)]
fn write_route_scoped_identity_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");

    let yaml = format!(
        r#"engine_settings:
  # Route-scoped dispatch only engages when routing is enabled.
  dispatch: policy
plugins:
  - name: id-global
    kind: identity/jwt
    hooks:
      - identity.resolve
    mode: sequential
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
  - name: id-route
    kind: identity/jwt
    hooks:
      - identity.resolve
    mode: sequential
    on_error: fail
    config:
      header: X-Route-Token
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
  authentication:
    - id-global
routes:
  # `apl` is required for a route to run identity/policy at all — without
  # a policy the body phase treats the route as passthrough.
  - tool: open-tool
    authorization:
      pre_invocation:
        - "require(authenticated)"
  - tool: scoped-tool
    authentication:
      replace_inherited: true
      steps:
        - id-route
    authorization:
      pre_invocation:
        - "require(authenticated)"
"#
    );

    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let path_str = cfg_path.to_str().expect("utf8 path").to_owned();
    (dir, path_str)
}

/// Drive a `tools/call` for `tool`, carrying `token` in `header` as the
/// ONLY identity header on the request, and return the body-phase
/// action. The classifier metadata (`mcp.method` / `mcp.name`) is what
/// tells the filter which route this is — and therefore which identity
/// resolvers to scope to.
async fn dispatch_tool_with_header(
    filter: &PolicyFilter,
    tool: &str,
    header: &'static str,
    token: &str,
) -> FilterAction {
    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        header,
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);
    ctx.set_metadata("mcp.method", "tools/call");
    ctx.set_metadata("mcp.name", tool);
    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{}}}"#,
    );
    filter
        .on_request_body(&mut ctx, &mut Some(body), true)
        .await
        .expect("filter ran")
}

/// A route whose `authentication:` block names `id-route` (with
/// `replace_inherited`) resolves identity with ONLY that resolver: a
/// request carrying just `X-Route-Token` — no `Authorization` — is
/// accepted. This is the wiring under test: the filter must stamp the
/// route coordinates onto the `Extensions` so the identity hook scopes
/// to the route's `authentication:` list instead of running every
/// registered resolver.
#[tokio::test(flavor = "multi_thread")]
async fn route_authentication_scopes_identity_to_its_resolver() {
    let (_dir, path) = write_route_scoped_identity_config();
    let filter = build_filter(path);
    let token = mint_jwt(&standard_claims("alice"));

    let action = dispatch_tool_with_header(&filter, "scoped-tool", "X-Route-Token", &token).await;
    assert!(
        !matches!(action, FilterAction::Reject(_)),
        "scoped-tool must scope to id-route (reads X-Route-Token); a reject means the global \
         id-global (reads Authorization, absent here) wrongly ran; got {action:?}",
    );
}

/// `replace_inherited` genuinely DROPS the inherited global resolver:
/// `scoped-tool` carrying only `Authorization` (which the global
/// `id-global` reads) and NO `X-Route-Token` is rejected — `id-global`
/// never runs, and the route's `id-route` finds no header. Pins that the
/// scoping EXCLUDES the inherited resolver rather than merely adding the
/// route's on top. (Before the fix, `id-global` ran for every route, so
/// this request would have been accepted.)
#[tokio::test(flavor = "multi_thread")]
async fn route_replace_inherited_excludes_global_resolver() {
    let (_dir, path) = write_route_scoped_identity_config();
    let filter = build_filter(path);
    let token = mint_jwt(&standard_claims("alice"));

    let action = dispatch_tool_with_header(&filter, "scoped-tool", "Authorization", &token).await;
    assert!(
        matches!(&action, FilterAction::Reject(rej) if rej.status == 401),
        "scoped-tool must NOT run the global resolver; Authorization-only must 401; got {action:?}",
    );
}

/// Control: a route with NO `authentication:` block inherits the global
/// resolver. `open-tool` with only `Authorization` is accepted (global
/// `id-global` runs); with only `X-Route-Token` it is rejected (the
/// route resolver is not in scope here). Together with the scoped-tool
/// cases, this shows the filter selects resolvers PER ROUTE — not one
/// global set for all traffic.
#[tokio::test(flavor = "multi_thread")]
async fn route_without_authentication_inherits_global_resolver() {
    let (_dir, path) = write_route_scoped_identity_config();
    let filter = build_filter(path);
    let token = mint_jwt(&standard_claims("alice"));

    let allowed = dispatch_tool_with_header(&filter, "open-tool", "Authorization", &token).await;
    assert!(
        !matches!(allowed, FilterAction::Reject(_)),
        "open-tool inherits id-global (reads Authorization); a reject means id-route \
         (reads X-Route-Token, absent here) wrongly ran; got {allowed:?}",
    );

    let rejected = dispatch_tool_with_header(&filter, "open-tool", "X-Route-Token", &token).await;
    assert!(
        matches!(&rejected, FilterAction::Reject(rej) if rej.status == 401),
        "open-tool does not use the route resolver; X-Route-Token-only must 401; got {rejected:?}",
    );
}

/// The header-phase gate has no route coordinates and therefore must not
/// publish its unscoped identity result. Once body classification selects
/// `open-tool`, the route-scoped resolution is authoritative and publishes the
/// global resolver's subject even when a different route token is also present.
#[tokio::test(flavor = "multi_thread")]
#[expect(clippy::too_many_lines, reason = "linear two-phase route identity regression")]
async fn route_scoped_identity_is_published_only_after_authoritative_resolution() {
    let (_dir, path) = write_route_scoped_identity_config();
    let filter = build_filter(path);
    let global_token = mint_jwt(&standard_claims("alice"));
    let route_token = mint_jwt(&standard_claims("bob"));

    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {global_token}")).expect("header value"),
    );
    req.headers.insert(
        "X-Route-Token",
        HeaderValue::from_str(&format!("Bearer {route_token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);

    let gate = filter.on_request(&mut ctx).await.expect("identity gate ran");
    assert!(
        matches!(&gate, FilterAction::Continue),
        "identity gate should continue before route resolution; got {gate:?}",
    );
    assert!(
        ctx.extensions.get::<AuthenticatedIdentity>().is_none(),
        "unscoped header gate must not publish a route-dependent principal",
    );

    ctx.set_metadata("mcp.method", "tools/call");
    ctx.set_metadata("mcp.name", "open-tool");
    let mut body = Some(bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"open-tool","arguments":{}}}"#,
    ));
    let action = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect("route policy ran");

    assert!(
        matches!(&action, FilterAction::BodyDone),
        "authoritative route policy should complete body processing; got {action:?}",
    );
    assert_eq!(
        ctx.extensions
            .get::<AuthenticatedIdentity>()
            .map(AuthenticatedIdentity::subject_id),
        Some("alice"),
        "open-tool inherits the global resolver; the route-only Bob token must not win",
    );
}

/// Write a policy document selecting the Valkey-backed session store via a
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
  # Under `dispatch: policy` a plugin runs only where a policy names it, so an
  # identity plugin no `authentication:` list reaches fails the load. This is
  # the list that reaches it.
  authentication:
    - jwt-user
  session_store:
    kind: valkey
    endpoint: localhost:6379
routes:
  - tool: read-secret
    authorization:
      pre_invocation:
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
        allow_private_idp: false,
        body_access: super::config::BodyAccessMode::ReadOnly,
        require_protocol_metadata: true,
        init_timeout_secs: 30,
        max_buffer_bytes: 10_485_760,
        llm: super::config::LlmOptions::default(),
    };
    PolicyFilter::new(cfg).expect("filter should construct")
}

/// Body filter that records the authenticated subject visible at its position
/// in the pipeline. Its `StreamBuffer` mode forces body-first pre-read.
struct IdentityBodyObserver {
    observed_subjects: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl crate::HttpFilter for IdentityBodyObserver {
    fn name(&self) -> &'static str {
        "identity_body_observer"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, crate::FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(1_024) }
    }

    async fn on_request_body(
        &self,
        ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, crate::FilterError> {
        let subject = ctx
            .extensions
            .get::<AuthenticatedIdentity>()
            .map_or("<missing>", AuthenticatedIdentity::subject_id)
            .to_owned();
        self.observed_subjects.lock().expect("observer lock").push(subject);
        Ok(FilterAction::BodyDone)
    }
}

/// Build a real two-filter pipeline so lifecycle state is keyed by the policy
/// filter's runtime ID exactly as it is in production.
fn build_policy_observer_pipeline(config_path: &str, observed_subjects: &Arc<Mutex<Vec<String>>>) -> FilterPipeline {
    let mut registry = FilterRegistry::with_builtins();
    let observer_state = Arc::clone(observed_subjects);
    registry
        .register(
            "identity_body_observer",
            FilterFactory::Http(Arc::new(move |_| {
                let filter: Box<dyn crate::HttpFilter> = Box::new(IdentityBodyObserver {
                    observed_subjects: Arc::clone(&observer_state),
                });
                Ok(filter)
            })),
        )
        .expect("register observer");

    let mut entries: Vec<FilterEntry> = serde_yaml::from_str(&format!(
        "- filter: policy\n  config_path: {config_path}\n- filter: identity_body_observer\n"
    ))
    .expect("pipeline config");
    FilterPipeline::build(&mut entries, &registry).expect("build pipeline")
}

/// Exercise the protocol's body-first ordering: a partial body chunk reaches
/// the policy and then the downstream observer before the header phase. The
/// observer must see identity, and the later header phase must use the
/// completion marker rather than requiring the credential again.
#[expect(
    clippy::too_many_lines,
    reason = "linear body-first and header-second lifecycle regression"
)]
async fn assert_pre_read_admission(config_path: &str, method: Method) {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let pipeline = build_policy_observer_pipeline(config_path, &observed);
    assert!(
        matches!(
            pipeline.body_capabilities().request_body_mode,
            BodyMode::StreamBuffer { .. }
        ),
        "observer must force body-first StreamBuffer mode",
    );

    let token = mint_jwt(&standard_claims("alice"));
    let mut req = make_request(method, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut body_ctx = make_filter_context(&req);
    let mut partial_body = Some(bytes::Bytes::from_static(b"{"));
    let body_action = pipeline
        .execute_http_request_body(&mut body_ctx, &mut partial_body, false)
        .await
        .expect("pre-read body pipeline ran");
    assert!(
        matches!(&body_action, FilterAction::Continue),
        "partial pre-read body processing should continue; got {body_action:?}",
    );
    assert_eq!(
        *observed.lock().expect("observer lock"),
        ["alice"],
        "downstream body consumer must see authenticated identity on its first invocation",
    );

    let extensions = std::mem::take(&mut body_ctx.extensions);
    let filter_state = std::mem::take(&mut body_ctx.filter_state);
    drop(body_ctx);
    req.headers.remove("Authorization");

    let mut header_ctx = make_filter_context(&req);
    header_ctx.extensions = extensions;
    header_ctx.filter_state = filter_state;
    let header_action = pipeline
        .execute_http_request(&mut header_ctx)
        .await
        .expect("header pipeline ran");
    assert!(
        matches!(header_action, FilterAction::Continue),
        "body-phase completion marker must prevent credential revalidation",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pre_read_authenticates_before_identity_only_body_consumer() {
    let (_dir, path) = write_single_plugin_config();
    assert_pre_read_admission(&path, Method::POST).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pre_read_authorizes_before_pure_l7_body_consumer() {
    let (_dir, path) = write_l7_global_config();
    assert_pre_read_admission(&path, Method::GET).await;
}

/// Each policy instance owns its early gate result. The observer between two
/// metadata-optional entity policies must see the first policy's Alice subject,
/// not the second policy's Bob subject that was gated later in header order.
#[tokio::test(flavor = "multi_thread")]
#[expect(clippy::too_many_lines, reason = "two-policy lifecycle isolation regression")]
async fn gated_identity_is_isolated_between_policy_instances() {
    let (_first_dir, first_path) = write_tool_route_config_for_header("Authorization");
    let (_second_dir, second_path) = write_tool_route_config_for_header("X-Second-Token");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let observer_state = Arc::clone(&observed);
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "identity_body_observer",
            FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(IdentityBodyObserver {
                    observed_subjects: Arc::clone(&observer_state),
                }))
            })),
        )
        .expect("register observer");
    let mut entries: Vec<FilterEntry> = serde_yaml::from_str(&format!(
        "- filter: policy\n  config_path: {first_path}\n  require_protocol_metadata: false\n\
         - filter: identity_body_observer\n\
         - filter: policy\n  config_path: {second_path}\n  require_protocol_metadata: false\n"
    ))
    .expect("pipeline config");
    let pipeline = FilterPipeline::build(&mut entries, &registry).expect("build pipeline");

    let alice_token = mint_jwt(&standard_claims("alice"));
    let bob_token = mint_jwt(&standard_claims("bob"));
    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {alice_token}")).expect("header value"),
    );
    req.headers.insert(
        "X-Second-Token",
        HeaderValue::from_str(&format!("Bearer {bob_token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);

    let header_action = pipeline
        .execute_http_request(&mut ctx)
        .await
        .expect("header pipeline ran");
    assert!(
        matches!(&header_action, FilterAction::Continue),
        "both policy header gates should continue; got {header_action:?}",
    );
    assert!(
        ctx.extensions.get::<AuthenticatedIdentity>().is_none(),
        "route-dependent header gates must not publish an unscoped identity",
    );

    let body_action = pipeline
        .execute_http_request_body(&mut ctx, &mut Some(bytes::Bytes::new()), true)
        .await
        .expect("body pipeline ran");
    assert!(
        matches!(&body_action, FilterAction::Continue),
        "body pipeline should continue after both policy evaluations; got {body_action:?}",
    );
    assert_eq!(*observed.lock().expect("observer lock"), ["alice"]);
    assert_eq!(
        ctx.extensions
            .get::<AuthenticatedIdentity>()
            .map(AuthenticatedIdentity::subject_id),
        Some("bob"),
    );
}

// -----------------------------------------------------------------------------
// Config parsing
// -----------------------------------------------------------------------------

#[test]
fn config_parses_minimal_yaml() {
    let yaml = "config_path: /etc/praxis/policy.yaml";
    let cfg: PolicyFilterConfig = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(cfg.config_path, "/etc/praxis/policy.yaml", "config_path round-trips",);
    assert_eq!(cfg.max_buffer_bytes, 10_485_760, "max_buffer_bytes defaults to 10 MiB",);
}

#[test]
fn rejects_zero_max_buffer_bytes() {
    let cfg = PolicyFilterConfig {
        config_path: "/nonexistent/policy.yaml".to_owned(),
        allow_private_idp: false,
        body_access: super::config::BodyAccessMode::ReadWrite,
        require_protocol_metadata: true,
        init_timeout_secs: 30,
        max_buffer_bytes: 0,
        llm: super::config::LlmOptions::default(),
    };
    let err = match PolicyFilter::new(cfg) {
        Ok(_) => panic!("zero max_buffer_bytes must be rejected"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("max_buffer_bytes must be > 0"), "got: {err}");
}

#[test]
fn rejects_oversized_max_buffer_bytes() {
    let cfg = PolicyFilterConfig {
        config_path: "/nonexistent/policy.yaml".to_owned(),
        allow_private_idp: false,
        body_access: super::config::BodyAccessMode::ReadWrite,
        require_protocol_metadata: true,
        init_timeout_secs: 30,
        max_buffer_bytes: praxis_core::config::ABSOLUTE_MAX_BODY_BYTES + 1,
        llm: super::config::LlmOptions::default(),
    };
    let err = match PolicyFilter::new(cfg) {
        Ok(_) => panic!("oversized max_buffer_bytes must be rejected"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("exceeds the maximum"), "got: {err}");
}

#[test]
fn referenced_files_declares_the_policy_document() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path.clone());
    assert_eq!(
        filter.referenced_files(),
        vec![std::path::PathBuf::from(&path)],
        "the policy document must be declared so edits to it trigger a reload"
    );
}

#[test]
fn config_max_buffer_bytes_override() {
    let yaml = "config_path: /etc/praxis/policy.yaml\nmax_buffer_bytes: 1048576";
    let cfg: PolicyFilterConfig = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(cfg.max_buffer_bytes, 1_048_576, "explicit max_buffer_bytes wins");
}

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

/// Write a policy whose issuer uses a loopback `jwks_url`.
fn write_jwks_url_config(capabilities: &str) -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
    mode: sequential
    on_error: fail
{capabilities}    config:
      header: Authorization
      trusted_issuers:
        - issuer: "{TEST_ISSUER}"
          audiences: ["{TEST_AUDIENCE}"]
          algorithms: ["RS256"]
          decoding_key:
            kind: jwks_url
            url: "http://127.0.0.1:1/jwks.json"
            insecure_http: true
          leeway_seconds: 60
      claim_mapper: standard

global:
  authentication:
    - jwt-user
"#
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let path_str = cfg_path.to_str().expect("utf8 path").to_owned();
    (dir, path_str)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_jwks_issuer_constructs_with_the_installed_transport() {
    let (_dir, path) = write_jwks_url_config("    capabilities:\n      - perform_http\n");
    if let Err(e) = try_build_filter_allowing_private(path, true) {
        panic!("a refused connection is recoverable and must still boot; got {e}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_jwks_issuer_without_perform_http_fails_to_construct() {
    let (_dir, path) = write_jwks_url_config("");
    let err = try_build_filter_allowing_private(path, true)
        .err()
        .expect("a withheld capability must refuse to start");
    let msg = err.to_string();
    assert!(
        msg.contains("perform_http"),
        "the error must name the capability to add; got {msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_loopback_idp_policy_constructs_when_private_access_is_disabled() {
    let (_dir, path) = write_jwks_url_config("    capabilities:\n      - perform_http\n");
    if let Err(e) = try_build_filter_allowing_private(path, false) {
        panic!("a refused destination is recoverable and must still boot; got {e}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_inline_key_config_needs_no_egress_capability() {
    let (_dir, path) = write_single_plugin_config();
    let _filter = build_filter(path);
}

/// Write a policy covering the supported request assertion shapes.
#[expect(clippy::too_many_lines, reason = "test fixture: the YAML literal is the bulk")]
fn write_assertions_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
    mode: sequential
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
  authentication:
    - jwt-user
  assertions:
    request:
      headers:
        - name: x-auth-user-id
          from: subject.id
        - name: x-auth-roles
          from: subject.roles
          encode: csv
        - name: x-auth-context
          members:
            tenant: claim.tenant
      strip:
        - x-drop-me

routes:
  - tool: echo
    authorization:
      pre_invocation:
        - "require(authenticated)"
"#
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().expect("utf8 path").to_owned())
}

#[tokio::test(flavor = "multi_thread")]
#[expect(clippy::too_many_lines, reason = "linear assertion contract coverage")]
async fn request_assertions_reach_the_upstream_request() {
    let (_dir, path) = write_assertions_config();
    let filter = build_filter(path);

    let mut claims = standard_claims("alice");
    claims["roles"] = json!(["admin", "writer"]);
    claims["tenant"] = json!("acme");
    let token = mint_jwt(&claims);

    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    req.headers.insert("x-auth-user-id", HeaderValue::from_static("root"));
    req.headers.insert("x-drop-me", HeaderValue::from_static("secret"));
    let mut ctx = make_filter_context(&req);
    ctx.set_metadata("mcp.method", "tools/call");
    ctx.set_metadata("mcp.name", "echo");

    let mut body = Some(bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#,
    ));
    let action = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect("body phase ran");
    assert!(
        matches!(action, FilterAction::BodyDone),
        "the route allows, and the body phase signals that with BodyDone; got {action:?}"
    );

    let set: std::collections::HashMap<String, String> = ctx
        .request_headers_to_set
        .iter()
        .map(|(n, v)| (n.as_str().to_owned(), v.to_str().unwrap_or_default().to_owned()))
        .collect();

    assert_eq!(
        set.get("x-auth-user-id").map(String::as_str),
        Some("alice"),
        "the client sent `root` under this name and must not have it forwarded: \
         an entry removes its target before injecting"
    );
    assert_eq!(
        set.get("x-auth-roles").map(String::as_str),
        Some("admin,writer"),
        "a collection renders under its declared encoding, sorted"
    );
    assert_eq!(
        set.get("x-auth-context").map(String::as_str),
        Some(r#"{"tenant":"acme"}"#),
        "a members entry renders one JSON object with the operator's keys"
    );

    let removed: Vec<&str> = ctx
        .request_headers_to_remove
        .iter()
        .map(http::header::HeaderName::as_str)
        .collect();
    assert!(
        removed.contains(&"x-drop-me"),
        "a `strip:` entry removes a name no header entry targets; got {removed:?}"
    );
    assert!(
        !removed.contains(&"authorization"),
        "nothing here strips the credential, and praxis must not invent removals: \
         got {removed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_policy_without_assertions_touches_no_upstream_header() {
    let (_dir, path) = write_tool_route_config();
    let filter = build_filter(path);

    let token = mint_jwt(&standard_claims("alice"));
    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);
    ctx.set_metadata("mcp.method", "tools/call");
    ctx.set_metadata("mcp.name", "echo");

    let mut body = Some(bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#,
    ));
    drop(
        filter
            .on_request_body(&mut ctx, &mut body, true)
            .await
            .expect("body phase ran"),
    );

    assert!(
        ctx.request_headers_to_remove.is_empty(),
        "no contract means no removals; got {:?}",
        ctx.request_headers_to_remove
    );
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

/// When a downstream pre-read ran `on_request_body` first and stashed
/// `ResolvedIdentity` (having stripped the inbound credential for the
/// upstream), the early `identity_gate` must skip rather than re-resolve
/// against the now-missing headers. A credential-less request that would
/// normally 401 here passes because the body phase is authoritative.
///
/// The routes-only config is what puts `on_request` on the `identity_gate`
/// path, and stashing `ResolvedIdentity` is what a body phase that already
/// resolved and enforced identity leaves behind.
#[tokio::test(flavor = "multi_thread")]
async fn identity_gate_skips_when_body_phase_already_resolved() {
    use ppe::praxis_policy_core::identity::{IdentityPayload, TokenSource};

    use super::filter::ResolvedIdentity;

    let (_dir, path) = write_cel_policy_config();
    let filter = build_filter(path);

    let req = make_request(Method::POST, "/");
    let mut ctx = make_filter_context(&req);

    ctx.extensions.insert(ResolvedIdentity(IdentityPayload::new(
        String::new(),
        TokenSource::Bearer,
    )));

    let action = filter.on_request(&mut ctx).await.expect("on_request ran");
    assert!(
        matches!(action, FilterAction::Continue),
        "gate must be skipped when ResolvedIdentity is already stashed; got {action:?}",
    );
}

/// Control for `identity_gate_skips_when_body_phase_already_resolved`: the
/// same credential-less request with no `ResolvedIdentity` stashed must run
/// the gate and reject — proving the skip (not something else) is what flips
/// the outcome to `Continue`.
#[tokio::test(flavor = "multi_thread")]
async fn identity_gate_rejects_when_identity_not_yet_resolved() {
    let (_dir, path) = write_cel_policy_config();
    let filter = build_filter(path);

    let req = make_request(Method::POST, "/");
    let mut ctx = make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.expect("on_request ran");
    assert!(
        matches!(action, FilterAction::Reject(_)),
        "no resolved identity → gate must reject; got {action:?}",
    );
}

/// A valid HS256 JWT in the configured header passes the identity
/// chain and the filter emits Continue.
#[tokio::test(flavor = "multi_thread")]
#[expect(clippy::too_many_lines, reason = "linear identity projection contract assertions")]
async fn valid_hs256_jwt_continues() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);

    let mut claims = standard_claims("alice");
    claims["roles"] = json!(["admin", "writer", "admin"]);
    claims["teams"] = json!(["platform"]);
    claims["tenant"] = json!("acme");
    claims["profile"] = json!({"tier": "gold"});
    claims["authorization"] = json!("custom-value");
    claims["projects"] = json!(["alpha", "beta"]);
    claims["seat_count"] = json!(7);
    claims["ratio"] = json!(1.5);
    claims["is_admin"] = json!(true);
    claims["absent"] = json!(null);
    let token = mint_jwt(&claims);
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

    let identity = ctx
        .extensions
        .get::<AuthenticatedIdentity>()
        .expect("validated subject should be published");
    assert_eq!(identity.subject_id(), "alice");
    assert_eq!(
        identity.roles().iter().map(String::as_str).collect::<Vec<_>>(),
        ["admin", "writer"],
    );
    assert_eq!(
        identity.teams().iter().map(String::as_str).collect::<Vec<_>>(),
        ["platform"]
    );
    assert_eq!(identity.custom_claims().get("tenant").map(String::as_str), Some("acme"));
    assert_eq!(
        identity.custom_claims().get("authorization").map(String::as_str),
        Some("custom-value"),
    );
    assert_eq!(
        identity.custom_claims().get("profile").map(String::as_str),
        Some(r#"{"tier":"gold"}"#),
    );
    for (claim, want) in [
        ("projects", r#"["alpha","beta"]"#),
        ("seat_count", "7"),
        ("ratio", "1.5"),
        ("is_admin", "true"),
        ("absent", "null"),
    ] {
        assert_eq!(
            identity.custom_claims().get(claim).map(String::as_str),
            Some(want),
            "claim `{claim}` must render as its compact JSON form",
        );
    }
    for excluded in ["iss", "aud", "sub", "exp", "iat", "roles", "teams"] {
        assert!(
            !identity.custom_claims().contains_key(excluded),
            "registered and promoted claims must not be exposed as custom claims: {excluded}",
        );
    }
}

/// The pure-L7 authorization path resolves identity independently of the
/// identity-only gate and publishes the same stable extension.
#[tokio::test(flavor = "multi_thread")]
async fn pure_l7_allow_publishes_authenticated_identity() {
    let (_dir, path) = write_l7_global_config();
    let filter = build_filter(path);

    let token = mint_jwt(&standard_claims("alice"));
    let mut req = make_request(Method::GET, "/");
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
    assert_eq!(
        ctx.extensions
            .get::<AuthenticatedIdentity>()
            .map(AuthenticatedIdentity::subject_id),
        Some("alice"),
    );
}

/// Entity-aware policies resolve identity in the body phase. That producer
/// path must publish the extension before later body filters execute.
#[tokio::test(flavor = "multi_thread")]
async fn entity_allow_publishes_authenticated_identity() {
    let (_dir, path) = write_tool_route_config();
    let filter = build_filter(path);

    let token = mint_jwt(&standard_claims("alice"));
    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);
    ctx.set_metadata("mcp.method", "tools/call");
    ctx.set_metadata("mcp.name", "echo");
    let mut body = Some(bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#,
    ));

    let action = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect("filter ran");
    assert!(
        matches!(action, FilterAction::BodyDone),
        "expected BodyDone; got {action:?}"
    );
    assert_eq!(
        ctx.extensions
            .get::<AuthenticatedIdentity>()
            .map(AuthenticatedIdentity::subject_id),
        Some("alice"),
    );
}

/// A JWT whose signature byte has been flipped fails verification and
/// the filter emits HTTP 401.
#[tokio::test(flavor = "multi_thread")]
async fn tampered_jwt_signature_rejects_401() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);

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

#[tokio::test]
async fn current_thread_runtime_is_accepted() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);

    let req = make_request(Method::POST, "/");
    let mut ctx = make_filter_context(&req);

    let action = filter
        .on_request(&mut ctx)
        .await
        .expect("current-thread runtime must be accepted");
    assert!(
        matches!(action, FilterAction::Reject(_)),
        "unauthenticated request should be rejected; got {action:?}",
    );
}

#[tokio::test]
async fn current_thread_runtime_allows_pure_l7() {
    let (_dir, path) = write_l7_global_config();
    let filter = build_filter(path); // ReadOnly, http_global && !entity_routes

    let req = make_request(Method::GET, "/");
    let mut ctx = make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await;
    assert!(
        action.is_ok(),
        "pure-L7 must not be refused on a current-thread runtime; got {action:?}",
    );
}

// -----------------------------------------------------------------------------
// Config-schema guards
// -----------------------------------------------------------------------------

#[test]
fn config_rejects_unknown_fields() {
    let yaml = "
config_path: /etc/praxis/policy.yaml
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

#[test]
fn config_require_protocol_metadata_defaults_to_true() {
    let yaml = "config_path: /etc/praxis/policy.yaml";
    let cfg: PolicyFilterConfig = serde_yaml::from_str(yaml).expect("parse");
    assert!(cfg.require_protocol_metadata, "default must be fail-closed");
}

#[test]
fn config_init_timeout_defaults_to_30s() {
    let yaml = "config_path: /etc/praxis/policy.yaml";
    let cfg: PolicyFilterConfig = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(cfg.init_timeout_secs, 30);
}

#[test]
fn config_init_timeout_honors_override() {
    let yaml = "config_path: /etc/praxis/policy.yaml\ninit_timeout_secs: 5";
    let cfg: PolicyFilterConfig = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(cfg.init_timeout_secs, 5);
}

// End-to-end exercise of the `init_timeout_secs` knob via the JWKS
// path is intentionally NOT a unit test: the bundled identity-jwt
// plugin has its own JWKS connect/request timeouts plus soft-fail-at-
// boot, so a hung JWKS endpoint never propagates a hang through
// `PolicyEngine::initialize` in the first place. The wrap-timeout in
// `PolicyFilter::new` is defense-in-depth for OTHER init paths (custom
// plugins, future hooks) where a future could legitimately stall.
// The unit tests above pin the surface; the timeout's behavior is
// exercised by `tokio::time::timeout` itself.

// -----------------------------------------------------------------------------
// Fail-closed policy gate (require_protocol_metadata)
// -----------------------------------------------------------------------------

/// For an entity-aware policy (declares tool/prompt/resource routes) with
/// `require_protocol_metadata: true` (default), a request that reaches the
/// body phase without `mcp.method` is rejected with
/// HTTP 500 + `X-Policy-Violation: config.missing_protocol_metadata`. This
/// catches a misconfigured chain (protocol classifier filter missing or ordered
/// after policy) loudly at the first body-phase request.
#[tokio::test(flavor = "multi_thread")]
async fn missing_protocol_metadata_rejects_when_required() {
    let (_dir, path) = write_tool_route_config();
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

/// An entity-bound method without its entity name cannot select the
/// route-scoped resolver. The filter must reject instead of admitting the
/// request with neither authorization nor a trusted identity projection.
#[tokio::test(flavor = "multi_thread")]
async fn missing_entity_name_rejects_after_successful_identity_gate() {
    let (_dir, path) = write_tool_route_config();
    let filter = build_filter(path);
    let authorization =
        HeaderValue::from_str(&format!("Bearer {}", mint_jwt(&standard_claims("alice")))).expect("header value");
    let mut req = make_request(Method::POST, "/");
    req.headers.insert("Authorization", authorization);
    let mut ctx = make_filter_context(&req);

    let gate = filter.on_request(&mut ctx).await.expect("identity gate ran");
    assert!(
        matches!(&gate, FilterAction::Continue),
        "identity gate should continue before entity metadata is available; got {gate:?}",
    );
    assert!(
        ctx.extensions.get::<AuthenticatedIdentity>().is_none(),
        "header gate must not publish identity before authoritative entity resolution",
    );
    ctx.set_metadata("mcp.method", "tools/call");

    let action = filter
        .on_request_body(&mut ctx, &mut Some(bytes::Bytes::new()), true)
        .await
        .expect("body policy ran");
    assert!(
        matches!(&action, FilterAction::Reject(rejection) if rejection.status == 500),
        "missing entity name must reject fail-closed; got {action:?}",
    );
    assert!(
        ctx.extensions.get::<AuthenticatedIdentity>().is_none(),
        "failed entity resolution must not publish authenticated identity",
    );
}

/// For an entity-aware policy with `require_protocol_metadata: false`, a
/// request with no `mcp.method` passes through (identity-only mode for
/// non-classified traffic). Pins the opt-out behavior.
#[tokio::test(flavor = "multi_thread")]
#[expect(clippy::too_many_lines, reason = "full identity-only fallback lifecycle")]
async fn missing_protocol_metadata_passes_when_not_required() {
    let (_dir, path) = write_tool_route_config();
    let cfg = PolicyFilterConfig {
        config_path: path,
        allow_private_idp: false,
        body_access: super::config::BodyAccessMode::ReadOnly,
        require_protocol_metadata: false,
        init_timeout_secs: 30,
        max_buffer_bytes: 10_485_760,
        llm: super::config::LlmOptions::default(),
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
    assert_eq!(
        ctx.extensions
            .get::<AuthenticatedIdentity>()
            .map(AuthenticatedIdentity::subject_id),
        Some("alice"),
        "identity-only fallback should publish the validated unscoped principal",
    );
}

// -----------------------------------------------------------------------------
// Post-phase deny envelope (json_rpc_error_envelope_bytes)
// -----------------------------------------------------------------------------

#[test]
fn json_rpc_error_envelope_has_expected_shape() {
    use ppe::praxis_policy_core::error::PluginViolation;

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

#[test]
fn json_rpc_error_envelope_preserves_string_request_id() {
    use super::error::json_rpc_error_envelope_bytes;
    let id = serde_json::json!("req-abc-123");
    let bytes = json_rpc_error_envelope_bytes(None, &id);
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    assert_eq!(parsed["id"], "req-abc-123");
}

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

#[test]
fn auth_rejection_shape_when_violation_present() {
    use ppe::praxis_policy_core::error::PluginViolation;

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
// http_authz_rejection (generic-HTTP / L7 deny mapping)
// -----------------------------------------------------------------------------

#[test]
fn http_authz_rejection_defaults_without_details() {
    use ppe::praxis_policy_core::error::PluginViolation;

    use super::error::http_authz_rejection;

    let violation = PluginViolation::new("policy.method_denied", "only GET is permitted");
    let rej = http_authz_rejection(Some(&violation));
    assert_eq!(rej.status, 403, "default L7 deny status is 403");

    let viol = rej
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("X-Policy-Violation"));
    assert_eq!(viol.expect("X-Policy-Violation header").1, "policy.method_denied");

    let body = std::str::from_utf8(rej.body.as_ref().expect("body present")).expect("utf8 body");
    assert!(
        body.contains("policy.method_denied") && body.contains("only GET is permitted"),
        "default body carries code and reason; got {body:?}",
    );
}

#[test]
fn http_authz_rejection_applies_custom_denywith() {
    use std::collections::HashMap;

    use ppe::praxis_policy_core::error::PluginViolation;

    use super::error::http_authz_rejection;

    let mut details = HashMap::new();
    details.insert("http.status".to_owned(), serde_json::json!(401));
    details.insert("http.body".to_owned(), serde_json::json!("{\"error\":\"nope\"}"));
    details.insert(
        "http.headers".to_owned(),
        serde_json::json!({ "X-Authz-Denied": "method-not-allowed" }),
    );
    let violation = PluginViolation::new("policy.deny", "denied").with_details(details);

    let rej = http_authz_rejection(Some(&violation));
    assert_eq!(rej.status, 401, "custom denyWith status wins");
    let body = std::str::from_utf8(rej.body.as_ref().expect("body present")).expect("utf8 body");
    assert_eq!(body, "{\"error\":\"nope\"}", "custom denyWith body wins");
    let custom = rej
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("X-Authz-Denied"));
    assert_eq!(custom.expect("custom denyWith header").1, "method-not-allowed");
}

#[test]
fn http_authz_rejection_clamps_out_of_range_status() {
    use std::collections::HashMap;

    use ppe::praxis_policy_core::error::PluginViolation;

    use super::error::http_authz_rejection;

    let mut details = HashMap::new();
    details.insert("http.status".to_owned(), serde_json::json!(700));
    let violation = PluginViolation::new("policy.deny", "denied").with_details(details);
    let rej = http_authz_rejection(Some(&violation));
    assert_eq!(rej.status, 403, "an out-of-range denyWith status falls back to 403");
}

#[test]
fn http_authz_rejection_drops_control_char_headers() {
    use std::collections::HashMap;

    use ppe::praxis_policy_core::error::PluginViolation;

    use super::error::http_authz_rejection;

    let mut details = HashMap::new();
    details.insert(
        "http.headers".to_owned(),
        serde_json::json!({
            "X-Safe": "ok",
            "X-Bad": "value\r\nInjected: evil",
        }),
    );
    let violation = PluginViolation::new("policy.deny", "denied").with_details(details);
    let rej = http_authz_rejection(Some(&violation));

    assert!(
        rej.headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("X-Safe") && v == "ok"),
        "a safe denyWith header must attach",
    );
    assert!(
        !rej.headers.iter().any(|(_, v)| v.contains("Injected")),
        "a header value with CR/LF must be dropped, not injected",
    );
}

#[test]
fn http_authz_rejection_falls_back_to_sentinel_when_no_violation() {
    use super::error::http_authz_rejection;

    let rej = http_authz_rejection(None);
    assert_eq!(rej.status, 403);
    let viol = rej
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("X-Policy-Violation"));
    assert_eq!(viol.expect("X-Policy-Violation header").1, "policy.deny");
}

// -----------------------------------------------------------------------------
// fit_to_original_length (request/response body framing)
// -----------------------------------------------------------------------------

#[test]
fn fit_to_original_length_pads_on_shrink() {
    use super::filter::fit_to_original_length;
    let new = bytes::Bytes::from_static(b"abc");
    let out = fit_to_original_length(new, 8, "tools/call", "test");
    assert_eq!(out.len(), 8, "padded length must match original");
    assert_eq!(&out[..3], b"abc");
    assert!(
        out[3..].iter().all(|b| *b == b' '),
        "shrink padding must be ASCII spaces; got {:?}",
        &out[3..],
    );
}

#[test]
fn fit_to_original_length_passes_through_on_equal() {
    use super::filter::fit_to_original_length;
    let new = bytes::Bytes::from_static(b"redacted");
    let out = fit_to_original_length(new.clone(), 8, "tools/call", "test");
    assert_eq!(out, new);
}

#[test]
fn fit_to_original_length_truncates_on_grow() {
    use super::filter::fit_to_original_length;
    let new = bytes::Bytes::from_static(b"a much longer rewritten payload");
    let out = fit_to_original_length(new.clone(), 4, "tools/call", "test");
    assert_eq!(out.len(), 4, "grow path must truncate to the original length");
    assert_eq!(&*out, &new[..4], "truncation keeps the leading bytes");
}

// -----------------------------------------------------------------------------
// cmf.rs — JSON-RPC method → entity coords
// -----------------------------------------------------------------------------

#[test]
fn entity_for_protocol_method_covers_known_methods() {
    use super::common_message_format::entity_for_protocol_method;
    assert!(entity_for_protocol_method("tools/call").is_some());
    assert!(entity_for_protocol_method("prompts/get").is_some());
    assert!(entity_for_protocol_method("resources/read").is_some());
    assert!(entity_for_protocol_method("service/list").is_none());
    assert!(entity_for_protocol_method("initialize").is_none());
    assert!(entity_for_protocol_method("unknown/method").is_none());
}

#[test]
fn entity_for_protocol_method_post_covers_known_methods() {
    use super::common_message_format::entity_for_protocol_method_post;
    assert!(entity_for_protocol_method_post("tools/call").is_some());
    assert!(entity_for_protocol_method_post("prompts/get").is_some());
    assert!(entity_for_protocol_method_post("resources/read").is_some());
    assert!(entity_for_protocol_method_post("service/list").is_none());
    assert!(entity_for_protocol_method_post("initialize").is_none());
}

// -----------------------------------------------------------------------------
// json_rpc.rs — id extraction + content builders + re-serializers
// -----------------------------------------------------------------------------

#[test]
fn json_rpc_id_handles_string_numeric_and_malformed() {
    use super::json_rpc::ParsedEnvelope;
    let str_id = bytes::Bytes::from_static(br#"{"jsonrpc":"2.0","id":"req-1","method":"x"}"#);
    let num_id = bytes::Bytes::from_static(br#"{"jsonrpc":"2.0","id":42,"method":"x"}"#);
    let no_id = bytes::Bytes::from_static(br#"{"jsonrpc":"2.0","method":"x"}"#);
    let bad = bytes::Bytes::from_static(b"not json");
    assert_eq!(ParsedEnvelope::parse(&str_id).id_string(), "req-1");
    assert_eq!(ParsedEnvelope::parse(&num_id).id_string(), "42");
    assert_eq!(ParsedEnvelope::parse(&no_id).id_string(), "");
    assert_eq!(ParsedEnvelope::parse(&bad).id_string(), "");
}

#[test]
fn json_rpc_id_value_preserves_json_type() {
    use super::json_rpc::ParsedEnvelope;
    let str_id = bytes::Bytes::from_static(br#"{"id":"req-1"}"#);
    let num_id = bytes::Bytes::from_static(br#"{"id":42}"#);
    let bad = bytes::Bytes::from_static(b"{");
    assert_eq!(ParsedEnvelope::parse(&str_id).id_value(), serde_json::json!("req-1"));
    assert_eq!(ParsedEnvelope::parse(&num_id).id_value(), serde_json::json!(42));
    assert_eq!(ParsedEnvelope::parse(&bad).id_value(), serde_json::Value::Null);
}

#[test]
fn build_content_for_method_tools_call() {
    use ppe::praxis_policy_core::cmf::ContentPart;

    use super::json_rpc::build_content_for_method;

    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call",
             "params":{"name":"echo","arguments":{"text":"hi","n":7}}}"#,
    );
    let parts = build_content_for_method(
        "tools/call",
        "echo",
        "corr-1",
        &super::json_rpc::ParsedEnvelope::parse(&body),
    );
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

#[test]
fn build_content_for_method_resources_read() {
    use ppe::praxis_policy_core::cmf::ContentPart;

    use super::json_rpc::build_content_for_method;

    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"resources/read",
             "params":{"uri":"file:///etc/example"}}"#,
    );
    let parts = build_content_for_method(
        "resources/read",
        "file:///etc/example",
        "corr-1",
        &super::json_rpc::ParsedEnvelope::parse(&body),
    );
    assert_eq!(parts.len(), 1);
    match &parts[0] {
        ContentPart::ResourceRef { content } => {
            assert_eq!(content.uri, "file:///etc/example");
            assert_eq!(content.resource_request_id, "corr-1");
        },
        other => panic!("expected ResourceRef; got {other:?}"),
    }
}

#[test]
fn build_content_for_method_unknown_method_yields_empty() {
    use super::json_rpc::build_content_for_method;
    let body = bytes::Bytes::from_static(br#"{"method":"tools/list"}"#);
    let parts = build_content_for_method(
        "tools/list",
        "n/a",
        "corr-1",
        &super::json_rpc::ParsedEnvelope::parse(&body),
    );
    assert!(parts.is_empty());
}

#[test]
fn reserialize_tools_call_round_trips_with_mutated_args() {
    use ppe::praxis_policy_core::cmf::{ContentPart, Message, Role, ToolCall};

    use super::json_rpc::reserialize_json_rpc_body;

    let original = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call",
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
    let new_bytes = reserialize_json_rpc_body(parse_dom(&original), "tools/call", &message).expect("rewrite Some");
    let parsed: serde_json::Value = serde_json::from_slice(&new_bytes).expect("valid JSON");
    assert_eq!(parsed["jsonrpc"], "2.0");
    assert_eq!(parsed["id"], 1);
    assert_eq!(parsed["method"], "tools/call");
    assert_eq!(parsed["params"]["name"], "echo");
    assert_eq!(parsed["params"]["arguments"]["a"], "[REDACTED]");
}

#[test]
fn build_response_content_for_method_text_fallback() {
    use ppe::praxis_policy_core::cmf::ContentPart;

    use super::json_rpc::build_response_content_for_method;

    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"result":{
             "content":[{"type":"text","text":"{\"k\":\"v\"}"}],
             "isError":false}}"#,
    );
    let parts = build_response_content_for_method(
        "tools/call",
        "echo",
        "corr-1",
        &super::json_rpc::ParsedEnvelope::parse(&body),
    );
    assert_eq!(parts.len(), 1);
    match &parts[0] {
        ContentPart::ToolResult { content } => {
            assert!(!content.is_error);
            assert_eq!(content.content, serde_json::json!({"k":"v"}));
        },
        other => panic!("expected ToolResult; got {other:?}"),
    }
}

#[test]
fn build_response_content_for_method_prefers_structured_content() {
    use ppe::praxis_policy_core::cmf::ContentPart;

    use super::json_rpc::build_response_content_for_method;

    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"result":{
             "content":[{"type":"text","text":"ignored"}],
             "structuredContent":{"hi":"there"},
             "isError":true}}"#,
    );
    let parts = build_response_content_for_method(
        "tools/call",
        "echo",
        "corr-1",
        &super::json_rpc::ParsedEnvelope::parse(&body),
    );
    assert_eq!(parts.len(), 1);
    match &parts[0] {
        ContentPart::ToolResult { content } => {
            assert!(content.is_error);
            assert_eq!(content.content, serde_json::json!({"hi":"there"}));
        },
        other => panic!("expected ToolResult; got {other:?}"),
    }
}

#[test]
fn build_response_content_for_method_folds_all_text_blocks() {
    use ppe::praxis_policy_core::cmf::ContentPart;

    use super::json_rpc::build_response_content_for_method;

    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"result":{
             "content":[
               {"type":"text","text":"first secret"},
               {"type":"text","text":"second secret"}
             ],
             "isError":false}}"#,
    );
    let parts = build_response_content_for_method(
        "tools/call",
        "echo",
        "corr-1",
        &super::json_rpc::ParsedEnvelope::parse(&body),
    );
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

#[test]
fn reserialize_response_collapses_to_single_vetted_block() {
    use ppe::praxis_policy_core::cmf::{ContentPart, Message, Role, ToolResult};

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
    let out = reserialize_json_rpc_response_body(parse_dom(&original), "tools/call", &message).expect("Some");
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

#[test]
fn deny_envelope_fits_committed_length() {
    use ppe::praxis_policy_core::error::PluginViolation;

    use super::{error::json_rpc_error_envelope_bytes, filter::fit_to_original_length};

    let violation = PluginViolation::new("gateway.response_rewrite_overflow", "too large to fit");
    let envelope = json_rpc_error_envelope_bytes(Some(&violation), &serde_json::json!(1));
    let original_len = envelope.len() + 64;
    let fitted = fit_to_original_length(envelope, original_len, "tools/call", "overflow");
    assert_eq!(
        fitted.len(),
        original_len,
        "deny envelope must be padded to exactly the committed length",
    );
}

// -----------------------------------------------------------------------------
// on_request_body — CMF dispatch path (identity-only policy, no routes)
// -----------------------------------------------------------------------------

/// `on_request_body` for an identity-only policy (no entity routes): even
/// with `mcp.method` / `mcp.name` present, there are no entity
/// routes to authorize, so the body phase short-circuits to `BodyDone`.
/// (Actual per-entity CMF dispatch is covered by the routed-policy tests.)
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
    ctx.set_metadata("mcp.method", "tools/call");
    ctx.set_metadata("mcp.name", "echo");

    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call",
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

/// A single entity-route rule can combine `http.*` with entity/identity
/// attributes: the `echo` tool is gated by `http.method == "POST" &&
/// subject.id == "alice"`. Proves the body-phase evaluation is enriched with
/// the HTTP request line (via the engine's `read_headers` grant to entity routes),
/// so the same policy sees both dimensions. `alice` over POST passes; the
/// same caller over GET is denied by the `http.method` half of the predicate.
#[tokio::test(flavor = "multi_thread")]
async fn entity_route_rule_sees_http_attributes() {
    let (_dir, path) = write_http_entity_config();
    let filter = build_filter(path);

    let allow = dispatch_echo_method(&filter, "alice", Method::POST).await;
    assert!(
        matches!(allow, FilterAction::BodyDone),
        "POST + alice satisfies the combined http+identity predicate; got {allow:?}",
    );

    let deny = dispatch_echo_method(&filter, "alice", Method::GET).await;
    assert!(
        matches!(deny, FilterAction::Reject(_)),
        "GET must be denied by the http.method half of the rule (proves http.* is present \
         at the body phase); got {deny:?}",
    );
}

#[test]
fn derives_l7_shape_for_global_only_policy() {
    let (_dir, path) = write_l7_global_config();
    let filter = build_filter(path);
    assert_eq!(
        filter.derived_shape(),
        (true, false),
        "global-only policy should derive (http_global, !entity_routes)",
    );
}

#[test]
fn derives_entity_shape_for_routed_policy() {
    let (_dir, path) = write_cel_policy_config();
    let filter = build_filter(path);
    assert_eq!(
        filter.derived_shape(),
        (false, true),
        "a routes-only policy derives (!http_global, entity_routes)",
    );
}

#[tokio::test]
async fn combined_shape_on_request_uses_identity_gate_not_http_authz() {
    let (_dir, path) = write_combined_global_and_routes_config();
    let filter = build_filter(path);
    assert_eq!(
        filter.derived_shape(),
        (true, true),
        "a global + routes policy derives the combined shape",
    );

    let token = mint_jwt(&standard_claims("alice"));
    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.expect("on_request ran");
    assert!(
        matches!(action, FilterAction::Continue),
        "combined shape must pass on_request via the identity gate (not L7 http-authz, \
         which would 403 this POST under the GET-only global policy); got {action:?}",
    );
}

/// Session tainting end-to-end through the filter: reading the secret
/// taints the session (`taint(secret, session)`), and a later call in
/// the SAME session is denied (`security.labels contains "secret"`). A
/// DIFFERENT session id is unaffected — taint is session-scoped. Proves
/// the `X-Session-Id` → `agent.session_id` wiring + the engine session
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

/// A non-entity policy behind a `StreamBuffer` downstream must reject
/// unauthenticated traffic on its FIRST body chunk — before the downstream body
/// consumer ever executes. Proves the pre-read admission path rejects (not just
/// accepts) when credentials are absent, closing the window where a body
/// consumer could run before authentication.
#[tokio::test(flavor = "multi_thread")]
async fn pre_read_rejects_unauthenticated_before_downstream_body_consumer() {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let (_dir, path) = write_single_plugin_config();
    let pipeline = build_policy_observer_pipeline(&path, &observed);

    let req = make_request(Method::POST, "/");
    let mut ctx = make_filter_context(&req);
    let mut partial_body = Some(bytes::Bytes::from_static(b"{"));
    let action = pipeline
        .execute_http_request_body(&mut ctx, &mut partial_body, false)
        .await
        .expect("pre-read body pipeline ran");
    assert!(
        matches!(&action, FilterAction::Reject(rej) if rej.status == 401),
        "unauthenticated pre-read must reject 401 before downstream observer runs; got {action:?}",
    );
    assert!(
        observed.lock().expect("observer lock").is_empty(),
        "downstream body consumer must NOT execute when policy rejects",
    );
}

/// Entity-routed policy waits for the full body so the upstream protocol
/// classifier has finished parsing and writing route metadata. Non-entity
/// policies intentionally authenticate on the first chunk instead.
#[tokio::test(flavor = "multi_thread")]
async fn entity_on_request_body_continues_on_partial_chunks() {
    let (_dir, path) = write_tool_route_config();
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

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "linear setup + assertions for the fail-closed response path"
)]
async fn response_phase_without_request_identity_fails_closed() {
    let (_dir, path) = write_tool_route_config();
    let cfg = PolicyFilterConfig {
        config_path: path,
        allow_private_idp: false,
        body_access: super::config::BodyAccessMode::ReadWrite,
        require_protocol_metadata: true,
        init_timeout_secs: 30,
        max_buffer_bytes: 10_485_760,
        llm: super::config::LlmOptions::default(),
    };
    let filter = PolicyFilter::new(cfg).expect("filter should construct");

    let req = make_request(Method::POST, "/");
    let mut ctx = make_filter_context(&req);
    ctx.set_metadata("mcp.method", "tools/call");
    ctx.set_metadata("mcp.name", "echo");

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

#[test]
#[expect(clippy::too_many_lines, reason = "test fixture construction")]
fn attach_delegated_tokens_first_writer_wins_per_outbound_header() {
    use std::sync::Arc;

    use chrono::{Duration, Utc};
    use ppe::praxis_policy_core::extensions::{
        container::Extensions,
        raw_credentials::{DelegationKey, DelegationMode, RawCredentialsExtension, RawDelegatedToken},
    };

    use super::filter::attach_delegated_tokens;

    let expires = Utc::now() + Duration::hours(1);
    let tok_a = RawDelegatedToken::new("token-a", "Authorization", "aud-a", Vec::<String>::new(), expires);
    let tok_b = RawDelegatedToken::new("token-b", "Authorization", "aud-b", Vec::<String>::new(), expires);
    let key_a = DelegationKey::new(DelegationMode::OnBehalfOfUser, "aud-a", Vec::new()).with_subject_id("alice");
    let key_b = DelegationKey::new(DelegationMode::OnBehalfOfUser, "aud-b", Vec::new()).with_subject_id("alice");
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

#[test]
fn attach_delegated_tokens_distinct_outbound_headers_all_attach() {
    use std::sync::Arc;

    use chrono::{Duration, Utc};
    use ppe::praxis_policy_core::extensions::{
        container::Extensions,
        raw_credentials::{DelegationKey, DelegationMode, RawCredentialsExtension, RawDelegatedToken},
    };

    use super::filter::attach_delegated_tokens;

    let expires = Utc::now() + Duration::hours(1);
    let tok_auth = RawDelegatedToken::new("token-auth", "Authorization", "aud-auth", Vec::<String>::new(), expires);
    let tok_x = RawDelegatedToken::new("token-x", "X-Upstream-Token", "aud-x", Vec::<String>::new(), expires);
    let key_auth = DelegationKey::new(DelegationMode::OnBehalfOfUser, "aud-auth", Vec::new()).with_subject_id("alice");
    let key_x = DelegationKey::new(DelegationMode::OnBehalfOfUser, "aud-x", Vec::new()).with_subject_id("alice");
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

// -----------------------------------------------------------------------------
// spawn_blocking offload
// -----------------------------------------------------------------------------

/// Concurrent CMF dispatches must not block the async runtime. With the
/// evaluation offloaded to `spawn_blocking`, multiple requests can
/// proceed in parallel without starving the worker threads. This test
/// fires four concurrent policy evaluations on a two-thread runtime;
/// all must complete without deadlocking or failing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_cmf_dispatch_completes_without_blocking() {
    use std::sync::Arc;

    let (_dir, path) = write_cel_policy_config();
    let filter = Arc::new(build_filter(path));

    let mut handles = Vec::new();
    for _ in 0..4 {
        let f = Arc::clone(&filter);
        handles.push(tokio::spawn(async move { dispatch_echo_as(&f, "alice").await }));
    }

    for h in handles {
        let action = h.await.expect("task should not panic");
        assert!(
            matches!(action, FilterAction::BodyDone),
            "alice satisfies the CEL predicate; expected BodyDone, got {action:?}",
        );
    }
}

// -----------------------------------------------------------------------------
// Host-supplied plugin factories
// -----------------------------------------------------------------------------

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use ppe::prelude::{
    AnyHookHandler, CmfHook, Extensions, HookHandler, MessagePayload, Plugin, PluginConfig, PluginContext, PluginError,
    PluginFactory, PluginInstance, PluginResult, TypedHandlerAdapter,
};

use super::register_policy_plugin_factory;

/// A plugin that does nothing, to stand in for one a host would supply.
struct StubPlugin {
    cfg: PluginConfig,
}

impl Plugin for StubPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for StubPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::allow()
    }
}

/// Counts how many times it built a plugin, so a test can tell one construction
/// from two. Deliberately accepts any config, including one a bundled factory
/// would reject — that difference is what the override test keys on.
struct StubFactory {
    builds: Arc<AtomicUsize>,
}

impl PluginFactory for StubFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        self.builds.fetch_add(1, Ordering::SeqCst);
        let plugin = Arc::new(StubPlugin { cfg: config.clone() });
        let adapter: Arc<dyn AnyHookHandler> = Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&plugin)));
        Ok(PluginInstance {
            plugin,
            handlers: vec![("cmf.tool_pre_invoke", adapter)],
        })
    }
}

/// Register a stub under `kind` and hand back its build counter.
fn register_stub(kind: &'static str) -> Arc<AtomicUsize> {
    let builds = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&builds);
    register_policy_plugin_factory(
        kind,
        Arc::new(move || {
            Box::new(StubFactory {
                builds: Arc::clone(&counter),
            })
        }),
    );
    builds
}

/// A policy document whose only plugin is of `kind`, with no `config:` block.
/// Every bundled plugin requires one, so a bundled factory rejects this and the
/// permissive stub accepts it.
fn write_config_naming_kind(kind: &str) -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        "plugins:\n  - name: host-plugin\n    kind: {kind}\n    hooks:\n      - cmf.tool_pre_invoke\n    mode: sequential\n    on_error: fail\n\
         routes:\n  - tool: echo\n    authorization:\n      pre_invocation:\n        - \"run(host-plugin)\"\n"
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let path_str = cfg_path.to_str().expect("utf8 path").to_owned();
    (dir, path_str)
}

/// Parse a test body into the DOM the reserializers consume.
fn parse_dom(bytes: &bytes::Bytes) -> serde_json::Value {
    serde_json::from_slice(bytes).expect("valid envelope")
}

fn try_build_filter(config_path: String) -> Result<PolicyFilter, crate::FilterError> {
    try_build_filter_allowing_private(config_path, false)
}

/// Build a filter with the configured private-destination policy.
///
/// Registers a shared connector first, so the transport these filters
/// install takes the same path a server does instead of falling back to a
/// private pool. Any registered connector will do here — the point is that
/// one is registered at all — but the registration is a process-wide
/// last-wins slot, so this holds the lock across the construction that reads
/// it back rather than overwriting what a concurrent test is asserting on.
fn try_build_filter_allowing_private(
    config_path: String,
    allow_private_idp: bool,
) -> Result<PolicyFilter, crate::FilterError> {
    let _guard = crate::policy_connector::REGISTRATION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    crate::set_policy_subrequest_connector(&praxis_core::subrequest::SubRequestConnector::new(
        praxis_core::config::DEFAULT_SUBREQUEST_POOL_SIZE,
        None,
    ));
    PolicyFilter::new(PolicyFilterConfig {
        config_path,
        allow_private_idp,
        body_access: super::config::BodyAccessMode::ReadOnly,
        require_protocol_metadata: true,
        init_timeout_secs: 30,
        max_buffer_bytes: 10_485_760,
        llm: super::config::LlmOptions::default(),
    })
}

#[test]
fn a_kind_with_no_registration_fails_the_load() {
    let (_dir, path) = write_config_naming_kind("test/never-registered");
    let err = try_build_filter(path).err().expect("must not construct");
    let msg = err.to_string();
    assert!(
        msg.contains("no factory registered"),
        "expected the engine's unresolved-kind error, got: {msg}"
    );
    assert!(
        msg.contains("test/never-registered"),
        "the message must name the kind so an operator knows what to register: {msg}"
    );
}

#[test]
fn a_host_registered_kind_loads_and_its_factory_is_used() {
    let builds = register_stub("test/host-supplied");
    let (_dir, path) = write_config_naming_kind("test/host-supplied");
    try_build_filter(path).expect("a registered kind must construct");
    assert_eq!(
        builds.load(Ordering::SeqCst),
        1,
        "the host's factory must be the one that built the plugin"
    );
}

#[test]
fn one_registration_serves_repeated_filter_construction() {
    let builds = register_stub("test/reload-survivor");

    let (_dir_a, path_a) = write_config_naming_kind("test/reload-survivor");
    try_build_filter(path_a).expect("first construction must succeed");

    let (_dir_b, path_b) = write_config_naming_kind("test/reload-survivor");
    try_build_filter(path_b).expect("a reload must construct too, from the same registration");

    assert_eq!(
        builds.load(Ordering::SeqCst),
        2,
        "each construction must build its own plugin from the surviving registration"
    );
}

#[test]
fn a_factory_may_register_another_kind_while_factories_are_built() {
    register_policy_plugin_factory(
        "test/registers-a-sibling",
        Arc::new(|| {
            register_stub("test/registered-from-inside-a-factory");
            Box::new(StubFactory {
                builds: Arc::new(AtomicUsize::new(0)),
            })
        }),
    );

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let kinds: Vec<String> = super::host_plugins::host_plugin_factories()
            .into_iter()
            .map(|(kind, _)| kind)
            .collect();
        drop(tx.send(kinds));
    });
    let kinds = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("building factories must not deadlock on the registry lock");
    assert!(
        kinds.iter().any(|kind| kind == "test/registers-a-sibling"),
        "the registering factory itself must be built: {kinds:?}"
    );
}

#[test]
fn a_host_registration_replaces_a_bundled_kind() {
    let builds = register_stub("delegator/oauth");
    let (_dir, path) = write_config_naming_kind("delegator/oauth");
    try_build_filter(path).expect("the stub accepts a config the bundled delegator would reject, so it must win");
    assert_eq!(
        builds.load(Ordering::SeqCst),
        1,
        "the host's factory must have replaced the bundled one"
    );
}

/// Signing secret for the route-scoped identity fixture.
const ROUTE_SECRET: &str = "praxis-cpex-route-secret-not-for-production-use";
/// Issuer for the route-scoped identity fixture.
const ROUTE_ISSUER: &str = "https://route-idp.test.local";

/// Mint an HS256 JWT signed with [`ROUTE_SECRET`], for [`ROUTE_ISSUER`].
fn mint_route_jwt(subject: &str) -> String {
    let claims = json!({
        "iss": ROUTE_ISSUER,
        "aud": TEST_AUDIENCE,
        "sub": subject,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    });
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(ROUTE_SECRET.as_bytes()),
    )
    .expect("sign route JWT")
}

/// Return identity plugins that trust distinct global and route issuers.
#[expect(clippy::too_many_lines, reason = "test fixture: the YAML literal is the bulk")]
fn two_issuer_plugins() -> String {
    format!(
        r#"plugins:
  - name: global-jwt
    kind: identity/jwt
    hooks:
      - identity.resolve
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
  - name: route-jwt
    kind: identity/jwt
    hooks:
      - identity.resolve
    on_error: fail
    config:
      header: Authorization
      trusted_issuers:
        - issuer: "{ROUTE_ISSUER}"
          audiences: ["{TEST_AUDIENCE}"]
          algorithms: ["HS256"]
          decoding_key:
            kind: secret
            secret: "{ROUTE_SECRET}"
          leeway_seconds: 60
      claim_mapper: standard
"#
    )
}

/// Write an L7 policy with route-scoped authentication.
fn write_http_route_authentication_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"{plugins}
global:
  authentication:
    - global-jwt
  authorization:
    pre_invocation:
      - "require(authenticated)"
routes:
  - http:
      path_prefix: /v1/files
    authentication:
      replace_inherited: true
      steps:
        - route-jwt
    authorization:
      pre_invocation:
        - "require(authenticated)"
"#,
        plugins = two_issuer_plugins()
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().expect("utf8 path").to_owned())
}

/// Run L7 policy for a path and bearer token.
async fn l7_action(filter: &PolicyFilter, path: &str, token: &str) -> FilterAction {
    let mut req = make_request(Method::GET, path);
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);
    filter.on_request(&mut ctx).await.expect("header phase ran")
}

#[tokio::test(flavor = "multi_thread")]
async fn an_http_route_authentication_list_governs_its_own_path() {
    let (_dir, path) = write_http_route_authentication_config();
    let filter = build_filter(path);
    assert_eq!(
        filter.derived_shape(),
        (true, false),
        "the fixture is the pure-L7 shape, which authorizes at the header phase",
    );

    let route_token = mint_route_jwt("alice");
    let global_token = mint_jwt(&standard_claims("alice"));

    let covered = l7_action(&filter, "/v1/files/q3.pdf", &route_token).await;
    assert!(
        matches!(covered, FilterAction::Continue),
        "only the route's own list trusts this issuer, so admitting the request \
         is what witnesses that the list ran; got {covered:?}",
    );

    let uncovered = l7_action(&filter, "/elsewhere", &route_token).await;
    assert!(
        matches!(uncovered, FilterAction::Reject(_)),
        "no route covers this path, so the global list runs and does not trust \
         the route issuer; got {uncovered:?}",
    );

    let replaced = l7_action(&filter, "/v1/files/q3.pdf", &global_token).await;
    assert!(
        matches!(replaced, FilterAction::Reject(_)),
        "`replace_inherited: true` drops the global list, so a token only that \
         list trusts must not authenticate on the route; got {replaced:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
#[expect(clippy::too_many_lines, reason = "test fixture: the YAML literal is the bulk")]
async fn the_early_identity_gate_honors_an_http_route_authentication_list() {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"{plugins}
global:
  authentication:
    - global-jwt
routes:
  - tool: echo
    authorization:
      pre_invocation:
        - "require(authenticated)"
  - http:
      path_prefix: /mcp
    authentication:
      replace_inherited: true
      steps:
        - route-jwt
"#,
        plugins = two_issuer_plugins()
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let filter = build_filter(cfg_path.to_str().expect("utf8 path").to_owned());
    assert_eq!(
        filter.derived_shape(),
        (false, true),
        "the fixture is entity-routed, which takes the early-gate path",
    );

    let mut req = make_request(Method::POST, "/mcp/rpc");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {}", mint_route_jwt("alice"))).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.expect("header phase ran");
    assert!(
        matches!(action, FilterAction::Continue),
        "the gate must dispatch the route's list for a path it covers; got {action:?}",
    );
}

/// Write an assertion fixture with caller-selected header casing.
#[expect(clippy::too_many_lines, reason = "test fixture: the YAML literal is the bulk")]
fn write_assertions_config_named(asserted: &str) -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
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
  authentication:
    - jwt-user
  assertions:
    request:
      headers:
        - name: {asserted}
          from: subject.id
      strip:
        - x-drop-me
routes:
  - tool: echo
    authorization:
      pre_invocation:
        - "require(authenticated)"
"#
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().expect("utf8 path").to_owned())
}

/// Request header mutations queued by the policy filter.
struct Queued {
    set: std::collections::HashMap<String, String>,
    removed: Vec<String>,
    extra: Vec<(String, String)>,
}

/// Run the `echo` policy and collect upstream header mutations.
#[expect(clippy::too_many_lines, reason = "one linear dispatch plus three queue projections")]
async fn queued_for_echo(filter: &PolicyFilter, ctx: &mut crate::HttpFilterContext<'_>) -> Queued {
    ctx.set_metadata("mcp.method", "tools/call");
    ctx.set_metadata("mcp.name", "echo");
    let mut body = Some(bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#,
    ));
    let action = filter
        .on_request_body(ctx, &mut body, true)
        .await
        .expect("body phase ran");
    assert!(
        matches!(action, FilterAction::BodyDone),
        "the route allows, so the body phase signals BodyDone; got {action:?}"
    );
    Queued {
        set: ctx
            .request_headers_to_set
            .iter()
            .map(|(n, v)| (n.as_str().to_owned(), v.to_str().unwrap_or_default().to_owned()))
            .collect(),
        removed: ctx
            .request_headers_to_remove
            .iter()
            .map(|n| n.as_str().to_owned())
            .collect(),
        extra: ctx
            .extra_request_headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.clone()))
            .collect(),
    }
}

/// Build a request authenticated as `alice`.
fn request_for_alice() -> crate::Request {
    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {}", mint_jwt(&standard_claims("alice")))).expect("header value"),
    );
    req
}

#[tokio::test(flavor = "multi_thread")]
async fn a_duplicated_asserted_header_is_replaced_not_diffed() {
    let (_dir, path) = write_assertions_config_named("x-auth-user-id");
    let filter = build_filter(path);

    let mut req = request_for_alice();
    req.headers.append("x-auth-user-id", HeaderValue::from_static("root"));
    req.headers.append("x-auth-user-id", HeaderValue::from_static("alice"));
    let mut ctx = make_filter_context(&req);
    let queued = queued_for_echo(&filter, &mut ctx).await;

    assert_eq!(
        queued.set.get("x-auth-user-id").map(String::as_str),
        Some("alice"),
        "the asserted name must be set unconditionally, so the duplicate the \
         client sent cannot survive beside it; got {:?}",
        queued.set,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mixed_case_assertion_is_not_read_as_a_removal() {
    let (_dir, path) = write_assertions_config_named("X-Auth-User-Id");
    let filter = build_filter(path);

    let mut req = request_for_alice();
    req.headers.insert("x-auth-user-id", HeaderValue::from_static("alice"));
    let mut ctx = make_filter_context(&req);
    let queued = queued_for_echo(&filter, &mut ctx).await;

    assert_eq!(
        queued.set.get("x-auth-user-id").map(String::as_str),
        Some("alice"),
        "the entry asserts this name, so it is set whatever the request carried; got {:?}",
        queued.set,
    );
    assert!(
        !queued.removed.contains(&"x-auth-user-id".to_owned()),
        "and it is not also removed: an asserted name reaching the upstream absent \
         is the upstream losing the identity it authorizes on; got {:?}",
        queued.removed,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_promoted_header_cannot_append_to_an_asserted_name() {
    let (_dir, path) = write_assertions_config_named("x-auth-user-id");
    let filter = build_filter(path);

    let req = request_for_alice();
    let mut ctx = make_filter_context(&req);
    ctx.extra_request_headers
        .push((std::borrow::Cow::Borrowed("X-Auth-User-Id"), "root".to_owned()));
    let queued = queued_for_echo(&filter, &mut ctx).await;

    assert!(
        queued.extra.is_empty(),
        "a promotion under an asserted name is dropped, since it would otherwise \
         be applied last; got {:?}",
        queued.extra,
    );
    assert_eq!(
        queued.set.get("x-auth-user-id").map(String::as_str),
        Some("alice"),
        "and the contract's own value is what reaches the upstream; got {:?}",
        queued.set,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pending_set_cannot_survive_a_strip() {
    let (_dir, path) = write_assertions_config_named("x-auth-user-id");
    let filter = build_filter(path);

    let req = request_for_alice();
    let mut ctx = make_filter_context(&req);
    ctx.request_headers_to_set.push((
        "x-drop-me".parse().expect("header name"),
        HeaderValue::from_static("sneaky"),
    ));
    let queued = queued_for_echo(&filter, &mut ctx).await;

    assert!(
        !queued.set.contains_key("x-drop-me"),
        "a `strip:` is the last word on the name, so the queued set is dropped; got {:?}",
        queued.set,
    );
    assert!(
        queued.removed.contains(&"x-drop-me".to_owned()),
        "and the removal is queued even though the request never carried the \
         header itself; got {:?}",
        queued.removed,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_name_no_level_governs_keeps_its_pending_mutations() {
    let (_dir, path) = write_assertions_config_named("x-auth-user-id");
    let filter = build_filter(path);

    let req = request_for_alice();
    let mut ctx = make_filter_context(&req);
    ctx.request_headers_to_set.push((
        "x-upstream-authorization".parse().expect("header name"),
        HeaderValue::from_static("Bearer minted"),
    ));
    ctx.extra_request_headers
        .push((std::borrow::Cow::Borrowed("x-forwarded-for"), "203.0.113.7".to_owned()));
    let queued = queued_for_echo(&filter, &mut ctx).await;

    assert_eq!(
        queued.set.get("x-upstream-authorization").map(String::as_str),
        Some("Bearer minted"),
        "nothing asserts or strips this name, so the contract has no claim on it; got {:?}",
        queued.set,
    );
    assert_eq!(
        queued.extra,
        vec![("x-forwarded-for".to_owned(), "203.0.113.7".to_owned())],
        "and a promotion under an ungoverned name still reaches the upstream",
    );
}

/// Write an L7 policy with response assertions.
#[expect(clippy::too_many_lines, reason = "test fixture: the YAML literal is the bulk")]
fn write_response_assertions_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
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
  authentication:
    - jwt-user
  authorization:
    pre_invocation:
      - "require(authenticated)"
  assertions:
    response:
      headers:
        - name: x-decided-for
          from: subject.id
      strip:
        - server
"#
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().expect("utf8 path").to_owned())
}

#[tokio::test(flavor = "multi_thread")]
#[expect(clippy::too_many_lines, reason = "linear response-contract coverage")]
async fn response_assertions_reach_the_downstream_response() {
    let (_dir, path) = write_response_assertions_config();
    let filter = build_filter(path);

    let req = request_for_alice();
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.expect("header phase ran");
    assert!(
        matches!(action, FilterAction::Continue),
        "the global policy admits an authenticated GET; got {action:?}"
    );

    let mut response = crate::test_utils::make_response();
    response
        .headers
        .insert("content-type", HeaderValue::from_static("application/json"));
    response.headers.insert("server", HeaderValue::from_static("gunicorn"));
    response
        .headers
        .insert("x-decided-for", HeaderValue::from_static("root"));
    ctx.response_header = Some(&mut response);

    let action = filter.on_response(&mut ctx).await.expect("response phase ran");
    assert!(
        matches!(action, FilterAction::Continue),
        "nothing here denies on the way out; got {action:?}"
    );
    assert!(
        ctx.response_headers_modified,
        "the filter edited the response headers and must say so",
    );

    let headers = &response.headers;
    assert_eq!(
        headers.get("x-decided-for").and_then(|v| v.to_str().ok()),
        Some("alice"),
        "the entry renders the resolved subject, replacing what the upstream sent",
    );
    assert!(
        !headers.contains_key("server"),
        "a `strip:` entry removes the name on the response half too",
    );
    assert_eq!(
        headers.get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "and a header no level governs is left exactly as the upstream returned it",
    );
}

#[tokio::test(flavor = "multi_thread")]
#[expect(clippy::too_many_lines, reason = "test fixture: the YAML literal is the bulk")]
async fn an_entity_route_response_contract_is_refused_at_load() {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
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
  authentication:
    - jwt-user
routes:
  - tool: echo
    assertions:
      response:
        strip:
          - server
    authorization:
      pre_invocation:
        - "require(authenticated)"
"#
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let cfg = PolicyFilterConfig {
        config_path: cfg_path.to_str().expect("utf8 path").to_owned(),
        allow_private_idp: false,
        body_access: super::config::BodyAccessMode::ReadOnly,
        require_protocol_metadata: true,
        init_timeout_secs: 30,
        max_buffer_bytes: 10_485_760,
        llm: super::config::LlmOptions::default(),
    };
    let err = PolicyFilter::new(cfg)
        .err()
        .expect("an unappliable response contract must refuse to start");
    let msg = err.to_string();
    assert!(
        msg.contains("tool: echo") && msg.contains("assertions.response"),
        "the error must name the level to move; got {msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_policy_without_a_response_contract_touches_no_response_header() {
    let (_dir, path) = write_tool_route_config();
    let filter = build_filter(path);

    let req = request_for_alice();
    let mut ctx = make_filter_context(&req);
    let mut response = crate::test_utils::make_response();
    response.headers.insert("server", HeaderValue::from_static("gunicorn"));
    ctx.response_header = Some(&mut response);

    drop(filter.on_response(&mut ctx).await.expect("response phase ran"));
    assert!(!ctx.response_headers_modified, "no contract means no edit",);
    assert!(
        response.headers.contains_key("server"),
        "and the upstream's headers reach the client unchanged",
    );
}
#[tokio::test(flavor = "multi_thread")]
async fn the_response_half_is_gated_on_the_policy_declaring_one() {
    let (_dir, path) = write_l7_global_config();
    assert_eq!(
        build_filter(path).response_hook(),
        None,
        "a `pre_invocation`-only global policy has no response half",
    );

    let (_dir, path) = write_tool_route_config();
    assert_eq!(
        build_filter(path).response_hook(),
        None,
        "nor does an entity-routed policy with no response contract",
    );

    let (_dir, path) = write_response_assertions_config();
    assert_eq!(
        build_filter(path).response_hook(),
        Some("http.response"),
        "a declared response contract opens the half; the engine applies a \
         contract at every return site of the hook, registered handler or not",
    );
}

// -----------------------------------------------------------------------------
// Inference (LLM) authorization
// -----------------------------------------------------------------------------

/// Write a policy with named and catch-all inference routes.
#[expect(
    clippy::too_many_lines,
    reason = "test fixture — the YAML literal is the bulk; splitting helpers would obscure the shape under test"
)]
fn write_llm_route_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
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
  authentication:
    - jwt-user
routes:
  - llm: allowed-model
    authorization:
      pre_invocation:
        - "require(authenticated)"
  - llm: "*"
    authorization:
      pre_invocation:
        - "deny('model is not permitted', 'model_not_allowed')"
"#
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().expect("utf8 path").to_owned())
}

/// Write a policy with inference and MCP tool routes.
#[expect(
    clippy::too_many_lines,
    reason = "test fixture — the YAML literal is the bulk; splitting helpers would obscure the shape under test"
)]
fn write_llm_and_tool_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
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
  authentication:
    - jwt-user
routes:
  - tool: echo
    authorization:
      pre_invocation:
        - "require(authenticated)"
      post_invocation:
        - "completion.tokens.total > 100: deny('completion too long', 'completion_too_long')"
  - llm: "*"
    authorization:
      pre_invocation:
        - "deny('model is not permitted', 'model_not_allowed')"
      post_invocation:
        - "completion.tokens.total > 100: deny('completion too long', 'completion_too_long')"
"#
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().expect("utf8 path").to_owned())
}


/// Write a policy with only an inference response hook.
#[expect(
    clippy::too_many_lines,
    reason = "test fixture — the YAML literal is the bulk; splitting helpers would obscure the shape under test"
)]
fn write_llm_post_only_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
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
  authentication:
    - jwt-user
routes:
  - llm: "*"
    authorization:
      post_invocation:
        - "completion.tokens.total > 100: deny('completion too long', 'completion_too_long')"
"#
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().expect("utf8 path").to_owned())
}

/// Write an inference policy with request and response field mutators.
#[expect(
    clippy::too_many_lines,
    reason = "test fixture — the YAML literal is the bulk; splitting helpers would obscure the shape under test"
)]
fn write_llm_mutator_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
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
  authentication:
    - jwt-user
routes:
  - llm: "*"
    authorization:
      pre_invocation:
        - "require(authenticated)"
    args:
      messages: "redact(authenticated)"
    result:
      content: "redact(authenticated)"
"#
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().expect("utf8 path").to_owned())
}

/// Write a policy that denies a configured inference provider.
#[expect(
    clippy::too_many_lines,
    reason = "test fixture — the YAML literal is the bulk; splitting helpers would obscure the shape under test"
)]
fn write_llm_provider_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
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
  authentication:
    - jwt-user
routes:
  - llm: "*"
    authorization:
      pre_invocation:
        - "llm.provider == 'contoso': deny('provider reached the bag', 'provider_seen')"
"#
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().expect("utf8 path").to_owned())
}

/// Write a policy with one named inference route and no catch-all.
#[expect(
    clippy::too_many_lines,
    reason = "test fixture — the YAML literal is the bulk; splitting helpers would obscure the shape under test"
)]
fn write_llm_and_tool_config_without_catch_all() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
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
  authentication:
    - jwt-user
routes:
  - llm: allowed-model
    authorization:
      pre_invocation:
        - "require(authenticated)"
"#
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().expect("utf8 path").to_owned())
}

/// Write a policy that denies large inference responses.
#[expect(
    clippy::too_many_lines,
    reason = "test fixture — the YAML literal is the bulk; splitting helpers would obscure the shape under test"
)]
fn write_llm_post_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");
    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
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
  authentication:
    - jwt-user
routes:
  - llm: "*"
    authorization:
      pre_invocation:
        - "require(authenticated)"
      post_invocation:
        - "completion.tokens.total > 100: deny('completion too long', 'completion_too_long')"
"#
    );
    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    (dir, cfg_path.to_str().expect("utf8 path").to_owned())
}

/// Build a policy filter with custom inference options.
fn build_filter_with_llm(config_path: String, llm: super::config::LlmOptions) -> PolicyFilter {
    PolicyFilter::new(PolicyFilterConfig {
        config_path,
        allow_private_idp: false,
        body_access: super::config::BodyAccessMode::ReadOnly,
        require_protocol_metadata: true,
        init_timeout_secs: 30,
        max_buffer_bytes: 10_485_760,
        llm,
    })
    .expect("filter should construct")
}

/// Whether a rejection contains the requested header.
fn has_header(rejection: &crate::Rejection, name: &str, value: &str) -> bool {
    rejection
        .headers
        .iter()
        .any(|(header, held)| header.eq_ignore_ascii_case(name) && held == value)
}

/// Run an authenticated inference request through the body phase.
async fn dispatch_inference_as(filter: &PolicyFilter, subject: &str, body: &str) -> FilterAction {
    let token = mint_jwt(&standard_claims(subject));
    let mut req = make_request(Method::POST, "/v1/chat/completions");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);
    filter
        .on_request_body(&mut ctx, &mut Some(bytes::Bytes::from(body.to_owned())), true)
        .await
        .expect("filter ran")
}

#[test]
fn derives_the_inference_shape_for_an_llm_only_policy() {
    let (_dir, path) = write_llm_route_config();
    let filter = build_filter(path);
    assert_eq!(
        filter.derived_shape(),
        (false, true),
        "`llm:` routes are entity routes: authorization belongs at the body phase",
    );
    assert_eq!(
        filter.derived_llm_shape(),
        (true, false),
        "a pre-invocation-only inference policy declares no response half",
    );
}

#[test]
fn derives_the_inference_response_half_when_the_policy_declares_one() {
    let (_dir, path) = write_llm_post_config();
    assert_eq!(build_filter(path).derived_llm_shape(), (true, true));
}

#[tokio::test(flavor = "multi_thread")]
async fn inference_request_is_authorized_without_classifier_metadata() {
    let (_dir, path) = write_llm_route_config();
    let filter = build_filter(path);

    let action = dispatch_inference_as(&filter, "alice", r#"{"model":"allowed-model","messages":[]}"#).await;
    assert!(
        matches!(action, FilterAction::BodyDone),
        "the per-model route must admit an authenticated caller with no classifier in the chain; got {action:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_model_outside_the_policy_is_denied_with_a_provider_error() {
    let (_dir, path) = write_llm_route_config();
    let filter = build_filter(path);

    let action = dispatch_inference_as(&filter, "alice", r#"{"model":"other-model","messages":[]}"#).await;
    let FilterAction::Reject(rejection) = action else {
        panic!("a model the policy excludes must be denied; got {action:?}");
    };
    assert_eq!(rejection.status, 403, "an inference client expects a real HTTP status");
    assert!(
        has_header(&rejection, "content-type", "application/json"),
        "an SDK parses error.message out of the body, so the media type has to be named; got {:?}",
        rejection.headers,
    );
    assert!(
        rejection
            .headers
            .iter()
            .any(|(name, value)| name == "X-Policy-Violation" && value == "model_not_allowed"),
        "the violation code must be on the response for audit pipelines; got {:?}",
        rejection.headers,
    );
    let body: serde_json::Value =
        serde_json::from_slice(&rejection.body.expect("deny body")).expect("deny body is JSON");
    assert_eq!(body["error"]["code"], "model_not_allowed");
    assert_eq!(body["error"]["type"], "policy_violation");
    assert_eq!(
        body["error"]["message"], "model is not permitted",
        "an OpenAI SDK surfaces error.message, so the policy's reason has to land there",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_with_no_usable_model_fails_closed() {
    let (_dir, path) = write_llm_route_config();
    let filter = build_filter(path);

    for body in [r#"{"messages":[]}"#, r#"{"model":42}"#, r#"{"model":""}"#, "not json"] {
        let action = dispatch_inference_as(&filter, "alice", body).await;
        let FilterAction::Reject(rejection) = action else {
            panic!("body {body} must be denied; got {action:?}");
        };
        assert!(
            rejection
                .headers
                .iter()
                .any(|(name, value)| name == "X-Policy-Violation" && value == "llm.model_missing"),
            "body {body} must deny with the missing-model violation; got {:?}",
            rejection.headers,
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_model_no_route_selects_is_denied() {
    let (_dir, path) = write_llm_and_tool_config_without_catch_all();
    let filter = build_filter(path);

    let action = dispatch_inference_as(&filter, "alice", r#"{"model":"unlisted-model","messages":[]}"#).await;
    let FilterAction::Reject(rejection) = action else {
        panic!("a model outside every route must be denied; got {action:?}");
    };
    assert!(
        rejection
            .headers
            .iter()
            .any(|(name, value)| name == "X-Policy-Violation" && value == "llm.no_route"),
        "the deny must say no route covers the model; got {:?}",
        rejection.headers,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn require_route_false_admits_a_model_no_route_selects() {
    let (_dir, path) = write_llm_and_tool_config_without_catch_all();
    let filter = build_filter_with_llm(
        path,
        super::config::LlmOptions {
            require_route: false,
            ..Default::default()
        },
    );

    let action = dispatch_inference_as(&filter, "alice", r#"{"model":"unlisted-model","messages":[]}"#).await;
    assert!(
        matches!(action, FilterAction::BodyDone),
        "with the gate off an unlisted model takes the identity-only path; got {action:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_catch_all_route_satisfies_the_route_requirement() {
    let (_dir, path) = write_llm_route_config();
    let filter = build_filter(path);

    let action = dispatch_inference_as(&filter, "alice", r#"{"model":"other-model","messages":[]}"#).await;
    let FilterAction::Reject(rejection) = action else {
        panic!("the catch-all denies this model by policy; got {action:?}");
    };
    assert!(
        rejection
            .headers
            .iter()
            .any(|(name, value)| name == "X-Policy-Violation" && value == "model_not_allowed"),
        "the catch-all's own rule must decide it, not the route gate; got {:?}",
        rejection.headers,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bodyless_request_is_not_asked_for_a_model() {
    let (_dir, path) = write_llm_route_config();
    let filter = build_filter(path);

    let token = mint_jwt(&standard_claims("alice"));
    for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
        let mut req = make_request(method.clone(), "/v1/models");
        req.headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
        );
        let mut ctx = make_filter_context(&req);
        let action = filter
            .on_request_body(&mut ctx, &mut None, true)
            .await
            .expect("filter ran");
        assert!(
            matches!(action, FilterAction::BodyDone),
            "{method} carries no body, so it must not be denied for carrying no model; got {action:?}",
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bodyless_request_still_needs_a_token() {
    let (_dir, path) = write_llm_route_config();
    let filter = build_filter(path);

    let req = make_request(Method::GET, "/v1/models");
    let mut ctx = make_filter_context(&req);
    let action = filter
        .on_request_body(&mut ctx, &mut None, true)
        .await
        .expect("filter ran");
    assert!(
        matches!(&action, FilterAction::Reject(rejection) if rejection.status == 401),
        "an unauthenticated discovery call is still an identity failure; got {action:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_configured_provider_reaches_the_attribute_bag() {
    let (_dir, path) = write_llm_provider_config();
    let filter = build_filter_with_llm(
        path,
        super::config::LlmOptions {
            provider: Some("contoso".to_owned()),
            ..Default::default()
        },
    );

    let action = dispatch_inference_as(&filter, "alice", r#"{"model":"any-model","messages":[]}"#).await;
    let FilterAction::Reject(rejection) = action else {
        panic!("the provider-keyed rule must fire; got {action:?}");
    };
    assert!(
        has_header(&rejection, "x-policy-violation", "provider_seen"),
        "`llm.provider` must be readable by a rule; got {:?}",
        rejection.headers,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unset_provider_leaves_the_attribute_absent() {
    let (_dir, path) = write_llm_provider_config();
    let filter = build_filter(path);

    let action = dispatch_inference_as(&filter, "alice", r#"{"model":"any-model","messages":[]}"#).await;
    assert!(
        matches!(action, FilterAction::BodyDone),
        "an absent provider must not match the comparison; got {action:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn require_model_false_admits_a_request_with_no_model() {
    let (_dir, path) = write_llm_route_config();
    let filter = build_filter_with_llm(
        path,
        super::config::LlmOptions {
            require_model: false,
            ..Default::default()
        },
    );

    let action = dispatch_inference_as(&filter, "alice", r#"{"messages":[]}"#).await;
    assert!(
        matches!(action, FilterAction::BodyDone),
        "with the gate off, a body carrying no model takes the identity-only path; got {action:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_carrying_both_entity_coordinates_is_denied() {
    let (_dir, path) = write_llm_and_tool_config();
    let filter = build_filter(path);

    let token = mint_jwt(&standard_claims("alice"));
    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);
    ctx.set_metadata("mcp.method", "tools/call");
    ctx.set_metadata("mcp.name", "echo");
    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}},"model":"other-model"}"#,
    );

    let action = filter
        .on_request_body(&mut ctx, &mut Some(body), true)
        .await
        .expect("filter ran");
    let FilterAction::Reject(rejection) = action else {
        panic!("an ambiguous body must be denied; got {action:?}");
    };
    assert!(
        rejection
            .headers
            .iter()
            .any(|(name, value)| name == "X-Policy-Violation" && value == "llm.ambiguous_entity"),
        "the deny must name the ambiguity, not a route decision; got {:?}",
        rejection.headers,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plain_mcp_request_still_takes_the_mcp_path() {
    let (_dir, path) = write_llm_and_tool_config();
    let filter = build_filter(path);

    let token = mint_jwt(&standard_claims("alice"));
    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);
    ctx.set_metadata("mcp.method", "tools/call");
    ctx.set_metadata("mcp.name", "echo");
    let body = bytes::Bytes::from_static(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#,
    );

    let action = filter
        .on_request_body(&mut ctx, &mut Some(body), true)
        .await
        .expect("filter ran");
    assert!(
        matches!(action, FilterAction::BodyDone),
        "the tool route must decide a request with no top-level `model`; got {action:?}",
    );
}

#[test]
fn inference_routes_buffer_the_request_body_in_read_only() {
    let (_dir, path) = write_llm_route_config();
    assert!(
        matches!(
            build_filter(path).request_body_mode(),
            BodyMode::StreamBuffer {
                max_bytes: Some(10_485_760)
            }
        ),
        "an inference policy must ask for the whole body, bounded by llm.max_request_bytes",
    );

    let (_dir, path) = write_tool_route_config();
    assert!(
        matches!(build_filter(path).request_body_mode(), BodyMode::Stream),
        "an MCP policy keeps streaming: the classifier ahead of it already buffers",
    );
}

#[test]
fn the_inference_ceiling_defaults_to_the_json_rpc_one() {
    let cfg = super::config::LlmOptions::default();
    assert_eq!(
        cfg.max_request_bytes, 10_485_760,
        "a deployment that set neither knob must keep the ceiling it had",
    );
}

#[test]
fn the_lower_ceiling_binds_when_both_apply() {
    let (_dir, path) = write_llm_route_config();
    let filter = PolicyFilter::new(PolicyFilterConfig {
        config_path: path,
        allow_private_idp: false,
        body_access: super::config::BodyAccessMode::ReadWrite,
        require_protocol_metadata: true,
        init_timeout_secs: 30,
        max_buffer_bytes: 10_485_760,
        llm: super::config::LlmOptions {
            max_request_bytes: 4096,
            ..Default::default()
        },
    })
    .expect("filter should construct");

    assert!(
        matches!(
            filter.request_body_mode(),
            BodyMode::StreamBuffer { max_bytes: Some(4096) }
        ),
        "the smaller of the two ceilings must win",
    );
}

#[test]
fn rejects_an_out_of_range_inference_ceiling() {
    for (max_request_bytes, expected) in [
        (0, "llm.max_request_bytes must be > 0"),
        (praxis_core::config::ABSOLUTE_MAX_BODY_BYTES + 1, "exceeds the maximum"),
    ] {
        let (_dir, path) = write_llm_route_config();
        let err = PolicyFilter::new(PolicyFilterConfig {
            config_path: path,
            allow_private_idp: false,
            body_access: super::config::BodyAccessMode::ReadOnly,
            require_protocol_metadata: true,
            init_timeout_secs: 30,
            max_buffer_bytes: 10_485_760,
            llm: super::config::LlmOptions {
                max_request_bytes,
                ..Default::default()
            },
        })
        .err()
        .unwrap_or_else(|| panic!("{max_request_bytes} must be rejected"))
        .to_string();
        assert!(err.contains(expected), "got: {err}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_parsed_model_reaches_filter_metadata() {
    let (_dir, path) = write_llm_route_config();
    let filter = build_filter(path);

    let token = mint_jwt(&standard_claims("alice"));
    let mut req = make_request(Method::POST, "/v1/chat/completions");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);
    let body = bytes::Bytes::from_static(br#"{"model":"allowed-model","stream":true,"messages":[]}"#);

    drop(
        filter
            .on_request_body(&mut ctx, &mut Some(body), true)
            .await
            .expect("filter ran"),
    );

    assert_eq!(ctx.get_metadata("llm.model"), Some("allowed-model"));
    assert_eq!(
        ctx.get_metadata("llm.stream"),
        Some("true"),
        "the streaming flag is recorded so the response half can skip an SSE body",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn inference_request_without_a_token_is_rejected_by_identity() {
    let (_dir, path) = write_llm_route_config();
    let filter = build_filter(path);

    let req = make_request(Method::POST, "/v1/chat/completions");
    let mut ctx = make_filter_context(&req);
    let body = bytes::Bytes::from_static(br#"{"model":"allowed-model","messages":[]}"#);

    let action = filter
        .on_request_body(&mut ctx, &mut Some(body), true)
        .await
        .expect("filter ran");
    assert!(
        matches!(&action, FilterAction::Reject(rejection) if rejection.status == 401),
        "an unauthenticated inference call is an identity failure, not a policy deny; got {action:?}",
    );
}

/// Build a read-write inference policy filter.
fn build_read_write_filter(config_path: String) -> PolicyFilter {
    PolicyFilter::new(PolicyFilterConfig {
        config_path,
        allow_private_idp: false,
        body_access: super::config::BodyAccessMode::ReadWrite,
        require_protocol_metadata: true,
        init_timeout_secs: 30,
        max_buffer_bytes: 10_485_760,
        llm: super::config::LlmOptions::default(),
    })
    .expect("filter should construct")
}

/// Run an inference request admitted by the test policy.
async fn admit_inference(filter: &PolicyFilter, ctx: &mut crate::HttpFilterContext<'_>) {
    let mut request = Some(bytes::Bytes::from_static(INFERENCE_REQUEST));
    drop(
        filter
            .on_request_body(ctx, &mut request, true)
            .await
            .expect("request phase ran"),
    );
}

/// Return a chat request containing redactable text.
const MUTATED_REQUEST: &[u8] = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"secret"}]}"#;

/// Return a minimal admitted chat request.
const INFERENCE_REQUEST: &[u8] = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#;

/// Return a completion within the token budget.
const WITHIN_BUDGET_RESPONSE: &str = r#"{"model":"gpt-4o","usage":{"prompt_tokens":5,"completion_tokens":5,"total_tokens":10},"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"hi"}}]}"#;

/// Return a completion over the token budget.
const OVER_BUDGET_RESPONSE: &str = r#"{"model":"gpt-4o","usage":{"prompt_tokens":5000,"completion_tokens":4999,"total_tokens":9999},"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"a long answer"}}]}"#;

/// Return a short completion over the token budget.
const TINY_OVER_BUDGET_RESPONSE: &str = r#"{"usage":{"total_tokens":9999}}"#;

/// Return a non-JSON response body.
const NON_JSON_RESPONSE: &str = "upstream failure, not JSON";

/// Return a JSON-RPC tool result.
const MCP_RESPONSE: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok, with enough room for the round-trip"}]}}"#;

/// Run an inference request and response through the filter.
async fn inference_round_trip(
    filter: &PolicyFilter,
    request_body: &'static str,
    response_body: &'static str,
    content_type: &'static str,
) -> bytes::Bytes {
    let req = request_for_alice();
    let mut ctx = make_filter_context(&req);
    let mut request = Some(bytes::Bytes::from_static(request_body.as_bytes()));
    let action = filter
        .on_request_body(&mut ctx, &mut request, true)
        .await
        .expect("request phase ran");
    assert!(
        matches!(action, FilterAction::BodyDone),
        "the request half must admit before the response half is meaningful; got {action:?}",
    );

    let mut response = crate::test_utils::make_response();
    response
        .headers
        .insert("content-type", HeaderValue::from_static(content_type));
    ctx.response_header = Some(&mut response);

    let mut body = Some(bytes::Bytes::from_static(response_body.as_bytes()));
    drop(
        filter
            .on_response_body(&mut ctx, &mut body, true)
            .expect("response phase ran"),
    );
    body.expect("response body")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deny_too_large_for_the_committed_length_stays_valid_json() {
    let (_dir, path) = write_llm_post_config();
    let filter = build_read_write_filter(path);

    let body = inference_round_trip(
        &filter,
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#,
        TINY_OVER_BUDGET_RESPONSE,
        "application/json",
    )
    .await;

    assert_eq!(
        body.len(),
        TINY_OVER_BUDGET_RESPONSE.len(),
        "the body must still match the Content-Length already on the wire",
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or_else(|e| panic!("a deny body must parse; got {body:?} ({e})"));
    assert!(
        parsed.is_object(),
        "the degraded envelope must still be a JSON object; got {body:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_field_mutator_leaves_an_inference_request_untouched() {
    let (_dir, path) = write_llm_mutator_config();
    let filter = build_read_write_filter(path);

    let req = request_for_alice();
    let mut ctx = make_filter_context(&req);
    let mut request = Some(bytes::Bytes::from_static(MUTATED_REQUEST));
    drop(
        filter
            .on_request_body(&mut ctx, &mut request, true)
            .await
            .expect("request phase ran"),
    );
    assert_eq!(
        request.expect("request body"),
        bytes::Bytes::from_static(MUTATED_REQUEST),
        "the upstream must receive the original body, not a partial redaction",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_field_mutator_leaves_an_inference_response_untouched() {
    let (_dir, path) = write_llm_mutator_config();
    let filter = build_read_write_filter(path);

    let body = inference_round_trip(
        &filter,
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"secret"}]}"#,
        WITHIN_BUDGET_RESPONSE,
        "application/json",
    )
    .await;

    assert_eq!(
        body,
        bytes::Bytes::from_static(WITHIN_BUDGET_RESPONSE.as_bytes()),
        "the client must receive the upstream body, not a partial redaction",
    );
}


#[test]
fn a_post_only_inference_policy_is_active() {
    let (_dir, path) = write_llm_post_only_config();
    let filter = build_read_write_filter(path);
    assert_eq!(
        filter.derived_shape(),
        (false, true),
        "a post-only `llm:` policy declares entity routes, so authorization belongs at the body phase",
    );
    assert_eq!(filter.derived_llm_shape(), (true, true));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_only_inference_policy_denies_an_over_budget_completion() {
    let (_dir, path) = write_llm_post_only_config();
    let filter = build_read_write_filter(path);

    let body = inference_round_trip(
        &filter,
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#,
        OVER_BUDGET_RESPONSE,
        "application/json",
    )
    .await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("deny body is JSON");
    assert_eq!(
        parsed["error"]["code"], "completion_too_long",
        "a post-only policy must reach its response rule; got {body:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unclassified_json_rpc_body_with_a_model_is_denied() {
    let (_dir, path) = write_llm_and_tool_config();
    let filter = build_filter(path);

    let action = dispatch_inference_as(
        &filter,
        "alice",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"},"model":"allowed-model"}"#,
    )
    .await;
    let FilterAction::Reject(rejection) = action else {
        panic!("an unclassified body carrying both coordinates must be denied; got {action:?}");
    };
    assert!(
        has_header(&rejection, "x-policy-violation", "llm.ambiguous_entity"),
        "the deny must name the ambiguity rather than authorizing the model; got {:?}",
        rejection.headers,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unclassified_json_rpc_body_reports_the_classifier() {
    let (_dir, path) = write_llm_and_tool_config();
    let filter = build_filter(path);

    let action = dispatch_inference_as(
        &filter,
        "alice",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}"#,
    )
    .await;
    assert!(
        matches!(&action, FilterAction::Reject(rejection) if rejection.status == 500),
        "a mixed policy must still fail closed on a missing classifier; got {action:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_get_carrying_a_body_is_still_evaluated() {
    let (_dir, path) = write_llm_route_config();
    let filter = build_filter(path);

    let token = mint_jwt(&standard_claims("alice"));
    let mut req = make_request(Method::GET, "/v1/chat/completions");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);
    let mut body = Some(bytes::Bytes::from_static(br#"{"model":"other-model","messages":[]}"#));

    let action = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect("filter ran");
    let FilterAction::Reject(rejection) = action else {
        panic!("a GET carrying a model must be evaluated, not waved through; got {action:?}");
    };
    assert!(
        has_header(&rejection, "x-policy-violation", "model_not_allowed"),
        "the catch-all must decide it; got {:?}",
        rejection.headers,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_type_sharing_the_sse_prefix_is_not_treated_as_sse() {
    let (_dir, path) = write_llm_post_config();
    let filter = build_read_write_filter(path);

    let body = inference_round_trip(
        &filter,
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#,
        OVER_BUDGET_RESPONSE,
        "text/event-streamx",
    )
    .await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("deny body is JSON");
    assert_eq!(
        parsed["error"]["code"], "completion_too_long",
        "only the real SSE type may skip the response half; got {body:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sse_type_skips_the_response_half_with_parameters() {
    let (_dir, path) = write_llm_post_config();
    let filter = build_read_write_filter(path);

    for content_type in [
        "text/event-stream",
        "text/event-stream; charset=utf-8",
        "TEXT/EVENT-STREAM",
    ] {
        let body = inference_round_trip(
            &filter,
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#,
            OVER_BUDGET_RESPONSE,
            content_type,
        )
        .await;
        assert_eq!(
            body,
            bytes::Bytes::from_static(OVER_BUDGET_RESPONSE.as_bytes()),
            "content type {content_type} names SSE, so the response half must stand aside",
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_past_the_inference_ceiling_is_rejected() {
    let (_dir, path) = write_llm_route_config();
    let filter = build_filter_with_llm(
        path,
        super::config::LlmOptions {
            max_request_bytes: 64,
            ..Default::default()
        },
    );

    let padding = "x".repeat(256);
    let body = format!(r#"{{"model":"allowed-model","messages":[],"pad":"{padding}"}}"#);
    let action = dispatch_inference_as(&filter, "alice", &body).await;
    let FilterAction::Reject(rejection) = action else {
        panic!("a body past the ceiling must be rejected; got {action:?}");
    };
    assert_eq!(rejection.status, 413, "the client can act on this by sending less");
    assert!(
        has_header(&rejection, "x-policy-violation", "llm.body_too_large"),
        "got {:?}",
        rejection.headers,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_content_encoded_completion_fails_closed() {
    let (_dir, path) = write_llm_post_config();
    let filter = build_read_write_filter(path);

    let req = request_for_alice();
    let mut ctx = make_filter_context(&req);
    admit_inference(&filter, &mut ctx).await;

    let mut response = crate::test_utils::make_response();
    response
        .headers
        .insert("content-type", HeaderValue::from_static("application/json"));
    response
        .headers
        .insert("content-encoding", HeaderValue::from_static("gzip"));
    ctx.response_header = Some(&mut response);

    let mut body = Some(bytes::Bytes::from_static(WITHIN_BUDGET_RESPONSE.as_bytes()));
    drop(
        filter
            .on_response_body(&mut ctx, &mut body, true)
            .expect("response phase ran"),
    );

    let served = body.expect("response body");
    let parsed: serde_json::Value = serde_json::from_slice(&served).expect("deny body is JSON");
    assert_eq!(
        parsed["error"]["code"], "llm.response_unreadable",
        "an encoded completion must not skip the response-phase policy; got {served:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn accept_encoding_is_stripped_when_the_policy_evaluates_completions() {
    let (_dir, path) = write_llm_post_config();
    let filter = build_read_write_filter(path);

    let req = request_for_alice();
    let mut ctx = make_filter_context(&req);
    admit_inference(&filter, &mut ctx).await;

    assert!(
        ctx.request_headers_to_remove.contains(&http::header::ACCEPT_ENCODING),
        "the upstream must be asked for plain JSON; got {:?}",
        ctx.request_headers_to_remove,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn accept_encoding_survives_a_request_only_inference_policy() {
    let (_dir, path) = write_llm_route_config();
    let filter = build_filter(path);

    let token = mint_jwt(&standard_claims("alice"));
    let mut req = make_request(Method::POST, "/v1/chat/completions");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);
    let mut request = Some(bytes::Bytes::from_static(br#"{"model":"allowed-model","messages":[]}"#));
    drop(
        filter
            .on_request_body(&mut ctx, &mut request, true)
            .await
            .expect("request phase ran"),
    );

    assert!(
        !ctx.request_headers_to_remove.contains(&http::header::ACCEPT_ENCODING),
        "a pre-invocation-only policy reads no completion, so compression should survive",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_response_releases_the_buffer_on_the_first_chunk() {
    let (_dir, path) = write_llm_post_config();
    let filter = build_read_write_filter(path);

    let req = request_for_alice();
    let mut ctx = make_filter_context(&req);
    admit_inference(&filter, &mut ctx).await;

    let mut response = crate::test_utils::make_response();
    response
        .headers
        .insert("content-type", HeaderValue::from_static("text/event-stream"));
    ctx.response_header = Some(&mut response);

    let mut first = Some(bytes::Bytes::from_static(b"data: {\"delta\":\"hi\"}\n\n"));
    let action = filter
        .on_response_body(&mut ctx, &mut first, false)
        .expect("response phase ran");
    assert!(
        matches!(action, FilterAction::Release),
        "a mid-stream SSE chunk must release the buffer, not be held to EOS; got {action:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_over_budget_completion_is_replaced_with_a_provider_error() {
    let (_dir, path) = write_llm_post_config();
    let filter = build_read_write_filter(path);

    let body = inference_round_trip(
        &filter,
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#,
        r#"{"model":"gpt-4o","usage":{"prompt_tokens":100,"completion_tokens":100,"total_tokens":200},
            "choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"a long answer"}}]}"#,
        "application/json",
    )
    .await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("deny body is JSON");
    assert_eq!(
        parsed["error"]["code"], "completion_too_long",
        "the post-phase deny must replace the upstream payload; got {body:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_completion_within_budget_reaches_the_client_unchanged() {
    let (_dir, path) = write_llm_post_config();
    let filter = build_read_write_filter(path);

    let body = inference_round_trip(
        &filter,
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#,
        WITHIN_BUDGET_RESPONSE,
        "application/json",
    )
    .await;

    assert_eq!(body, bytes::Bytes::from_static(WITHIN_BUDGET_RESPONSE.as_bytes()));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_response_skips_the_response_half() {
    let (_dir, path) = write_llm_post_config();
    let filter = build_read_write_filter(path);

    let requested = inference_round_trip(
        &filter,
        r#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}"#,
        OVER_BUDGET_RESPONSE,
        "application/json",
    )
    .await;
    let parsed: serde_json::Value = serde_json::from_slice(&requested).expect("deny body is JSON");
    assert_eq!(
        parsed["error"]["code"], "completion_too_long",
        "asking to stream must not skip post-invocation policy when the upstream answered with \
         one JSON completion; otherwise `stream: true` is a one-word bypass. Got {requested:?}",
    );

    let sse = inference_round_trip(
        &filter,
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#,
        OVER_BUDGET_RESPONSE,
        "text/event-stream",
    )
    .await;
    assert_eq!(
        sse,
        bytes::Bytes::from_static(OVER_BUDGET_RESPONSE.as_bytes()),
        "nor must a response the upstream chose to stream, whatever the request asked for",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_json_response_body_passes_through() {
    let (_dir, path) = write_llm_post_config();
    let filter = build_read_write_filter(path);

    let body = inference_round_trip(
        &filter,
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#,
        NON_JSON_RESPONSE,
        "application/json",
    )
    .await;
    assert_eq!(body, bytes::Bytes::from_static(NON_JSON_RESPONSE.as_bytes()));
}

#[test]
fn the_mixed_fixture_opens_the_inference_response_half() {
    let (_dir, path) = write_llm_and_tool_config();
    assert_eq!(build_read_write_filter(path).derived_llm_shape(), (true, true));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_inference_response_half_does_not_claim_mcp_responses() {
    let (_dir, path) = write_llm_and_tool_config();
    let filter = build_read_write_filter(path);

    let req = request_for_alice();
    let mut ctx = make_filter_context(&req);
    ctx.set_metadata("mcp.method", "tools/call");
    ctx.set_metadata("mcp.name", "echo");
    let request_body =
        bytes::Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}"#);
    drop(
        filter
            .on_request_body(&mut ctx, &mut Some(request_body), true)
            .await
            .expect("request phase ran"),
    );

    let mut body = Some(bytes::Bytes::from_static(MCP_RESPONSE.as_bytes()));
    drop(
        filter
            .on_response_body(&mut ctx, &mut body, true)
            .expect("response phase ran"),
    );

    let served = body.expect("response body");
    assert!(
        served.starts_with(br#"{"jsonrpc""#),
        "an MCP response must stay on the JSON-RPC post path — whatever that path does to the \
         body, the shape stays JSON-RPC rather than the provider envelope an inference deny \
         would produce; got {served:?}",
    );
}
