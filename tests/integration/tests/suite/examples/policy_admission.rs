// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration test for the policy head-admission example
//! (`examples/configs/security/policy-admission.yaml`).
//!
//! The example lists a body-buffering `json_body_field` before `policy`. Each
//! denial below is sent with a declared body that never arrives: the proxy can
//! only answer if policy decided at the request head, before the classifier
//! started reading.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    net::TcpStream,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use praxis_core::config::Config;
use praxis_filter::{FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext};
use praxis_test_utils::{
    example_config_path, free_port, http_send, parse_body, parse_status, patch_yaml, start_header_echo_backend,
    start_proxy, start_proxy_with_registry, start_reloadable_proxy,
};

// Identity parameters mirrored from
// `tests/integration/fixtures/admission-policy.yaml`.
const FIXTURE_ISSUER: &str = "https://idp.example.com";
const FIXTURE_AUDIENCE: &str = "praxis-policy-example";
const FIXTURE_SECRET: &str = "REPLACE-WITH-A-PROPERLY-RANDOM-SHARED-SECRET-DO-NOT-COMMIT";

#[test]
fn an_unauthenticated_request_is_rejected_before_its_body_is_read() {
    let backend = start_header_echo_backend();
    let proxy = start_proxy(&load_example(free_port(), backend.port(), None));
    assert_eq!(status_without_body(proxy.addr(), None, 1024), 401);
}

#[test]
fn an_authenticated_request_is_classified_and_forwarded() {
    let backend = start_header_echo_backend();
    let proxy = start_proxy(&load_example(free_port(), backend.port(), None));
    let body = r#"{"model":"m1"}"#;
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST /v1/chat HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: \
             application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            mint_fixture_jwt("alice"),
            body.len()
        ),
    );
    assert_eq!(parse_status(&raw), 200, "{raw}");
    assert!(
        parse_body(&raw).to_ascii_lowercase().contains("x-model: m1"),
        "the classifier still ran after admission: {raw}"
    );
}

#[test]
fn the_pre_identity_limit_rejects_at_the_head() {
    let backend = start_header_echo_backend();
    let proxy = start_proxy(&load_example(free_port(), backend.port(), None));
    let mut statuses = Vec::new();
    while statuses.last() != Some(&429) && statuses.len() < 5 {
        statuses.push(status_without_body(proxy.addr(), None, 64));
    }
    assert_eq!(statuses.last(), Some(&429), "{statuses:?}");
    assert!(
        statuses.iter().rev().skip(1).all(|status| *status == 401),
        "every request under the limit reached identity (the harness's readiness probe spends \
         part of the budget): {statuses:?}"
    );
    assert_eq!(
        status_without_body(proxy.addr(), Some(&mint_fixture_jwt("alice")), 64),
        429,
        "a valid credential does not lift the limit charged before identity"
    );
}

#[test]
fn a_declared_body_over_the_limit_is_judged_after_admission() {
    let backend = start_header_echo_backend();
    let proxy = start_proxy(&load_example(free_port(), backend.port(), None));
    let oversized = 1_048_576; // 1 MiB, over the classifier's 64 KiB
    assert_eq!(status_without_body(proxy.addr(), None, oversized), 401);
    assert_eq!(
        status_without_body(proxy.addr(), Some(&mint_fixture_jwt("alice")), oversized),
        413
    );
}

#[test]
fn an_earlier_ip_acl_still_rejects_before_admission() {
    let backend = start_header_echo_backend();
    let ip_acl = "      - filter: ip_acl\n        deny:\n          - \"127.0.0.0/8\"\n\n";
    let proxy = start_proxy(&without_classifier(&load_example_yaml(
        free_port(),
        backend.port(),
        Some(ip_acl),
    )));
    for token in [None, Some(mint_fixture_jwt("alice"))] {
        assert_eq!(
            post_json(proxy.addr(), token.as_deref()),
            403,
            "policy admits in the request phase after ip_acl, so ip_acl answers first (token: {})",
            token.is_some()
        );
    }
}

#[test]
fn a_pre_reading_pipeline_keeps_head_admission_behind_an_earlier_ip_acl() {
    let backend = start_header_echo_backend();
    let ip_acl = "      - filter: ip_acl\n        deny:\n          - \"127.0.0.0/8\"\n\n";
    let proxy = start_proxy(&load_example(free_port(), backend.port(), Some(ip_acl)));
    assert_eq!(
        status_without_body(proxy.addr(), None, 64),
        401,
        "the pre-read would run policy before ip_acl anyway, so the head still rejects first"
    );
}

#[test]
fn an_earlier_static_response_still_answers_without_credentials() {
    let backend = start_header_echo_backend();
    let health = "      - filter: static_response\n        conditions:\n          - when:\n              path: \
                  \"/healthz\"\n        status: 200\n        body: \"ok\"\n\n";
    let proxy = start_proxy(&without_classifier(&load_example_yaml(
        free_port(),
        backend.port(),
        Some(health),
    )));
    let raw = http_send(
        proxy.addr(),
        "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "{raw}");
    assert_eq!(
        post_json(proxy.addr(), None),
        401,
        "other paths still need a credential"
    );
}

#[test]
fn a_route_that_replaces_global_authentication_judges_its_own_credential() {
    let backend = start_header_echo_backend();
    let dir = tempfile::TempDir::new().unwrap();
    let config = route_replacing_config(&dir, free_port(), backend.port());
    let proxy = start_proxy(&config);
    let send = |authorization: &str| {
        let body = r#"{"model":"m1","messages":[{"role":"user","content":"hi"}]}"#;
        parse_status(&http_send(
            proxy.addr(),
            &format!(
                "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\n{authorization}Content-Type: \
                 application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        ))
    };
    assert_eq!(
        send("Authorization: Bearer sk-test-alice\r\n"),
        200,
        "the global JWT resolver must not judge a route that replaced it"
    );
    assert_eq!(
        send(&format!("Authorization: Bearer {}\r\n", mint_fixture_jwt("alice"))),
        401,
        "the replaced global credential is not accepted on the route"
    );
    assert_eq!(send(""), 401, "a missing key is denied by the route");
}

#[test]
fn a_classified_tool_call_is_authorized_after_head_admission() {
    let backend = start_header_echo_backend();
    let dir = tempfile::TempDir::new().unwrap();
    let proxy = start_proxy_with_registry(&mcp_config(&dir, free_port(), backend.port()), &tagging_registry());
    assert_eq!(
        status_without_body(proxy.addr(), None, 64),
        401,
        "an unauthenticated tool call is denied at the head, before classification"
    );
    let allowed = tool_call(proxy.addr(), "echo", &mint_fixture_jwt("alice"));
    assert_eq!(parse_status(&allowed), 200, "{allowed}");
    assert!(!allowed.contains("-32001"), "the backend answered: {allowed}");
    let denied = tool_call(proxy.addr(), "admin", &mint_fixture_jwt("alice"));
    assert_eq!(
        parse_status(&denied),
        200,
        "a tool denial is a JSON-RPC error: {denied}"
    );
    assert!(
        denied.contains("-32001") && denied.contains("admin_closed"),
        "the route denied it after the head admitted it: {denied}"
    );
}

#[test]
fn a_request_admitted_before_a_reload_finishes_on_its_pipeline() {
    let backend = start_header_echo_backend();
    let dir = tempfile::TempDir::new().unwrap();
    let port = free_port();
    let open = load_example_yaml(port, backend.port(), None);
    let fixture = format!("{}/fixtures/admission-policy.yaml", env!("CARGO_MANIFEST_DIR"));
    let closed_policy = dir.path().join("closed-policy.yaml");
    let closed_rules = std::fs::read_to_string(&fixture)
        .unwrap()
        .replace("\"require(authenticated)\"", "\"deny('closed', 'closed')\"");
    std::fs::write(&closed_policy, closed_rules).unwrap();
    let closed = open.replace(&fixture, closed_policy.to_str().unwrap());
    let proxy = start_reloadable_proxy(&open);

    let body = r#"{"model":"m1"}"#;
    let mut held = TcpStream::connect(proxy.addr()).unwrap();
    held.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        held,
        "POST /v1/chat HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: \
         application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        mint_fixture_jwt("alice"),
        body.len(),
        body.get(..1).unwrap()
    )
    .unwrap();
    held.flush().unwrap();

    let after = proxy.reload_until(
        &closed,
        || post_json(proxy.addr(), Some(&mint_fixture_jwt("alice"))),
        |status| *status == 403,
    );
    assert_eq!(after, 403, "new requests use the reloaded policy");

    held.write_all(body.get(1..).unwrap().as_bytes()).unwrap();
    let mut response = String::new();
    let _read = held.read_to_string(&mut response);
    assert_eq!(
        parse_status(&response),
        200,
        "the held request keeps its pipeline and head admission: {response}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Load the example with its policy at the in-repo fixture, `prefix` filters
/// inserted at the head of the chain, and ports patched.
fn load_example(proxy_port: u16, backend_port: u16, prefix: Option<&str>) -> Config {
    let yaml = load_example_yaml(proxy_port, backend_port, prefix);
    Config::from_yaml(&yaml).unwrap_or_else(|e| panic!("parse security/policy-admission.yaml: {e}"))
}

/// The example without its body-buffering classifier, so nothing pre-reads the
/// body and the chain's request phase runs in order before any body hook.
fn without_classifier(yaml: &str) -> Config {
    let classifier = "      - filter: json_body_field\n        field: model\n        header: X-Model\n        \
                      max_body_bytes: 65536 # 64 KiB\n";
    assert!(yaml.contains(classifier), "the example's classifier entry moved");
    Config::from_yaml(&yaml.replace(classifier, "")).unwrap()
}

/// The example YAML with its policy at the in-repo fixture, `prefix` filters
/// inserted at the head of the chain, and ports patched.
fn load_example_yaml(proxy_port: u16, backend_port: u16, prefix: Option<&str>) -> String {
    let path = example_config_path("security/policy-admission.yaml");
    let policy = format!("{}/fixtures/admission-policy.yaml", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let mut yaml = raw.replace("/etc/praxis/admission-policy.yaml", &policy);
    if let Some(prefix) = prefix {
        yaml = yaml.replacen("    filters:\n", &format!("    filters:\n{prefix}"), 1);
    }
    patch_yaml(&yaml, proxy_port, &HashMap::from([("127.0.0.1:3000", backend_port)]))
}

/// A proxy whose only filter before routing is an inference policy: a global
/// JWT resolver that every inference route replaces with API keys.
fn route_replacing_config(dir: &tempfile::TempDir, proxy_port: u16, backend_port: u16) -> Config {
    let keys = format!("{}/fixtures/api-keys.yaml", env!("CARGO_MANIFEST_DIR"));
    let admission = format!("{}/fixtures/admission-policy.yaml", env!("CARGO_MANIFEST_DIR"));
    let jwt = std::fs::read_to_string(&admission).unwrap();
    let jwt_plugin = jwt
        .split("  - name: jwt-user")
        .nth(1)
        .and_then(|rest| rest.split("\nglobal:").next())
        .unwrap();
    let policy = format!(
        "engine_settings:\n  dispatch: policy\n\nplugins:\n  - name: jwt-user{jwt_plugin}
  - name: api-keys
    kind: identity/api-key
    hooks: [identity.resolve]
    on_error: fail
    config:
      credential:
        kind: header
        name: Authorization
      prefix: \"Bearer sk-test-\"
      provider:
        kind: file
        path: {keys}
        index: sha256
      record_map:
        subject:
          id: user

global:
  authentication:
    - jwt-user

routes:
  - llm: \"*\"
    authentication:
      replace_inherited: true
      steps: [api-keys]
    authorization:
      pre_invocation:
        - \"require(authenticated)\"
"
    );
    let policy_path = dir.path().join("policy.yaml");
    std::fs::write(&policy_path, policy).unwrap();
    let yaml = format!(
        "listeners:
  - name: default
    address: \"127.0.0.1:{proxy_port}\"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: policy
        config_path: {}
      - filter: router
        routes:
          - path_prefix: \"/\"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: [\"127.0.0.1:{backend_port}\"]
insecure_options:
  allow_private_endpoints: true
",
        policy_path.display()
    );
    Config::from_yaml(&yaml).unwrap()
}

/// The status of a JSON POST that sends its body, with `token` if any.
fn post_json(addr: &str, token: Option<&str>) -> u16 {
    let authorization = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let body = r#"{"model":"m1"}"#;
    parse_status(&http_send(
        addr,
        &format!(
            "POST /v1/chat HTTP/1.1\r\nHost: localhost\r\n{authorization}Content-Type: \
             application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    ))
}

/// The status of a POST that declares `content_length` body bytes and sends
/// none. Only a decision made before the body is read can answer it.
fn status_without_body(addr: &str, token: Option<&str>, content_length: u64) -> u16 {
    let authorization = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        stream,
        "POST /v1/chat HTTP/1.1\r\nHost: localhost\r\n{authorization}Content-Type: application/json\r\n\
         Content-Length: {content_length}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    stream.flush().unwrap();
    let mut head = [0_u8; 64];
    let read = stream
        .read(&mut head)
        .unwrap_or_else(|e| panic!("no answer without the body; the proxy waited for it: {e}"));
    parse_status(&String::from_utf8_lossy(head.get(..read).unwrap()))
}

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

/// The MCP policy: global JWT authentication, an `echo` tool any
/// authenticated caller may use, and an `admin` tool no one may.
fn mcp_config(dir: &tempfile::TempDir, proxy_port: u16, backend_port: u16) -> Config {
    let admission = format!("{}/fixtures/admission-policy.yaml", env!("CARGO_MANIFEST_DIR"));
    let fixture = std::fs::read_to_string(admission).unwrap();
    let jwt_plugin = fixture
        .split("  - name: jwt-user")
        .nth(1)
        .and_then(|rest| rest.split("\nglobal:").next())
        .unwrap();
    let policy = format!(
        "engine_settings:\n  dispatch: policy\n\nplugins:\n  - name: jwt-user{jwt_plugin}
global:
  authentication:
    - jwt-user

routes:
  - tool: echo
    authorization:
      pre_invocation:
        - \"require(authenticated)\"
  - tool: admin
    authorization:
      pre_invocation:
        - \"deny('admin is closed', 'admin_closed')\"
"
    );
    let policy_path = dir.path().join("mcp-policy.yaml");
    std::fs::write(&policy_path, policy).unwrap();
    let yaml = format!(
        "listeners:
  - name: default
    address: \"127.0.0.1:{proxy_port}\"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: tool_tagger
      - filter: policy
        config_path: {}
      - filter: router
        routes:
          - path_prefix: \"/\"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: [\"127.0.0.1:{backend_port}\"]
insecure_options:
  allow_private_endpoints: true
",
        policy_path.display()
    );
    Config::from_yaml(&yaml).unwrap()
}

/// `POST` a `tools/call` for `tool` with `token`.
fn tool_call(addr: &str, tool: &str, token: &str) -> String {
    let body =
        format!(r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"{tool}","arguments":{{}}}}}}"#);
    http_send(
        addr,
        &format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nX-Tool: {tool}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

/// Stands in for the protocol classifier: tags each request as a
/// `tools/call` for the tool named in `X-Tool`, after the head phase.
struct ToolTagger;

#[async_trait::async_trait]
impl HttpFilter for ToolTagger {
    fn name(&self) -> &'static str {
        "tool_tagger"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let tool = ctx
            .request
            .headers
            .get("x-tool")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("echo")
            .to_owned();
        ctx.filter_metadata
            .insert("mcp.method", "tools/call")
            .expect("entry must fit in the filter's metadata");
        ctx.filter_metadata
            .insert("mcp.name", &tool)
            .expect("entry must fit in the filter's metadata");
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
