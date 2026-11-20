// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! HTTP fallback admission and its upstream header contract.

use std::{collections::HashMap, sync::atomic::Ordering};

use bytes::Bytes;
use http::{HeaderName, HeaderValue};
use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, HttpFilter, HttpFilterContext, TrustedHeaderMutation,
};
use praxis_test_utils::{
    free_port, http_send, parse_body, parse_status, registry_with, start_header_echo_backend, start_proxy,
    start_proxy_with_registry, start_request_counting_backend,
};

use super::{backend_map, fixture_with_global, load_example_with, mint_fixture_jwt};

/// The HTTP contract applies to discovery and accepted non-model bodies.
const CONTRACT: &str = "  authorization:
    pre_invocation:
      - \"require(role.research)\"
  assertions:
    request:
      headers:
        - name: x-auth-user-id
          from: subject.id
      strip: [authorization, x-api-key, 'x-secret-*']";

#[test]
fn a_body_cannot_bypass_discovery_authorization_when_models_are_optional() {
    let (_dir, path) = fixture_with_global(CONTRACT);
    let (backend, count) = start_request_counting_backend("allowed");
    let proxy = start_proxy(&config(backend.port(), &path));
    let denied = mint_fixture_jwt("support-bot", &["support"]);
    for (method, body) in [("GET", "{}"), ("GET", " "), ("POST", ""), ("POST", "{}")] {
        let raw = http_send(proxy.addr(), &request(method, body, &denied));
        assert_eq!(parse_status(&raw), 403, "{method} {body:?}: {raw}");
    }
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "denied requests never reach the backend"
    );
    let allowed = mint_fixture_jwt("research-bot", &["research"]);
    let raw = http_send(proxy.addr(), &request("GET", "{}", &allowed));
    assert_eq!(parse_status(&raw), 200, "{raw}");
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "the positive control reaches the same backend"
    );
}

#[test]
fn fallback_assertions_survive_ordered_body_mutations() {
    let (_dir, path) = fixture_with_global(CONTRACT);
    let backend = start_header_echo_backend();
    let token = mint_fixture_jwt("research-bot", &["research"]);
    for before_policy in [true, false] {
        let mut config = config(backend.port(), &path);
        let index = usize::from(!before_policy);
        config.filter_chains[0].filters.insert(
            index,
            serde_yaml::from_str("filter: ordered_headers").expect("test filter entry"),
        );
        let registry = if before_policy {
            registry_with("ordered_headers", || Box::new(OrderedHeaders { governed: true }))
        } else {
            registry_with("ordered_headers", || Box::new(OrderedHeaders { governed: false }))
        };
        let proxy = start_proxy_with_registry(&config, &registry);
        for (method, body) in [("GET", ""), ("GET", "{}"), ("POST", " ")] {
            let raw = http_send(proxy.addr(), &request(method, body, &token));
            assert_eq!(
                parse_status(&raw),
                200,
                "before={before_policy}, {method} {body:?}: {raw}"
            );
            assert_headers(&parse_body(&raw));
        }
    }
}

#[test]
fn ordered_delegation_reaches_the_backend_only_as_assertions_permit() {
    let (issuer, exchanges) = start_request_counting_backend(
        r#"{"access_token":"delegated-secret","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","expires_in":300}"#,
    );
    let (_dir, path) = delegation_policy(issuer.port());
    let original: serde_yaml::Value = serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let backend = start_header_echo_backend();
    let token = mint_fixture_jwt("research-bot", &["research"]);
    for (index, (strip, replace, expected)) in [
        (false, false, Some("Bearer delegated-secret")),
        (true, false, None),
        (false, true, Some("research-bot")),
    ]
    .into_iter()
    .enumerate()
    {
        let mut policy = original.clone();
        let contract = &mut policy["global"]["assertions"]["request"];
        if !strip {
            contract["strip"]
                .as_sequence_mut()
                .unwrap()
                .retain(|name| name.as_str() != Some("authorization"));
        }
        if replace {
            contract["headers"]
                .as_sequence_mut()
                .unwrap()
                .push(serde_yaml::from_str("name: authorization\nfrom: subject.id").unwrap());
        }
        std::fs::write(&path, serde_yaml::to_string(&policy).unwrap()).unwrap();
        let mut config = config(backend.port(), &path);
        config.filter_chains[0].filters[0].config["allow_private_idp"] = serde_yaml::Value::Bool(true);
        config.filter_chains[0]
            .filters
            .insert(0, serde_yaml::from_str("filter: ordered_headers").unwrap());
        let registry = registry_with("ordered_headers", || Box::new(OrderedHeaders { governed: true }));
        let proxy = start_proxy_with_registry(&config, &registry);
        let raw = http_send(proxy.addr(), &request("GET", "{}", &token));
        assert_eq!(parse_status(&raw), 200, "strip={strip}, replace={replace}: {raw}");
        let body = parse_body(&raw);
        let headers = upstream_headers(&body);
        assert_eq!(
            headers.get("authorization").map(Vec::as_slice),
            expected.as_ref().map(std::slice::from_ref),
            "{raw}"
        );
        assert!(
            !headers.contains_key("x-api-key") && !headers.contains_key("x-secret-pending"),
            "{raw}"
        );
        assert_eq!(headers.get("x-auth-user-id"), Some(&vec!["research-bot"]), "{raw}");
        assert_eq!(headers.get("x-ordered-note"), Some(&vec!["present"]), "{raw}");
        assert!(!raw.contains(&token), "the inbound token must not reach the backend");
        assert_eq!(
            exchanges.load(Ordering::SeqCst),
            index + 1,
            "one exchange per admitted request"
        );
    }
}

/// Add a real OAuth delegator with access to the credential it exchanges.
fn delegation_policy(port: u16) -> (tempfile::TempDir, String) {
    let (dir, path) = fixture_with_global(CONTRACT);
    let mut policy: serde_yaml::Value = serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    policy["plugins"].as_sequence_mut().unwrap().push(
        serde_yaml::from_str(&format!(
            r#"name: exchange
kind: delegator/oauth
hooks: [token.delegate]
on_error: fail
capabilities: [perform_http, read_inbound_credentials]
config:
  token_endpoint: http://127.0.0.1:{port}/token
  client_id: test-gateway
  client_secret_source: {{kind: literal, secret: test-secret}}
  insecure_http: true
"#
        ))
        .unwrap(),
    );
    policy["global"]["authorization"]["pre_invocation"]
        .as_sequence_mut()
        .unwrap()
        .push(serde_yaml::Value::String(
            "delegate(exchange, target: upstream, audience: upstream)".to_owned(),
        ));
    std::fs::write(&path, serde_yaml::to_string(&policy).unwrap()).unwrap();
    (dir, path)
}

#[tokio::test]
async fn http2_header_only_discovery_enforces_policy_and_ordered_assertions() {
    let (_dir, path) = fixture_with_global(CONTRACT);
    let backend = start_header_echo_backend();
    let mut config = config(backend.port(), &path);
    config.filter_chains[0]
        .filters
        .insert(0, serde_yaml::from_str("filter: ordered_headers").unwrap());
    let registry = registry_with("ordered_headers", || Box::new(OrderedHeaders { governed: true }));
    let proxy = start_proxy_with_registry(&config, &registry);
    let stream = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
    let (mut client, connection) = h2::client::handshake(stream).await.unwrap();
    let driver = tokio::spawn(connection);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for (subject, roles, expected) in [
            ("support-bot", vec!["support"], 403),
            ("research-bot", vec!["research"], 200),
        ] {
            let token = mint_fixture_jwt(subject, &roles);
            let request = http::Request::get(format!("http://{}/v1/models", proxy.addr()))
                .header("authorization", format!("Bearer {token}"))
                .header("x-api-key", "caller-key")
                .header("x-auth-user-id", "root")
                .body(())
                .unwrap();
            let (response, _) = client.send_request(request, true).unwrap();
            let mut response = response.await.unwrap();
            assert_eq!(response.status(), expected, "{subject}");
            let mut body = Vec::new();
            while let Some(chunk) = response.body_mut().data().await {
                body.extend_from_slice(&chunk.unwrap());
            }
            if expected == 200 {
                assert_headers(std::str::from_utf8(&body).unwrap());
            }
        }
    })
    .await
    .expect("HTTP/2 admission completes");
    driver.abort();
    let _result = driver.await;
}

/// Load the runnable inference example with model omission enabled.
fn config(backend_port: u16, policy: &str) -> Config {
    let mut config = load_example_with(free_port(), backend_map(backend_port), policy);
    config.filter_chains[0].filters[0].config["llm"]["require_model"] = serde_yaml::Value::Bool(false);
    config
}

/// A request whose credential and asserted identity must not be forwarded.
fn request(method: &str, body: &str, token: &str) -> String {
    format!(
        "{method} /v1/models HTTP/1.1\r\nHost: localhost\r\n\
         Authorization: Bearer {token}\r\nX-Api-Key: caller-key\r\n\
         X-Auth-User-Id: root\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    )
}

/// Assert the headers recorded by the upstream, including duplicate fields.
fn assert_headers(raw: &str) {
    let seen = upstream_headers(raw);
    for name in ["authorization", "x-api-key", "x-secret-pending"] {
        assert!(!seen.contains_key(name), "{name} must not reach the backend: {raw}");
    }
    assert_eq!(seen.get("x-auth-user-id"), Some(&vec!["research-bot"]), "{raw}");
    assert_eq!(
        seen.get("x-ordered-note"),
        Some(&vec!["present"]),
        "no lost or duplicate add: {raw}"
    );
}

/// Keep every field line the echo backend observed.
fn upstream_headers(raw: &str) -> HashMap<String, Vec<&str>> {
    let mut seen: HashMap<String, Vec<&str>> = HashMap::new();
    for (name, value) in raw.lines().filter_map(|line| line.split_once(':')) {
        seen.entry(name.trim().to_ascii_lowercase())
            .or_default()
            .push(value.trim());
    }
    seen
}

/// Model the downstream ext-proc producer's ordered mutation contract.
struct OrderedHeaders {
    /// Whether this producer precedes policy and writes governed headers.
    governed: bool,
}

#[async_trait::async_trait]
impl HttpFilter for OrderedHeaders {
    fn name(&self) -> &'static str {
        "ordered_headers"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(praxis_filter::BodyRequirement::Optional)
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(1_024) }
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }
        begin_ordered(ctx);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            HeaderName::from_static("x-ordered-note"),
            "present".to_owned(),
        ));
        if self.governed {
            for name in ["x-api-key", "x-secret-pending", "x-auth-user-id"] {
                ctx.pre_read_mutations.push(TrustedHeaderMutation::Set(
                    HeaderName::from_static(name),
                    HeaderValue::from_static("injected"),
                ));
            }
        }
        Ok(FilterAction::BodyDone)
    }
}

/// Preserve preceding legacy producers when activating ordered replay.
fn begin_ordered(ctx: &mut HttpFilterContext<'_>) {
    if !ctx.pre_read_mutations.is_empty() {
        return;
    }
    ctx.pre_read_mutations.extend(
        ctx.request_headers_to_remove
            .iter()
            .cloned()
            .map(TrustedHeaderMutation::Remove),
    );
    ctx.pre_read_mutations.extend(
        ctx.request_headers_to_set
            .iter()
            .cloned()
            .map(|(name, value)| TrustedHeaderMutation::Set(name, value)),
    );
    ctx.pre_read_mutations
        .extend(ctx.extra_request_headers.iter().map(|(name, value)| {
            TrustedHeaderMutation::Add(HeaderName::try_from(name.as_ref()).expect("header name"), value.clone())
        }));
}
