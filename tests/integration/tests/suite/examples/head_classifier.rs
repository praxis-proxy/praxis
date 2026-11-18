// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the head classifier example configuration.

use std::collections::HashMap;

#[cfg(feature = "basic-auth-filter")]
use praxis_core::config::Config;
#[cfg(feature = "basic-auth-filter")]
use praxis_test_utils::start_request_counting_backend;
use praxis_test_utils::{free_port, http_send, parse_body, parse_status, start_backend_with_shutdown, start_proxy};

/// Start the head-classifier example proxy wired to three backends.
fn proxy_for(api: u16, assets: u16, other: u16, proxy_port: u16) -> praxis_test_utils::ProxyGuard {
    let config = super::load_example_config(
        "traffic-management/head-classifier.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", api),
            ("127.0.0.1:3002", assets),
            ("127.0.0.1:3003", other),
        ]),
    );
    start_proxy(&config)
}

/// Send a POST with a plain-text body over a closing connection.
fn post(addr: &str, path: &str, body: &str) -> String {
    http_send(
        addr,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

#[test]
fn head_class_drives_routing() {
    let api = start_backend_with_shutdown("api-backend");
    let assets = start_backend_with_shutdown("assets-backend");
    let other = start_backend_with_shutdown("other-backend");
    let proxy_port = free_port();
    let proxy = proxy_for(api.port(), assets.port(), other.port(), proxy_port);
    let get = |path: &str| {
        parse_body(&http_send(
            proxy.addr(),
            &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        ))
    };
    assert_eq!(get("/api/users"), "api-backend", "/api/* classifies as api");
    assert_eq!(
        get("/assets/app.js"),
        "assets-backend",
        "/assets/* classifies as assets"
    );
    assert_eq!(get("/home"), "other-backend", "unmatched path uses the default class");
}

#[test]
fn head_class_gates_body_guardrails_before_pre_read() {
    let api = start_backend_with_shutdown("api-backend");
    let assets = start_backend_with_shutdown("assets-backend");
    let other = start_backend_with_shutdown("other-backend");
    let proxy_port = free_port();
    let proxy = proxy_for(api.port(), assets.port(), other.port(), proxy_port);

    // A forbidden body on /api/* is blocked: the head phase promoted class `api`
    // before the body pre-read, so the body guardrails gate matched. If the head
    // phase ran after pre-read, the gate would be unset and this would not block.
    assert_eq!(
        parse_status(&post(proxy.addr(), "/api/users", "forbidden")),
        403,
        "class api must block a forbidden body, proving head ran before pre-read"
    );

    // The same forbidden body on /home is not blocked: class `other` does not
    // match the gate, so guardrails is skipped and the body reaches the backend.
    assert_eq!(
        parse_status(&post(proxy.addr(), "/home", "forbidden")),
        200,
        "class other must skip guardrails even with a forbidden body"
    );
}

/// Existing head classifiers with opposite private-path results and branch-gated auth.
#[cfg(feature = "basic-auth-filter")]
const BRANCH_AUTH_YAML: &str = r#"
listeners:
  - name: default
    address: "127.0.0.1:PROXY_PORT"
    protocol: http
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: head_classifier
        name: private_classifier
        rules: [{path_prefix: /private, class: untrusted}]
        default_class: public
        branch_chains:
          - name: authenticate_private
            on_result: {filter: head_classifier, key: class, result: untrusted}
            rejoin: next
            chains:
              - name: authentication
                filters:
                  - filter: basic_auth
                    credentials: [{username: admin, password: secret}]
      - filter: head_classifier
        name: later_classifier
        rules: [{path_prefix: /private, class: trusted}]
        default_class: public
      - filter: router
        routes: [{path_prefix: /, cluster: backend}]
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:BACKEND_PORT"]
insecure_options:
  allow_private_endpoints: true
"#;

/// Send one path with optional valid Basic credentials.
#[cfg(feature = "basic-auth-filter")]
fn branch_auth_get(addr: &str, path: &str, authorized: bool) -> String {
    let auth = if authorized {
        "Authorization: Basic YWRtaW46c2VjcmV0\r\n"
    } else {
        ""
    };
    http_send(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Connection: close\r\n\r\n"),
    )
}

#[cfg(feature = "basic-auth-filter")]
#[test]
fn head_classifier_branch_auth_cannot_be_skipped_by_later_instance() {
    use std::sync::atomic::Ordering;

    let (backend, hits) = start_request_counting_backend("protected");
    let yaml = BRANCH_AUTH_YAML
        .replace("PROXY_PORT", &free_port().to_string())
        .replace("BACKEND_PORT", &backend.port().to_string());
    let config = Config::from_yaml(&yaml).expect("config must pass normal validation");
    let proxy = start_proxy(&config);
    let startup_hits = hits.load(Ordering::SeqCst);
    let denied = branch_auth_get(proxy.addr(), "/private", false);
    assert_eq!(parse_status(&denied), 401, "private path needs authentication");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        startup_hits,
        "denied request must not reach backend"
    );
    let allowed = branch_auth_get(proxy.addr(), "/private", true);
    assert_eq!(parse_status(&allowed), 200, "valid credentials should forward");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        startup_hits.saturating_add(1),
        "authorized request must reach backend once"
    );
    let public = branch_auth_get(proxy.addr(), "/public", false);
    assert_eq!(parse_status(&public), 200, "public path remains reachable");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        startup_hits.saturating_add(2),
        "only authorized and public requests reach backend"
    );
}
