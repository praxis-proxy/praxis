// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for filters inside branch chains.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, parse_body, parse_header, parse_status, start_backend_with_shutdown,
    start_header_echo_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn branch_and_nested_branch_response_headers_reach_the_client() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let filters = r#"
      - filter: headers
        response_add:
          - name: X-Host
            value: host
        branch_chains:
          - name: decorate
            chains:
              - name: decorate_chain
                filters:
                  - filter: headers
                    response_add:
                      - name: X-Branch
                        value: branch
                    branch_chains:
                      - name: nested
                        chains:
                          - name: nested_chain
                            filters:
                              - filter: headers
                                response_add:
                                  - name: X-Nested
                                    value: nested
"#;
    let config = Config::from_yaml(&branch_yaml(proxy_port, backend_guard.port(), filters)).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "the request should proxy to the backend");
    assert_eq!(
        parse_header(&raw, "x-branch"),
        Some("branch".to_owned()),
        "a branch filter's response header must reach the client, got:\n{raw}"
    );
    assert_eq!(
        parse_header(&raw, "x-nested"),
        Some("nested".to_owned()),
        "a nested branch filter's response header must reach the client, got:\n{raw}"
    );
    assert_eq!(
        parse_header(&raw, "x-host"),
        Some("host".to_owned()),
        "the host filter's response header must still reach the client, got:\n{raw}"
    );
}

#[test]
fn cors_in_branch_adds_allow_origin_header() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let filters = r#"
      - filter: headers
        request_add:
          - name: X-Host
            value: host
        branch_chains:
          - name: browser
            chains:
              - name: cors_chain
                filters:
                  - filter: cors
                    allow_origins:
                      - "https://app.example.com"
                    allow_methods:
                      - GET
"#;
    let config = Config::from_yaml(&branch_yaml(proxy_port, backend_guard.port(), filters)).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(
        parse_status(&raw),
        200,
        "the allowed origin should proxy to the backend"
    );
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        Some("https://app.example.com".to_owned()),
        "cors inside a branch must add Access-Control-Allow-Origin, got:\n{raw}"
    );
}

#[test]
fn named_branch_refs_inherit_conditions_at_runtime() {
    let backend_guard = start_header_echo_backend();
    let branch_refs = [
        ("direct", "              - guarded"),
        (
            "nested",
            r"              - name: inline_wrapper
                filters:
                  - filter: headers
                    branch_chains:
                      - name: inner
                        chains:
                          - guarded",
        ),
    ];

    for (shape, branch_ref) in branch_refs {
        let config = Config::from_yaml(&conditioned_named_branch_yaml(
            free_port(),
            backend_guard.port(),
            branch_ref,
        ))
        .unwrap();
        let proxy = start_proxy(&config);
        for (path, should_add_header) in [("/api", true), ("/other", false)] {
            let raw = http_send(
                proxy.addr(),
                &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
            );
            assert_eq!(parse_status(&raw), 200, "{shape} branch should reach the backend");
            let body = parse_body(&raw).to_ascii_lowercase();
            assert_eq!(
                body.contains("x-inherited: applied"),
                should_add_header,
                "{shape} branch must apply its inherited condition for {path}, got:\n{body}"
            );
        }
    }
}

#[test]
fn terminal_branch_response_headers_reach_the_client() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let filters = format!(
        r#"
      - filter: guardrails
        action: flag
        rules:
          - target: header
            name: "X-Flagged"
            contains: "true"
        branch_chains:
          - name: flagged
            on_result:
              filter: guardrails
              result: blocked
            rejoin: terminal
            chains:
              - name: flagged_route
                filters:
                  - filter: headers
                    response_add:
                      - name: X-Flagged-By
                        value: branch
                  - filter: router
                    routes:
                      - path_prefix: "/"
                        cluster: "backend"
                  - filter: load_balancer
                    clusters:
                      - name: "backend"
                        endpoints:
                          - "127.0.0.1:{backend_port}"
"#
    );
    let config = Config::from_yaml(&branch_yaml(proxy_port, backend_port, &filters)).unwrap();
    let proxy = start_proxy(&config);

    let flagged = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Flagged: true\r\nConnection: close\r\n\r\n",
    );
    let plain = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(
        parse_status(&flagged),
        200,
        "the terminal branch should forward upstream"
    );
    assert_eq!(
        parse_header(&flagged, "x-flagged-by"),
        Some("branch".to_owned()),
        "a terminal branch filter's response header must reach the client, got:\n{flagged}"
    );
    assert_eq!(parse_status(&plain), 200, "an unflagged request should proxy");
    assert!(
        parse_header(&plain, "x-flagged-by").is_none(),
        "a branch that never fired must not touch the response, got:\n{plain}"
    );
}

#[test]
fn weighted_target_is_reselected_when_a_branch_reenters_the_router() {
    let stable_guard = start_backend_with_shutdown("stable");
    let canary_guard = start_backend_with_shutdown("canary");
    let proxy_port = free_port();
    let config = Config::from_yaml(&reentrant_weighted_yaml(
        proxy_port,
        stable_guard.port(),
        canary_guard.port(),
    ))
    .unwrap();
    let proxy = start_proxy(&config);

    for _ in 0..10 {
        let raw = http_send(
            proxy.addr(),
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(
            parse_status(&raw),
            200,
            "the re-entering pipeline should proxy to a weighted target, got:\n{raw}"
        );
        assert_eq!(
            parse_body(&raw),
            "canary",
            "the 1:1 route picks stable first and canary second; one branch re-entry must select \
             again, so every request ends on canary (a single selection would alternate)"
        );
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Proxy config whose weighted route is re-entered by a later branch chain.
///
/// `main` runs the named router, then a headers filter whose unconditional
/// branch rejoins the router. Because the rejoin target sits earlier in the
/// chain, it is a `ReEnter` and requires `max_iterations`.
fn reentrant_weighted_yaml(proxy_port: u16, stable_port: u16, canary_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        name: routing
        routes:
          - path_prefix: "/"
            weighted_clusters:
              targets:
                - name: stable
                - name: canary
      - filter: headers
        request_add:
          - name: X-Reentered
            value: "1"
        branch_chains:
          - name: again
            rejoin: routing
            max_iterations: 1
            chains:
              - name: again_chain
                filters:
                  - filter: headers
                    request_add:
                      - name: X-Loop
                        value: "1"
      - filter: load_balancer
        clusters:
          - name: stable
            endpoints:
              - "127.0.0.1:{stable_port}"
          - name: canary
            endpoints:
              - "127.0.0.1:{canary_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// Proxy config whose `main` chain runs `filters`, then routes to the backend.
fn branch_yaml(proxy_port: u16, backend_port: u16, filters: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
{filters}
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// Build a proxy whose branch child refers to the conditioned `guarded` chain.
fn conditioned_named_branch_yaml(proxy_port: u16, backend_port: u16, branch_ref: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: guarded
    conditions:
      - when:
          path_prefix: "/api"
    filters:
      - filter: headers
        request_add:
          - name: X-Inherited
            value: applied
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: outer
            chains:
{branch_ref}
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}
