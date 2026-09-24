// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for response hooks of filters inside branch chains.

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_send, parse_header, parse_status, start_backend_with_shutdown, start_proxy};

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

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

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
