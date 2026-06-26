// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Responses proxy filter example tests.

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_send, json_post, parse_body, parse_status, start_backend};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn responses_proxy_example_forwards_request() {
    let backend_port = start_backend("backend-ok");
    let proxy_port = free_port();
    let yaml = make_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = praxis_test_utils::start_proxy(&config);

    let body = r#"{"model":"gpt-4.1-mini","input":"Hello"}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));

    assert_eq!(parse_status(&raw), 200, "proxied request should return 200");
    assert_eq!(
        parse_body(&raw),
        "backend-ok",
        "response body should match backend response"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build YAML config for a responses_proxy passthrough.
fn make_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: responses_proxy
        name: inference
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    )
}
