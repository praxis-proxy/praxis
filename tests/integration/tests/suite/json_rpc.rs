// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the `json_rpc` filter.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, json_post, parse_body, parse_status, start_backend_with_shutdown, start_header_echo_backend,
    start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn extracts_json_rpc_method_to_header() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/api", r#"{"jsonrpc":"2.0","method":"service/invoke","id":1}"#),
    );

    assert_eq!(parse_status(&raw), 200, "JSON-RPC request should return 200");
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-json-rpc-method: service/invoke"),
        "expected X-Json-Rpc-Method header echoed by backend, got:\n{body}"
    );
    assert!(
        body.to_lowercase().contains("x-json-rpc-id: 1"),
        "expected X-Json-Rpc-Id header echoed by backend, got:\n{body}"
    );
    assert!(
        body.to_lowercase().contains("x-json-rpc-kind: request"),
        "expected X-Json-Rpc-Kind header echoed by backend, got:\n{body}"
    );
}

#[test]
fn extracts_notification_without_id() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post(
            "/api",
            r#"{"jsonrpc":"2.0","method":"notifications/service/list_changed"}"#,
        ),
    );

    assert_eq!(parse_status(&raw), 200, "JSON-RPC notification should return 200");
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase()
            .contains("x-json-rpc-method: notifications/service/list_changed"),
        "expected method header for notification, got:\n{body}"
    );
    assert!(
        body.to_lowercase().contains("x-json-rpc-kind: notification"),
        "expected kind=notification header, got:\n{body}"
    );
    assert!(
        !body.to_lowercase().contains("x-json-rpc-id:"),
        "notifications should not have id header, got:\n{body}"
    );
}

#[test]
fn method_based_routing_different_clusters() {
    let backend1_guard = start_backend_with_shutdown("tools-backend");
    let backend1_port = backend1_guard.port();

    let backend2_guard = start_backend_with_shutdown("messaging-backend");
    let backend2_port = backend2_guard.port();

    let proxy_port = free_port();
    let yaml = routing_proxy_yaml(proxy_port, backend1_port, backend2_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw1 = http_send(
        proxy.addr(),
        &json_post(
            "/rpc-tools/",
            r#"{"jsonrpc":"2.0","id":"req-1","method":"service/invoke","params":{"name":"calculator"}}"#,
        ),
    );
    assert_eq!(parse_status(&raw1), 200, "service/invoke request should return 200");
    assert_eq!(
        parse_body(&raw1),
        "tools-backend",
        "service/invoke should route to tools backend"
    );

    let raw2 = http_send(
        proxy.addr(),
        &json_post(
            "/rpc-msg/",
            r#"{"jsonrpc":"2.0","id":"msg-123","method":"ProcessRequest","params":{"recipient":"agent-42"}}"#,
        ),
    );
    assert_eq!(parse_status(&raw2), 200, "ProcessRequest request should return 200");
    assert_eq!(
        parse_body(&raw2),
        "messaging-backend",
        "ProcessRequest should route to messaging backend"
    );
}

#[test]
fn non_json_rpc_passes_through() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/api", r#"{"message":"hello","user":"alice"}"#),
    );

    assert_eq!(parse_status(&raw), 200, "non-JSON-RPC request should pass through");
    let body = parse_body(&raw);
    assert!(
        !body.to_lowercase().contains("x-json-rpc"),
        "non-JSON-RPC should not add JSON-RPC headers, got:\n{body}"
    );
}

#[test]
fn invalid_json_passes_through() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/api", "not json at all"));

    assert_eq!(parse_status(&raw), 200, "invalid JSON should pass through by default");
    let body = parse_body(&raw);
    assert!(
        !body.to_lowercase().contains("x-json-rpc"),
        "invalid JSON should not add JSON-RPC headers, got:\n{body}"
    );
}

#[test]
fn string_and_numeric_ids_handled() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw1 = http_send(
        proxy.addr(),
        &json_post("/api", r#"{"jsonrpc":"2.0","method":"test","id":"req-abc"}"#),
    );
    assert_eq!(parse_status(&raw1), 200, "string ID should work");
    let body1 = parse_body(&raw1);
    assert!(
        body1.to_lowercase().contains("x-json-rpc-id: req-abc"),
        "expected string ID header, got:\n{body1}"
    );

    let raw2 = http_send(
        proxy.addr(),
        &json_post("/api", r#"{"jsonrpc":"2.0","method":"test","id":42}"#),
    );
    assert_eq!(parse_status(&raw2), 200, "numeric ID should work");
    let body2 = parse_body(&raw2);
    assert!(
        body2.to_lowercase().contains("x-json-rpc-id: 42"),
        "expected numeric ID header, got:\n{body2}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn simple_proxy_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: json_rpc
        max_body_bytes: 1048576
        batch_policy: reject
        on_invalid: continue
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
    )
}

fn routing_proxy_yaml(proxy_port: u16, backend1_port: u16, backend2_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: json_rpc
        max_body_bytes: 1048576
        batch_policy: reject
        on_invalid: continue
        headers:
          method: X-Json-Rpc-Method
          id: X-Json-Rpc-Id
          kind: X-Json-Rpc-Kind
      - filter: router
        routes:
          - path_prefix: "/rpc-tools/"
            headers:
              x-json-rpc-method: "service/invoke"
            cluster: "tools"
          - path_prefix: "/rpc-tools/"
            headers:
              x-json-rpc-method: "service/list"
            cluster: "tools"
          - path_prefix: "/rpc-msg/"
            headers:
              x-json-rpc-method: "ProcessRequest"
            cluster: "messaging"
          - path_prefix: "/rpc-msg/"
            headers:
              x-json-rpc-method: "StreamRequest"
            cluster: "messaging"
          - path_prefix: "/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "tools"
            endpoints:
              - "127.0.0.1:{backend1_port}"
          - name: "messaging"
            endpoints:
              - "127.0.0.1:{backend2_port}"
          - name: "default"
            endpoints:
              - "127.0.0.1:{backend1_port}"
"#
    )
}
