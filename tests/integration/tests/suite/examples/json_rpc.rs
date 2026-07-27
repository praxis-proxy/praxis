// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the `json_rpc` example config.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_send, json_post, parse_body, parse_status, start_header_echo_backend, start_proxy,
};

use super::load_example_config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn json_rpc_extracts_method_and_id_headers() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();
    let config = load_example_config(
        "payload-processing/json-rpc.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/", r#"{"jsonrpc":"2.0","method":"eth_blockNumber","id":1}"#),
    );
    assert_eq!(parse_status(&raw), 200, "valid JSON-RPC request should return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-json-rpc-method: eth_blocknumber"),
        "backend should receive X-Json-Rpc-Method header, got:\n{body}"
    );
    assert!(
        lower.contains("x-json-rpc-id: 1"),
        "backend should receive X-Json-Rpc-Id header, got:\n{body}"
    );
    assert!(
        lower.contains("x-json-rpc-kind: request"),
        "backend should receive X-Json-Rpc-Kind: request header, got:\n{body}"
    );
}

#[test]
fn json_rpc_notification_has_no_id() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();
    let config = load_example_config(
        "payload-processing/json-rpc.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/", r#"{"jsonrpc":"2.0","method":"eth_subscribe","params":[]}"#),
    );
    assert_eq!(parse_status(&raw), 200, "JSON-RPC notification should return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-json-rpc-method: eth_subscribe"),
        "notification should have method header, got:\n{body}"
    );
    assert!(
        lower.contains("x-json-rpc-kind: notification"),
        "notification should have kind=notification, got:\n{body}"
    );
    assert!(
        !lower.contains("x-json-rpc-id:"),
        "notification should not have id header, got:\n{body}"
    );
}

#[test]
fn json_rpc_rejects_batch_array() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();
    let config = load_example_config(
        "payload-processing/json-rpc.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post(
            "/",
            r#"[{"jsonrpc":"2.0","method":"a","id":1},{"jsonrpc":"2.0","method":"b","id":2}]"#,
        ),
    );
    assert_eq!(
        parse_status(&raw),
        400,
        "batch array should be rejected when batch_policy is 'reject'"
    );
}

#[test]
fn json_rpc_rejects_invalid_body() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();
    let config = load_example_config(
        "payload-processing/json-rpc.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/", "not valid json"));
    assert_eq!(
        parse_status(&raw),
        400,
        "invalid JSON body should be rejected when on_invalid is 'reject'"
    );
}
