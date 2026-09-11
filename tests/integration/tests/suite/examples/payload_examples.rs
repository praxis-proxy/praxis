// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for payload-processing example
//! configurations not covered by `payload_processing.rs`.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_get, http_send, json_post, parse_body, parse_status, start_backend_with_shutdown,
    start_echo_backend, start_proxy,
};

use super::load_example_config;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const JSON_BODY_EXAMPLE: &str = "payload-processing/json-body.yaml";
const JSON_BODY_PAYLOAD: &str =
    r#"{"model":"old","secret":"s3cret","prompt":"hi","stream":true,"user":{"id":1},"internal":"drop-me"}"#;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn compression_returns_200_with_accept_encoding() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "payload-processing/compression.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Accept-Encoding: gzip\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "compression proxy should return 200 with Accept-Encoding"
    );
}

#[test]
fn compression_returns_200_without_accept_encoding() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "payload-processing/compression.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "request without Accept-Encoding should return 200");
    assert_eq!(body, "ok", "uncompressed response should match backend body");
}

#[test]
fn stream_buffer_routes_process_action() {
    // The processor cluster lists two distinct endpoints (3001, 3002); give
    // each its own backend (both returning "processed") rather than collapsing
    // them onto one address, which config validation rejects as a duplicate.
    let processor_guard = start_backend_with_shutdown("processed");
    let processor_guard_2 = start_backend_with_shutdown("processed");
    let default_guard = start_backend_with_shutdown("default");
    let proxy_port = free_port();
    let config = load_example_config(
        "payload-processing/stream-buffer.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", processor_guard.port()),
            ("127.0.0.1:3002", processor_guard_2.port()),
            ("127.0.0.1:3003", default_guard.port()),
            ("127.0.0.1:3000", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/tasks", r#"{"action":"process","payload":"data"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "process action should return 200");
    assert_eq!(
        parse_body(&raw),
        "processed",
        "action=process should route to processor cluster"
    );
}

#[test]
fn stream_buffer_routes_validate_action() {
    let validator_guard = start_backend_with_shutdown("validated");
    let default_guard = start_backend_with_shutdown("default");
    // The processor cluster (3001, 3002) is not exercised here but its two
    // endpoints must still map to distinct addresses, since config validation
    // rejects a duplicate endpoint address within a cluster.
    let processor_guard = start_backend_with_shutdown("default");
    let proxy_port = free_port();
    let config = load_example_config(
        "payload-processing/stream-buffer.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", default_guard.port()),
            ("127.0.0.1:3002", processor_guard.port()),
            ("127.0.0.1:3003", validator_guard.port()),
            ("127.0.0.1:3000", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/tasks", r#"{"action":"validate","item":"x"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "validate action should return 200");
    assert_eq!(
        parse_body(&raw),
        "validated",
        "action=validate should route to validator cluster"
    );
}

#[test]
fn stream_buffer_routes_unknown_action_to_default() {
    let default_guard = start_backend_with_shutdown("default-hit");
    // The processor cluster (3001, 3002) is not exercised here but its two
    // endpoints must still map to distinct addresses, since config validation
    // rejects a duplicate endpoint address within a cluster.
    let processor_guard = start_backend_with_shutdown("default-hit");
    let proxy_port = free_port();
    let config = load_example_config(
        "payload-processing/stream-buffer.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", default_guard.port()),
            ("127.0.0.1:3002", processor_guard.port()),
            ("127.0.0.1:3003", default_guard.port()),
            ("127.0.0.1:3000", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/tasks", r#"{"action":"unknown","data":"x"}"#));
    assert_eq!(parse_status(&raw), 200, "unknown action should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-hit",
        "unknown action should fall through to default cluster"
    );
}

#[test]
fn json_body_rewrites_request_payload() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = load_example_config(
        JSON_BODY_EXAMPLE,
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/chat", JSON_BODY_PAYLOAD));
    assert_eq!(parse_status(&raw), 200, "json_body example should return 200");
    let body = parse_body(&raw);
    let parsed: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("echoed body should be JSON, got {body:?}: {e}"));
    assert_eq!(parsed["model"], "forced-model", "replace /model");
    assert_eq!(parsed["tenant"], "acme", "add /tenant");
    assert_eq!(parsed["prompt"], "hi", "unmatched fields copied");
    assert_eq!(parsed["stream"], serde_json::json!(true), "unmatched /stream copied");
    assert_eq!(parsed["user"], serde_json::json!({"id": 1}), "unmatched /user copied");
    assert_eq!(parsed["original_model"], "old", "extract /model then add from metadata");
    assert!(parsed.get("secret").is_none(), "remove /secret");
    assert!(parsed.get("internal").is_none(), "response_remove /internal");
}

#[test]
fn json_body_rejects_invalid_json() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = load_example_config(
        JSON_BODY_EXAMPLE,
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/chat", "not-json"));
    assert_eq!(parse_status(&raw), 400, "on_invalid reject should return 400");
}
