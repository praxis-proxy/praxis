// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for payload-processing example
//! configurations not covered by `payload_processing.rs`.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_get, http_send, json_post, parse_body, parse_status, start_backend_with_shutdown, start_proxy,
};

use super::load_example_config;

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
    let processor_guard = start_backend_with_shutdown("processed");
    let default_guard = start_backend_with_shutdown("default");
    let proxy_port = free_port();
    let config = load_example_config(
        "payload-processing/stream-buffer.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", processor_guard.port()),
            ("127.0.0.1:3002", processor_guard.port()),
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
    let proxy_port = free_port();
    let config = load_example_config(
        "payload-processing/stream-buffer.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", default_guard.port()),
            ("127.0.0.1:3002", default_guard.port()),
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
    let proxy_port = free_port();
    let config = load_example_config(
        "payload-processing/stream-buffer.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", default_guard.port()),
            ("127.0.0.1:3002", default_guard.port()),
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
