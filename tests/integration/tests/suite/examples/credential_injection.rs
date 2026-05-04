// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Tests for the credential injection example configuration.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_send, parse_body, parse_status, start_header_echo_backend_with_shutdown};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn credential_injection_config_parses() {
    let config = super::load_example_config(
        "ai/credential-injection.yaml",
        29900,
        HashMap::from([("127.0.0.1:3000", 29901_u16), ("127.0.0.1:3001", 29902_u16)]),
    );

    assert_eq!(config.listeners.len(), 1, "should have 1 listener");
    assert_eq!(&*config.listeners[0].name, "gateway", "listener name should be gateway");
}

#[test]
fn credential_injection_injects_bearer_token() {
    let backend_guard = start_header_echo_backend_with_shutdown();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let config = super::load_example_config(
        "ai/credential-injection.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", backend_port)]),
    );

    let proxy = praxis_test_utils::start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET /v1/chat HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "should return 200");
    let body = parse_body(&raw);
    assert!(
        body.contains("Bearer sk-example-openai-key"),
        "upstream should receive Bearer token in Authorization header: {body}"
    );
}

#[test]
fn credential_injection_strips_client_credential() {
    let backend_guard = start_header_echo_backend_with_shutdown();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let config = super::load_example_config(
        "ai/credential-injection.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", backend_port)]),
    );

    let proxy = praxis_test_utils::start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET /v1/chat HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: client-spoofed-token\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "should return 200");
    let body = parse_body(&raw);
    assert!(
        !body.contains("client-spoofed-token"),
        "client credential should be stripped: {body}"
    );
    assert!(
        body.contains("Bearer sk-example-openai-key"),
        "server credential should be injected: {body}"
    );
}

#[test]
fn credential_injection_internal_cluster() {
    let backend_guard = start_header_echo_backend_with_shutdown();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let config = super::load_example_config(
        "ai/credential-injection.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", backend_port)]),
    );

    let proxy = praxis_test_utils::start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET /internal/api HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "should return 200");
    let body = parse_body(&raw);
    assert!(
        body.contains("internal-secret"),
        "upstream should receive x-api-key for internal cluster: {body}"
    );
}
