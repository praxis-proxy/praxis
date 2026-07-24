// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the `credential_injection` example config.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_send, parse_body, parse_status, start_backend_with_shutdown, start_header_echo_backend, start_proxy,
};

use super::load_example_config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn credential_injection_injects_bearer_for_provider_a() {
    let provider_guard = start_header_echo_backend();
    let internal_guard = start_backend_with_shutdown("internal");
    let default_guard = start_backend_with_shutdown("default");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/credential-injection.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", provider_guard.port()),
            ("127.0.0.1:3002", internal_guard.port()),
            ("127.0.0.1:3000", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /v1/chat HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "provider-a route should return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("authorization: bearer example-api-key"),
        "provider-a should receive injected Bearer credential, got:\n{body}"
    );
}

#[test]
fn credential_injection_injects_api_key_for_internal() {
    let provider_guard = start_backend_with_shutdown("provider");
    let internal_guard = start_header_echo_backend();
    let default_guard = start_backend_with_shutdown("default");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/credential-injection.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", provider_guard.port()),
            ("127.0.0.1:3002", internal_guard.port()),
            ("127.0.0.1:3000", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /internal/data HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "internal route should return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-api-key: internal-secret-token"),
        "internal cluster should receive injected x-api-key, got:\n{body}"
    );
}

#[test]
fn credential_injection_replaces_client_provided_header() {
    let provider_guard = start_header_echo_backend();
    let internal_guard = start_backend_with_shutdown("internal");
    let default_guard = start_backend_with_shutdown("default");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/credential-injection.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", provider_guard.port()),
            ("127.0.0.1:3002", internal_guard.port()),
            ("127.0.0.1:3000", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /v1/chat HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: spoofed-value\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "request with spoofed auth should return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("authorization: bearer example-api-key"),
        "injected credential should replace client-provided Authorization, got:\n{body}"
    );
    assert!(
        !lower.contains("spoofed-value"),
        "spoofed client credential should not appear in upstream request, got:\n{body}"
    );
}

#[test]
fn credential_injection_skips_unconfigured_cluster() {
    let provider_guard = start_backend_with_shutdown("provider");
    let internal_guard = start_backend_with_shutdown("internal");
    let default_guard = start_header_echo_backend();
    let proxy_port = free_port();
    let config = load_example_config(
        "security/credential-injection.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", provider_guard.port()),
            ("127.0.0.1:3002", internal_guard.port()),
            ("127.0.0.1:3000", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /other HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "default route should return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        !lower.contains("authorization: bearer"),
        "default cluster should not receive injected credentials, got:\n{body}"
    );
}
