// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the `guardrails` example config.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_send, parse_status, start_backend_with_shutdown, start_proxy};

use super::load_example_config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn guardrails_example_pii_ssn_in_body_is_blocked() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/guardrails.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    // Body contains an SSN; the PII body rule should fire regardless of the
    // negate rule also being present.
    let payload = r#"{"ssn":"123-45-6789"}"#;
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nX-Authorized: trusted-client\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(parse_status(&raw), 403, "SSN in body should be rejected by PII rule");
}

#[test]
fn guardrails_example_pii_credit_card_in_body_is_blocked() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/guardrails.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let payload = r#"{"card":"4111-1111-1111-1111"}"#;
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nX-Authorized: trusted-client\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(
        parse_status(&raw),
        403,
        "credit card in body should be rejected by PII rule"
    );
}

#[test]
fn guardrails_example_pii_in_secret_header_is_blocked() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/guardrails.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    // SSN sent in X-Secret header should be blocked regardless of clean body.
    let payload = r#"{"key":"value"}"#;
    let raw = http_send(
        proxy.addr(),
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nX-Authorized: trusted-client\r\nX-Secret: 123-45-6789\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert_eq!(
        parse_status(&raw),
        403,
        "SSN in X-Secret header should be rejected by PII rule"
    );
}
