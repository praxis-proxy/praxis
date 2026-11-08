// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the `guardrails` example config.

use std::{collections::HashMap, time::Duration};

use praxis_test_utils::{
    H1Completion, PayloadSpec, free_port, http_send, parse_status, start_backend_with_shutdown, start_counting_backend,
    start_proxy,
};

use super::load_example_config;
use crate::guardrails::{inspection_proxy, post_spec_with_headers};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn guardrails_example_boundary_and_late_pii() {
    for over in [false, true] {
        let size = if over { 1_048_577 } else { 1_048_576 };
        let bad = PayloadSpec::padded(size, br#"{"padding":""#, br#"","ssn":"123-45-6789"}"#, b'x').unwrap();
        let clean_size = if over { 64 } else { size };
        let clean = PayloadSpec::padded(clean_size, br#"{"padding":""#, br#"","ssn":"123-45-678x"}"#, b'x').unwrap();
        let backend = start_counting_backend(clean.clone(), "example", clean_size);
        let port = free_port();
        let config = load_example_config(
            "security/guardrails.yaml",
            port,
            HashMap::from([("127.0.0.1:3000", backend.port)]),
        );
        let proxy = inspection_proxy(&config);
        let headers = "X-Authorized: trusted-client\r\n";
        let status = post_spec_with_headers(proxy.addr(), &bad, 16_384, headers, || {
            assert!(matches!(
                backend.accepted.recv_timeout(Duration::from_millis(100)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
        });
        assert_eq!(status, Some(if over { 413 } else { 403 }));
        assert!(matches!(
            backend.accepted.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert_eq!(
            post_spec_with_headers(proxy.addr(), &clean, 16_384, headers, || {}),
            Some(200)
        );
        let receipt = backend.receipt.recv_timeout(Duration::from_secs(30)).unwrap();
        assert_eq!(
            (receipt.bytes, receipt.verified_bytes, receipt.completion),
            (clean_size, clean_size, Some(H1Completion::ContentLength))
        );
        assert_eq!(receipt.mismatch, None);
        backend.join();
    }
}

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
