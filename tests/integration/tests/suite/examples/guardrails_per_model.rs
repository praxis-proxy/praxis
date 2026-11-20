// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the `guardrails-per-model` example config.
//!
//! Proves issue #1091: a body-inspecting `guardrails` filter runs only for the
//! model promoted from the request body, and is skipped for other models.

use std::{collections::HashMap, time::Duration};

use praxis_test_utils::{
    H1Completion, PayloadSpec, free_port, http_send, parse_status, start_backend_with_shutdown, start_counting_backend,
    start_proxy,
};

use super::load_example_config;
use crate::guardrails::{inspection_proxy, post_spec};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn large_per_model_gate_uses_promoted_selector_before_inspecting_tail() {
    let size = 10_485_760; // 10 MiB, the example's merged JSON buffer limit.
    let guarded = PayloadSpec::padded(
        size,
        br#"{"model":"guarded-model","prompt":""#,
        br#" forbidden"}"#,
        b'x',
    )
    .unwrap();
    let other = PayloadSpec::padded(size, br#"{"model":"other-model","prompt":""#, br#" forbidden"}"#, b'x').unwrap();
    assert_eq!(guarded.len(), other.len());
    let backend = start_counting_backend(other.clone(), "other-model", size);
    let config = load_example_config(
        "security/guardrails-per-model.yaml",
        free_port(),
        HashMap::from([("127.0.0.1:3000", backend.port)]),
    );
    let proxy = inspection_proxy(&config);
    assert_eq!(
        post_spec(proxy.addr(), &guarded, 16_384, || {
            assert!(matches!(
                backend.accepted.recv_timeout(Duration::from_millis(100)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
        }),
        Some(403)
    );
    assert!(matches!(
        backend.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    assert_eq!(post_spec(proxy.addr(), &other, 16_384, || {}), Some(200));
    let receipt = backend.receipt.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(
        (receipt.bytes, receipt.verified_bytes, receipt.completion),
        (size, size, Some(H1Completion::ContentLength))
    );
    assert_eq!(receipt.mismatch, None);
    assert!(!receipt.headers.iter().any(|(name, _)| name == "x-praxis-guard-model"));
    backend.join();
}

#[test]
fn per_model_example_rejects_one_byte_above_its_buffer_limit() {
    let oversized = PayloadSpec::padded(
        10_485_761,
        br#"{"model":"other-model","prompt":""#,
        br#" hello"}"#,
        b'x',
    )
    .unwrap();
    let clean = PayloadSpec::padded(64, br#"{"model":"other-model","prompt":""#, br#" hello"}"#, b'x').unwrap();
    let backend = start_counting_backend(clean.clone(), "example", clean.len());
    let config = load_example_config(
        "security/guardrails-per-model.yaml",
        free_port(),
        HashMap::from([("127.0.0.1:3000", backend.port)]),
    );
    let proxy = inspection_proxy(&config);
    assert_eq!(post_spec(proxy.addr(), &oversized, 16_384, || {}), Some(413));
    assert!(matches!(
        backend.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    assert_eq!(post_spec(proxy.addr(), &clean, 16_384, || {}), Some(200));
    let receipt = backend.receipt.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(
        (receipt.verified_bytes, receipt.completion),
        (clean.len(), Some(H1Completion::ContentLength))
    );
    backend.join();
}

fn proxy_for(backend_port: u16, proxy_port: u16) -> praxis_test_utils::ProxyGuard {
    let config = load_example_config(
        "security/guardrails-per-model.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    start_proxy(&config)
}

fn post(addr: &str, payload: &str) -> String {
    http_send(
        addr,
        &format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        ),
    )
}

#[test]
fn guardrails_per_model_guarded_model_forbidden_body_blocked() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let proxy = proxy_for(backend_guard.port(), proxy_port);

    let raw = post(proxy.addr(), r#"{"model":"guarded-model","prompt":"forbidden"}"#);
    assert_eq!(
        parse_status(&raw),
        403,
        "guardrails should block a forbidden body for the guarded model"
    );
}

#[test]
fn guardrails_per_model_guarded_model_clean_body_allowed() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let proxy = proxy_for(backend_guard.port(), proxy_port);

    let raw = post(proxy.addr(), r#"{"model":"guarded-model","prompt":"hello"}"#);
    assert_eq!(
        parse_status(&raw),
        200,
        "a clean body for the guarded model should pass guardrails"
    );
}

#[test]
fn guardrails_per_model_other_model_skips_guardrails() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let proxy = proxy_for(backend_guard.port(), proxy_port);

    // A different model does not match the gate, so guardrails is skipped and
    // the forbidden body reaches the backend.
    let raw = post(proxy.addr(), r#"{"model":"other-model","prompt":"forbidden"}"#);
    assert_eq!(
        parse_status(&raw),
        200,
        "a non-guarded model should skip guardrails even with a forbidden body"
    );
}
