// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Response header normalization and malformed upstream field rejection.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, parse_body, parse_header, parse_status, simple_proxy_yaml, start_malicious_response_header_backend,
    start_proxy,
};

use super::test_utils::{send_text, status_lines};

#[test]
fn upstream_obs_fold_does_not_inject_a_response_header() {
    let raw = response_with_header(b"X-Safe: ok\r\n X-Injected: evil".to_vec());
    assert_eq!(parse_status(&raw), 200, "obs-fold response should be normalized");
    assert_eq!(
        parse_header(&raw, "x-safe").as_deref(),
        Some("ok X-Injected: evil"),
        "continuation must stay in X-Safe"
    );
    assert!(
        parse_header(&raw, "x-injected").is_none(),
        "folding must not create a separate header: {raw}"
    );
    assert_eq!(parse_body(&raw), "ok", "body must preserve upstream framing");
    assert_eq!(status_lines(&raw), 1, "only one response may be forwarded");
}

#[test]
fn upstream_set_cookie_bare_cr_injection_rejected() {
    let raw = response_with_header(b"Set-Cookie: session=abc\rSet-Cookie: injected=1".to_vec());
    assert_eq!(parse_status(&raw), 502, "malformed upstream cookie must be rejected");
    assert!(
        parse_header(&raw, "set-cookie").is_none(),
        "rejection must not forward either cookie: {raw}"
    );
    assert_eq!(
        status_lines(&raw),
        1,
        "rejection must not split into multiple responses"
    );
}

#[test]
fn upstream_response_control_characters_rejected() {
    for byte in (0x01_u8..=0x08).chain(0x0E..=0x1F) {
        let mut header = b"X-Ctl: before".to_vec();
        header.push(byte);
        header.extend_from_slice(b"after");
        let raw = response_with_header(header);
        assert_eq!(parse_status(&raw), 502, "upstream CTL {byte:#x} must be rejected");
        assert!(
            parse_header(&raw, "x-ctl").is_none(),
            "CTL header must not reach the client: {raw}"
        );
        assert_eq!(status_lines(&raw), 1, "CTL rejection must produce one response");
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Observe the same malformed response through a complete, error-aware read.
fn response_with_header(header: Vec<u8>) -> String {
    let backend = start_malicious_response_header_backend(header);
    let config = Config::from_yaml(&simple_proxy_yaml(free_port(), backend.port())).unwrap();
    let proxy = start_proxy(&config);
    send_text(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
}
