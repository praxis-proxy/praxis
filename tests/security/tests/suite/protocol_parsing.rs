// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Malformed chunk boundaries, ambiguous framing, and request-target limits.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, parse_body, parse_status, simple_proxy_yaml, start_backend_with_shutdown, start_echo_backend,
    start_proxy,
};

use super::test_utils::{send_text, status_lines};

#[test]
fn chunked_encoding_non_hex_size_rejected() {
    assert_invalid_chunk("xyz");
}

#[test]
fn chunked_encoding_maximum_size_rejected() {
    assert_invalid_chunk("ffffffffffffffff");
}

#[test]
fn chunked_encoding_overflow_size_rejected() {
    assert_invalid_chunk("1ffffffffffffffff");
}

/// [RFC 9112 Section 6.3] requires closing after a request containing TE and CL.
///
/// [RFC 9112 Section 6.3]: https://datatracker.ietf.org/doc/html/rfc9112#section-6.3
#[test]
fn mixed_chunked_and_content_length_closes_connection() {
    let backend = start_backend_with_shutdown("te-cl");
    let config = Config::from_yaml(&simple_proxy_yaml(free_port(), backend.port())).unwrap();
    let proxy = start_proxy(&config);
    let raw = send_text(
        proxy.addr(),
        "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "TE must determine framing after CL is removed");
    assert_eq!(parse_body(&raw), "te-cl", "only the configured response should arrive");
    assert_eq!(
        status_lines(&raw),
        1,
        "ambiguous framing must yield one response and EOF"
    );
}

#[test]
fn request_target_exceeding_parser_limit_rejected() {
    let backend = start_backend_with_shutdown("ok");
    let config = Config::from_yaml(&simple_proxy_yaml(free_port(), backend.port())).unwrap();
    let proxy = start_proxy(&config);
    let path = format!("/{}", "a".repeat(65_536));
    let raw = send_text(
        proxy.addr(),
        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    );
    assert_eq!(
        parse_status(&raw),
        400,
        "the pinned URI parser rejects a 65,537-byte target"
    );
    assert_eq!(status_lines(&raw), 1, "oversized target must be rejected and closed");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Require a rejection response and peer close, rather than treating timeout as rejection.
fn assert_invalid_chunk(size: &str) {
    let backend = start_echo_backend();
    let config = Config::from_yaml(&simple_proxy_yaml(free_port(), backend.port())).unwrap();
    let proxy = start_proxy(&config);
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{size}\r\nx\r\n0\r\n\r\n"
    );
    let raw = send_text(proxy.addr(), &request);
    assert_eq!(parse_status(&raw), 400, "chunk size {size} must be rejected: {raw}");
    assert_eq!(status_lines(&raw), 1, "invalid chunk must yield one rejection and EOF");
}
