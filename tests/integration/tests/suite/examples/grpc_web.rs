// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the gRPC-Web translation example configuration.
//!
//! The point of the filter is that a browser-shaped call reaches a
//! gRPC backend and gets its status back in the body, so these drive
//! it the way a browser would — over HTTP/1.1, with no access to
//! trailers — and read the status out of the response bytes.

use std::collections::HashMap;

use base64::Engine as _;
use praxis_core::config::Config;
use praxis_test_utils::{GrpcBackend, free_port, http_send, parse_body, parse_status, start_grpc_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn a_binary_grpc_web_call_gets_its_status_in_the_body() {
    let backend = start_grpc_backend(
        GrpcBackend::status(5)
            .message("no such user")
            .body(b"\x00\x00\x00\x00\x02hi".as_slice()),
    );
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));

    let raw = http_send(proxy.addr(), &grpc_web_request("application/grpc-web+proto", ""));

    assert_eq!(parse_status(&raw), 200, "the call should reach the backend: {raw}");
    assert_eq!(
        header_value(&raw, "content-type").as_deref(),
        Some("application/grpc-web+proto"),
        "the response should be typed as gRPC-Web, not native gRPC: {raw}"
    );
    let body = parse_body(&raw);
    assert!(
        body.contains("grpc-status: 5"),
        "the trailer must arrive in the body, since a browser cannot read HTTP trailers: {body:?}"
    );
    assert!(
        body.contains("grpc-message: no such user"),
        "the message should survive the translation: {body:?}"
    );
    assert!(
        !raw.to_ascii_lowercase().contains("\ngrpc-status:"),
        "the status must not also be left as an HTTP trailer: {raw}"
    );
}

#[test]
fn a_successful_call_carries_status_zero() {
    let backend = start_grpc_backend(GrpcBackend::ok().body(b"\x00\x00\x00\x00\x02hi".as_slice()));
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));

    let raw = http_send(proxy.addr(), &grpc_web_request("application/grpc-web+proto", ""));
    let body = parse_body(&raw);

    assert!(
        body.contains("hi"),
        "the message frame should be forwarded verbatim: {body:?}"
    );
    assert!(
        body.contains("grpc-status: 0"),
        "a successful call still needs its status frame: {body:?}"
    );
}

#[test]
fn a_text_call_is_decoded_upstream_and_re_encoded_downstream() {
    let backend = start_grpc_backend(GrpcBackend::ok().body(b"\x00\x00\x00\x00\x02hi".as_slice()));
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));

    let encoded_request = base64::engine::general_purpose::STANDARD.encode(b"\x00\x00\x00\x00\x00");
    let raw = http_send(
        proxy.addr(),
        &grpc_web_request("application/grpc-web-text", &encoded_request),
    );

    assert_eq!(parse_status(&raw), 200, "the call should succeed: {raw}");
    let body = parse_body(&raw);
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .unwrap_or_else(|error| panic!("the -text response must be valid base64 ({error}): {body:?}"));
    let text = String::from_utf8_lossy(&decoded);
    assert!(
        text.contains("grpc-status: 0"),
        "the decoded stream should carry the trailer frame: {text:?}"
    );
    assert!(text.contains("hi"), "and the message frame: {text:?}");
}

#[test]
fn a_trailers_only_error_keeps_its_status_in_the_headers() {
    // A single END_STREAM header block with the status and no body.
    // There is no body phase to append a frame to, and none is needed:
    // gRPC-Web clients read the status off the headers in this case.
    let backend = start_grpc_backend(GrpcBackend::status(7).message("denied").trailers_only());
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));

    let raw = http_send(proxy.addr(), &grpc_web_request("application/grpc-web+proto", ""));

    assert_eq!(
        header_value(&raw, "grpc-status").as_deref(),
        Some("7"),
        "the status must survive to the client: {raw}"
    );
    assert!(
        !parse_body(&raw).contains("grpc-status: 2"),
        "a real status must never be overwritten by the synthesized UNKNOWN: {raw}"
    );
}

#[test]
fn non_grpc_web_traffic_is_untouched() {
    let backend = start_grpc_backend(GrpcBackend::ok().body(b"\x00\x00\x00\x00\x02hi".as_slice()));
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));

    // A native gRPC client needs no translation and must not get a
    // trailer frame appended to its body.
    let raw = http_send(proxy.addr(), &grpc_web_request("application/grpc", ""));

    assert_eq!(parse_status(&raw), 200, "native gRPC should pass through: {raw}");
    assert!(
        !parse_body(&raw).contains("grpc-status:"),
        "a native gRPC client reads trailers itself: {raw}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Load the example config, pointing it at `backend_port`.
fn example(proxy_port: u16, backend_port: u16) -> Config {
    super::load_example_config(
        "payload-processing/grpc-web.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:50051", backend_port)]),
    )
}

/// Build a gRPC-Web request with the given content type and body.
fn grpc_web_request(content_type: &str, body: &str) -> String {
    format!(
        "POST /pkg.Svc/Method HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        len = body.len(),
    )
}

/// A header value from a raw HTTP/1.1 response.
fn header_value(raw: &str, name: &str) -> Option<String> {
    raw.lines()
        .take_while(|line| !line.trim().is_empty())
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _value)| key.trim().eq_ignore_ascii_case(name))
        .map(|(_key, value)| value.trim().to_owned())
}
