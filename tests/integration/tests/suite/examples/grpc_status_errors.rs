// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the gRPC Trailers-Only error example configuration.

use std::collections::HashMap;

use praxis_core::config::Config;
use praxis_test_utils::{
    GrpcBackend, free_port, h2c_grpc_call, http_send, parse_status, start_grpc_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Load the example config, pointing it at `backend_port`.
fn example(proxy_port: u16, backend_port: u16) -> Config {
    super::load_example_config(
        "transformation/grpc-status-errors.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:50051", backend_port)]),
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn a_route_miss_becomes_unimplemented() {
    let backend = start_grpc_backend(GrpcBackend::ok());
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));

    // No route matches /other.Svc, so the proxy answers 404 itself.
    let result = h2c_grpc_call(proxy.addr(), "/other.Svc/Method", &[]);

    assert_eq!(result.status, 200, "gRPC reports failures as HTTP 200");
    assert_eq!(
        result.grpc_header("grpc-status").as_deref(),
        Some("12"),
        "a route miss is UNIMPLEMENTED: {:?}",
        result.headers
    );
    assert!(
        result.end_stream,
        "a Trailers-Only response must end the stream on its header block; \
         without END_STREAM a gRPC client reports the call as broken"
    );
    assert_eq!(
        result.headers.get("content-type").and_then(|value| value.to_str().ok()),
        Some("application/grpc"),
        "the response should be typed as gRPC"
    );
}

#[test]
fn an_unreachable_upstream_becomes_unavailable() {
    // A port with nothing behind it: the proxy's own 502.
    let dead_port = free_port();
    let proxy_port = free_port();
    let mut config = example(proxy_port, dead_port);
    // The example's readiness probe needs a live listener, not a live
    // backend, so start the proxy without waiting on the upstream.
    config.insecure_options.allow_private_endpoints = true;
    let proxy = start_proxy(&config);

    let result = h2c_grpc_call(proxy.addr(), "/pkg.Svc/Method", &[]);

    assert_eq!(
        result.grpc_header("grpc-status").as_deref(),
        Some("14"),
        "an unreachable upstream is UNAVAILABLE: {:?}",
        result.headers
    );
    assert!(result.end_stream, "the error must be a Trailers-Only response");
    assert!(
        result.grpc_header("grpc-message").is_some(),
        "the proxy's error text should reach the client as grpc-message"
    );
}

#[test]
fn the_request_codec_is_echoed_on_errors() {
    let backend = start_grpc_backend(GrpcBackend::ok());
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));

    let result = h2c_grpc_call(
        proxy.addr(),
        "/other.Svc/Method",
        &[("content-type", "application/grpc+json")],
    );

    assert_eq!(
        result.headers.get("content-type").and_then(|value| value.to_str().ok()),
        Some("application/grpc+json"),
        "content_type: echo should answer in the request's codec"
    );
}

#[test]
fn non_grpc_requests_keep_ordinary_http_errors() {
    let backend = start_grpc_backend(GrpcBackend::ok());
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));

    let raw = http_send(
        proxy.addr(),
        "GET /other/path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(
        parse_status(&raw),
        404,
        "a plain HTTP client should still get a real 404: {raw}"
    );
    assert!(
        !raw.to_ascii_lowercase().contains("grpc-status"),
        "non-gRPC traffic must not be given a gRPC envelope: {raw}"
    );
}

#[test]
fn a_successful_call_is_not_rewritten() {
    let backend = start_grpc_backend(GrpcBackend::ok().body(b"\x00\x00\x00\x00\x02hi".as_slice()));
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));

    let result = h2c_grpc_call(proxy.addr(), "/pkg.Svc/Method", &[]);

    assert_eq!(result.status, 200, "the call should succeed");
    assert_eq!(
        result.grpc_header("grpc-status").as_deref(),
        Some("0"),
        "the backend's own OK status should pass through untouched"
    );
    assert!(
        !result.end_stream,
        "a real response has a body, so its header block must not end the stream"
    );
}
