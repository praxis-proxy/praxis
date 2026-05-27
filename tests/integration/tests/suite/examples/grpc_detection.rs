// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for gRPC detection example configuration.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_send, parse_body, parse_status, start_backend_with_shutdown, start_proxy};

#[test]
fn grpc_request_routes_to_grpc_backend() {
    let default_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/grpc-detection.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", default_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/grpc\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "gRPC request should return 200");
    assert_eq!(
        parse_body(&raw),
        "grpc-detected",
        "gRPC request should be detected and get static response"
    );
}

#[test]
fn non_grpc_request_routes_to_default_backend() {
    let default_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/grpc-detection.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", default_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_eq!(parse_status(&raw), 200, "non-gRPC request should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "non-gRPC request should route to default backend"
    );
}
