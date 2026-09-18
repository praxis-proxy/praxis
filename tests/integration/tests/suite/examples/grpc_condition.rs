// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the gRPC condition predicate example configuration.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_send, parse_body, parse_header, parse_status, start_backend_with_shutdown, start_proxy,
};

/// Load the example config in front of a backend returning `backend-ok`.
fn start(proxy_port: u16) -> (praxis_test_utils::BackendGuard, praxis_core::config::Config) {
    let backend = start_backend_with_shutdown("backend-ok");
    let config = super::load_example_config(
        "pipeline/grpc-condition.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend.port())]),
    );
    (backend, config)
}

#[test]
fn grpc_request_takes_the_gated_branch() {
    let proxy_port = free_port();
    let (_backend, config) = start(proxy_port);
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /pkg.Svc/Method HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/grpc\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "gRPC request should return 200");
    assert_eq!(
        parse_body(&raw),
        "grpc-only",
        "when: grpc: true should run the static_response filter"
    );
    assert!(
        parse_header(&raw, "x-traffic").is_none(),
        "unless: grpc: true should skip the header filter for gRPC traffic"
    );
}

#[test]
fn grpc_codec_suffix_is_still_grpc() {
    let proxy_port = free_port();
    let (_backend, config) = start(proxy_port);
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /pkg.Svc/Method HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/grpc+proto\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(
        parse_body(&raw),
        "grpc-only",
        "application/grpc+proto should satisfy the grpc predicate"
    );
}

#[test]
fn non_grpc_request_is_proxied_and_tagged() {
    let proxy_port = free_port();
    let (_backend, config) = start(proxy_port);
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "non-gRPC request should return 200");
    assert_eq!(
        parse_body(&raw),
        "backend-ok",
        "when: grpc: true should skip the static_response filter for non-gRPC traffic"
    );
    assert_eq!(
        parse_header(&raw, "x-traffic").as_deref(),
        Some("http"),
        "unless: grpc: true should run the header filter for non-gRPC traffic"
    );
}

#[test]
fn grpc_web_is_not_treated_as_grpc() {
    let proxy_port = free_port();
    let (_backend, config) = start(proxy_port);
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /pkg.Svc/Method HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/grpc-web\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(
        parse_body(&raw),
        "backend-ok",
        "gRPC-Web is a distinct protocol and should not satisfy the grpc predicate"
    );
}
