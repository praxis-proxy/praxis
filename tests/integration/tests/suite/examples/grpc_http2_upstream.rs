// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the gRPC HTTP/2 upstream example configuration.

use std::collections::HashMap;

use praxis_test_utils::{GrpcBackend, free_port, http_send, parse_status, start_grpc_backend, start_proxy};

/// A gRPC request, whose upstream leg must be HTTP/2.
const GRPC_REQUEST: &str = "POST /pkg.Svc/Method HTTP/1.1\r\n\
     Host: localhost\r\n\
     Content-Type: application/grpc\r\n\
     Content-Length: 0\r\n\
     Connection: close\r\n\r\n";

#[test]
fn grpc_call_reaches_an_http2_only_backend() {
    let backend = start_grpc_backend(GrpcBackend::ok().body(b"\x00\x00\x00\x00\x02hi".as_slice()));
    let proxy_port = free_port();
    let config = super::load_example_config(
        "protocols/grpc-http2-upstream.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:50051", backend.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), GRPC_REQUEST);

    assert_eq!(
        parse_status(&raw),
        200,
        "the example's h2 upstream must reach an HTTP/2-only gRPC backend: {raw}"
    );
}

#[test]
fn removing_the_h2_setting_breaks_the_grpc_upstream() {
    // The example is only meaningful if `http.version: h2` is what makes
    // it work: with the default HTTP/1.1 leg the same backend must be
    // unreachable.
    let backend = start_grpc_backend(GrpcBackend::ok());
    let proxy_port = free_port();
    let path = praxis_test_utils::example_config_path("protocols/grpc-http2-upstream.yaml");
    let yaml = std::fs::read_to_string(&path).expect("read example config");
    let downgraded = yaml.replace("version: h2", "version: h1");
    assert_ne!(yaml, downgraded, "the example must configure an h2 upstream");
    let patched = praxis_test_utils::patch_yaml(
        &downgraded,
        proxy_port,
        &HashMap::from([("127.0.0.1:50051", backend.port())]),
    );
    let config = praxis_core::config::Config::from_yaml(&praxis_test_utils::allow_loopback_endpoints(&patched))
        .expect("downgraded example should parse");
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), GRPC_REQUEST);

    assert_ne!(
        parse_status(&raw),
        200,
        "without http.version: h2 the HTTP/2-only backend must be unreachable"
    );
}
