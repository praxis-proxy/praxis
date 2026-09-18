// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Upstream HTTP/2 (`clusters[].http.version`) end-to-end tests.
//!
//! gRPC upstreams speak HTTP/2 only, and response trailers — which carry
//! `grpc-status` — exist on no other version. These tests pin that the
//! `h2` setting actually changes the upstream leg, and that the default
//! stays HTTP/1.1.

use praxis_core::config::Config;
use praxis_test_utils::{
    GrpcBackend, free_port, http_send, parse_status, start_backend_with_shutdown, start_grpc_backend, start_proxy,
};

/// Build a proxy config pointing at `backend_port` with the given
/// upstream HTTP version.
fn config_for(proxy_port: u16, backend_port: u16, version: &str) -> Config {
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
            http:
              version: {version}
insecure_options:
  allow_private_endpoints: true
"#
    );
    Config::from_yaml(&yaml).expect("config should parse")
}

#[test]
fn h2_upstream_reaches_an_http2_only_backend() {
    let backend = start_grpc_backend(GrpcBackend::ok().body(b"\x00\x00\x00\x00\x02hi".as_slice()));
    let proxy_port = free_port();
    let config = config_for(proxy_port, backend.port(), "h2");
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /pkg.Svc/Method HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/grpc\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(
        parse_status(&raw),
        200,
        "an HTTP/2-only backend should be reachable with http.version: h2, got: {raw}"
    );
}

#[test]
fn default_upstream_cannot_reach_an_http2_only_backend() {
    let backend = start_grpc_backend(GrpcBackend::ok());
    let proxy_port = free_port();
    let config = config_for(proxy_port, backend.port(), "h1");
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /pkg.Svc/Method HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/grpc\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );

    assert_ne!(
        parse_status(&raw),
        200,
        "an HTTP/1.1 upstream leg cannot talk to an HTTP/2-only backend; \
         this test guards that h2 is what makes the other test pass"
    );
}

#[test]
fn auto_upstream_falls_back_to_http1_over_plaintext() {
    let backend = start_backend_with_shutdown("h1-backend");
    let proxy_port = free_port();
    let config = config_for(proxy_port, backend.port(), "auto");
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(
        parse_status(&raw),
        200,
        "auto has no plaintext negotiation mechanism, so it must stay on HTTP/1.1: {raw}"
    );
}
