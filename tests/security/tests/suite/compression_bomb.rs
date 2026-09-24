// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Compression-bomb attack-vector tests.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, parse_status, start_gzip_encoded_backend, start_proxy,
};

/// Precomputed gzip of 1 MiB of zero bytes (~1 KiB compressed).
const GZIP_1MB_ZEROS: &[u8] = include_bytes!("../../fixtures/gzip_1mb_zeros.gz");

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn gzip_compression_bomb_from_upstream_handled_safely() {
    let backend = start_gzip_encoded_backend(GZIP_1MB_ZEROS.to_vec());
    let proxy_port = free_port();
    let yaml = compression_proxy_yaml(proxy_port, backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Accept-Encoding: identity\r\n\
         Connection: close\r\n\
         \r\n",
    );
    let status = parse_status(&raw);

    // Proxy may pass through the compressed body, reject, or error — but must
    // not hang or expand into an unbounded in-memory bomb during the test.
    assert!(
        status == 200 || status == 400 || status == 413 || status == 502 || status == 0,
        "gzip bomb upstream must be handled safely (got {status})"
    );
    assert_ne!(status, 500, "must not crash with 500");
    assert!(
        raw.len() < 2_000_000,
        "response must not expand a 1MiB gzip bomb unboundedly (len={})",
        raw.len()
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn compression_proxy_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: compression
        min_size_bytes: 1
        gzip:
          enabled: true
          level: 1
        content_types:
          - "text/"
          - "application/"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}
