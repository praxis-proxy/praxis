// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Highly compressed upstream bodies remain encoded during pass-through.

use praxis_core::config::Config;
use praxis_test_utils::{free_port, parse_header, parse_status, start_gzip_encoded_backend, start_proxy};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Gzip of 1,000,000 zero bytes, stored in 1,003 compressed bytes.
const GZIP_1MB_ZEROS: &[u8] = include_bytes!("../../fixtures/gzip_1mb_zeros.gz");

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn highly_compressed_upstream_body_passes_through_unchanged() {
    let backend = start_gzip_encoded_backend(GZIP_1MB_ZEROS.to_vec());
    let proxy_port = free_port();
    let yaml = compression_proxy_yaml(proxy_port, backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = super::test_utils::send_bytes(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Accept-Encoding: identity\r\n\
         Connection: close\r\n\
         \r\n",
    );
    let header_end = raw
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .expect("response headers")
        + 4;
    let headers = std::str::from_utf8(&raw[..header_end]).expect("headers must be UTF-8");
    assert_eq!(parse_status(headers), 200, "encoded upstream response must succeed");
    assert_eq!(
        parse_header(headers, "content-encoding").as_deref(),
        Some("gzip"),
        "gzip must not be decoded"
    );
    assert_eq!(
        parse_header(headers, "content-length"),
        Some(GZIP_1MB_ZEROS.len().to_string()),
        "length must describe compressed bytes"
    );
    assert_eq!(
        &raw[header_end..],
        GZIP_1MB_ZEROS,
        "binary gzip payload must be forwarded unchanged"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Enable compression while testing preservation of an already encoded response.
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
