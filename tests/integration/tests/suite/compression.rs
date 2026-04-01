//! Integration tests for the `compression` filter.

use praxis_core::config::Config;
use praxis_test_utils::Backend;

use crate::common::{free_port, http_send, parse_header, parse_status, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn compression_filter_is_accepted_in_pipeline() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: compression
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: backend
  - filter: load_balancer
    clusters:
      - name: backend
        endpoints:
          - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(
        parse_status(&raw),
        200,
        "compression filter in pipeline should not break basic proxying"
    );
}

#[test]
fn compression_with_custom_level() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: compression
    level: 3
    min_size_bytes: 1
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: backend
  - filter: load_balancer
    clusters:
      - name: backend
        endpoints:
          - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(
        parse_status(&raw),
        200,
        "compression filter with custom level should proxy successfully"
    );
}

#[test]
fn compression_with_algorithm_config() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: compression
    level: 4
    gzip:
      enabled: true
      level: 6
    brotli:
      enabled: false
    zstd:
      enabled: true
      level: 3
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: backend
  - filter: load_balancer
    clusters:
      - name: backend
        endpoints:
          - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(
        parse_status(&raw),
        200,
        "compression filter with per-algorithm config should proxy successfully"
    );
}

#[test]
fn compression_in_filter_chain() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: compression
        level: 6
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(
        parse_status(&raw),
        200,
        "compression filter in filter_chain should work"
    );
}

#[test]
fn no_compression_without_accept_encoding() {
    let backend_port = start_backend("uncompressed-response");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: compression
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: backend
  - filter: load_balancer
    clusters:
      - name: backend
        endpoints:
          - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(parse_status(&raw), 200, "should return 200 without Accept-Encoding");
    let encoding = parse_header(&raw, "content-encoding");
    assert!(
        encoding.is_none(),
        "response should not be compressed without Accept-Encoding header"
    );
}

#[test]
fn compression_with_accept_encoding_gzip() {
    let body = "a".repeat(1024);
    let backend_port = Backend::fixed(body.leak()).header("Content-Type", "text/plain").start();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: compression
    min_size_bytes: 1
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: backend
  - filter: load_balancer
    clusters:
      - name: backend
        endpoints:
          - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let headers = send_and_read_headers(
        &addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    );
    assert!(
        headers.starts_with("HTTP/1.1 200"),
        "should return 200 with Accept-Encoding: gzip, got: {headers}"
    );
    let encoding = parse_header(&headers, "content-encoding");
    assert_eq!(
        encoding.as_deref(),
        Some("gzip"),
        "response should have Content-Encoding: gzip when client accepts gzip"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Send an HTTP request and read only the response headers
/// (up to `\r\n\r\n`). This avoids reading compressed body
/// bytes that would fail UTF-8 string conversion.
fn send_and_read_headers(addr: &str, request: &str) -> String {
    use std::{
        io::{Read, Write},
        net::TcpStream,
        time::Duration,
    };

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(request.as_bytes()).unwrap();

    let mut data = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
        if data.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(data.len(), |p| p + 4);
    String::from_utf8_lossy(&data[..header_end]).into_owned()
}
