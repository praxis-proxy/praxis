// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for slow-client (slowloris-style) and mid-response backend failure scenarios.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, http_post, parse_status, start_echo_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn slow_client_body_eventually_timeout() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let yaml = downstream_timeout_yaml(proxy_port, backend.port(), 500);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let mut stream = TcpStream::connect(proxy.addr()).expect("TCP connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");

    let request = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10000\r\n\r\npartial";
    stream
        .write_all(request.as_bytes())
        .expect("write request with partial body");

    let start = Instant::now();
    let mut raw = Vec::new();
    let read = stream.read_to_end(&mut raw);
    let elapsed = start.elapsed();
    let response = String::from_utf8_lossy(&raw);

    assert!(
        matches!(read, Ok(len) if len > 0),
        "proxy should answer the stalled upload and then close the connection, got {read:?}"
    );
    assert!(
        elapsed < Duration::from_secs(4),
        "the 500 ms downstream read timeout should cut the upload off well before the echo backend's own 5 s \
         read timeout; took {elapsed:?}"
    );
    assert_eq!(
        parse_status(&response),
        400,
        "a downstream body read timeout should get the proxy's 400, not a forwarded backend response: {response}"
    );

    let (status, body) = http_post(proxy.addr(), "/", "after-slow-client");
    assert_eq!(
        status, 200,
        "proxy should remain healthy after slow client; got {status}"
    );
    assert_eq!(
        body, "after-slow-client",
        "proxy should echo new request bodies normally"
    );
}

#[test]
fn backend_mid_response_failure_returns_502() {
    let partial_port = start_mid_response_drop_backend();
    let proxy_port = free_port();
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
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{partial_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 502, "backend dropping mid-headers should produce 502");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a YAML config with a downstream read timeout on the listener.
fn downstream_timeout_yaml(proxy_port: u16, backend_port: u16, timeout_ms: u64) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    downstream_read_timeout_ms: {timeout_ms}
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
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

/// Start a backend that sends the status line and a content-length
/// header but drops the connection before finishing the response
/// headers (no blank-line separator or body).
fn start_mid_response_drop_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = stream;
                drop(s.set_read_timeout(Some(Duration::from_secs(5))));
                let mut buf = [0_u8; 4096];
                let _bytes = s.read(&mut buf);
                let _sent = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n");
                let _flushed = s.flush();
                drop(s);
            });
        }
    });
    port
}
