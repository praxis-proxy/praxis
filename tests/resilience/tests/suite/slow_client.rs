// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for slow-client (slowloris-style) and mid-response backend failure scenarios.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn slow_client_headers_eventually_timeout() {
    let backend_port = start_backend("timeout-ok");
    let proxy_port = free_port();
    let yaml = downstream_timeout_yaml(proxy_port, backend_port, 500);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let mut stream = TcpStream::connect(proxy.addr()).expect("TCP connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let request = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10000\r\n\r\npartial";
    stream
        .write_all(request.as_bytes())
        .expect("write request with partial body");

    let start = Instant::now();
    let mut buf = [0_u8; 4096];
    let _result = stream.read(&mut buf);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(3),
        "slow client with downstream read timeout should not hang; took {elapsed:?}"
    );

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 200,
        "proxy should remain healthy after slow client; got {status}"
    );
    assert_eq!(body, "timeout-ok", "proxy should serve new requests normally");
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
