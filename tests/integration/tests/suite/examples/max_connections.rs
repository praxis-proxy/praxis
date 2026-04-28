// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Tests for max connections limiting behavior.

use std::{io::Write, net::TcpStream, time::Duration};

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_send, parse_header, parse_status, start_backend_with_shutdown, start_proxy,
    start_slow_backend,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn max_connections_rejects_excess_http() {
    let slow_port = start_slow_backend("slow", Duration::from_secs(3));
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    max_connections: 2
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
              - "127.0.0.1:{slow_port}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let mut held: Vec<TcpStream> = Vec::new();
    for _ in 0..2 {
        let mut stream = TcpStream::connect(proxy.addr()).expect("TCP connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("set read timeout");
        let request = format!("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).expect("write request");
        held.push(stream);
    }

    std::thread::sleep(Duration::from_millis(200));

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 503, "third request should be rejected with 503");
    let retry_after = parse_header(&raw, "Retry-After");
    assert_eq!(
        retry_after.as_deref(),
        Some("1"),
        "503 response should include Retry-After: 1"
    );

    drop(held);
}

#[test]
fn max_connections_allows_after_release() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    max_connections: 1
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
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "first request should succeed");
    assert_eq!(body, "ok", "first request body should match");

    let (status2, body2) = http_get(proxy.addr(), "/", None);
    assert_eq!(status2, 200, "second request after release should succeed");
    assert_eq!(body2, "ok", "second request body should match");
}

#[test]
fn max_connections_example_config_parses() {
    let proxy_port = free_port();
    let config = super::load_example_config(
        "operations/max-connections.yaml",
        proxy_port,
        std::collections::HashMap::from([("127.0.0.1:3001", free_port())]),
    );
    assert_eq!(
        config.listeners[0].max_connections,
        Some(100),
        "max_connections should be 100"
    );
}
