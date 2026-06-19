// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for proxy behavior when backends are unreachable, slow, or drop connections mid-request.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_post, http_send, parse_status, simple_proxy_yaml, start_backend, start_proxy,
    start_slow_backend,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn dead_backend_returns_502() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, dead_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 502, "dead backend should return 502");
}

#[test]
fn dead_backend_post_returns_502() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, dead_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_post(proxy.addr(), "/", "request body");
    assert_eq!(status, 502, "POST to dead backend should return 502");
}

#[test]
fn connection_drop_backend_returns_502() {
    let drop_port = start_connection_drop_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, drop_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 502, "backend that drops connection should produce 502");
}

#[test]
fn partial_response_backend_returns_502() {
    let partial_port = start_partial_response_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, partial_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 502, "backend sending partial response should produce 502");
}

#[test]
fn slow_backend_with_read_timeout_returns_502() {
    let slow_port = start_slow_backend("slow", Duration::from_secs(5));
    let proxy_port = free_port();
    let yaml = read_timeout_proxy_yaml(proxy_port, slow_port, 500);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let start = Instant::now();
    let (status, _) = http_get(proxy.addr(), "/", None);
    let elapsed = start.elapsed();

    assert_eq!(status, 502, "slow backend with read timeout should return 502");
    assert!(
        elapsed < Duration::from_secs(3),
        "read timeout should fire quickly, not wait for full backend delay; took {elapsed:?}"
    );
}

#[test]
fn slow_backend_with_timeout_filter_returns_504() {
    let slow_port = start_slow_backend("slow-response", Duration::from_millis(300));
    let proxy_port = free_port();
    let yaml = timeout_filter_yaml(proxy_port, slow_port, 100);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 504,
        "backend slower than timeout filter threshold should return 504"
    );
}

#[test]
fn fast_backend_with_timeout_filter_succeeds() {
    let backend_port = start_backend("fast");
    let proxy_port = free_port();
    let yaml = timeout_filter_yaml(proxy_port, backend_port, 5000);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "fast backend within timeout should return 200");
    assert_eq!(body, "fast", "response body should pass through");
}

#[test]
fn repeated_requests_to_dead_backend_all_return_502() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, dead_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    for i in 0..5 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        assert_eq!(
            status, 502,
            "request {i} to dead backend should consistently return 502"
        );
    }
}

#[test]
fn proxy_remains_healthy_after_backend_failures() {
    let dead_port = free_port();
    let live_port = start_backend("alive");
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
          - path_prefix: "/dead/"
            cluster: dead
          - path_prefix: "/"
            cluster: live
      - filter: load_balancer
        clusters:
          - name: dead
            endpoints:
              - "127.0.0.1:{dead_port}"
          - name: live
            endpoints:
              - "127.0.0.1:{live_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/dead/path", None);
    assert_eq!(status, 502, "request to dead cluster should return 502");

    let (status, body) = http_get(proxy.addr(), "/ok", None);
    assert_eq!(
        status, 200,
        "request to live cluster should succeed after dead cluster failure"
    );
    assert_eq!(body, "alive", "live cluster should serve response");
}

#[test]
fn hang_backend_with_read_timeout_returns_error() {
    let hang_port = start_hang_backend();
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
              - "127.0.0.1:{hang_port}"
            read_timeout_ms: 500
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let start = Instant::now();
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let elapsed = start.elapsed();
    let status = parse_status(&raw);

    assert!(
        status == 502 || status == 504,
        "hanging backend with read timeout should produce 502 or 504, got {status}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "read timeout should prevent indefinite hang; took {elapsed:?}"
    );
}

#[test]
fn client_disconnect_during_slow_response_does_not_crash_proxy() {
    let slow_port = start_slow_backend("slow-body", Duration::from_secs(3));
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, slow_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let mut stream = TcpStream::connect(proxy.addr()).expect("TCP connect");
    drop(stream.set_read_timeout(Some(Duration::from_millis(200))));
    let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(request.as_bytes()).expect("write request");
    drop(stream);

    std::thread::sleep(Duration::from_millis(200));

    let live_port = start_backend("still-alive");
    let proxy_port2 = free_port();
    let yaml2 = simple_proxy_yaml(proxy_port2, live_port);
    let config2 = Config::from_yaml(&yaml2).unwrap();
    let proxy2 = start_proxy(&config2);

    let (status, body) = http_get(proxy2.addr(), "/", None);
    assert_eq!(status, 200, "proxy should remain functional after client disconnect");
    assert_eq!(body, "still-alive", "proxy should serve new requests normally");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Start a backend that accepts the connection then
/// immediately closes it without sending a response.
fn start_connection_drop_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0_u8; 1024];
                let _bytes = s.read(&mut buf);
                drop(s);
            });
        }
    });
    port
}

/// Start a backend that reads headers then hangs without
/// ever sending a response.
fn start_hang_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = stream;
                drop(s.set_read_timeout(Some(Duration::from_secs(30))));
                let mut buf = [0_u8; 4096];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {},
                    }
                }
            });
        }
    });
    port
}

/// Start a backend that sends a partial HTTP response
/// (status line only, no headers or body) then drops.
fn start_partial_response_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = stream;
                drop(s.set_read_timeout(Some(Duration::from_secs(5))));
                let mut buf = [0_u8; 4096];
                let _bytes = s.read(&mut buf);
                let _sent = s.write_all(b"HTTP/1.1 200 OK\r\n");
                let _flushed = s.flush();
                drop(s);
            });
        }
    });
    port
}

/// Build a YAML config with a cluster-level read timeout.
fn read_timeout_proxy_yaml(proxy_port: u16, backend_port: u16, read_timeout_ms: u64) -> String {
    format!(
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
              - "127.0.0.1:{backend_port}"
            read_timeout_ms: {read_timeout_ms}
"#
    )
}

/// Build a YAML config with a timeout filter for SLA enforcement.
fn timeout_filter_yaml(proxy_port: u16, backend_port: u16, timeout_ms: u64) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: timeout
        timeout_ms: {timeout_ms}
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
