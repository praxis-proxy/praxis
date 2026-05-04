// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Smoke tests.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, simple_proxy_yaml, start_backend, start_proxy, wait_for_tcp};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn server_starts_and_serves_request() {
    let backend_port = start_backend("smoke");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "proxy must return 200 for valid request");
    assert_eq!(body, "smoke", "response body must match backend");
}

#[test]
fn health_endpoints_return_200() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let admin_port = free_port();

    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
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
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let admin_addr = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin_addr);

    let (healthy_status, _) = http_get(&admin_addr, "/healthy", None);
    let (ready_status, _) = http_get(&admin_addr, "/ready", None);

    assert_eq!(healthy_status, 200, "/healthy must return 200");
    assert_eq!(ready_status, 200, "/ready must return 200");
}

#[test]
fn http_round_trip_preserves_body() {
    let backend_port = start_backend("hello from backend");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/anything", None);
    assert_eq!(status, 200, "round-trip must return 200");
    assert_eq!(body, "hello from backend", "response body must match backend");
}

#[test]
fn static_response_without_upstream() {
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
      - filter: static_response
        status: 200
        body: "static reply"
        headers:
          - name: "Content-Type"
            value: "text/plain"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "static response must return 200");
    assert_eq!(body, "static reply", "static response body must match config");
}

#[test]
fn invalid_config_rejected_at_parse_time() {
    let result = Config::from_yaml("clusters: []");
    assert!(result.is_err(), "config with no listeners should fail to parse");
}

#[test]
fn unknown_filter_chain_rejected() {
    let yaml = r#"
listeners:
  - name: default
    address: "127.0.0.1:0"
    filter_chains:
      - nonexistent
"#;
    let config = Config::from_yaml(yaml);

    match config {
        Err(_) => {},
        Ok(mut cfg) => {
            assert!(
                cfg.validate().is_err(),
                "referencing unknown chain should produce \
                 a validation error"
            );
        },
    }
}

#[test]
fn tcp_proxy_round_trip() {
    let echo_port = start_tcp_echo_server();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: tcp-test
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    upstream: "127.0.0.1:{echo_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    std::thread::spawn(move || {
        praxis::run_server(config, None);
    });

    let proxy_addr = format!("127.0.0.1:{proxy_port}");
    wait_for_tcp(&proxy_addr);

    let mut stream = TcpStream::connect(&proxy_addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

    let payload = b"smoke test payload";
    stream.write_all(payload).unwrap();

    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], payload, "TCP echo response did not match sent payload");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Start a raw TCP echo server that reads bytes and writes
/// them back.
fn start_tcp_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        },
                    }
                }
            });
        }
    });

    port
}
