// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Runtime SSRF protection tests.
//!
//! Verifies that the TCP proxy rejects connections to private/reserved
//! IP addresses at runtime when `allow_private_upstreams` is not set,
//! even when `allow_private_endpoints` permits them at config time.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, start_full_proxy, start_tcp_tagged_backend, wait_for_tcp};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn tcp_proxy_rejects_private_upstream_at_runtime() {
    let backend_port = start_tcp_tagged_backend("ssrf-target");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: tcp
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    cluster: backend
    filter_chains: [main]

insecure_options:
  allow_private_endpoints: true

clusters:
  - name: backend
    endpoints:
      - "127.0.0.1:{backend_port}"

filter_chains:
  - name: main
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("should connect to proxy listener");
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    drop(stream.write_all(b"hello"));

    let mut buf = vec![0_u8; 128];
    let n = stream.read(&mut buf).unwrap_or(0);
    assert_eq!(
        n, 0,
        "proxy should close connection without forwarding to private upstream, got {n} bytes",
    );
}

#[test]
fn tcp_proxy_allows_private_upstream_with_override() {
    let backend_port = start_tcp_tagged_backend("allowed");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: tcp
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    cluster: backend
    filter_chains: [main]

insecure_options:
  allow_private_endpoints: true
  allow_private_upstreams: true

clusters:
  - name: backend
    endpoints:
      - "127.0.0.1:{backend_port}"

filter_chains:
  - name: main
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("should connect to proxy listener");
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    stream.write_all(b"hello").unwrap();

    let mut buf = vec![0_u8; 128];
    let n = stream.read(&mut buf).expect("should receive data from backend");
    assert!(n > 0, "with allow_private_upstreams, proxy should forward to backend");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains("hello"),
        "response should contain forwarded payload, got: {resp}"
    );
}
