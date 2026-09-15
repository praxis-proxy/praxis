// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the TCP open-connection gauge.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_full_proxy, start_tcp_tagged_backend, wait_for_tcp};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

pub(crate) fn gauge_value(body: &str, listener: &str) -> Option<f64> {
    body.lines()
        .find(|line| {
            line.starts_with("praxis_tcp_active_connections{") && line.contains(&format!("listener=\"{listener}\""))
        })
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse::<f64>().ok())
}

fn proxy_yaml(listener: &str, proxy_port: u16, admin_port: u16, backend_port: u16) -> String {
    format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: {listener}
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    upstream: "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_upstreams: true
"#
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn tcp_active_connections_rises_while_a_session_is_open() {
    let backend_port = start_tcp_tagged_backend("gauge");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = Config::from_yaml(&proxy_yaml("tcp-gauge-rise", proxy_port, admin_port, backend_port)).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let held = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect");

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut body = String::new();
    let mut value = None;
    while std::time::Instant::now() < deadline {
        body = http_get(&admin, "/metrics", None).1;
        value = gauge_value(&body, "tcp-gauge-rise");
        if value == Some(1.0) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        value,
        Some(1.0),
        "gauge should read 1 while one session is open:\n{body}"
    );
    drop(held);
}

#[test]
fn tcp_active_connections_returns_to_zero_after_close() {
    let backend_port = start_tcp_tagged_backend("drain");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = Config::from_yaml(&proxy_yaml("tcp-gauge-drain", proxy_port, admin_port, backend_port)).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(b"SELECT 1").expect("TCP write");
    stream.shutdown(std::net::Shutdown::Write).expect("shutdown write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("TCP read");
    drop(stream);

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut body = String::new();
    let mut value = None;
    while std::time::Instant::now() < deadline {
        body = http_get(&admin, "/metrics", None).1;
        value = gauge_value(&body, "tcp-gauge-drain");
        if value == Some(0.0) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        value,
        Some(0.0),
        "gauge must drain to zero after the session closes; a leak here means the guard is not dropped:\n{body}"
    );
}
