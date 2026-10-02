// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the TCP byte-throughput counters.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_full_proxy, start_tcp_tagged_backend, wait_for_tcp};

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

fn counter_value(body: &str, metric: &str, listener: &str) -> Option<f64> {
    body.lines()
        .find(|line| line.starts_with(&format!("{metric}{{")) && line.contains(&format!("listener=\"{listener}\"")))
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse::<f64>().ok())
}

fn wait_for_counter(admin: &str, metric: &str, listener: &str, at_least: f64) -> (Option<f64>, String) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut body = String::new();
    let mut value = None;
    while std::time::Instant::now() < deadline {
        body = http_get(admin, "/metrics", None).1;
        value = counter_value(&body, metric, listener);
        if value.is_some_and(|v| v >= at_least) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    (value, body)
}

fn proxy_yaml(listener: &str, proxy_port: u16, admin_port: u16, backend_port: u16, extra: &str) -> String {
    format!(
        r#"
admin:
  metrics_address: "127.0.0.1:{admin_port}"
listeners:
  - name: {listener}
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    upstream: "127.0.0.1:{backend_port}"
{extra}
insecure_options:
  allow_private_upstreams: true
"#
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn tcp_byte_counters_record_both_directions() {
    let backend_port = start_tcp_tagged_backend("bytes-backend");
    let proxy_port = free_port();
    let admin_port = free_port();
    let listener = "tcp-bytes-both-directions";
    let config = Config::from_yaml(&proxy_yaml(listener, proxy_port, admin_port, backend_port, "")).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let payload = b"SELECT 1 FROM metrics";
    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(payload).expect("TCP write");
    stream.shutdown(std::net::Shutdown::Write).expect("shutdown write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("TCP read");
    drop(stream);

    let sent_bytes = buf.len() as f64;
    let (received, body) = wait_for_counter(
        &admin,
        "praxis_tcp_bytes_received_total",
        listener,
        payload.len() as f64,
    );
    assert_eq!(
        received,
        Some(payload.len() as f64),
        "received counter should equal the bytes the client wrote:\n{body}"
    );

    let (sent, body) = wait_for_counter(&admin, "praxis_tcp_bytes_sent_total", listener, sent_bytes);
    assert_eq!(
        sent,
        Some(sent_bytes),
        "sent counter should equal the bytes the client read back:\n{body}"
    );
}

#[test]
fn tcp_byte_counters_survive_a_session_timeout() {
    let backend_port = start_tcp_tagged_backend("timeout-backend");
    let proxy_port = free_port();
    let admin_port = free_port();
    let listener = "tcp-bytes-session-timeout";
    let config = Config::from_yaml(&proxy_yaml(
        listener,
        proxy_port,
        admin_port,
        backend_port,
        "    tcp_session_timeout_ms: 300",
    ))
    .unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let payload = b"HELLO";
    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(payload).expect("TCP write");
    let mut buf = [0_u8; 64];
    let _read = stream.read(&mut buf);
    std::thread::sleep(Duration::from_millis(600));
    drop(stream);

    let (received, body) = wait_for_counter(
        &admin,
        "praxis_tcp_bytes_received_total",
        listener,
        payload.len() as f64,
    );
    assert_eq!(
        received,
        Some(payload.len() as f64),
        "a session ended by the idle timeout must still report the bytes it forwarded; \
         reading counts from copy_bidirectional's return value would report 0 here:\n{body}"
    );
}
