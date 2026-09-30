// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the per-listener downstream keep-alive idle timeout.

use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::TcpStream,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{BackendGuard, ProxyGuard, free_port, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn idle_keepalive_connection_is_closed_after_the_timeout() {
    let (_proxy, addr) = proxy_with_keepalive_timeout(Some(1_000));
    let mut conn = connect(&addr);

    assert_eq!(request(&mut conn, "HTTP/1.1", ""), 200, "first request");
    let idle_for = time_until_closed(&mut conn);

    assert!(
        idle_for >= Duration::from_millis(700) && idle_for <= Duration::from_millis(3_500),
        "an idle keep-alive connection must close about 1 s after its last response, closed after {idle_for:?}"
    );
}

#[test]
fn a_busy_keepalive_connection_stays_open() {
    let (_proxy, addr) = proxy_with_keepalive_timeout(Some(1_000));
    let mut conn = connect(&addr);

    for index in 0..6 {
        assert_eq!(
            request(&mut conn, "HTTP/1.1", ""),
            200,
            "request {index} on one connection, each within the idle timeout"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
}

#[test]
fn connection_close_still_closes_immediately() {
    let (_proxy, addr) = proxy_with_keepalive_timeout(Some(30_000));
    let mut conn = connect(&addr);

    assert_eq!(request(&mut conn, "HTTP/1.1", "Connection: close\r\n"), 200, "request");
    let idle_for = time_until_closed(&mut conn);

    assert!(
        idle_for < Duration::from_millis(500),
        "Connection: close must win over the keep-alive timeout, closed after {idle_for:?}"
    );
}

#[test]
fn http_1_0_without_keepalive_is_still_closed() {
    let (_proxy, addr) = proxy_with_keepalive_timeout(Some(30_000));
    let mut conn = connect(&addr);

    assert_eq!(request(&mut conn, "HTTP/1.0", ""), 200, "request");
    let idle_for = time_until_closed(&mut conn);

    assert!(
        idle_for < Duration::from_millis(500),
        "the timeout must not turn on keep-alive for an HTTP/1.0 client, closed after {idle_for:?}"
    );
}

#[test]
fn sub_second_timeouts_round_up_to_a_second() {
    let (_proxy, addr) = proxy_with_keepalive_timeout(Some(1));
    let mut conn = connect(&addr);

    assert_eq!(request(&mut conn, "HTTP/1.1", ""), 200, "request");
    let idle_for = time_until_closed(&mut conn);

    assert!(
        idle_for >= Duration::from_millis(700) && idle_for <= Duration::from_millis(3_500),
        "1 ms is applied as 1 s, never as no timeout or an instant close, closed after {idle_for:?}"
    );
}

#[test]
fn without_a_timeout_idle_connections_stay_open() {
    let (_proxy, addr) = proxy_with_keepalive_timeout(None);
    let mut conn = connect(&addr);

    assert_eq!(request(&mut conn, "HTTP/1.1", ""), 200, "first request");
    std::thread::sleep(Duration::from_millis(2_500));

    assert_eq!(
        request(&mut conn, "HTTP/1.1", ""),
        200,
        "the default leaves idle keep-alive connections open"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Start a proxy in front of a backend with `downstream_keepalive_timeout_ms`.
fn proxy_with_keepalive_timeout(timeout_ms: Option<u64>) -> ((ProxyGuard, BackendGuard), String) {
    let backend = start_backend_with_shutdown("ok");
    let backend_port = backend.port();
    let port = free_port();
    let timeout = timeout_ms.map_or_else(String::new, |ms| format!("\n    downstream_keepalive_timeout_ms: {ms}"));
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{port}"{timeout}
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
    );
    let proxy = start_proxy(&Config::from_yaml(&yaml).expect("valid config"));
    ((proxy, backend), format!("127.0.0.1:{port}"))
}

/// Open a client connection with a generous read timeout.
fn connect(addr: &str) -> BufReader<TcpStream> {
    let stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    BufReader::new(stream)
}

/// Send `GET /` with `version` and `extra` headers on `conn` and read the
/// whole response, returning its status.
fn request(conn: &mut BufReader<TcpStream>, version: &str, extra: &str) -> u16 {
    conn.get_mut()
        .write_all(format!("GET / {version}\r\nHost: localhost\r\n{extra}\r\n").as_bytes())
        .expect("write request");
    let mut status_line = String::new();
    conn.read_line(&mut status_line).expect("read status line");
    let mut content_length = 0;
    loop {
        let mut line = String::new();
        conn.read_line(&mut line).expect("read header");
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().expect("content length");
        }
    }
    let mut body = vec![0_u8; content_length];
    conn.read_exact(&mut body).expect("read body");
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status code")
}

/// Wait for the proxy to close `conn`, returning how long it stayed open.
fn time_until_closed(conn: &mut BufReader<TcpStream>) -> Duration {
    let started = Instant::now();
    let mut rest = Vec::new();
    let _read = conn.read_to_end(&mut rest);
    assert!(rest.is_empty(), "no bytes may follow the response: {rest:?}");
    started.elapsed()
}
