// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the `bandwidth_limit` filter.

use std::{
    io::{ErrorKind, Read as _, Write as _},
    net::TcpStream,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, http_post, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn download_is_paced_when_there_is_no_burst() {
    let body = "x".repeat(16_000);
    let backend = start_backend_with_shutdown(&body);
    let proxy_port = free_port();
    let config = Config::from_yaml(&bandwidth_yaml(proxy_port, backend.port(), 0, true)).unwrap();
    let proxy = start_proxy(&config);

    let started = Instant::now();
    let (status, response) = http_get(proxy.addr(), "/", None);
    let elapsed = started.elapsed();

    assert_eq!(status, 200, "paced download should still succeed");
    assert_eq!(response.len(), 16_000, "the full body should arrive");
    assert!(
        elapsed >= Duration::from_millis(1_200),
        "16000 bytes at 8000 bytes per second should take about two seconds, elapsed {elapsed:?}"
    );
}

#[test]
fn download_burst_covers_a_small_body() {
    let body = "x".repeat(16_000);
    let backend = start_backend_with_shutdown(&body);
    let proxy_port = free_port();
    let config = Config::from_yaml(&bandwidth_yaml(proxy_port, backend.port(), 16_000, true)).unwrap();
    let proxy = start_proxy(&config);

    let started = Instant::now();
    let (status, response) = http_get(proxy.addr(), "/", None);
    let elapsed = started.elapsed();

    assert_eq!(status, 200, "a burst-covered download should succeed");
    assert_eq!(response.len(), 16_000, "the full body should arrive");
    assert!(
        elapsed < Duration::from_millis(1_000),
        "a burst that covers the body should not wait out the byte rate, elapsed {elapsed:?}"
    );
}

#[test]
fn headers_arrive_before_the_paced_body() {
    let body = "x".repeat(16_000);
    let backend = start_backend_with_shutdown(&body);
    let proxy_port = free_port();
    let config = Config::from_yaml(&bandwidth_yaml(proxy_port, backend.port(), 0, true)).unwrap();
    let proxy = start_proxy(&config);

    let (header_at, total, early_body, raw) = read_head_then_body(proxy.addr());

    assert!(
        header_at < Duration::from_millis(700),
        "the response head should arrive before the body wait, elapsed {header_at:?}"
    );
    assert_eq!(early_body, 0, "the body should still be waiting when the head arrives");
    assert!(
        raw.starts_with(b"HTTP/1.1 200") || raw.starts_with(b"HTTP/1.0 200"),
        "the head should be a successful response"
    );
    assert!(
        total >= Duration::from_millis(1_500),
        "16000 bytes at 8000 bytes per second should take about two seconds, elapsed {total:?}"
    );
    assert_eq!(
        raw.iter().filter(|byte| **byte == b'x').count(),
        16_000,
        "the paced body should still arrive in full"
    );
}

fn upload_is_paced_when_there_is_no_burst() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = Config::from_yaml(&bandwidth_yaml(proxy_port, backend.port(), 0, false)).unwrap();
    let proxy = start_proxy(&config);
    let payload = "y".repeat(8_000);

    let started = Instant::now();
    let (status, response) = http_post(proxy.addr(), "/", &payload);
    let elapsed = started.elapsed();

    assert_eq!(status, 200, "paced upload should still succeed");
    assert_eq!(response, "ok", "the backend response should be unchanged");
    assert!(
        elapsed >= Duration::from_millis(700),
        "8000 bytes at 8000 bytes per second should take about a second, elapsed {elapsed:?}"
    );
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Read a response, recording when the head finished and how many body bytes came with it.
fn read_head_then_body(addr: &str) -> (Duration, Duration, usize, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_nodelay(true).expect("nodelay");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("send request");

    let started = Instant::now();
    let mut data = Vec::new();
    let mut buf = [0_u8; 1024];
    let mut header_at = None;
    let mut early_body = 0;
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => note_read(&mut data, &buf[..n], started, &mut header_at, &mut early_body),
            Err(err) if err.kind() == ErrorKind::Interrupted => {},
            Err(err) if err.kind() == ErrorKind::TimedOut || err.kind() == ErrorKind::WouldBlock => break,
            Err(err) => panic!("read response: {err}"),
        }
    }
    let header_at = header_at.expect("response head");
    (header_at, started.elapsed(), early_body, data)
}

/// Append `chunk` and record the first moment the head is complete.
fn note_read(
    data: &mut Vec<u8>,
    chunk: &[u8],
    started: Instant,
    header_at: &mut Option<Duration>,
    early_body: &mut usize,
) {
    data.extend_from_slice(chunk);
    if header_at.is_some() {
        return;
    }
    let Some(end) = data.windows(4).position(|window| window == b"\r\n\r\n") else {
        return;
    };
    *header_at = Some(started.elapsed());
    *early_body = data
        .get(end.saturating_add(4)..)
        .unwrap_or_default()
        .iter()
        .filter(|byte| **byte == b'x')
        .count();
}

/// Proxy config that paces either the response or the request.
fn bandwidth_yaml(proxy_port: u16, backend_port: u16, burst_bytes: u64, download: bool) -> String {
    let direction = if download {
        "download_bytes_per_sec: 8000"
    } else {
        "upload_bytes_per_sec: 8000"
    };
    format!(
        r#"
listeners:
  - name: proxy
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: bandwidth_limit
        mode: per_connection
        {direction}
        burst_bytes: {burst_bytes}
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
