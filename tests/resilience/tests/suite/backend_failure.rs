// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for proxy behavior when backends are unreachable, slow, send more than they declare, or drop or reset
//! connections mid-exchange.

use std::{
    io::{ErrorKind, Read as _, Write as _},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_post, http_send, parse_header, parse_status, simple_proxy_yaml, start_backend,
    start_proxy, start_slow_backend,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Body length the truncating backend declares in `Content-Length`.
const DECLARED_BODY_LEN: usize = 1_000;

/// Body bytes the truncating backend actually sends before it resets or
/// stalls.
const SENT_BODY_LEN: usize = 100;

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
fn slow_backend_with_read_timeout_returns_504() {
    let slow_port = start_slow_backend("slow", Duration::from_secs(5));
    let proxy_port = free_port();
    let yaml = read_timeout_proxy_yaml(proxy_port, slow_port, 500);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let start = Instant::now();
    let (status, _) = http_get(proxy.addr(), "/", None);
    let elapsed = start.elapsed();

    assert_eq!(status, 504, "slow backend with read timeout should return 504");
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
insecure_options:
  allow_private_endpoints: true
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
insecure_options:
  allow_private_endpoints: true
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

#[test]
fn backend_overread_is_cut_at_content_length_and_never_pooled() {
    let (backend_port, reused) = start_overread_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&simple_proxy_yaml(proxy_port, backend_port)).unwrap();
    let proxy = start_proxy(&config);

    for i in 0..3 {
        let (read, _, raw) = get_until_closed(proxy.addr(), "/");
        let response = String::from_utf8_lossy(&raw);
        assert!(
            matches!(read, Ok(len) if len > 0),
            "request {i}: proxy should answer and then close, got {read:?}"
        );
        assert_eq!(
            parse_status(&response),
            200,
            "request {i}: the declared part of the response should come through: {response}"
        );
        assert_eq!(
            response.split_once("\r\n\r\n").map(|(_, body)| body),
            Some("hello"),
            "request {i}: client should get exactly the 5 declared bytes and nothing of what followed: {response}"
        );
    }
    assert_eq!(
        reused.load(Ordering::SeqCst),
        0,
        "an upstream connection that sent more than its Content-Length must never go back into the pool"
    );
}

#[test]
fn backend_reset_mid_body_truncates_the_response() {
    let backend_port = start_truncating_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&simple_proxy_yaml(proxy_port, backend_port)).unwrap();
    let proxy = start_proxy(&config);

    let (read, elapsed, raw) = get_until_closed(proxy.addr(), "/reset");
    assert_closed_promptly(&read, elapsed, "upstream reset mid-body");
    assert_truncated(&raw, "upstream reset mid-body");

    let (status, body) = http_get(proxy.addr(), "/healthy", None);
    assert_eq!(
        status, 200,
        "proxy should serve the next request after an upstream reset"
    );
    assert_eq!(body, "healthy", "the next request should get the backend's full body");
}

#[test]
fn stalled_backend_body_hits_the_read_timeout() {
    let backend_port = start_truncating_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&read_timeout_proxy_yaml(proxy_port, backend_port, 500)).unwrap();
    let proxy = start_proxy(&config);

    let (read, elapsed, raw) = get_until_closed(proxy.addr(), "/stall");
    assert_closed_promptly(&read, elapsed, "stalled upstream body");
    assert!(
        elapsed >= Duration::from_millis(400),
        "the connection should stay open until the 500 ms read timeout fires; closed after {elapsed:?}"
    );
    assert_truncated(&raw, "stalled upstream body");

    let (status, body) = http_get(proxy.addr(), "/healthy", None);
    assert_eq!(status, 200, "proxy should serve the next request after a stalled body");
    assert_eq!(body, "healthy", "the next request should get the backend's full body");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Assert the proxy ended the client connection (with a FIN or a reset)
/// soon after the upstream failed, rather than leaving the client's read
/// to time out.
fn assert_closed_promptly(read: &std::io::Result<usize>, elapsed: Duration, what: &str) {
    assert!(
        !matches!(read, Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)),
        "{what}: proxy should close the client connection, but the client's read timed out"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "{what}: proxy should close the client connection promptly; took {elapsed:?}"
    );
}

/// Assert `raw` is a 200 that keeps its declared length but stops short
/// of it, so the client can tell the body was cut off.
fn assert_truncated(raw: &[u8], what: &str) {
    let response = String::from_utf8_lossy(raw);
    let body_len = response.split_once("\r\n\r\n").map_or(0, |(_, body)| body.len());
    assert_eq!(
        parse_status(&response),
        200,
        "{what}: the headers were already forwarded, so the client should see the 200: {response}"
    );
    assert_eq!(
        parse_header(&response, "content-length"),
        Some(DECLARED_BODY_LEN.to_string()),
        "{what}: the declared length should pass through so the client can spot the short body: {response}"
    );
    assert!(
        body_len < DECLARED_BODY_LEN,
        "{what}: client must not get a complete-looking body, got {body_len} of {DECLARED_BODY_LEN} bytes"
    );
}

/// Send a `Connection: close` GET for `path` and read until the proxy
/// closes the connection. Returns the read outcome, how long the read
/// took, and every byte received.
fn get_until_closed(addr: &str, path: &str) -> (std::io::Result<usize>, Duration, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).expect("TCP connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).expect("write request");

    let start = Instant::now();
    let mut raw = Vec::new();
    let read = stream.read_to_end(&mut raw);
    (read, start.elapsed(), raw)
}

/// Start a keep-alive backend whose every response runs past its
/// `Content-Length`: the extra bytes are a second, complete response
/// with the body `smuggled`. Returns the port and a count of requests
/// that arrived on an already-used connection.
fn start_overread_backend() -> (u16, Arc<AtomicUsize>) {
    let reused = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&reused);
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let counter = Arc::clone(&counter);
            std::thread::spawn(move || serve_overread(stream, &counter));
        }
    });
    (port, reused)
}

/// Answer every request on `stream` with the overlong response, counting
/// any request after the first in `reused`.
fn serve_overread(mut stream: TcpStream, reused: &AtomicUsize) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut buf = [0_u8; 4096];
    for request_num in 0_usize.. {
        if !matches!(stream.read(&mut buf), Ok(len) if len > 0) {
            break;
        }
        if request_num > 0 {
            reused.fetch_add(1, Ordering::SeqCst);
        }
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello\
                         HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nsmuggled";
        if stream.write_all(response).is_err() {
            break;
        }
    }
}

/// Start a backend that answers `/reset` and `/stall` with a 200 that
/// declares [`DECLARED_BODY_LEN`] bytes but sends only [`SENT_BODY_LEN`],
/// then resets the connection (`/reset`) or goes quiet until the proxy
/// hangs up (`/stall`). Any other path gets a complete `200 healthy`.
fn start_truncating_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || serve_truncating(stream));
        }
    });
    port
}

/// Answer one request on `stream` for [`start_truncating_backend`].
fn serve_truncating(mut stream: TcpStream) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(30))));
    let mut buf = [0_u8; 4096];
    let Ok(len) = stream.read(&mut buf) else {
        return;
    };
    let request = String::from_utf8_lossy(&buf[..len]).into_owned();
    let path = request.split_whitespace().nth(1).unwrap_or("/");
    if path != "/reset" && path != "/stall" {
        let _sent = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nhealthy");
        return;
    }

    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {DECLARED_BODY_LEN}\r\nConnection: close\r\n\r\n");
    let _sent = stream.write_all(head.as_bytes());
    let _sent = stream.write_all(&[b'x'; SENT_BODY_LEN]);
    let _flushed = stream.flush();

    if path == "/reset" {
        std::thread::sleep(Duration::from_millis(200));
        reset_connection(stream);
    } else {
        while matches!(stream.read(&mut buf), Ok(len) if len > 0) {}
    }
}

/// Close `stream` with a TCP RST instead of a FIN, by setting
/// `SO_LINGER` to zero before dropping it.
fn reset_connection(stream: TcpStream) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("tokio runtime for the resetting backend");
    let _entered = runtime.enter();
    stream.set_nonblocking(true).expect("non-blocking backend socket");
    let stream = tokio::net::TcpStream::from_std(stream).expect("register backend socket");
    stream.set_zero_linger().expect("set SO_LINGER to zero");
    drop(stream);
}

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
insecure_options:
  allow_private_endpoints: true
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
insecure_options:
  allow_private_endpoints: true
"#
    )
}
