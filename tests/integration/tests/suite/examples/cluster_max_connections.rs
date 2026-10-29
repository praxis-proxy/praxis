// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the per-cluster `max_connections` concurrency ceiling.
//!
//! The listener-level cap is covered by `super::max_connections`. These tests
//! keep the listener uncapped so every rejection they observe can only come
//! from the cluster's own ceiling.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
};

use praxis_core::config::Config;
use praxis_test_utils::{
    bind_unique_port, free_port, http_get, http_send, parse_header, parse_status, start_backend_with_shutdown,
    start_proxy,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ARRIVAL_TIMEOUT: Duration = Duration::from_secs(10);
const HOLD_MARKER: &str = "hold";

/// How long the fake server waits for the rest of a request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest request head the fake server reads before giving up.
const MAX_HEAD_BYTES: usize = 8_192; // 8 KiB

// fake server
struct HoldingBackend {
    arrivals: Receiver<()>,
    port: u16,
}

/// Boot a fake server that holds marked requests open.
///
/// `early_head` is written on a held connection before it holds, so the proxy
/// can be shown a response head that is not the end of the request.
fn start_holding_backend(early_head: Option<&'static [u8]>) -> HoldingBackend {
    let (listener, port) = bind_unique_port();
    let (announce, arrivals) = mpsc::channel();
    thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else { return };
            let announce = announce.clone();
            thread::spawn(move || serve_held_connection(&mut stream, &announce, early_head));
        }
    });
    HoldingBackend { arrivals, port }
}

/// Read a request head, through the blank line that ends it.
fn read_request_head(stream: &mut TcpStream) -> Option<String> {
    stream.set_read_timeout(Some(HEAD_TIMEOUT)).ok()?;
    let mut head = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        if head.len() >= MAX_HEAD_BYTES {
            return None;
        }
        let read = stream.read(&mut buffer).unwrap_or(0);
        if read == 0 {
            return None;
        }
        head.extend_from_slice(buffer.get(..read).unwrap_or_default());
    }
    // Holding a connection blocks on a read that must not time out.
    stream.set_read_timeout(None).ok()?;
    Some(String::from_utf8_lossy(&head).into_owned())
}

/// Answer an unmarked request, or announce and hold a marked one.
fn serve_held_connection(stream: &mut TcpStream, announce: &mpsc::Sender<()>, early_head: Option<&[u8]>) {
    let Some(head) = read_request_head(stream) else {
        return;
    };
    let Some(request_line) = head.lines().next() else {
        return;
    };
    if !request_line.contains(HOLD_MARKER) {
        drop(stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"));
        return;
    }
    if let Some(early_head) = early_head {
        drop(stream.write_all(early_head));
        drop(stream.flush());
    }
    if announce.send(()).is_err() {
        return;
    }
    let mut buffer = [0_u8; 4096];
    while stream.read(&mut buffer).unwrap_or(0) > 0 {}
}

/// Open `count` connections to `addr`, write a request on each, and return
/// once every one has reached `backend`.
///
/// `path` must contain [`HOLD_MARKER`] so the backend holds it instead of
/// answering. The returned sockets must outlive the assertion that follows:
/// dropping them lets the proxy close the upstream legs and release the slots.
fn hold_in_flight(addr: &str, path: &str, count: usize, backend: &HoldingBackend) -> Vec<TcpStream> {
    assert!(
        path.contains(HOLD_MARKER),
        "hold_in_flight needs a path the backend will hold, got {path:?}"
    );
    let mut held = Vec::with_capacity(count);
    for _ in 0..count {
        let mut stream = TcpStream::connect(addr).expect("TCP connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("set read timeout");
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes())
            .expect("write request");
        held.push(stream);
    }
    for arrived in 0..count {
        // expects announce.send(()) from request
        backend.arrivals.recv_timeout(ARRIVAL_TIMEOUT).unwrap_or_else(|err| {
            panic!("only {arrived} of {count} held requests reached the backend: {err}");
        });
    }
    held
}

/// Single-cluster config with the listener uncapped and the cluster capped
/// at `max_connections`.
fn single_cluster_yaml(proxy_port: u16, backend_port: u16, max_connections: u32) -> String {
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
            max_connections: {max_connections}
insecure_options:
  allow_private_endpoints: true
"#
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn cluster_max_connections_rejects_excess_with_503() {
    let backend = start_holding_backend(None);
    let proxy_port = free_port();
    let config = Config::from_yaml(&single_cluster_yaml(proxy_port, backend.port, 2)).unwrap();
    let proxy = start_proxy(&config);

    let held = hold_in_flight(proxy.addr(), "/hold", 2, &backend);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        503,
        "a request past the cluster's max_connections should be shed with 503"
    );
    assert_eq!(
        parse_header(&raw, "Retry-After").as_deref(),
        Some("1"),
        "cluster shedding should carry Retry-After: 1 like the listener cap"
    );

    drop(held);
}

#[test]
fn cluster_max_connections_holds_the_slot_until_the_final_response() {
    let backend = start_holding_backend(Some(b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n"));
    let proxy_port = free_port();
    let config = Config::from_yaml(&single_cluster_yaml(proxy_port, backend.port, 1)).unwrap();
    let proxy = start_proxy(&config);

    let held = hold_in_flight(proxy.addr(), "/hold", 1, &backend);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        503,
        "a 103 is not the end of the held request, so its slot must stay taken"
    );

    drop(held);
}

#[test]
fn cluster_max_connections_allows_after_release() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = Config::from_yaml(&single_cluster_yaml(proxy_port, backend_guard.port(), 1)).unwrap();
    let proxy = start_proxy(&config);

    for attempt in 0..3 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "sequential request {attempt} should reuse the one slot");
        assert_eq!(body, "ok", "request {attempt} should reach the backend");
    }
}

#[test]
fn cluster_max_connections_is_per_cluster_not_per_listener() {
    let slow_backend = start_holding_backend(None);
    let slow_port = slow_backend.port;
    let fast_guard = start_backend_with_shutdown("fast");
    let fast_port = fast_guard.port();
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
          - path_prefix: "/slow/"
            cluster: slow-model
          - path_prefix: "/"
            cluster: fast-api
      - filter: load_balancer
        clusters:
          - name: slow-model
            endpoints:
              - "127.0.0.1:{slow_port}"
            max_connections: 1
          - name: fast-api
            endpoints:
              - "127.0.0.1:{fast_port}"
            max_connections: 64
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let held = hold_in_flight(proxy.addr(), "/slow/hold", 1, &slow_backend);

    let raw = http_send(
        proxy.addr(),
        "GET /slow/two HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        503,
        "the saturated cluster should shed its own excess"
    );

    let (status, body) = http_get(proxy.addr(), "/other", None);
    assert_eq!(
        status, 200,
        "a cluster under its own ceiling must keep serving while another is saturated"
    );
    assert_eq!(body, "fast", "the unsaturated cluster should reach its backend");

    drop(held);
}

#[test]
fn cluster_max_connections_example_config_parses() {
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/cluster-max-connections.yaml",
        proxy_port,
        std::collections::HashMap::from([("127.0.0.1:9000", free_port()), ("127.0.0.1:9001", free_port())]),
    );
    let clusters = config.filter_chains[0].filters[1]
        .config
        .get("clusters")
        .and_then(serde_yaml::Value::as_sequence)
        .expect("load_balancer should declare clusters");
    let caps: Vec<Option<u64>> = clusters
        .iter()
        .map(|cluster| cluster.get("max_connections").and_then(serde_yaml::Value::as_u64))
        .collect();
    assert_eq!(
        caps,
        vec![Some(2), Some(64)],
        "both example clusters should carry their own ceiling"
    );
}

#[test]
fn cluster_max_connections_example_functional() {
    let slow_backend = start_holding_backend(None);
    let fast_guard = start_backend_with_shutdown("fast");
    let proxy_port = free_port();

    let config = super::load_example_config(
        "traffic-management/cluster-max-connections.yaml",
        proxy_port,
        std::collections::HashMap::from([
            ("127.0.0.1:9000", slow_backend.port),
            ("127.0.0.1:9001", fast_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);
    let held = hold_in_flight(proxy.addr(), "/slow/hold", 2, &slow_backend);

    let raw = http_send(
        proxy.addr(),
        "GET /slow/three HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        503,
        "the example's slow-model ceiling of 2 should shed the third request"
    );
    assert_eq!(
        parse_header(&raw, "Retry-After").as_deref(),
        Some("1"),
        "the example's shed response should carry Retry-After: 1"
    );

    let (status, body) = http_get(proxy.addr(), "/anything", None);
    assert_eq!(status, 200, "the example's fast-api cluster should stay available");
    assert_eq!(body, "fast", "fast-api should reach its own backend");

    drop(held);
}
