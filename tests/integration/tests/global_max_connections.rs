// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the process-wide `runtime.max_connections` limit.
//!
//! The global semaphore lives in a process-global `OnceLock`, installed once
//! per process and never resized, so these tests cannot run inside the shared
//! `suite` process without capping every other test in it. They run as their
//! own test binary, and as a single test function because every case in the
//! scenario shares that one semaphore.
//!
//! The per-listener half of the same fix is covered by
//! `suite/examples/max_connections.rs`; what is exercised here is the global
//! permit: that it is bundled and carried across HTTP/1.1 keep-alive idle on a
//! listener with no `max_connections` of its own, and that it is released
//! rather than leaked when the per-listener limit rejects the request.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_assert_message,
    clippy::panic,
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    clippy::too_many_lines,
    clippy::unwrap_used,
    reason = "test code"
)]

use std::{
    io::Write as _,
    net::TcpStream,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, parse_header, parse_status, read_full_response, start_backend_with_shutdown, start_proxy,
    wait_for_http,
};

/// Process-wide connection ceiling installed for this test binary.
const GLOBAL_LIMIT: usize = 2;

/// Build a config with a listener that has its own `max_connections` and one
/// that relies on the process-wide limit alone.
fn two_listener_yaml(limited_port: u16, open_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: limited
    address: "127.0.0.1:{limited_port}"
    max_connections: 1
    filter_chains: [main]
  - name: open
    address: "127.0.0.1:{open_port}"
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
    )
}

/// Open a keep-alive connection, send one request, and return it still open
/// alongside the response status.
fn keepalive_request(addr: &str) -> (TcpStream, u16) {
    let mut stream = TcpStream::connect(addr).expect("TCP connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write request");
    let status = parse_status(&read_full_response(&mut stream));
    (stream, status)
}

/// Send a one-shot request on its own connection and return the raw response.
fn oneshot_request(addr: &str) -> String {
    http_send(addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
}

/// Poll `addr` until a one-shot request is admitted, or panic after 5 seconds.
///
/// Permits are released when the proxy finishes tearing the connection down,
/// which is not synchronous with the client's `close()`.
fn wait_until_admitted(addr: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let raw = oneshot_request(addr);
        if parse_status(&raw) != 503 {
            return raw;
        }
        assert!(Instant::now() < deadline, "no slot was released within 5s");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn global_max_connections_is_scoped_to_the_connection() {
    praxis_protocol::connections::init_global_limit(GLOBAL_LIMIT);

    let backend_guard = start_backend_with_shutdown("ok");
    let limited_port = free_port();
    let open_port = free_port();
    let limited_addr = format!("127.0.0.1:{limited_port}");
    let open_addr = format!("127.0.0.1:{open_port}");
    let config = Config::from_yaml(&two_listener_yaml(limited_port, open_port, backend_guard.port())).unwrap();
    let _proxy = start_proxy(&config);
    wait_for_http(&open_addr);

    // Readiness probes close their connections; let the proxy hand those
    // permits back before counting slots.
    std::thread::sleep(Duration::from_millis(200));

    // 1/2: an idle keep-alive connection on the limited listener holds both a
    // global permit and that listener's only permit.
    let (limited_idle, status) = keepalive_request(&limited_addr);
    assert_eq!(status, 200, "first request on the limited listener should succeed");
    std::thread::sleep(Duration::from_millis(200));

    // The listener's slot is taken, so this is rejected on the per-listener
    // limit after a global permit was already acquired. That global permit
    // must be dropped, not parked on the rejected request.
    let raw = oneshot_request(&limited_addr);
    assert_eq!(
        parse_status(&raw),
        503,
        "the limited listener's single slot is held by the idle connection"
    );

    // 2/2: a keep-alive connection on the listener with no limit of its own.
    // It takes the second and last global permit -- which proves the rejection
    // above released the global permit it had acquired.
    let (open_idle, status) = keepalive_request(&open_addr);
    assert_eq!(
        status, 200,
        "a listener-level rejection must release the global permit it acquired"
    );
    std::thread::sleep(Duration::from_millis(200));

    // Both global permits are now held by idle connections. A request-scoped
    // global permit would have been handed back when each request finished,
    // so this must be rejected for the limit to be connection-scoped.
    let raw = oneshot_request(&open_addr);
    assert_eq!(
        parse_status(&raw),
        503,
        "the global limit must stay taken while idle keep-alive connections hold it"
    );
    assert_eq!(
        parse_header(&raw, "Retry-After").as_deref(),
        Some("1"),
        "503 response should include Retry-After: 1"
    );

    // Closing a holder returns its global permit.
    drop(open_idle);
    let raw = wait_until_admitted(&open_addr);
    assert_eq!(
        parse_status(&raw),
        200,
        "a global permit should be released when its connection closes"
    );

    drop(limited_idle);
}
