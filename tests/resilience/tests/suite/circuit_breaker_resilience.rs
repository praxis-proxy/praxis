// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! End-to-end resilience tests for the circuit breaker filter,
//! verifying open/half-open/closed state transitions under
//! real proxy traffic.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{Backend, ProxyGuard, free_port, http_get, http_send, parse_header, parse_status, start_proxy};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Longest a held healthy response waits for release, so a failed test
/// never leaves a backend thread parked forever.
const HOLD_LIMIT: Duration = Duration::from_secs(10);

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn circuit_breaker_opens_after_failures() {
    let backend_port = Backend::status(500, "error").start();
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
      - filter: circuit_breaker
        clusters:
          - name: backend
            consecutive_failures: 3
            recovery_window_secs: 60
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 500,
        "first request should reach the 500-returning backend (circuit starts closed)"
    );

    let mut saw_503 = false;
    for _ in 0..10 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        if status == 503 {
            saw_503 = true;
            break;
        }
        assert!(
            status == 500 || status == 502,
            "pre-trip requests should return an upstream error, got {status}"
        );
    }
    assert!(
        saw_503,
        "circuit should open and reject with 503 after threshold failures"
    );

    for i in 0..3 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        assert_eq!(
            status, 503,
            "request {i} after circuit opens should remain rejected with 503"
        );
    }
}

#[test]
fn circuit_breaker_recovers_after_window() {
    let backend_port = Backend::status(500, "error").start();
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
      - filter: circuit_breaker
        clusters:
          - name: backend
            consecutive_failures: 3
            recovery_window_secs: 1
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let mut circuit_open = false;
    for _ in 0..10 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        if status == 503 {
            circuit_open = true;
            break;
        }
    }
    assert!(circuit_open, "circuit should open after consecutive failures");

    thread::sleep(Duration::from_millis(1500));

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 500, "half-open probe should reach the backend and return 500");

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 503, "circuit should re-open after failed half-open probe");
}

#[test]
fn circuit_breaker_closes_after_successful_probe() {
    let switches = Arc::new(BackendSwitches::default());
    let proxy = start_breaker_proxy(&switches);

    trip_circuit(proxy.addr());

    switches.healthy.store(true, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(1500));

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "half-open probe should reach the recovered backend");
    assert_eq!(body, "recovered", "half-open probe should carry the backend's response");

    for i in 0..5 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(
            status, 200,
            "request {i} after a successful probe should pass through a closed circuit"
        );
        assert_eq!(body, "recovered", "request {i} should reach the backend");
    }

    switches.healthy.store(false, Ordering::SeqCst);
    for i in 0..3 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        assert_eq!(
            status, 500,
            "failure {i} should reach the backend: closing the circuit must reset the failure streak"
        );
    }
    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 503,
        "a fresh streak of consecutive_failures should open the circuit again"
    );
}

#[test]
fn circuit_breaker_half_open_admits_a_single_probe() {
    let switches = Arc::new(BackendSwitches::default());
    let proxy = start_breaker_proxy(&switches);

    trip_circuit(proxy.addr());
    let hits_before_probe = switches.hits.load(Ordering::SeqCst);

    switches.hold.store(true, Ordering::SeqCst);
    switches.healthy.store(true, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(1500));

    let probe_addr = proxy.addr().to_owned();
    let probe = thread::spawn(move || http_get(&probe_addr, "/", None));
    wait_for_hits(&switches, hits_before_probe + 1);

    let num_threads = 8;
    let barrier = Arc::new(Barrier::new(num_threads));
    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let addr = proxy.addr().to_owned();
            thread::spawn(move || {
                barrier.wait();
                http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            })
        })
        .collect();
    for (i, handle) in handles.into_iter().enumerate() {
        let raw = handle.join().expect("concurrent request thread should not panic");
        assert_eq!(
            parse_status(&raw),
            503,
            "concurrent request {i} during the half-open probe should be rejected: {raw}"
        );
        assert_eq!(
            parse_header(&raw, "x-circuit-state").as_deref(),
            Some("open"),
            "concurrent request {i} should be rejected by the circuit breaker: {raw}"
        );
    }
    assert_eq!(
        switches.hits.load(Ordering::SeqCst),
        hits_before_probe + 1,
        "only the probe should reach the backend while the circuit is half-open"
    );

    switches.hold.store(false, Ordering::SeqCst);
    let (status, body) = probe.join().expect("probe thread should not panic");
    assert_eq!(status, 200, "the held probe should complete once released");
    assert_eq!(body, "recovered", "the probe should carry the backend's response");

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "a successful probe should close the circuit");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Switches a test flips to change [`start_switchable_backend`] while
/// the proxy runs.
#[derive(Default)]
struct BackendSwitches {
    /// Answer `200 recovered` instead of `500 error`.
    healthy: AtomicBool,

    /// Hold healthy responses until cleared (bounded by
    /// [`HOLD_LIMIT`]), keeping a half-open probe in flight.
    hold: AtomicBool,

    /// Requests the backend has received.
    hits: AtomicUsize,
}

/// Start a switchable backend behind a circuit-breaking proxy, and leave
/// the backend failing.
///
/// The backend starts out healthy because the harness's readiness probe
/// travels through the breaker, and a failed probe would count toward
/// the failure streak the tests measure.
fn start_breaker_proxy(switches: &Arc<BackendSwitches>) -> ProxyGuard {
    switches.healthy.store(true, Ordering::SeqCst);
    let backend_port = start_switchable_backend(Arc::clone(switches));
    let config = Config::from_yaml(&circuit_breaker_yaml(free_port(), backend_port)).unwrap();
    let proxy = start_proxy(&config);
    switches.healthy.store(false, Ordering::SeqCst);
    proxy
}

/// Start a backend whose answer follows `switches`: 500 while unhealthy,
/// 200 once healthy (after any hold). Every request bumps `hits`.
fn start_switchable_backend(switches: Arc<BackendSwitches>) -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let switches = Arc::clone(&switches);
            thread::spawn(move || serve_switchable(stream, &switches));
        }
    });
    port
}

/// Answer one request on `stream` according to `switches`.
fn serve_switchable(mut stream: TcpStream, switches: &BackendSwitches) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut buf = [0_u8; 4096];
    let _bytes = stream.read(&mut buf);
    switches.hits.fetch_add(1, Ordering::SeqCst);

    let response = if switches.healthy.load(Ordering::SeqCst) {
        let deadline = Instant::now() + HOLD_LIMIT;
        while switches.hold.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nrecovered"
    } else {
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\nConnection: close\r\n\r\nerror"
    };
    let _sent = stream.write_all(response.as_bytes());
}

/// Drive three failures through the proxy and confirm the circuit opened.
fn trip_circuit(addr: &str) {
    for i in 0..3 {
        let (status, _) = http_get(addr, "/", None);
        assert_eq!(status, 500, "failure {i} should reach the failing backend");
    }
    let (status, _) = http_get(addr, "/", None);
    assert_eq!(status, 503, "circuit should open after three consecutive failures");
}

/// Wait until the backend has seen `expected` requests.
fn wait_for_hits(switches: &BackendSwitches, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while switches.hits.load(Ordering::SeqCst) < expected {
        assert!(
            Instant::now() < deadline,
            "backend should see request {expected} within 5 s, saw {}",
            switches.hits.load(Ordering::SeqCst)
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// Proxy config with a circuit breaker (three failures, 1 s recovery
/// window) in front of one backend.
fn circuit_breaker_yaml(proxy_port: u16, backend_port: u16) -> String {
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
      - filter: circuit_breaker
        clusters:
          - name: backend
            consecutive_failures: 3
            recovery_window_secs: 1
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
