// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Forward-proxy behavior beyond the example configurations.
//!
//! One listener can forward-proxy `CONNECT` and reverse-proxy every other
//! request through the same filter chain. A `CONNECT` then runs the chain's
//! router like any request, and its authority-form target matches a
//! catch-all route. The circuit-breaker tests check that the tunnel, which
//! dials its own destination, leaves the routed cluster's circuit breaker
//! alone.
//!
//! The access-record tests check how a tunnel's end is recorded: every
//! record says how its tunnel closed, and one a peer broke off is written
//! whatever the sampling, as for any response cut off midway.

use std::{
    io::{Read as _, Write as _},
    net::{Shutdown, TcpListener, TcpStream},
    path::Path,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    BackendGuard, ProxyGuard, free_port, http_get, start_full_proxy, start_stateful_backend, start_tcp_echo_backend,
    wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests: mixed listener with a catch-all route and a circuit breaker
// -----------------------------------------------------------------------------

#[test]
fn connect_does_not_close_a_half_open_circuit() {
    // The CONNECT arrives once the recovery window has passed. Had it taken
    // the half-open probe, the tunnel's 200 would have closed the circuit
    // for a backend that is still failing.
    let backend = start_stateful_backend(Vec::new()); // answers every request with 500
    let echo_port = start_tcp_echo_backend();
    let proxy = start_mixed_listener(&backend, echo_port);
    open_circuit(proxy.addr());

    std::thread::sleep(RECOVERY_ELAPSED);
    tunnel_round_trip(proxy.addr(), echo_port);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 500, "the first request after the recovery window is the probe");
    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 503,
        "the failed probe must reopen the circuit; a CONNECT must not have closed it"
    );
}

#[test]
fn refused_connect_does_not_use_up_the_half_open_probe() {
    // A refused CONNECT never reaches the cluster either. Had it taken the
    // probe, releasing it unused would leave the circuit half-open with no
    // probe in flight, refusing every request until the half-open timeout.
    let backend = start_stateful_backend(vec![
        (500, "down".to_owned()),
        (500, "down".to_owned()),
        (200, "recovered".to_owned()),
    ]);
    let echo_port = start_tcp_echo_backend();
    let proxy = start_mixed_listener(&backend, echo_port);
    open_circuit(proxy.addr());

    std::thread::sleep(RECOVERY_ELAPSED);
    let (_stream, status) = send_connect(proxy.addr(), "other.invalid:443");
    assert_eq!(status, 403, "the destination rules refuse the CONNECT");

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        (status, body.as_str()),
        (200, "recovered"),
        "the next request must be the probe, reach the recovered backend, and close the circuit"
    );
}

// -----------------------------------------------------------------------------
// Tests: how a tunnel's end is recorded
// -----------------------------------------------------------------------------

#[test]
fn access_records_say_how_each_tunnel_closed() {
    let echo_port = start_tcp_echo_backend();
    let resetting_port = start_resetting_destination();
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("access.ndjson");
    let proxy = start_logged_listener(&log, 1.0, &[echo_port, resetting_port]);

    close_tunnel_cleanly(proxy.addr(), echo_port);
    tunnel_to_resetting_destination(proxy.addr(), resetting_port);

    let records = wait_for_records(&log, 2);
    let mut reasons: Vec<&str> = records
        .iter()
        .map(|record| record["metadata.tunnel.close_reason"].as_str().unwrap_or("-"))
        .collect();
    reasons.sort_unstable();
    assert_eq!(reasons, ["completed", "destination_error"], "records: {records:?}");
    assert!(
        records.iter().all(|record| record["status"] == "200"),
        "both tunnels opened: {records:?}"
    );
}

#[test]
fn a_tunnel_the_destination_breaks_off_is_recorded_whatever_the_sampling() {
    // The sample rate drops every ordinary record this test produces.
    let echo_port = start_tcp_echo_backend();
    let resetting_port = start_resetting_destination();
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("access.ndjson");
    let proxy = start_logged_listener(&log, 0.000_001, &[echo_port, resetting_port]);

    close_tunnel_cleanly(proxy.addr(), echo_port);
    tunnel_to_resetting_destination(proxy.addr(), resetting_port);

    let records = wait_for_records(&log, 1);
    // A sampled-out record would have been written by now.
    std::thread::sleep(Duration::from_millis(200));
    let records = read_records(&log).unwrap_or(records);
    assert_eq!(records.len(), 1, "only the broken-off tunnel's record: {records:?}");
    assert_eq!(records[0]["metadata.tunnel.close_reason"], "destination_error");
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Start a forward-proxy listener for tunnels to `localhost` on `ports`,
/// writing access records with each tunnel's close reason to `log`.
fn start_logged_listener(log: &Path, sample_rate: f64, ports: &[u16]) -> ProxyGuard {
    let destinations: String = ports
        .iter()
        .map(|port| format!("        - host: localhost\n          port: {port}\n"))
        .collect();
    let yaml = format!(
        r#"
listeners:
  - name: tunnel-close
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
    forward_proxy:
      enabled: true
      allow_destinations:
{destinations}
filter_chains:
  - name: main
    filters:
      - filter: access_log
        sample_rate: {sample_rate}
        fields: [method, status, metadata.tunnel.close_reason]
        sink:
          type: file
          path: "{log}"

insecure_options:
  allow_private_upstreams: true
"#,
        proxy_port = free_port(),
        log = log.display(),
    );
    let config = Config::from_yaml(&yaml).unwrap_or_else(|e| panic!("logged listener config should parse: {e}"));
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    proxy
}

/// Start a destination that resets each connection once the client's first
/// bytes arrive: closing a socket with unread bytes resets it.
fn start_resetting_destination() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut byte = [0_u8; 1];
            let _peeked = stream.peek(&mut byte);
            drop(stream);
        }
    });
    port
}

/// Relay one message through a tunnel to the echo destination, then close
/// it from the client: both sides end cleanly.
fn close_tunnel_cleanly(proxy: &str, echo_port: u16) {
    tunnel_round_trip_on(proxy, echo_port, |stream| {
        stream.shutdown(Shutdown::Write).unwrap();
        let mut rest = Vec::new();
        stream
            .read_to_end(&mut rest)
            .expect("the destination's half-close reaches the client");
    });
}

/// Send one byte through a tunnel to the resetting destination and wait
/// for the proxy to end the tunnel.
fn tunnel_to_resetting_destination(proxy: &str, port: u16) {
    let (mut stream, status) = send_connect(proxy, &format!("localhost:{port}"));
    assert_eq!(status, 200, "the tunnel to the resetting destination opens");
    stream.write_all(b"x").unwrap();
    let mut rest = Vec::new();
    let _ended = stream.read_to_end(&mut rest);
}

/// Poll the access log until it holds `count` records.
fn wait_for_records(log: &Path, count: usize) -> Vec<serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let records = read_records(log).unwrap_or_default();
        if records.len() >= count || Instant::now() > deadline {
            return records;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The access records written so far, `None` before the file exists.
fn read_records(log: &Path) -> Option<Vec<serde_json::Value>> {
    let text = std::fs::read_to_string(log).ok()?;
    Some(
        text.lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect(),
    )
}

/// Consecutive backend failures that open the circuit.
const CONSECUTIVE_FAILURES: usize = 2;

/// A wait past the breaker's one-second recovery window.
const RECOVERY_ELAPSED: Duration = Duration::from_millis(1_100);

/// Start a mixed listener: CONNECT to `localhost:echo_port` is tunneled;
/// every other request takes a catch-all route to the `app` cluster on
/// `backend`, guarded by a circuit breaker.
///
/// The half-open timeout is far beyond the test, so a probe taken and
/// released unused keeps refusing requests rather than being replaced.
fn start_mixed_listener(backend: &BackendGuard, echo_port: u16) -> ProxyGuard {
    let yaml = format!(
        r#"
listeners:
  - name: mixed
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
    forward_proxy:
      enabled: true
      allow_destinations:
        - host: localhost
          port: {echo_port}

filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: app
      - filter: circuit_breaker
        clusters:
          - name: app
            consecutive_failures: {CONSECUTIVE_FAILURES}
            recovery_window_secs: 1
            half_open_timeout_secs: 3600
      - filter: load_balancer
        clusters:
          - name: app
            endpoints: ["127.0.0.1:{backend_port}"]

insecure_options:
  allow_private_endpoints: true
  allow_private_upstreams: true
"#,
        proxy_port = free_port(),
        backend_port = backend.port(),
    );
    let config = Config::from_yaml(&yaml).unwrap_or_else(|e| panic!("mixed listener config should parse: {e}"));
    // A TCP readiness check: an HTTP one would send a request through the
    // breaker and use up a scripted backend response.
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    proxy
}

/// Fail requests to the catch-all cluster until its circuit opens.
fn open_circuit(proxy: &str) {
    for attempt in 1..=CONSECUTIVE_FAILURES {
        let (status, _) = http_get(proxy, "/", None);
        assert_eq!(status, 500, "failure {attempt} must reach the backend");
    }
    let (status, _) = http_get(proxy, "/", None);
    assert_eq!(status, 503, "the open circuit must refuse without forwarding");
}

/// Open a tunnel to the echo destination and relay one message through it.
fn tunnel_round_trip(proxy: &str, echo_port: u16) {
    tunnel_round_trip_on(proxy, echo_port, |_stream| {});
}

/// [`tunnel_round_trip`], then hand the tunnel to `finish`.
fn tunnel_round_trip_on(proxy: &str, echo_port: u16, finish: impl FnOnce(&mut TcpStream)) {
    let (mut stream, status) = send_connect(proxy, &format!("localhost:{echo_port}"));
    assert_eq!(status, 200, "the allowlisted CONNECT should open a tunnel");
    stream.write_all(b"ping").unwrap();
    let mut echoed = [0_u8; 4];
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"ping", "the tunnel should relay to the destination and back");
    finish(&mut stream);
}

/// Send `CONNECT target` and read the response head, one byte at a time so
/// no tunnel bytes are consumed. Returns the stream and the status code.
fn send_connect(proxy: &str, target: &str) -> (TcpStream, u16) {
    let mut stream = TcpStream::connect(proxy).expect("connect to proxy");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(stream, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").unwrap();
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("malformed CONNECT response head: {head:?}"));
    (stream, status)
}
