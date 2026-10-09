// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Log levels for failed downstream TLS handshakes.
//!
//! A TCP health check (a Kubernetes probe, a load balancer) connects to a TLS
//! listener and hangs up without sending a `ClientHello`. That must not log at
//! ERROR every few seconds, while a client that sends something other than TLS
//! still must. The lines come from the process-wide log subscriber, so each
//! test runs the real binary with the accept loop's target turned up to debug.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::{Duration, Instant},
};

use praxis_test_utils::{PraxisProcess, TestCertificates, free_port};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Debug line the accept loop writes when the client went away mid-handshake.
const ABANDONED: &str = "Downstream handshake abandoned";

/// Error line the accept loop writes for a handshake that really failed.
const HANDSHAKE_ERROR: &str = "Downstream handshake error";

/// `RUST_LOG` for the child: the default level, plus debug for the accept loop.
const LOG_FILTER: &str = "info,pingora_core::services::listening=debug";

/// How long to wait for the accept loop to log every handshake it was given.
const LOG_WAIT: Duration = Duration::from_secs(10);

/// Plain TCP probes each test sends on top of the readiness check's own.
const PROBES: usize = 3;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn tcp_probe_on_tls_listener_logs_below_error() {
    let certs = TestCertificates::generate();
    let port = free_port();
    let mut proxy = spawn(&certs, port);

    for _ in 0..PROBES {
        drop(TcpStream::connect(addr(port)).expect("probe connect"));
    }
    wait_for_logs(&proxy, |logs| {
        logs.matches(ABANDONED).count() + logs.matches(HANDSHAKE_ERROR).count() > PROBES
    });
    proxy.terminate();
    let logs = proxy.logs();

    assert!(
        !logs.contains(HANDSHAKE_ERROR),
        "a client that hangs up before its ClientHello must not log a handshake error:\n{logs}"
    );
    let abandoned: Vec<&str> = logs.lines().filter(|line| line.contains(ABANDONED)).collect();
    assert!(
        abandoned.len() > PROBES,
        "every probe, the readiness check's included, should log an abandoned handshake:\n{logs}"
    );
    assert!(
        abandoned.iter().all(|line| line.contains("DEBUG")),
        "abandoned handshakes should log at DEBUG:\n{logs}"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn plaintext_client_on_tls_listener_logs_handshake_error() {
    let certs = TestCertificates::generate();
    let port = free_port();
    let mut proxy = spawn(&certs, port);

    send_plaintext_request(&addr(port));
    wait_for_logs(&proxy, |logs| logs.contains(HANDSHAKE_ERROR));
    proxy.terminate();
    let logs = proxy.logs();

    let errors: Vec<&str> = logs.lines().filter(|line| line.contains(HANDSHAKE_ERROR)).collect();
    assert!(
        !errors.is_empty(),
        "plaintext HTTP sent to a TLS listener must log a handshake error:\n{logs}"
    );
    assert!(
        errors.iter().all(|line| line.contains("ERROR")),
        "a real handshake failure should log at ERROR:\n{logs}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Start `praxis` with a TLS listener on `port` and the accept loop at debug.
fn spawn(certs: &TestCertificates, port: u16) -> PraxisProcess {
    PraxisProcess::spawn_with_env(&config(certs, port), &addr(port), &[("RUST_LOG", LOG_FILTER)])
}

/// Proxy config on `port`: a TLS listener in front of a static 200.
fn config(certs: &TestCertificates, port: u16) -> String {
    format!(
        r#"
shutdown_timeout_secs: 1
runtime:
  threads: 1
listeners:
  - name: secure
    address: "127.0.0.1:{port}"
    filter_chains: [main]
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        body: "ok"
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    )
}

/// Loopback address for `port`.
fn addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

/// Send a plaintext HTTP request where the `ClientHello` belongs, then wait
/// for the listener to hang up.
fn send_plaintext_request(addr: &str) {
    let mut stream = TcpStream::connect(addr).expect("connect to proxy");
    stream.set_read_timeout(Some(LOG_WAIT)).expect("set read timeout");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut reply = Vec::new();
    let _read = stream.read_to_end(&mut reply);
}

/// Poll the captured logs until `done` holds or [`LOG_WAIT`] passes.
fn wait_for_logs<F: Fn(&str) -> bool>(proxy: &PraxisProcess, done: F) {
    let deadline = Instant::now() + LOG_WAIT;
    while !done(&proxy.logs()) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
}
