// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Behaviours of the hyper backend that the Pingora backend does not share.
//!
//! The shutdown tests drive the real binary with process signals: `SIGTERM`
//! drains in-flight requests within `shutdown_timeout_secs`, `SIGINT` stops
//! within a second. The HTTP/2 test pins that `downstream_read_timeout_ms`
//! bounds the body reads of an HTTP/2 client too. Pingora documents
//! `Session::set_read_timeout` as a no-op for HTTP/2, so an HTTP/2 upload
//! that stalls there waits for the upstream instead.

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{PraxisProcess, free_port, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn sigterm_finishes_an_in_flight_request_before_exiting() {
    let (upstream, arrived) = slow_upstream("finished", Duration::from_secs(2));
    let port = free_port();
    let mut proxy = PraxisProcess::spawn(&proxy_config(port, upstream, 5), &addr(port));
    let mut client = send_get(port);
    arrived.recv_timeout(Duration::from_secs(5)).unwrap();

    proxy.signal("TERM");
    let signalled = Instant::now();
    let stopped_accepting = refuses_connections_within(port, Duration::from_secs(1));
    let response = read_response(&mut client);
    let exited = proxy.wait_for_exit(Duration::from_secs(8));
    let took = signalled.elapsed();

    assert!(
        response.starts_with("HTTP/1.1 200") && response.ends_with("finished"),
        "the request in flight at SIGTERM must still be answered:\n{response}\n{}",
        proxy.logs()
    );
    assert!(
        stopped_accepting,
        "the listener must stop accepting as soon as SIGTERM arrives, before the drain ends"
    );
    let status = exited.unwrap_or_else(|| panic!("praxis must exit after the drain:\n{}", proxy.logs()));
    assert!(status.success(), "a graceful shutdown exits zero, got {status}");
    assert!(
        took < Duration::from_secs(5),
        "within shutdown_timeout_secs, took {took:?}"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn sigterm_stops_waiting_for_a_request_that_outlives_the_shutdown_timeout() {
    let (upstream, arrived) = slow_upstream("never", Duration::from_secs(30));
    let port = free_port();
    let mut proxy = PraxisProcess::spawn(&proxy_config(port, upstream, 4), &addr(port));
    let _client = send_get(port);
    arrived.recv_timeout(Duration::from_secs(5)).unwrap();

    proxy.signal("TERM");
    let signalled = Instant::now();
    let exited = proxy.wait_for_exit(Duration::from_secs(10));
    let took = signalled.elapsed();

    assert!(
        exited.is_some(),
        "praxis must exit with a request still in flight:\n{}",
        proxy.logs()
    );
    assert!(
        took >= Duration::from_millis(2_500),
        "a graceful shutdown gives in-flight work most of shutdown_timeout_secs (4 s), exited after {took:?}"
    );
    assert!(
        took < Duration::from_secs(6),
        "and no more than shutdown_timeout_secs, exited after {took:?}"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn sigint_exits_without_waiting_for_in_flight_requests() {
    let (upstream, arrived) = slow_upstream("never", Duration::from_secs(30));
    let port = free_port();
    let mut proxy = PraxisProcess::spawn(&proxy_config(port, upstream, 30), &addr(port));
    let mut client = send_get(port);
    arrived.recv_timeout(Duration::from_secs(5)).unwrap();

    proxy.signal("INT");
    let signalled = Instant::now();
    let exited = proxy.wait_for_exit(Duration::from_secs(10));
    let took = signalled.elapsed();
    let response = read_response(&mut client);

    assert!(
        exited.is_some(),
        "praxis must exit on SIGINT with a request in flight:\n{}",
        proxy.logs()
    );
    assert!(
        took < Duration::from_secs(4),
        "SIGINT must not wait out shutdown_timeout_secs (30 s), exited after {took:?}"
    );
    assert!(
        !response.contains("never"),
        "the request in flight is not answered:\n{response}"
    );
}

#[test]
fn http2_body_that_never_arrives_is_answered_with_the_read_timeout() {
    let (upstream, arrived) = slow_upstream("never", Duration::from_secs(30));
    let port = free_port();
    let yaml = proxy_config(port, upstream, 1).replace(r#"path_prefix: "/""#, r#"path_prefix: "/upload""#);
    let config = Config::from_yaml(&format!("{yaml}    downstream_read_timeout_ms: 300\n")).unwrap();
    let _proxy = start_proxy(&config);

    let started = Instant::now();
    let status = h2_post_without_body(&addr(port));
    let took = started.elapsed();

    assert!(
        arrived.try_recv().is_ok(),
        "the request head is forwarded while its body is awaited"
    );
    assert!(
        status == 400 || status == 408,
        "a stalled HTTP/2 body is answered as a client timeout, got {status}"
    );
    assert!(
        took < Duration::from_secs(5),
        "the 300 ms read timeout answers it, not the upstream, took {took:?}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Loopback address for `port`.
fn addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

/// A proxy on `port` routing everything to `upstream`, draining for up to
/// `shutdown_timeout_secs`. The listener entry comes last, so a test can
/// append listener settings.
fn proxy_config(port: u16, upstream: u16, shutdown_timeout_secs: u64) -> String {
    format!(
        r#"
shutdown_timeout_secs: {shutdown_timeout_secs}
runtime:
  threads: 2
insecure_options:
  allow_private_endpoints: true
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: slow
      - filter: load_balancer
        clusters:
          - name: slow
            endpoints:
              - "127.0.0.1:{upstream}"
listeners:
  - name: web
    address: "127.0.0.1:{port}"
    filter_chains: [main]
"#
    )
}

/// An upstream that answers every request with `body` after `delay`, and
/// reports on the returned channel each request head it receives.
fn slow_upstream(body: &'static str, delay: Duration) -> (u16, mpsc::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (arrived, arrivals) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let arrived = arrived.clone();
            thread::spawn(move || {
                let mut head = [0_u8; 4096];
                if stream.read(&mut head).unwrap_or(0) == 0 {
                    return;
                }
                let _sent = arrived.send(());
                thread::sleep(delay);
                let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                let _written = stream.write_all(response.as_bytes());
            });
        }
    });
    (port, arrivals)
}

/// Open a connection to the proxy on `port` and send a `GET /` on it.
fn send_get(port: u16) -> TcpStream {
    let mut client = TcpStream::connect(addr(port)).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    client
}

/// Everything the proxy sends on `client` until it closes, resets, or the
/// read times out.
fn read_response(client: &mut TcpStream) -> String {
    let mut raw = Vec::new();
    let _read = client.read_to_end(&mut raw);
    String::from_utf8_lossy(&raw).into_owned()
}

/// Whether connecting to `port` is refused within `limit`.
fn refuses_connections_within(port: u16, limit: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < limit {
        if TcpStream::connect(addr(port)).is_err() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Open an HTTP/2 stream to `addr` for a `POST` that declares a body and
/// never sends it, and return the response status.
fn h2_post_without_body(addr: &str) -> u16 {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (client, connection) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(connection);
        let mut client = client.ready().await.unwrap();
        let request = http::Request::post(format!("http://{addr}/upload"))
            .header("content-length", "100")
            .body(())
            .unwrap();
        let (response, _body) = client.send_request(request, false).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(10), response)
            .await
            .expect("the proxy answers before the test gives up")
            .unwrap();
        response.status().as_u16()
    })
}
