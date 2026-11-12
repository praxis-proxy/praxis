// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Wire-level checks for the readiness-first drain handshake.
//!
//! RFC 9112 §9.6: a server that intends to close an HTTP/1.1 connection
//! sends `Connection: close` so the client does not reuse it. HTTP/2 forbids
//! connection-specific headers (RFC 9113 §8.2.2), and an upgraded connection
//! already switched protocols, so neither carries the drain marker.

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use praxis_test_utils::{PraxisProcess, free_port, http_get};

/// Drain window long enough for the readiness polls and all three probes.
const DRAIN_DELAY_SECS: u64 = 40; // 40 s

/// Drain window for the HTTP/2 GOAWAY check: long enough to observe the frame,
/// short enough to keep the test quick.
#[cfg(feature = "hyper")]
const GOAWAY_DRAIN_DELAY_SECS: u64 = 10; // 10 s

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn drain_marks_http1_and_spares_http2_and_upgrades() {
    let upstream = start_upstream(false);
    let port = free_port();
    let admin_port = free_port();
    let admin = format!("127.0.0.1:{admin_port}");
    let mut proxy = PraxisProcess::spawn(&proxy_config(port, admin_port, upstream.port()), &admin);

    wait_for_ready(&admin, 200, "the proxy must serve before the drain starts");
    proxy.signal("TERM");
    wait_for_ready(&admin, 503, "the drain must fail readiness immediately");

    let http1 = http1_get_keepalive(port);
    assert!(
        http1.starts_with("HTTP/1.1 200"),
        "HTTP/1 request must succeed during drain: {http1}"
    );
    assert!(
        http1.to_ascii_lowercase().contains("connection: close"),
        "RFC 9112 §9.6: an HTTP/1.1 response during drain must close the connection: {http1}"
    );

    let http2 = h2c_get_headers(port, "/");
    assert_eq!(http2.status(), 200, "HTTP/2 request must succeed during drain");
    assert!(
        http2.headers().get(http::header::CONNECTION).is_none(),
        "RFC 9113 §8.2.2: an HTTP/2 response must not carry Connection: {:?}",
        http2.headers()
    );

    #[cfg(not(feature = "hyper"))]
    assert_upgrade_survives_drain(port);

    let status = proxy.wait_for_exit(Duration::from_secs(90));
    assert!(
        status.is_some_and(|status| status.success()),
        "the delayed handoff must exit cleanly"
    );
}

#[test]
#[cfg(not(feature = "hyper"))]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn drain_does_not_close_after_an_informational_response() {
    let upstream = start_upstream(false);
    let port = free_port();
    let admin_port = free_port();
    let admin = format!("127.0.0.1:{admin_port}");
    let mut proxy = PraxisProcess::spawn(&proxy_config(port, admin_port, upstream.port()), &admin);

    wait_for_ready(&admin, 200, "the proxy must serve before the drain starts");
    proxy.signal("TERM");
    wait_for_ready(&admin, 503, "the drain must fail readiness immediately");

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream
        .write_all(
            b"POST / HTTP/1.1\r\n\
              Host: localhost\r\n\
              Expect: 100-continue\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .expect("write request");
    let interim = read_head_exact(&mut stream);
    assert!(
        interim.starts_with("HTTP/1.1 100"),
        "the proxy must forward the interim response during drain: {interim}"
    );
    assert!(
        !interim.to_ascii_lowercase().contains("connection: close"),
        "RFC 9112 §9.6: an informational response must not close the connection: {interim}"
    );
    let final_head = read_head_exact(&mut stream);
    assert!(
        final_head.starts_with("HTTP/1.1 200"),
        "the final response must still arrive: {final_head}"
    );
    assert!(
        final_head.to_ascii_lowercase().contains("connection: close"),
        "RFC 9112 §9.6: the final response during drain must close the connection: {final_head}"
    );

    let status = proxy.wait_for_exit(Duration::from_secs(90));
    assert!(
        status.is_some_and(|status| status.success()),
        "the delayed handoff must exit cleanly"
    );
}

/// A filter-generated reply during the drain also closes the connection.
///
/// The iterative request router answers some requests without an
/// upstream, so the drain marker cannot depend on the response filter
/// that runs after one. RFC 9112 §9.6 still wants `Connection: close`
/// on that reply, and the status proves the static response filter
/// answered rather than a fall-through to the routed backend.
#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn drain_marks_a_filter_generated_reply() {
    let upstream = start_upstream(false);
    let port = free_port();
    let admin_port = free_port();
    let admin = format!("127.0.0.1:{admin_port}");
    let mut proxy = PraxisProcess::spawn(&terminal_reply_config(port, admin_port, upstream.port()), &admin);

    wait_for_ready(&admin, 200, "the proxy must serve before the drain starts");
    proxy.signal("TERM");
    wait_for_ready(&admin, 503, "the drain must fail readiness immediately");

    let http1 = http1_get_keepalive_on(port, "/terminal");
    assert!(
        http1.starts_with("HTTP/1.1 204"),
        "the static response filter must answer /terminal itself: {http1}"
    );
    assert!(
        http1.to_ascii_lowercase().contains("connection: close"),
        "RFC 9112 §9.6: a filter-generated HTTP/1.1 reply during drain must close the connection: {http1}"
    );

    let status = proxy.wait_for_exit(Duration::from_secs(90));
    assert!(
        status.is_some_and(|status| status.success()),
        "the delayed handoff must exit cleanly"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn sighup_does_not_stop_the_proxy() {
    let upstream = start_upstream(false);
    let port = free_port();
    let admin_port = free_port();
    let admin = format!("127.0.0.1:{admin_port}");
    let mut proxy = PraxisProcess::spawn(&proxy_config(port, admin_port, upstream.port()), &admin);

    wait_for_ready(&admin, 200, "the proxy must serve before SIGHUP");
    proxy.signal("HUP");
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        assert_eq!(
            http_get(&admin, "/ready", None).0,
            200,
            "SIGHUP must not drop readiness"
        );
        let response = http1_get_keepalive(port);
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "SIGHUP must not stop requests: {response}"
        );
        thread::sleep(Duration::from_millis(100));
    }

    proxy.signal("TERM");
    let status = proxy.wait_for_exit(Duration::from_secs(90));
    assert!(
        status.is_some_and(|status| status.success()),
        "the proxy must still shut down cleanly after SIGHUP"
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn in_flight_request_finishes_during_the_drain_delay() {
    let upstream = start_upstream(true);
    let port = free_port();
    let admin_port = free_port();
    let admin = format!("127.0.0.1:{admin_port}");
    let mut proxy = PraxisProcess::spawn(&proxy_config(port, admin_port, upstream.port()), &admin);

    wait_for_ready(&admin, 200, "the proxy must serve before the in-flight request");
    let request = thread::spawn(move || http1_get_keepalive(port));
    thread::sleep(Duration::from_millis(200));

    proxy.signal("TERM");
    wait_for_ready(&admin, 503, "the drain must begin while the request is in flight");
    upstream.release();

    let response = request.join().expect("in-flight request thread");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the in-flight request must complete during drain: {response}"
    );
    let status = proxy.wait_for_exit(Duration::from_secs(90));
    assert!(
        status.is_some_and(|status| status.success()),
        "the delayed handoff must exit cleanly"
    );
}

/// Existing HTTP/2 connections get GOAWAY when the drain begins, and their
/// in-flight streams still complete.
///
/// The Hyper listener owns each downstream connection, so it can start the
/// HTTP/2 graceful shutdown at the lifecycle transition. Pingora's HTTP/2
/// connection loop is internal to its runtime and only starts that shutdown
/// when the listener itself stops, after the delay.
#[test]
#[cfg(feature = "hyper")]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn draining_http2_connection_receives_goaway_and_finishes_its_stream() {
    let upstream = start_upstream(true);
    let port = free_port();
    let admin_port = free_port();
    let admin = format!("127.0.0.1:{admin_port}");
    let mut proxy = PraxisProcess::spawn(
        &proxy_config_with_drain(port, admin_port, upstream.port(), GOAWAY_DRAIN_DELAY_SECS),
        &admin,
    );

    wait_for_ready(&admin, 200, "the proxy must serve before the drain starts");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build the HTTP/2 test runtime");
    let (mut sender, response, connection) = runtime.block_on(async {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect to the proxy");
        let (mut sender, connection) = h2::client::handshake(tcp).await.expect("HTTP/2 handshake");
        let connection = tokio::spawn(async move {
            drop(connection.await);
        });
        let request = http::Request::get("http://localhost/").body(()).expect("build request");
        let (response, _send) = sender.send_request(request, true).expect("send request");
        (sender, response, connection)
    });
    thread::sleep(Duration::from_millis(200));

    let started = Instant::now();
    proxy.signal("TERM");
    wait_for_ready(&admin, 503, "the drain must begin while the request is in flight");

    runtime.block_on(async {
        let goaway = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match std::future::poll_fn(|cx| sender.poll_ready(cx)).await {
                    Ok(()) => tokio::time::sleep(Duration::from_millis(10)).await,
                    Err(error) => break error,
                }
            }
        })
        .await
        .expect("the draining proxy must send GOAWAY before the drain delay ends");
        assert!(
            goaway.is_go_away(),
            "the client must observe a GOAWAY error, got {goaway:?}"
        );
        assert_eq!(
            goaway.reason(),
            Some(h2::Reason::NO_ERROR),
            "a drain GOAWAY must not carry an error: {goaway:?}"
        );

        upstream.release();
        let response = response.await.expect("the in-flight stream must complete");
        assert_eq!(
            response.status(),
            200,
            "an in-flight HTTP/2 stream must finish during drain"
        );
        drop(tokio::time::timeout(Duration::from_secs(5), connection).await);
    });

    assert!(
        started.elapsed() < Duration::from_secs(GOAWAY_DRAIN_DELAY_SECS),
        "GOAWAY must arrive before the drain delay ends"
    );
    let status = proxy.wait_for_exit(Duration::from_secs(90));
    assert!(
        status.is_some_and(|status| status.success()),
        "the delayed handoff must exit cleanly"
    );
}

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

/// Proxy with a delayed handoff and a local backend, plus a readiness listener.
fn proxy_config(port: u16, admin_port: u16, upstream: u16) -> String {
    proxy_config_with_drain(port, admin_port, upstream, DRAIN_DELAY_SECS)
}

/// Proxy with a caller-selected drain delay and a local backend.
fn proxy_config_with_drain(port: u16, admin_port: u16, upstream: u16, drain_delay_secs: u64) -> String {
    format!(
        r#"
shutdown_timeout_secs: 60
shutdown_drain_delay_secs: {drain_delay_secs}
runtime:
  threads: 2
insecure_options:
  allow_private_endpoints: true
admin:
  metrics_address: "127.0.0.1:{admin_port}"
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
              - "127.0.0.1:{upstream}"
listeners:
  - name: web
    address: "127.0.0.1:{port}"
    filter_chains: [main]
"#
    )
}

/// Proxy whose `/terminal` prefix is answered by a `static_response`
/// filter ahead of the router, so the reply is generated without an
/// upstream.
fn terminal_reply_config(port: u16, admin_port: u16, upstream: u16) -> String {
    format!(
        r#"
shutdown_timeout_secs: 60
shutdown_drain_delay_secs: 40
runtime:
  threads: 2
insecure_options:
  allow_private_endpoints: true
admin:
  metrics_address: "127.0.0.1:{admin_port}"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        conditions:
          - when:
              path_prefix: /terminal
        status: 204
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{upstream}"
listeners:
  - name: web
    address: "127.0.0.1:{port}"
    filter_chains: [main]
"#
    )
}

/// Guarded backend that serves keep-alive requests and echoes upgrades.
struct Upstream {
    port: u16,
    shutdown: Arc<AtomicBool>,
    hold: Arc<(Mutex<bool>, Condvar)>,
}

impl Upstream {
    fn port(&self) -> u16 {
        self.port
    }

    fn release(&self) {
        let (released, wake) = &*self.hold;
        *released.lock().expect("release upstream responses") = true;
        wake.notify_all();
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        drop(TcpStream::connect(("127.0.0.1", self.port)));
    }
}

/// Starts the backend; `hold_responses` blocks each response until released.
fn start_upstream(hold_responses: bool) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let port = listener.local_addr().expect("upstream address").port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let accept_shutdown = Arc::clone(&shutdown);
    let hold = Arc::new((Mutex::new(!hold_responses), Condvar::new()));
    let response_hold = Arc::clone(&hold);
    thread::spawn(move || {
        for stream in listener.incoming() {
            if accept_shutdown.load(Ordering::Acquire) {
                break;
            }
            let Ok(mut stream) = stream else { break };
            let hold = Arc::clone(&response_hold);
            thread::spawn(move || {
                let mut buffer = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    let read = stream.read(&mut chunk).unwrap_or(0);
                    if read == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                    while let Some(end) = head_end(&buffer) {
                        let request = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
                        buffer.drain(..end);
                        if request.contains("upgrade: websocket") {
                            let _accepted = stream.write_all(
                                b"HTTP/1.1 101 Switching Protocols\r\n\
                                  Upgrade: websocket\r\n\
                                  Connection: Upgrade\r\n\
                                  Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                            );
                            echo_upgraded(&mut stream);
                            return;
                        }
                        if request.contains("expect: 100-continue") {
                            let _continued = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                        }
                        let (released, wake) = &*hold;
                        let mut released = released.lock().expect("wait for the upstream release");
                        while !*released {
                            released = wake.wait(released).expect("wait for the upstream release");
                        }
                        drop(released);
                        let _answered = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                    }
                }
            });
        }
    });
    Upstream { port, shutdown, hold }
}

/// Returns the index just past the HTTP head terminator, if present.
fn head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|start| start.saturating_add(4))
}

/// Echoes tunnelled bytes until the client or proxy closes the upgrade.
fn echo_upgraded(stream: &mut TcpStream) {
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(read) => {
                if stream.write_all(&chunk[..read]).is_err() {
                    return;
                }
            },
        }
    }
}

/// Poll `/ready` until it reports `expected`, failing after a short wait.
fn wait_for_ready(admin: &str, expected: u16, context: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if http_get(admin, "/ready", None).0 == expected {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("{context} (last /ready: {:?})", http_get(admin, "/ready", None));
}

/// Send a keep-alive HTTP/1.1 request and return the response head.
fn http1_get_keepalive(port: u16) -> String {
    http1_get_keepalive_on(port, "/")
}

/// Send a keep-alive HTTP/1.1 request for `path` and return the head.
fn http1_get_keepalive_on(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
    stream.write_all(request.as_bytes()).expect("write request");
    read_head(&mut stream)
}

/// Assert an upgrade still carries data during the drain handoff.
///
/// The hyper backend does not tunnel protocol upgrades, so this probe only
/// runs on backends that do.
#[cfg(not(feature = "hyper"))]
fn assert_upgrade_survives_drain(port: u16) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream
        .write_all(
            b"GET / HTTP/1.1\r\n\
              Host: localhost\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .expect("write upgrade request");
    let head = read_head(&mut stream);
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "an upgrade must succeed during drain: {head}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("connection: close"),
        "an upgrade response must not carry the drain marker: {head}"
    );
    let message = b"drain-ping";
    stream.write_all(message).expect("write into the upgraded tunnel");
    let mut echoed = [0_u8; 10];
    stream
        .read_exact(&mut echoed)
        .expect("data must flow through the upgraded tunnel during drain");
    assert_eq!(&echoed, message, "the upgraded tunnel must echo data during drain");
}

/// Read exactly one response head, leaving any following bytes unread.
#[cfg(not(feature = "hyper"))]
fn read_head_exact(stream: &mut TcpStream) -> String {
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) => response.push(byte[0]),
        }
    }
    String::from_utf8_lossy(&response).into_owned()
}

/// Read through the response header terminator.
fn read_head(stream: &mut TcpStream) -> String {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
        }
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&response).into_owned()
}

/// Fetch an HTTP/2 response with its headers so a drain marker can be checked.
fn h2c_get_headers(port: u16, path: &str) -> http::Response<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build the HTTP/2 test runtime");
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect to the proxy");
            let (mut client, connection) = h2::client::handshake(tcp).await.expect("HTTP/2 handshake");
            tokio::spawn(async move {
                drop(connection.await);
            });
            let request = http::Request::get(path)
                .header("host", "localhost")
                .body(())
                .expect("build request");
            let (response, _) = client.send_request(request, true).expect("send request");
            let response = response.await.expect("read response");
            let mut builder = http::Response::builder().status(response.status());
            for (name, value) in response.headers() {
                builder = builder.header(name, value);
            }
            builder.body(()).expect("rebuild response")
        })
        .await
        .expect("HTTP/2 exchange must finish during drain")
    })
}
