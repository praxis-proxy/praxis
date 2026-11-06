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
    thread,
    time::{Duration, Instant},
};

use praxis_test_utils::{PraxisProcess, free_port, http_get};

/// Drain window long enough for the readiness polls and all three probes.
const DRAIN_DELAY_SECS: u64 = 40; // 40 s

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
/// Verify drain headers across HTTP/1.1, HTTP/2, and upgrades.
fn drain_marks_http1_and_spares_http2_and_upgrades() {
    let upstream = keepalive_upstream();
    let port = free_port();
    let admin_port = free_port();
    let admin = format!("127.0.0.1:{admin_port}");
    let mut proxy = PraxisProcess::spawn(&proxy_config(port, admin_port, upstream), &admin);

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

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

/// Proxy with a delayed handoff and a local backend, plus a readiness listener.
fn proxy_config(port: u16, admin_port: u16, upstream: u16) -> String {
    format!(
        r#"
shutdown_timeout_secs: 60
shutdown_drain_delay_secs: {DRAIN_DELAY_SECS}
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

/// Backend that answers normally, or switches protocols for an upgrade.
fn keepalive_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let port = listener.local_addr().expect("upstream address").port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            thread::spawn(move || {
                let mut head = [0_u8; 4096];
                loop {
                    let read = stream.read(&mut head).unwrap_or(0);
                    if read == 0 {
                        return;
                    }
                    let request = String::from_utf8_lossy(&head[..read]).to_ascii_lowercase();
                    let upgrade = request.contains("upgrade: websocket");
                    let response = if upgrade {
                        "HTTP/1.1 101 Switching Protocols\r\n\
                         Upgrade: websocket\r\n\
                         Connection: Upgrade\r\n\
                         Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
                    } else {
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                    };
                    let _written = stream.write_all(response.as_bytes());
                    if upgrade {
                        return;
                    }
                }
            });
        }
    });
    port
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
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write request");
    read_head(&mut stream)
}

/// Assert an upgrade still succeeds during the drain handoff.
///
/// The hyper backend does not tunnel protocol upgrades, so this probe only
/// runs on backends that do.
#[cfg(not(feature = "hyper"))]
fn assert_upgrade_survives_drain(port: u16) {
    let upgrade = upgrade_request(port);
    assert!(
        upgrade.starts_with("HTTP/1.1 101"),
        "an upgrade must succeed during drain: {upgrade}"
    );
    assert!(
        !upgrade.to_ascii_lowercase().contains("connection: close"),
        "an upgrade response must not carry the drain marker: {upgrade}"
    );
}

/// Send a WebSocket upgrade and return the response head.
#[cfg(not(feature = "hyper"))]
fn upgrade_request(port: u16) -> String {
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
    read_head(&mut stream)
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
