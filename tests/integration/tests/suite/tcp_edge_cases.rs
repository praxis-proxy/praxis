// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for TCP proxy edge cases: session timeouts,
//! maximum session duration, and connect-filter rejections.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    sync::Arc,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_filter::{FilterAction, FilterError, FilterFactory, FilterRegistry, Rejection, TcpFilter, TcpFilterContext};
use praxis_test_utils::{
    free_port, start_full_proxy, start_full_proxy_with_registry, start_tcp_tagged_backend, wait_for_tcp,
};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// YAML for a TCP listener proxying to one backend, with optional
/// extra listener settings and a leading filter entry.
fn tcp_yaml(proxy_port: u16, backend_port: u16, listener_extra: &str, extra_filter: &str) -> String {
    format!(
        r#"
listeners:
  - name: tcp_edge
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    cluster: pool
    filter_chains: [chain]
{listener_extra}

insecure_options:
  allow_private_endpoints: true
  allow_private_upstreams: true

clusters:
  - name: pool
    endpoints:
      - "127.0.0.1:{backend_port}"

filter_chains:
  - name: chain
    filters:
{extra_filter}
      - filter: tcp_load_balancer
        clusters:
          - name: pool
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn tcp_session_timeout_closes_idle_session() {
    let backend_port = start_holding_backend();
    let proxy_port = free_port();
    let yaml = tcp_yaml(proxy_port, backend_port, "    tcp_session_timeout_ms: 400", "");
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect failed");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    // Send a little traffic so the session passes the SNI peek and
    // enters forwarding, then hold the connection open; the proxy
    // must close it when the session timeout elapses.
    stream.write_all(b"plain-preamble").expect("TCP write failed");
    let started = Instant::now();
    let mut buf = Vec::new();
    let read = stream.read_to_end(&mut buf);
    let elapsed = started.elapsed();

    assert!(read.is_ok(), "the proxy should close the connection cleanly: {read:?}");
    assert!(
        elapsed < Duration::from_secs(4),
        "the session timeout should close the connection promptly, took {elapsed:?}, buf={:?}",
        String::from_utf8_lossy(&buf)
    );
}

#[test]
fn tcp_session_omitted_timeout_gets_default_and_forwards() {
    // No tcp_session_timeout_ms in config: validation applies the 5-minute
    // default, and forwarding must relay traffic both ways and propagate the
    // client's EOF through to a clean close long before that deadline.
    let backend_port = start_tcp_tagged_backend("defaulted");
    let proxy_port = free_port();
    let yaml = tcp_yaml(proxy_port, backend_port, "", "");
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    // One connect/write/read exchange. `None` if the proxy shed the
    // connection during setup (a clean empty close under suite load).
    let attempt = || -> Option<String> {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        stream.write_all(b"default-timeout-traffic").ok()?;
        // Half-close: the proxy must forward the EOF; the tagged backend
        // echoes and closes, and the proxy must relay that close back.
        stream.shutdown(std::net::Shutdown::Write).ok()?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).ok()?;
        Some(String::from_utf8_lossy(&buf).into_owned())
    };

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = String::from("<connection shed on every attempt>");
    loop {
        if let Some(text) = attempt() {
            if text == "defaulted:default-timeout-traffic" {
                return;
            }
            last = text.chars().take(48).collect();
        }
        assert!(
            Instant::now() < deadline,
            "a defaulted-timeout session must forward bytes and close cleanly: {last:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Start a backend that accepts connections and holds them open
/// without responding, so sessions only end when the proxy ends them.
fn start_holding_backend() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind holding backend");
    let port = listener.local_addr().expect("holding backend port").port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buf = [0_u8; 1024];
                // Hold the socket open, draining until the peer closes.
                while let Ok(n) = std::io::Read::read(&mut stream, &mut buf) {
                    if n == 0 {
                        break;
                    }
                }
            });
        }
    });
    port
}

#[test]
fn tcp_max_duration_closes_long_session() {
    let backend_port = start_holding_backend();
    let proxy_port = free_port();
    let yaml = tcp_yaml(proxy_port, backend_port, "    tcp_max_duration_secs: 1", "");
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect failed");
    stream
        .set_read_timeout(Some(Duration::from_secs(6)))
        .expect("set read timeout");

    stream.write_all(b"plain-preamble").expect("TCP write failed");
    let started = Instant::now();
    let mut buf = Vec::new();
    let read = stream.read_to_end(&mut buf);
    let elapsed = started.elapsed();

    assert!(read.is_ok(), "the proxy should close the connection cleanly: {read:?}");
    assert!(
        elapsed >= Duration::from_millis(900),
        "the session should live until the duration cap, took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the duration cap should close the connection, took {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// Connect-filter outcomes
// ---------------------------------------------------------------------------

/// TCP filter that rejects every connection.
struct RejectingTcpFilter;

#[async_trait::async_trait]
impl TcpFilter for RejectingTcpFilter {
    fn name(&self) -> &'static str {
        "test_tcp_reject"
    }

    async fn on_connect(&self, _ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Reject(Rejection::status(403)))
    }
}

/// TCP filter that errors on every connection.
struct ErroringTcpFilter;

#[async_trait::async_trait]
impl TcpFilter for ErroringTcpFilter {
    fn name(&self) -> &'static str {
        "test_tcp_error"
    }

    async fn on_connect(&self, _ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Err("test_tcp_error: connect filter failure".to_owned().into())
    }
}

/// Registry with builtins plus the rejecting/erroring TCP test filters.
fn tcp_test_registry() -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "test_tcp_reject",
            FilterFactory::Tcp(Arc::new(|_config| Ok(Box::new(RejectingTcpFilter)))),
        )
        .unwrap();
    registry
        .register(
            "test_tcp_error",
            FilterFactory::Tcp(Arc::new(|_config| Ok(Box::new(ErroringTcpFilter)))),
        )
        .unwrap();
    registry
}

/// Connect and verify the proxy drops the connection without
/// forwarding any backend data.
fn assert_connection_dropped(proxy_port: u16) {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect failed");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    stream.write_all(b"data").expect("TCP write failed");

    let mut buf = Vec::new();
    let read = stream.read_to_end(&mut buf);
    assert!(read.is_ok(), "the proxy should close the connection: {read:?}");
    assert!(
        buf.is_empty(),
        "no backend data should be forwarded on a refused connection, got: {buf:?}"
    );
}

#[test]
fn tcp_connect_filter_rejection_drops_connection() {
    let backend_port = start_tcp_tagged_backend("guarded");
    let proxy_port = free_port();
    let yaml = tcp_yaml(proxy_port, backend_port, "", "      - filter: test_tcp_reject");
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = tcp_test_registry();
    let _proxy = start_full_proxy_with_registry(&config, &registry);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    assert_connection_dropped(proxy_port);
}

#[test]
fn tcp_connect_filter_error_drops_connection() {
    let backend_port = start_tcp_tagged_backend("errored");
    let proxy_port = free_port();
    let yaml = tcp_yaml(proxy_port, backend_port, "", "      - filter: test_tcp_error");
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = tcp_test_registry();
    let _proxy = start_full_proxy_with_registry(&config, &registry);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    assert_connection_dropped(proxy_port);
}

#[test]
fn tcp_oversized_tls_record_peek_grows_buffer_and_forwards() {
    let backend_port = start_tcp_tagged_backend("peeked");
    let proxy_port = free_port();
    let yaml = tcp_yaml(proxy_port, backend_port, "", "");
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    // A TLS-looking record header whose length field (big-endian 0x07D0 =
    // 2000) claims a 2000-byte fragment forces the SNI peek buffer to grow
    // past its initial 1 KiB before the record completes, the handshake type
    // (0x41) is rejected as not a ClientHello, and the bytes are forwarded
    // verbatim. Keeping the length under the 16 KiB peek ceiling lets the
    // record complete so the peek returns promptly instead of reading to its
    // cap (which would time out and drop the connection under load).
    let mut payload = vec![0x16, 0x03, 0x01, 0x07, 0xD0];
    payload.extend(std::iter::repeat_n(0x41, 20_000));

    // One connect/write/read exchange. Returns the backend's echo, or `None`
    // if the proxy shed the connection during setup (a clean empty close).
    let attempt = || -> Option<String> {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        stream.write_all(&payload).ok()?;
        stream.shutdown(std::net::Shutdown::Write).ok()?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).ok()?;
        Some(String::from_utf8_lossy(&buf).into_owned())
    };

    // Under the heavy concurrency of the full suite (many in-process proxies,
    // plus the OTLP exporter when the `otel` feature is enabled) the proxy can
    // shed a connection during setup, closing it cleanly with no bytes
    // forwarded. That is valid overload behavior, so retry the exchange; the
    // guarantee under test is only that peeked bytes reach the backend, which
    // needs a single unshed attempt.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = String::from("<connection shed on every attempt>");
    loop {
        if let Some(text) = attempt() {
            if text.starts_with("peeked:") {
                return;
            }
            last = text.chars().take(24).collect();
        }
        assert!(
            Instant::now() < deadline,
            "the peeked bytes must be forwarded to the backend within the retry window: {last:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn tcp_proxy_shutdown_closes_open_sessions() {
    let backend_port = start_holding_backend();
    let proxy_port = free_port();
    let yaml = tcp_yaml(proxy_port, backend_port, "", "");
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect failed");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    stream.write_all(b"plain-preamble").expect("TCP write failed");

    // Give the session a moment to enter forwarding, then stop the proxy.
    std::thread::sleep(Duration::from_millis(300));
    drop(proxy);

    let mut buf = Vec::new();
    let read = stream.read_to_end(&mut buf);
    assert!(
        read.is_ok(),
        "proxy shutdown should close open sessions cleanly: {read:?}"
    );
}

#[test]
fn tcp_unresolvable_upstream_drops_connection() {
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: tcp_nodns
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    cluster: pool
    filter_chains: [chain]

insecure_options:
  allow_private_endpoints: true
  allow_private_upstreams: true

clusters:
  - name: pool
    endpoints:
      - "praxis-invalid.invalid:80"

filter_chains:
  - name: chain
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: pool
            endpoints:
              - "praxis-invalid.invalid:80"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect failed");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    stream.write_all(b"plain-preamble").expect("TCP write failed");

    let mut buf = Vec::new();
    let read = stream.read_to_end(&mut buf);
    assert!(read.is_ok(), "the proxy should close the connection: {read:?}");
    assert!(
        buf.is_empty(),
        "no data should come back for an unresolvable upstream, got: {buf:?}"
    );
}
