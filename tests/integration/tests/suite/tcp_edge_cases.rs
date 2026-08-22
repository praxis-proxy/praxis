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

    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect failed");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    // A TLS-looking record header claiming a 2000-byte payload forces
    // the SNI peek buffer to grow past its initial size before the
    // parse fails and the bytes are forwarded verbatim.
    let mut payload = vec![0x16, 0x03, 0x01, 0x70, 0x00];
    payload.extend(std::iter::repeat_n(0x41, 20_000));
    stream.write_all(&payload).expect("TCP write failed");
    stream.shutdown(std::net::Shutdown::Write).expect("TCP shutdown write");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("TCP read failed");
    let text = String::from_utf8_lossy(&buf);
    let preview: String = text.chars().take(24).collect();
    assert!(
        text.starts_with("peeked:"),
        "the peeked bytes must be forwarded to the backend: {preview:?}"
    );
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
