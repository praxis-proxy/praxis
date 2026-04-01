//! Core smoke tests.
//!
//! Verify the proxy starts, serves traffic, and rejects bad
//! input without crashing.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};

use praxis_core::config::Config;

use crate::common::{free_port, http_get, simple_proxy_yaml, start_backend, start_proxy, wait_for_tcp};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// The proxy starts, binds to the configured port, and
/// serves at least one request without crashing.
#[test]
fn server_starts_and_serves_request() {
    let backend_port = start_backend("smoke");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "proxy must return 200 for valid request");
    assert_eq!(body, "smoke", "response body must match backend");
}

/// The admin health endpoint returns 200 on `/healthy` and
/// `/ready`.
#[test]
fn health_endpoints_return_200() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let admin_port = free_port();

    let yaml = format!(
        r#"
admin_address: "127.0.0.1:{admin_port}"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
routes:
  - path_prefix: "/"
    cluster: "backend"
clusters:
  - name: "backend"
    endpoints:
      - "127.0.0.1:{backend_port}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    start_proxy(&config);

    let admin_addr = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin_addr);

    let (healthy_status, _) = http_get(&admin_addr, "/healthy", None);
    let (ready_status, _) = http_get(&admin_addr, "/ready", None);

    assert_eq!(healthy_status, 200, "/healthy must return 200");
    assert_eq!(ready_status, 200, "/ready must return 200");
}

/// A request through the proxy reaches the backend and the
/// response body arrives intact.
#[test]
fn http_round_trip_preserves_body() {
    let backend_port = start_backend("hello from backend");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, body) = http_get(&addr, "/anything", None);
    assert_eq!(status, 200, "round-trip must return 200");
    assert_eq!(body, "hello from backend", "response body must match backend");
}

/// A `static_response` filter returns a fixed body without
/// contacting any upstream.
#[test]
fn static_response_without_upstream() {
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        body: "static reply"
        headers:
          - name: "Content-Type"
            value: "text/plain"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "static response must return 200");
    assert_eq!(body, "static reply", "static response body must match config");
}

/// Configs with missing required fields are rejected at
/// parse time, not at runtime with a panic.
#[test]
fn invalid_config_rejected_at_parse_time() {
    let result = Config::from_yaml("clusters: []");
    assert!(result.is_err(), "config with no listeners should fail to parse");
}

/// Configs referencing a nonexistent filter chain are
/// rejected during validation.
#[test]
fn unknown_filter_chain_rejected() {
    let yaml = r#"
listeners:
  - name: default
    address: "127.0.0.1:0"
    filter_chains:
      - nonexistent
"#;
    let config = Config::from_yaml(yaml);

    match config {
        Err(_) => {},
        Ok(cfg) => {
            assert!(
                cfg.validate().is_err(),
                "referencing unknown chain should produce \
                 a validation error"
            );
        },
    }
}

/// Start a raw TCP echo server that reads bytes and writes
/// them back.
fn start_tcp_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        },
                    }
                }
            });
        }
    });

    port
}

/// Bytes sent through a TCP proxy arrive at the backend and
/// the echo comes back intact.
#[test]
fn tcp_proxy_round_trip() {
    let echo_port = start_tcp_echo_server();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: tcp-test
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    upstream: "127.0.0.1:{echo_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    std::thread::spawn(move || {
        praxis::run_server(config);
    });

    let proxy_addr = format!("127.0.0.1:{proxy_port}");
    wait_for_tcp(&proxy_addr);

    let mut stream = TcpStream::connect(&proxy_addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

    let payload = b"smoke test payload";
    stream.write_all(payload).unwrap();

    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], payload, "TCP echo response did not match sent payload");
}
