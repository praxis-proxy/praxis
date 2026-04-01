//! Integration tests for per-listener downstream read timeout.

use std::{
    io::{Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

use praxis_core::config::Config;

use crate::common::{free_port, http_get, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn downstream_read_timeout_normal_request_succeeds() {
    let backend_port = start_backend("timeout-ok");
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    downstream_read_timeout_ms: 2000
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: backend
  - filter: load_balancer
    clusters:
      - name: backend
        endpoints:
          - "127.0.0.1:{backend_port}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(
        status, 200,
        "normal request should succeed with read timeout configured"
    );
    assert_eq!(body, "timeout-ok", "response body should pass through");
}

#[test]
fn downstream_read_timeout_stalled_body_closes_connection() {
    let backend_port = start_backend("body-ok");
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    downstream_read_timeout_ms: 500
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: backend
  - filter: load_balancer
    clusters:
      - name: backend
        endpoints:
          - "127.0.0.1:{backend_port}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let mut stream = TcpStream::connect(&addr).expect("TCP connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let request = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10000\r\n\r\npartial";
    stream
        .write_all(request.as_bytes())
        .expect("write request with partial body");

    let stall_start = Instant::now();
    let mut buf = [0u8; 4096];
    let result = stream.read(&mut buf);
    let elapsed = stall_start.elapsed();

    match result {
        Ok(0) => {
            assert!(
                elapsed < Duration::from_secs(3),
                "connection should close within timeout window, took {elapsed:?}"
            );
        },
        Err(e) => {
            assert!(
                elapsed < Duration::from_secs(3),
                "connection error should occur within timeout window, took {elapsed:?}: {e}"
            );
        },
        Ok(n) => {
            let data = String::from_utf8_lossy(&buf[..n]);
            assert!(
                elapsed < Duration::from_secs(3),
                "response should arrive within timeout window, took {elapsed:?}: {data}"
            );
        },
    }
}
