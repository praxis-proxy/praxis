// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for proxy behavior when backends go down and come
//! back, verifying that traffic resumes correctly.

use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_backend, start_proxy, wait_for_http};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn backend_restart_resumes_traffic() {
    let mut backend = RestartableBackend::start("version-1");
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
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
        backend_port = backend.port,
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "initial request should succeed");
    assert_eq!(body, "version-1", "should get version-1 response");

    backend.restart("version-2");

    let mut saw_v2 = false;
    for i in 0..10 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        if status == 200 && body == "version-2" {
            saw_v2 = true;
            break;
        }
        assert!(
            status == 200 || status == 502,
            "request {i} during restart should be 200 or 502, got {status}"
        );
    }
    assert!(saw_v2, "traffic should resume with version-2 after backend restart");
}

#[test]
fn backend_down_then_up_recovers() {
    let mut backend = RestartableBackend::start("before-outage");
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
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
        backend_port = backend.port,
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "pre-outage request should succeed");

    backend.stop();

    for i in 0..3 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 502, "request {i} during outage should return 502");
    }

    backend.restart("after-outage");

    let mut recovered = false;
    for i in 0..10 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        if status == 200 && body == "after-outage" {
            recovered = true;
            break;
        }
        assert!(
            status == 200 || status == 502,
            "request {i} during recovery should be 200 or 502, got {status}"
        );
    }
    assert!(recovered, "proxy should recover after backend comes back up");
}

#[test]
fn mixed_healthy_unhealthy_endpoints_serve_from_healthy() {
    let live_port = start_backend("live-endpoint");
    let dead_port = free_port();
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
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{live_port}"
              - "127.0.0.1:{dead_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let mut successes = 0_u32;
    let mut failures = 0_u32;
    for _ in 0..20 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        match status {
            200 => {
                assert_eq!(body, "live-endpoint", "200 should come from the live endpoint");
                successes += 1;
            },
            502 => failures += 1,
            other => panic!("unexpected status {other} from mixed cluster"),
        }
    }

    assert!(successes > 0, "at least some requests should reach the live endpoint");
    assert!(failures > 0, "at least some requests should hit the dead endpoint");
}

#[test]
fn all_endpoints_dead_returns_502_consistently() {
    let dead_a = free_port();
    let dead_b = free_port();
    let dead_c = free_port();
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
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{dead_a}"
              - "127.0.0.1:{dead_b}"
              - "127.0.0.1:{dead_c}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    for i in 0..5 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 502, "request {i} with all endpoints dead should return 502");
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// A backend that can be stopped and restarted on the same port.
struct RestartableBackend {
    /// The port this backend binds to.
    port: u16,

    /// Signal to stop the current listener.
    running: Arc<AtomicBool>,
}

impl RestartableBackend {
    /// Start a backend that returns `body` for every request.
    fn start(body: &str) -> Self {
        let port = free_port();
        let running = Arc::new(AtomicBool::new(true));
        Self::spawn_listener(port, body, Arc::clone(&running));
        wait_for_http(&format!("127.0.0.1:{port}"));
        Self { port, running }
    }

    /// Stop accepting connections.
    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(50));
    }

    /// Restart the backend on the same port with a new body.
    fn restart(&mut self, body: &str) {
        self.running.store(false, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(50));
        let new_running = Arc::new(AtomicBool::new(true));
        Self::spawn_listener(self.port, body, Arc::clone(&new_running));
        self.running = new_running;
        let port = self.port;
        wait_for_http(&format!("127.0.0.1:{port}"));
    }

    /// Spawn a TCP listener thread for the backend.
    fn spawn_listener(port: u16, body: &str, running: Arc<AtomicBool>) {
        let body = body.to_owned();
        std::thread::spawn(move || {
            let listener = TcpListener::bind(format!("127.0.0.1:{port}")).expect("bind for restart");
            drop(listener.set_nonblocking(true));
            while running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let body = body.clone();
                        std::thread::spawn(move || {
                            drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
                            let _headers = read_until_headers(&mut stream);
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _sent = stream.write_all(resp.as_bytes());
                        });
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    },
                    Err(_) => break,
                }
            }
        });
    }
}

/// Read from a stream until the HTTP header terminator is found.
fn read_until_headers(stream: &mut std::net::TcpStream) -> String {
    let mut data = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
        if data.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&data).into_owned()
}
