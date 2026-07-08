// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for health check detection and recovery, verifying
//! that unhealthy endpoints are removed from load balancer
//! rotation.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_full_proxy, wait_for_http};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn unhealthy_endpoint_removed_from_rotation() {
    let stable_guard = start_backend_with_shutdown("stable");
    let stable_port = stable_guard.port();
    let stoppable = StoppableBackend::start("stoppable");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
insecure_options:
  allow_private_health_checks: true
clusters:
  - name: backend
    endpoints:
      - "127.0.0.1:{stable_port}"
      - "127.0.0.1:{stoppable_port}"
    health_check:
      type: http
      path: "/healthz"
      expected_status: 200
      interval_ms: 200
      timeout_ms: 100
      unhealthy_threshold: 1
      healthy_threshold: 1
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
              - "127.0.0.1:{stable_port}"
              - "127.0.0.1:{stoppable_port}"
"#,
        stoppable_port = stoppable.port,
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);

    let addr = format!("127.0.0.1:{proxy_port}");
    wait_for_http(&addr);

    let mut saw_stable = false;
    let mut saw_stoppable = false;
    for _ in 0..20 {
        let (status, body) = http_get(&addr, "/", None);
        assert_eq!(status, 200, "request should succeed while both backends healthy");
        if body == "stable" {
            saw_stable = true;
        }
        if body == "stoppable" {
            saw_stoppable = true;
        }
        if saw_stable && saw_stoppable {
            break;
        }
    }
    assert!(saw_stable, "traffic should reach stable backend");
    assert!(saw_stoppable, "traffic should reach stoppable backend");

    stoppable.stop();

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut consecutive_stable = 0;
    while Instant::now() < deadline {
        let (status, body) = http_get(&addr, "/", None);
        if status == 200 && body == "stable" {
            consecutive_stable += 1;
            if consecutive_stable >= 5 {
                break;
            }
        } else {
            consecutive_stable = 0;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        consecutive_stable >= 5,
        "after stopping one backend, all traffic should route to the remaining \
         healthy backend (got {consecutive_stable} consecutive stable responses)"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// A backend server that can be stopped mid-test.
struct StoppableBackend {
    /// Port this backend listens on.
    port: u16,

    /// Signal to stop accepting connections.
    running: Arc<AtomicBool>,
}

impl StoppableBackend {
    /// Start a stoppable backend returning `body` for every request.
    fn start(body: &str) -> Self {
        let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = Arc::clone(&running);
        let body = body.to_owned();

        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            while running_clone.load(Ordering::Relaxed) {
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

        Self { port, running }
    }

    /// Stop accepting connections.
    fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Read from a stream until the HTTP header terminator is found.
fn read_until_headers(stream: &mut TcpStream) -> String {
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
