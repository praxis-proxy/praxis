// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Resilience tests for HTTP status forwarding and status-based retry.

use std::{
    io::{ErrorKind, Read as _, Write as _},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use praxis_core::config::Config;
use praxis_test_utils::{Backend, free_port, http_get, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn upstream_502_forwarded_without_status_retry_by_default() {
    let failing = CountedBackend::start(502, "bad gateway", "/retry");
    let readiness = Backend::fixed("ready").start();
    let proxy_port = free_port();
    let yaml = retry_proxy_yaml(proxy_port, readiness, &[failing.port], None, false);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    assert_eq!(failing.count(), 0, "readiness must not touch the measured cluster");
    let (status, _) = http_get(proxy.addr(), "/retry", None);
    assert_eq!(status, 502, "without Status5xx, upstream 502 should be forwarded");
    assert_eq!(
        failing.count(),
        1,
        "default policy must make exactly one backend attempt"
    );
}

#[test]
fn all_backends_502_returns_502_without_status_retry() {
    let backend_a = CountedBackend::start(502, "bad gateway a", "/retry");
    let backend_b = CountedBackend::start(502, "bad gateway b", "/retry");
    let readiness = Backend::fixed("ready").start();
    let proxy_port = free_port();
    let yaml = retry_proxy_yaml(proxy_port, readiness, &[backend_a.port, backend_b.port], None, false);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    assert_eq!((backend_a.count(), backend_b.count()), (0, 0));
    for request in 0..5 {
        let before = backend_a.count() + backend_b.count();
        let (status, _) = http_get(proxy.addr(), "/retry", None);
        let after = backend_a.count() + backend_b.count();
        assert_eq!(status, 502, "request {request}: upstream 502 must be forwarded");
        assert_eq!(
            after - before,
            1,
            "request {request}: default policy must make one attempt"
        );
        if request == 0 {
            assert_eq!(
                (backend_a.count(), backend_b.count()),
                (1, 0),
                "the measured round-robin cluster must start at its first endpoint"
            );
        }
    }
}

#[test]
fn status_5xx_retry_recovers_on_healthy_backend() {
    let failing = CountedBackend::start(503, "unavailable", "/retry");
    let healthy = CountedBackend::start(200, "ok", "/retry");
    let direct = CountedBackend::start(200, "ok", "/direct");
    let readiness = Backend::fixed("ready").start();
    let proxy_port = free_port();
    let yaml = retry_proxy_yaml(
        proxy_port,
        readiness,
        &[failing.port, healthy.port],
        Some(direct.port),
        true,
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    assert_eq!((failing.count(), healthy.count(), direct.count()), (0, 0, 0));
    let (status, body) = http_get(proxy.addr(), "/retry", None);
    assert_eq!(status, 200, "Status5xx policy should retry onto healthy host");
    assert_eq!(body, "ok");
    assert_eq!(
        (failing.count(), healthy.count()),
        (1, 1),
        "one measured request must first hit 503 then retry once on the healthy endpoint"
    );

    let (direct_status, direct_body) = http_get(proxy.addr(), "/direct", None);
    assert_eq!(direct_status, 200, "direct healthy route should succeed");
    assert_eq!(direct_body, "ok");
    assert_eq!(
        direct.count(),
        1,
        "direct success must make exactly one backend attempt"
    );
    assert_eq!((failing.count(), healthy.count()), (1, 1));
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

struct CountedBackend {
    port: u16,
    attempts: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl CountedBackend {
    fn start(status: u16, body: &str, expected_path: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind counted backend");
        let port = listener.local_addr().expect("counted backend address").port();
        listener.set_nonblocking(true).expect("nonblocking counted backend");
        let attempts = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_attempts = Arc::clone(&attempts);
        let worker_stop = Arc::clone(&stop);
        let body = body.to_owned();
        let expected_request = format!("GET {expected_path} HTTP/1.1");
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                        stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                        let mut request = Vec::new();
                        while !request.ends_with(b"\r\n\r\n") {
                            let mut chunk = [0_u8; 4096];
                            let received = stream.read(&mut chunk).expect("read counted request");
                            assert!(received > 0, "counted request must contain complete headers");
                            request.extend_from_slice(&chunk[..received]);
                            assert!(request.len() <= 16_384, "counted request headers must be bounded");
                        }
                        assert!(
                            request.starts_with(expected_request.as_bytes()),
                            "counted backend received unexpected path"
                        );
                        worker_attempts.fetch_add(1, Ordering::SeqCst);
                        let reason = match status {
                            200 => "OK",
                            502 => "Bad Gateway",
                            503 => "Service Unavailable",
                            _ => panic!("unexpected counted backend status {status}"),
                        };
                        let response = format!(
                            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        stream.write_all(response.as_bytes()).expect("write counted response");
                    },
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    },
                    Err(error) => panic!("accept counted request: {error}"),
                }
            }
        });
        Self {
            port,
            attempts,
            stop,
            worker: Some(worker),
        }
    }

    fn count(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }
}

impl Drop for CountedBackend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.expect("counted backend worker");
            }
        }
    }
}

fn retry_proxy_yaml(
    proxy_port: u16,
    readiness_port: u16,
    retry_ports: &[u16],
    direct_port: Option<u16>,
    status_retry: bool,
) -> String {
    let retry_endpoints = retry_ports
        .iter()
        .map(|port| format!("              - \"127.0.0.1:{port}\""))
        .collect::<Vec<_>>()
        .join("\n");
    let direct_route = direct_port.map_or_else(String::new, |_| {
        "          - path_prefix: \"/direct\"\n            cluster: direct\n".to_owned()
    });
    let retry_policy = if status_retry {
        "            retry_policy:\n              max_retries: 3\n              retriable_conditions: [status_5xx]\n              backoff:\n                base_interval_ms: 1\n                max_interval_ms: 5\n"
    } else {
        ""
    };
    let direct_cluster = direct_port.map_or_else(String::new, |port| {
        format!(
            "          - name: direct\n            endpoints:\n              - \"127.0.0.1:{port}\"\n{retry_policy}"
        )
    });
    format!(
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
          - path_prefix: "/retry"
            cluster: measured
{direct_route}          - path_prefix: "/"
            cluster: readiness
      - filter: load_balancer
        clusters:
          - name: measured
            endpoints:
{retry_endpoints}
            load_balancer_strategy: round_robin
{retry_policy}{direct_cluster}          - name: readiness
            endpoints:
              - "127.0.0.1:{readiness_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}
