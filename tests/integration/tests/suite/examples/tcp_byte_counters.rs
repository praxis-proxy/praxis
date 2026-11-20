// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the tcp-byte-counters example
//! configuration.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

use praxis_test_utils::{
    bind_unique_port, free_port, http_get, start_full_proxy, start_tcp_tagged_backend, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn tcp_byte_counters_example_emits_counters() {
    let backend = ByteBackend::start();
    let proxy_port = free_port();
    let admin_port = free_port();
    let mut config = super::load_example_config(
        "observability/tcp-byte-counters.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:5432", proxy_port),
            ("127.0.0.1:15432", backend.port),
            ("127.0.0.1:9902", admin_port),
        ]),
    );
    let listener = format!("postgres-byte-example-{proxy_port}");
    config.listeners[0].name = listener.clone();

    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let (status, baseline) = http_get(&admin, "/metrics", None);
    assert_eq!(status, 200, "baseline scrape must succeed");
    let before_received = counter_value(&baseline, "praxis_tcp_bytes_received_total", &listener).unwrap_or(0.0);
    let before_sent = counter_value(&baseline, "praxis_tcp_bytes_sent_total", &listener).unwrap_or(0.0);
    let payload = b"SELECT 1";
    let response = send_and_close(proxy_port, payload);
    assert_eq!(response, "database reply", "example proxy must return backend bytes");
    assert_eq!(
        backend
            .received
            .recv_timeout(Duration::from_secs(2))
            .expect("complete backend payload"),
        payload,
        "backend must receive full payload"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut body = String::new();
    let mut after_received = None;
    let mut after_sent = None;
    while std::time::Instant::now() < deadline {
        let (status, scrape) = http_get(&admin, "/metrics", None);
        assert_eq!(status, 200, "/metrics should return 200");
        body = scrape;
        after_received = counter_value(&body, "praxis_tcp_bytes_received_total", &listener);
        after_sent = counter_value(&body, "praxis_tcp_bytes_sent_total", &listener);
        if after_received == Some(before_received + payload.len() as f64)
            && after_sent == Some(before_sent + response.len() as f64)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        after_received,
        Some(before_received + payload.len() as f64),
        "received series for this listener must grow by client bytes: {body}"
    );
    assert_eq!(
        after_sent,
        Some(before_sent + response.len() as f64),
        "sent series for this listener must grow by unequal backend bytes: {body}"
    );
}

#[test]
fn tcp_byte_counters_example_forwards_traffic() {
    let backend_port = start_tcp_tagged_backend("dbdata");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "observability/tcp-byte-counters.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:5432", proxy_port),
            ("127.0.0.1:15432", backend_port),
            ("127.0.0.1:9902", admin_port),
        ]),
    );

    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let resp = send_and_close(proxy_port, b"hello");
    assert!(
        resp.contains("dbdata"),
        "tcp-byte-counters example should forward to tagged backend, got: {resp}"
    );
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

fn send_and_close(proxy_port: u16, payload: &[u8]) -> String {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    stream.write_all(payload).expect("TCP write");
    stream.shutdown(std::net::Shutdown::Write).expect("shutdown write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("TCP read");
    String::from_utf8_lossy(&buf).into_owned()
}

fn counter_value(scrape: &str, metric: &str, listener: &str) -> Option<f64> {
    scrape
        .lines()
        .find(|line| line.starts_with(&format!("{metric}{{")) && line.contains(&format!("listener=\"{listener}\"")))
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse().ok())
}

struct ByteBackend {
    port: u16,
    received: std::sync::mpsc::Receiver<Vec<u8>>,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl ByteBackend {
    fn start() -> Self {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        };

        let (listener, port) = bind_unique_port();
        listener.set_nonblocking(true).expect("nonblocking byte backend");
        let (delivered, received) = mpsc::channel();
        let running = Arc::new(AtomicBool::new(true));
        let active = Arc::clone(&running);
        let worker = std::thread::spawn(move || {
            while active.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .expect("byte backend read timeout");
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .expect("byte backend write timeout");
                        let mut bytes = Vec::new();
                        stream.read_to_end(&mut bytes).expect("complete client payload");
                        if !bytes.is_empty() {
                            stream.write_all(b"database reply").expect("complete backend reply");
                            delivered.send(bytes).expect("record backend payload");
                        }
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    },
                    Err(error) => panic!("byte backend accept: {error}"),
                }
            }
        });
        Self {
            port,
            received,
            running,
            worker: Some(worker),
        }
    }
}

impl Drop for ByteBackend {
    fn drop(&mut self) {
        self.running.store(false, std::sync::atomic::Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !std::thread::panicking() {
                result.expect("byte backend worker");
            }
        }
    }
}
