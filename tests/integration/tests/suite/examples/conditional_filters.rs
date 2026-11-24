// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the conditional filters example configuration.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    sync::mpsc,
    time::Duration,
};

use praxis_test_utils::{
    bind_unique_port, free_port, http_send, parse_body, parse_header, parse_status, start_full_proxy,
    start_header_echo_backend, start_stateful_backend, wait_for_tcp,
};

#[test]
fn conditional_filters() {
    let observing = start_header_echo_backend();
    let proxy_port = free_port();
    let config = example_config(proxy_port, observing.port());
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());

    for method in ["POST", "PUT", "PATCH", "DELETE", "GET", "OPTIONS"] {
        let raw = request(proxy.addr(), method, "/api/items");
        assert_eq!(parse_status(&raw), 200, "{method} must reach observing backend");
        assert_eq!(
            parse_header(&raw, "cache-control"),
            Some("public, max-age=60".to_owned()),
            "successful {method} response must be cacheable"
        );
        let body = parse_body(&raw);
        let source_values: Vec<_> = body
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.eq_ignore_ascii_case("x-internal-source"))
            .map(|(_, value)| value.trim())
            .collect();
        let expected = if ["POST", "PUT", "PATCH", "DELETE"].contains(&method) {
            vec!["gateway"]
        } else {
            Vec::new()
        };
        assert_eq!(source_values, expected, "{method} request header condition must hold");
    }

    drop(proxy);
    let status_backend = start_stateful_backend(vec![(201, "created".to_owned()), (404, "missing".to_owned())]);
    let status_port = free_port();
    let config = example_config(status_port, status_backend.port());
    let status_proxy = start_full_proxy(&config);
    wait_for_tcp(status_proxy.addr());
    for (path, status, body) in [("/api/created", 201, "created"), ("/api/missing", 404, "missing")] {
        let raw = request(status_proxy.addr(), "GET", path);
        assert_eq!(parse_status(&raw), status, "backend status must survive for {path}");
        assert_eq!(parse_body(&raw), body, "backend body must survive for {path}");
        assert_eq!(
            parse_header(&raw, "cache-control"),
            None,
            "non-200 {status} must not receive cache header"
        );
    }
}

#[test]
fn api_timeout_is_conditioned() {
    let (listener, backend_port) = bind_unique_port();
    let (delivered, observed) = mpsc::channel();
    let backend = DelayedBackend::start(listener, delivered);

    let proxy_port = free_port();
    let mut config = example_config(proxy_port, backend_port);
    let timeout = config.filter_chains[0]
        .filters
        .iter_mut()
        .find(|entry| entry.filter_type == "timeout")
        .expect("example timeout filter");
    timeout.config["timeout_ms"] = serde_yaml::Value::from(40);
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());

    for (path, expected) in [
        ("/api/data", 504),
        ("/healthz", 200),
        ("/outside", 200),
        ("/apikeys", 200),
    ] {
        let raw = request(proxy.addr(), "GET", path);
        assert_eq!(parse_status(&raw), expected, "timeout condition for {path}: {raw}");
        assert_eq!(
            observed.recv_timeout(Duration::from_secs(2)).expect("backend delivery"),
            path,
            "each path must reach the backend"
        );
        if expected == 200 {
            assert_eq!(
                parse_body(&raw),
                "delayed-backend",
                "unconditioned {path} must return backend body"
            );
        }
    }
    drop(backend);
}

fn example_config(proxy_port: u16, backend_port: u16) -> praxis_core::config::Config {
    super::load_example_config(
        "pipeline/conditional-filters.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    )
}

fn request(addr: &str, method: &str, path: &str) -> String {
    http_send(
        addr,
        &format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    )
}

struct DelayedBackend {
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl DelayedBackend {
    fn start(listener: std::net::TcpListener, delivered: mpsc::Sender<String>) -> Self {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        listener.set_nonblocking(true).expect("nonblocking delayed backend");
        let running = Arc::new(AtomicBool::new(true));
        let active = Arc::clone(&running);
        let worker = std::thread::spawn(move || {
            while active.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => delayed_response(stream, &delivered),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    },
                    Err(error) => panic!("delayed backend accept: {error}"),
                }
            }
        });
        Self {
            running,
            worker: Some(worker),
        }
    }
}

impl Drop for DelayedBackend {
    fn drop(&mut self) {
        self.running.store(false, std::sync::atomic::Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !std::thread::panicking() {
                result.expect("delayed backend worker");
            }
        }
    }
}

fn delayed_response(mut stream: std::net::TcpStream, delivered: &mpsc::Sender<String>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("backend read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("backend write timeout");
    let mut data = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !data.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        let count = stream.read(&mut buffer).expect("read example request");
        assert_ne!(count, 0, "request headers must complete");
        data.extend_from_slice(&buffer[..count]);
    }
    let request = String::from_utf8_lossy(&data);
    let path = request.split_whitespace().nth(1).expect("request path").to_owned();
    delivered.send(path).expect("record backend delivery");
    std::thread::sleep(Duration::from_millis(120));
    let body = b"delayed-backend";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    drop(stream.write_all(response.as_bytes()));
    drop(stream.write_all(body));
}
