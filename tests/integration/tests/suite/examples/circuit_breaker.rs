// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the circuit breaker example config.

use std::collections::HashMap;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn circuit_breaker_config_parses() {
    let config = super::load_example_config(
        "traffic-management/circuit-breaker.yaml",
        29800,
        HashMap::from([("127.0.0.1:3001", 29801_u16), ("127.0.0.1:3002", 29802_u16)]),
    );

    assert_eq!(config.listeners.len(), 1, "should have 1 listener");
    assert_eq!(&*config.listeners[0].name, "http", "listener name should be http");
}

#[test]
fn circuit_breaker_functional() {
    // The backend cluster lists two distinct endpoints; give each its own
    // backend rather than collapsing them onto one address (a duplicate
    // endpoint address is rejected by config validation).
    let backend_guard_1 = praxis_test_utils::start_backend_with_shutdown("ok");
    let backend_guard_2 = praxis_test_utils::start_backend_with_shutdown("ok");
    let proxy_port = praxis_test_utils::free_port();

    let config = super::load_example_config(
        "traffic-management/circuit-breaker.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", backend_guard_1.port()),
            ("127.0.0.1:3002", backend_guard_2.port()),
        ]),
    );

    let proxy = praxis_test_utils::start_proxy(&config);
    let (status, body) = praxis_test_utils::http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "healthy backend should return 200");
    assert_eq!(body, "ok", "response body should match backend");
}

#[test]
fn example_opens_and_half_opens() {
    use std::time::Duration;

    let mut backend = BreakerBackend::start();
    let proxy_port = praxis_test_utils::free_port();
    let mut config = super::load_example_config(
        "traffic-management/circuit-breaker.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", backend.ports[0]),
            ("127.0.0.1:3002", backend.ports[1]),
        ]),
    );
    let breaker = config.filter_chains[0]
        .filters
        .iter_mut()
        .find(|entry| entry.filter_type == "circuit_breaker")
        .expect("example circuit breaker");
    breaker.config["clusters"][0]["recovery_window_secs"] = serde_yaml::Value::from(1);
    let proxy = praxis_test_utils::start_full_proxy(&config);
    praxis_test_utils::wait_for_tcp(proxy.addr());

    for attempt in 1..=5 {
        let (status, _) = praxis_test_utils::http_get(proxy.addr(), "/", None);
        assert_eq!(status, 500, "backend failure {attempt} must reach client");
        assert_eq!(backend.deliveries(), attempt, "failure must reach a backend");
    }
    let (status, _) = praxis_test_utils::http_get(proxy.addr(), "/", None);
    assert_eq!(status, 503, "open breaker must reject without forwarding");
    assert_eq!(backend.deliveries(), 5, "open breaker must not deliver");

    std::thread::sleep(Duration::from_millis(1100));
    backend.hold(true, 500);
    let failed_probe = backend.probe(proxy.addr());
    backend.wait_for_deliveries(6);
    let (status, _) = praxis_test_utils::http_get(proxy.addr(), "/", None);
    assert_eq!(status, 503, "second half-open request must be rejected");
    assert_eq!(backend.deliveries(), 6, "only one half-open probe may reach backend");
    backend.release();
    assert_eq!(failed_probe.finish().0, 500);
    let (status, _) = praxis_test_utils::http_get(proxy.addr(), "/", None);
    assert_eq!(status, 503, "failed probe must reopen the breaker");
    assert_eq!(backend.deliveries(), 6);

    std::thread::sleep(Duration::from_millis(1100));
    backend.hold(true, 200);
    let successful_probe = backend.probe(proxy.addr());
    backend.wait_for_deliveries(7);
    let (status, _) = praxis_test_utils::http_get(proxy.addr(), "/", None);
    assert_eq!(status, 503, "second recovery probe must be rejected");
    assert_eq!(backend.deliveries(), 7);
    backend.release();
    assert_eq!(successful_probe.finish().0, 200);
    let (status, body) = praxis_test_utils::http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "successful probe must close breaker");
    assert_eq!(body, "breaker-backend");
    assert_eq!(backend.deliveries(), 8, "closed breaker must resume forwarding");
    backend.stop();
}

struct BreakerState {
    deliveries: usize,
    status: u16,
    hold: bool,
}

struct BreakerBackend {
    ports: [u16; 2],
    state: std::sync::Arc<(std::sync::Mutex<BreakerState>, std::sync::Condvar)>,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl BreakerBackend {
    fn start() -> Self {
        let first = praxis_test_utils::bind_unique_port();
        let second = praxis_test_utils::bind_unique_port();
        let state = std::sync::Arc::new((
            std::sync::Mutex::new(BreakerState {
                deliveries: 0,
                status: 500,
                hold: false,
            }),
            std::sync::Condvar::new(),
        ));
        let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let mut backend = Self {
            ports: [first.1, second.1],
            state,
            running,
            workers: Vec::new(),
        };
        backend.serve(first.0);
        backend.serve(second.0);
        backend
    }

    fn serve(&mut self, listener: std::net::TcpListener) {
        use std::sync::atomic::Ordering;
        listener.set_nonblocking(true).expect("nonblocking breaker backend");
        let running = std::sync::Arc::clone(&self.running);
        let state = std::sync::Arc::clone(&self.state);
        self.workers.push(std::thread::spawn(move || {
            while running.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => respond_breaker(stream, &state),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    },
                    Err(error) => panic!("breaker backend accept: {error}"),
                }
            }
        }));
    }

    fn deliveries(&self) -> usize {
        self.state.0.lock().expect("breaker state").deliveries
    }

    fn wait_for_deliveries(&self, expected: usize) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while self.deliveries() < expected {
            assert!(
                std::time::Instant::now() < deadline,
                "expected {expected} backend deliveries"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn hold(&self, hold: bool, status: u16) {
        let mut state = self.state.0.lock().expect("breaker state");
        state.hold = hold;
        state.status = status;
    }

    fn probe(&self, addr: &str) -> ProbeRequest {
        let addr = addr.to_owned();
        ProbeRequest {
            state: std::sync::Arc::clone(&self.state),
            worker: Some(std::thread::spawn(move || {
                praxis_test_utils::http_get(&addr, "/", None)
            })),
        }
    }

    fn release(&self) {
        let mut state = self.state.0.lock().expect("breaker state");
        state.hold = false;
        drop(state);
        self.state.1.notify_all();
    }

    fn stop(&mut self) {
        use std::sync::atomic::Ordering;
        self.running.store(false, Ordering::Release);
        self.release();
        let mut success = true;
        for worker in self.workers.drain(..) {
            success &= worker.join().is_ok();
        }
        if !std::thread::panicking() {
            assert!(success, "breaker backend workers must finish successfully");
        }
    }
}

impl Drop for BreakerBackend {
    fn drop(&mut self) {
        self.stop();
    }
}

struct ProbeRequest {
    state: std::sync::Arc<(std::sync::Mutex<BreakerState>, std::sync::Condvar)>,
    worker: Option<std::thread::JoinHandle<(u16, String)>>,
}

impl ProbeRequest {
    fn finish(mut self) -> (u16, String) {
        self.worker
            .take()
            .expect("probe worker")
            .join()
            .expect("half-open response")
    }
}

impl Drop for ProbeRequest {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            {
                let mut state = self.state.0.lock().expect("breaker state");
                state.hold = false;
                drop(state);
                self.state.1.notify_all();
            }
            let result = worker.join();
            if !std::thread::panicking() {
                result.expect("half-open request worker");
            }
        }
    }
}

fn respond_breaker(
    mut stream: std::net::TcpStream,
    state: &std::sync::Arc<(std::sync::Mutex<BreakerState>, std::sync::Condvar)>,
) {
    use std::io::{Read as _, Write as _};
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("breaker backend timeout");
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("breaker backend write timeout");
    let mut data = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !data.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        let count = stream.read(&mut buffer).expect("breaker backend request");
        assert_ne!(count, 0, "breaker backend request must complete");
        data.extend_from_slice(&buffer[..count]);
    }
    let (lock, ready) = &**state;
    let mut control = lock.lock().expect("breaker state");
    control.deliveries += 1;
    while control.hold {
        control = ready.wait(control).expect("breaker hold");
    }
    let status = control.status;
    drop(control);
    let reason = if status == 200 { "OK" } else { "Internal Server Error" };
    let body = "breaker-backend";
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).expect("breaker backend response");
}
