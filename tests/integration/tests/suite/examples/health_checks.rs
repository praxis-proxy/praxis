// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for health check behavior.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
};

use praxis_test_utils::{free_port, start_full_proxy, wait_for_tcp};

use super::routing_health::TestHealthBackend;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn health_checks_config_parses() {
    let config = super::load_example_config(
        "traffic-management/health-checks.yaml",
        19800,
        HashMap::from([
            ("127.0.0.1:3001", 19801_u16),
            ("127.0.0.1:3002", 19802_u16),
            ("127.0.0.1:3003", 19803_u16),
            ("127.0.0.1:5432", 19804_u16),
            ("127.0.0.1:5433", 19805_u16),
            ("127.0.0.1:9090", 19806_u16),
        ]),
    );

    assert_eq!(config.clusters.len(), 2, "should have 2 clusters");

    let backend = config
        .clusters
        .iter()
        .find(|c| &*c.name == "backend")
        .expect("backend cluster");
    let hc = backend.health_check.as_ref().expect("backend should have health_check");
    assert_eq!(
        hc.check_type,
        praxis_core::config::HealthCheckType::Http,
        "backend check type should be http"
    );
    assert_eq!(hc.path, "/healthz", "backend path should be /healthz");
    assert_eq!(hc.expected_status, 200, "expected status should be 200");
    assert_eq!(hc.interval_ms, 5000, "interval should be 5000");
    assert_eq!(hc.timeout_ms, 2000, "timeout should be 2000");
    assert_eq!(hc.healthy_threshold, 2, "healthy threshold should be 2");
    assert_eq!(hc.unhealthy_threshold, 3, "unhealthy threshold should be 3");
    assert_eq!(
        hc.passive_unhealthy_threshold,
        Some(5),
        "passive_unhealthy_threshold should be 5"
    );
    assert_eq!(
        hc.passive_healthy_threshold,
        Some(3),
        "passive_healthy_threshold should be 3"
    );

    let database = config
        .clusters
        .iter()
        .find(|c| &*c.name == "database")
        .expect("database cluster");
    let hc = database
        .health_check
        .as_ref()
        .expect("database should have health_check");
    assert_eq!(
        hc.check_type,
        praxis_core::config::HealthCheckType::Tcp,
        "database check type should be tcp"
    );
    assert_eq!(hc.interval_ms, 10000, "database interval should be 10000");
    assert_eq!(hc.timeout_ms, 3000, "database timeout should be 3000");
}

#[test]
fn http_probe_removes_and_restores_backend() {
    let first = TestHealthBackend::start("http-first");
    let second = TestHealthBackend::start("http-second");
    let third = TestHealthBackend::start("http-third");
    let database_first = TestHealthBackend::start("database-first");
    let database_second = TestHealthBackend::start("database-second");
    let proxy_port = free_port();
    let admin_port = free_port();
    let mut config = super::load_example_config(
        "traffic-management/health-checks.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", first.port()),
            ("127.0.0.1:3002", second.port()),
            ("127.0.0.1:3003", third.port()),
            ("127.0.0.1:5432", database_first.port()),
            ("127.0.0.1:5433", database_second.port()),
            ("127.0.0.1:9902", admin_port),
        ]),
    );
    for cluster in &mut config.clusters {
        let health = cluster.health_check.as_mut().expect("example health check");
        health.interval_ms = 200;
        health.timeout_ms = 100;
    }
    config.admin.verbose = true;
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);
    second.wait_for_probe_after(0);
    assert_routes(proxy.addr(), "/", &["http-first", "http-second", "http-third"]);
    assert!(
        second.probe_count() > 0,
        "active runner must GET /healthz on second endpoint"
    );

    let previous = second.probe_count();
    second.set_healthy(false);
    second.wait_for_probe_after(previous);
    wait_for_healthy_count(&admin, "backend", 2, 3);
    assert_routes(proxy.addr(), "/", &["http-first", "http-third"]);

    let previous = second.probe_count();
    second.set_healthy(true);
    second.wait_for_probe_after(previous);
    wait_for_healthy_count(&admin, "backend", 3, 3);
    assert_routes(proxy.addr(), "/", &["http-first", "http-second", "http-third"]);
}

#[test]
fn tcp_probe_removes_and_restores_backend() {
    let http_first = TestHealthBackend::start("http-first");
    let http_second = TestHealthBackend::start("http-second");
    let http_third = TestHealthBackend::start("http-third");
    let database_first = TcpHealthBackend::start("database-first");
    let mut database_second = TcpHealthBackend::start("database-second");
    let proxy_port = free_port();
    let admin_port = free_port();
    let mut config = super::load_example_config(
        "traffic-management/health-checks.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", http_first.port()),
            ("127.0.0.1:3002", http_second.port()),
            ("127.0.0.1:3003", http_third.port()),
            ("127.0.0.1:5432", database_first.port),
            ("127.0.0.1:5433", database_second.port),
            ("127.0.0.1:9902", admin_port),
        ]),
    );
    for cluster in &mut config.clusters {
        let health = cluster.health_check.as_mut().expect("example health check");
        health.interval_ms = 200;
        health.timeout_ms = 100;
    }
    config.admin.verbose = true;
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);
    database_second.wait_for_connection_after(0);
    assert_routes(proxy.addr(), "/db", &["database-first", "database-second"]);

    database_second.stop();
    wait_for_healthy_count(&admin, "database", 1, 2);
    assert_routes(proxy.addr(), "/db", &["database-first"]);

    let previous = database_second.connections.load(std::sync::atomic::Ordering::Acquire);
    database_second.restart();
    database_second.wait_for_connection_after(previous);
    wait_for_healthy_count(&admin, "database", 2, 2);
    assert_routes(proxy.addr(), "/db", &["database-first", "database-second"]);
}

struct TcpHealthBackend {
    port: u16,
    identity: &'static str,
    connections: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl TcpHealthBackend {
    fn start(identity: &'static str) -> Self {
        let (listener, port) = praxis_test_utils::bind_unique_port();
        let mut backend = Self {
            port,
            identity,
            connections: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            worker: None,
        };
        backend.spawn(listener);
        backend
    }

    fn spawn(&mut self, listener: std::net::TcpListener) {
        use std::sync::atomic::Ordering;
        listener.set_nonblocking(true).expect("nonblocking TCP health backend");
        self.running.store(true, Ordering::Release);
        let running = std::sync::Arc::clone(&self.running);
        let connections = std::sync::Arc::clone(&self.connections);
        let identity = self.identity;
        self.worker = Some(std::thread::spawn(move || {
            while running.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        connections.fetch_add(1, Ordering::Release);
                        stream
                            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                            .expect("backend read timeout");
                        stream
                            .set_write_timeout(Some(std::time::Duration::from_secs(2)))
                            .expect("backend write timeout");
                        let mut data = Vec::new();
                        let mut buffer = [0_u8; 1024];
                        while !data.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                            match stream.read(&mut buffer) {
                                Ok(0) | Err(_) => break,
                                Ok(count) => data.extend_from_slice(&buffer[..count]),
                            }
                        }
                        if data.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{identity}",
                                identity.len()
                            );
                            stream.write_all(response.as_bytes()).expect("backend response");
                            // The proxy closes after this fixed-length, Connection: close
                            // response. Let it send FIN first so the server port can rebind.
                            stream
                                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                                .expect("passive close timeout");
                            assert_eq!(
                                stream.read(&mut buffer).expect("proxy closes upstream"),
                                0,
                                "proxy must close first so the backend port can be rebound"
                            );
                        }
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    },
                    Err(error) => panic!("TCP health backend accept: {error}"),
                }
            }
        }));
    }

    fn stop(&mut self) {
        use std::sync::atomic::Ordering;
        self.running.store(false, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !std::thread::panicking() {
                result.expect("TCP health backend worker");
            }
        }
    }

    fn restart(&mut self) {
        let listener =
            std::net::TcpListener::bind(("127.0.0.1", self.port)).expect("rebind recovered TCP health endpoint");
        self.spawn(listener);
    }

    fn wait_for_connection_after(&self, previous: usize) {
        use std::sync::atomic::Ordering;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while self.connections.load(Ordering::Acquire) <= previous {
            assert!(std::time::Instant::now() < deadline, "TCP health probe never connected");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

impl Drop for TcpHealthBackend {
    fn drop(&mut self) {
        self.stop();
    }
}

fn wait_for_healthy_count(admin: &str, cluster: &str, healthy: usize, total: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let (status, body) = praxis_test_utils::http_get(admin, "/ready", None);
        assert_eq!(status, 200, "each cluster retains a healthy endpoint: {body}");
        let value: serde_json::Value = serde_json::from_str(&body).expect("readiness JSON");
        let detail = &value["clusters"]["detail"][cluster];
        assert_eq!(detail["total"], total, "readiness must describe the example cluster");
        if detail["healthy"] == healthy {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{cluster} did not reach {healthy}/{total} healthy endpoints: {body}"
        );
        std::thread::sleep(std::time::Duration::from_millis(30));
    }
}

fn assert_routes(proxy_addr: &str, path: &str, expected: &[&str]) {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..6 {
        let (status, body) = praxis_test_utils::http_get(proxy_addr, path, None);
        assert_eq!(
            status, 200,
            "healthy routing phase must return backend identity: {body}"
        );
        assert!(
            expected.contains(&body.as_str()),
            "unexpected endpoint at {path}: {body}"
        );
        seen.insert(body);
    }
    assert_eq!(
        seen,
        expected
            .iter()
            .map(|identity| (*identity).to_owned())
            .collect::<std::collections::HashSet<_>>(),
        "every expected endpoint must participate in the finite routing cycle"
    );
}
