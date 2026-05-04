// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Integration tests for active health checks.

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use praxis_core::{
    config::Config,
    health::{EndpointHealth, HealthRegistry},
};
use praxis_test_utils::{
    free_port, http_get, start_backend_with_shutdown, start_full_proxy, start_proxy, wait_for_http,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn health_check_config_parses_with_clusters() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{port}"
    filter_chains: [main]
insecure_options:
  allow_private_health_checks: true
clusters:
  - name: backend
    endpoints:
      - "127.0.0.1:{backend_port}"
    health_check:
      type: http
      path: "/healthz"
      expected_status: 200
      interval_ms: 5000
      timeout_ms: 2000
      healthy_threshold: 2
      unhealthy_threshold: 3
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
        port = free_port(),
    );

    let config = Config::from_yaml(&yaml);
    assert!(
        config.is_ok(),
        "config with health_check should parse: {:?}",
        config.err()
    );

    let config = config.unwrap();
    let cluster = &config.clusters[0];
    let hc = cluster.health_check.as_ref().expect("health_check should be present");
    assert_eq!(
        hc.check_type,
        praxis_core::config::HealthCheckType::Http,
        "check type should be http"
    );
    assert_eq!(hc.path, "/healthz", "path should be /healthz");
    assert_eq!(hc.expected_status, 200, "expected status should be 200");
    assert_eq!(hc.interval_ms, 5000, "interval should be 5000ms");
    assert_eq!(hc.timeout_ms, 2000, "timeout should be 2000ms");
    assert_eq!(hc.healthy_threshold, 2, "healthy threshold should be 2");
    assert_eq!(hc.unhealthy_threshold, 3, "unhealthy threshold should be 3");
}

#[test]
fn health_check_tcp_config_parses() {
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{port}"
    filter_chains: [main]
insecure_options:
  allow_private_health_checks: true
clusters:
  - name: db
    endpoints:
      - "127.0.0.1:5432"
    health_check:
      type: tcp
      interval_ms: 10000
      timeout_ms: 3000
      healthy_threshold: 1
      unhealthy_threshold: 2
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        port = free_port(),
    );

    let config = Config::from_yaml(&yaml);
    assert!(
        config.is_ok(),
        "TCP health check config should parse: {:?}",
        config.err()
    );

    let config = config.unwrap();
    let hc = config.clusters[0].health_check.as_ref().unwrap();
    assert_eq!(
        hc.check_type,
        praxis_core::config::HealthCheckType::Tcp,
        "check type should be tcp"
    );
}

#[test]
fn health_check_grpc_rejected() {
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{port}"
    filter_chains: [main]
clusters:
  - name: backend
    endpoints:
      - "127.0.0.1:8080"
    health_check:
      type: grpc
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        port = free_port(),
    );

    let config = Config::from_yaml(&yaml);
    assert!(config.is_err(), "gRPC health check should be rejected");
    let err = config.unwrap_err().to_string();
    assert!(
        err.contains("grpc") || err.contains("gRPC"),
        "error should mention grpc: {err}"
    );
}

#[test]
fn health_check_invalid_timeout_rejected() {
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{port}"
    filter_chains: [main]
clusters:
  - name: backend
    endpoints:
      - "127.0.0.1:8080"
    health_check:
      type: http
      interval_ms: 1000
      timeout_ms: 2000
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        port = free_port(),
    );

    let config = Config::from_yaml(&yaml);
    assert!(config.is_err(), "timeout >= interval should be rejected");
    let err = config.unwrap_err().to_string();
    assert!(
        err.contains("timeout") && err.contains("interval"),
        "error should mention timeout and interval: {err}"
    );
}

#[test]
fn ready_endpoint_reports_cluster_health() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let admin_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
admin:
  address: "127.0.0.1:{admin_port}"
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
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();

    let mut server = praxis_core::server::build_http_server(config.shutdown_timeout_secs, &Default::default());
    let registry = praxis_filter::FilterRegistry::with_builtins();
    for listener in &config.listeners {
        let chains: HashMap<&str, &Vec<_>> = config
            .filter_chains
            .iter()
            .map(|c| (c.name.as_str(), &c.filters))
            .collect();
        let mut entries = Vec::new();
        for chain_name in &listener.filter_chains {
            if let Some(filters) = chains.get(chain_name.as_str()) {
                entries.extend_from_slice(filters);
            }
        }
        let pipeline = Arc::new(praxis_filter::FilterPipeline::build(&mut entries, &registry).unwrap());
        let swappable = Arc::new(arc_swap::ArcSwap::from(pipeline));
        praxis_protocol::http::load_http_handler(&mut server, listener, swappable, &mut Vec::new()).unwrap();
    }

    let mut health_map = HashMap::new();
    let entry = praxis_core::health::ClusterHealthEntry::new(
        vec![EndpointHealth::new(), EndpointHealth::new()],
        vec![Arc::from("10.0.0.1:80"), Arc::from("10.0.0.2:80")],
        None,
        None,
    );
    entry.endpoints()[1].mark_unhealthy();
    health_map.insert(Arc::from("backend"), Arc::new(entry));
    let health_registry: HealthRegistry = Arc::new(health_map);

    praxis_protocol::http::pingora::health::add_health_endpoint_to_pingora_server(
        &mut server,
        &format!("127.0.0.1:{admin_port}"),
        Some(health_registry),
        true,
    );

    std::thread::spawn(move || {
        server.run_forever();
    });

    wait_for_http(&format!("127.0.0.1:{admin_port}"));

    let (status, body) = http_get(&format!("127.0.0.1:{admin_port}"), "/ready", None);
    assert_eq!(status, 200, "/ready should return 200 when some endpoints healthy");
    let json: serde_json::Value = serde_json::from_str(&body).expect("response body should be valid JSON");
    assert_eq!(json["status"], "ok", "status should be ok: {body}");
    assert_eq!(
        json["clusters"]["healthy"], 1,
        "should report 1 healthy cluster: {body}"
    );
    assert_eq!(json["clusters"]["total"], 1, "should report 1 total cluster: {body}");

    let (status, body) = http_get(&format!("127.0.0.1:{admin_port}"), "/healthy", None);
    assert_eq!(status, 200, "/healthy should always return 200");
    assert!(body.contains("ok"), "/healthy body should contain ok: {body}");
}

#[test]
fn ready_endpoint_returns_503_when_all_unhealthy() {
    let admin_port = free_port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
admin:
  address: "127.0.0.1:{admin_port}"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let mut server = praxis_core::server::build_http_server(config.shutdown_timeout_secs, &Default::default());
    let registry = praxis_filter::FilterRegistry::with_builtins();

    for listener in &config.listeners {
        let chains: HashMap<&str, &Vec<_>> = config
            .filter_chains
            .iter()
            .map(|c| (c.name.as_str(), &c.filters))
            .collect();
        let mut entries = Vec::new();
        for chain_name in &listener.filter_chains {
            if let Some(filters) = chains.get(chain_name.as_str()) {
                entries.extend_from_slice(filters);
            }
        }
        let pipeline = Arc::new(praxis_filter::FilterPipeline::build(&mut entries, &registry).unwrap());
        let swappable = Arc::new(arc_swap::ArcSwap::from(pipeline));
        praxis_protocol::http::load_http_handler(&mut server, listener, swappable, &mut Vec::new()).unwrap();
    }

    let mut health_map = HashMap::new();
    let entry = praxis_core::health::ClusterHealthEntry::new(
        vec![EndpointHealth::new()],
        vec![Arc::from("10.0.0.1:80")],
        None,
        None,
    );
    entry.endpoints()[0].mark_unhealthy();
    health_map.insert(Arc::from("backend"), Arc::new(entry));
    let health_registry: HealthRegistry = Arc::new(health_map);

    praxis_protocol::http::pingora::health::add_health_endpoint_to_pingora_server(
        &mut server,
        &format!("127.0.0.1:{admin_port}"),
        Some(health_registry),
        true,
    );

    std::thread::spawn(move || {
        server.run_forever();
    });

    wait_for_http(&format!("127.0.0.1:{admin_port}"));

    let (status, body) = http_get(&format!("127.0.0.1:{admin_port}"), "/ready", None);
    assert_eq!(status, 503, "/ready should return 503 when all endpoints unhealthy");
    assert!(body.contains("degraded"), "status should be degraded: {body}");
    assert!(body.contains(r#""healthy":0"#), "should report 0 healthy: {body}");
}

#[test]
fn health_check_builds_registry_for_checked_clusters() {
    let registry = praxis_core::health::build_health_registry(&[
        praxis_core::config::Cluster {
            health_check: Some(praxis_core::config::HealthCheckConfig {
                check_type: praxis_core::config::HealthCheckType::Http,
                expected_status: 200,
                healthy_threshold: 2,
                interval_ms: 5000,
                passive_healthy_threshold: None,
                passive_unhealthy_threshold: None,
                path: "/".to_owned(),
                timeout_ms: 2000,
                unhealthy_threshold: 3,
            }),
            ..praxis_core::config::Cluster::with_defaults("checked", vec!["10.0.0.1:80".into(), "10.0.0.2:80".into()])
        },
        praxis_core::config::Cluster::with_defaults("unchecked", vec!["10.0.0.3:80".into()]),
    ]);

    assert!(
        registry.contains_key("checked"),
        "checked cluster should be in registry"
    );
    assert!(
        !registry.contains_key("unchecked"),
        "unchecked cluster should not be in registry"
    );
    assert_eq!(
        registry["checked"].endpoints().len(),
        2,
        "checked cluster should have 2 endpoints"
    );
    assert!(
        registry["checked"].endpoints()[0].is_healthy(),
        "endpoints should start healthy"
    );
    assert!(
        registry["checked"].endpoints()[1].is_healthy(),
        "endpoints should start healthy"
    );
}

#[test]
fn health_check_routes_away_from_unhealthy_backend() {
    let stable_port_guard = start_backend_with_shutdown("stable");
    let stable_port = stable_port_guard.port();
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
    start_full_proxy(config);

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

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut consecutive_stable = 0;
    while std::time::Instant::now() < deadline {
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
        "traffic should consistently route to stable backend (got {consecutive_stable} consecutive)"
    );
}

#[test]
fn h2_probe_succeeds_against_proxy_listener() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
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
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _guard = start_proxy(&config);

    let addr = format!("127.0.0.1:{proxy_port}");
    praxis_test_utils::wait_for_http2(&addr);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let result = rt.block_on(praxis_protocol::http::pingora::health::probe::h2_probe(
        &addr,
        Duration::from_secs(5),
    ));
    assert!(
        result,
        "h2_probe should succeed against a running proxy with h2c enabled"
    );
}

#[test]
fn h2_probe_fails_against_non_h2_endpoint() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let result = rt.block_on(praxis_protocol::http::pingora::health::probe::h2_probe(
        "127.0.0.1:1",
        Duration::from_millis(100),
    ));
    assert!(!result, "h2_probe should fail against a non-listening port");
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
    /// Start a stoppable backend that returns `body` for every request.
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
                            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                            let _headers = read_until_headers(&mut stream);
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _sent = stream.write_all(resp.as_bytes());
                        });
                    },
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
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
    let mut buf = [0u8; 4096];
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
