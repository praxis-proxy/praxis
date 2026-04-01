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

use crate::common::{free_port, http_get, start_backend, start_full_proxy, wait_for_http};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn health_check_config_parses_with_clusters() {
    let backend_port = start_backend("ok");

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{port}"
    filter_chains: [main]
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
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let admin_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
admin_address: "127.0.0.1:{admin_port}"
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
        let pipeline = Arc::new(praxis_filter::FilterPipeline::build(&entries, &registry).unwrap());
        praxis_protocol::http::load_http_handler(&mut server, listener, pipeline).unwrap();
    }

    let mut health_map = HashMap::new();
    let endpoints = vec![EndpointHealth::new(), EndpointHealth::new()];
    endpoints[1].mark_unhealthy();
    health_map.insert(Arc::from("backend"), Arc::new(endpoints));
    let health_registry: HealthRegistry = Arc::new(health_map);

    praxis_protocol::http::pingora::health::add_health_endpoint_to_pingora_server(
        &mut server,
        &format!("127.0.0.1:{admin_port}"),
        Some(health_registry),
    );

    std::thread::spawn(move || {
        server.run_forever();
    });

    wait_for_http(&format!("127.0.0.1:{admin_port}"));

    let (status, body) = http_get(&format!("127.0.0.1:{admin_port}"), "/ready", None);
    assert_eq!(status, 200, "/ready should return 200 when some endpoints healthy");
    assert!(body.contains(r#""healthy":1"#), "should report 1 healthy: {body}");
    assert!(body.contains(r#""unhealthy":1"#), "should report 1 unhealthy: {body}");
    assert!(body.contains(r#""total":2"#), "should report total 2: {body}");
    assert!(body.contains(r#""status":"ok""#), "status should be ok: {body}");

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
admin_address: "127.0.0.1:{admin_port}"
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
        let pipeline = Arc::new(praxis_filter::FilterPipeline::build(&entries, &registry).unwrap());
        praxis_protocol::http::load_http_handler(&mut server, listener, pipeline).unwrap();
    }

    let mut health_map = HashMap::new();
    let endpoints = vec![EndpointHealth::new()];
    endpoints[0].mark_unhealthy();
    health_map.insert(Arc::from("backend"), Arc::new(endpoints));
    let health_registry: HealthRegistry = Arc::new(health_map);

    praxis_protocol::http::pingora::health::add_health_endpoint_to_pingora_server(
        &mut server,
        &format!("127.0.0.1:{admin_port}"),
        Some(health_registry),
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
            name: Arc::from("checked"),
            endpoints: vec!["10.0.0.1:80".into(), "10.0.0.2:80".into()],
            connection_timeout_ms: None,
            idle_timeout_ms: None,
            load_balancer_strategy: Default::default(),
            read_timeout_ms: None,
            total_connection_timeout_ms: None,
            upstream_sni: None,
            upstream_tls: false,
            write_timeout_ms: None,
            health_check: Some(praxis_core::config::HealthCheckConfig {
                check_type: praxis_core::config::HealthCheckType::Http,
                path: "/".to_owned(),
                expected_status: 200,
                interval_ms: 5000,
                timeout_ms: 2000,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
            }),
        },
        praxis_core::config::Cluster {
            name: Arc::from("unchecked"),
            endpoints: vec!["10.0.0.3:80".into()],
            connection_timeout_ms: None,
            idle_timeout_ms: None,
            load_balancer_strategy: Default::default(),
            read_timeout_ms: None,
            total_connection_timeout_ms: None,
            upstream_sni: None,
            upstream_tls: false,
            write_timeout_ms: None,
            health_check: None,
        },
    ]);

    assert!(
        registry.contains_key("checked"),
        "checked cluster should be in registry"
    );
    assert!(
        !registry.contains_key("unchecked"),
        "unchecked cluster should not be in registry"
    );
    assert_eq!(registry["checked"].len(), 2, "checked cluster should have 2 endpoints");
    assert!(registry["checked"][0].is_healthy(), "endpoints should start healthy");
    assert!(registry["checked"][1].is_healthy(), "endpoints should start healthy");
}

#[test]
fn health_check_routes_away_from_unhealthy_backend() {
    let stable_port = start_backend("stable");
    let stoppable = StoppableBackend::start("stoppable");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
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

    std::thread::sleep(Duration::from_millis(600));

    for i in 0..10 {
        let (status, body) = http_get(&addr, "/", None);
        assert_eq!(status, 200, "request {i} should succeed after backend removed");
        assert_eq!(
            body, "stable",
            "request {i} should only reach stable backend after unhealthy detection"
        );
    }
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
        let (listener, port) = praxis_test_utils::network::bind_unique_port();
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
                            let _ = read_until_headers(&mut stream);
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = stream.write_all(resp.as_bytes());
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
