// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Health endpoints, config parsing, and admin tests.

use praxis_core::config::Config;
use praxis_protocol::http::load_http_handler;

/// Wrap a pipeline [`Arc`] in [`ArcSwap`] for handler registration.
fn swappable(
    pipeline: std::sync::Arc<praxis_filter::FilterPipeline>,
) -> std::sync::Arc<arc_swap::ArcSwap<praxis_filter::FilterPipeline>> {
    std::sync::Arc::new(arc_swap::ArcSwap::from(pipeline))
}
use praxis_test_utils::{
    build_pipeline, free_port, http_get, simple_proxy_yaml, start_backend_with_shutdown, start_proxy, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn health_endpoints() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let admin_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [routing]
admin:
  address: "127.0.0.1:{admin_port}"
filter_chains:
  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let pipeline = std::sync::Arc::new(build_pipeline(&config));
    let mut server = praxis_core::server::build_http_server(config.shutdown_timeout_secs, &Default::default());
    for listener in &config.listeners {
        load_http_handler(&mut server, listener, swappable(pipeline.clone()), &mut Vec::new()).unwrap();
    }
    praxis_protocol::http::pingora::health::add_health_endpoint_to_pingora_server(
        &mut server,
        config.admin.address.as_ref().unwrap(),
        None,
        false,
    );
    let server = server;
    std::thread::spawn(move || {
        server.run_forever();
    });
    wait_for_tcp(&format!("127.0.0.1:{admin_port}"));

    let admin_addr = format!("127.0.0.1:{admin_port}");
    let (status, body) = http_get(&admin_addr, "/ready", None);
    assert_eq!(status, 200, "/ready endpoint should return 200");
    assert!(body.contains("ok"), "/ready body should contain 'ok', got: {body}");

    let (status, body) = http_get(&admin_addr, "/healthy", None);
    assert_eq!(status, 200, "/healthy endpoint should return 200");
    assert!(body.contains("ok"), "/healthy body should contain 'ok', got: {body}");

    let (status, _) = http_get(&admin_addr, "/unknown", None);
    assert_eq!(status, 404, "unknown admin path should return 404");
}

#[test]
fn runtime_config_parsed_from_yaml_and_proxies() {
    let backend_port_guard = start_backend_with_shutdown("runtime ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
runtime:
  threads: 2
  work_stealing: false
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    assert_eq!(config.runtime.threads, 2, "threads should be parsed from YAML");
    assert!(!config.runtime.work_stealing, "work_stealing should be false");

    let runtime = praxis_core::RuntimeOptions {
        threads: config.runtime.threads,
        work_stealing: config.runtime.work_stealing,
        global_queue_interval: config.runtime.global_queue_interval,
        upstream_ca_file: config.runtime.upstream_ca_file.clone(),
        upstream_keepalive_pool_size: config.runtime.upstream_keepalive_pool_size,
    };
    let pipeline = std::sync::Arc::new(build_pipeline(&config));
    let mut server = praxis_core::server::build_http_server(config.shutdown_timeout_secs, &runtime);
    for listener in &config.listeners {
        load_http_handler(&mut server, listener, swappable(pipeline.clone()), &mut Vec::new()).unwrap();
    }
    std::thread::spawn(move || {
        server.run_forever();
    });

    let addr = format!("127.0.0.1:{proxy_port}");
    wait_for_tcp(&addr);

    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "runtime config proxy should return 200");
    assert_eq!(body, "runtime ok", "runtime config proxy should forward response");
}

#[test]
fn connection_timeout_config_parses() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
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
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
            connection_timeout_ms: 5000
            idle_timeout_ms: 30000
            read_timeout_ms: 10000
            write_timeout_ms: 10000
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "connection timeout config should proxy correctly");
    assert_eq!(body, "ok", "response body should match backend");
}

#[test]
fn pipeline_style_config_proxies() {
    let backend_port_guard = start_backend_with_shutdown("pipeline ok");
    let backend_port = backend_port_guard.port();
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
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "pipeline-style config should return 200");
    assert_eq!(body, "pipeline ok", "pipeline-style config should forward response");
}

#[test]
fn admin_address_none_still_proxies() {
    let backend_port_guard = start_backend_with_shutdown("no admin");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&simple_proxy_yaml(proxy_port, backend_port)).unwrap();
    assert!(
        config.admin.address.is_none(),
        "admin address should be None when not configured"
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "proxy without admin address should return 200");
    assert_eq!(body, "no admin", "proxy without admin should forward response");
}
