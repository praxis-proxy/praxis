// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Multiple listeners and per-listener pipeline tests.

use praxis_core::config::Config;
use praxis_protocol::http::load_http_handler;
use praxis_test_utils::{
    build_pipeline, free_port, http_get, http_send, parse_status, start_backend_with_shutdown, start_proxy,
    wait_for_tcp,
};

/// Wrap a pipeline [`Arc`] in [`ArcSwap`] for handler registration.
fn swappable(
    pipeline: std::sync::Arc<praxis_filter::FilterPipeline>,
) -> std::sync::Arc<arc_swap::ArcSwap<praxis_filter::FilterPipeline>> {
    std::sync::Arc::new(arc_swap::ArcSwap::from(pipeline))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn multiple_listeners() {
    let backend_port_guard = start_backend_with_shutdown("multi listener");
    let backend_port = backend_port_guard.port();
    let port_a = free_port();
    let port_b = free_port();
    let port_c = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: listener_a
    address: "127.0.0.1:{port_a}"
    filter_chains: [main]
  - name: listener_b
    address: "127.0.0.1:{port_b}"
    filter_chains: [main]
  - name: listener_c
    address: "127.0.0.1:{port_c}"
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
    let pipeline = std::sync::Arc::new(build_pipeline(&config));
    let mut server = praxis_core::server::build_http_server(config.shutdown_timeout_secs, &Default::default());
    for listener in &config.listeners {
        load_http_handler(&mut server, listener, swappable(pipeline.clone()), &mut Vec::new()).unwrap();
    }
    let server = server;
    std::thread::spawn(move || {
        server.run_forever();
    });
    wait_for_tcp(&format!("127.0.0.1:{port_a}"));

    let (status_a, body_a) = http_get(&format!("127.0.0.1:{port_a}"), "/", None);
    assert_eq!(status_a, 200, "listener A should return 200");
    assert_eq!(body_a, "multi listener", "listener A should forward response");

    let (status_b, body_b) = http_get(&format!("127.0.0.1:{port_b}"), "/", None);
    assert_eq!(status_b, 200, "listener B should return 200");
    assert_eq!(body_b, "multi listener", "listener B should forward response");

    let (status_c, body_c) = http_get(&format!("127.0.0.1:{port_c}"), "/", None);
    assert_eq!(status_c, 200, "listener C should return 200");
    assert_eq!(body_c, "multi listener", "listener C should forward response");
}

#[test]
fn per_listener_pipelines() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let port_a = free_port();
    let port_b = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: alpha
    address: "127.0.0.1:{port_a}"
    filter_chains: [shared, chain_alpha]
  - name: beta
    address: "127.0.0.1:{port_b}"
    filter_chains: [shared, chain_beta]
filter_chains:
  - name: shared
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
  - name: chain_alpha
    filters:
      - filter: headers
        response_add:
          - name: X-Listener
            value: "alpha"
  - name: chain_beta
    filters:
      - filter: headers
        response_add:
          - name: X-Listener
            value: "beta"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{port_b}"));

    let raw_a = http_send(
        &format!("127.0.0.1:{port_a}"),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw_a), 200, "listener alpha should return 200");
    assert!(
        raw_a.contains("x-listener: alpha"),
        "listener A should add X-Listener: alpha, got:\n{raw_a}"
    );
    assert!(
        !raw_a.contains("x-listener: beta"),
        "listener A must NOT have beta's header"
    );

    let raw_b = http_send(
        &format!("127.0.0.1:{port_b}"),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw_b), 200, "listener beta should return 200");
    assert!(
        raw_b.contains("x-listener: beta"),
        "listener B should add X-Listener: beta, got:\n{raw_b}"
    );
    assert!(
        !raw_b.contains("x-listener: alpha"),
        "listener B must NOT have alpha's header"
    );
}
