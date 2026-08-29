// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for operations example configurations.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    TestCertificates, example_config_path, free_port, http_get, http_send, https_get, parse_header, patch_yaml,
    start_backend_with_shutdown, start_full_proxy, start_proxy, start_reloadable_proxy, wait_for_https,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn container_default() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "operations/container-default.yaml",
        proxy_port,
        HashMap::from([("0.0.0.0:9901", admin_port)]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "container default root should return 200");
    assert!(
        body.contains(r#""status": "ok""#),
        "response should contain status ok, got: {body}"
    );

    let (status, body) = http_get(proxy.addr(), "/nonexistent", None);
    assert_eq!(status, 404, "container default unknown path should return 404");
    assert!(
        body.contains(r#""error": "not found""#),
        "404 response should contain error message, got: {body}"
    );
}

#[test]
fn log_overrides() {
    let proxy_port = free_port();
    let config = super::load_example_config("operations/log-overrides.yaml", proxy_port, HashMap::new());
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "log overrides should return 200");
    assert!(
        body.contains(r#""status": "ok""#),
        "response should contain status ok, got: {body}"
    );
}

#[test]
fn production_gateway() {
    let api_port_guard = start_backend_with_shutdown("api-ok");
    let api_port = api_port_guard.port();
    let web_port_guard = start_backend_with_shutdown("web-ok");
    let web_port = web_port_guard.port();
    let http_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: http
    address: "127.0.0.1:{http_port}"
    filter_chains:
      - observability
      - security
      - routing

filter_chains:
  - name: observability
    filters:
      - filter: request_id
      - filter: access_log

  - name: security
    filters:
      - filter: timeout
        timeout_ms: 10000
      - filter: headers
        request_add:
          - name: "X-Forwarded-By"
            value: "praxis"
        response_set:
          - name: "X-Frame-Options"
            value: "DENY"
          - name: "X-Content-Type-Options"
            value: "nosniff"
          - name: "Referrer-Policy"
            value: "strict-origin-when-cross-origin"
        response_remove:
          - "Server"
          - "X-Powered-By"

  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: api
          - path_prefix: "/"
            cluster: web
      - filter: load_balancer
        clusters:
          - name: api
            load_balancer_strategy: least_connections
            connection_timeout_ms: 2000
            read_timeout_ms: 10000
            idle_timeout_ms: 60000
            endpoints:
              - "127.0.0.1:{api_port}"
          - name: web
            load_balancer_strategy: round_robin
            connection_timeout_ms: 2000
            read_timeout_ms: 10000
            idle_timeout_ms: 60000
            endpoints:
              - "127.0.0.1:{web_port}"

runtime:
  threads: 0
  work_stealing: true

shutdown_timeout_secs: 30
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = format!("127.0.0.1:{http_port}");
    let _proxy = start_proxy(&config);

    let (status, body) = http_get(&addr, "/api/v1/users", None);
    assert_eq!(status, 200, "production gateway /api/ should return 200");
    assert_eq!(body, "api-ok", "/api/ should route to api backend");

    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "production gateway root should return 200");
    assert_eq!(body, "web-ok", "root should route to web backend");

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(
        parse_header(&raw, "x-frame-options"),
        Some("DENY".to_owned()),
        "X-Frame-Options should be DENY"
    );
    assert_eq!(
        parse_header(&raw, "x-content-type-options"),
        Some("nosniff".to_owned()),
        "X-Content-Type-Options should be nosniff"
    );
}

#[test]
fn production_gateway_example_serves_https_and_http() {
    let certs = TestCertificates::generate();
    // The api and web clusters each list distinct endpoints; give every one
    // its own backend rather than collapsing them onto one address (a
    // duplicate endpoint address is rejected by config validation). All api
    // backends share a response body, as do all web backends, so the routing
    // assertions below stay meaningful regardless of which endpoint is chosen.
    let api_1 = start_backend_with_shutdown("api-backend");
    let api_2 = start_backend_with_shutdown("api-backend");
    let api_3 = start_backend_with_shutdown("api-backend");
    let web_1 = start_backend_with_shutdown("web-backend");
    let web_2 = start_backend_with_shutdown("web-backend");
    let https_port = free_port();
    let http_port = free_port();

    let path = example_config_path("operations/production-gateway.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let patched = patch_yaml(
        &yaml,
        http_port,
        &HashMap::from([
            ("127.0.0.1:443", https_port),
            ("127.0.0.1:80", http_port),
            ("10.0.1.10:8080", api_1.port()),
            ("10.0.1.11:8080", api_2.port()),
            ("10.0.1.12:8080", api_3.port()),
            ("10.0.2.10:8080", web_1.port()),
            ("10.0.2.11:8080", web_2.port()),
        ]),
    )
    .replace("/etc/praxis/tls/cert.pem", &certs.cert_path.display().to_string())
    .replace("/etc/praxis/tls/key.pem", &certs.key_path.display().to_string());
    let patched = praxis_test_utils::allow_loopback_endpoints(&patched);
    let config = Config::from_yaml(&patched).expect("production-gateway example should parse");

    let _proxy = start_full_proxy(&config);
    let client_cfg = certs.client_config();
    wait_for_https(&format!("127.0.0.1:{https_port}"), &client_cfg);

    // HTTPS listener: path routing plus the security header pipeline.
    let (status, body) = https_get(&format!("127.0.0.1:{https_port}"), "/api/v1/users", &client_cfg);
    assert_eq!(status, 200, "HTTPS /api/ should return 200");
    assert_eq!(body, "api-backend", "HTTPS /api/ should route to the api cluster");

    // Plain HTTP listener runs the same composed chains.
    let (status, body) = http_get(&format!("127.0.0.1:{http_port}"), "/", None);
    assert_eq!(status, 200, "HTTP root should return 200");
    assert_eq!(body, "web-backend", "HTTP root should route to the web cluster");

    let raw = http_send(
        &format!("127.0.0.1:{http_port}"),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_header(&raw, "x-frame-options"),
        Some("DENY".to_owned()),
        "the security chain should set X-Frame-Options"
    );
    assert_eq!(
        parse_header(&raw, "x-content-type-options"),
        Some("nosniff".to_owned()),
        "the security chain should set X-Content-Type-Options"
    );
}

#[test]
fn hot_reload_example_applies_config_change() {
    let proxy_port = free_port();

    let path = example_config_path("operations/hot-reload.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let patched = patch_yaml(&yaml, proxy_port, &HashMap::new());

    let proxy = start_reloadable_proxy(&patched);

    let (status, body) = http_get(proxy.addr(), "/api/hello", None);
    assert_eq!(status, 200, "hot-reload example should return 200");
    assert!(
        body.contains("hello from praxis"),
        "initial static response should serve, got: {body}"
    );

    // Edit the config the way the example instructs: change the
    // static_response body and let the watcher swap the pipeline.
    proxy.write_config(&patched.replace("hello from praxis", "reloaded"));

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let (status, body) = http_get(proxy.addr(), "/api/hello", None);
        assert_eq!(status, 200, "proxy should keep serving across the reload");
        if body.contains("reloaded") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "reloaded static response should serve within the deadline, last body: {body}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
