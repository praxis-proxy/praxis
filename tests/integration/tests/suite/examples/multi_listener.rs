// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for multi-listener behavior.

use std::collections::HashMap;

use praxis_core::config::Config;
use praxis_test_utils::{
    TestCertificates, example_config_path, free_port, http_get, https_get, patch_yaml, start_backend_with_shutdown,
    start_full_proxy, start_proxy, wait_for_https, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn multi_listener() {
    let api_port_guard = start_backend_with_shutdown("api");
    let api_port = api_port_guard.port();
    let web_port_guard = start_backend_with_shutdown("web");
    let web_port = web_port_guard.port();
    let http_port = free_port();
    let admin_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: http
    address: "127.0.0.1:{http_port}"
    filter_chains: [main]
  - name: admin
    address: "127.0.0.1:{admin_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: request_id
      - filter: access_log
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: api
          - path_prefix: "/"
            cluster: web
      - filter: load_balancer
        clusters:
          - name: api
            endpoints:
              - "127.0.0.1:{api_port}"
          - name: web
            endpoints:
              - "127.0.0.1:{web_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let addr_http = format!("127.0.0.1:{http_port}");
    let addr_admin = format!("127.0.0.1:{admin_port}");

    let _proxy = start_proxy(&config);
    wait_for_tcp(&addr_admin);

    let (status, body) = http_get(&addr_http, "/api/test", None);
    assert_eq!(status, 200, "http listener /api/ should return 200");
    assert_eq!(body, "api", "http listener should route /api/ to api backend");

    let (status, body) = http_get(&addr_admin, "/", None);
    assert_eq!(status, 200, "admin listener root should return 200");
    assert_eq!(body, "web", "admin listener should route root to web backend");

    let (status, body) = http_get(&addr_admin, "/api/test", None);
    assert_eq!(status, 200, "admin listener /api/ should return 200");
    assert_eq!(body, "api", "admin listener should route /api/ to api backend");
}

#[test]
fn multi_listener_example_serves_http_https_and_admin() {
    let certs = TestCertificates::generate();
    let api1 = start_backend_with_shutdown("api");
    let api2 = start_backend_with_shutdown("api");
    let web = start_backend_with_shutdown("web");
    let http_port = free_port();
    let https_port = free_port();
    let admin_port = free_port();

    let path = example_config_path("operations/multi-listener.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let patched = patch_yaml(
        &yaml,
        http_port,
        &HashMap::from([
            ("127.0.0.1:8443", https_port),
            ("127.0.0.1:9090", admin_port),
            ("127.0.0.1:3001", api1.port()),
            ("127.0.0.1:3002", api2.port()),
            ("127.0.0.1:4000", web.port()),
        ]),
    )
    .replace("/etc/praxis/tls/cert.pem", &certs.cert_path.display().to_string())
    .replace("/etc/praxis/tls/key.pem", &certs.key_path.display().to_string());
    let config = Config::from_yaml(&patched).expect("multi-listener example should parse");

    let _proxy = start_full_proxy(&config);
    let client_cfg = certs.client_config();
    wait_for_https(&format!("127.0.0.1:{https_port}"), &client_cfg);

    // Public HTTP listener routes by path.
    let (status, body) = http_get(&format!("127.0.0.1:{http_port}"), "/api/users", None);
    assert_eq!(status, 200, "public HTTP /api/ should return 200");
    assert_eq!(body, "api", "public HTTP should route /api/ to the api cluster");
    let (status, body) = http_get(&format!("127.0.0.1:{http_port}"), "/", None);
    assert_eq!(status, 200, "public HTTP root should return 200");
    assert_eq!(body, "web", "public HTTP should route root to the web cluster");

    // Public HTTPS listener shares the same pipeline over TLS.
    let (status, body) = https_get(&format!("127.0.0.1:{https_port}"), "/api/users", &client_cfg);
    assert_eq!(status, 200, "HTTPS /api/ should return 200");
    assert_eq!(body, "api", "HTTPS should route /api/ to the api cluster");

    // Internal admin listener serves the same routes without the
    // observability filters.
    let (status, body) = http_get(&format!("127.0.0.1:{admin_port}"), "/", None);
    assert_eq!(status, 200, "admin listener root should return 200");
    assert_eq!(body, "web", "admin listener should route root to the web cluster");
}
