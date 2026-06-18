// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Path-based routing tests.

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn path_based_routing() {
    let api_port_guard = start_backend_with_shutdown("api response");
    let api_port = api_port_guard.port();
    let web_port_guard = start_backend_with_shutdown("web response");
    let web_port = web_port_guard.port();
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
          - path_prefix: "/api/"
            cluster: "api"
          - path_prefix: "/"
            cluster: "web"
      - filter: load_balancer
        clusters:
          - name: "api"
            endpoints:
              - "127.0.0.1:{api_port}"
          - name: "web"
            endpoints:
              - "127.0.0.1:{web_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/api/users", None);
    assert_eq!(status, 200, "/api/ path should return 200");
    assert_eq!(body, "api response", "/api/ should route to api backend");

    let (status, body) = http_get(proxy.addr(), "/index.html", None);
    assert_eq!(status, 200, "default path should return 200");
    assert_eq!(body, "web response", "default path should route to web backend");
}

#[test]
fn no_matching_route_returns_404() {
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
          - path_prefix: "/api/"
            cluster: "api"
      - filter: load_balancer
        clusters:
          - name: "api"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _body) = http_get(proxy.addr(), "/other", None);
    assert_eq!(status, 404, "unmatched route should return 404");
}
