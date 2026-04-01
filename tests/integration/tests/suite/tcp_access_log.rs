//! Integration tests for the `tcp_access_log` filter.

use praxis_core::config::Config;

use crate::common::{free_port, http_get, http_send, parse_body, parse_status, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn tcp_access_log_does_not_alter_response() {
    let backend_port = start_backend("hello from backend");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: proxy
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: tcp_access_log
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
    let addr = start_proxy(&config);

    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "tcp_access_log should not change response status");
    assert_eq!(
        body, "hello from backend",
        "tcp_access_log should not alter response body"
    );
}

#[test]
fn tcp_access_log_handles_multiple_requests() {
    let backend_port = start_backend("repeated");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: proxy
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: tcp_access_log
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
    let addr = start_proxy(&config);

    for _ in 0..5 {
        let (status, body) = http_get(&addr, "/", None);
        assert_eq!(status, 200, "repeated request should return 200");
        assert_eq!(body, "repeated", "repeated request body should match backend");
    }
}

#[test]
fn tcp_access_log_combined_with_headers_filter() {
    let backend_port = start_backend("combined");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: proxy
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: tcp_access_log
      - filter: headers
        response_add:
          - name: X-Via
            value: "praxis"
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
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(parse_status(&raw), 200, "combined filters should return 200");
    assert_eq!(parse_body(&raw), "combined", "response body should match backend");
    assert!(
        raw.to_lowercase().contains("x-via: praxis"),
        "headers filter should still add X-Via when tcp_access_log is present, got:\n{raw}"
    );
}

#[test]
fn tcp_access_log_does_not_interfere_with_routing() {
    let api_port = start_backend("api");
    let web_port = start_backend("web");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: proxy
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: tcp_access_log
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
    let addr = start_proxy(&config);

    let (status, body) = http_get(&addr, "/api/users", None);
    assert_eq!(status, 200, "/api/ path should return 200");
    assert_eq!(body, "api", "/api/ should route to api backend");

    let (status, body) = http_get(&addr, "/index.html", None);
    assert_eq!(status, 200, "default path should return 200");
    assert_eq!(body, "web", "default path should route to web backend");
}

#[test]
fn tcp_access_log_per_listener_isolation() {
    let backend_port = start_backend("isolated");
    let port_a = free_port();
    let port_b = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: with_log
    address: "127.0.0.1:{port_a}"
    filter_chains: [logging, shared]
  - name: without_log
    address: "127.0.0.1:{port_b}"
    filter_chains: [shared]
filter_chains:
  - name: logging
    filters:
      - filter: tcp_access_log
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
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    start_proxy(&config);
    crate::common::wait_for_tcp(&format!("127.0.0.1:{port_b}"));

    let (status_a, body_a) = http_get(&format!("127.0.0.1:{port_a}"), "/", None);
    assert_eq!(status_a, 200, "listener with log should return 200");
    assert_eq!(body_a, "isolated", "listener with log should proxy correctly");

    let (status_b, body_b) = http_get(&format!("127.0.0.1:{port_b}"), "/", None);
    assert_eq!(status_b, 200, "listener without log should return 200");
    assert_eq!(body_b, "isolated", "listener without log should proxy correctly");
}

#[test]
fn tcp_access_log_preserves_404_on_no_route() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: proxy
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: tcp_access_log
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, _body) = http_get(&addr, "/not-found", None);
    assert_eq!(
        status, 404,
        "unmatched route should return 404 even with tcp_access_log"
    );
}
