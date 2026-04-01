//! Integration tests for the `ip_acl` filter.

use praxis_core::config::Config;

use crate::common::{
    free_port, http_get, http_send, parse_header, parse_status, start_backend, start_proxy, wait_for_http,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn acl_allow_loopback_in_full_pipeline() {
    let port_a = start_backend("backend-a");
    let port_b = start_backend("backend-b");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        allow:
          - "127.0.0.0/8"
        deny:
          - "0.0.0.0/0"
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
              - "127.0.0.1:{port_a}"
          - name: "web"
            endpoints:
              - "127.0.0.1:{port_b}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, body) = http_get(&addr, "/api/users", None);
    assert_eq!(status, 200, "loopback should be allowed by ACL");
    assert_eq!(body, "backend-a", "/api/ should route to api backend");

    let (status, body) = http_get(&addr, "/index.html", None);
    assert_eq!(status, 200, "loopback should be allowed for web path");
    assert_eq!(body, "backend-b", "default path should route to web backend");
}

#[test]
fn acl_with_path_condition_only_enforces_on_matching_path() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        deny:
          - "0.0.0.0/0"
        conditions:
          - when:
              path_prefix: "/admin/"
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

    let (status, _) = http_get(&addr, "/admin/settings", None);
    assert_eq!(status, 403, "/admin/ path should be blocked by ACL");

    let (status, body) = http_get(&addr, "/public/page", None);
    assert_eq!(status, 200, "non-admin path should bypass ACL");
    assert_eq!(body, "ok", "non-admin path should return backend response");
}

#[test]
fn acl_with_response_headers_on_allowed_request() {
    let backend_port = start_backend("allowed");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        allow:
          - "127.0.0.0/8"
        deny:
          - "0.0.0.0/0"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: headers
        response_add:
          - name: X-ACL-Status
            value: "passed"
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
    assert_eq!(parse_status(&raw), 200, "allowed request should return 200");
    assert_eq!(
        parse_header(&raw, "x-acl-status"),
        Some("passed".to_string()),
        "allowed request should have response header from headers filter"
    );
}

#[test]
fn per_listener_acl_rules() {
    let backend_port = start_backend("ok");
    let port_open = free_port();
    let port_locked = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: open
    address: "127.0.0.1:{port_open}"
    filter_chains: [routing, open_acl]
  - name: locked
    address: "127.0.0.1:{port_locked}"
    filter_chains: [routing, locked_acl]
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
  - name: open_acl
    filters:
      - filter: ip_acl
        allow:
          - "127.0.0.0/8"
        deny:
          - "0.0.0.0/0"
  - name: locked_acl
    filters:
      - filter: ip_acl
        deny:
          - "127.0.0.0/8"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    start_proxy(&config);
    wait_for_http(&format!("127.0.0.1:{port_locked}"));

    let (status, body) = http_get(&format!("127.0.0.1:{port_open}"), "/", None);
    assert_eq!(status, 200, "open listener should allow loopback");
    assert_eq!(body, "ok", "open listener should return backend response");

    let (status, _) = http_get(&format!("127.0.0.1:{port_locked}"), "/", None);
    assert_eq!(status, 403, "locked listener should deny loopback");
}

#[test]
fn acl_exact_host_cidr_32() {
    let backend_port = start_backend("precise");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        allow:
          - "127.0.0.1/32"
        deny:
          - "0.0.0.0/0"
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
    assert_eq!(status, 200, "/32 CIDR should match 127.0.0.1 exactly");
    assert_eq!(body, "precise", "/32 CIDR should forward backend response");
}

#[test]
fn acl_with_observability_filters() {
    let backend_port = start_backend("observed");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        allow:
          - "127.0.0.0/8"
        deny:
          - "0.0.0.0/0"
      - filter: request_id
      - filter: access_log
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

    let (status, body) = http_get(&addr, "/test", None);
    assert_eq!(
        status, 200,
        "allowed request with observability filters should return 200"
    );
    assert_eq!(
        body, "observed",
        "response body should pass through observability filters"
    );
}

#[test]
fn acl_unless_condition_exempts_path() {
    let backend_port = start_backend("healthy");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        deny:
          - "0.0.0.0/0"
        conditions:
          - unless:
              path_prefix: "/healthz"
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

    let (status, body) = http_get(&addr, "/healthz", None);
    assert_eq!(status, 200, "/healthz should bypass ACL via unless condition");
    assert_eq!(body, "healthy", "/healthz should return backend response");

    let (status, _) = http_get(&addr, "/api/data", None);
    assert_eq!(status, 403, "non-exempt path should be denied by ACL");
}
