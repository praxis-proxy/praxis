//! Integration tests for wildcard subdomain routing.

use praxis_core::config::Config;

use crate::common::{free_port, http_get, http_send, parse_status, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn wildcard_host_routes_subdomain_to_cluster() {
    let wildcard_port = start_backend("wildcard-backend");
    let default_port = start_backend("default-backend");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        host: "*.example.com"
        cluster: "wildcard"
      - path_prefix: "/"
        cluster: "default"
  - filter: load_balancer
    clusters:
      - name: "wildcard"
        endpoints:
          - "127.0.0.1:{wildcard_port}"
      - name: "default"
        endpoints:
          - "127.0.0.1:{default_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, body) = http_get(&addr, "/", Some("api.example.com"));
    assert_eq!(status, 200, "api.example.com should match wildcard route");
    assert_eq!(
        body, "wildcard-backend",
        "api.example.com should route to wildcard cluster"
    );

    let (status, body) = http_get(&addr, "/", Some("www.example.com"));
    assert_eq!(status, 200, "www.example.com should match wildcard route");
    assert_eq!(
        body, "wildcard-backend",
        "www.example.com should route to wildcard cluster"
    );
}

#[test]
fn wildcard_host_does_not_match_bare_domain() {
    let wildcard_port = start_backend("wildcard-backend");
    let default_port = start_backend("default-backend");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        host: "*.example.com"
        cluster: "wildcard"
      - path_prefix: "/"
        cluster: "default"
  - filter: load_balancer
    clusters:
      - name: "wildcard"
        endpoints:
          - "127.0.0.1:{wildcard_port}"
      - name: "default"
        endpoints:
          - "127.0.0.1:{default_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, body) = http_get(&addr, "/", Some("example.com"));
    assert_eq!(status, 200, "example.com should fall back to default route");
    assert_eq!(
        body, "default-backend",
        "bare domain should not match wildcard, should route to default"
    );
}

#[test]
fn wildcard_host_does_not_match_multi_level_subdomain() {
    let wildcard_port = start_backend("wildcard-backend");
    let default_port = start_backend("default-backend");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        host: "*.example.com"
        cluster: "wildcard"
      - path_prefix: "/"
        cluster: "default"
  - filter: load_balancer
    clusters:
      - name: "wildcard"
        endpoints:
          - "127.0.0.1:{wildcard_port}"
      - name: "default"
        endpoints:
          - "127.0.0.1:{default_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, body) = http_get(&addr, "/", Some("a.b.example.com"));
    assert_eq!(status, 200, "multi-level subdomain should fall back to default route");
    assert_eq!(
        body, "default-backend",
        "a.b.example.com should not match single-level wildcard"
    );
}

#[test]
fn wildcard_host_with_port_in_host_header() {
    let wildcard_port = start_backend("wildcard-backend");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        host: "*.example.com"
        cluster: "wildcard"
  - filter: load_balancer
    clusters:
      - name: "wildcard"
        endpoints:
          - "127.0.0.1:{wildcard_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\nHost: app.example.com:9090\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(
        status, 200,
        "wildcard host should match after port is stripped from Host header"
    );
}

#[test]
fn exact_host_takes_priority_over_wildcard() {
    let exact_port = start_backend("exact-backend");
    let wildcard_port = start_backend("wildcard-backend");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        host: "api.example.com"
        cluster: "exact"
      - path_prefix: "/"
        host: "*.example.com"
        cluster: "wildcard"
  - filter: load_balancer
    clusters:
      - name: "exact"
        endpoints:
          - "127.0.0.1:{exact_port}"
      - name: "wildcard"
        endpoints:
          - "127.0.0.1:{wildcard_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, body) = http_get(&addr, "/", Some("api.example.com"));
    assert_eq!(status, 200, "exact host should match");
    assert_eq!(
        body, "exact-backend",
        "exact host should take priority over wildcard (first-match)"
    );

    let (status, body) = http_get(&addr, "/", Some("www.example.com"));
    assert_eq!(status, 200, "www.example.com should match wildcard");
    assert_eq!(
        body, "wildcard-backend",
        "non-exact subdomain should fall through to wildcard"
    );
}

#[test]
fn wildcard_no_match_returns_404() {
    let wildcard_port = start_backend("wildcard-backend");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        host: "*.example.com"
        cluster: "wildcard"
  - filter: load_balancer
    clusters:
      - name: "wildcard"
        endpoints:
          - "127.0.0.1:{wildcard_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, _body) = http_get(&addr, "/", Some("other.dev"));
    assert_eq!(status, 404, "non-matching host with no default route should return 404");
}

#[test]
fn wildcard_combined_with_path_routing() {
    let api_port = start_backend("api-response");
    let web_port = start_backend("web-response");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/api/"
        host: "*.example.com"
        cluster: "api"
      - path_prefix: "/"
        host: "*.example.com"
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

    let (status, body) = http_get(&addr, "/api/users", Some("app.example.com"));
    assert_eq!(status, 200, "/api/ with wildcard host should return 200");
    assert_eq!(
        body, "api-response",
        "wildcard + /api/ prefix should route to api cluster"
    );

    let (status, body) = http_get(&addr, "/index.html", Some("app.example.com"));
    assert_eq!(status, 200, "/ with wildcard host should return 200");
    assert_eq!(body, "web-response", "wildcard + / prefix should route to web cluster");
}

#[test]
fn wildcard_shorthand_routes_config() {
    let wildcard_port = start_backend("wildcard-shorthand");
    let default_port = start_backend("default-shorthand");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
routes:
  - path_prefix: "/"
    host: "*.example.com"
    cluster: "wildcard"
  - path_prefix: "/"
    cluster: "default"
clusters:
  - name: "wildcard"
    endpoints:
      - "127.0.0.1:{wildcard_port}"
  - name: "default"
    endpoints:
      - "127.0.0.1:{default_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, body) = http_get(&addr, "/", Some("tenant.example.com"));
    assert_eq!(status, 200, "wildcard in shorthand routes should match");
    assert_eq!(
        body, "wildcard-shorthand",
        "wildcard in shorthand routes should route to wildcard cluster"
    );

    let (status, body) = http_get(&addr, "/", Some("other.dev"));
    assert_eq!(status, 200, "non-matching host should fall back to default");
    assert_eq!(
        body, "default-shorthand",
        "non-matching host should route to default cluster"
    );
}
