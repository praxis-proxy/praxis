//! IP ACL adversarial tests.
//!
//! Verifies that the `ip_acl` filter correctly denies or
//! allows traffic based on source IP, and that rejection
//! responses do not leak internal details.

use praxis_core::config::Config;

use crate::common::{
    free_port, http_get, http_send, parse_body, parse_header, parse_status, start_backend, start_header_echo_backend,
    start_proxy,
};

// -----------------------------------------------------------------------------
// YAML Builder
// -----------------------------------------------------------------------------

/// Build proxy YAML with ip_acl filter before router.
fn acl_yaml(proxy_port: u16, backend_port: u16, allow: &[&str], deny: &[&str]) -> String {
    let allow_yaml = if allow.is_empty() {
        String::new()
    } else {
        let entries: Vec<String> = allow.iter().map(|a| format!("          - \"{a}\"")).collect();
        format!("        allow:\n{}", entries.join("\n"))
    };

    let deny_yaml = if deny.is_empty() {
        String::new()
    } else {
        let entries: Vec<String> = deny.iter().map(|d| format!("          - \"{d}\"")).collect();
        format!("        deny:\n{}", entries.join("\n"))
    };

    format!(
        r#"
listeners:
  - name: proxy
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
{allow_yaml}
{deny_yaml}
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
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn deny_all_blocks_loopback() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = acl_yaml(proxy_port, backend_port, &[], &["0.0.0.0/0"]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, _) = http_get(&addr, "/", None);
    assert_eq!(status, 403, "deny 0.0.0.0/0 must block loopback");
}

#[test]
fn allow_loopback_with_deny_all() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = acl_yaml(proxy_port, backend_port, &["127.0.0.0/8"], &["0.0.0.0/0"]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, _) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "allow 127.0.0.0/8 must override deny-all");
}

#[test]
fn deny_loopback_blocks_request() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = acl_yaml(proxy_port, backend_port, &[], &["127.0.0.0/8"]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, _) = http_get(&addr, "/", None);
    assert_eq!(status, 403, "deny 127.0.0.0/8 must block loopback client");
}

#[test]
fn empty_acl_allows_all() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = acl_yaml(proxy_port, backend_port, &[], &[]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, _) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "empty ACL must allow all traffic");
}

#[test]
fn allow_list_only_rejects_non_matching() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = acl_yaml(proxy_port, backend_port, &["10.0.0.0/8"], &[]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let (status, _) = http_get(&addr, "/", None);
    assert_eq!(status, 403, "allow-only for 10.0.0.0/8 must reject 127.0.0.1");
}

#[test]
fn acl_rejection_has_no_body_leakage() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = acl_yaml(proxy_port, backend_port, &[], &["0.0.0.0/0"]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert!(!body_lower.contains("panic"), "rejection body contains panic info");
    assert!(!body_lower.contains("thread"), "rejection body contains thread info");
    assert!(
        !body_lower.contains("stack"),
        "rejection body contains stack trace info"
    );
    assert!(!body_lower.contains(".rs"), "rejection body contains Rust file paths");
    assert!(!body_lower.contains("praxis"), "rejection body leaks proxy name");
}

#[test]
fn acl_applies_to_all_methods() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = acl_yaml(proxy_port, backend_port, &[], &["0.0.0.0/0"]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"];
    for method in methods {
        let raw = http_send(
            &addr,
            &format!("{method} / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
        );
        let status = parse_status(&raw);
        assert_eq!(status, 403, "ACL deny-all must block {method} requests");
    }
}

#[test]
fn acl_before_router_means_no_routing_on_denied() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = acl_yaml(proxy_port, backend_port, &[], &["0.0.0.0/0"]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let status = parse_status(&raw);
    assert_eq!(status, 403, "deny-all ACL must return 403");

    let server = parse_header(&raw, "server");
    assert!(
        server.as_deref() != Some("praxis-test-backend"),
        "denied request must not reach backend; got Server: {server:?}"
    );
}
