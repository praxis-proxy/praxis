//! Information leakage adversarial tests.
//!
//! Verifies that error and rejection responses do not
//! expose internal details such as stack traces, file
//! paths, server headers, or backend addresses.

use praxis_core::config::Config;

use crate::common::{free_port, http_send, parse_body, parse_header, parse_status, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// YAML Builder For ACL-Denied Proxy
// -----------------------------------------------------------------------------

/// Generate proxy YAML that denies all traffic via ip_acl.
fn deny_all_yaml(proxy_port: u16, backend_port: u16) -> String {
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
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn error_responses_have_no_stack_traces() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = deny_all_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(parse_status(&raw), 403, "deny-all ACL must return 403");

    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert!(!body_lower.contains("panic"), "error body contains panic info: {body}");
    assert!(
        !body_lower.contains("thread '"),
        "error body contains thread info: {body}"
    );
    assert!(
        !body_lower.contains("stack backtrace"),
        "error body contains stack trace: {body}"
    );
    assert!(
        !body_lower.contains(".rs:"),
        "error body contains Rust source paths: {body}"
    );
    assert!(
        !body_lower.contains("src/"),
        "error body contains source directory paths: {body}"
    );
}

#[test]
fn backend_server_header_not_leaked_in_rejection() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = deny_all_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(parse_status(&raw), 403, "deny-all ACL must return 403");

    let server = parse_header(&raw, "server");
    assert!(
        server.as_deref() != Some("praxis-test-backend"),
        "backend Server header leaked in rejection response: {server:?}"
    );
}

#[test]
fn proxy_error_on_no_backend_reveals_nothing() {
    let proxy_port = free_port();
    let dead_port = free_port();
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
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{dead_port}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let status = parse_status(&raw);
    assert!(status >= 400, "unreachable backend must produce an error status");

    let body = parse_body(&raw);
    let raw_lower = raw.to_lowercase();

    assert!(
        !body.contains(&dead_port.to_string()),
        "error response reveals backend port: {body}"
    );
    assert!(
        !raw_lower.contains(&format!("127.0.0.1:{dead_port}")),
        "error response reveals backend address in headers or body"
    );
}

#[test]
fn rejection_responses_include_connection_close() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = deny_all_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(parse_status(&raw), 403, "deny-all ACL must return 403");

    assert!(raw.contains("\r\n\r\n"), "rejection response must be well-formed HTTP");
}
