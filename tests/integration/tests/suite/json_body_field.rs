// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for the `json_body_field` filter.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, json_post, parse_body, parse_status, start_header_echo_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn extracts_string_field_to_header() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = proxy_yaml(proxy_port, backend_port, "model", "X-Model");
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/chat", r#"{"model":"model-alpha-1","prompt":"hi"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "string field extraction should return 200");
    assert_echoed_header_once(&parse_body(&raw), "X-Model", "model-alpha-1");
}

#[test]
fn custom_field_and_header_names() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = proxy_yaml(proxy_port, backend_port, "provider", "X-Provider");
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let raw = http_send(proxy.addr(), &json_post("/api", r#"{"provider":"provider-b"}"#));
    assert_eq!(parse_status(&raw), 200, "custom field extraction should return 200");
    assert_echoed_header_once(&parse_body(&raw), "X-Provider", "provider-b");
}

#[test]
fn numeric_value_promoted_as_string() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = proxy_yaml(proxy_port, backend_port, "count", "X-Count");
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let raw = http_send(proxy.addr(), &json_post("/api", r#"{"count":42}"#));
    assert_eq!(parse_status(&raw), 200, "numeric field extraction should return 200");
    assert_echoed_header_once(&parse_body(&raw), "X-Count", "42");
}

#[test]
fn boolean_value_promoted_as_string() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = proxy_yaml(proxy_port, backend_port, "enabled", "X-Enabled");
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let raw = http_send(proxy.addr(), &json_post("/api", r#"{"enabled":true}"#));
    assert_eq!(parse_status(&raw), 200, "boolean field extraction should return 200");
    assert_echoed_header_once(&parse_body(&raw), "X-Enabled", "true");
}

#[test]
fn missing_field_passes_through_without_header() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = proxy_yaml(proxy_port, backend_port, "model", "X-Model");
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let raw = http_send(proxy.addr(), &json_post("/api", r#"{"prompt":"hello"}"#));
    assert_eq!(parse_status(&raw), 200, "missing field should still return 200");
    assert_echoed_header_absent(&parse_body(&raw), "X-Model");
}

#[test]
fn invalid_json_passes_through_without_error() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = proxy_yaml(proxy_port, backend_port, "model", "X-Model");
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let raw = http_send(proxy.addr(), &json_post("/api", "not json at all"));
    assert_eq!(parse_status(&raw), 200, "invalid JSON should still return 200");
    assert_echoed_header_absent(&parse_body(&raw), "X-Model");
}

#[test]
fn empty_body_passes_through_without_error() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = proxy_yaml(proxy_port, backend_port, "model", "X-Model");
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "POST /api HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "empty body should still return 200");
    assert_echoed_header_absent(&parse_body(&raw), "X-Model");
}

#[test]
fn nested_object_value_promoted_as_json_string() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = proxy_yaml(proxy_port, backend_port, "model", "X-Model");
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        &json_post("/api", r#"{"model":{"name":"model-alpha-1"}}"#),
    );
    assert_eq!(parse_status(&raw), 200, "nested object field should return 200");
    let body = parse_body(&raw);
    let lines = echoed_header_lines(&body, "X-Model");
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one X-Model header line, got {} in:\n{body}",
        lines.len()
    );
    assert!(
        lines[0].contains("model-alpha-1"),
        "stringified object value should contain inner content, got:\n{body}"
    );
}

#[test]
fn promoted_header_visible_alongside_routing() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
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
      - filter: json_body_field
        field: model
        header: X-Model
      - filter: router
        routes:
          - path_prefix: "/v1/"
            cluster: "api"
      - filter: load_balancer
        clusters:
          - name: "api"
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/chat", r#"{"model":"model-alpha-2"}"#));
    assert_eq!(
        parse_status(&raw),
        200,
        "promoted header with routing should return 200"
    );
    assert_echoed_header_once(&parse_body(&raw), "X-Model", "model-alpha-2");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Collect echoed request-header lines for `name` (case-insensitive).
///
/// The header-echo backend returns upstream request headers as the response
/// body, one line per header. Counting lines catches duplicate promotions that
/// a substring `contains` check would miss.
fn echoed_header_lines<'a>(body: &'a str, name: &str) -> Vec<&'a str> {
    let prefix = format!("{}:", name.to_ascii_lowercase());
    body.lines()
        .filter(|line| line.trim_start().to_ascii_lowercase().starts_with(&prefix))
        .collect()
}

fn assert_echoed_header_once(body: &str, name: &str, value: &str) {
    let lines = echoed_header_lines(body, name);
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one {name} header line, got {} in:\n{body}",
        lines.len()
    );
    let expected = format!("{}: {}", name.to_ascii_lowercase(), value.to_ascii_lowercase());
    assert_eq!(
        lines[0].trim().to_ascii_lowercase(),
        expected,
        "expected {name}: {value}, got line {:?}\nfull body:\n{body}",
        lines[0]
    );
}

fn assert_echoed_header_absent(body: &str, name: &str) {
    let lines = echoed_header_lines(body, name);
    assert!(
        lines.is_empty(),
        "{name} should not be present, got {} line(s) in:\n{body}",
        lines.len()
    );
}

/// Build proxy YAML with `json_body_field` in the pipeline.
fn proxy_yaml(proxy_port: u16, backend_port: u16, field: &str, header: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: json_body_field
        field: "{field}"
        header: "{header}"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}
