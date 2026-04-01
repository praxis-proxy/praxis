//! Integration tests for the `json_body_field` filter.

use praxis_core::config::Config;

use crate::common::{free_port, http_send, parse_body, parse_status, start_header_echo_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn extracts_string_field_to_header() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = proxy_yaml(proxy_port, backend_port, "model", "X-Model");
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let raw = http_send(
        &addr,
        &json_post("/v1/chat", r#"{"model":"claude-sonnet-4-5","prompt":"hi"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "string field extraction should return 200");
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-model: claude-sonnet-4-5"),
        "expected X-Model header echoed by backend, got:\n{body}"
    );
}

#[test]
fn custom_field_and_header_names() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = proxy_yaml(proxy_port, backend_port, "provider", "X-Provider");
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let raw = http_send(&addr, &json_post("/api", r#"{"provider":"anthropic"}"#));
    assert_eq!(parse_status(&raw), 200, "custom field extraction should return 200");
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-provider: anthropic"),
        "expected X-Provider header, got:\n{body}"
    );
}

#[test]
fn numeric_value_promoted_as_string() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = proxy_yaml(proxy_port, backend_port, "count", "X-Count");
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let raw = http_send(&addr, &json_post("/api", r#"{"count":42}"#));
    assert_eq!(parse_status(&raw), 200, "numeric field extraction should return 200");
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-count: 42"),
        "expected X-Count: 42 header, got:\n{body}"
    );
}

#[test]
fn boolean_value_promoted_as_string() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = proxy_yaml(proxy_port, backend_port, "enabled", "X-Enabled");
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let raw = http_send(&addr, &json_post("/api", r#"{"enabled":true}"#));
    assert_eq!(parse_status(&raw), 200, "boolean field extraction should return 200");
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-enabled: true"),
        "expected X-Enabled: true header, got:\n{body}"
    );
}

#[test]
fn missing_field_passes_through_without_header() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = proxy_yaml(proxy_port, backend_port, "model", "X-Model");
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let raw = http_send(&addr, &json_post("/api", r#"{"prompt":"hello"}"#));
    assert_eq!(parse_status(&raw), 200, "missing field should still return 200");
    let body = parse_body(&raw);
    assert!(
        !body.to_lowercase().contains("x-model"),
        "X-Model should not be present when field is missing, got:\n{body}"
    );
}

#[test]
fn invalid_json_passes_through_without_error() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = proxy_yaml(proxy_port, backend_port, "model", "X-Model");
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let raw = http_send(&addr, &json_post("/api", "not json at all"));
    assert_eq!(parse_status(&raw), 200, "invalid JSON should still return 200");
    let body = parse_body(&raw);
    assert!(
        !body.to_lowercase().contains("x-model"),
        "X-Model should not be present for invalid JSON, got:\n{body}"
    );
}

#[test]
fn empty_body_passes_through_without_error() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = proxy_yaml(proxy_port, backend_port, "model", "X-Model");
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let raw = http_send(
        &addr,
        "POST /api HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "empty body should still return 200");
    let body = parse_body(&raw);
    assert!(
        !body.to_lowercase().contains("x-model"),
        "X-Model should not be present for empty body, got:\n{body}"
    );
}

#[test]
fn nested_object_value_promoted_as_json_string() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = proxy_yaml(proxy_port, backend_port, "model", "X-Model");
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let raw = http_send(&addr, &json_post("/api", r#"{"model":{"name":"claude-sonnet-4-5"}}"#));
    assert_eq!(parse_status(&raw), 200, "nested object field should return 200");
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-model:"),
        "X-Model header should be present even for object values, got:\n{body}"
    );
    assert!(
        body.contains("claude-sonnet-4-5"),
        "stringified object value should contain inner content, got:\n{body}"
    );
}

#[test]
fn promoted_header_visible_alongside_routing() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
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
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, &json_post("/v1/chat", r#"{"model":"claude-3"}"#));
    assert_eq!(
        parse_status(&raw),
        200,
        "promoted header with routing should return 200"
    );
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-model: claude-3"),
        "expected promoted header after routing, got:\n{body}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a raw HTTP POST request with a JSON Content-Type.
fn json_post(path: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    )
}

/// Build proxy YAML with `json_body_field` in the pipeline.
fn proxy_yaml(proxy_port: u16, backend_port: u16, field: &str, header: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
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
"#
    )
}
