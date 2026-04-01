//! Integration tests for payload processing example configurations.

use praxis_core::config::Config;

use crate::common::{
    free_port, http_send, parse_body, parse_status, start_backend, start_header_echo_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn stream_buffer_routes_by_extracted_action() {
    let process_port = start_backend("process-backend");
    let validate_port = start_backend("validate-backend");
    let default_port = start_backend("default-backend");
    let proxy_port = free_port();

    let yaml = action_routing_yaml(proxy_port, process_port, validate_port, default_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, &json_post("/tasks", r#"{"action":"process","payload":"data"}"#));
    assert_eq!(parse_status(&raw), 200, "process action should return 200");
    assert_eq!(
        parse_body(&raw),
        "process-backend",
        "action=process should route to processor cluster"
    );

    let raw = http_send(&addr, &json_post("/tasks", r#"{"action":"validate","payload":"data"}"#));
    assert_eq!(parse_status(&raw), 200, "validate action should return 200");
    assert_eq!(
        parse_body(&raw),
        "validate-backend",
        "action=validate should route to validator cluster"
    );
}

#[test]
fn stream_buffer_unknown_action_routes_to_default() {
    let process_port = start_backend("process-backend");
    let validate_port = start_backend("validate-backend");
    let default_port = start_backend("default-backend");
    let proxy_port = free_port();

    let yaml = action_routing_yaml(proxy_port, process_port, validate_port, default_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, &json_post("/tasks", r#"{"action":"unknown","payload":"data"}"#));
    assert_eq!(parse_status(&raw), 200, "unknown action should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "unknown action should route to default cluster"
    );
}

#[test]
fn stream_buffer_missing_action_routes_to_default() {
    let process_port = start_backend("process-backend");
    let validate_port = start_backend("validate-backend");
    let default_port = start_backend("default-backend");
    let proxy_port = free_port();

    let yaml = action_routing_yaml(proxy_port, process_port, validate_port, default_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, &json_post("/tasks", r#"{"payload":"data"}"#));
    assert_eq!(parse_status(&raw), 200, "missing action should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "missing action field should route to default cluster"
    );
}

#[test]
fn multi_field_extracts_both_fields() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = multi_field_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        &json_post("/v1/chat", r#"{"model":"claude-sonnet-4-5","user_id":"u-42"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "multi-field extraction should return 200");
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("x-model: claude-sonnet-4-5"),
        "expected X-Model header echoed by backend, got:\n{body}"
    );
    assert!(
        body_lower.contains("x-user-id: u-42"),
        "expected X-User-Id header echoed by backend, got:\n{body}"
    );
}

#[test]
fn multi_field_missing_one_still_extracts_other() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = multi_field_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, &json_post("/v1/chat", r#"{"model":"claude-sonnet-4-5"}"#));
    assert_eq!(parse_status(&raw), 200, "single-field present should return 200");
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("x-model: claude-sonnet-4-5"),
        "expected X-Model header when only model is present, got:\n{body}"
    );
    assert!(
        !body_lower.contains("x-user-id"),
        "X-User-Id should not be present when user_id field is missing, got:\n{body}"
    );
}

#[test]
fn multi_field_routes_by_extracted_model() {
    let claude_port = start_backend("claude-backend");
    let default_port = start_backend("default-backend");
    let proxy_port = free_port();

    let yaml = multi_field_routing_yaml(proxy_port, claude_port, default_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        &json_post("/v1/chat", r#"{"model":"claude-sonnet-4-5","user_id":"u-42"}"#),
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "claude-sonnet-4-5 model routing should return 200"
    );
    assert_eq!(
        parse_body(&raw),
        "claude-backend",
        "model=claude-sonnet-4-5 should route to claude_sonnet cluster"
    );

    let raw = http_send(&addr, &json_post("/v1/chat", r#"{"model":"unknown","user_id":"u-42"}"#));
    assert_eq!(parse_status(&raw), 200, "unknown model routing should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "unknown model should route to default cluster"
    );
}

#[test]
fn conditional_extraction_fires_on_matching_path() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = conditional_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        &json_post("/v1/chat/completions", r#"{"model":"claude-sonnet-4-5","prompt":"hi"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "matching path extraction should return 200");
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-model: claude-sonnet-4-5"),
        "X-Model should be extracted on /v1/ path, got:\n{body}"
    );
}

#[test]
fn conditional_extraction_skips_on_non_matching_path() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = conditional_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        &json_post("/other/endpoint", r#"{"model":"claude-sonnet-4-5","prompt":"hi"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "non-matching path should return 200");
    let body = parse_body(&raw);
    assert!(
        !body.to_lowercase().contains("x-model"),
        "X-Model should NOT be extracted on /other/ path, got:\n{body}"
    );
}

#[test]
fn body_limit_allows_small_body_with_extraction() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = body_limit_extraction_yaml(proxy_port, backend_port, 4096);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        &json_post("/v1/chat", r#"{"model":"claude-sonnet-4-5","prompt":"hello"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "small body under limit should return 200");
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-model: claude-sonnet-4-5"),
        "field should be extracted from small body, got:\n{body}"
    );
}

#[test]
fn body_limit_rejects_oversized_body() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = body_limit_extraction_yaml(proxy_port, backend_port, 32);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let large_body = format!(r#"{{"model":"claude-sonnet-4-5","prompt":"{}"}}"#, "x".repeat(100));
    let raw = http_send(&addr, &json_post("/v1/chat", &large_body));
    assert_eq!(parse_status(&raw), 413, "oversized body should be rejected with 413");
}

#[test]
fn body_limit_exact_boundary_succeeds() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();

    let small_json = r#"{"model":"claude-sonnet-4-5"}"#;
    let limit = small_json.len();
    let yaml = body_limit_extraction_yaml(proxy_port, backend_port, limit);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, &json_post("/v1/chat", small_json));
    assert_eq!(
        parse_status(&raw),
        200,
        "body at exact limit boundary should return 200"
    );
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-model: claude-sonnet-4-5"),
        "field should be extracted at exact boundary, got:\n{body}"
    );
}

#[test]
fn tenant_extraction_routes_to_correct_backend() {
    let acme_port = start_backend("acme-backend");
    let globex_port = start_backend("globex-backend");
    let default_port = start_backend("default-backend");
    let proxy_port = free_port();

    let yaml = tenant_routing_yaml(proxy_port, acme_port, globex_port, default_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        &json_post("/api/data", r#"{"tenant_id":"acme","query":"SELECT *"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "acme tenant routing should return 200");
    assert_eq!(
        parse_body(&raw),
        "acme-backend",
        "tenant_id=acme should route to acme cluster"
    );

    let raw = http_send(
        &addr,
        &json_post("/api/data", r#"{"tenant_id":"globex","query":"SELECT *"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "globex tenant routing should return 200");
    assert_eq!(
        parse_body(&raw),
        "globex-backend",
        "tenant_id=globex should route to globex cluster"
    );
}

#[test]
fn tenant_extraction_unknown_tenant_routes_to_default() {
    let acme_port = start_backend("acme-backend");
    let globex_port = start_backend("globex-backend");
    let default_port = start_backend("default-backend");
    let proxy_port = free_port();

    let yaml = tenant_routing_yaml(proxy_port, acme_port, globex_port, default_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        &json_post("/api/data", r#"{"tenant_id":"unknown","query":"SELECT *"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "unknown tenant should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "unknown tenant_id should route to default cluster"
    );
}

#[test]
fn tenant_extraction_missing_tenant_routes_to_default() {
    let acme_port = start_backend("acme-backend");
    let globex_port = start_backend("globex-backend");
    let default_port = start_backend("default-backend");
    let proxy_port = free_port();

    let yaml = tenant_routing_yaml(proxy_port, acme_port, globex_port, default_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, &json_post("/api/data", r#"{"query":"SELECT *"}"#));
    assert_eq!(parse_status(&raw), 200, "missing tenant should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "missing tenant_id should route to default cluster"
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

/// YAML config for action-based routing via stream-buffer extraction.
fn action_routing_yaml(proxy_port: u16, process_port: u16, validate_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - body-inspection
      - routing
filter_chains:
  - name: body-inspection
    filters:
      - filter: json_body_field
        field: action
        header: X-Action
  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            headers:
              x-action: "process"
            cluster: processor
          - path_prefix: "/"
            headers:
              x-action: "validate"
            cluster: validator
          - path_prefix: "/"
            cluster: default
      - filter: load_balancer
        clusters:
          - name: processor
            endpoints:
              - "127.0.0.1:{process_port}"
          - name: validator
            endpoints:
              - "127.0.0.1:{validate_port}"
          - name: default
            endpoints:
              - "127.0.0.1:{default_port}"
"#
    )
}

/// YAML config for multi-field extraction echoing headers back.
fn multi_field_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: json_body_field
    fields:
      - field: model
        header: X-Model
      - field: user_id
        header: X-User-Id
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: backend
  - filter: load_balancer
    clusters:
      - name: backend
        endpoints:
          - "127.0.0.1:{backend_port}"
"#
    )
}

/// YAML config for multi-field extraction with model-based routing.
fn multi_field_routing_yaml(proxy_port: u16, claude_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: json_body_field
    fields:
      - field: model
        header: X-Model
      - field: user_id
        header: X-User-Id
  - filter: router
    routes:
      - path_prefix: "/"
        headers:
          x-model: "claude-sonnet-4-5"
        cluster: claude_sonnet
      - path_prefix: "/"
        cluster: default
  - filter: load_balancer
    clusters:
      - name: claude_sonnet
        endpoints:
          - "127.0.0.1:{claude_port}"
      - name: default
        endpoints:
          - "127.0.0.1:{default_port}"
"#
    )
}

/// YAML config for conditional field extraction on /v1/ paths.
fn conditional_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: json_body_field
    conditions:
      - when:
          path_prefix: "/v1/"
    field: model
    header: X-Model
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: backend
  - filter: load_balancer
    clusters:
      - name: backend
        endpoints:
          - "127.0.0.1:{backend_port}"
"#
    )
}

/// YAML config for body size limit combined with field extraction.
fn body_limit_extraction_yaml(proxy_port: u16, backend_port: u16, limit: usize) -> String {
    format!(
        r#"
max_request_body_bytes: {limit}
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: json_body_field
    field: model
    header: X-Model
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: backend
  - filter: load_balancer
    clusters:
      - name: backend
        endpoints:
          - "127.0.0.1:{backend_port}"
"#
    )
}

/// YAML config for tenant-based access control routing.
fn tenant_routing_yaml(proxy_port: u16, acme_port: u16, globex_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - extract-tenant
      - routing
filter_chains:
  - name: extract-tenant
    filters:
      - filter: json_body_field
        field: tenant_id
        header: X-Tenant-Id
  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            headers:
              x-tenant-id: "acme"
            cluster: acme
          - path_prefix: "/"
            headers:
              x-tenant-id: "globex"
            cluster: globex
          - path_prefix: "/"
            cluster: default
      - filter: load_balancer
        clusters:
          - name: acme
            endpoints:
              - "127.0.0.1:{acme_port}"
          - name: globex
            endpoints:
              - "127.0.0.1:{globex_port}"
          - name: default
            endpoints:
              - "127.0.0.1:{default_port}"
"#
    )
}
