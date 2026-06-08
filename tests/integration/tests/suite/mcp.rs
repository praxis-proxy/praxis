// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for MCP classifier filter.

use std::{io::Write, net::TcpStream};

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, parse_body, parse_status, start_backend_with_shutdown, start_echo_backend,
    start_header_echo_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Routing Tests
// -----------------------------------------------------------------------------

#[test]
fn mcp_tools_call_routes_by_name() {
    let weather_guard = start_backend_with_shutdown("weather-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = mcp_routing_yaml(proxy_port, weather_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather"}}"#;
    let request = json_post_with_mcp_headers("/mcp/", body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        "weather-backend",
        "tools/call with name=get_weather should route to weather cluster"
    );
}

#[test]
fn mcp_tools_call_params_forwarded_to_backend() {
    let backend_guard = start_echo_backend();
    let proxy_port = free_port();

    let yaml = mcp_default_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{"city":"Raleigh","units":"metric"}}}"#;
    let request = json_post_with_mcp_headers("/mcp/", body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    let echoed_body = parse_body(&raw);
    let parsed: serde_json::Value = serde_json::from_str(&echoed_body).unwrap();
    assert_eq!(
        parsed["params"]["name"], "get_weather",
        "tools/call params.name should reach backend unchanged"
    );
    assert_eq!(
        parsed["params"]["arguments"]["city"], "Raleigh",
        "tools/call params.arguments should reach backend unchanged"
    );
}

#[test]
fn mcp_tools_list_routes_to_default() {
    let weather_guard = start_backend_with_shutdown("weather-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = mcp_routing_yaml(proxy_port, weather_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
    let request = json_post_with_mcp_headers("/mcp/", body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "tools/list should route to default cluster"
    );
}

// -----------------------------------------------------------------------------
// Header Validation Tests
// -----------------------------------------------------------------------------

#[test]
fn mcp_header_body_mismatch_rejected_with_id() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = mcp_default_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather"}}"#;
    let request = json_post_with_mcp_headers(
        "/mcp/",
        body,
        &[("Mcp-Method", "tools/list"), ("Mcp-Name", "get_weather")],
    );
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200, "JSON-RPC application errors use HTTP 200");
    let response_body = parse_body(&raw);
    let parsed: serde_json::Value = serde_json::from_str(&response_body).unwrap();
    assert_eq!(parsed["error"]["code"], -32001);
    assert_eq!(parsed["error"]["message"], "HeaderMismatch");
    assert_eq!(parsed["id"], 1);
}

#[test]
fn mcp_mismatch_ignore_routes_by_body() {
    let weather_guard = start_backend_with_shutdown("weather-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = mcp_mismatch_ignore_yaml(proxy_port, weather_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather"}}"#;
    let request = json_post_with_mcp_headers("/mcp/", body, &[("Mcp-Method", "tools/list")]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        "weather-backend",
        "mismatch: ignore should route by body-derived values"
    );
}

// -----------------------------------------------------------------------------
// Batch Tests
// -----------------------------------------------------------------------------

#[test]
fn mcp_batch_rejected_even_with_on_invalid_continue() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = mcp_passthrough_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]"#;
    let request = json_post_with_mcp_headers("/mcp/", body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(
        parse_status(&raw),
        400,
        "batch should be rejected even with on_invalid: continue"
    );
}

// -----------------------------------------------------------------------------
// Compatibility Tests
// -----------------------------------------------------------------------------

#[test]
fn mcp_on_invalid_continue_passes_non_json() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = mcp_passthrough_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "GET /sse HTTP/1.1\r\n\
         Host: localhost\r\n\
         Accept: text/event-stream\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
}

// -----------------------------------------------------------------------------
// Synthesize Tests
// -----------------------------------------------------------------------------

#[test]
fn mcp_synthesize_injects_standard_headers_when_missing() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = mcp_synthesize_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather"}}"#;
    let request = json_post_with_mcp_headers("/mcp/", body, &[]);
    let raw = http_send(proxy.addr(), &request);
    let echoed = parse_body(&raw);
    let echoed_lower = echoed.to_lowercase();

    assert_eq!(parse_status(&raw), 200);
    assert!(
        echoed_lower.contains("mcp-method: tools/call"),
        "synthesize should inject mcp-method to backend: {echoed}"
    );
    assert!(
        echoed_lower.contains("mcp-name: get_weather"),
        "synthesize should inject mcp-name to backend: {echoed}"
    );
    assert!(
        !echoed_lower.contains("x-praxis-mcp-method"),
        "internal x-praxis-mcp-method should NOT reach backend: {echoed}"
    );
}

// -----------------------------------------------------------------------------
// Header Leak Tests
// -----------------------------------------------------------------------------

#[test]
fn mcp_standard_headers_preserved_internal_stripped() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = mcp_passthrough_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test"}}"#;
    let request = json_post_with_mcp_headers("/mcp", body, &[("MCP-Session-Id", "sess-123")]);
    let raw = http_send(proxy.addr(), &request);
    let echoed = parse_body(&raw);
    let echoed_lower = echoed.to_lowercase();

    assert!(
        echoed_lower.contains("mcp-session-id: sess-123"),
        "standard MCP-Session-Id should reach backend: {echoed}"
    );
    assert!(
        !echoed_lower.contains("x-praxis-mcp-method"),
        "internal x-praxis-mcp-method should NOT reach backend: {echoed}"
    );
    assert!(
        !echoed_lower.contains("x-praxis-mcp-name"),
        "internal x-praxis-mcp-name should NOT reach backend: {echoed}"
    );
}

// -----------------------------------------------------------------------------
// Required Name Tests
// -----------------------------------------------------------------------------

#[test]
fn mcp_tools_call_missing_name_rejected() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = mcp_default_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#;
    let request = json_post_with_mcp_headers("/mcp/", body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200, "JSON-RPC InvalidParams uses HTTP 200 per spec");
    assert_invalid_params_response(&raw, &serde_json::json!(1));
}

#[test]
fn mcp_tools_call_missing_params_rejected() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = mcp_default_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#;
    let request = json_post_with_mcp_headers("/mcp/", body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200, "JSON-RPC InvalidParams uses HTTP 200 per spec");
    assert_invalid_params_response(&raw, &serde_json::json!(1));
}

#[test]
fn mcp_tools_call_non_string_name_rejected() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = mcp_default_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":"req\\1","method":"tools/call","params":{"name":42}}"#;
    let request = json_post_with_mcp_headers("/mcp/", body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200, "JSON-RPC InvalidParams uses HTTP 200 per spec");
    assert_invalid_params_response(&raw, &serde_json::json!("req\\1"));
}

// -----------------------------------------------------------------------------
// Spurious Header Tests
// -----------------------------------------------------------------------------

#[test]
fn mcp_spurious_name_header_for_nameless_method_rejected() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = mcp_default_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let request = json_post_with_mcp_headers("/mcp/", body, &[("Mcp-Method", "tools/list"), ("Mcp-Name", "evil")]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(
        parse_status(&raw),
        200,
        "JSON-RPC HeaderMismatch uses HTTP 200 per spec"
    );
}

// -----------------------------------------------------------------------------
// Fragmented / Oversized Body Tests
// -----------------------------------------------------------------------------

#[test]
fn mcp_fragmented_body_routes_correctly() {
    let weather_guard = start_backend_with_shutdown("weather-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = mcp_routing_yaml(proxy_port, weather_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather"}}"#;
    let headers = format!(
        "POST /mcp/ HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len(),
    );
    let body_half = body.len() / 2;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    stream.write_all(headers.as_bytes()).unwrap();
    stream.write_all(&body.as_bytes()[..body_half]).unwrap();
    stream.flush().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    stream.write_all(&body.as_bytes()[body_half..]).unwrap();
    stream.flush().unwrap();

    let mut response = Vec::new();
    std::io::Read::read_to_end(&mut stream, &mut response).unwrap();
    let raw = String::from_utf8_lossy(&response);

    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        "weather-backend",
        "fragmented body should still route correctly"
    );
}

#[test]
fn mcp_oversized_body_rejected() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = mcp_small_body_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let payload = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"test","data":"{}"}}}}"#,
        "x".repeat(2000)
    );
    let request = json_post_with_mcp_headers("/mcp/", &payload, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(
        parse_status(&raw),
        413,
        "body exceeding max_body_bytes should return 413"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn json_post_with_mcp_headers(path: &str, body: &str, headers: &[(&str, &str)]) -> String {
    let mut extra = String::new();
    for (name, value) in headers {
        extra.push_str(&format!("{name}: {value}\r\n"));
    }
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         {extra}\
         \r\n\
         {body}",
        body.len(),
    )
}

fn assert_invalid_params_response(raw: &str, expected_id: &serde_json::Value) {
    let response_body = parse_body(raw);
    let parsed: serde_json::Value = serde_json::from_str(&response_body).unwrap();

    assert_eq!(parsed["jsonrpc"], "2.0", "response should be JSON-RPC 2.0");
    assert_eq!(parsed["error"]["code"], -32602, "error code should be InvalidParams");
    assert_eq!(
        parsed["error"]["message"], "InvalidParams",
        "error message should identify InvalidParams"
    );
    assert_eq!(&parsed["id"], expected_id, "response id should match request id");
}

fn mcp_routing_yaml(proxy_port: u16, weather_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: mcp
        max_body_bytes: 65536
        on_invalid: continue
        headers:
          method: x-praxis-mcp-method
          name: x-praxis-mcp-name
      - filter: router
        routes:
          - path_prefix: "/mcp/"
            headers:
              x-praxis-mcp-name: "get_weather"
            cluster: "weather"
          - path_prefix: "/mcp/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "weather"
            endpoints:
              - "127.0.0.1:{weather_port}"
          - name: "default"
            endpoints:
              - "127.0.0.1:{default_port}"
"#,
    )
}

fn mcp_default_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: mcp
        max_body_bytes: 65536
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    )
}

fn mcp_mismatch_ignore_yaml(proxy_port: u16, weather_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: mcp
        max_body_bytes: 65536
        header_validation:
          mismatch: ignore
        headers:
          method: x-praxis-mcp-method
          name: x-praxis-mcp-name
      - filter: router
        routes:
          - path_prefix: "/mcp/"
            headers:
              x-praxis-mcp-name: "get_weather"
            cluster: "weather"
          - path_prefix: "/mcp/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "weather"
            endpoints:
              - "127.0.0.1:{weather_port}"
          - name: "default"
            endpoints:
              - "127.0.0.1:{default_port}"
"#,
    )
}

fn mcp_synthesize_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: mcp
        max_body_bytes: 65536
        header_validation:
          missing: synthesize
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    )
}

fn mcp_passthrough_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: mcp
        max_body_bytes: 65536
        on_invalid: continue
        header_validation:
          mismatch: ignore
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    )
}

fn mcp_small_body_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: mcp
        max_body_bytes: 256
        on_invalid: continue
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    )
}
