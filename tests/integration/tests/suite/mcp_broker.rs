// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for MCP static catalog and broker behavior.

use std::collections::HashMap;

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, load_example_config, parse_body, parse_status, start_backend_with_shutdown, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn mcp_broker_initialize_returns_session() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = broker_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body =
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}"#;
    let request = json_post("/mcp", body);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200, "initialize should return 200");
    let response_body = parse_body(&raw);
    assert!(
        response_body.contains("protocolVersion"),
        "should contain protocolVersion: {response_body}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&response_body).unwrap();
    assert_eq!(
        parsed["result"]["serverInfo"]["name"], "praxis",
        "should contain Praxis server name: {response_body}"
    );
    assert!(
        raw.contains("mcp-session-id:"),
        "response should contain mcp-session-id header"
    );
    assert_ne!(
        response_body, "backend",
        "response should come from Praxis, not backend"
    );
}

#[test]
fn mcp_broker_tools_list_returns_prefixed_catalog() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = broker_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
    let request = json_post("/mcp", body);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200, "tools/list should return 200");
    let response_body = parse_body(&raw);
    assert!(
        response_body.contains("weather_get_weather"),
        "should contain prefixed weather tool: {response_body}"
    );
    assert!(
        response_body.contains("cal_create_event"),
        "should contain prefixed calendar tool: {response_body}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&response_body).unwrap();
    let tools = parsed["result"]["tools"].as_array().unwrap();
    assert!(
        tools.iter().all(|tool| tool.get("inputSchema").is_some()),
        "every returned tool should include inputSchema: {response_body}"
    );
    assert_eq!(
        tools[1]["inputSchema"],
        serde_json::json!({"type": "object", "additionalProperties": false}),
        "tools without configured schema should get a closed object inputSchema"
    );
    assert_ne!(
        response_body, "backend",
        "response should come from Praxis, not backend"
    );
}

#[test]
fn mcp_broker_example_serves_prefixed_catalog() {
    let weather_guard = start_backend_with_shutdown("weather");
    let calendar_guard = start_backend_with_shutdown("calendar");
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/mcp-static-catalog.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", weather_guard.port()),
            ("127.0.0.1:3002", calendar_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/mcp", r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
    );

    assert_eq!(parse_status(&raw), 200, "tools/list should return 200");
    let body = parse_body(&raw);
    assert!(
        body.contains("weather_get_weather"),
        "weather tool should include prefix: {body}"
    );
    assert!(
        body.contains("weather_forecast"),
        "weather forecast should include prefix: {body}"
    );
    assert!(
        body.contains("cal_create_event"),
        "calendar create tool should include prefix: {body}"
    );
    assert!(
        body.contains("cal_list_events"),
        "calendar list tool should include prefix: {body}"
    );
    assert!(
        body.contains(r#""city""#),
        "example inputSchema should be preserved: {body}"
    );
}

#[test]
fn mcp_broker_ping_returns_result() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = broker_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":5,"method":"ping"}"#;
    let request = json_post("/mcp", body);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200, "ping should return 200");
    let response_body = parse_body(&raw);
    assert!(
        response_body.contains(r#""result":{}"#),
        "ping should return empty result: {response_body}"
    );
    assert!(
        response_body.contains(r#""id":5"#),
        "ping should preserve numeric id: {response_body}"
    );
}

#[test]
fn mcp_broker_initialized_notification_returns_202() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = broker_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let request = json_post("/mcp", body);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 202, "notifications/initialized should return 202");
    assert_eq!(
        parse_body(&raw),
        "",
        "accepted notifications should not include a JSON-RPC response body"
    );
}

#[test]
fn mcp_broker_ping_with_null_id_rejected() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = broker_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#;
    let request = json_post("/mcp", body);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(
        parse_status(&raw),
        200,
        "null request ids should return JSON-RPC errors"
    );
    let response_body = parse_body(&raw);
    assert!(
        response_body.contains("-32600"),
        "null request ids should return invalid request: {response_body}"
    );
    assert!(
        response_body.contains(r#""id":null"#),
        "invalid id response should use null id: {response_body}"
    );
}

#[test]
fn mcp_broker_ping_with_missing_id_rejected() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = broker_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","method":"ping"}"#;
    let request = json_post("/mcp", body);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(
        parse_status(&raw),
        200,
        "request methods without ids should return JSON-RPC errors"
    );
    let response_body = parse_body(&raw);
    assert!(
        response_body.contains("-32600"),
        "missing request ids should return invalid request: {response_body}"
    );
}

#[test]
fn mcp_broker_unsupported_method_returns_method_not_found() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = broker_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":7,"method":"resources/list"}"#;
    let request = json_post("/mcp", body);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(
        parse_status(&raw),
        200,
        "unsupported method should return a JSON-RPC error response"
    );
    let response_body = parse_body(&raw);
    assert!(
        response_body.contains("-32601"),
        "unsupported method should return -32601: {response_body}"
    );
}

#[test]
fn mcp_broker_tools_call_not_forwarded_before_routing() {
    let backend_guard = start_backend_with_shutdown("not-reachable-backend");
    let proxy_port = free_port();

    let yaml = broker_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body =
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"weather_get_weather","arguments":{}}}"#;
    let request = json_post("/mcp", body);
    let raw = http_send(proxy.addr(), &request);

    let status = parse_status(&raw);
    let response_body = parse_body(&raw);

    assert_eq!(
        status, 200,
        "tools/call should return a JSON-RPC error response before backend routing is added"
    );
    assert!(
        response_body.contains("-32601"),
        "tools/call should return -32601 before backend routing is added: {response_body}"
    );
    assert!(
        !response_body.contains("not-reachable-backend"),
        "tools/call must not reach the backend before routing is added"
    );
}

#[test]
fn mcp_broker_delete_returns_controlled_response() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = broker_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "DELETE /mcp HTTP/1.1\r\n\
         Host: localhost\r\n\
         Mcp-Session-Id: mcp-test-session\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 204, "DELETE with session should return 204");
}

#[test]
fn mcp_broker_wrong_path_returns_404() {
    let backend_guard = start_backend_with_shutdown("backend");
    let proxy_port = free_port();

    let yaml = broker_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let request = json_post("/not-mcp", body);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 404, "POST to /not-mcp should return 404");
    assert!(
        !parse_body(&raw).contains("backend"),
        "wrong-path request must not reach backend"
    );
}

#[test]
fn mcp_broker_ping_with_query_param() {
    let backend_guard = start_backend_with_shutdown("not-reachable-backend");
    let proxy_port = free_port();

    let yaml = broker_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":9,"method":"ping"}"#;
    let request = json_post("/mcp?x=1", body);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(
        parse_status(&raw),
        200,
        "POST /mcp?x=1 should match configured MCP path"
    );
    let response_body = parse_body(&raw);
    assert!(
        response_body.contains(r#""result":{}"#),
        "ping should return empty result: {response_body}"
    );
    assert!(
        !response_body.contains("not-reachable-backend"),
        "query-param request must not reach backend"
    );
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn json_post(path: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len(),
    )
}

fn broker_yaml(proxy_port: u16, backend_port: u16) -> String {
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
        path: /mcp
        max_body_bytes: 65536
        servers:
          - name: weather
            cluster: weather-mcp
            path: /mcp
            tool_prefix: "weather_"
            tools:
              - name: get_weather
                description: Get current weather
          - name: calendar
            cluster: calendar-mcp
            path: /mcp
            tool_prefix: "cal_"
            tools:
              - name: create_event
                description: Create a calendar event
      - filter: load_balancer
        clusters:
          - name: weather-mcp
            endpoints:
              - "127.0.0.1:{backend_port}"
          - name: calendar-mcp
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    )
}
