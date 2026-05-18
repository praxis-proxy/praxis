// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Integration tests for payload-processing example configurations.

use std::collections::HashMap;

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_send, json_post, load_example_config, parse_body, parse_status, patch_yaml,
    start_backend_with_shutdown, start_header_echo_backend_with_shutdown, start_proxy, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn ai_inference_body_based_routing_matches_model() {
    let mistral_port_guard = start_backend_with_shutdown("mistral-response");
    let mistral_port = mistral_port_guard.port();
    let granite_port_guard = start_backend_with_shutdown("granite-response");
    let granite_port = granite_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-response");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/ai-inference-body-based-routing.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", mistral_port),
            ("10.0.1.2:8080", mistral_port),
            ("10.0.2.1:8080", granite_port),
            ("10.0.2.2:8080", granite_port),
            ("10.0.3.1:8080", default_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post(
            "/v1/chat/completions",
            r#"{"model":"mistral-7b-instruct","messages":[]}"#,
        ),
    );
    assert_eq!(parse_status(&raw), 200, "mistral model should return 200");
    assert_eq!(
        parse_body(&raw),
        "mistral-response",
        "model=mistral-7b-instruct should route to mistral cluster"
    );
}

#[test]
fn ai_inference_body_based_routing_falls_through_to_default() {
    let mistral_port_guard = start_backend_with_shutdown("mistral-response");
    let mistral_port = mistral_port_guard.port();
    let granite_port_guard = start_backend_with_shutdown("granite-response");
    let granite_port = granite_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-response");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/ai-inference-body-based-routing.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", mistral_port),
            ("10.0.1.2:8080", mistral_port),
            ("10.0.2.1:8080", granite_port),
            ("10.0.2.2:8080", granite_port),
            ("10.0.3.1:8080", default_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/chat/completions", r#"{"model":"unknown-model","messages":[]}"#),
    );
    assert_eq!(parse_status(&raw), 200, "unknown model should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-response",
        "unknown model should fall through to default cluster"
    );
}

#[test]
fn multi_field_extraction_extracts_both_fields() {
    let backend_guard = start_header_echo_backend_with_shutdown();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/multi-field-extraction.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", backend_port),
            ("10.0.1.2:8080", backend_port),
            ("10.0.2.1:8080", backend_port),
            ("10.0.3.1:8080", backend_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post(
            "/v1/chat/completions",
            r#"{"model":"claude-sonnet-4-5","user_id":"u-42"}"#,
        ),
    );
    assert_eq!(parse_status(&raw), 200, "multi-field extraction should return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-model: claude-sonnet-4-5"),
        "expected X-Model header echoed by backend, got:\n{body}"
    );
    assert!(
        lower.contains("x-user-id: u-42"),
        "expected X-User-Id header echoed by backend, got:\n{body}"
    );
}

#[test]
fn multi_field_extraction_routes_by_model() {
    let claude_port_guard = start_backend_with_shutdown("claude-backend");
    let claude_port = claude_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/multi-field-extraction.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", claude_port),
            ("10.0.1.2:8080", claude_port),
            ("10.0.2.1:8080", default_port),
            ("10.0.3.1:8080", default_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post(
            "/v1/chat/completions",
            r#"{"model":"claude-sonnet-4-5","user_id":"u-42"}"#,
        ),
    );
    assert_eq!(parse_status(&raw), 200, "claude model routing should return 200");
    assert_eq!(
        parse_body(&raw),
        "claude-backend",
        "model=claude-sonnet-4-5 should route to claude_sonnet cluster"
    );
}

#[test]
fn conditional_field_extraction_fires_on_v1_path() {
    let backend_guard = start_header_echo_backend_with_shutdown();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/conditional-field-extraction.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", backend_port),
            ("10.0.2.1:8080", backend_port),
            ("10.0.3.1:8080", backend_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post(
            "/v1/chat/completions",
            r#"{"model":"mistral-large-latest","messages":[]}"#,
        ),
    );
    assert_eq!(parse_status(&raw), 200, "v1 path extraction should return 200");
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-model: mistral-large-latest"),
        "X-Model should be extracted on /v1/ path, got:\n{body}"
    );
}

#[test]
fn conditional_field_extraction_skips_on_non_v1_path() {
    let backend_guard = start_header_echo_backend_with_shutdown();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/conditional-field-extraction.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", backend_port),
            ("10.0.2.1:8080", backend_port),
            ("10.0.3.1:8080", backend_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/healthz", r#"{"model":"mistral-large-latest","messages":[]}"#),
    );
    assert_eq!(parse_status(&raw), 200, "non-v1 path should return 200");
    let body = parse_body(&raw);
    assert!(
        !body.to_lowercase().contains("x-model"),
        "X-Model should NOT be extracted on non-/v1/ path, got:\n{body}"
    );
}

#[test]
fn field_extraction_access_control_routes_acme() {
    let acme_port_guard = start_backend_with_shutdown("acme-backend");
    let acme_port = acme_port_guard.port();
    let globex_port_guard = start_backend_with_shutdown("globex-backend");
    let globex_port = globex_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/field-extraction-access-control.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", acme_port),
            ("10.0.1.2:8080", acme_port),
            ("10.0.2.1:8080", globex_port),
            ("10.0.3.1:8080", default_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/api/data", r#"{"tenant_id":"acme","query":"SELECT *"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "acme tenant should return 200");
    assert_eq!(
        parse_body(&raw),
        "acme-backend",
        "tenant_id=acme should route to acme cluster"
    );
}

#[test]
fn field_extraction_access_control_routes_globex() {
    let acme_port_guard = start_backend_with_shutdown("acme-backend");
    let acme_port = acme_port_guard.port();
    let globex_port_guard = start_backend_with_shutdown("globex-backend");
    let globex_port = globex_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/field-extraction-access-control.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", acme_port),
            ("10.0.1.2:8080", acme_port),
            ("10.0.2.1:8080", globex_port),
            ("10.0.3.1:8080", default_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/api/data", r#"{"tenant_id":"globex","query":"SELECT *"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "globex tenant should return 200");
    assert_eq!(
        parse_body(&raw),
        "globex-backend",
        "tenant_id=globex should route to globex cluster"
    );
}

#[test]
fn field_extraction_access_control_unknown_tenant_to_default() {
    let acme_port_guard = start_backend_with_shutdown("acme-backend");
    let acme_port = acme_port_guard.port();
    let globex_port_guard = start_backend_with_shutdown("globex-backend");
    let globex_port = globex_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/field-extraction-access-control.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", acme_port),
            ("10.0.1.2:8080", acme_port),
            ("10.0.2.1:8080", globex_port),
            ("10.0.3.1:8080", default_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/api/data", r#"{"tenant_id":"unknown","query":"SELECT *"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "unknown tenant should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "unknown tenant should route to default cluster"
    );
}

#[test]
fn body_size_limit_allows_small_body() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/body-size-limit-with-extraction.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/chat", r#"{"model":"claude-sonnet-4-5","prompt":"hello"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "small body under 1024 limit should return 200");
}

#[test]
fn body_size_limit_rejects_oversized_body() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/body-size-limit-with-extraction.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let large_body = format!(r#"{{"model":"claude-sonnet-4-5","prompt":"{}"}}"#, "x".repeat(2000));
    let raw = http_send(proxy.addr(), &json_post("/v1/chat", &large_body));
    assert_eq!(parse_status(&raw), 413, "oversized body should be rejected with 413");
}

#[test]
fn multi_listener_body_pipeline_passthrough() {
    let default_port_guard = start_backend_with_shutdown("passthrough-ok");
    let default_port = default_port_guard.port();
    let claude_port_guard = start_backend_with_shutdown("claude-response");
    let claude_port = claude_port_guard.port();
    let proxy_passthrough = free_port();
    let proxy_streambuf = free_port();
    let proxy_buffered = free_port();

    let path = praxis_test_utils::example_config_path("payload-processing/multi-listener-body-pipeline.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let patched = patch_yaml(&yaml, proxy_streambuf, &HashMap::new());
    let patched = patched
        .replace("0.0.0.0:8081", &format!("127.0.0.1:{proxy_buffered}"))
        .replace("0.0.0.0:8082", &format!("127.0.0.1:{proxy_passthrough}"))
        .replace("127.0.0.1:3000", &format!("127.0.0.1:{default_port}"))
        .replace("127.0.0.1:3001", &format!("127.0.0.1:{claude_port}"));
    let config = Config::from_yaml(&patched).unwrap();

    let _proxy = start_proxy(&config);
    let passthrough_addr = format!("127.0.0.1:{proxy_passthrough}");
    wait_for_tcp(&passthrough_addr);

    let (status, body) = http_get(&passthrough_addr, "/anything", None);
    assert_eq!(status, 200, "passthrough listener should return 200");
    assert_eq!(
        body, "passthrough-ok",
        "passthrough listener should route to default backend"
    );
}

#[test]
fn multi_listener_body_pipeline_stream_buffer_routes() {
    let default_port_guard = start_backend_with_shutdown("default-response");
    let default_port = default_port_guard.port();
    let claude_port_guard = start_backend_with_shutdown("claude-response");
    let claude_port = claude_port_guard.port();
    let proxy_streambuf = free_port();
    let proxy_buffered = free_port();
    let proxy_passthrough = free_port();

    let path = praxis_test_utils::example_config_path("payload-processing/multi-listener-body-pipeline.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let patched = patch_yaml(&yaml, proxy_streambuf, &HashMap::new());
    let patched = patched
        .replace("0.0.0.0:8081", &format!("127.0.0.1:{proxy_buffered}"))
        .replace("0.0.0.0:8082", &format!("127.0.0.1:{proxy_passthrough}"))
        .replace("127.0.0.1:3000", &format!("127.0.0.1:{default_port}"))
        .replace("127.0.0.1:3001", &format!("127.0.0.1:{claude_port}"));
    let config = Config::from_yaml(&patched).unwrap();

    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/chat", r#"{"model":"claude-sonnet-4-5","user_id":"u-1"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "stream-buffer listener should return 200");
    assert_eq!(
        parse_body(&raw),
        "claude-response",
        "model=claude-sonnet-4-5 should route to claude_sonnet cluster on stream-buffer listener"
    );
}

#[test]
fn json_rpc_routing_routes_mcp_tools() {
    let mcp_tools_guard = start_backend_with_shutdown("mcp-tools-response");
    let mcp_tools_port = mcp_tools_guard.port();
    let mcp_discovery_guard = start_backend_with_shutdown("mcp-discovery-response");
    let mcp_discovery_port = mcp_discovery_guard.port();
    let a2a_send_guard = start_backend_with_shutdown("a2a-send-response");
    let a2a_send_port = a2a_send_guard.port();
    let a2a_tasks_guard = start_backend_with_shutdown("a2a-tasks-response");
    let a2a_tasks_port = a2a_tasks_guard.port();
    let default_guard = start_backend_with_shutdown("default-response");
    let default_port = default_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/json-rpc-routing.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:9001", mcp_tools_port),
            ("127.0.0.1:9002", mcp_tools_port),
            ("127.0.0.1:9101", mcp_discovery_port),
            ("127.0.0.1:9201", a2a_send_port),
            ("127.0.0.1:9202", a2a_send_port),
            ("127.0.0.1:9301", a2a_tasks_port),
            ("127.0.0.1:9000", default_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post(
            "/mcp/",
            r#"{"jsonrpc":"2.0","id":"req-1","method":"tools/call","params":{"name":"calculator"}}"#,
        ),
    );
    assert_eq!(parse_status(&raw), 200, "MCP tools/call should return 200");
    assert_eq!(
        parse_body(&raw),
        "mcp-tools-response",
        "JSON-RPC method=tools/call should route to mcp-tools cluster"
    );
}

#[test]
fn json_rpc_routing_routes_a2a_send() {
    let mcp_tools_guard = start_backend_with_shutdown("mcp-tools-response");
    let mcp_tools_port = mcp_tools_guard.port();
    let mcp_discovery_guard = start_backend_with_shutdown("mcp-discovery-response");
    let mcp_discovery_port = mcp_discovery_guard.port();
    let a2a_send_guard = start_backend_with_shutdown("a2a-send-response");
    let a2a_send_port = a2a_send_guard.port();
    let a2a_tasks_guard = start_backend_with_shutdown("a2a-tasks-response");
    let a2a_tasks_port = a2a_tasks_guard.port();
    let default_guard = start_backend_with_shutdown("default-response");
    let default_port = default_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/json-rpc-routing.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:9001", mcp_tools_port),
            ("127.0.0.1:9002", mcp_tools_port),
            ("127.0.0.1:9101", mcp_discovery_port),
            ("127.0.0.1:9201", a2a_send_port),
            ("127.0.0.1:9202", a2a_send_port),
            ("127.0.0.1:9301", a2a_tasks_port),
            ("127.0.0.1:9000", default_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post(
            "/a2a/",
            r#"{"jsonrpc":"2.0","id":"msg-123","method":"SendMessage","params":{"recipient":"agent-42"}}"#,
        ),
    );
    assert_eq!(parse_status(&raw), 200, "A2A SendMessage should return 200");
    assert_eq!(
        parse_body(&raw),
        "a2a-send-response",
        "JSON-RPC method=SendMessage should route to a2a-send cluster"
    );
}

#[test]
fn json_rpc_routing_falls_through_to_default() {
    let mcp_tools_guard = start_backend_with_shutdown("mcp-tools-response");
    let mcp_tools_port = mcp_tools_guard.port();
    let mcp_discovery_guard = start_backend_with_shutdown("mcp-discovery-response");
    let mcp_discovery_port = mcp_discovery_guard.port();
    let a2a_send_guard = start_backend_with_shutdown("a2a-send-response");
    let a2a_send_port = a2a_send_guard.port();
    let a2a_tasks_guard = start_backend_with_shutdown("a2a-tasks-response");
    let a2a_tasks_port = a2a_tasks_guard.port();
    let default_guard = start_backend_with_shutdown("default-response");
    let default_port = default_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/json-rpc-routing.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:9001", mcp_tools_port),
            ("127.0.0.1:9002", mcp_tools_port),
            ("127.0.0.1:9101", mcp_discovery_port),
            ("127.0.0.1:9201", a2a_send_port),
            ("127.0.0.1:9202", a2a_send_port),
            ("127.0.0.1:9301", a2a_tasks_port),
            ("127.0.0.1:9000", default_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post(
            "/unknown/",
            r#"{"jsonrpc":"2.0","id":"unknown-1","method":"UnknownMethod"}"#,
        ),
    );
    assert_eq!(parse_status(&raw), 200, "unknown method should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-response",
        "unknown method should route to default cluster"
    );
}

#[test]
fn mcp_classifier_routing_routes_by_tool_name() {
    let weather_guard = start_backend_with_shutdown("weather-response");
    let weather_port = weather_guard.port();
    let calendar_guard = start_backend_with_shutdown("calendar-response");
    let calendar_port = calendar_guard.port();
    let default_guard = start_backend_with_shutdown("default-response");
    let default_port = default_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/mcp-classifier-routing.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:9001", weather_port),
            ("127.0.0.1:9002", calendar_port),
            ("127.0.0.1:9003", default_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &mcp_json_post(
            "/",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather"}}"#,
            &[("Mcp-Method", "tools/call"), ("Mcp-Name", "get_weather")],
        ),
    );
    assert_eq!(parse_status(&raw), 200, "tools/call get_weather should return 200");
    assert_eq!(
        parse_body(&raw),
        "weather-response",
        "tools/call with name=get_weather should route to weather-tools cluster"
    );
}

#[test]
fn mcp_classifier_routing_default_fallback() {
    let weather_guard = start_backend_with_shutdown("weather-response");
    let weather_port = weather_guard.port();
    let calendar_guard = start_backend_with_shutdown("calendar-response");
    let calendar_port = calendar_guard.port();
    let default_guard = start_backend_with_shutdown("default-response");
    let default_port = default_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/mcp-classifier-routing.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:9001", weather_port),
            ("127.0.0.1:9002", calendar_port),
            ("127.0.0.1:9003", default_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &mcp_json_post(
            "/",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            &[("Mcp-Method", "tools/list")],
        ),
    );
    assert_eq!(parse_status(&raw), 200, "tools/list should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-response",
        "tools/list should route to default-mcp cluster"
    );
}

#[test]
fn mcp_classifier_routing_routes_calendar_without_client_mcp_headers() {
    let weather_guard = start_backend_with_shutdown("weather-response");
    let weather_port = weather_guard.port();
    let calendar_guard = start_backend_with_shutdown("calendar-response");
    let calendar_port = calendar_guard.port();
    let default_guard = start_backend_with_shutdown("default-response");
    let default_port = default_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/mcp-classifier-routing.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:9001", weather_port),
            ("127.0.0.1:9002", calendar_port),
            ("127.0.0.1:9003", default_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &mcp_json_post(
            "/",
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_calendar"}}"#,
            &[],
        ),
    );
    assert_eq!(parse_status(&raw), 200, "tools/call get_calendar should return 200");
    assert_eq!(
        parse_body(&raw),
        "calendar-response",
        "tools/call with name=get_calendar should route to calendar-tools cluster without client Mcp-* headers"
    );
}

fn mcp_json_post(path: &str, body: &str, headers: &[(&str, &str)]) -> String {
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
