// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for A2A classifier filter.

use std::io::{Read, Write};

use praxis_core::config::Config;
use praxis_test_utils::{
    Backend, free_port, http_send, parse_body, parse_status, start_backend_with_shutdown, start_header_echo_backend,
    start_proxy,
};

// -----------------------------------------------------------------------------
// Routing Tests
// -----------------------------------------------------------------------------

#[test]
fn a2a_send_message_routes_to_agent_backend() {
    let agent_guard = start_backend_with_shutdown("agent-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = a2a_routing_yaml(proxy_port, agent_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":"Hello","recipient":"agent1"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        "agent-backend",
        "SendMessage should route to agent backend"
    );
}

#[test]
fn a2a_streaming_message_routes_by_streaming_header() {
    let streaming_guard = start_backend_with_shutdown("streaming-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = a2a_streaming_routing_yaml(proxy_port, streaming_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"SendStreamingMessage","params":{"message":"Hello stream"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        "streaming-backend",
        "SendStreamingMessage should route to streaming backend via x-praxis-a2a-streaming: true"
    );
}

#[test]
fn a2a_streaming_message_sse_response_passes_through_unchanged() {
    let sse_body = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":\"working\"}}\n\n\
                    data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":\"completed\"}}\n\n";
    let sse_guard = Backend::fixed(sse_body)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .start_with_shutdown();
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = a2a_streaming_routing_yaml(proxy_port, sse_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"SendStreamingMessage","params":{"message":"Hello"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", body, &[]);

    let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut response = Vec::new();
    read_until_timeout(&mut stream, &mut response);
    let raw = String::from_utf8_lossy(&response);

    assert_eq!(parse_status(&raw), 200);

    assert!(
        raw.contains("text/event-stream"),
        "backend's text/event-stream content-type should reach client: {raw}"
    );

    let response_body = parse_body(&raw);
    assert_eq!(
        response_body, sse_body,
        "SSE response body should pass through unchanged"
    );
}

#[test]
fn a2a_get_task_routes_by_task_id() {
    let task_guard = start_backend_with_shutdown("task-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = a2a_task_routing_yaml(proxy_port, task_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"task-123"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        "task-backend",
        "GetTask with params.id=task-123 should route to task backend"
    );
}

#[test]
fn a2a_push_notification_config_routes_by_task_id() {
    let task_guard = start_backend_with_shutdown("task-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = a2a_task_routing_yaml(proxy_port, task_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"GetTaskPushNotificationConfig","params":{"taskId":"task-123"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        "task-backend",
        "push notification config methods should extract params.taskId for routing"
    );
}

#[test]
fn a2a_unknown_method_routes_to_default() {
    let agent_guard = start_backend_with_shutdown("agent-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = a2a_routing_yaml(proxy_port, agent_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"UnknownA2aMethod","params":{}}"#;
    let request = json_post_with_a2a_headers("/a2a/", body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "unknown valid JSON-RPC methods should route to static fallback"
    );
}

#[test]
fn a2a_alias_resolves_to_canonical_method() {
    let agent_guard = start_backend_with_shutdown("agent-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = a2a_alias_routing_yaml(proxy_port, agent_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":"Hello"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        "agent-backend",
        "message/send alias should resolve to SendMessage and route to agent backend"
    );
}

// -----------------------------------------------------------------------------
// Header Leak Tests
// -----------------------------------------------------------------------------

#[test]
fn a2a_internal_headers_not_leaked_upstream() {
    let header_echo_guard = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = a2a_header_leakage_yaml(proxy_port, header_echo_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":"Hello"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    let echoed = parse_body(&raw);
    let echoed_lower = echoed.to_lowercase();

    assert!(
        !echoed_lower.contains("x-praxis-a2a-"),
        "internal x-praxis-a2a-* headers should NOT reach backend: {echoed}"
    );
    assert!(
        !echoed_lower.contains("x-a2a-"),
        "internal x-a2a-* headers should NOT reach backend: {echoed}"
    );
}

// -----------------------------------------------------------------------------
// Compatibility Tests
// -----------------------------------------------------------------------------

#[test]
fn a2a_non_a2a_traffic_continues_with_on_invalid_continue() {
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = a2a_passthrough_yaml(proxy_port, default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"not":"a2a","request":"data"}"#;
    let request = json_post_with_a2a_headers("/a2a/", body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "non-A2A traffic should pass through with on_invalid: continue"
    );
}

// -----------------------------------------------------------------------------
// Batch Tests
// -----------------------------------------------------------------------------

#[test]
fn a2a_batch_input_returns_400() {
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = a2a_passthrough_yaml(proxy_port, default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"[{"jsonrpc":"2.0","id":1,"method":"SendMessage"}]"#;
    let request = json_post_with_a2a_headers("/a2a/", body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(
        parse_status(&raw),
        400,
        "batch input should return HTTP 400 even with on_invalid: continue"
    );
}

// -----------------------------------------------------------------------------
// Task Routing Tests
// -----------------------------------------------------------------------------

#[test]
fn a2a_task_route_capture_then_lookup() {
    let json_body = r#"{"jsonrpc":"2.0","id":1,"result":{"task":{"id":"task-123","contextId":"ctx-1","status":{"state":"TASK_STATE_WORKING"}}}}"#;
    let agent_a_guard = Backend::fixed(json_body)
        .header("content-type", "application/json")
        .start_with_shutdown();
    let agent_b_guard = start_backend_with_shutdown("agent-b");
    let proxy_port = free_port();

    let yaml = a2a_task_routing_enabled_yaml(proxy_port, agent_a_guard.port(), agent_b_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let send_body = r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":"Hello"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", send_body, &[]);
    let raw = http_send(proxy.addr(), &request);
    assert_eq!(parse_status(&raw), 200, "SendMessage should succeed");

    let get_body = r#"{"jsonrpc":"2.0","id":2,"method":"GetTask","params":{"id":"task-123"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", get_body, &[]);
    let raw = http_send(proxy.addr(), &request);
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        json_body,
        "GetTask should route to agent-a (which created the task), not fallback agent-b"
    );
}

#[test]
fn a2a_message_only_response_does_not_create_mapping() {
    let msg_body = r#"{"jsonrpc":"2.0","id":1,"result":{"message":{"messageId":"msg-1","role":"ROLE_AGENT","parts":[{"text":"done"}]}}}"#;
    let agent_a_guard = Backend::fixed(msg_body)
        .header("content-type", "application/json")
        .start_with_shutdown();
    let agent_b_guard = start_backend_with_shutdown("agent-b");
    let proxy_port = free_port();

    let yaml = a2a_task_routing_enabled_yaml(proxy_port, agent_a_guard.port(), agent_b_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let send_body = r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":"Hello"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", send_body, &[]);
    let raw = http_send(proxy.addr(), &request);
    assert_eq!(parse_status(&raw), 200, "SendMessage should succeed");

    let get_body = r#"{"jsonrpc":"2.0","id":2,"method":"GetTask","params":{"id":"task-123"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", get_body, &[]);
    let raw = http_send(proxy.addr(), &request);
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        "agent-b",
        "GetTask should follow fallback because message-only response did not create a mapping"
    );
}

#[test]
fn a2a_task_route_miss_continues() {
    let agent_a_guard = start_backend_with_shutdown("agent-a");
    let agent_b_guard = start_backend_with_shutdown("agent-b");
    let proxy_port = free_port();

    let yaml = a2a_task_routing_enabled_yaml(proxy_port, agent_a_guard.port(), agent_b_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let get_body = r#"{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"unknown-task"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", get_body, &[]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    assert_eq!(parse_body(&raw), "agent-b", "unknown task should follow fallback route");
}

#[test]
fn a2a_internal_route_header_cannot_be_spoofed() {
    let agent_a_guard = start_backend_with_shutdown("agent-a");
    let agent_b_guard = start_backend_with_shutdown("agent-b");
    let proxy_port = free_port();

    let yaml = a2a_task_routing_enabled_yaml(proxy_port, agent_a_guard.port(), agent_b_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let get_body = r#"{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"no-mapping"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", get_body, &[("x-praxis-a2a-route-cluster", "agent-a")]);
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(
        parse_status(&raw),
        400,
        "client-supplied reserved internal headers should be rejected before reaching the filter pipeline"
    );
}

#[test]
fn a2a_task_route_captured_from_direct_result_shape() {
    let json_body =
        r#"{"jsonrpc":"2.0","id":1,"result":{"id":"task-direct-1","status":{"state":"TASK_STATE_WORKING"}}}"#;
    let agent_a_guard = Backend::fixed(json_body)
        .header("content-type", "application/json")
        .start_with_shutdown();
    let agent_b_guard = start_backend_with_shutdown("agent-b");
    let proxy_port = free_port();

    let yaml = a2a_task_routing_enabled_yaml(proxy_port, agent_a_guard.port(), agent_b_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let send_body = r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":"Hello"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", send_body, &[]);
    let raw = http_send(proxy.addr(), &request);
    assert_eq!(parse_status(&raw), 200, "SendMessage should succeed");
    assert_eq!(
        parse_body(&raw),
        json_body,
        "SendMessage response should come from agent-a"
    );

    let get_body = r#"{"jsonrpc":"2.0","id":2,"method":"GetTask","params":{"id":"task-direct-1"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", get_body, &[]);
    let raw = http_send(proxy.addr(), &request);
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        json_body,
        "direct result.id shape should also capture task route"
    );
}

#[test]
fn a2a_sse_response_unchanged_with_task_routing_enabled() {
    let sse_body = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":\"working\"}}\n\n\
                    data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":\"completed\"}}\n\n";
    let sse_guard = Backend::fixed(sse_body)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .start_with_shutdown();
    let default_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();

    let yaml = a2a_task_routing_sse_yaml(proxy_port, sse_guard.port(), default_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"SendStreamingMessage","params":{"message":"Hello"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", body, &[]);

    let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut response = Vec::new();
    read_until_timeout(&mut stream, &mut response);
    let raw = String::from_utf8_lossy(&response);

    assert_eq!(parse_status(&raw), 200);
    assert!(
        raw.contains("text/event-stream"),
        "SSE content-type should reach client with task routing enabled: {raw}"
    );

    let response_body = parse_body(&raw);
    assert_eq!(
        response_body, sse_body,
        "SSE response body should pass through unchanged with task routing enabled"
    );
}

// -----------------------------------------------------------------------------
// SSE Streaming Task Routing Tests
// -----------------------------------------------------------------------------

#[test]
fn a2a_streaming_task_route_capture_then_lookup() {
    let sse_body = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"task\":{\"id\":\"task-stream-1\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\n\n";
    let sse_guard = Backend::fixed(sse_body)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .start_with_shutdown();
    let agent_b_guard = start_backend_with_shutdown("agent-b");
    let proxy_port = free_port();

    let yaml = a2a_streaming_task_routing_yaml(proxy_port, sse_guard.port(), agent_b_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let send_body = r#"{"jsonrpc":"2.0","id":1,"method":"SendStreamingMessage","params":{"message":"Hello"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", send_body, &[]);

    let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut response = Vec::new();
    read_until_timeout(&mut stream, &mut response);
    let raw = String::from_utf8_lossy(&response);

    assert_eq!(parse_status(&raw), 200, "SendStreamingMessage should succeed");
    assert!(
        raw.contains("text/event-stream"),
        "SSE content-type should reach client"
    );

    let response_body = parse_body(&raw);
    assert_eq!(
        response_body, sse_body,
        "SSE response body should pass through unchanged"
    );

    let get_body = r#"{"jsonrpc":"2.0","id":2,"method":"GetTask","params":{"id":"task-stream-1"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", get_body, &[]);
    let raw = http_send(&format!("127.0.0.1:{proxy_port}"), &request);
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        sse_body,
        "GetTask should route to agent-a (which created the streamed task), not fallback agent-b"
    );
}

#[test]
fn a2a_streaming_multi_event_sse_captures_task_route() {
    let sse_body = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"task\":{\"id\":\"task-multi-evt\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\n\n\
                    data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"statusUpdate\":{\"taskId\":\"task-multi-evt\",\"status\":{\"state\":\"TASK_STATE_COMPLETED\"}}}}\n\n";
    let sse_guard = Backend::fixed(sse_body)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .start_with_shutdown();
    let agent_b_guard = start_backend_with_shutdown("agent-b");
    let proxy_port = free_port();

    let yaml = a2a_streaming_task_routing_yaml(proxy_port, sse_guard.port(), agent_b_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let send_body = r#"{"jsonrpc":"2.0","id":1,"method":"SendStreamingMessage","params":{"message":"Hello"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", send_body, &[]);

    let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut response = Vec::new();
    read_until_timeout(&mut stream, &mut response);
    let raw = String::from_utf8_lossy(&response);
    assert_eq!(parse_status(&raw), 200, "multi-event SSE should succeed");

    let response_body = parse_body(&raw);
    assert_eq!(
        response_body, sse_body,
        "multi-event SSE body should pass through unchanged"
    );

    let get_body = r#"{"jsonrpc":"2.0","id":2,"method":"GetTask","params":{"id":"task-multi-evt"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", get_body, &[]);
    let raw = http_send(&format!("127.0.0.1:{proxy_port}"), &request);
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        sse_body,
        "GetTask should route to agent-a (which created the streamed task), not fallback agent-b"
    );
}

#[test]
fn a2a_streaming_malformed_sse_does_not_create_mapping() {
    let sse_body = "data: not valid json\n\n";
    let sse_guard = Backend::fixed(sse_body)
        .header("content-type", "text/event-stream")
        .start_with_shutdown();
    let agent_b_guard = start_backend_with_shutdown("agent-b");
    let proxy_port = free_port();

    let yaml = a2a_streaming_task_routing_yaml(proxy_port, sse_guard.port(), agent_b_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let send_body = r#"{"jsonrpc":"2.0","id":1,"method":"SendStreamingMessage","params":{"message":"Hello"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", send_body, &[]);

    let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut response = Vec::new();
    read_until_timeout(&mut stream, &mut response);
    let raw = String::from_utf8_lossy(&response);
    assert_eq!(parse_status(&raw), 200, "malformed SSE should still pass through");

    let response_body = parse_body(&raw);
    assert_eq!(
        response_body, sse_body,
        "malformed SSE body should pass through unchanged"
    );

    let get_body = r#"{"jsonrpc":"2.0","id":2,"method":"GetTask","params":{"id":"nonexistent-task"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", get_body, &[]);
    let raw = http_send(&format!("127.0.0.1:{proxy_port}"), &request);
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        "agent-b",
        "no mapping should exist from malformed SSE, so GetTask follows fallback"
    );
}

#[test]
fn a2a_non_streaming_task_routing_unchanged_with_sse_capture() {
    let json_body = r#"{"jsonrpc":"2.0","id":1,"result":{"task":{"id":"task-json-1","contextId":"ctx-1","status":{"state":"TASK_STATE_WORKING"}}}}"#;
    let agent_a_guard = Backend::fixed(json_body)
        .header("content-type", "application/json")
        .start_with_shutdown();
    let agent_b_guard = start_backend_with_shutdown("agent-b");
    let proxy_port = free_port();

    let yaml = a2a_streaming_task_routing_yaml(proxy_port, agent_a_guard.port(), agent_b_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let send_body = r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":"Hello"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", send_body, &[]);
    let raw = http_send(proxy.addr(), &request);
    assert_eq!(parse_status(&raw), 200, "SendMessage should succeed");

    let get_body = r#"{"jsonrpc":"2.0","id":2,"method":"GetTask","params":{"id":"task-json-1"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", get_body, &[]);
    let raw = http_send(proxy.addr(), &request);
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        json_body,
        "non-streaming SendMessage task routing should still work unchanged"
    );
}

#[test]
fn a2a_streaming_status_update_only_captures_task_route() {
    let sse_body = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"statusUpdate\":{\"taskId\":\"task-su-only\",\"contextId\":\"ctx-1\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\n\n\
                    data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"artifactUpdate\":{\"taskId\":\"task-su-only\",\"contextId\":\"ctx-1\",\"artifact\":{\"artifactId\":\"a1\",\"parts\":[{\"text\":\"output\"}]}}}}\n\n\
                    data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"statusUpdate\":{\"taskId\":\"task-su-only\",\"contextId\":\"ctx-1\",\"status\":{\"state\":\"TASK_STATE_COMPLETED\"}}}}\n\n";
    let sse_guard = Backend::fixed(sse_body)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .start_with_shutdown();
    let agent_b_guard = start_backend_with_shutdown("agent-b");
    let proxy_port = free_port();

    let yaml = a2a_streaming_task_routing_yaml(proxy_port, sse_guard.port(), agent_b_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let send_body = r#"{"jsonrpc":"2.0","id":1,"method":"SendStreamingMessage","params":{"message":"Hello"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", send_body, &[]);

    let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut response = Vec::new();
    read_until_timeout(&mut stream, &mut response);
    let raw = String::from_utf8_lossy(&response);
    assert_eq!(parse_status(&raw), 200, "statusUpdate-only SSE should succeed");

    let response_body = parse_body(&raw);
    assert_eq!(
        response_body, sse_body,
        "statusUpdate-only SSE body should pass through unchanged"
    );

    let get_body = r#"{"jsonrpc":"2.0","id":2,"method":"GetTask","params":{"id":"task-su-only"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", get_body, &[]);
    let raw = http_send(&format!("127.0.0.1:{proxy_port}"), &request);
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        sse_body,
        "GetTask should route to agent-a (statusUpdate-only events captured task route)"
    );
}

#[test]
fn a2a_subscribe_to_task_sse_captures_task_route() {
    let sse_body = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"statusUpdate\":{\"taskId\":\"task-sub-e2e\",\"contextId\":\"ctx-1\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\n\n";
    let sse_guard = Backend::fixed(sse_body)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .start_with_shutdown();
    let agent_b_guard = start_backend_with_shutdown("agent-b");
    let proxy_port = free_port();

    let yaml = a2a_streaming_task_routing_yaml(proxy_port, sse_guard.port(), agent_b_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let send_body = r#"{"jsonrpc":"2.0","id":1,"method":"SubscribeToTask","params":{"id":"task-sub-e2e"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", send_body, &[]);

    let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut response = Vec::new();
    read_until_timeout(&mut stream, &mut response);
    let raw = String::from_utf8_lossy(&response);
    assert_eq!(parse_status(&raw), 200, "SubscribeToTask SSE should succeed");

    let get_body = r#"{"jsonrpc":"2.0","id":2,"method":"GetTask","params":{"id":"task-sub-e2e"}}"#;
    let request = json_post_with_a2a_headers("/a2a/", get_body, &[]);
    let raw = http_send(&format!("127.0.0.1:{proxy_port}"), &request);
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        sse_body,
        "GetTask should route to agent-a after SubscribeToTask SSE captured the task route"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn json_post_with_a2a_headers(path: &str, body: &str, headers: &[(&str, &str)]) -> String {
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

/// SSE backends close the connection after sending all data, but the
/// proxy may keep it open until the read timeout fires. `WouldBlock`
/// is expected; other I/O errors are real failures.
fn read_until_timeout(stream: &mut std::net::TcpStream, buf: &mut Vec<u8>) {
    match stream.read_to_end(buf) {
        Ok(_) => {},
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {},
        Err(e) => panic!("unexpected read error: {e}"),
    }
}

fn a2a_routing_yaml(proxy_port: u16, agent_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: a2a
        max_body_bytes: 65536
        on_invalid: continue
        headers:
          method: x-praxis-a2a-method
          family: x-praxis-a2a-family
          task_id: x-praxis-a2a-task-id
          streaming: x-praxis-a2a-streaming
      - filter: router
        routes:
          - path_prefix: "/a2a/"
            headers:
              x-praxis-a2a-method: "SendMessage"
            cluster: "agent"
          - path_prefix: "/a2a/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "agent"
            endpoints:
              - "127.0.0.1:{agent_port}"
          - name: "default"
            endpoints:
              - "127.0.0.1:{default_port}"
"#,
    )
}

fn a2a_streaming_routing_yaml(proxy_port: u16, streaming_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: a2a
        max_body_bytes: 65536
        on_invalid: continue
        headers:
          streaming: x-praxis-a2a-streaming
      - filter: router
        routes:
          - path_prefix: "/a2a/"
            headers:
              x-praxis-a2a-streaming: "true"
            cluster: "streaming"
          - path_prefix: "/a2a/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "streaming"
            endpoints:
              - "127.0.0.1:{streaming_port}"
          - name: "default"
            endpoints:
              - "127.0.0.1:{default_port}"
"#,
    )
}

fn a2a_task_routing_yaml(proxy_port: u16, task_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: a2a
        max_body_bytes: 65536
        on_invalid: continue
        headers:
          method: x-praxis-a2a-method
          task_id: x-praxis-a2a-task-id
      - filter: router
        routes:
          - path_prefix: "/a2a/"
            headers:
              x-praxis-a2a-task-id: "task-123"
            cluster: "task"
          - path_prefix: "/a2a/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "task"
            endpoints:
              - "127.0.0.1:{task_port}"
          - name: "default"
            endpoints:
              - "127.0.0.1:{default_port}"
"#,
    )
}

fn a2a_alias_routing_yaml(proxy_port: u16, agent_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: a2a
        max_body_bytes: 65536
        on_invalid: continue
        method_aliases:
          message/send: SendMessage
        headers:
          method: x-praxis-a2a-method
      - filter: router
        routes:
          - path_prefix: "/a2a/"
            headers:
              x-praxis-a2a-method: "SendMessage"
            cluster: "agent"
          - path_prefix: "/a2a/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "agent"
            endpoints:
              - "127.0.0.1:{agent_port}"
          - name: "default"
            endpoints:
              - "127.0.0.1:{default_port}"
"#,
    )
}

fn a2a_header_leakage_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: a2a
        max_body_bytes: 65536
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

fn a2a_task_routing_enabled_yaml(proxy_port: u16, agent_a_port: u16, agent_b_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: a2a
        max_body_bytes: 65536
        on_invalid: continue
        headers:
          method: x-praxis-a2a-method
          task_id: x-praxis-a2a-task-id
        task_routing:
          enabled: true
          route_cluster_header: x-praxis-a2a-route-cluster
      - filter: router
        routes:
          - path_prefix: "/a2a/"
            headers:
              x-praxis-a2a-route-cluster: "agent-a"
            cluster: "agent-a"
          - path_prefix: "/a2a/"
            headers:
              x-praxis-a2a-route-cluster: "agent-b"
            cluster: "agent-b"
          - path_prefix: "/a2a/"
            headers:
              x-praxis-a2a-method: "SendMessage"
            cluster: "agent-a"
          - path_prefix: "/a2a/"
            cluster: "agent-b"
      - filter: load_balancer
        clusters:
          - name: "agent-a"
            endpoints:
              - "127.0.0.1:{agent_a_port}"
          - name: "agent-b"
            endpoints:
              - "127.0.0.1:{agent_b_port}"
"#,
    )
}

fn a2a_task_routing_sse_yaml(proxy_port: u16, streaming_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: a2a
        max_body_bytes: 65536
        on_invalid: continue
        headers:
          method: x-praxis-a2a-method
          streaming: x-praxis-a2a-streaming
        task_routing:
          enabled: true
      - filter: router
        routes:
          - path_prefix: "/a2a/"
            headers:
              x-praxis-a2a-streaming: "true"
            cluster: "streaming"
          - path_prefix: "/a2a/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "streaming"
            endpoints:
              - "127.0.0.1:{streaming_port}"
          - name: "default"
            endpoints:
              - "127.0.0.1:{default_port}"
"#,
    )
}

fn a2a_streaming_task_routing_yaml(proxy_port: u16, agent_a_port: u16, agent_b_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: a2a
        max_body_bytes: 65536
        on_invalid: continue
        headers:
          method: x-praxis-a2a-method
          task_id: x-praxis-a2a-task-id
          streaming: x-praxis-a2a-streaming
        task_routing:
          enabled: true
          route_cluster_header: x-praxis-a2a-route-cluster
      - filter: router
        routes:
          - path_prefix: "/a2a/"
            headers:
              x-praxis-a2a-route-cluster: "agent-a"
            cluster: "agent-a"
          - path_prefix: "/a2a/"
            headers:
              x-praxis-a2a-route-cluster: "agent-b"
            cluster: "agent-b"
          - path_prefix: "/a2a/"
            headers:
              x-praxis-a2a-method: "SendMessage"
            cluster: "agent-a"
          - path_prefix: "/a2a/"
            headers:
              x-praxis-a2a-streaming: "true"
            cluster: "agent-a"
          - path_prefix: "/a2a/"
            cluster: "agent-b"
      - filter: load_balancer
        clusters:
          - name: "agent-a"
            endpoints:
              - "127.0.0.1:{agent_a_port}"
          - name: "agent-b"
            endpoints:
              - "127.0.0.1:{agent_b_port}"
"#,
    )
}

fn a2a_passthrough_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: a2a
        max_body_bytes: 65536
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
