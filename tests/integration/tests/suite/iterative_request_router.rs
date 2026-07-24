// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the `iterative_request_router` filter.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_post, http_send, json_post, parse_status, start_backend, start_backend_with_shutdown,
    start_echo_backend, start_full_proxy, start_header_echo_backend, start_stateful_backend,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn single_step_done() {
    let backend_port = start_backend("hello");
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: primary
steps:
  - name: primary
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:{backend_port}"]
    on_result:
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "single step done should return 200");
    assert_eq!(body, "hello", "response body should be 'hello'");
}

#[test]
fn provider_failover_5xx() {
    let primary = start_stateful_backend(vec![(503, "service-unavailable".to_owned())]);
    let fallback = start_backend_with_shutdown("fallback-ok");
    let primary_port = primary.port();
    let fallback_port = fallback.port();

    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: primary
steps:
  - name: primary
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: p
      - filter: load_balancer
        clusters:
          - name: p
            endpoints: ["127.0.0.1:{primary_port}"]
    on_result:
      - status: [502, 503, 504]
        next: fallback
      - default: true
        done: true
  - name: fallback
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: f
      - filter: load_balancer
        clusters:
          - name: f
            endpoints: ["127.0.0.1:{fallback_port}"]
    on_result:
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "failover should return 200 from fallback");
    assert_eq!(body, "fallback-ok", "should get fallback response");
}

#[test]
fn provider_failover_primary_succeeds() {
    let primary = start_backend_with_shutdown("primary-ok");
    let fallback = start_backend_with_shutdown("fallback-ok");
    let primary_port = primary.port();
    let fallback_port = fallback.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: primary
steps:
  - name: primary
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: p
      - filter: load_balancer
        clusters:
          - name: p
            endpoints: ["127.0.0.1:{primary_port}"]
    on_result:
      - status: [502, 503, 504]
        next: fallback
      - default: true
        done: true
  - name: fallback
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: f
      - filter: load_balancer
        clusters:
          - name: f
            endpoints: ["127.0.0.1:{fallback_port}"]
    on_result:
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "primary success should return 200");
    assert_eq!(body, "primary-ok", "should get primary response, not fallback");
}

#[test]
fn multi_iteration_self_loop() {
    let backend = start_stateful_backend(vec![
        (503, "retry-1".to_owned()),
        (503, "retry-2".to_owned()),
        (200, "success".to_owned()),
    ]);
    let backend_port = backend.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: step
max_iterations: 5
steps:
  - name: step
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: b
      - filter: load_balancer
        clusters:
          - name: b
            endpoints: ["127.0.0.1:{backend_port}"]
    on_result:
      - status: [503]
        next: step
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "should succeed after retries");
    assert_eq!(body, "success", "should get final success response");
}

#[test]
fn max_iterations_enforcement() {
    let backend = start_stateful_backend(vec![
        (503, "a".to_owned()),
        (503, "b".to_owned()),
        (503, "c".to_owned()),
        (503, "d".to_owned()),
    ]);
    let backend_port = backend.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: step
max_iterations: 3
steps:
  - name: step
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: b
      - filter: load_balancer
        clusters:
          - name: b
            endpoints: ["127.0.0.1:{backend_port}"]
    on_result:
      - status: [503]
        next: step
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 508, "max iterations should return 508");
}

#[test]
fn depth_prevention() {
    let backend_port = start_backend("unreachable");
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: step
steps:
  - name: step
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: b
      - filter: load_balancer
        clusters:
          - name: b
            endpoints: ["127.0.0.1:{backend_port}"]
    on_result:
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             x-praxis-iterative-depth: 3\r\n\
             \r\n"
        ),
    );
    let status = parse_status(&raw);
    assert!(
        status == 400 || status == 508,
        "depth=3 should be rejected (400 from reserved header check or 508 from filter), got {status}"
    );
}

#[test]
fn request_body_preserved() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: step
steps:
  - name: step
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: b
      - filter: load_balancer
        clusters:
          - name: b
            endpoints: ["127.0.0.1:{backend_port}"]
    on_result:
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let raw = http_send(proxy.addr(), &json_post("/v1/chat", r#"{"prompt":"hello"}"#));
    assert_eq!(parse_status(&raw), 200, "echo should return 200");
}

#[test]
fn empty_body_get() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: step
steps:
  - name: step
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: b
      - filter: load_balancer
        clusters:
          - name: b
            endpoints: ["127.0.0.1:{backend_port}"]
    on_result:
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "GET with no body should succeed");
    assert_eq!(body, "ok");
}

#[test]
fn self_loop_terminates() {
    let backend = start_stateful_backend(vec![
        (200, "1".to_owned()),
        (200, "2".to_owned()),
        (200, "3".to_owned()),
        (200, "4".to_owned()),
    ]);
    let backend_port = backend.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: step
max_iterations: 3
steps:
  - name: step
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: b
      - filter: load_balancer
        clusters:
          - name: b
            endpoints: ["127.0.0.1:{backend_port}"]
    on_result:
      - default: true
        next: step
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 508, "self-loop with max_iterations=3 should return 508");
}

#[test]
fn second_transition_matches() {
    let backend = start_stateful_backend(vec![(503, "error".to_owned())]);
    let fallback = start_backend_with_shutdown("fallback");
    let backend_port = backend.port();
    let fallback_port = fallback.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: primary
steps:
  - name: primary
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: p
      - filter: load_balancer
        clusters:
          - name: p
            endpoints: ["127.0.0.1:{backend_port}"]
    on_result:
      - status: [404]
        next: not-found-handler
      - status: [503]
        next: fallback
      - default: true
        done: true
  - name: not-found-handler
    filters:
      - filter: static_response
        status: 404
    on_result:
      - default: true
        done: true
  - name: fallback
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: f
      - filter: load_balancer
        clusters:
          - name: f
            endpoints: ["127.0.0.1:{fallback_port}"]
    on_result:
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "second transition (503) should fire");
    assert_eq!(body, "fallback", "should get fallback response");
}

#[test]
fn rapid_sequential_requests() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: step
steps:
  - name: step
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: b
      - filter: load_balancer
        clusters:
          - name: b
            endpoints: ["127.0.0.1:{backend_port}"]
    on_result:
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    for i in 0..10 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "request {i} should succeed");
        assert_eq!(body, "ok", "request {i} body should match");
    }
}

#[test]
fn failover_429_quota_exhaustion() {
    let primary = start_stateful_backend(vec![(429, "rate limited".to_owned())]);
    let fallback = start_backend_with_shutdown("fallback-ok");
    let primary_port = primary.port();
    let fallback_port = fallback.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: primary
steps:
  - name: primary
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: p
      - filter: load_balancer
        clusters:
          - name: p
            endpoints: ["127.0.0.1:{primary_port}"]
    on_result:
      - status: [429]
        next: fallback
      - default: true
        done: true
  - name: fallback
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: f
      - filter: load_balancer
        clusters:
          - name: f
            endpoints: ["127.0.0.1:{fallback_port}"]
    on_result:
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "429 failover should produce 200");
    assert_eq!(body, "fallback-ok", "should get fallback response on 429");
}

#[test]
fn empty_response_body() {
    let backend = start_stateful_backend(vec![(200, String::new())]);
    let backend_port = backend.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: step
steps:
  - name: step
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: b
      - filter: load_balancer
        clusters:
          - name: b
            endpoints: ["127.0.0.1:{backend_port}"]
    on_result:
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "empty response body should return 200");
    assert!(body.is_empty(), "body should be empty, got: {body}");
}

#[test]
fn no_transition_matches_returns_response() {
    let backend = start_stateful_backend(vec![(200, "ok".to_owned())]);
    let backend_port = backend.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: step
steps:
  - name: step
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: b
      - filter: load_balancer
        clusters:
          - name: b
            endpoints: ["127.0.0.1:{backend_port}"]
    on_result:
      - status: [404]
        next: step
      - status: [503]
        next: step
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "no match should return response as-is");
    assert_eq!(body, "ok", "should get the actual response body");
}

#[test]
fn step_contexts_are_isolated() {
    let primary = start_stateful_backend(vec![(503, "down".to_owned())]);
    let fallback = start_backend_with_shutdown("fallback-ok");
    let primary_port = primary.port();
    let fallback_port = fallback.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: primary
steps:
  - name: primary
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: p
      - filter: load_balancer
        clusters:
          - name: p
            endpoints: ["127.0.0.1:{primary_port}"]
    on_result:
      - status: [503]
        next: fallback
      - default: true
        done: true
  - name: fallback
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: f
      - filter: load_balancer
        clusters:
          - name: f
            endpoints: ["127.0.0.1:{fallback_port}"]
    on_result:
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "step isolation test should return 200");
    assert_eq!(body, "fallback-ok", "fallback should run with isolated context");
}

#[test]
fn agentic_loop_model_tool_model() {
    let model = start_stateful_backend(vec![
        (202, r#"{"tool_calls":["get_weather"]}"#.to_owned()),
        (200, r#"{"answer":"sunny"}"#.to_owned()),
    ]);
    let tool = start_backend_with_shutdown(r#"{"result":"72F"}"#);
    let model_port = model.port();
    let tool_port = tool.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: model-call
max_iterations: 10
steps:
  - name: model-call
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: model
      - filter: load_balancer
        clusters:
          - name: model
            endpoints: ["127.0.0.1:{model_port}"]
    on_result:
      - status: [202]
        next: tool-dispatch
      - default: true
        done: true
  - name: tool-dispatch
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: tools
      - filter: load_balancer
        clusters:
          - name: tools
            endpoints: ["127.0.0.1:{tool_port}"]
    on_result:
      - default: true
        next: model-call
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let raw = http_send(proxy.addr(), &json_post("/v1/chat", r#"{"prompt":"weather?"}"#));
    let status = parse_status(&raw);
    assert_eq!(status, 200, "agentic loop should complete with 200");
}

#[test]
fn agentic_loop_done_immediately() {
    let model = start_stateful_backend(vec![(200, r#"{"answer":"42"}"#.to_owned())]);
    let model_port = model.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: model-call
steps:
  - name: model-call
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: m
      - filter: load_balancer
        clusters:
          - name: m
            endpoints: ["127.0.0.1:{model_port}"]
    on_result:
      - status: [202]
        next: model-call
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "immediate done should return 200");
    assert!(body.contains("42"), "should get model's answer");
}

#[test]
fn agentic_loop_max_iterations() {
    let model = start_stateful_backend(vec![
        (202, "loop-1".to_owned()),
        (202, "loop-2".to_owned()),
        (202, "loop-3".to_owned()),
        (202, "loop-4".to_owned()),
        (202, "loop-5".to_owned()),
        (202, "loop-6".to_owned()),
    ]);
    let tool = start_backend_with_shutdown("tool-result");
    let model_port = model.port();
    let tool_port = tool.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: model-call
max_iterations: 3
steps:
  - name: model-call
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: m
      - filter: load_balancer
        clusters:
          - name: m
            endpoints: ["127.0.0.1:{model_port}"]
    on_result:
      - status: [202]
        next: tool-dispatch
      - default: true
        done: true
  - name: tool-dispatch
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: t
      - filter: load_balancer
        clusters:
          - name: t
            endpoints: ["127.0.0.1:{tool_port}"]
    on_result:
      - default: true
        next: model-call
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 508, "agentic loop should hit max iterations");
}

#[test]
fn credential_injection_reaches_backend() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: step
steps:
  - name: step
    filters:
      - filter: headers
        request_add:
          - name: x-api-key
            value: "test-key-123"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: b
      - filter: load_balancer
        clusters:
          - name: b
            endpoints: ["127.0.0.1:{backend_port}"]
    on_result:
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "credential injection should return 200");
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-api-key") && lower.contains("test-key-123"),
        "injected header should reach the backend: {body}"
    );
}

#[test]
fn large_body_at_max_response_bytes() {
    let echo = start_echo_backend();
    let backend_port = echo.port();
    let proxy_port = free_port();
    let body_size = 512;
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: step
max_response_bytes: {body_size}
steps:
  - name: step
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: b
      - filter: load_balancer
        clusters:
          - name: b
            endpoints: ["127.0.0.1:{backend_port}"]
    on_result:
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let payload = "x".repeat(body_size);
    let (status, body) = http_post(proxy.addr(), "/echo", &payload);
    assert_eq!(status, 200, "body at max_response_bytes should succeed");
    assert_eq!(body.len(), body_size, "echoed body should match sent size");
}

#[test]
fn combined_status_and_filter_result_transition() {
    let model = start_stateful_backend(vec![(200, "final-answer".to_owned())]);
    let model_port = model.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: step
steps:
  - name: step
    filters:
      - filter: grpc_detection
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: b
      - filter: load_balancer
        clusters:
          - name: b
            endpoints: ["127.0.0.1:{model_port}"]
    on_result:
      - status: [200]
        filter: grpc_detection
        key: detected
        value: "true"
        next: step
      - default: true
        done: true
"#
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "non-gRPC request should hit default done");
    assert_eq!(
        body, "final-answer",
        "combined transition should NOT fire (grpc not detected)"
    );
}

#[test]
fn router_only_step_no_lb() {
    let config_result = Config::from_yaml(&irr_yaml(
        free_port(),
        r#"
initial_step: step
steps:
  - name: step
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: b
    on_result:
      - default: true
        done: true
"#,
    ));
    assert!(
        config_result.is_ok(),
        "step with router but no LB should parse: {:?}",
        config_result.err()
    );
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

fn irr_yaml(proxy_port: u16, irr_config: &str) -> String {
    let indented = irr_config
        .lines()
        .map(|line| {
            if line.trim().is_empty() {
                String::new()
            } else {
                format!("        {line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "listeners:\n\
         \x20 - name: default\n\
         \x20   address: \"127.0.0.1:{proxy_port}\"\n\
         \x20   filter_chains: [main]\n\
         filter_chains:\n\
         \x20 - name: main\n\
         \x20   filters:\n\
         \x20     - filter: iterative_request_router\n\
         {indented}\n"
    )
}
