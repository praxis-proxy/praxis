// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the `iterative_request_router` filter.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext,
};
use praxis_test_utils::{
    Backend, free_port, http_get, http_post, http_send, json_post, parse_body, parse_header, parse_status,
    start_backend, start_backend_with_shutdown, start_echo_backend, start_full_proxy, start_full_proxy_with_registry,
    start_header_echo_backend, start_slow_backend, start_stateful_backend,
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
fn provider_failover_on_connection_refusal() {
    let unavailable_port = free_port();
    let fallback = start_backend_with_shutdown("fallback-ok");
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
            cluster: primary
      - filter: load_balancer
        clusters:
          - name: primary
            endpoints: ["127.0.0.1:{unavailable_port}"]
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
            cluster: fallback
      - filter: load_balancer
        clusters:
          - name: fallback
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

    assert_eq!(status, 200, "connection refusal should transition to fallback");
    assert_eq!(body, "fallback-ok");
}

#[test]
fn provider_failover_on_local_step_rejection() {
    let fallback = start_backend_with_shutdown("fallback-ok");
    let proxy_port = free_port();
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "test_reject_503",
            FilterFactory::Http(Arc::new(|_config| Ok(Box::new(Reject503Filter)))),
        )
        .unwrap();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: primary
steps:
  - name: primary
    filters:
      - filter: test_reject_503
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: unused
      - filter: load_balancer
        clusters:
          - name: unused
            endpoints: ["127.0.0.1:{}"]
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
            cluster: fallback
      - filter: load_balancer
        clusters:
          - name: fallback
            endpoints: ["127.0.0.1:{}"]
    on_result:
      - default: true
        done: true
"#,
            free_port(),
            fallback.port(),
        ),
    ))
    .unwrap();

    let proxy = start_full_proxy_with_registry(&config, &registry);
    let (status, body) = http_get(proxy.addr(), "/", None);

    assert_eq!(status, 200, "local 503 should transition to fallback");
    assert_eq!(body, "fallback-ok");
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
fn parent_security_filter_runs_before_iteration() {
    let backend = start_backend_with_shutdown("must-not-run");
    let proxy_port = free_port();
    let yaml = irr_yaml(
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
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:{}"]
    on_result:
      - default: true
        done: true
"#,
            backend.port()
        ),
    )
    .replacen(
        "    filters:\n      - filter: iterative_request_router",
        "    filters:\n      - filter: ip_acl\n        deny:\n          - \"0.0.0.0/0\"\n      - filter: iterative_request_router",
        1,
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_full_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/responses", r#"{"input":"blocked"}"#));

    assert_eq!(
        parse_status(&raw),
        403,
        "parent ACL must reject before the router starts"
    );
}

#[test]
fn body_derived_condition_can_enable_iteration() {
    let echo = start_echo_backend();
    let proxy_port = free_port();
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "test_body_promoter",
            FilterFactory::Http(Arc::new(|_config| Ok(Box::new(BodyPromoterFilter)))),
        )
        .unwrap();
    let irr = format!(
        r#"
initial_step: step
steps:
  - name: step
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: echo
      - filter: load_balancer
        clusters:
          - name: echo
            endpoints: ["127.0.0.1:{}"]
    on_result:
      - default: true
        done: true
"#,
        echo.port()
    );
    let yaml = irr_yaml(proxy_port, &irr).replacen(
        "    filters:\n      - filter: iterative_request_router",
        "    filters:\n      - filter: test_body_promoter\n      - filter: iterative_request_router\n        conditions:\n          - when:\n              headers:\n                x-enable-iteration: \"true\"",
        1,
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_full_proxy_with_registry(&config, &registry);
    let payload = r#"{"input":"route me"}"#;

    let (status, body) = http_post(proxy.addr(), "/echo", payload);

    assert_eq!(status, 200, "body-derived condition should enable the router");
    assert_eq!(body, payload, "the pre-read body must reach the selected step");
}

#[test]
fn response_limit_does_not_limit_inbound_request_body() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: step
max_response_bytes: 2
steps:
  - name: step
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

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/responses", r#"{"input":"larger than two bytes"}"#),
    );

    assert_eq!(parse_status(&raw), 200, "response limit must not cap request buffering");
    assert_eq!(parse_body(&raw), "ok");
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
fn credential_injection_replaces_client_header() {
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
      - filter: credential_injection
        clusters:
          - name: b
            header: Authorization
            value: "trusted-token"
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
        "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: attacker-token\r\nConnection: close\r\n\r\n",
    );
    let body = parse_body(&raw).to_lowercase();

    assert_eq!(parse_status(&raw), 200);
    assert!(
        body.contains("trusted-token"),
        "proxy credential should reach backend: {body}"
    );
    assert!(
        !body.contains("attacker-token"),
        "client credential must be replaced before dispatch: {body}"
    );
}

#[test]
fn credentials_do_not_cross_step_boundaries() {
    let primary = start_stateful_backend(vec![(503, "retry".to_owned())]);
    let fallback = start_header_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: primary
steps:
  - name: primary
    filters:
      - filter: headers
        request_set:
          - name: Authorization
            value: "Bearer primary-secret"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: primary
      - filter: load_balancer
        clusters:
          - name: primary
            endpoints: ["127.0.0.1:{primary_port}"]
    on_result:
      - status: [503]
        next: fallback
  - name: fallback
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: fallback
      - filter: load_balancer
        clusters:
          - name: fallback
            endpoints: ["127.0.0.1:{fallback_port}"]
    on_result:
      - default: true
        done: true
"#,
            primary_port = primary.port(),
            fallback_port = fallback.port(),
        ),
    ))
    .unwrap();

    let proxy = start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);

    assert_eq!(status, 200);
    assert!(
        !body.to_ascii_lowercase().contains("primary-secret"),
        "credentials from the primary step must not reach fallback: {body}"
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
fn max_state_bytes_rejects_oversized_iteration_state() {
    let backend = start_backend_with_shutdown("unreachable");
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: step
max_state_bytes: 1
steps:
  - name: step
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
"#,
            backend_port = backend.port(),
        ),
    ))
    .unwrap();

    let proxy = start_full_proxy(&config);
    let (status, _) = http_get(proxy.addr(), "/", None);

    assert_eq!(status, 413, "iteration state above max_state_bytes should be rejected");
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

/// Praxis AI filters are registered externally and depend on request-body,
/// response-header, and response-body callbacks for request translation,
/// tool-call parsing, guardrails, and usage accounting. An iterative-router
/// step must therefore use the caller's registry and execute the complete
/// HTTP filter lifecycle around its subrequest.
#[test]
fn external_agentic_filter_completes_model_tool_model_round_trip() {
    let model = Backend::status(202, r#"{"output":[{"type":"function_call"}]}"#).start_with_shutdown();
    let tool = start_backend_with_shutdown(r#"{"result":"72F"}"#);
    let final_model = start_echo_backend();
    let proxy_port = free_port();
    let calls = Arc::new(LifecycleCalls::default());
    let state = Arc::new(Mutex::new(AgenticState::default()));
    let factory_calls = Arc::clone(&calls);
    let factory_state = Arc::clone(&state);

    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "test_agentic_lifecycle",
            FilterFactory::Http(Arc::new(move |config| {
                Ok(Box::new(AgenticLifecycleProbe {
                    calls: Arc::clone(&factory_calls),
                    role: ProbeRole::from_config(config)?,
                    state: Arc::clone(&factory_state),
                }))
            })),
        )
        .unwrap();

    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: model
steps:
  - name: model
    filters:
      - filter: test_agentic_lifecycle
        role: model-response
      - filter: router
        routes:
          - path_prefix: "/"
            headers:
              x-body-route: model
            cluster: model
      - filter: load_balancer
        clusters:
          - name: model
            endpoints: ["127.0.0.1:{model_port}"]
    on_result:
      - filter: test_agentic_lifecycle
        key: saw_tool_call
        value: "true"
        next: tool
  - name: tool
    filters:
      - filter: headers
        request_set:
          - name: content-type
            value: application/json
      - filter: test_agentic_lifecycle
        role: tool-response
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: tool
      - filter: load_balancer
        clusters:
          - name: tool
            endpoints: ["127.0.0.1:{tool_port}"]
    on_result:
      - default: true
        next: final-model
  - name: final-model
    filters:
      - filter: headers
        request_set:
          - name: content-type
            value: application/json
      - filter: test_agentic_lifecycle
        role: final-model-request
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: final-model
      - filter: load_balancer
        clusters:
          - name: final-model
            endpoints: ["127.0.0.1:{final_model_port}"]
    on_result:
      - default: true
        done: true
"#,
            model_port = model.port(),
            tool_port = tool.port(),
            final_model_port = final_model.port(),
        ),
    ))
    .unwrap();

    let proxy = start_full_proxy_with_registry(&config, &registry);
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", r#"{"input":"weather?"}"#));

    assert_eq!(
        parse_status(&raw),
        200,
        "agentic round trip should return the final model response"
    );
    let final_body: serde_json::Value = serde_json::from_str(&parse_body(&raw)).unwrap();
    assert_eq!(
        final_body["input"][0]["type"], "function_call_output",
        "second model request must contain a function-call output item"
    );
    assert_eq!(final_body["input"][0]["call_id"], "call_1");
    assert_eq!(
        final_body["input"][0]["output"], "72F",
        "tool result must reach the second model request"
    );
    assert!(calls.request.load(Ordering::Relaxed) > 0, "on_request must run");
    assert!(
        calls.request_body.load(Ordering::Relaxed) > 0,
        "on_request_body must run so AI filters can translate the next model request"
    );
    assert!(
        calls.response.load(Ordering::Relaxed) > 0,
        "on_response must run so AI filters can inspect model response metadata"
    );
    assert!(
        calls.response_body.load(Ordering::Relaxed) > 0,
        "on_response_body must run so AI filters can parse tool calls and usage"
    );
}

#[test]
fn overall_deadline_includes_step_filter_lifecycle() {
    let backend = start_backend_with_shutdown("should-not-complete");
    let proxy_port = free_port();
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "test_slow_request",
            FilterFactory::Http(Arc::new(|_config| Ok(Box::new(SlowRequestFilter)))),
        )
        .unwrap();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: slow
timeout_ms: 10
steps:
  - name: slow
    filters:
      - filter: test_slow_request
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:{}"]
    on_result:
      - default: true
        done: true
"#,
            backend.port()
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let started = std::time::Instant::now();
    let (status, _body) = http_get(proxy.addr(), "/", None);

    assert_eq!(status, 504, "a slow step filter must consume the overall deadline");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(500),
        "request outlived the configured deadline: {:?}",
        started.elapsed()
    );
}

// ---------------------------------------------------------------------------
// Terminal Response Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn preceding_filter_sees_terminal_response_body() {
    let backend_port = start_backend("upstream-payload");
    let proxy_port = free_port();
    let probe = Arc::new(ResponseProbe::default());
    let probe_clone = Arc::clone(&probe);
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "test_response_probe",
            FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(ResponseProbeFilter(Arc::clone(&probe_clone))))
            })),
        )
        .unwrap();

    let yaml = irr_yaml(
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
    )
    .replacen(
        "    filters:\n      - filter: iterative_request_router",
        "    filters:\n      - filter: test_response_probe\n      - filter: iterative_request_router",
        1,
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, body) = http_get(proxy.addr(), "/", None);

    assert_eq!(status, 200);
    assert_eq!(body, "upstream-payload");
    let seen_body = probe.body.lock().unwrap().clone();
    assert_eq!(
        seen_body.as_deref(),
        Some(b"upstream-payload".as_slice()),
        "preceding filter must see the terminal response body"
    );
}

#[test]
fn response_header_mutation_reaches_client() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "test_response_tagger",
            FilterFactory::Http(Arc::new(|_| Ok(Box::new(ResponseTaggerFilter)))),
        )
        .unwrap();

    let yaml = irr_yaml(
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
    )
    .replacen(
        "    filters:\n      - filter: iterative_request_router",
        "    filters:\n      - filter: test_response_tagger\n      - filter: iterative_request_router",
        1,
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let raw = http_send(proxy.addr(), &http_get_raw("/"));
    let status = parse_status(&raw);
    assert_eq!(status, 200);
    assert!(
        raw.contains("x-response-tagged: true"),
        "response-header mutation by preceding filter must reach the client"
    );
}

#[test]
fn response_hooks_execute_once() {
    let backend_port = start_backend("once");
    let proxy_port = free_port();
    let probe = Arc::new(ResponseProbe::default());
    let probe_clone = Arc::clone(&probe);
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "test_response_probe",
            FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(ResponseProbeFilter(Arc::clone(&probe_clone))))
            })),
        )
        .unwrap();

    let yaml = irr_yaml(
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
    )
    .replacen(
        "    filters:\n      - filter: iterative_request_router",
        "    filters:\n      - filter: test_response_probe\n      - filter: iterative_request_router",
        1,
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, _) = http_get(proxy.addr(), "/", None);

    assert_eq!(status, 200);
    assert_eq!(
        probe.response_calls.load(Ordering::SeqCst),
        1,
        "on_response must execute exactly once"
    );
    assert_eq!(
        probe.response_body_calls.load(Ordering::SeqCst),
        1,
        "on_response_body must execute exactly once"
    );
}

// ---------------------------------------------------------------------------
// HEAD Framing
// ---------------------------------------------------------------------------

#[test]
fn head_preserves_upstream_content_length() {
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
    let raw = http_send(
        proxy.addr(),
        "HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    let cl = parse_header(&raw, "content-length");
    let body = parse_body(&raw);

    assert_eq!(status, 200);
    assert!(body.is_empty(), "HEAD must not return a body, got: {body:?}");
    assert_eq!(cl.as_deref(), Some("5"), "HEAD Content-Length must match GET body size");
}

// ---------------------------------------------------------------------------
// Transport vs Local Timeout Provenance
// ---------------------------------------------------------------------------

#[test]
fn transport_timeout_triggers_transport_transition() {
    let slow_port = start_slow_backend("slow", std::time::Duration::from_secs(2));
    let fallback = start_backend_with_shutdown("fallback-ok");
    let fallback_port = fallback.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: primary
timeout_ms: 5000
step_timeout_ms: 50
steps:
  - name: primary
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: primary
      - filter: load_balancer
        clusters:
          - name: primary
            endpoints: ["127.0.0.1:{slow_port}"]
    on_result:
      - origin: transport
        transport_error: deadline_exceeded
        next: fallback
      - default: true
        done: true
  - name: fallback
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: fallback
      - filter: load_balancer
        clusters:
          - name: fallback
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

    assert_eq!(
        status, 200,
        "transport timeout should match transport/deadline_exceeded and failover"
    );
    assert_eq!(body, "fallback-ok");
}

#[test]
fn local_timeout_does_not_match_transport_transition() {
    let backend = start_backend_with_shutdown("backend-ok");
    let fallback = start_backend_with_shutdown("fallback-ok");
    let fallback_port = fallback.port();
    let proxy_port = free_port();
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "test_slow_request",
            FilterFactory::Http(Arc::new(|_config| Ok(Box::new(SlowRequestFilter)))),
        )
        .unwrap();
    let config = Config::from_yaml(&irr_yaml(
        proxy_port,
        &format!(
            r#"
initial_step: primary
timeout_ms: 5000
step_timeout_ms: 50
steps:
  - name: primary
    filters:
      - filter: test_slow_request
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: primary
      - filter: load_balancer
        clusters:
          - name: primary
            endpoints: ["127.0.0.1:{}"]
    on_result:
      - origin: transport
        transport_error: deadline_exceeded
        next: fallback
      - default: true
        done: true
  - name: fallback
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: fallback
      - filter: load_balancer
        clusters:
          - name: fallback
            endpoints: ["127.0.0.1:{fallback_port}"]
    on_result:
      - default: true
        done: true
"#,
            backend.port()
        ),
    ))
    .unwrap();
    let proxy = start_full_proxy_with_registry(&config, &registry);
    let (status, _body) = http_get(proxy.addr(), "/", None);

    assert_eq!(
        status, 504,
        "local filter timeout must NOT match transport/deadline_exceeded; \
         should fall through to default:done and return 504"
    );
}

fn http_get_raw(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ResponseProbe {
    response_calls: AtomicUsize,
    response_body_calls: AtomicUsize,
    body: Mutex<Option<Bytes>>,
}

struct ResponseProbeFilter(Arc<ResponseProbe>);

#[async_trait::async_trait]
impl HttpFilter for ResponseProbeFilter {
    fn name(&self) -> &'static str {
        "test_response_probe"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.0.response_calls.fetch_add(1, Ordering::SeqCst);
        Ok(FilterAction::Continue)
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn response_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(65_536),
        }
    }

    fn on_response_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        self.0.response_body_calls.fetch_add(1, Ordering::SeqCst);
        if end_of_stream {
            self.0.body.lock().unwrap().clone_from(body);
        }
        Ok(FilterAction::Continue)
    }
}

struct ResponseTaggerFilter;

#[async_trait::async_trait]
impl HttpFilter for ResponseTaggerFilter {
    fn name(&self) -> &'static str {
        "test_response_tagger"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if let Some(resp) = ctx.response_header.as_mut() {
            resp.headers
                .insert("x-response-tagged", http::HeaderValue::from_static("true"));
        }
        Ok(FilterAction::Continue)
    }
}

struct SlowRequestFilter;

struct Reject503Filter;

#[async_trait::async_trait]
impl HttpFilter for Reject503Filter {
    fn name(&self) -> &'static str {
        "test_reject_503"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Reject(praxis_filter::Rejection::status(503)))
    }
}

struct BodyPromoterFilter;

#[async_trait::async_trait]
impl HttpFilter for BodyPromoterFilter {
    fn name(&self) -> &'static str {
        "test_body_promoter"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(16_384),
        }
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if end_of_stream {
            ctx.extra_request_headers
                .push((std::borrow::Cow::Borrowed("x-enable-iteration"), "true".to_owned()));
        }
        Ok(FilterAction::Continue)
    }
}

#[async_trait::async_trait]
impl HttpFilter for SlowRequestFilter {
    fn name(&self) -> &'static str {
        "test_slow_request"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        Ok(FilterAction::Continue)
    }
}

#[derive(Default)]
struct LifecycleCalls {
    request: AtomicUsize,
    request_body: AtomicUsize,
    response: AtomicUsize,
    response_body: AtomicUsize,
}

struct AgenticLifecycleProbe {
    calls: Arc<LifecycleCalls>,
    role: ProbeRole,
    state: Arc<Mutex<AgenticState>>,
}

#[derive(Clone, Copy)]
enum ProbeRole {
    FinalModelRequest,
    ModelResponse,
    ToolResponse,
}

impl ProbeRole {
    fn from_config(config: &serde_yaml::Value) -> Result<Self, FilterError> {
        match config.get("role").and_then(serde_yaml::Value::as_str) {
            Some("final-model-request") => Ok(Self::FinalModelRequest),
            Some("model-response") => Ok(Self::ModelResponse),
            Some("tool-response") => Ok(Self::ToolResponse),
            role => Err(format!("test_agentic_lifecycle: invalid role {role:?}").into()),
        }
    }
}

#[derive(Default)]
struct AgenticState {
    tool_call: Option<serde_json::Value>,
    tool_result: Option<String>,
}

#[async_trait::async_trait]
impl HttpFilter for AgenticLifecycleProbe {
    fn name(&self) -> &'static str {
        "test_agentic_lifecycle"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.calls.request.fetch_add(1, Ordering::Relaxed);
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        if matches!(self.role, ProbeRole::FinalModelRequest) {
            BodyAccess::ReadWrite
        } else {
            BodyAccess::ReadOnly
        }
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(16_384),
        }
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        self.calls.request_body.fetch_add(1, Ordering::Relaxed);
        if end_of_stream && matches!(self.role, ProbeRole::ModelResponse) {
            ctx.extra_request_headers
                .push((std::borrow::Cow::Borrowed("x-body-route"), "model".to_owned()));
        }
        if end_of_stream && matches!(self.role, ProbeRole::FinalModelRequest) {
            let state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let tool_result = state
                .tool_result
                .clone()
                .ok_or_else(|| -> FilterError { "tool result missing before final model request".into() })?;
            let tool_call = state.tool_call.clone();
            drop(state);
            let request = tool_call.map_or_else(
                || {
                    serde_json::json!({
                        "input": [{
                            "type": "function_call_output",
                            "call_id": "call_1",
                            "output": tool_result,
                        }]
                    })
                },
                |tool_call| {
                    let call_id = tool_call["call_id"].as_str().unwrap_or("call_1");
                    let name = tool_call["name"].as_str().unwrap_or("get_weather");
                    let arguments = tool_call["arguments"].as_str().unwrap_or("{\"city\":\"Paris\"}");
                    serde_json::json!({
                        "model": "Qwen/Qwen3-0.6B",
                        "input": [
                            {"role": "user", "content": "What is the weather in Paris?"},
                            {
                                "type": "function_call",
                                "name": name,
                                "arguments": arguments,
                                "call_id": call_id,
                            },
                            {
                                "type": "function_call_output",
                                "call_id": call_id,
                                "output": tool_result,
                            }
                        ],
                        "tools": [{
                            "type": "function",
                            "name": "get_weather",
                            "description": "Get current weather",
                            "parameters": {
                                "type": "object",
                                "properties": {"city": {"type": "string"}},
                                "required": ["city"]
                            }
                        }],
                        "tool_choice": "none",
                        "temperature": 0,
                        "max_output_tokens": 192
                    })
                },
            );
            *body = Some(Bytes::from(
                serde_json::to_vec(&request).map_err(|error| -> FilterError { error.to_string().into() })?,
            ));
        }
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.calls.response.fetch_add(1, Ordering::Relaxed);
        Ok(FilterAction::Continue)
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn response_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(16_384),
        }
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        self.calls.response_body.fetch_add(1, Ordering::Relaxed);
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        match self.role {
            ProbeRole::ModelResponse => {
                let tool_call = body
                    .as_ref()
                    .and_then(|body| serde_json::from_slice::<serde_json::Value>(body).ok())
                    .and_then(|value| {
                        value["output"]
                            .as_array()
                            .and_then(|output| output.iter().find(|item| item["type"] == "function_call"))
                            .cloned()
                    });
                if let Some(tool_call) = tool_call {
                    if tool_call["call_id"].is_string()
                        && tool_call["name"].is_string()
                        && tool_call["arguments"].is_string()
                    {
                        self.state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .tool_call = Some(tool_call);
                    }
                    ctx.filter_results
                        .entry("test_agentic_lifecycle")
                        .or_default()
                        .set("saw_tool_call", "true")?;
                }
            },
            ProbeRole::ToolResponse => {
                let result = body
                    .as_ref()
                    .and_then(|body| serde_json::from_slice::<serde_json::Value>(body).ok())
                    .and_then(|value| {
                        value
                            .get("result")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    })
                    .ok_or_else(|| -> FilterError { "tool response missing result".into() })?;
                self.state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .tool_result = Some(result);
            },
            ProbeRole::FinalModelRequest => {},
        }
        Ok(FilterAction::Continue)
    }
}

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
