// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for branching example configurations.

use std::collections::HashMap;

use praxis_test_utils::{
    ProxyGuard, free_port, http_get, http_send, json_post, parse_body, parse_status, start_backend_with_shutdown,
    start_header_echo_backend, start_proxy,
};

use super::load_example_config;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn unconditional_branch_audit_header_reaches_backend() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let config = load_example_config(
        "branching/unconditional-branch.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "unconditional branch should return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-audit: applied"),
        "audit branch should add X-Audit header to backend request, got:\n{body}"
    );
    assert!(
        lower.contains("x-pipeline: main"),
        "main chain should add X-Pipeline header, got:\n{body}"
    );
}

#[test]
fn conditional_terminal_blocks_dangerous_request() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "branching/conditional-terminal.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Danger: true\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        403,
        "request with X-Danger:true should be blocked with 403"
    );
}

#[test]
fn conditional_terminal_allows_safe_request() {
    let backend_guard = start_backend_with_shutdown("hello");
    let proxy_port = free_port();
    let config = load_example_config(
        "branching/conditional-terminal.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "safe request should return 200");
    assert_eq!(body, "hello", "safe request should reach backend");
}

#[test]
fn conditional_skip_to_clean_request_gets_tag() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let config = load_example_config(
        "branching/conditional-skip-to.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "clean request should return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-clean: true"),
        "clean request should get X-Clean header via skip-to branch, got:\n{body}"
    );
    assert!(
        !lower.contains("x-inspected"),
        "clean request should skip the inspection middleware between the branch host and routing, got:\n{body}"
    );
}

#[test]
fn conditional_skip_to_flagged_request_skips_branch() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let config = load_example_config(
        "branching/conditional-skip-to.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Danger: true\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "flagged request should still return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        !lower.contains("x-clean"),
        "flagged request should NOT get X-Clean header, got:\n{body}"
    );
    assert!(
        lower.contains("x-inspected: full"),
        "flagged request should fall through to the inspection middleware, got:\n{body}"
    );
}

#[test]
fn cross_chain_flat_preprocess_header_reaches_backend() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let config = load_example_config(
        "branching/cross-chain-flat.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "cross-chain flat pipeline should return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-preprocess: true"),
        "preprocessing chain should add X-Preprocess header, got:\n{body}"
    );
}

#[test]
fn multiple_branches_blocks_dangerous_request() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "branching/multiple-branches.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Danger: true\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        403,
        "X-Danger:true should trigger blocked_path branch with 403"
    );
}

#[test]
fn multiple_branches_tags_safe_request() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let config = load_example_config(
        "branching/multiple-branches.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "safe request should return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-guardrails: passed"),
        "safe request should get X-Guardrails:passed via passed_path branch, got:\n{body}"
    );
}

#[test]
fn named_chain_ref_guardrail_header_reaches_backend() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let config = load_example_config(
        "branching/named-chain-ref.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "named chain ref should return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-guardrail: applied"),
        "guardrails chain should add X-Guardrail header, got:\n{body}"
    );
    assert!(
        lower.contains("x-entry: checked"),
        "main chain should add X-Entry header, got:\n{body}"
    );
}

#[test]
fn nested_branches_blocks_dangerous_request() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "branching/nested-branches.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Danger: true\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        403,
        "nested branch should block X-Danger:true with 403"
    );
}

#[test]
fn nested_branches_allows_safe_request() {
    let backend_guard = start_backend_with_shutdown("hello");
    let proxy_port = free_port();
    let config = load_example_config(
        "branching/nested-branches.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "safe request through nested branches should return 200");
    assert_eq!(body, "hello", "safe request should reach backend");
}

#[test]
fn reentrance_normal_flow() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let config = load_example_config(
        "branching/reentrance.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "reentrance normal flow should return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-classify: run"),
        "classify filter should add X-Classify header, got:\n{body}"
    );
}

#[test]
fn result_matchers_any_of_forwards_listed_methods_untouched() {
    let backend_guard = start_header_echo_backend();
    let proxy = start_result_matchers_proxy(backend_guard.port());

    for method in ["ping", "echo"] {
        let raw = http_send(proxy.addr(), &json_post("/", &rpc_call(method)));
        let body = parse_body(&raw).to_lowercase();

        assert_eq!(parse_status(&raw), 200, "any_of should let {method} through");
        assert!(
            !body.contains("x-health-check"),
            "{method} is not a health check and should not be tagged, got:\n{body}"
        );
    }
}

#[test]
fn result_matchers_contains_tags_listed_health_checks() {
    let backend_guard = start_header_echo_backend();
    let proxy = start_result_matchers_proxy(backend_guard.port());

    for method in ["health", "health_check"] {
        let raw = http_send(proxy.addr(), &json_post("/", &rpc_call(method)));
        let body = parse_body(&raw).to_lowercase();

        assert_eq!(
            parse_status(&raw),
            200,
            "{method} is listed and should reach the backend"
        );
        assert!(
            body.contains("x-health-check: true"),
            "contains: health should tag {method} for the backend, got:\n{body}"
        );
    }
}

#[test]
fn result_matchers_deny_unlisted_methods() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy = start_result_matchers_proxy(backend_guard.port());

    for method in ["admin_reset", "eth_blockNumber", "healthz"] {
        let raw = http_send(proxy.addr(), &json_post("/", &rpc_call(method)));

        assert_eq!(parse_status(&raw), 403, "{method} is not listed and should be denied");
        assert_eq!(
            parse_body(&raw),
            "method not allowed",
            "the unconditional deny should answer {method}"
        );
    }
}

#[test]
fn result_matchers_deny_methods_json_rpc_cannot_record() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy = start_result_matchers_proxy(backend_guard.port());

    // JSON escapes that decode to a control character, so json_rpc records
    // the call's kind but no method. Even a listed name fails closed.
    for method in [r"admin\u0001reset", r"ping\u0001"] {
        let raw = http_send(proxy.addr(), &json_post("/", &rpc_call(method)));

        assert_eq!(
            parse_status(&raw),
            403,
            "a method json_rpc could not record ({method}) should be denied"
        );
        assert_eq!(
            parse_body(&raw),
            "method not allowed",
            "the unconditional deny should answer {method}"
        );
    }
}

#[test]
fn result_matchers_not_rejects_notifications() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy = start_result_matchers_proxy(backend_guard.port());

    let raw = http_send(proxy.addr(), &json_post("/", r#"{"jsonrpc":"2.0","method":"ping"}"#));

    assert_eq!(parse_status(&raw), 400, "not: request should reject a notification");
    assert_eq!(
        parse_body(&raw),
        "expected a JSON-RPC request",
        "the not branch should answer the notification"
    );
}

#[test]
fn result_matchers_not_rejects_requests_without_a_verdict() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy = start_result_matchers_proxy(backend_guard.port());

    let (no_body_status, no_body) = http_get(proxy.addr(), "/", None);
    let raw = http_send(proxy.addr(), &json_post("/", r#"{"hello":"world"}"#));

    assert_eq!(
        no_body_status, 400,
        "not: request should fire when json_rpc wrote no kind at all"
    );
    assert_eq!(
        no_body, "expected a JSON-RPC request",
        "the not branch should answer a request with no body"
    );
    assert_eq!(
        parse_status(&raw),
        400,
        "not: request should fire for a JSON body that is not JSON-RPC"
    );
    assert_eq!(
        parse_body(&raw),
        "expected a JSON-RPC request",
        "the not branch should answer a non-JSON-RPC body"
    );
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

/// Start the result matchers example in front of the backend on `backend_port`.
fn start_result_matchers_proxy(backend_port: u16) -> ProxyGuard {
    let config = load_example_config(
        "branching/result-matchers.yaml",
        free_port(),
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    start_proxy(&config)
}

/// A JSON-RPC 2.0 request body calling `method`.
fn rpc_call(method: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","method":"{method}","id":1}}"#)
}
