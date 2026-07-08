// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for branching example configurations.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_get, http_send, parse_body, parse_status, start_backend_with_shutdown, start_header_echo_backend,
    start_proxy,
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
