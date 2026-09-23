// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the bound-upstream dispatch example.
//!
//! One pipeline drives two ownership modes from the same frozen logical
//! binding: a provider-owned request is dispatched directly by a branch whose
//! `cluster_source: bound_upstream` load balancer reads the binding, while every
//! other request runs gateway-owned processing and an `iterative_request_router`
//! whose step dispatches from the same binding. Neither path uses a second
//! router or a top-level load balancer.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_send, parse_body, parse_header, parse_status, start_backend_with_shutdown, start_echo_backend,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn dual_path_dispatches_both_modes_from_one_binding() {
    let openai = start_backend_with_shutdown("openai");
    let chat = start_backend_with_shutdown("chat");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/bound-upstream-dispatch.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", openai.port()), ("127.0.0.1:3002", chat.port())]),
    );
    let proxy = praxis_test_utils::start_full_proxy(&config);

    // Provider path: bound to the openai cluster by the /openai/ route, taken by
    // the direct branch. The branch rejoins `terminal`, so the gateway marker
    // and the IRR never run.
    let raw = http_send(
        proxy.addr(),
        "GET /openai/v1/responses HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "direct provider path should return 200");
    assert_eq!(
        parse_body(&raw),
        "openai",
        "direct path should reach the openai backend"
    );
    assert_eq!(
        parse_header(&raw, "X-Gateway-Processed"),
        None,
        "direct path must skip gateway-owned processing (branch rejoins terminal)"
    );

    // Non-provider path: bound to the chat cluster by the catch-all route, gains
    // the gateway marker, then dispatched by the IRR step's bound-consuming load
    // balancer.
    let raw = http_send(
        proxy.addr(),
        "GET /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "gateway + IRR path should return 200");
    assert_eq!(parse_body(&raw), "chat", "IRR step should reach the chat backend");
    assert_eq!(
        parse_header(&raw, "X-Gateway-Processed").as_deref(),
        Some("true"),
        "non-provider path should run gateway-owned processing"
    );

    let query = http_send(
        proxy.addr(),
        "GET /openai/v1/responses?stream=false HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_body(&query),
        "openai",
        "the query string must not change prefix routing"
    );

    let boundary = http_send(
        proxy.addr(),
        "GET /openai HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_body(&boundary),
        "openai",
        "the configured trailing slash is normalized at the /openai segment boundary"
    );
}

#[test]
fn direct_path_preserves_body_and_applies_pipeline_wide_limit() {
    let openai = start_echo_backend();
    let chat = start_backend_with_shutdown("chat");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/bound-upstream-dispatch.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", openai.port()), ("127.0.0.1:3002", chat.port())]),
    );
    let proxy = praxis_test_utils::start_full_proxy(&config);

    let body = "provider-body";
    let request = format!(
        "POST /openai/v1/responses HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let response = http_send(proxy.addr(), &request);
    assert_eq!(parse_status(&response), 200);
    assert_eq!(parse_body(&response), body, "buffering must preserve direct-path bytes");

    let oversized = "x".repeat(65_537);
    let request = format!(
        "POST /openai/v1/responses HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{oversized}",
        oversized.len()
    );
    let response = http_send(proxy.addr(), &request);
    assert_eq!(
        parse_status(&response),
        413,
        "the IRR StreamBuffer ceiling applies before the direct branch"
    );
}
