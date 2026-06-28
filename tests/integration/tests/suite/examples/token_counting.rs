// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the `token_count` filter.
//!
//! These tests verify that the filter loads, handles all provider configurations,
//! and passes requests through without errors. Detailed token extraction logic
//! is covered by unit tests in `filter/src/builtins/http/ai/token_count.rs`.
//!
//! # Why no end-to-end header assertions?
//!
//! `token_count` writes token metadata in `on_response_body` (body phase).
//! `token_usage_headers` reads it in `on_response` (headers phase), which
//! runs before the body phase. The metadata is therefore not yet present when
//! `token_usage_headers` tries to inject headers. This is the same constraint
//! documented in `token_usage_headers.rs`.

use std::collections::HashMap;

use praxis_core::config::Config;
use praxis_test_utils::{Backend, free_port, http_send, parse_header, parse_status, start_proxy};

// ---------------------------------------------------------------------------
// Provider smoke tests — filter loads and proxies without errors
// ---------------------------------------------------------------------------

#[test]
fn token_count_openai_passes_through() {
    let body = r#"{"id":"chatcmpl-1","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}"#;
    let backend_port = Backend::fixed(body)
        .header("content-type", "application/json")
        .start();

    let proxy_port = free_port();
    let config = Config::from_yaml(&make_yaml(proxy_port, "openai", backend_port)).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /v1/chat/completions HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "openai: proxy should return 200");
}

#[test]
fn token_count_anthropic_passes_through() {
    let body =
        r#"{"id":"msg_1","type":"message","content":[],"usage":{"input_tokens":15,"output_tokens":42}}"#;
    let backend_port = Backend::fixed(body)
        .header("content-type", "application/json")
        .start();

    let proxy_port = free_port();
    let config = Config::from_yaml(&make_yaml(proxy_port, "anthropic", backend_port)).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /v1/messages HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "anthropic: proxy should return 200");
}

#[test]
fn token_count_google_passes_through() {
    let body =
        r#"{"candidates":[],"usageMetadata":{"promptTokenCount":8,"candidatesTokenCount":16,"totalTokenCount":24}}"#;
    let backend_port = Backend::fixed(body)
        .header("content-type", "application/json")
        .start();

    let proxy_port = free_port();
    let config = Config::from_yaml(&make_yaml(proxy_port, "google", backend_port)).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /v1/models/gemini-pro:generateContent HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "google: proxy should return 200");
}

#[test]
fn token_count_bedrock_passes_through() {
    let body = r#"{"output":{"message":{}},"usage":{"inputTokens":12,"outputTokens":30,"totalTokens":42}}"#;
    let backend_port = Backend::fixed(body)
        .header("content-type", "application/json")
        .start();

    let proxy_port = free_port();
    let config = Config::from_yaml(&make_yaml(proxy_port, "bedrock", backend_port)).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /model/anthropic.claude/converse HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "bedrock: proxy should return 200");
}

#[test]
fn token_count_azure_passes_through() {
    let body = r#"{"id":"chatcmpl-az","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":10,"total_tokens":15}}"#;
    let backend_port = Backend::fixed(body)
        .header("content-type", "application/json")
        .start();

    let proxy_port = free_port();
    let config = Config::from_yaml(&make_yaml(proxy_port, "azure", backend_port)).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /openai/deployments/gpt-4/chat/completions HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "azure: proxy should return 200");
}

// ---------------------------------------------------------------------------
// Bedrock InvokeModel — header-based extraction
// ---------------------------------------------------------------------------

#[test]
fn token_count_bedrock_invoke_model_passes_through() {
    let backend_port = Backend::fixed(r#"{"output":{}}"#)
        .header("content-type", "application/json")
        .header("x-amzn-bedrock-input-token-count", "25")
        .header("x-amzn-bedrock-output-token-count", "50")
        .start();

    let proxy_port = free_port();
    let config =
        Config::from_yaml(&make_yaml(proxy_port, "bedrock_invoke_model", backend_port)).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /model/amazon.titan-text-express/invoke HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "bedrock_invoke_model: proxy should return 200");
}

// ---------------------------------------------------------------------------
// No-usage body is a no-op
// ---------------------------------------------------------------------------

#[test]
fn token_count_no_usage_field_does_not_break_response() {
    let backend_port = Backend::fixed(r#"{"error":"insufficient_quota"}"#)
        .header("content-type", "application/json")
        .start();

    let proxy_port = free_port();
    let config = Config::from_yaml(&make_yaml(proxy_port, "openai", backend_port)).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /v1/chat/completions HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "missing usage should not break the response");
    assert_eq!(
        parse_header(&raw, "praxis-token-input"),
        None,
        "no token headers without usage data"
    );
}

// ---------------------------------------------------------------------------
// Example config smoke test
// ---------------------------------------------------------------------------

#[test]
fn token_counting_example_config_loads() {
    let backend_port_guard = praxis_test_utils::start_backend_with_shutdown(
        r#"{"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
    );
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "ai/token-counting.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "POST /v1/chat/completions HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "example config should load and serve requests");
}

// ---------------------------------------------------------------------------
// Test utilities
// ---------------------------------------------------------------------------

/// Minimal pipeline: `token_count` → `router` → `load_balancer`.
fn make_yaml(proxy_port: u16, provider: &str, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: token_count
        provider: {provider}
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
