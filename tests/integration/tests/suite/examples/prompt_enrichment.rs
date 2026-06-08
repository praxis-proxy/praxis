// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for the prompt enrichment example configuration.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_send, json_post, parse_body, parse_status, start_echo_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn prompt_enrichment_config_parses() {
    let config = super::load_example_config(
        "ai/prompt-enrichment.yaml",
        29910,
        HashMap::from([("127.0.0.1:3000", 29911_u16)]),
    );

    assert_eq!(config.listeners.len(), 1, "should have 1 listener");
    assert_eq!(&*config.listeners[0].name, "gateway", "listener name should be gateway");
}

#[test]
fn prompt_enrichment_prepends_and_appends() {
    let backend_guard = start_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let config = super::load_example_config(
        "ai/prompt-enrichment.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );

    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        &json_post(
            "/v1/chat/completions",
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#,
        ),
    );

    assert_eq!(parse_status(&raw), 200, "enrichment should return 200");
    let body = parse_body(&raw);
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("backend should echo valid JSON");
    let messages = parsed["messages"].as_array().expect("messages should be an array");
    assert_eq!(messages.len(), 3, "should have prepend + original + append");
    assert_eq!(messages[0]["role"], "system", "prepended message should be system");
    assert!(
        messages[0]["content"].as_str().unwrap().contains("Acme Corp"),
        "prepended content should mention Acme Corp"
    );
    assert_eq!(messages[1]["role"], "user", "original message should be preserved");
    assert_eq!(messages[1]["content"], "Hello", "original content should be preserved");
    assert_eq!(messages[2]["role"], "user", "appended message should be user");
    assert_eq!(
        messages[2]["content"], "Remember to cite your sources.",
        "appended content should match config"
    );
    assert_eq!(parsed["model"], "gpt-4o", "model should be preserved");
}

#[test]
fn prompt_enrichment_passes_non_chat_traffic() {
    let backend_guard = start_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let config = super::load_example_config(
        "ai/prompt-enrichment.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );

    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "POST /v1/embeddings HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: 23\r\n\
         Connection: close\r\n\r\n\
         {\"input\":\"hello world\"}",
    );

    assert_eq!(parse_status(&raw), 200, "non-chat traffic should pass through");
    let body = parse_body(&raw);
    assert!(
        body.contains("hello world"),
        "non-chat body should be forwarded unchanged: {body}"
    );
}
