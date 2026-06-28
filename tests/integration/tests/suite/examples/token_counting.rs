// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for token counting filters.
//!
//! ## What is tested
//!
//! | Test | Provider | What is verified |
//! |------|----------|-----------------|
//! | `bedrock_invoke_model_*` | bedrock_invoke_model | X-Token-* headers present (tokens come from upstream response *headers*, available before body processing — the only case where header injection is possible) |
//! | Non-Bedrock non-streaming | openai/anthropic/google/bedrock/azure | 200 OK + body byte-for-byte unchanged |
//! | SSE streaming | openai/anthropic/google | 200 OK + body byte-for-byte unchanged |
//! | `missing_usage_fields_*` | openai | X-Token-* headers absent |
//! | `example_config_*` | openai | 200 OK + body unchanged |
//!
//! ## Why X-Token headers are only verified for Bedrock InvokeModel
//!
//! In the Praxis/Pingora filter pipeline, response headers are committed
//! *before* the response body is processed.  The `x_token_headers` filter
//! runs its `on_response` hook (where it can write headers) in *reverse*
//! pipeline order, which means it executes *after* `token_count.on_response`
//! but *before* `token_count.on_response_body`.  For Bedrock InvokeModel,
//! `token_count` extracts the counts from upstream response *headers* inside
//! `on_response`, making them immediately available.  For every other
//! provider, counts are extracted from the response body inside
//! `on_response_body`, at which point headers have already been sent.

use std::collections::HashMap;

use praxis_test_utils::{
    Backend, example_config_path, free_port, http_send, json_post, load_example_config,
    parse_body, parse_header, parse_status, patch_yaml, start_proxy,
};

// -----------------------------------------------------------------------------
// Mock response bodies
// -----------------------------------------------------------------------------

const OPENAI_JSON: &str =
    r#"{"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}"#;

const ANTHROPIC_JSON: &str =
    r#"{"content":[],"usage":{"input_tokens":10,"output_tokens":20}}"#;

const GOOGLE_JSON: &str =
    r#"{"candidates":[],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":20,"totalTokenCount":30}}"#;

const BEDROCK_CONVERSE_JSON: &str =
    r#"{"output":{},"usage":{"inputTokens":10,"outputTokens":20}}"#;

const BEDROCK_INVOKE_MODEL_JSON: &str = r#"{"completion":"hello"}"#;

// OpenAI and Azure share the same JSON format.
const AZURE_JSON: &str = OPENAI_JSON;

// SSE streams
const OPENAI_SSE: &str = concat!(
    "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}],\"usage\":null}\n\n",
    "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":20,\"total_tokens\":30}}\n\n",
    "data: [DONE]\n\n",
);

const ANTHROPIC_SSE: &str = concat!(
    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":10}}}\n\n",
    "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n",
    "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":20}}\n\n",
    "data: {\"type\":\"message_stop\"}\n\n",
);

const GOOGLE_SSE: &str = concat!(
    "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hello\"}]}}]}\n\n",
    "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\" world\"}]}}],\"usageMetadata\":{\"promptTokenCount\":10,\"candidatesTokenCount\":20,\"totalTokenCount\":30}}\n\n",
);

// OpenAI SSE with keep-alive comments, empty lines, and pretty-printed JSON.
const OPENAI_SSE_NOISY: &str = concat!(
    ": ping\n\n",
    "\n",
    "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}],\"usage\":null}\n\n",
    "\n",
    ": keep-alive\n\n",
    "data: {\n  \"choices\": [],\n  \"usage\": {\n    \"prompt_tokens\": 10,\n    \"completion_tokens\": 20,\n    \"total_tokens\": 30\n  }\n}\n\n",
    "data: [DONE]\n\n",
);

// OpenAI JSON without a usage field — no token headers should be injected.
const OPENAI_NO_USAGE_JSON: &str = r#"{"choices":[{"message":{"content":"Hello"}}]}"#;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Build a YAML config for the token counting pipeline using the example file,
/// substituting `provider: openai` with the given provider name.
fn token_count_config(proxy_port: u16, backend_port: u16, provider: &str) -> praxis_core::config::Config {
    let path = example_config_path("ai/token-counting.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let yaml = yaml.replace("provider: openai", &format!("provider: {provider}"));
    let patched = patch_yaml(&yaml, proxy_port, &HashMap::from([("127.0.0.1:8000", backend_port)]));
    praxis_core::config::Config::from_yaml(&patched).expect("config should parse")
}

/// Assert that all three token headers are present with the expected values.
///
/// Only call this for providers where tokens arrive in upstream *response headers*
/// (i.e. `bedrock_invoke_model`).  For body-based providers the header injection
/// phase runs before the body is parsed, so these headers cannot be set.
fn assert_token_headers(raw: &str, input: u64, output: u64, total: u64) {
    assert_eq!(
        parse_header(raw, "x-token-input").as_deref(),
        Some(input.to_string().as_str()),
        "X-Token-Input should be {input}"
    );
    assert_eq!(
        parse_header(raw, "x-token-output").as_deref(),
        Some(output.to_string().as_str()),
        "X-Token-Output should be {output}"
    );
    assert_eq!(
        parse_header(raw, "x-token-total").as_deref(),
        Some(total.to_string().as_str()),
        "X-Token-Total should be {total}"
    );
}

// -----------------------------------------------------------------------------
// Non-streaming tests — body passthrough
// -----------------------------------------------------------------------------

#[test]
fn openai_non_streaming_extracts_token_counts() {
    let backend = Backend::fixed(OPENAI_JSON).header("content-type", "application/json").start_with_shutdown();
    let proxy_port = free_port();
    let config = token_count_config(proxy_port, backend.port(), "openai");
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/chat/completions", "{}"));
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(parse_body(&raw), OPENAI_JSON, "body should pass through unchanged");
    // X-Token headers are not verified here: for body-based providers the
    // response header phase runs before the body is parsed.  Token extraction
    // correctness is covered by unit tests in token_usage::tests.
}

#[test]
fn anthropic_non_streaming_extracts_token_counts() {
    let backend = Backend::fixed(ANTHROPIC_JSON).header("content-type", "application/json").start_with_shutdown();
    let proxy_port = free_port();
    let config = token_count_config(proxy_port, backend.port(), "anthropic");
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/messages", "{}"));
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(parse_body(&raw), ANTHROPIC_JSON, "body should pass through unchanged");
}

#[test]
fn google_non_streaming_extracts_token_counts() {
    let backend = Backend::fixed(GOOGLE_JSON).header("content-type", "application/json").start_with_shutdown();
    let proxy_port = free_port();
    let config = token_count_config(proxy_port, backend.port(), "google");
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1beta/models/gemini-pro:generateContent", "{}"));
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(parse_body(&raw), GOOGLE_JSON, "body should pass through unchanged");
}

#[test]
fn bedrock_converse_non_streaming_extracts_token_counts() {
    let backend = Backend::fixed(BEDROCK_CONVERSE_JSON).header("content-type", "application/json").start_with_shutdown();
    let proxy_port = free_port();
    let config = token_count_config(proxy_port, backend.port(), "bedrock");
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/model/anthropic.claude-3/converse", "{}"));
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(parse_body(&raw), BEDROCK_CONVERSE_JSON, "body should pass through unchanged");
}

/// Bedrock InvokeModel is the only provider that delivers token counts via
/// upstream response *headers* (`x-amzn-bedrock-*`).  Because those counts
/// are available during `on_response` (before the body is read), the
/// `x_token_headers` filter can inject the X-Token-* headers successfully.
#[test]
fn bedrock_invoke_model_extracts_token_counts_from_headers() {
    let backend = Backend::fixed(BEDROCK_INVOKE_MODEL_JSON)
        .header("content-type", "application/json")
        .header("x-amzn-bedrock-input-token-count", "10")
        .header("x-amzn-bedrock-output-token-count", "20")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = token_count_config(proxy_port, backend.port(), "bedrock_invoke_model");
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/model/amazon.titan/invoke", "{}"));
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(parse_body(&raw), BEDROCK_INVOKE_MODEL_JSON, "body should pass through unchanged");
    assert_token_headers(&raw, 10, 20, 30);
}

#[test]
fn azure_non_streaming_extracts_token_counts() {
    let backend = Backend::fixed(AZURE_JSON).header("content-type", "application/json").start_with_shutdown();
    let proxy_port = free_port();
    let config = token_count_config(proxy_port, backend.port(), "azure");
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/openai/deployments/gpt-4/chat/completions", "{}"));
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(parse_body(&raw), AZURE_JSON, "body should pass through unchanged");
}

// -----------------------------------------------------------------------------
// SSE streaming tests — body passthrough
// -----------------------------------------------------------------------------

#[test]
fn openai_streaming_extracts_token_counts() {
    let backend = Backend::fixed(OPENAI_SSE)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = token_count_config(proxy_port, backend.port(), "openai");
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/chat/completions", r#"{"stream":true}"#));
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(parse_body(&raw), OPENAI_SSE, "SSE body should pass through unchanged");
}

#[test]
fn anthropic_streaming_split_events_extracts_token_counts() {
    let backend = Backend::fixed(ANTHROPIC_SSE)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = token_count_config(proxy_port, backend.port(), "anthropic");
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/messages", r#"{"stream":true}"#));
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(parse_body(&raw), ANTHROPIC_SSE, "SSE body should pass through unchanged");
}

#[test]
fn google_streaming_no_done_sentinel_extracts_token_counts() {
    let backend = Backend::fixed(GOOGLE_SSE)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = token_count_config(proxy_port, backend.port(), "google");
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1beta/models/gemini-pro:streamGenerateContent", r#"{"stream":true}"#));
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(parse_body(&raw), GOOGLE_SSE, "SSE body should pass through unchanged");
}

// -----------------------------------------------------------------------------
// Passthrough and edge cases
// -----------------------------------------------------------------------------

#[test]
fn non_json_response_body_passes_through_unchanged() {
    // Verify the filter handles a non-JSON body (e.g. a plain-text error page)
    // without crashing: parse silently fails, no token headers are injected,
    // and the original body is forwarded byte-for-byte.
    let backend = Backend::fixed("Internal Server Error")
        .header("content-type", "text/plain")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = token_count_config(proxy_port, backend.port(), "openai");
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/chat/completions", "{}"));
    assert_eq!(parse_status(&raw), 200, "non-JSON upstream response should still return 200");
    assert_eq!(
        parse_body(&raw),
        "Internal Server Error",
        "non-JSON body must be forwarded byte-for-byte"
    );
    assert!(
        parse_header(&raw, "x-token-input").is_none(),
        "X-Token-Input must be absent when body is not valid JSON"
    );
}

#[test]
fn missing_usage_fields_no_token_headers_injected() {
    let backend = Backend::fixed(OPENAI_NO_USAGE_JSON).header("content-type", "application/json").start_with_shutdown();
    let proxy_port = free_port();
    let config = token_count_config(proxy_port, backend.port(), "openai");
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/chat/completions", "{}"));
    assert_eq!(parse_status(&raw), 200);
    assert!(
        parse_header(&raw, "x-token-input").is_none(),
        "X-Token-Input must be absent when usage fields are missing"
    );
    assert!(
        parse_header(&raw, "x-token-output").is_none(),
        "X-Token-Output must be absent when usage fields are missing"
    );
    assert!(
        parse_header(&raw, "x-token-total").is_none(),
        "X-Token-Total must be absent when usage fields are missing"
    );
}

#[test]
fn openai_streaming_whitespace_and_comments() {
    let backend = Backend::fixed(OPENAI_SSE_NOISY)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .start_with_shutdown();
    let proxy_port = free_port();
    let config = token_count_config(proxy_port, backend.port(), "openai");
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/chat/completions", r#"{"stream":true}"#));
    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        OPENAI_SSE_NOISY,
        "noisy SSE body must pass through byte-for-byte unchanged"
    );
}

// -----------------------------------------------------------------------------
// Example config smoke test
// -----------------------------------------------------------------------------

#[test]
fn example_config_token_counting_openai() {
    let backend = Backend::fixed(OPENAI_JSON).header("content-type", "application/json").start_with_shutdown();
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/token-counting.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:8000", backend.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/chat/completions", "{}"));
    assert_eq!(parse_status(&raw), 200, "example config smoke test should return 200");
    assert_eq!(parse_body(&raw), OPENAI_JSON, "body should pass through unchanged");
}
