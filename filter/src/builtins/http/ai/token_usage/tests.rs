// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Unit tests for token usage extraction.

use super::{TokenUsageProvider, extract_token_usage, set_token_usage};

// -----------------------------------------------------------------------------
// set_token_usage Tests
// -----------------------------------------------------------------------------

#[test]
fn set_token_usage_writes_all_metadata_keys() {
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    set_token_usage(&mut ctx, 150, 80, Some(230));
    assert_eq!(ctx.get_metadata("token.input"), Some("150"));
    assert_eq!(ctx.get_metadata("token.output"), Some("80"));
    assert_eq!(ctx.get_metadata("token.total"), Some("230"));
}

#[test]
fn set_token_usage_computes_total_when_none() {
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    set_token_usage(&mut ctx, 100, 50, None);
    assert_eq!(ctx.get_metadata("token.total"), Some("150"));
}

#[test]
fn set_token_usage_uses_explicit_total() {
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    set_token_usage(&mut ctx, 100, 50, Some(200));
    assert_eq!(
        ctx.get_metadata("token.total"),
        Some("200"),
        "explicit total should override computed sum"
    );
}

#[test]
fn set_token_usage_saturates_on_overflow() {
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    set_token_usage(&mut ctx, u64::MAX, 1, None);
    assert_eq!(
        ctx.get_metadata("token.total"),
        Some(&*u64::MAX.to_string()),
        "total should saturate instead of wrapping"
    );
}

#[test]
fn set_token_usage_overwrites_previous() {
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    set_token_usage(&mut ctx, 100, 50, None);
    set_token_usage(&mut ctx, 200, 80, Some(280));
    assert_eq!(ctx.get_metadata("token.input"), Some("200"));
    assert_eq!(ctx.get_metadata("token.output"), Some("80"));
    assert_eq!(ctx.get_metadata("token.total"), Some("280"));
}

#[test]
fn set_token_usage_zero_values() {
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    set_token_usage(&mut ctx, 0, 0, None);
    assert_eq!(ctx.get_metadata("token.input"), Some("0"));
    assert_eq!(ctx.get_metadata("token.output"), Some("0"));
    assert_eq!(ctx.get_metadata("token.total"), Some("0"));
}

// -----------------------------------------------------------------------------
// Provider-Specific Parsing Tests
// -----------------------------------------------------------------------------

#[test]
fn openai_full_response() {
    let json = br#"{
        "id": "chatcmpl-abc123",
        "choices": [],
        "usage": {
            "prompt_tokens": 15,
            "completion_tokens": 42,
            "total_tokens": 57
        }
    }"#;

    let usage = extract_token_usage(TokenUsageProvider::OpenAi, json).unwrap();

    assert_eq!(usage.input_tokens(), 15, "input_tokens should be 15");
    assert_eq!(usage.output_tokens(), 42, "output_tokens should be 42");
    assert_eq!(usage.total_tokens(), 57, "total_tokens should be 57");
}

#[test]
fn azure_same_as_openai() {
    let json = br#"{"usage": {"prompt_tokens": 5, "completion_tokens": 10, "total_tokens": 15}}"#;

    let usage = extract_token_usage(TokenUsageProvider::Azure, json).unwrap();

    assert_eq!(usage.input_tokens(), 5, "Azure should parse like OpenAI");
    assert_eq!(usage.output_tokens(), 10, "Azure should parse like OpenAI");
}

#[test]
fn anthropic_full_response() {
    let json = br#"{
        "id": "msg_01abc",
        "type": "message",
        "content": [],
        "usage": {
            "input_tokens": 15,
            "output_tokens": 42
        }
    }"#;

    let usage = extract_token_usage(TokenUsageProvider::Anthropic, json).unwrap();

    assert_eq!(usage.input_tokens(), 15, "input_tokens should be 15");
    assert_eq!(usage.output_tokens(), 42, "output_tokens should be 42");
    assert_eq!(usage.total_tokens(), 57, "total_tokens should be calculated");
}

#[test]
fn anthropic_with_prompt_caching() {
    // When prompt caching is enabled, input_tokens only contains non-cached tokens.
    // Total input = input_tokens + cache_creation_input_tokens + cache_read_input_tokens
    let json = br#"{
        "id": "msg_01abc",
        "type": "message",
        "content": [],
        "usage": {
            "input_tokens": 50,
            "output_tokens": 100,
            "cache_creation_input_tokens": 1000,
            "cache_read_input_tokens": 5000
        }
    }"#;

    let usage = extract_token_usage(TokenUsageProvider::Anthropic, json).unwrap();

    assert_eq!(
        usage.input_tokens(),
        6050,
        "input should sum all input token types: 50 + 1000 + 5000"
    );
    assert_eq!(usage.output_tokens(), 100, "output_tokens should be 100");
    assert_eq!(usage.total_tokens(), 6150, "total should be 6050 + 100");
}

#[test]
fn google_full_response() {
    let json = br#"{
        "candidates": [],
        "usageMetadata": {
            "promptTokenCount": 15,
            "candidatesTokenCount": 42,
            "totalTokenCount": 57
        }
    }"#;

    let usage = extract_token_usage(TokenUsageProvider::Google, json).unwrap();

    assert_eq!(usage.input_tokens(), 15, "promptTokenCount should map to input_tokens");
    assert_eq!(
        usage.output_tokens(),
        42,
        "candidatesTokenCount should map to output_tokens"
    );
    assert_eq!(usage.total_tokens(), 57, "totalTokenCount should map to total_tokens");
}

#[test]
fn google_without_total() {
    let json = br#"{"usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 20}}"#;

    let usage = extract_token_usage(TokenUsageProvider::Google, json).unwrap();

    assert_eq!(usage.input_tokens(), 10, "promptTokenCount should map to input_tokens");
    assert_eq!(
        usage.output_tokens(),
        20,
        "candidatesTokenCount should map to output_tokens"
    );
    assert_eq!(
        usage.total_tokens(),
        30,
        "total should be calculated when totalTokenCount is absent"
    );
}

#[test]
fn bedrock_claude_invoke_model_response() {
    // Claude via Bedrock InvokeModel uses the same format as direct Anthropic API
    let json = br#"{
        "id": "msg_01abc",
        "type": "message",
        "usage": {
            "input_tokens": 15,
            "output_tokens": 42
        }
    }"#;

    let usage = extract_token_usage(TokenUsageProvider::Bedrock, json).unwrap();

    assert_eq!(usage.input_tokens(), 15, "input_tokens should map to input_tokens");
    assert_eq!(usage.output_tokens(), 42, "output_tokens should map to output_tokens");
    assert_eq!(usage.total_tokens(), 57, "total should be calculated");
}

#[test]
fn bedrock_converse_response() {
    let json = br#"{
        "output": {"message": {"role": "assistant", "content": []}},
        "usage": {
            "inputTokens": 15,
            "outputTokens": 42,
            "totalTokens": 57
        }
    }"#;

    let usage = extract_token_usage(TokenUsageProvider::Bedrock, json).unwrap();

    assert_eq!(usage.input_tokens(), 15, "inputTokens should map to input_tokens");
    assert_eq!(usage.output_tokens(), 42, "outputTokens should map to output_tokens");
    assert_eq!(usage.total_tokens(), 57, "totalTokens should map to total_tokens");
}

// -----------------------------------------------------------------------------
// Error Handling Tests
// -----------------------------------------------------------------------------

#[test]
fn missing_usage_returns_none() {
    let json = br#"{"id": "123", "choices": []}"#;

    let result = extract_token_usage(TokenUsageProvider::OpenAi, json);

    assert!(result.is_none(), "missing usage field should return None");
}

#[test]
fn google_missing_usage_returns_none() {
    let json = br#"{"candidates": []}"#;

    let result = extract_token_usage(TokenUsageProvider::Google, json);

    assert!(result.is_none(), "missing usageMetadata field should return None");
}

#[test]
fn invalid_json_returns_none() {
    let json = b"not valid json";

    let result = extract_token_usage(TokenUsageProvider::OpenAi, json);

    assert!(result.is_none(), "invalid JSON should return None");
}

#[test]
fn empty_body_returns_none() {
    let result = extract_token_usage(TokenUsageProvider::OpenAi, b"");

    assert!(result.is_none(), "empty body should return None");
}

#[test]
fn error_response_returns_none() {
    let json = br#"{"error": {"message": "Invalid API key", "type": "invalid_request_error"}}"#;

    let result = extract_token_usage(TokenUsageProvider::OpenAi, json);

    assert!(result.is_none(), "error response should return None");
}
