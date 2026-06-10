// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Provider-specific JSON parsing for token usage extraction.

use serde::Deserialize;

use super::TokenUsage;

// -----------------------------------------------------------------------------
// OpenAI / Azure
// -----------------------------------------------------------------------------

/// `OpenAI` / Azure `OpenAI` response format.
#[derive(Deserialize)]
#[allow(dead_code, reason = "fields accessed via serde deserialization")]
struct OpenAiResponse {
    /// Token usage statistics.
    usage: Option<OpenAiUsage>,
}

/// `OpenAI` usage object.
#[derive(Deserialize)]
#[allow(dead_code, reason = "fields accessed via serde deserialization")]
struct OpenAiUsage {
    /// Tokens in the prompt.
    prompt_tokens: u64,

    /// Tokens in the completion.
    completion_tokens: u64,

    /// Total tokens (optional, can be calculated).
    total_tokens: Option<u64>,
}

/// Parses `OpenAI`/Azure response format.
pub(super) fn parse_openai(body: &[u8]) -> Option<TokenUsage> {
    let response: OpenAiResponse = serde_json::from_slice(body).ok()?;
    let usage = response.usage?;
    Some(TokenUsage::new(
        usage.prompt_tokens,
        usage.completion_tokens,
        usage.total_tokens,
    ))
}

// -----------------------------------------------------------------------------
// Anthropic
// -----------------------------------------------------------------------------

/// `Anthropic` Claude response format.
#[derive(Deserialize)]
#[allow(dead_code, reason = "fields accessed via serde deserialization")]
struct AnthropicResponse {
    /// Token usage statistics.
    usage: Option<AnthropicUsage>,
}

/// `Anthropic` usage object.
#[derive(Deserialize)]
#[allow(dead_code, reason = "fields accessed via serde deserialization")]
struct AnthropicUsage {
    /// Tokens in the input (excludes cached tokens when caching is active).
    input_tokens: u64,

    /// Tokens in the output.
    output_tokens: u64,

    /// Tokens written to cache (prompt caching).
    cache_creation_input_tokens: Option<u64>,

    /// Tokens read from cache (prompt caching).
    cache_read_input_tokens: Option<u64>,
}

/// Parses `Anthropic` Claude response format.
///
/// When prompt caching is enabled, `input_tokens` only contains tokens after
/// the cache breakpoint. The actual total is the sum of all input token fields.
pub(super) fn parse_anthropic(body: &[u8]) -> Option<TokenUsage> {
    let response: AnthropicResponse = serde_json::from_slice(body).ok()?;
    let usage = response.usage?;
    let actual_input = usage
        .input_tokens
        .saturating_add(usage.cache_creation_input_tokens.unwrap_or(0))
        .saturating_add(usage.cache_read_input_tokens.unwrap_or(0));
    Some(TokenUsage::new(actual_input, usage.output_tokens, None))
}

// -----------------------------------------------------------------------------
// Google Gemini
// -----------------------------------------------------------------------------

/// Google `Gemini` response format.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code, reason = "fields accessed via serde deserialization")]
struct GoogleResponse {
    /// Token usage metadata.
    usage_metadata: Option<GoogleUsageMetadata>,
}

/// Google `Gemini` usage metadata object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code, reason = "fields accessed via serde deserialization")]
struct GoogleUsageMetadata {
    /// Tokens in the prompt.
    prompt_token_count: u64,

    /// Tokens in the candidates (output).
    candidates_token_count: u64,

    /// Total tokens (optional, can be calculated).
    total_token_count: Option<u64>,
}

/// Parses Google `Gemini` response format.
pub(super) fn parse_google(body: &[u8]) -> Option<TokenUsage> {
    let response: GoogleResponse = serde_json::from_slice(body).ok()?;
    let usage = response.usage_metadata?;
    Some(TokenUsage::new(
        usage.prompt_token_count,
        usage.candidates_token_count,
        usage.total_token_count,
    ))
}

// -----------------------------------------------------------------------------
// AWS Bedrock
// -----------------------------------------------------------------------------

/// AWS `Bedrock` Converse API response format (fields in `usage` object).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code, reason = "fields accessed via serde deserialization")]
struct BedrockConverseResponse {
    /// Token usage statistics.
    usage: Option<BedrockConverseUsage>,
}

/// `Bedrock` Converse API usage object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code, reason = "fields accessed via serde deserialization")]
struct BedrockConverseUsage {
    /// Tokens in the input.
    input_tokens: u64,

    /// Tokens in the output.
    output_tokens: u64,

    /// Total tokens (optional).
    total_tokens: Option<u64>,
}

/// Parses AWS `Bedrock` response format.
///
/// # Supported Formats
///
/// 1. **Converse API** (recommended): `usage.inputTokens`, `usage.outputTokens`
///    - AWS's unified API that works with all Bedrock models
///    - Always returns a consistent format regardless of underlying model
///
/// 2. **Claude via `InvokeModel`**: `usage.input_tokens`, `usage.output_tokens`
///    - Claude models via `InvokeModel` use the same format as direct Anthropic API
///
/// # Not Supported
///
/// Other models via `InvokeModel` have different response formats:
/// - Titan: `inputTextTokenCount`, `results[0].tokenCount`
/// - Llama: `prompt_token_count`, `generation_token_count`
/// - Cohere: token counts in HTTP headers
///
/// For these models, use the Converse API or submit a follow-up issue to add support.
pub(super) fn parse_bedrock(body: &[u8]) -> Option<TokenUsage> {
    // Try Converse API format first (AWS recommended, works with all models)
    if let Ok(response) = serde_json::from_slice::<BedrockConverseResponse>(body)
        && let Some(usage) = response.usage
    {
        return Some(TokenUsage::new(
            usage.input_tokens,
            usage.output_tokens,
            usage.total_tokens,
        ));
    }

    // Fall back to Claude/Anthropic format (Claude via InvokeModel)
    // Claude via Bedrock InvokeModel uses the same format as direct Anthropic API
    parse_anthropic(body)
}
