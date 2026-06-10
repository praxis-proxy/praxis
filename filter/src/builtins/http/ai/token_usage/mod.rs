// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Unified token usage extraction from AI provider responses.
//!
//! Maps provider-specific JSON response formats (`OpenAI`, `Anthropic`, Google,
//! `Bedrock`, Azure) into a common [`TokenUsage`] representation.

mod providers;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests;

use providers::{parse_anthropic, parse_bedrock, parse_google, parse_openai};

// -----------------------------------------------------------------------------
// Public Types
// -----------------------------------------------------------------------------

/// Unified token usage extracted from an AI provider response.
///
/// All providers report input (prompt) and output (completion) token counts,
/// though field names vary. This struct normalizes them into a single format.
///
/// Fields are private to allow future changes without breaking the API.
/// Use the getter methods to access values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenUsage {
    /// Tokens in the input/prompt.
    input: u64,

    /// Tokens in the output/completion.
    output: u64,

    /// Total tokens (input + output).
    total: u64,
}

impl TokenUsage {
    /// Creates a new `TokenUsage` instance.
    pub(crate) fn new(input: u64, output: u64, total: Option<u64>) -> Self {
        Self {
            input,
            output,
            total: total.unwrap_or_else(|| input.saturating_add(output)),
        }
    }

    /// Returns the number of tokens in the input/prompt.
    pub fn input_tokens(&self) -> u64 {
        self.input
    }

    /// Returns the number of tokens in the output/completion.
    pub fn output_tokens(&self) -> u64 {
        self.output
    }

    /// Returns the total number of tokens (input + output).
    ///
    /// Some providers include this explicitly in the response;
    /// for others it is computed as `input + output`.
    pub fn total_tokens(&self) -> u64 {
        self.total
    }
}

/// AI provider identifier for response format selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenUsageProvider {
    /// `OpenAI` API (`usage.prompt_tokens`, `usage.completion_tokens`).
    OpenAi,

    /// `Anthropic` Claude API (`usage.input_tokens`, `usage.output_tokens`).
    Anthropic,

    /// Google `Gemini` API (`usageMetadata.promptTokenCount`, `usageMetadata.candidatesTokenCount`).
    Google,

    /// AWS `Bedrock` (supports both `InvokeModel` and `Converse` API formats).
    Bedrock,

    /// Azure `OpenAI` (same format as `OpenAI`).
    Azure,
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Extracts token usage from a provider's JSON response body.
///
/// Returns `None` if the response doesn't contain usage information
/// (e.g., error responses, malformed JSON, or missing fields).
///
/// # Example
///
/// ```
/// use praxis_filter::{TokenUsageProvider, extract_token_usage};
///
/// let openai_response =
///     br#"{"usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}}"#;
/// let usage = extract_token_usage(TokenUsageProvider::OpenAi, openai_response).unwrap();
/// assert_eq!(usage.input_tokens(), 10);
/// assert_eq!(usage.output_tokens(), 20);
/// assert_eq!(usage.total_tokens(), 30);
/// ```
pub fn extract_token_usage(provider: TokenUsageProvider, body: &[u8]) -> Option<TokenUsage> {
    match provider {
        TokenUsageProvider::OpenAi | TokenUsageProvider::Azure => parse_openai(body),
        TokenUsageProvider::Anthropic => parse_anthropic(body),
        TokenUsageProvider::Google => parse_google(body),
        TokenUsageProvider::Bedrock => parse_bedrock(body),
    }
}
