// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Token counting filter: extracts token usage from AI provider responses
//! and writes the counts to `FilterContext` for downstream consumers.
//!
//! For non-streaming (JSON) responses the full body is buffered and parsed
//! at end-of-stream. For SSE streaming responses the filter buffers all
//! chunks, then scans the assembled event stream for token counts once the
//! stream closes. The chosen strategy (full buffering) is documented in the
//! proposal for [#220].
//!
//! Token counts are written as filter metadata under keys
//! `token.input`, `token.output`, and `token.total` via
//! [`HttpFilterContext::set_token_usage`].

use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;

use crate::{
    FilterAction, FilterError,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};
use super::token_usage::{TokenUsage, TokenUsageProvider, extract_token_usage};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum response body size to buffer (8 MiB).
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Metadata key used to pass the SSE flag from `on_response` to `on_response_body`.
const META_IS_SSE: &str = "token_count.is_sse";

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the token count filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenCountConfig {
    /// AI provider whose response format to parse.
    provider: ProviderKind,
}

/// Supported provider identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProviderKind {
    /// OpenAI Chat Completions / Responses API.
    Openai,
    /// Anthropic Claude API.
    Anthropic,
    /// Google Gemini API.
    Google,
    /// AWS Bedrock Converse API (JSON body).
    Bedrock,
    /// AWS Bedrock InvokeModel API (HTTP response headers).
    BedrockInvokeModel,
    /// Azure OpenAI (same format as OpenAI).
    Azure,
}

// -----------------------------------------------------------------------------
// Filter
// -----------------------------------------------------------------------------

/// Extracts token usage from AI provider responses and writes counts to
/// `FilterContext`.
///
/// # YAML configuration
///
/// ```yaml
/// filter: token_count
/// provider: openai   # openai | anthropic | google | bedrock | bedrock_invoke_model | azure
/// ```
pub struct TokenCountFilter {
    provider: ProviderKind,
}

impl TokenCountFilter {
    /// Create from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if config parsing fails.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: TokenCountConfig = parse_filter_config("token_count", config)?;
        Ok(Box::new(Self { provider: cfg.provider }))
    }
}

#[async_trait]
impl HttpFilter for TokenCountFilter {
    fn name(&self) -> &'static str {
        "token_count"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    /// Detect SSE responses and handle Bedrock InvokeModel header-based extraction.
    ///
    /// For Bedrock InvokeModel, token counts arrive as HTTP response headers
    /// (`x-amzn-bedrock-input-token-count`, `x-amzn-bedrock-output-token-count`)
    /// rather than in the JSON body. This is the only provider with a header-based
    /// extraction path.
    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let (is_sse, bedrock_input, bedrock_output) =
            if let Some(resp) = ctx.response_header.as_ref() {
                let content_type = resp
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");

                let is_sse = content_type.contains("text/event-stream");

                let bedrock_input = if self.provider == ProviderKind::BedrockInvokeModel {
                    resp.headers
                        .get("x-amzn-bedrock-input-token-count")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                } else {
                    None
                };

                let bedrock_output = if self.provider == ProviderKind::BedrockInvokeModel {
                    resp.headers
                        .get("x-amzn-bedrock-output-token-count")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                } else {
                    None
                };

                (is_sse, bedrock_input, bedrock_output)
            } else {
                return Ok(FilterAction::Continue);
            };

        if is_sse {
            ctx.set_metadata(META_IS_SSE, "1");
        }

        if let (Some(i), Some(o)) = (bedrock_input, bedrock_output) {
            ctx.set_token_usage(i, o, None);
        }

        Ok(FilterAction::Continue)
    }

    fn response_body_access(&self) -> BodyAccess {
        if self.provider == ProviderKind::BedrockInvokeModel {
            BodyAccess::None
        } else {
            BodyAccess::ReadOnly
        }
    }

    fn response_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(MAX_BODY_BYTES),
        }
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if self.provider == ProviderKind::BedrockInvokeModel {
            return Ok(FilterAction::Release);
        }

        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        let Some(data) = body.as_ref().filter(|b| !b.is_empty()) else {
            return Ok(FilterAction::Continue);
        };

        let is_sse = ctx.get_metadata(META_IS_SSE) == Some("1");

        let usage = if is_sse {
            extract_from_sse(self.provider, data)
        } else {
            extract_token_usage(to_library_provider(self.provider), data)
        };

        if let Some(u) = usage {
            ctx.set_token_usage(u.input_tokens(), u.output_tokens(), Some(u.total_tokens()));
        }

        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// SSE Extraction
// -----------------------------------------------------------------------------

/// Extract token usage from a buffered SSE event stream.
fn extract_from_sse(provider: ProviderKind, data: &[u8]) -> Option<TokenUsage> {
    let text = std::str::from_utf8(data).ok()?;

    match provider {
        ProviderKind::Anthropic => extract_anthropic_sse(text),
        _ => extract_last_usage_from_sse(to_library_provider(provider), text),
    }
}

/// Scan SSE `data:` lines and return the last one that contains valid token
/// usage for the given provider.
///
/// Used for OpenAI, Google, Azure, and Bedrock Converse, where usage
/// appears in a single terminal chunk.
fn extract_last_usage_from_sse(provider: TokenUsageProvider, text: &str) -> Option<TokenUsage> {
    let mut last: Option<TokenUsage> = None;
    for line in text.lines() {
        if let Some(json) = line.strip_prefix("data: ") {
            if json == "[DONE]" {
                continue;
            }
            if let Some(u) = extract_token_usage(provider, json.as_bytes()) {
                last = Some(u);
            }
        }
    }
    last
}

/// Extract token usage from an Anthropic SSE stream where `input_tokens`
/// and `output_tokens` arrive in different event types.
///
/// - `message_start` → `message.usage.input_tokens`
/// - `message_delta` → `usage.output_tokens`
fn extract_anthropic_sse(text: &str) -> Option<TokenUsage> {
    let mut input_tokens: Option<u64> = None;
    let mut output_tokens: Option<u64> = None;

    for line in text.lines() {
        let Some(json) = line.strip_prefix("data: ") else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
            continue;
        };
        match v.get("type").and_then(|t| t.as_str()) {
            Some("message_start") => {
                if let Some(n) = v
                    .get("message")
                    .and_then(|m| m.get("usage"))
                    .and_then(|u| u.get("input_tokens"))
                    .and_then(serde_json::Value::as_u64)
                {
                    input_tokens = Some(n);
                }
            }
            Some("message_delta") => {
                if let Some(n) = v
                    .get("usage")
                    .and_then(|u| u.get("output_tokens"))
                    .and_then(serde_json::Value::as_u64)
                {
                    output_tokens = Some(n);
                }
            }
            _ => {}
        }
    }

    Some(TokenUsage::new(input_tokens?, output_tokens?, None))
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Map the filter's `ProviderKind` to the library's `TokenUsageProvider`.
fn to_library_provider(kind: ProviderKind) -> TokenUsageProvider {
    match kind {
        ProviderKind::Openai | ProviderKind::Azure => TokenUsageProvider::OpenAi,
        ProviderKind::Anthropic => TokenUsageProvider::Anthropic,
        ProviderKind::Google => TokenUsageProvider::Google,
        ProviderKind::Bedrock | ProviderKind::BedrockInvokeModel => TokenUsageProvider::Bedrock,
    }
}
