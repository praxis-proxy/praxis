// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Response-based token counting filter.
//!
//! Extracts token usage from provider responses and writes counts to
//! [`crate::FilterContext`] metadata under `token.input`, `token.output`,
//! and `token.total`. JSON parsing is delegated to the `token_usage` library.

use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use tracing::trace;

use crate::{
    FilterAction, FilterError,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

use super::token_usage::{TokenUsage, TokenUsageProvider, extract_token_usage, set_token_usage};

const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const META_IS_SSE: &str = "token_count.is_sse";
const HEADER_BEDROCK_INPUT: &str = "x-amzn-bedrock-input-token-count";
const HEADER_BEDROCK_OUTPUT: &str = "x-amzn-bedrock-output-token-count";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenCountConfig {
    provider: ProviderKind,
}

/// AI provider selecting the token extraction strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProviderKind {
    #[serde(rename = "openai")]
    OpenAi,
    Anthropic,
    Google,
    Bedrock,
    BedrockInvokeModel,
    Azure,
}

impl ProviderKind {
    /// Returns `None` for `BedrockInvokeModel` (header-only path).
    fn to_library_provider(self) -> Option<TokenUsageProvider> {
        match self {
            Self::OpenAi => Some(TokenUsageProvider::OpenAi),
            Self::Anthropic => Some(TokenUsageProvider::Anthropic),
            Self::Google => Some(TokenUsageProvider::Google),
            Self::Bedrock => Some(TokenUsageProvider::Bedrock),
            Self::Azure => Some(TokenUsageProvider::Azure),
            Self::BedrockInvokeModel => None,
        }
    }
}

/// Extracts token usage from AI provider responses and writes counts to
/// [`crate::FilterContext`] for downstream consumers.
///
/// Supported `provider` values: `openai`, `anthropic`, `google`, `bedrock`,
/// `bedrock_invoke_model`, `azure`. Provider must be set explicitly; Azure
/// and OpenAI share the same JSON schema so auto-detection is ambiguous.
pub struct TokenCountFilter {
    provider: ProviderKind,
}

impl TokenCountFilter {
    /// # Errors
    /// Returns [`FilterError`] if `provider` is missing, unknown, or unexpected keys are present.
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

    /// Detects SSE responses; for `bedrock_invoke_model` reads counts from headers directly.
    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if self.provider == ProviderKind::BedrockInvokeModel {
            extract_bedrock_headers(ctx);
            return Ok(FilterAction::Continue);
        }

        let is_sse = ctx
            .response_header
            .as_ref()
            .and_then(|r| r.headers.get("content-type"))
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("text/event-stream"));

        if is_sse {
            ctx.set_metadata(META_IS_SSE, "true".to_owned());
            trace!("SSE response detected; token counts will be extracted at stream close");
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
        if self.provider == ProviderKind::BedrockInvokeModel {
            BodyMode::Stream
        } else {
            BodyMode::StreamBuffer {
                max_bytes: Some(MAX_BODY_BYTES),
            }
        }
    }

    /// Triggered once at `end_of_stream`; dispatches to SSE or JSON extractor.
    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        let Some(bytes) = body.as_deref() else {
            trace!("no response body available for token extraction");
            return Ok(FilterAction::Continue);
        };

        let Some(library_provider) = self.provider.to_library_provider() else {
            return Ok(FilterAction::Continue);
        };

        let is_sse = ctx.get_metadata(META_IS_SSE).is_some_and(|v| v == "true");

        let usage = if is_sse {
            extract_from_sse(library_provider, bytes)
        } else {
            extract_token_usage(library_provider, bytes)
        };

        match usage {
            Some(u) => {
                set_token_usage(ctx, u.input_tokens(), u.output_tokens(), Some(u.total_tokens()));
                trace!(
                    input = u.input_tokens(),
                    output = u.output_tokens(),
                    total = u.total_tokens(),
                    "token usage written to FilterContext"
                );
            },
            None => {
                trace!("no token usage found in provider response; FilterContext not updated");
            },
        }

        Ok(FilterAction::Continue)
    }
}

/// Reads Bedrock InvokeModel token counts from response headers; no-op if either is absent.
fn extract_bedrock_headers(ctx: &mut HttpFilterContext<'_>) {
    let input = ctx
        .response_header
        .as_ref()
        .and_then(|r| r.headers.get(HEADER_BEDROCK_INPUT))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    let output = ctx
        .response_header
        .as_ref()
        .and_then(|r| r.headers.get(HEADER_BEDROCK_OUTPUT))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    let (Some(input), Some(output)) = (input, output) else {
        trace!("Bedrock InvokeModel token headers not present or unparseable");
        return;
    };

    set_token_usage(ctx, input, output, None);
    trace!(input, output, "Bedrock InvokeModel token counts extracted from response headers");
}

/// Dispatches SSE body to the appropriate provider extractor.
fn extract_from_sse(provider: TokenUsageProvider, data: &[u8]) -> Option<TokenUsage> {
    match provider {
        TokenUsageProvider::Anthropic => extract_anthropic_sse(data),
        _ => extract_last_usage_from_sse(provider, data),
    }
}

/// Returns token usage from the last parseable `data:` line; skips `[DONE]`.
fn extract_last_usage_from_sse(provider: TokenUsageProvider, data: &[u8]) -> Option<TokenUsage> {
    let text = std::str::from_utf8(data).ok()?;
    let mut last: Option<TokenUsage> = None;
    for line in text.lines() {
        let Some(json) = line.strip_prefix("data:").map(|s| s.trim_start()) else {
            continue;
        };
        if json == "[DONE]" {
            continue;
        }
        if let Some(usage) = extract_token_usage(provider, json.as_bytes()) {
            last = Some(usage);
        }
    }
    last
}

#[derive(Deserialize)]
struct AnthropicMessageStart {
    #[serde(rename = "type")]
    event_type: String,
    message: Option<AnthropicStartMessage>,
}

#[derive(Deserialize)]
struct AnthropicStartMessage {
    usage: Option<AnthropicStartUsage>,
}

#[derive(Deserialize)]
struct AnthropicStartUsage {
    input_tokens: u64,
}

#[derive(Deserialize)]
struct AnthropicMessageDelta {
    #[serde(rename = "type")]
    event_type: String,
    usage: Option<AnthropicDeltaUsage>,
}

#[derive(Deserialize)]
struct AnthropicDeltaUsage {
    output_tokens: u64,
}

/// Extracts Anthropic SSE token usage from `message_start` and `message_delta` events.
fn extract_anthropic_sse(data: &[u8]) -> Option<TokenUsage> {
    let text = std::str::from_utf8(data).ok()?;
    let mut input_tokens: Option<u64> = None;
    let mut output_tokens: Option<u64> = None;

    for line in text.lines() {
        let Some(json) = line.strip_prefix("data:").map(|s| s.trim_start()) else {
            continue;
        };

        if input_tokens.is_none()
            && let Ok(event) = serde_json::from_str::<AnthropicMessageStart>(json)
            && event.event_type == "message_start"
            && let Some(msg) = event.message
            && let Some(usage) = msg.usage
        {
            input_tokens = Some(usage.input_tokens);
        }

        if output_tokens.is_none()
            && let Ok(event) = serde_json::from_str::<AnthropicMessageDelta>(json)
            && event.event_type == "message_delta"
            && let Some(usage) = event.usage
        {
            output_tokens = Some(usage.output_tokens);
        }
    }

    let (Some(input), Some(output)) = (input_tokens, output_tokens) else {
        return None;
    };

    Some(TokenUsage::new(input, output, None))
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::test_utils::{make_filter_context, make_request};

    #[test]
    fn from_config_openai() {
        let yaml = serde_yaml::from_str("provider: openai").unwrap();
        let filter = TokenCountFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "token_count");
    }

    #[test]
    fn from_config_anthropic() {
        let yaml = serde_yaml::from_str("provider: anthropic").unwrap();
        let filter = TokenCountFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "token_count");
    }

    #[test]
    fn from_config_google() {
        let yaml = serde_yaml::from_str("provider: google").unwrap();
        let filter = TokenCountFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "token_count");
    }

    #[test]
    fn from_config_bedrock() {
        let yaml = serde_yaml::from_str("provider: bedrock").unwrap();
        let filter = TokenCountFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "token_count");
    }

    #[test]
    fn from_config_bedrock_invoke_model() {
        let yaml = serde_yaml::from_str("provider: bedrock_invoke_model").unwrap();
        let filter = TokenCountFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "token_count");
    }

    #[test]
    fn from_config_azure() {
        let yaml = serde_yaml::from_str("provider: azure").unwrap();
        let filter = TokenCountFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "token_count");
    }

    #[test]
    fn from_config_missing_provider_fails() {
        let yaml = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let result = TokenCountFilter::from_config(&yaml);
        assert!(result.is_err(), "missing provider should fail");
    }

    #[test]
    fn from_config_unknown_provider_fails() {
        let yaml = serde_yaml::from_str("provider: unknown_ai").unwrap();
        let result = TokenCountFilter::from_config(&yaml);
        assert!(result.is_err(), "unknown provider should fail");
    }

    #[test]
    fn from_config_unknown_key_fails() {
        let yaml = serde_yaml::from_str("provider: openai\nwrong_key: true").unwrap();
        let result = TokenCountFilter::from_config(&yaml);
        assert!(result.is_err(), "unknown keys should be rejected");
    }

    #[tokio::test]
    async fn extracts_openai_json_body() {
        let filter = TokenCountFilter { provider: ProviderKind::OpenAi };
        let body_bytes =
            br#"{"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}"#.to_vec();
        let mut body = Some(Bytes::from(body_bytes));

        let req = make_request(http::Method::POST, "/v1/chat/completions");
        let mut ctx = make_filter_context(&req);

        filter.on_response_body(&mut ctx, &mut body, true).unwrap();

        assert_eq!(ctx.get_metadata("token.input"), Some("10"));
        assert_eq!(ctx.get_metadata("token.output"), Some("20"));
        assert_eq!(ctx.get_metadata("token.total"), Some("30"));
    }

    #[tokio::test]
    async fn extracts_google_json_body() {
        let filter = TokenCountFilter { provider: ProviderKind::Google };
        let body_bytes =
            br#"{"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":15,"totalTokenCount":20}}"#
                .to_vec();
        let mut body = Some(Bytes::from(body_bytes));

        let req = make_request(http::Method::POST, "/v1/models/gemini/generate");
        let mut ctx = make_filter_context(&req);

        filter.on_response_body(&mut ctx, &mut body, true).unwrap();

        assert_eq!(ctx.get_metadata("token.input"), Some("5"));
        assert_eq!(ctx.get_metadata("token.output"), Some("15"));
        assert_eq!(ctx.get_metadata("token.total"), Some("20"));
    }

    #[tokio::test]
    async fn no_usage_field_leaves_context_empty() {
        let filter = TokenCountFilter { provider: ProviderKind::OpenAi };
        let mut body = Some(Bytes::from_static(b"{}"));

        let req = make_request(http::Method::POST, "/v1/chat");
        let mut ctx = make_filter_context(&req);

        filter.on_response_body(&mut ctx, &mut body, true).unwrap();

        assert!(ctx.get_metadata("token.input").is_none());
        assert!(ctx.get_metadata("token.output").is_none());
        assert!(ctx.get_metadata("token.total").is_none());
    }

    #[tokio::test]
    async fn skips_when_not_end_of_stream() {
        let filter = TokenCountFilter { provider: ProviderKind::OpenAi };
        let mut body = Some(Bytes::from_static(b"partial"));

        let req = make_request(http::Method::POST, "/v1/chat");
        let mut ctx = make_filter_context(&req);

        let action = filter.on_response_body(&mut ctx, &mut body, false).unwrap();
        assert!(matches!(action, FilterAction::Continue));
        assert!(ctx.get_metadata("token.input").is_none());
    }

    #[test]
    fn extract_last_usage_openai_sse() {
        let sse = b"data: {\"choices\":[]}\n\
                    data: {\"choices\":[],\"usage\":{\"prompt_tokens\":15,\"completion_tokens\":25,\"total_tokens\":40}}\n\
                    data: [DONE]\n";
        let usage = extract_last_usage_from_sse(TokenUsageProvider::OpenAi, sse).unwrap();
        assert_eq!(usage.input_tokens(), 15);
        assert_eq!(usage.output_tokens(), 25);
        assert_eq!(usage.total_tokens(), 40);
    }

    #[test]
    fn extract_last_usage_returns_last_valid() {
        let sse = b"data: {\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":5}}\n\
                    data: {\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":20}}\n";
        let usage = extract_last_usage_from_sse(TokenUsageProvider::OpenAi, sse).unwrap();
        assert_eq!(usage.input_tokens(), 10, "should return last valid chunk");
        assert_eq!(usage.output_tokens(), 20);
    }

    #[test]
    fn extract_last_usage_skips_done_sentinel() {
        let sse = b"data: {\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":12}}\n\
                    data: [DONE]\n";
        let usage = extract_last_usage_from_sse(TokenUsageProvider::OpenAi, sse).unwrap();
        assert_eq!(usage.input_tokens(), 8);
        assert_eq!(usage.output_tokens(), 12);
    }

    #[test]
    fn extract_last_usage_no_data_lines_returns_none() {
        let sse = b"event: start\nretry: 1000\n";
        let result = extract_last_usage_from_sse(TokenUsageProvider::OpenAi, sse);
        assert!(result.is_none());
    }

    #[test]
    fn extract_anthropic_sse_happy_path() {
        let sse = b"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":12,\"output_tokens\":0}}}\n\
                    data: {\"type\":\"content_block_start\"}\n\
                    data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":34}}\n\
                    data: {\"type\":\"message_stop\"}\n";
        let usage = extract_anthropic_sse(sse).unwrap();
        assert_eq!(usage.input_tokens(), 12);
        assert_eq!(usage.output_tokens(), 34);
        assert_eq!(usage.total_tokens(), 46);
    }

    #[test]
    fn extract_anthropic_sse_missing_message_delta_returns_none() {
        let sse =
            b"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n";
        let result = extract_anthropic_sse(sse);
        assert!(result.is_none(), "missing message_delta should return None");
    }

    #[test]
    fn extract_anthropic_sse_missing_message_start_returns_none() {
        let sse = b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":20}}\n";
        let result = extract_anthropic_sse(sse);
        assert!(result.is_none(), "missing message_start should return None");
    }

    #[tokio::test]
    async fn extracts_bedrock_invoke_model_from_headers() {
        let filter = TokenCountFilter { provider: ProviderKind::BedrockInvokeModel };
        let req = make_request(http::Method::POST, "/model/amazon.titan/invoke");
        let mut ctx = make_filter_context(&req);

        let mut resp = crate::test_utils::make_response();
        resp.headers
            .insert("x-amzn-bedrock-input-token-count", "25".parse().unwrap());
        resp.headers
            .insert("x-amzn-bedrock-output-token-count", "50".parse().unwrap());
        ctx.response_header = Some(&mut resp);

        filter.on_response(&mut ctx).await.unwrap();
        ctx.response_header = None;

        assert_eq!(ctx.get_metadata("token.input"), Some("25"));
        assert_eq!(ctx.get_metadata("token.output"), Some("50"));
        assert_eq!(ctx.get_metadata("token.total"), Some("75"));
    }

    #[tokio::test]
    async fn bedrock_headers_absent_is_noop() {
        let filter = TokenCountFilter { provider: ProviderKind::BedrockInvokeModel };
        let req = make_request(http::Method::POST, "/model/amazon.titan/invoke");
        let mut ctx = make_filter_context(&req);

        let mut resp = crate::test_utils::make_response();
        ctx.response_header = Some(&mut resp);

        filter.on_response(&mut ctx).await.unwrap();
        ctx.response_header = None;

        assert!(ctx.get_metadata("token.input").is_none());
        assert!(ctx.get_metadata("token.output").is_none());
        assert!(ctx.get_metadata("token.total").is_none());
    }

    #[tokio::test]
    async fn bedrock_only_input_header_is_noop() {
        let filter = TokenCountFilter { provider: ProviderKind::BedrockInvokeModel };
        let req = make_request(http::Method::POST, "/model/amazon.titan/invoke");
        let mut ctx = make_filter_context(&req);

        let mut resp = crate::test_utils::make_response();
        resp.headers
            .insert("x-amzn-bedrock-input-token-count", "25".parse().unwrap());
        ctx.response_header = Some(&mut resp);

        filter.on_response(&mut ctx).await.unwrap();
        ctx.response_header = None;

        assert!(ctx.get_metadata("token.input").is_none(), "partial headers should not write metadata");
        assert!(ctx.get_metadata("token.output").is_none());
        assert!(ctx.get_metadata("token.total").is_none());
    }

    #[tokio::test]
    async fn bedrock_only_output_header_is_noop() {
        let filter = TokenCountFilter { provider: ProviderKind::BedrockInvokeModel };
        let req = make_request(http::Method::POST, "/model/amazon.titan/invoke");
        let mut ctx = make_filter_context(&req);

        let mut resp = crate::test_utils::make_response();
        resp.headers
            .insert("x-amzn-bedrock-output-token-count", "50".parse().unwrap());
        ctx.response_header = Some(&mut resp);

        filter.on_response(&mut ctx).await.unwrap();
        ctx.response_header = None;

        assert!(ctx.get_metadata("token.input").is_none(), "partial headers should not write metadata");
        assert!(ctx.get_metadata("token.output").is_none());
        assert!(ctx.get_metadata("token.total").is_none());
    }

    #[tokio::test]
    async fn on_response_sets_sse_flag_for_event_stream() {
        let filter = TokenCountFilter { provider: ProviderKind::OpenAi };
        let req = make_request(http::Method::POST, "/v1/chat/completions");
        let mut ctx = make_filter_context(&req);

        let mut resp = crate::test_utils::make_response();
        resp.headers
            .insert("content-type", "text/event-stream".parse().unwrap());
        ctx.response_header = Some(&mut resp);

        filter.on_response(&mut ctx).await.unwrap();
        ctx.response_header = None;

        assert_eq!(ctx.get_metadata(META_IS_SSE), Some("true"));
    }

    #[tokio::test]
    async fn on_response_no_sse_flag_for_json() {
        let filter = TokenCountFilter { provider: ProviderKind::OpenAi };
        let req = make_request(http::Method::POST, "/v1/chat/completions");
        let mut ctx = make_filter_context(&req);

        let mut resp = crate::test_utils::make_response();
        resp.headers
            .insert("content-type", "application/json".parse().unwrap());
        ctx.response_header = Some(&mut resp);

        filter.on_response(&mut ctx).await.unwrap();
        ctx.response_header = None;

        assert!(ctx.get_metadata(META_IS_SSE).is_none());
    }
}
