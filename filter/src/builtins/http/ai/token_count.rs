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
//! For Bedrock `InvokeModel`, body access is disabled entirely (`BodyAccess::None`,
//! `BodyMode::Stream`) since token counts arrive as HTTP response headers and
//! no body parsing is needed.
//!
//! Token counts are written as filter metadata under keys
//! `token.input`, `token.output`, and `token.total` via
//! [`set_token_usage`].
//!
//! [`set_token_usage`]: crate::context::HttpFilterContext::set_token_usage
//! [#220]: https://github.com/praxis-proxy/praxis/issues/220

use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;

use crate::{
    FilterAction, FilterError,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};
use super::token_usage::{TokenUsage, TokenUsageProvider, extract_token_usage, set_token_usage};

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
    /// AWS Bedrock `InvokeModel` API (HTTP response headers).
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
    /// AI provider whose response format to parse.
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

    /// Detect SSE responses and handle Bedrock `InvokeModel` header-based extraction.
    ///
    /// For Bedrock `InvokeModel`, token counts arrive as HTTP response headers
    /// (`x-amzn-bedrock-input-token-count`, `x-amzn-bedrock-output-token-count`)
    /// rather than in the JSON body. This is the only provider with a header-based
    /// extraction path.
    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let (is_sse, bedrock_counts) = {
            let Some(resp) = ctx.response_header.as_ref() else {
                return Ok(FilterAction::Continue);
            };
            let is_sse = resp
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|ct| ct.contains("text/event-stream"));
            let bedrock_counts = if self.provider == ProviderKind::BedrockInvokeModel {
                Some(bedrock_token_counts(resp))
            } else {
                None
            };
            (is_sse, bedrock_counts)
        };

        if is_sse {
            ctx.set_metadata(META_IS_SSE, "1".to_owned());
        }
        if let Some((Some(i), Some(o))) = bedrock_counts {
            set_token_usage(ctx, i, o, None);
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
            set_token_usage(ctx, u.input_tokens(), u.output_tokens(), Some(u.total_tokens()));
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
///
/// **Limitation:** assumes each SSE `data:` field is a single compact JSON
/// line. Multi-line pretty-printed payloads (e.g. `data: {\n  "usage": ...}`)
/// are not supported — the continuation lines lack the `data: ` prefix and
/// are silently skipped. In practice all supported providers send minified
/// single-line JSON in SSE data fields.
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
        let Some(json) = line.strip_prefix("data: ") else { continue };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else { continue };
        match v.get("type").and_then(|t| t.as_str()) {
            Some("message_start") => input_tokens = anthropic_input_tokens(&v),
            Some("message_delta") => output_tokens = anthropic_output_tokens(&v),
            _ => {}
        }
    }

    Some(TokenUsage::new(input_tokens?, output_tokens?, None))
}

/// Read `input_tokens` from an Anthropic `message_start` SSE event.
fn anthropic_input_tokens(v: &serde_json::Value) -> Option<u64> {
    v.get("message")
        .and_then(|m| m.get("usage"))
        .and_then(|u| u.get("input_tokens"))
        .and_then(serde_json::Value::as_u64)
}

/// Read `output_tokens` from an Anthropic `message_delta` SSE event.
fn anthropic_output_tokens(v: &serde_json::Value) -> Option<u64> {
    v.get("usage")
        .and_then(|u| u.get("output_tokens"))
        .and_then(serde_json::Value::as_u64)
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

/// Read Bedrock `InvokeModel` token counts from upstream response headers.
fn bedrock_token_counts(resp: &crate::context::Response) -> (Option<u64>, Option<u64>) {
    let input = resp
        .headers
        .get("x-amzn-bedrock-input-token-count")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let output = resp
        .headers
        .get("x-amzn-bedrock-output-token-count")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    (input, output)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

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
    use bytes::Bytes;

    use super::*;
    use crate::test_utils::{make_filter_context, make_request, make_response};

    // -------------------------------------------------------------------------
    // from_config
    // -------------------------------------------------------------------------

    #[test]
    fn from_config_all_providers_accepted() {
        for provider in &["openai", "anthropic", "google", "bedrock", "bedrock_invoke_model", "azure"] {
            let yaml = serde_yaml::from_str(&format!("provider: {provider}")).unwrap();
            let filter = TokenCountFilter::from_config(&yaml)
                .unwrap_or_else(|e| panic!("provider '{provider}' should be accepted: {e}"));
            assert_eq!(filter.name(), "token_count");
        }
    }

    #[test]
    fn from_config_unknown_provider_rejected() {
        let yaml = serde_yaml::from_str("provider: unknown_ai").unwrap();
        assert!(TokenCountFilter::from_config(&yaml).is_err(), "unknown provider should fail");
    }

    #[test]
    fn from_config_unknown_key_rejected() {
        let yaml = serde_yaml::from_str("provider: openai\nextra: true").unwrap();
        assert!(TokenCountFilter::from_config(&yaml).is_err(), "unknown keys should be rejected");
    }

    #[test]
    fn from_config_missing_provider_rejected() {
        let yaml = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        assert!(TokenCountFilter::from_config(&yaml).is_err(), "missing provider should fail");
    }

    // -------------------------------------------------------------------------
    // extract_last_usage_from_sse
    // -------------------------------------------------------------------------

    #[test]
    fn sse_last_usage_returns_last_valid_chunk() {
        let sse = "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":5}}\n\
                   data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":20,\"total_tokens\":30}}\n\
                   data: [DONE]\n";
        let u = extract_last_usage_from_sse(to_library_provider(ProviderKind::Openai), sse).unwrap();
        assert_eq!(u.input_tokens(), 10, "should use last valid chunk");
        assert_eq!(u.output_tokens(), 20);
        assert_eq!(u.total_tokens(), 30);
    }

    #[test]
    fn sse_last_usage_skips_done_sentinel() {
        let sse = "data: {\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":12}}\ndata: [DONE]\n";
        let u = extract_last_usage_from_sse(to_library_provider(ProviderKind::Openai), sse).unwrap();
        assert_eq!(u.input_tokens(), 8);
        assert_eq!(u.output_tokens(), 12);
    }

    #[test]
    fn sse_last_usage_skips_comment_and_empty_lines() {
        let sse = ": keep-alive\n\ndata: {\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":7}}\n";
        let u = extract_last_usage_from_sse(to_library_provider(ProviderKind::Openai), sse).unwrap();
        assert_eq!(u.input_tokens(), 3);
    }

    #[test]
    fn sse_last_usage_no_data_lines_returns_none() {
        let sse = "event: start\nretry: 1000\n: ping\n";
        assert!(
            extract_last_usage_from_sse(to_library_provider(ProviderKind::Openai), sse).is_none()
        );
    }

    #[test]
    fn sse_last_usage_all_lines_unparseable_returns_none() {
        let sse = "data: {\"choices\":[]}\ndata: not-json\ndata: [DONE]\n";
        assert!(
            extract_last_usage_from_sse(to_library_provider(ProviderKind::Openai), sse).is_none()
        );
    }

    #[test]
    fn sse_google_no_done_sentinel() {
        let sse = "data: {\"candidates\":[]}\n\
                   data: {\"candidates\":[],\"usageMetadata\":{\"promptTokenCount\":10,\"candidatesTokenCount\":20,\"totalTokenCount\":30}}\n";
        let u = extract_last_usage_from_sse(to_library_provider(ProviderKind::Google), sse).unwrap();
        assert_eq!(u.input_tokens(), 10);
        assert_eq!(u.output_tokens(), 20);
        assert_eq!(u.total_tokens(), 30);
    }

    // -------------------------------------------------------------------------
    // extract_anthropic_sse
    // -------------------------------------------------------------------------

    #[test]
    fn anthropic_sse_happy_path() {
        let sse = "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":12,\"output_tokens\":0}}}\n\
                   data: {\"type\":\"content_block_start\"}\n\
                   data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":34}}\n\
                   data: {\"type\":\"message_stop\"}\n";
        let u = extract_anthropic_sse(sse).unwrap();
        assert_eq!(u.input_tokens(), 12);
        assert_eq!(u.output_tokens(), 34);
        assert_eq!(u.total_tokens(), 46);
    }

    #[test]
    fn anthropic_sse_missing_message_start_returns_none() {
        let sse = "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":20}}\n";
        assert!(extract_anthropic_sse(sse).is_none(), "missing message_start → None");
    }

    #[test]
    fn anthropic_sse_missing_message_delta_returns_none() {
        let sse =
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n";
        assert!(extract_anthropic_sse(sse).is_none(), "missing message_delta → None");
    }

    #[test]
    fn anthropic_sse_malformed_json_skipped() {
        let sse = "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n\
                   data: not-json-at-all\n\
                   data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":15}}\n";
        let u = extract_anthropic_sse(sse).unwrap();
        assert_eq!(u.input_tokens(), 10);
        assert_eq!(u.output_tokens(), 15);
    }

    #[test]
    fn anthropic_sse_out_of_order_events_still_extracted() {
        // message_delta arrives before message_start — uncommon but the
        // scanner is order-independent so both values are collected.
        let sse = "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":25}}\n\
                   data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":8,\"output_tokens\":0}}}\n";
        let u = extract_anthropic_sse(sse).unwrap();
        assert_eq!(u.input_tokens(), 8);
        assert_eq!(u.output_tokens(), 25);
    }

    #[test]
    fn anthropic_sse_missing_input_tokens_field_returns_none() {
        // message_start present but no input_tokens inside usage.
        let sse = "data: {\"type\":\"message_start\",\"message\":{\"usage\":{}}}\n\
                   data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":20}}\n";
        assert!(extract_anthropic_sse(sse).is_none());
    }

    #[test]
    fn anthropic_sse_missing_output_tokens_field_returns_none() {
        let sse = "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n\
                   data: {\"type\":\"message_delta\",\"usage\":{}}\n";
        assert!(extract_anthropic_sse(sse).is_none());
    }

    // -------------------------------------------------------------------------
    // bedrock_token_counts
    // -------------------------------------------------------------------------

    #[test]
    fn bedrock_headers_both_present() {
        let mut resp = make_response();
        resp.headers.insert("x-amzn-bedrock-input-token-count", "15".parse().unwrap());
        resp.headers.insert("x-amzn-bedrock-output-token-count", "42".parse().unwrap());
        let (input, output) = bedrock_token_counts(&resp);
        assert_eq!(input, Some(15));
        assert_eq!(output, Some(42));
    }

    #[test]
    fn bedrock_headers_missing_input_returns_none() {
        let mut resp = make_response();
        resp.headers.insert("x-amzn-bedrock-output-token-count", "10".parse().unwrap());
        let (input, _) = bedrock_token_counts(&resp);
        assert!(input.is_none());
    }

    #[test]
    fn bedrock_headers_missing_output_returns_none() {
        let mut resp = make_response();
        resp.headers.insert("x-amzn-bedrock-input-token-count", "10".parse().unwrap());
        let (_, output) = bedrock_token_counts(&resp);
        assert!(output.is_none());
    }

    #[test]
    fn bedrock_headers_non_numeric_returns_none() {
        let mut resp = make_response();
        resp.headers.insert("x-amzn-bedrock-input-token-count", "not-a-number".parse().unwrap());
        resp.headers.insert("x-amzn-bedrock-output-token-count", "20".parse().unwrap());
        let (input, _) = bedrock_token_counts(&resp);
        assert!(input.is_none(), "non-numeric header value should parse to None");
    }

    // -------------------------------------------------------------------------
    // on_response_body
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn on_response_body_skips_when_not_end_of_stream() {
        let filter = TokenCountFilter { provider: ProviderKind::Openai };
        let req = make_request(http::Method::POST, "/v1/chat/completions");
        let mut ctx = make_filter_context(&req);
        let mut body = Some(Bytes::from_static(b"partial"));

        let action = filter.on_response_body(&mut ctx, &mut body, false).unwrap();
        assert!(matches!(action, FilterAction::Continue));
        assert!(ctx.get_metadata("token.input").is_none());
    }

    #[tokio::test]
    async fn on_response_body_skips_empty_body() {
        let filter = TokenCountFilter { provider: ProviderKind::Openai };
        let req = make_request(http::Method::POST, "/v1/chat/completions");
        let mut ctx = make_filter_context(&req);
        let mut body: Option<Bytes> = None;

        drop(filter.on_response_body(&mut ctx, &mut body, true).unwrap());
        assert!(ctx.get_metadata("token.input").is_none());
    }

    #[tokio::test]
    async fn on_response_body_extracts_openai_json() {
        let filter = TokenCountFilter { provider: ProviderKind::Openai };
        let req = make_request(http::Method::POST, "/v1/chat/completions");
        let mut ctx = make_filter_context(&req);
        let mut body = Some(Bytes::from_static(
            b"{\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":20,\"total_tokens\":30}}",
        ));

        drop(filter.on_response_body(&mut ctx, &mut body, true).unwrap());
        assert_eq!(ctx.get_metadata("token.input"), Some("10"));
        assert_eq!(ctx.get_metadata("token.output"), Some("20"));
        assert_eq!(ctx.get_metadata("token.total"), Some("30"));
    }

    #[tokio::test]
    async fn on_response_body_non_json_body_is_noop() {
        let filter = TokenCountFilter { provider: ProviderKind::Openai };
        let req = make_request(http::Method::POST, "/v1/chat/completions");
        let mut ctx = make_filter_context(&req);
        let mut body = Some(Bytes::from_static(b"Internal Server Error"));

        drop(filter.on_response_body(&mut ctx, &mut body, true).unwrap());
        assert!(ctx.get_metadata("token.input").is_none(), "non-JSON body must be a no-op");
    }

    // -------------------------------------------------------------------------
    // on_response — SSE flag and Bedrock header extraction
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn on_response_sets_sse_flag_for_event_stream() {
        let filter = TokenCountFilter { provider: ProviderKind::Openai };
        let req = make_request(http::Method::POST, "/v1/chat/completions");
        let mut ctx = make_filter_context(&req);

        let mut resp = make_response();
        resp.headers.insert("content-type", "text/event-stream".parse().unwrap());
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());
        ctx.response_header = None;

        assert_eq!(ctx.get_metadata(META_IS_SSE), Some("1"));
    }

    #[tokio::test]
    async fn on_response_no_sse_flag_for_json_content_type() {
        let filter = TokenCountFilter { provider: ProviderKind::Openai };
        let req = make_request(http::Method::POST, "/v1/chat/completions");
        let mut ctx = make_filter_context(&req);

        let mut resp = make_response();
        resp.headers.insert("content-type", "application/json".parse().unwrap());
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());
        ctx.response_header = None;

        assert!(ctx.get_metadata(META_IS_SSE).is_none());
    }

    #[tokio::test]
    async fn on_response_bedrock_invoke_model_extracts_from_headers() {
        let filter = TokenCountFilter { provider: ProviderKind::BedrockInvokeModel };
        let req = make_request(http::Method::POST, "/model/titan/invoke");
        let mut ctx = make_filter_context(&req);

        let mut resp = make_response();
        resp.headers.insert("x-amzn-bedrock-input-token-count", "25".parse().unwrap());
        resp.headers.insert("x-amzn-bedrock-output-token-count", "50".parse().unwrap());
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());
        ctx.response_header = None;

        assert_eq!(ctx.get_metadata("token.input"), Some("25"));
        assert_eq!(ctx.get_metadata("token.output"), Some("50"));
        assert_eq!(ctx.get_metadata("token.total"), Some("75"));
    }

    #[tokio::test]
    async fn on_response_bedrock_invoke_model_absent_headers_is_noop() {
        let filter = TokenCountFilter { provider: ProviderKind::BedrockInvokeModel };
        let req = make_request(http::Method::POST, "/model/titan/invoke");
        let mut ctx = make_filter_context(&req);

        let mut resp = make_response();
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());
        ctx.response_header = None;

        assert!(ctx.get_metadata("token.input").is_none());
    }
}
