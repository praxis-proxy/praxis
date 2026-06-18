// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Anthropic Messages API format classifier filter.
//!
//! Detects Anthropic Messages API requests using the shared
//! [`AiRequestFormat`] classifier and promotes routing facts to
//! configurable headers, durable metadata, and filter results.
//! Uses `anthropic-version` header as a boost signal when
//! body-only heuristics are ambiguous.
//!
//! [`AiRequestFormat`]: crate::builtins::http::ai::classifier::AiRequestFormat

mod config;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests;

use std::borrow::Cow;

use async_trait::async_trait;
use bytes::Bytes;
use tracing::{debug, trace};

use self::config::{AnthropicMessagesFormatConfig, OnInvalidBehavior, build_config};
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    builtins::http::{
        ai::classifier::{AiRequestFormat, ClassifiedRequest, classify_request_body},
        value_safety::is_safe_promoted_value,
    },
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum length of a body-derived value promoted to headers or filter results.
const MAX_PROMOTED_VALUE_LEN: usize = 256;

/// Header name sent by Anthropic SDK clients.
const ANTHROPIC_VERSION_HEADER: &str = "anthropic-version";

// -----------------------------------------------------------------------------
// AnthropicMessagesFormatFilter
// -----------------------------------------------------------------------------

/// Classifies Anthropic Messages API requests and promotes routing
/// facts to headers, metadata, and filter results.
///
/// # YAML
///
/// ```yaml
/// filter: anthropic_messages_format
/// ```
///
/// # Full YAML
///
/// ```yaml
/// filter: anthropic_messages_format
/// on_invalid: continue
/// max_body_bytes: 1048576
/// headers:
///   format: x-praxis-ai-format
///   model: x-praxis-ai-model
///   stream: x-praxis-ai-stream
/// ```
pub struct AnthropicMessagesFormatFilter {
    /// Parsed and validated configuration.
    config: AnthropicMessagesFormatConfig,
}

impl AnthropicMessagesFormatFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: AnthropicMessagesFormatConfig = parse_filter_config("anthropic_messages_format", config)?;
        let validated = build_config(cfg)?;
        Ok(Box::new(Self { config: validated }))
    }
}

#[async_trait]
impl HttpFilter for AnthropicMessagesFormatFilter {
    fn name(&self) -> &'static str {
        "anthropic_messages_format"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.config.max_body_bytes),
        }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        let bytes = match body.as_ref() {
            Some(b) => b.as_ref(),
            None => &[],
        };

        let mut classified = classify_request_body(bytes);

        let has_anthropic_header = ctx.request.headers.get(ANTHROPIC_VERSION_HEADER).is_some();
        let is_messages_path = is_anthropic_messages_path(ctx.request.uri.path());

        // Only ChatCompletions is eligible for reclassification: its
        // body shape (`messages` without required `max_tokens`) overlaps
        // with Anthropic Messages.  UnknownJson is not boosted because
        // the body lacked `messages` entirely, so the Anthropic signal
        // is too weak to override.
        if classified.format == AiRequestFormat::ChatCompletions && (has_anthropic_header || is_messages_path) {
            classified.format = AiRequestFormat::AnthropicMessages;
        }

        debug!(
            format = classified.format.as_str(),
            model = ?classified.model,
            anthropic_header = has_anthropic_header,
            messages_path = is_messages_path,
            "classified anthropic request body"
        );

        if let Some(action) = handle_invalid_format(classified.format, &self.config) {
            return Ok(action);
        }

        write_metadata(ctx, &classified);
        promote_headers(ctx, &classified, &self.config);
        promote_filter_results(ctx, &classified)?;

        Ok(FilterAction::Release)
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Check whether the format requires rejection.
fn handle_invalid_format(format: AiRequestFormat, config: &AnthropicMessagesFormatConfig) -> Option<FilterAction> {
    match config.on_invalid {
        OnInvalidBehavior::Continue => None,
        OnInvalidBehavior::Reject => {
            let message = match format {
                AiRequestFormat::InvalidJson => "invalid JSON body",
                AiRequestFormat::NonJson => "request body is not JSON",
                AiRequestFormat::UnknownJson => "unrecognized AI API format",
                AiRequestFormat::Responses | AiRequestFormat::AnthropicMessages | AiRequestFormat::ChatCompletions => {
                    return None;
                },
            };

            trace!(reason = message, "rejecting unrecognized body");
            Some(FilterAction::Reject(
                Rejection::status(400)
                    .with_header("content-type", "application/json")
                    .with_body(Bytes::from(format!(
                        r#"{{"error":{{"message":"{message}","type":"invalid_request_error"}}}}"#
                    ))),
            ))
        },
    }
}

/// Write durable metadata.
fn write_metadata(ctx: &mut HttpFilterContext<'_>, classified: &ClassifiedRequest) {
    ctx.set_metadata("anthropic_messages_format.format", classified.format.as_str());

    if let Some(model) = &classified.model
        && is_safe_promoted_value(model)
    {
        ctx.set_metadata("anthropic_messages_format.model", model.clone());
    }

    if let Some(stream) = classified.stream {
        ctx.set_metadata("anthropic_messages_format.stream", if stream { "true" } else { "false" });
    }

    if let Some(max_tokens) = classified.max_tokens {
        ctx.set_metadata("anthropic_messages_format.max_tokens", max_tokens.to_string());
    }

    if classified.has_tools {
        ctx.set_metadata("anthropic_messages_format.has_tools", "true");
    }
    if classified.has_prompt_id {
        ctx.set_metadata("anthropic_messages_format.has_prompt_id", "true");
    }
    if classified.has_conversation {
        ctx.set_metadata("anthropic_messages_format.has_conversation", "true");
    }
    if classified.has_previous_response_id {
        ctx.set_metadata("anthropic_messages_format.has_previous_response_id", "true");
    }
}

/// Promote classification facts to configurable request headers.
fn promote_headers(
    ctx: &mut HttpFilterContext<'_>,
    classified: &ClassifiedRequest,
    config: &AnthropicMessagesFormatConfig,
) {
    if let Some(header) = &config.headers.format {
        ctx.extra_request_headers
            .push((Cow::Owned(header.clone()), classified.format.as_str().to_owned()));
    }

    if let Some(header) = &config.headers.model
        && let Some(model) = &classified.model
        && is_safe_promoted_value(model)
        && model.len() <= MAX_PROMOTED_VALUE_LEN
    {
        ctx.extra_request_headers
            .push((Cow::Owned(header.clone()), model.clone()));
    }

    if let Some(header) = &config.headers.stream
        && let Some(stream) = classified.stream
    {
        let val = if stream { "true" } else { "false" };
        ctx.extra_request_headers
            .push((Cow::Owned(header.clone()), val.to_owned()));
    }
}

/// Check whether the path is the Anthropic Messages endpoint,
/// normalizing a trailing slash.
fn is_anthropic_messages_path(path: &str) -> bool {
    let normalized = path.strip_suffix('/').unwrap_or(path);
    normalized == "/v1/messages"
}

/// Promote classification facts to filter results for branch conditions.
fn promote_filter_results(ctx: &mut HttpFilterContext<'_>, classified: &ClassifiedRequest) -> Result<(), FilterError> {
    let results = ctx.filter_results.entry("anthropic_messages_format").or_default();

    results.set("format", classified.format.as_str())?;

    if let Some(model) = &classified.model
        && is_safe_promoted_value(model)
        && model.len() <= MAX_PROMOTED_VALUE_LEN
    {
        results.set("model", model.clone())?;
    }

    if let Some(stream) = classified.stream {
        results.set("stream", if stream { "true" } else { "false" })?;
    }

    if let Some(max_tokens) = classified.max_tokens {
        results.set("max_tokens", max_tokens.to_string())?;
    }

    if classified.has_tools {
        results.set("has_tools", "true")?;
    }
    if classified.has_prompt_id {
        results.set("has_prompt_id", "true")?;
    }
    if classified.has_conversation {
        results.set("has_conversation", "true")?;
    }
    if classified.has_previous_response_id {
        results.set("has_previous_response_id", "true")?;
    }

    Ok(())
}
