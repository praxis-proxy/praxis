// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Responses API filters: format classifier and request validation.
//!
//! Classifies requests as Responses API, Chat Completions, unknown
//! JSON, invalid JSON, or non-JSON. Requests matching Responses API
//! sub-resource paths (`/v1/responses/{id}`,
//! `/v1/responses/{id}/input_items`, `/v1/responses/{id}/cancel`,
//! `/v1/responses/input_tokens`, `/v1/responses/compact`) are
//! classified by method and path without inspecting the body.
//! `POST /v1/responses` (create) is classified by body content.
//! Promotes classification facts to configurable headers, durable
//! metadata, and filter results for routing. Does not mutate the
//! request body.
//!
//! The `openai_responses_validate` filter runs after the classifier
//! to validate parameter combinations and extract additional fields.

pub(crate) mod classifier;
mod config;
#[allow(
    dead_code,
    reason = "store utilities for GET (#458) and DELETE (#459) response endpoints"
)]
pub(crate) mod store;

pub use store::ResponseStoreFilter;

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

use self::{
    classifier::{AiRequestFormat, classify_request_body, is_responses_path},
    config::{OnInvalidBehavior, ResponsesFormatConfig, build_config},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum length of a body-derived value promoted to headers or filter results.
const MAX_PROMOTED_VALUE_LEN: usize = 256;
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    builtins::http::value_safety::is_safe_promoted_value,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// ResponsesFormatFilter
// -----------------------------------------------------------------------------

/// Classifies AI API request bodies and promotes routing facts to
/// headers, metadata, and filter results without mutating the body.
///
/// # YAML
///
/// ```yaml
/// filter: openai_responses_format
/// ```
///
/// # Full YAML
///
/// ```yaml
/// filter: openai_responses_format
/// on_invalid: continue
/// max_body_bytes: 67108864
/// headers:
///   format: x-praxis-ai-format
///   model: x-praxis-ai-model
///   stream: x-praxis-ai-stream
///   mode: x-praxis-responses-mode
/// ```
pub struct ResponsesFormatFilter {
    /// Parsed and validated configuration.
    config: ResponsesFormatConfig,
}

impl ResponsesFormatFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: ResponsesFormatConfig = parse_filter_config("openai_responses_format", config)?;
        let validated = build_config(cfg)?;
        Ok(Box::new(Self { config: validated }))
    }
}

#[async_trait]
impl HttpFilter for ResponsesFormatFilter {
    fn name(&self) -> &'static str {
        "openai_responses_format"
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

        let classified = if is_responses_path(&ctx.request.method, ctx.request.uri.path()) {
            debug!(
                method = %ctx.request.method,
                path = ctx.request.uri.path(),
                "classified request by method and path"
            );
            classifier::empty_result(AiRequestFormat::Responses)
        } else {
            classify_request_body(bytes)
        };

        debug!(
            format = classified.format.as_str(),
            model = ?classified.model,
            "classified request body"
        );

        if let Some(action) = handle_invalid_format(classified.format, &self.config) {
            return Ok(action);
        }

        let mode = compute_mode(&classified);

        write_metadata(ctx, &classified, mode);
        promote_headers(ctx, &classified, &self.config, mode);
        promote_filter_results(ctx, &classified, mode)?;

        Ok(FilterAction::Release)
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Check whether the format requires rejection.
fn handle_invalid_format(format: AiRequestFormat, config: &ResponsesFormatConfig) -> Option<FilterAction> {
    match config.on_invalid {
        OnInvalidBehavior::Continue => None,
        OnInvalidBehavior::Reject => {
            let message = match format {
                AiRequestFormat::InvalidJson => "invalid JSON body",
                AiRequestFormat::NonJson => "request body is not JSON",
                AiRequestFormat::UnknownJson => "unrecognized AI API format",
                AiRequestFormat::Responses | AiRequestFormat::ChatCompletions => return None,
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

/// Determine the routing mode for a Responses API request.
///
/// Returns `Some("stateful")` when the request needs orchestration
/// (conversation history, tools, persistence, or background processing)
/// and `Some("stateless")` when it can be forwarded directly to a
/// native Responses backend. Returns `None` for non-Responses formats.
fn compute_mode(classified: &classifier::ClassifiedRequest) -> Option<&'static str> {
    if classified.format != AiRequestFormat::Responses {
        return None;
    }
    // OpenAI spec: store defaults to true when omitted
    let stateful = classified.has_previous_response_id
        || classified.has_tools
        || classified.store.unwrap_or(true)
        || classified.background == Some(true)
        || classified.has_conversation
        || classified.has_prompt_id;
    Some(if stateful { "stateful" } else { "stateless" })
}

/// Write durable metadata that persists across all Pingora lifecycle phases.
fn write_metadata(ctx: &mut HttpFilterContext<'_>, classified: &classifier::ClassifiedRequest, mode: Option<&str>) {
    ctx.set_metadata("openai_responses_format.format", classified.format.as_str());
    write_optional_metadata(ctx, classified);
    write_boolean_metadata(ctx, classified);

    if let Some(m) = mode {
        ctx.set_metadata("openai_responses_format.mode", m);
    }
}

/// Write optional string and boolean-option metadata fields.
fn write_optional_metadata(ctx: &mut HttpFilterContext<'_>, classified: &classifier::ClassifiedRequest) {
    if let Some(model) = &classified.model
        && is_safe_promoted_value(model)
    {
        ctx.set_metadata("openai_responses_format.model", model.clone());
    }

    if let Some(stream) = classified.stream {
        ctx.set_metadata("openai_responses_format.stream", if stream { "true" } else { "false" });
    }

    if let Some(store) = classified.store {
        ctx.set_metadata("openai_responses_format.store", if store { "true" } else { "false" });
    }

    if let Some(background) = classified.background {
        ctx.set_metadata(
            "openai_responses_format.background",
            if background { "true" } else { "false" },
        );
    }
}

/// Write boolean presence flags to metadata.
fn write_boolean_metadata(ctx: &mut HttpFilterContext<'_>, classified: &classifier::ClassifiedRequest) {
    if classified.has_previous_response_id {
        ctx.set_metadata("openai_responses_format.has_previous_response_id", "true");
    }
    if classified.has_conversation {
        ctx.set_metadata("openai_responses_format.has_conversation", "true");
    }
    if classified.has_tools {
        ctx.set_metadata("openai_responses_format.has_tools", "true");
    }
    if classified.has_prompt_id {
        ctx.set_metadata("openai_responses_format.has_prompt_id", "true");
    }
}

/// Promote classification facts to configurable request headers.
fn promote_headers(
    ctx: &mut HttpFilterContext<'_>,
    classified: &classifier::ClassifiedRequest,
    config: &ResponsesFormatConfig,
    mode: Option<&str>,
) {
    if let Some(header) = &config.headers.format {
        let format_str = classified.format.as_str();
        ctx.extra_request_headers
            .push((Cow::Owned(header.clone()), format_str.to_owned()));
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

    if let Some(header) = &config.headers.mode
        && let Some(m) = mode
    {
        ctx.extra_request_headers
            .push((Cow::Owned(header.clone()), m.to_owned()));
    }
}

/// Promote classification facts to filter results for branch conditions.
fn promote_filter_results(
    ctx: &mut HttpFilterContext<'_>,
    classified: &classifier::ClassifiedRequest,
    mode: Option<&'static str>,
) -> Result<(), FilterError> {
    let results = ctx.filter_results.entry("openai_responses_format").or_default();

    results.set("format", classified.format.as_str())?;
    promote_optional_results(results, classified)?;
    promote_boolean_results(results, classified)?;

    if let Some(m) = mode {
        results.set("mode", m)?;
    }

    Ok(())
}

/// Promote optional string and boolean-option fields to filter results.
fn promote_optional_results(
    results: &mut crate::results::FilterResultSet,
    classified: &classifier::ClassifiedRequest,
) -> Result<(), FilterError> {
    if let Some(model) = &classified.model
        && is_safe_promoted_value(model)
        && model.len() <= MAX_PROMOTED_VALUE_LEN
    {
        results.set("model", model.clone())?;
    }

    if let Some(stream) = classified.stream {
        results.set("stream", if stream { "true" } else { "false" })?;
    }

    if let Some(store) = classified.store {
        results.set("store", if store { "true" } else { "false" })?;
    }

    if let Some(background) = classified.background {
        results.set("background", if background { "true" } else { "false" })?;
    }

    Ok(())
}

/// Promote boolean presence flags to filter results.
fn promote_boolean_results(
    results: &mut crate::results::FilterResultSet,
    classified: &classifier::ClassifiedRequest,
) -> Result<(), FilterError> {
    if classified.has_previous_response_id {
        results.set("has_previous_response_id", "true")?;
    }
    if classified.has_conversation {
        results.set("has_conversation", "true")?;
    }
    if classified.has_tools {
        results.set("has_tools", "true")?;
    }
    if classified.has_prompt_id {
        results.set("has_prompt_id", "true")?;
    }

    Ok(())
}

#[cfg(feature = "ai-inference")]
pub(crate) mod validate;

#[cfg(feature = "ai-inference")]
pub use validate::OpenaiResponsesValidateFilter;
