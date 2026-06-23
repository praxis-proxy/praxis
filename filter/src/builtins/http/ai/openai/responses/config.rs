// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration types for the Responses format classifier filter.

use serde::Deserialize;

use crate::{
    FilterError,
    builtins::http::ai::{
        OnInvalidBehavior,
        config_validation::{validate_header_name, validate_max_body_bytes},
    },
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default maximum request body size for `StreamBuffer` mode (10 MiB).
///
/// Matches the shared default for JSON body inspection filters.
/// Operators needing larger payloads (e.g. inline file data URLs) can
/// override via `max_body_bytes` in config.
const DEFAULT_MAX_BODY_BYTES: usize = 10_485_760; // 10 MiB

// -----------------------------------------------------------------------------
// Behavior Enums
// -----------------------------------------------------------------------------


// -----------------------------------------------------------------------------
// ResponsesFormatHeaders
// -----------------------------------------------------------------------------

/// Configurable header names for promoted classification facts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResponsesFormatHeaders {
    /// Header name for the detected format (e.g. `openai_responses`, `openai_chat_completions`).
    #[serde(default = "default_format_header")]
    pub format: Option<String>,

    /// Header name for the extracted model value.
    #[serde(default = "default_model_header")]
    pub model: Option<String>,

    /// Header name for the extracted stream flag.
    #[serde(default = "default_stream_header")]
    pub stream: Option<String>,

    /// Header name for the computed mode (`stateless` or `stateful`).
    #[serde(default = "default_mode_header")]
    pub mode: Option<String>,
}

impl Default for ResponsesFormatHeaders {
    fn default() -> Self {
        Self {
            format: default_format_header(),
            model: default_model_header(),
            stream: default_stream_header(),
            mode: default_mode_header(),
        }
    }
}

/// Default format header name.
#[expect(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_format_header() -> Option<String> {
    Some("x-praxis-ai-format".to_owned())
}

/// Default model header name.
#[expect(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_model_header() -> Option<String> {
    Some("x-praxis-ai-model".to_owned())
}

/// Default stream header name.
#[expect(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_stream_header() -> Option<String> {
    Some("x-praxis-ai-stream".to_owned())
}

/// Default mode header name.
#[expect(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_mode_header() -> Option<String> {
    Some("x-praxis-responses-mode".to_owned())
}

// -----------------------------------------------------------------------------
// ResponsesFormatConfig
// -----------------------------------------------------------------------------

/// YAML configuration for the [`ResponsesFormatFilter`].
///
/// [`ResponsesFormatFilter`]: super::ResponsesFormatFilter
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResponsesFormatConfig {
    /// Behavior when the body cannot be classified.
    #[serde(default = "OnInvalidBehavior::default_continue")]
    pub on_invalid: OnInvalidBehavior,

    /// Maximum body size in bytes for `StreamBuffer` mode.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Header names for promoted classification facts.
    #[serde(default)]
    pub headers: ResponsesFormatHeaders,
}

/// Default max body bytes.
fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

/// Validate the parsed configuration.
pub(crate) fn build_config(cfg: ResponsesFormatConfig) -> Result<ResponsesFormatConfig, FilterError> {
    validate_max_body_bytes("openai_responses_format", cfg.max_body_bytes)?;

    validate_header_name("openai_responses_format", "format", cfg.headers.format.as_deref())?;
    validate_header_name("openai_responses_format", "model", cfg.headers.model.as_deref())?;
    validate_header_name("openai_responses_format", "stream", cfg.headers.stream.as_deref())?;
    validate_header_name("openai_responses_format", "mode", cfg.headers.mode.as_deref())?;

    Ok(cfg)
}
