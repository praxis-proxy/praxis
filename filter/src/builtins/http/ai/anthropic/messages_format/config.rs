// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration types for the Anthropic Messages format classifier filter.

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

/// Default maximum request body size for `StreamBuffer` mode (1 MiB).
///
/// Smaller than the OpenAI Responses default (10 MiB) because Anthropic
/// Messages API payloads are typically text-only and do not carry inline
/// file data URLs.  Operators needing larger payloads can override via
/// `max_body_bytes` in config.
const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576; // 1 MiB

// -----------------------------------------------------------------------------
// Behavior Enums
// -----------------------------------------------------------------------------


// -----------------------------------------------------------------------------
// AnthropicMessagesFormatHeaders
// -----------------------------------------------------------------------------

/// Configurable header names for promoted classification facts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnthropicMessagesFormatHeaders {
    /// Header name for the detected format.
    #[serde(default = "default_format_header")]
    pub format: Option<String>,

    /// Header name for the extracted model value.
    #[serde(default = "default_model_header")]
    pub model: Option<String>,

    /// Header name for the extracted stream flag.
    #[serde(default = "default_stream_header")]
    pub stream: Option<String>,
}

impl Default for AnthropicMessagesFormatHeaders {
    fn default() -> Self {
        Self {
            format: default_format_header(),
            model: default_model_header(),
            stream: default_stream_header(),
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

// -----------------------------------------------------------------------------
// AnthropicMessagesFormatConfig
// -----------------------------------------------------------------------------

/// YAML configuration for the [`AnthropicMessagesFormatFilter`].
///
/// [`AnthropicMessagesFormatFilter`]: super::AnthropicMessagesFormatFilter
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnthropicMessagesFormatConfig {
    /// Behavior when the body cannot be classified.
    #[serde(default = "OnInvalidBehavior::default_continue")]
    pub on_invalid: OnInvalidBehavior,

    /// Maximum body size in bytes for `StreamBuffer` mode.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Header names for promoted classification facts.
    #[serde(default)]
    pub headers: AnthropicMessagesFormatHeaders,
}

/// Default max body bytes.
fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

/// Validate the parsed configuration.
pub(crate) fn build_config(cfg: AnthropicMessagesFormatConfig) -> Result<AnthropicMessagesFormatConfig, FilterError> {
    validate_max_body_bytes("anthropic_messages_format", cfg.max_body_bytes)?;

    validate_header_name("anthropic_messages_format", "format", cfg.headers.format.as_deref())?;
    validate_header_name("anthropic_messages_format", "model", cfg.headers.model.as_deref())?;
    validate_header_name("anthropic_messages_format", "stream", cfg.headers.stream.as_deref())?;

    Ok(cfg)
}
