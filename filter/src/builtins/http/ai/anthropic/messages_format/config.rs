// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration types for the Anthropic Messages format classifier filter.

use serde::Deserialize;

use crate::{FilterError, body::limits::MAX_JSON_BODY_BYTES};

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

/// Behavior when the request body is not a recognized AI API format.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OnInvalidBehavior {
    /// Continue processing.
    #[default]
    Continue,

    /// Reject the request with HTTP 400.
    Reject,
}

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
#[allow(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_format_header() -> Option<String> {
    Some("x-praxis-ai-format".to_owned())
}

/// Default model header name.
#[allow(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_model_header() -> Option<String> {
    Some("x-praxis-ai-model".to_owned())
}

/// Default stream header name.
#[allow(
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
    #[serde(default)]
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
    if cfg.max_body_bytes == 0 {
        return Err("anthropic_messages_format: 'max_body_bytes' must be greater than 0".into());
    }
    if cfg.max_body_bytes > MAX_JSON_BODY_BYTES {
        return Err(format!(
            "anthropic_messages_format: max_body_bytes ({}) exceeds maximum ({MAX_JSON_BODY_BYTES})",
            cfg.max_body_bytes
        )
        .into());
    }

    validate_header_name("format", cfg.headers.format.as_deref())?;
    validate_header_name("model", cfg.headers.model.as_deref())?;
    validate_header_name("stream", cfg.headers.stream.as_deref())?;

    Ok(cfg)
}

/// Validate a configured header name.
fn validate_header_name(field: &str, header_name: Option<&str>) -> Result<(), FilterError> {
    let Some(header_name) = header_name else {
        return Ok(());
    };
    if header_name.is_empty() {
        return Err(format!("anthropic_messages_format: {field} header name must not be empty").into());
    }
    if http::HeaderName::from_bytes(header_name.as_bytes()).is_err() {
        return Err(format!("anthropic_messages_format: {field} header name is not a valid HTTP header name").into());
    }
    Ok(())
}
