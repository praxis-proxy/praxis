// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration for the Anthropic Messages protocol filter.

use serde::Deserialize;

use crate::FilterError;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default Anthropic API version header value.
const DEFAULT_VERSION: &str = "2023-06-01";

// -----------------------------------------------------------------------------
// AnthropicMessagesProtocolConfig
// -----------------------------------------------------------------------------

/// YAML configuration for the [`AnthropicMessagesProtocolFilter`].
///
/// [`AnthropicMessagesProtocolFilter`]: super::AnthropicMessagesProtocolFilter
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnthropicMessagesProtocolConfig {
    /// Default `anthropic-version` header value when absent.
    #[serde(default = "default_version")]
    pub default_version: String,
}

/// Default version string.
fn default_version() -> String {
    DEFAULT_VERSION.to_owned()
}

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

/// Validate the parsed configuration.
pub(crate) fn build_config(
    cfg: AnthropicMessagesProtocolConfig,
) -> Result<AnthropicMessagesProtocolConfig, FilterError> {
    if cfg.default_version.is_empty() {
        return Err("anthropic_messages_protocol: 'default_version' must not be empty".into());
    }
    http::HeaderValue::from_str(&cfg.default_version).map_err(|e| -> FilterError {
        format!("anthropic_messages_protocol: 'default_version' must be a valid header value: {e}").into()
    })?;
    Ok(cfg)
}
