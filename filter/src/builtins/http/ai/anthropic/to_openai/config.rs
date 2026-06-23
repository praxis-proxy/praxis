// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration for the Anthropic-to-Chat-Completions transformation filter.

use serde::Deserialize;

use crate::{FilterError, builtins::http::ai::config_validation::validate_max_body_bytes};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default maximum request body size (1 MiB).
const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576; // 1 MiB

// -----------------------------------------------------------------------------
// AnthropicToOpenaiConfig
// -----------------------------------------------------------------------------

/// YAML configuration for the [`AnthropicToOpenaiFilter`].
///
/// [`AnthropicToOpenaiFilter`]: super::AnthropicToOpenaiFilter
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnthropicToOpenaiConfig {
    /// Maximum body size in bytes for `StreamBuffer` mode.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
}

/// Default max body bytes.
fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

/// Validate the parsed configuration.
pub(crate) fn build_config(cfg: AnthropicToOpenaiConfig) -> Result<AnthropicToOpenaiConfig, FilterError> {
    validate_max_body_bytes("anthropic_to_openai", cfg.max_body_bytes)?;
    Ok(cfg)
}
