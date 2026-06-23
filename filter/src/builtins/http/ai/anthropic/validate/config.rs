// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration for the Anthropic request validation filter.

use serde::Deserialize;

use crate::{FilterError, builtins::http::ai::config_validation::validate_max_body_bytes};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default maximum request body size for validation buffering.
///
/// Validation only needs the top-level JSON envelope, so the
/// default stays below the shared JSON inspection ceiling. Users
/// can raise it up to `MAX_JSON_BODY_BYTES` (64 MiB) when they need to
/// accept larger Anthropic request bodies.
const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576; // 1 MiB

// -----------------------------------------------------------------------------
// AnthropicValidateConfig
// -----------------------------------------------------------------------------

/// YAML configuration for the [`AnthropicValidateFilter`].
///
/// [`AnthropicValidateFilter`]: super::AnthropicValidateFilter
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnthropicValidateConfig {
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
pub(crate) fn build_config(cfg: AnthropicValidateConfig) -> Result<AnthropicValidateConfig, FilterError> {
    validate_max_body_bytes("anthropic_validate", cfg.max_body_bytes)?;
    Ok(cfg)
}
