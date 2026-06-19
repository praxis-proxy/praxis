// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration for the Anthropic request validation filter.

use serde::Deserialize;

use crate::{FilterError, body::limits::MAX_JSON_BODY_BYTES};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default maximum request body size for validation buffering.
///
/// Validation only needs the top-level JSON envelope, so the
/// default stays below the shared JSON inspection ceiling. Users
/// can raise it up to [`MAX_JSON_BODY_BYTES`] when they need to
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
    if cfg.max_body_bytes == 0 {
        return Err("anthropic_validate: 'max_body_bytes' must be greater than 0".into());
    }
    if cfg.max_body_bytes > MAX_JSON_BODY_BYTES {
        return Err(format!(
            "anthropic_validate: max_body_bytes ({}) exceeds maximum ({MAX_JSON_BODY_BYTES})",
            cfg.max_body_bytes
        )
        .into());
    }
    Ok(cfg)
}
