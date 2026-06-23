// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration for the Responses-to-Chat-Completions transformation filter.

use serde::Deserialize;

use crate::{
    FilterError, body::OPENAI_RESPONSES_BODY_MAX_BYTES, builtins::http::ai::config_validation::validate_max_body_bytes,
};

// -----------------------------------------------------------------------------
// OpenaiResponsesToChatCompletionsConfig
// -----------------------------------------------------------------------------

/// YAML configuration for the Responses-to-Chat-Completions filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OpenaiResponsesToChatCompletionsConfig {
    /// Maximum body size in bytes for `StreamBuffer` mode.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
}

/// Default max body bytes.
fn default_max_body_bytes() -> usize {
    OPENAI_RESPONSES_BODY_MAX_BYTES
}

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

/// Validate the parsed configuration.
pub(crate) fn build_config(
    cfg: OpenaiResponsesToChatCompletionsConfig,
) -> Result<OpenaiResponsesToChatCompletionsConfig, FilterError> {
    validate_max_body_bytes("openai_responses_to_chat_completions", cfg.max_body_bytes)?;
    Ok(cfg)
}
