// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration for the Anthropic stream events filter.

use serde::Deserialize;

use crate::{
    FilterError,
    body::{DEFAULT_JSON_BODY_MAX_BYTES, MAX_JSON_BODY_BYTES},
};

// -----------------------------------------------------------------------------
// AnthropicStreamEventsConfig
// -----------------------------------------------------------------------------

/// YAML configuration for the [`AnthropicStreamEventsFilter`].
///
/// [`AnthropicStreamEventsFilter`]: super::AnthropicStreamEventsFilter
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnthropicStreamEventsConfig {
    /// Maximum incomplete SSE event bytes retained between chunks.
    #[serde(default = "default_max_partial_event_bytes")]
    pub max_partial_event_bytes: usize,
}

/// Default maximum partial event bytes.
fn default_max_partial_event_bytes() -> usize {
    DEFAULT_JSON_BODY_MAX_BYTES
}

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

/// Validate the parsed configuration.
pub(crate) fn build_config(cfg: AnthropicStreamEventsConfig) -> Result<AnthropicStreamEventsConfig, FilterError> {
    validate_max_partial_event_bytes(cfg.max_partial_event_bytes)?;
    Ok(cfg)
}

/// Validate the maximum partial SSE event byte limit.
fn validate_max_partial_event_bytes(value: usize) -> Result<(), FilterError> {
    if value == 0 {
        return Err("anthropic_stream_events: 'max_partial_event_bytes' must be greater than 0".into());
    }

    if value > MAX_JSON_BODY_BYTES {
        return Err(format!(
            "anthropic_stream_events: max_partial_event_bytes ({value}) exceeds maximum ({MAX_JSON_BODY_BYTES})"
        )
        .into());
    }

    Ok(())
}
