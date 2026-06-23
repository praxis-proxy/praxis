// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Deserialized YAML configuration types for the prompt enrichment filter.

use serde::Deserialize;

use crate::{
    FilterError, body::DEFAULT_JSON_BODY_MAX_BYTES, builtins::http::ai::config_validation::validate_max_body_bytes,
};

// -----------------------------------------------------------------------------
// PromptEnrichConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the prompt enrichment filter.
///
/// ```yaml
/// filter: prompt_enrich
/// max_body_bytes: 10485760
/// on_invalid: continue
/// prepend:
///   - role: system
///     content: "You are a helpful assistant."
/// append:
///   - role: user
///     content: "Remember to cite your sources."
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PromptEnrichConfig {
    /// Maximum request body size to buffer before parsing.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Behavior when the body is not valid JSON or lacks a
    /// `messages` array.
    #[serde(default)]
    pub on_invalid: InvalidBodyBehavior,

    /// Messages to prepend at the beginning of the `messages` array.
    #[serde(default)]
    pub prepend: Vec<MessageConfig>,

    /// Messages to append at the end of the `messages` array.
    #[serde(default)]
    pub append: Vec<MessageConfig>,
}

/// Default for `max_body_bytes`.
fn default_max_body_bytes() -> usize {
    DEFAULT_JSON_BODY_MAX_BYTES
}

// -----------------------------------------------------------------------------
// MessageConfig
// -----------------------------------------------------------------------------

/// A single message to inject into the `messages` array.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MessageConfig {
    /// Role for the injected message.
    pub role: MessageRole,

    /// Text content of the injected message.
    pub content: String,
}

// -----------------------------------------------------------------------------
// MessageRole
// -----------------------------------------------------------------------------

// v1 intentionally supports only roles requested by issue #137.

/// Allowed roles for injected messages.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum MessageRole {
    /// System role, allowed in both `prepend` and `append`.
    System,

    /// User role, allowed only in `append`.
    User,
}

// -----------------------------------------------------------------------------
// InvalidBodyBehavior
// -----------------------------------------------------------------------------

/// Behavior when the request body cannot be enriched.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum InvalidBodyBehavior {
    /// Pass the original body through unchanged.
    #[default]
    Continue,

    /// Return HTTP 400.
    Reject,
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Validate a parsed config, returning an error for invalid combinations.
///
/// # Errors
///
/// Returns [`FilterError`] if:
/// - Both `prepend` and `append` are empty
/// - Any message has empty `content`
/// - `max_body_bytes` is zero
/// - A `prepend` message uses a role other than `system`
///
/// [`FilterError`]: crate::FilterError
pub(super) fn validate_config(cfg: &PromptEnrichConfig) -> Result<(), FilterError> {
    if cfg.prepend.is_empty() && cfg.append.is_empty() {
        return Err("prompt_enrich: at least one of 'prepend' or 'append' must be non-empty".into());
    }

    validate_max_body_bytes("prompt_enrich", cfg.max_body_bytes)?;

    for msg in &cfg.prepend {
        if msg.content.is_empty() {
            return Err("prompt_enrich: message 'content' must not be empty".into());
        }
        if msg.role != MessageRole::System {
            return Err("prompt_enrich: 'prepend' messages must use role 'system'".into());
        }
    }

    for msg in &cfg.append {
        if msg.content.is_empty() {
            return Err("prompt_enrich: message 'content' must not be empty".into());
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Serialization Helpers
// -----------------------------------------------------------------------------

/// Convert a [`MessageConfig`] to a [`serde_json::Value`] for injection.
pub(super) fn message_to_value(msg: &MessageConfig) -> serde_json::Value {
    let role_str = match msg.role {
        MessageRole::System => "system",
        MessageRole::User => "user",
    };
    serde_json::json!({
        "role": role_str,
        "content": msg.content,
    })
}
