// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Deserialized YAML configuration types for the model rewrite filter.

use std::collections::HashMap;

use serde::Deserialize;

use crate::{
    FilterError, body::DEFAULT_JSON_BODY_MAX_BYTES, builtins::http::ai::config_validation::validate_max_body_bytes,
};

// -----------------------------------------------------------------------------
// ModelRewriteConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the model rewrite filter.
///
/// ```yaml
/// filter: openai_responses_model_rewrite
/// default_model: "llama-3.3-70b"
/// model_aliases:
///   "codex-mini-latest": "llama-3.3-70b"
///   "gpt-4.1-*": "qwen-2.5-72b"
///   "gpt-4.1-mini": "qwen-2.5-72b"
/// max_body_bytes: 10485760
/// on_invalid: continue
/// headers:
///   effective_model: x-praxis-ai-effective-model
///   original_model: x-praxis-ai-original-model
/// ```
///
/// Quote wildcard alias keys in YAML, such as `"gpt-4.1-*"`, so `*` is
/// parsed as a literal character rather than YAML alias syntax. The examples
/// quote all alias keys for consistency.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ModelRewriteConfig {
    /// Model name to inject when the request body has no `model`
    /// field or when the field is `null`.
    #[serde(default)]
    pub default_model: Option<String>,

    /// Header names for promoted model values.
    #[serde(default)]
    pub headers: ModelRewriteHeaders,

    /// Maximum request body size to buffer before parsing.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Map from client-facing model names or single-wildcard patterns
    /// to backend model names. Quote wildcard keys in YAML. Exact aliases win
    /// before wildcard aliases; wildcard aliases are matched by literal specificity.
    #[serde(default)]
    pub model_aliases: HashMap<String, String>,

    /// Behavior when the body is not valid JSON.
    #[serde(default)]
    pub on_invalid: OnInvalidBehavior,
}

/// Default for `max_body_bytes`.
fn default_max_body_bytes() -> usize {
    DEFAULT_JSON_BODY_MAX_BYTES
}

// -----------------------------------------------------------------------------
// ModelRewriteHeaders
// -----------------------------------------------------------------------------

/// Configurable header names for promoted model values.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ModelRewriteHeaders {
    /// Header name for the effective (post-rewrite) model value.
    #[serde(default = "default_effective_model_header")]
    pub effective_model: Option<String>,

    /// Header name for the original (pre-rewrite) model value.
    #[serde(default = "default_original_model_header")]
    pub original_model: Option<String>,
}

impl Default for ModelRewriteHeaders {
    fn default() -> Self {
        Self {
            effective_model: default_effective_model_header(),
            original_model: default_original_model_header(),
        }
    }
}

/// Default effective model header name.
#[expect(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_effective_model_header() -> Option<String> {
    Some("x-praxis-ai-effective-model".to_owned())
}

/// Default original model header name.
#[expect(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_original_model_header() -> Option<String> {
    Some("x-praxis-ai-original-model".to_owned())
}

// -----------------------------------------------------------------------------
// OnInvalidBehavior
// -----------------------------------------------------------------------------

/// Behavior when the request body cannot be parsed as JSON.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum OnInvalidBehavior {
    /// Pass the original body through unchanged.
    #[default]
    Continue,

    /// Return HTTP 400.
    Reject,
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Validate a parsed config, returning an error for invalid values.
///
/// # Errors
///
/// Returns [`FilterError`] when the config is invalid.
///
/// [`FilterError`]: crate::FilterError
pub(super) fn validate_config(cfg: &ModelRewriteConfig) -> Result<(), FilterError> {
    if cfg.default_model.is_none() && cfg.model_aliases.is_empty() {
        return Err(
            "openai_responses_model_rewrite: at least one of 'default_model' or 'model_aliases' must be configured"
                .into(),
        );
    }

    if let Some(dm) = &cfg.default_model
        && dm.trim().is_empty()
    {
        return Err("openai_responses_model_rewrite: 'default_model' must not be empty".into());
    }

    validate_aliases(&cfg.model_aliases)?;
    validate_max_body_bytes("openai_responses_model_rewrite", cfg.max_body_bytes)?;
    validate_header_name("effective_model", cfg.headers.effective_model.as_deref())?;
    validate_header_name("original_model", cfg.headers.original_model.as_deref())?;

    Ok(())
}

/// Validate alias map entries.
fn validate_aliases(aliases: &HashMap<String, String>) -> Result<(), FilterError> {
    for (source, target) in aliases {
        if source.is_empty() {
            return Err("openai_responses_model_rewrite: alias source name must not be empty".into());
        }
        if source.chars().filter(|&c| c == '*').count() > 1 {
            return Err(format!(
                "openai_responses_model_rewrite: alias source pattern '{source}' must contain at most one '*'",
            )
            .into());
        }
        if target.is_empty() {
            return Err(
                format!("openai_responses_model_rewrite: alias target for '{source}' must not be empty").into(),
            );
        }
    }
    Ok(())
}

/// Validate a configured header name using the HTTP header-name parser.
fn validate_header_name(field: &str, name: Option<&str>) -> Result<(), FilterError> {
    let Some(name) = name else {
        return Ok(());
    };
    if name.is_empty() {
        return Err(format!("openai_responses_model_rewrite: '{field}' header name must not be empty").into());
    }
    if http::HeaderName::from_bytes(name.as_bytes()).is_err() {
        return Err(
            format!("openai_responses_model_rewrite: '{field}' header name is not a valid HTTP header name").into(),
        );
    }
    Ok(())
}
