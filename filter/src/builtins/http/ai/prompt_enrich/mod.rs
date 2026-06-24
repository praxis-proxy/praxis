// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Prompt enrichment filter: injects configured messages into
//! OpenAI-compatible chat completion request bodies.

mod config;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests;

use std::borrow::Cow;

use async_trait::async_trait;
use bytes::Bytes;

use self::config::{InvalidBodyBehavior, PromptEnrichConfig, message_to_value, validate_config};
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// PromptEnrichFilter
// -----------------------------------------------------------------------------

/// Injects statically configured messages into the `messages`
/// array of OpenAI-compatible chat completion request bodies.
///
/// Messages are pre-serialized at construction time. At
/// request time, the filter parses the JSON body, splices
/// prepend messages at the beginning and appends messages at
/// the end, then re-serializes the modified body.
///
/// At least one of `prepend` or `append` must be non-empty.
/// JSON is re-serialized, so byte-for-byte body identity is
/// not preserved.
///
/// In chains that also use `json_body_field` or
/// `model_to_header`, place `prompt_enrich` first.
///
/// # YAML configuration
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
///
/// # Example
///
/// ```rust
/// use praxis_filter::ai::PromptEnrichFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// prepend:
///   - role: system
///     content: "You are a helpful assistant."
/// "#,
/// )
/// .unwrap();
/// let filter = PromptEnrichFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "prompt_enrich");
/// ```
pub struct PromptEnrichFilter {
    /// Pre-serialized messages to append after existing messages.
    append: Vec<serde_json::Value>,

    /// Maximum request body size to buffer.
    max_body_bytes: usize,

    /// Behavior when the body cannot be enriched.
    on_invalid: InvalidBodyBehavior,

    /// Pre-serialized messages to prepend before existing messages.
    prepend: Vec<serde_json::Value>,
}

impl PromptEnrichFilter {
    /// Create from parsed YAML config.
    ///
    /// Validates the config and pre-serializes all configured
    /// messages to [`serde_json::Value`] at construction time.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if config parsing or validation fails.
    ///
    /// [`FilterError`]: crate::FilterError
    ///
    /// ```rust
    /// use praxis_filter::ai::PromptEnrichFilter;
    ///
    /// let yaml: serde_yaml::Value =
    ///     serde_yaml::from_str("prepend:\n  - role: system\n    content: \"Hello\"").unwrap();
    /// let filter = PromptEnrichFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "prompt_enrich");
    /// ```
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: PromptEnrichConfig = parse_filter_config("prompt_enrich", config)?;
        validate_config(&cfg)?;

        let prepend = cfg.prepend.iter().map(message_to_value).collect();
        let append = cfg.append.iter().map(message_to_value).collect();

        Ok(Box::new(Self {
            append,
            max_body_bytes: cfg.max_body_bytes,
            on_invalid: cfg.on_invalid,
            prepend,
        }))
    }
}

#[async_trait]
impl HttpFilter for PromptEnrichFilter {
    fn name(&self) -> &'static str {
        "prompt_enrich"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.max_body_bytes),
        }
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        let Some(raw) = body.as_ref() else {
            return Ok(FilterAction::Continue);
        };

        let mut value: serde_json::Value = match serde_json::from_slice(raw) {
            Ok(v) => v,
            Err(_) => return Ok(invalid_body_action(self.on_invalid, "invalid JSON body")),
        };

        let Some(messages) = value.get_mut("messages").and_then(serde_json::Value::as_array_mut) else {
            return Ok(invalid_body_action(
                self.on_invalid,
                "missing or invalid messages array",
            ));
        };

        messages.splice(0..0, self.prepend.iter().cloned());
        messages.extend(self.append.iter().cloned());

        let serialized =
            serde_json::to_vec(&value).map_err(|e| -> FilterError { format!("prompt_enrich: {e}").into() })?;

        let len = serialized.len();
        *body = Some(Bytes::from(serialized));

        ctx.extra_request_headers
            .push((Cow::Borrowed("content-length"), len.to_string()));

        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Map [`InvalidBodyBehavior`] to the appropriate [`FilterAction`].
fn invalid_body_action(behavior: InvalidBodyBehavior, message: &'static str) -> FilterAction {
    match behavior {
        InvalidBodyBehavior::Continue => FilterAction::Continue,
        InvalidBodyBehavior::Reject => FilterAction::Reject(
            Rejection::status(400)
                .with_header("content-type", "text/plain")
                .with_body(message),
        ),
    }
}
