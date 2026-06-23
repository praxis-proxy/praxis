// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! [`AiGuardrailsFilter`] implementation and `HttpFilter` trait impl.

use async_trait::async_trait;
use bytes::Bytes;

use super::{
    config::{AiGuardrailsConfig, PhaseConfig, ProviderType},
    providers::{GuardPhase, GuardProvider, GuardResult, nemo::NemoProvider},
};
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

/// Maximum request body size to buffer (1 MiB).
const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;

// -----------------------------------------------------------------------------
// AiGuardrailsFilter
// -----------------------------------------------------------------------------

/// Calls an external AI guardrail provider to evaluate request (and
/// eventually response) bodies. The provider determines whether
/// content should be passed, blocked, or redacted.
///
/// # YAML configuration
///
/// ```yaml
/// filter: ai_guardrails
/// provider:
///   type: nemo
///   endpoint: "http://nemo:8000/v1/guardrail/checks"
///   timeout_ms: 5000
/// phase:
///   request: true
///   response: false
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::AiGuardrailsFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// provider:
///   type: nemo
///   endpoint: "http://nemo:8000/v1/guardrail/checks"
/// "#,
/// )
/// .unwrap();
/// let filter = AiGuardrailsFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "ai_guardrails");
/// ```
pub struct AiGuardrailsFilter {
    /// Guard provider instance.
    provider: Box<dyn GuardProvider>,

    /// Which phases to evaluate (request / response).
    phase: PhaseConfig,
}

impl AiGuardrailsFilter {
    /// Create from parsed YAML config.
    ///
    /// Parses the shared config, then delegates provider-specific
    /// config parsing and validation to the provider's `from_config`.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if config parsing or validation fails.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: AiGuardrailsConfig = parse_filter_config("ai_guardrails", config)?;

        let provider: Box<dyn GuardProvider> = match cfg.provider.provider_type {
            ProviderType::Nemo => Box::new(NemoProvider::from_config(&cfg.provider.config)?),
        };

        Ok(Box::new(Self {
            provider,
            phase: cfg.phase,
        }))
    }
}

#[async_trait]
impl HttpFilter for AiGuardrailsFilter {
    fn name(&self) -> &'static str {
        "ai_guardrails"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(DEFAULT_MAX_BODY_BYTES),
        }
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        if !self.phase.request {
            return Ok(FilterAction::Continue);
        }

        let Some(bytes) = body.as_ref() else {
            return Ok(FilterAction::Continue);
        };

        if bytes.is_empty() {
            return Ok(FilterAction::Continue);
        }

        let messages = extract_messages(bytes)?;
        let result = self.provider.evaluate(messages, GuardPhase::Request).await?;

        // Capture label before consuming `result` in the match.
        let verdict = result.status_label();

        match result {
            GuardResult::Pass => {
                tracing::debug!(verdict, "ai_guardrails: provider verdict");
                Ok(FilterAction::Continue)
            },
            GuardResult::Block { reason } => {
                tracing::warn!(verdict, %reason, "ai_guardrails: provider verdict");
                Ok(FilterAction::Reject(Rejection::status(403).with_body(reason)))
            },
            GuardResult::Redact { reason, .. } => {
                // Full body replacement deferred to #579 (NeMo mask/redact action).
                tracing::warn!(verdict, %reason, "ai_guardrails: provider verdict; forwarding unchanged until #579");
                Ok(FilterAction::Continue)
            },
        }
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Extract messages from an OpenAI Chat or MCP request body.
///
/// Supports:
/// - OpenAI Chat request: `{"messages": [...]}`
///
/// Returns an error for unrecognized body formats to prevent
/// silently skipping guardrail evaluation.
///
/// # Errors
///
/// Returns [`FilterError`] if the body is not valid JSON or does not
/// contain a recognizable messages field.
fn extract_messages(body: &Bytes) -> Result<Vec<serde_json::Value>, FilterError> {
    let json: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| -> FilterError { format!("ai_guardrails: request body is not valid JSON: {e}").into() })?;

    // OpenAI Chat format: {"messages": [...]}
    if let Some(messages) = json.get("messages").and_then(|m| m.as_array()) {
        return Ok(messages.clone());
    }

    Err("ai_guardrails: request body does not contain recognizable messages".into())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use bytes::Bytes;

    use super::extract_messages;

    // -------------------------------------------------------------------------
    // extract_messages
    // -------------------------------------------------------------------------

    #[test]
    fn extract_messages_reads_openai_chat_messages_array() {
        let body = Bytes::from_static(
            br#"{"messages":[{"role":"user","content":"hello"},{"role":"assistant","content":"hi"}]}"#,
        );
        let msgs = extract_messages(&body).unwrap();
        assert_eq!(msgs.len(), 2, "should extract both messages");
        assert_eq!(
            msgs.first().and_then(|m| m["role"].as_str()),
            Some("user"),
            "first message role should be 'user'"
        );
    }

    #[test]
    fn extract_messages_errors_on_unrecognized_json() {
        let body = Bytes::from_static(br#"{"model":"gpt-4","prompt":"hello"}"#);
        let err = extract_messages(&body).unwrap_err();
        assert!(
            err.to_string().contains("recognizable messages"),
            "unrecognised body should produce a descriptive error; got: {err}"
        );
    }

    #[test]
    fn extract_messages_errors_on_invalid_json() {
        let body = Bytes::from_static(b"not json at all");
        let err = extract_messages(&body).unwrap_err();
        assert!(
            err.to_string().contains("not valid JSON"),
            "non-JSON body should produce a JSON parse error; got: {err}"
        );
    }
}
