// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! [`AiGuardrailsFilter`] implementation and `HttpFilter` trait impl.

use async_trait::async_trait;
use bytes::Bytes;

use super::{
    config::{AiGuardrailsConfig, ProviderType},
    providers::{GuardProvider, nemo::NemoProvider},
};
use crate::{
    FilterAction, FilterError,
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
/// use praxis_filter::ai::AiGuardrailsFilter;
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
    #[expect(
        dead_code,
        reason = "called by on_request_body once provider evaluation is wired (#578)"
    )]
    /// Guard provider instance.
    provider: Box<dyn GuardProvider>,
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

        Ok(Box::new(Self { provider }))
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
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        // Provider evaluation wired in #578 (NeMo request-side integration).
        Ok(FilterAction::Continue)
    }
}
