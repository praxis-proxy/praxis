// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Deserialized YAML configuration types for the AI guardrails filter.

use serde::Deserialize;

/// Deserialized YAML config for the `ai_guardrails` filter.
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
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AiGuardrailsConfig {
    /// External provider configuration (required).
    pub provider: ProviderConfig,

    /// Which phases to evaluate.
    #[serde(default)]
    pub phase: PhaseConfig,
}

/// Supported external guardrail provider types.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum ProviderType {
    /// NVIDIA `NeMo` Guardrails via `/v1/guardrail/checks`.
    Nemo,
}

/// Provider type selector and opaque provider-specific configuration.
///
/// The `type` field selects the provider. All remaining fields are
/// captured via `#[serde(flatten)]` and passed to the provider's
/// own `from_config` for parsing and validation.
#[derive(Debug, Deserialize)]
pub(super) struct ProviderConfig {
    /// Provider type selector.
    #[serde(rename = "type")]
    pub provider_type: ProviderType,

    /// Provider-specific fields (parsed by each provider's `from_config`).
    #[serde(flatten)]
    pub config: serde_yaml::Value,
}

/// Controls which phases (request/response) the filter evaluates.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PhaseConfig {
    /// Evaluate client requests before forwarding to the upstream.
    #[serde(default = "default_true")]
    pub request: bool,

    /// Evaluate upstream responses before forwarding to the client.
    #[expect(dead_code, reason = "read once response-side evaluation is implemented (#580)")]
    #[serde(default)]
    pub response: bool,
}

impl Default for PhaseConfig {
    fn default() -> Self {
        Self {
            request: true,
            response: false,
        }
    }
}

/// Returns `true` for serde default fields.
fn default_true() -> bool {
    true
}
