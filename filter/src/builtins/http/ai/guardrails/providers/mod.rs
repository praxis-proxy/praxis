// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Guard provider trait, result types, and provider implementations
//! for external AI guardrails.

pub(super) mod nemo;

use std::fmt;

use async_trait::async_trait;

use crate::FilterError;

// -----------------------------------------------------------------------------
// GuardPhase
// -----------------------------------------------------------------------------

/// Which phase of the proxy pipeline is being evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardPhase {
    /// Inspecting the client request before it reaches the upstream.
    Request,
    /// Inspecting the upstream response before it reaches the client.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used once response-side evaluation is implemented (#580)")
    )]
    Response,
}

impl fmt::Display for GuardPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request => f.write_str("request"),
            Self::Response => f.write_str("response"),
        }
    }
}

// -----------------------------------------------------------------------------
// GuardResult
// -----------------------------------------------------------------------------

/// Normalized verdict from an external guardrail provider evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardResult {
    /// Content is safe — forward unchanged.
    Pass,
    /// Content violates policy — reject with reason.
    Block {
        /// Human-readable block reason from the provider.
        reason: String,
    },
    /// Content contains sensitive data — forward with masked text.
    Redact {
        /// Provider-rewritten text with sensitive data masked.
        modified_text: String,
        /// Human-readable redaction reason from the provider.
        reason: String,
    },
}

impl GuardResult {
    /// Returns the status label written to trace logs and result sets.
    pub fn status_label(&self) -> &'static str {
        match self {
            Self::Pass => "passed",
            Self::Block { .. } => "blocked",
            Self::Redact { .. } => "redacted",
        }
    }
}

// -----------------------------------------------------------------------------
// GuardProvider trait
// -----------------------------------------------------------------------------

/// Trait every external guard provider must implement.
///
/// The provider receives pre-extracted messages from the filter
/// (the filter handles bytes → JSON parsing and message extraction).
///
/// Each provider is responsible for:
/// 1. Building the provider-specific HTTP payload
/// 2. Calling the external service
/// 3. Mapping the response to [`GuardResult`]
///
/// On failure (network error, timeout, bad response), return
/// `Err(FilterError)`. The pipeline's per-filter `failure_mode`
/// (open/closed) handles what happens next.
#[async_trait]
pub trait GuardProvider: Send + Sync {
    /// Evaluate the extracted messages against the external guard service.
    async fn evaluate(&self, messages: Vec<serde_json::Value>, phase: GuardPhase) -> Result<GuardResult, FilterError>;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_phase_display() {
        assert_eq!(GuardPhase::Request.to_string(), "request");
        assert_eq!(GuardPhase::Response.to_string(), "response");
    }

    #[test]
    fn guard_result_status_labels() {
        assert_eq!(GuardResult::Pass.status_label(), "passed");
        assert_eq!(GuardResult::Block { reason: "test".into() }.status_label(), "blocked");
        assert_eq!(
            GuardResult::Redact {
                modified_text: "***".into(),
                reason: "pii".into()
            }
            .status_label(),
            "redacted"
        );
    }
}
