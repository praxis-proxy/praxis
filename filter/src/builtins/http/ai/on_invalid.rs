// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Shared invalid-input behavior for AI classifier filters.

use serde::Deserialize;

// ---------------------------------------------------------------------------
// OnInvalidBehavior
// ---------------------------------------------------------------------------

/// Behavior when the request body is not a recognized AI API format.
///
/// Used by classifier filters (JSON-RPC, A2A, MCP, Anthropic Messages,
/// OpenAI Responses) to control what happens when parsing fails.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OnInvalidBehavior {
    /// Continue processing without classifier metadata.
    Continue,

    /// Reject the request with HTTP 400.
    Reject,

    /// Return a filter error (pipeline failure). Only used
    /// by the JSON-RPC filter.
    Error,
}

impl OnInvalidBehavior {
    /// Default for filters that pass through unrecognized input.
    pub(crate) const fn default_continue() -> Self {
        Self::Continue
    }

    /// Default for filters that reject unrecognized input.
    pub(crate) const fn default_reject() -> Self {
        Self::Reject
    }
}
