// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Shared invalid-input behavior for classifier filters.

use serde::Deserialize;

// ---------------------------------------------------------------------------
// OnInvalidBehavior
// ---------------------------------------------------------------------------

/// Behavior when the request body is not a recognized protocol format.
///
/// Used by classifier filters (e.g. JSON-RPC) to control what happens
/// when parsing fails.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnInvalidBehavior {
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
    pub const fn default_continue() -> Self {
        Self::Continue
    }

    /// Default for filters that reject unrecognized input.
    pub const fn default_reject() -> Self {
        Self::Reject
    }
}
