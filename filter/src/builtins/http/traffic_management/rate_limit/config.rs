// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Deserialized YAML configuration types for the rate limit filter.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// RateLimitConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the rate limit filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RateLimitConfig {
    /// `"per_ip"` or `"global"`.
    pub mode: String,

    /// Tokens replenished per second.
    pub rate: f64,

    /// Maximum bucket capacity.
    pub burst: u32,
}
