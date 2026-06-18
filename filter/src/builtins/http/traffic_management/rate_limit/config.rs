// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Deserialized YAML configuration types for the rate limit filter.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// RateLimitMode
// -----------------------------------------------------------------------------

/// Whether the rate limiter tracks one global bucket or per-IP buckets.
///
/// ```
/// use praxis_filter::RateLimitMode;
///
/// let mode: RateLimitMode = serde_yaml::from_str("global").unwrap();
/// assert!(matches!(mode, RateLimitMode::Global));
///
/// let mode: RateLimitMode = serde_yaml::from_str("per_ip").unwrap();
/// assert!(matches!(mode, RateLimitMode::PerIp));
/// ```
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitMode {
    /// One shared bucket for all clients.
    Global,

    /// Independent bucket per source IP address.
    PerIp,
}

// -----------------------------------------------------------------------------
// RateLimitConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the rate limit filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RateLimitConfig {
    /// Whether to use a single global bucket or per-IP buckets.
    pub mode: RateLimitMode,

    /// Tokens replenished per second.
    pub rate: f64,

    /// Maximum bucket capacity.
    pub burst: u32,
}
