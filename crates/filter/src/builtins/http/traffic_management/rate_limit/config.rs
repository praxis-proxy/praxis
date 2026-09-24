// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Deserialized YAML configuration types for the rate limit filter.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default IPv6 grouping prefix: a single address, the same keying as IPv4.
const DEFAULT_IPV6_PREFIX_LEN: u8 = 128;

/// Maximum IPv6 prefix length (a single address).
const MAX_IPV6_PREFIX_LEN: u8 = 128;

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

    /// IPv6 network prefix length (1-128) that `per_ip` mode groups
    /// clients by. Defaults to 128, one bucket per address. Set 64 on
    /// internet-facing listeners, where one subscriber controls a whole
    /// /64 and can rotate addresses to evade the limit; keep 128 inside
    /// a cluster or LAN, where a node or segment shares one /64. IPv4
    /// clients are keyed by full address. Ignored in `global` mode.
    #[serde(default)]
    pub ipv6_prefix_len: Ipv6PrefixLen,
}

// -----------------------------------------------------------------------------
// Ipv6PrefixLen
// -----------------------------------------------------------------------------

/// Validated IPv6 prefix length in the range 1..=128.
///
/// Zero is rejected because a /0 would fold every IPv6 client into a
/// single bucket; use `global` mode for that.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(try_from = "u8")]
pub(super) struct Ipv6PrefixLen(u8);

impl Ipv6PrefixLen {
    /// Network mask with the top `prefix_len` bits set.
    pub(super) fn mask(self) -> u128 {
        u128::MAX
            .checked_shl(u32::from(MAX_IPV6_PREFIX_LEN.saturating_sub(self.0)))
            .unwrap_or(0)
    }
}

impl Default for Ipv6PrefixLen {
    fn default() -> Self {
        Self(DEFAULT_IPV6_PREFIX_LEN)
    }
}

impl TryFrom<u8> for Ipv6PrefixLen {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if (1..=MAX_IPV6_PREFIX_LEN).contains(&value) {
            Ok(Self(value))
        } else {
            Err(format!("ipv6_prefix_len must be in 1..=128, got {value}"))
        }
    }
}
