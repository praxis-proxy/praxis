// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Per-cluster slow start: ramp a new or recovered endpoint up to its weight.

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// SlowStartConfig
// -----------------------------------------------------------------------------

/// Gradually raises an endpoint's load-balancing weight after it joins or
/// recovers, instead of giving it the configured weight on the first request.
///
/// Requires the `slow-start` Cargo feature. Load-balancer selection does not
/// read this ramp yet: the setting is accepted and stored, and a follow-up
/// applies it while choosing an endpoint.
///
/// The ramp is
/// `time_factor ^ (1 / aggression)`, where `time_factor` is the fraction of
/// [`window_ms`](Self::window_ms) that has elapsed. Aggression `1.0` is a
/// straight line. Values above `1.0` give the endpoint more of its weight
/// earlier in the window. Values below `1.0` hold it back until late in the
/// window.
///
/// Applies to round-robin, random, least-connections, and power-of-two-choices,
/// including when those run inside subset, priority, or zone-aware selection.
/// Consistent-hash, Maglev, and ring-hash keep the configured weight so a
/// moving ramp does not reshuffle the ring.
///
/// Endpoints already in the cluster when the proxy first observes it stay at
/// their configured weight. An address added later, and an endpoint that
/// becomes healthy again after a health-check failure, ramp from zero.
///
/// ```
/// use praxis_core::config::SlowStartConfig;
///
/// let yaml = r#"
/// window_ms: 30000
/// aggression: 1.0
/// "#;
/// let slow_start: SlowStartConfig = serde_yaml::from_str(yaml).unwrap();
/// assert_eq!(slow_start.window_ms, 30_000);
/// assert_eq!(slow_start.aggression, 1.0);
/// ```
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SlowStartConfig {
    /// Duration of the ramp, in milliseconds.
    ///
    /// Must be at least 1 and at most one hour. Over this span the endpoint's
    /// effective weight grows from 0 to its configured weight.
    pub window_ms: u64,

    /// Curve of the ramp. `1.0` (the default) is linear.
    ///
    /// Must be finite and in `(0, 100]`.
    #[serde(default = "default_aggression")]
    pub aggression: f64,
}

/// Default aggression: a linear ramp.
fn default_aggression() -> f64 {
    1.0
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    clippy::float_cmp,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn parses_window_and_defaults_aggression_to_linear() {
        let slow_start: SlowStartConfig = serde_yaml::from_str("window_ms: 15000\n").unwrap();
        assert_eq!(slow_start.window_ms, 15_000, "window should parse");
        assert_eq!(slow_start.aggression, 1.0, "aggression should default to linear");
    }

    #[test]
    fn rejects_unknown_field() {
        let err = serde_yaml::from_str::<SlowStartConfig>("window_ms: 1000\nmin_weight: 1\n").unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "unknown fields must fail: {err}"
        );
    }
}
