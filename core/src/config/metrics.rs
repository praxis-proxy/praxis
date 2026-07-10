// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Metrics and observability configuration.

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// MetricsConfig
// -----------------------------------------------------------------------------

/// Optional Prometheus metric collection settings.
///
/// All metrics default to disabled. Operators opt in per metric family.
///
/// ```
/// use praxis_core::config::MetricsConfig;
///
/// let metrics = MetricsConfig::default();
/// assert!(!metrics.filter_duration);
///
/// let metrics: MetricsConfig = serde_yaml::from_str("filter_duration: true").unwrap();
/// assert!(metrics.filter_duration);
/// ```
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    /// Record per-filter hook duration histograms (`praxis_filter_duration_seconds`).
    pub filter_duration: bool,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn defaults_filter_duration_off() {
        let metrics = MetricsConfig::default();
        assert!(!metrics.filter_duration, "filter_duration should default to false");
    }

    #[test]
    fn parse_empty_yields_defaults() {
        let metrics: MetricsConfig = serde_yaml::from_str("{}").unwrap();
        assert!(
            !metrics.filter_duration,
            "empty yaml should default filter_duration to false"
        );
    }

    #[test]
    fn parse_explicit_filter_duration() {
        let metrics: MetricsConfig = serde_yaml::from_str("filter_duration: true").unwrap();
        assert!(metrics.filter_duration, "explicit filter_duration should be true");
    }
}
