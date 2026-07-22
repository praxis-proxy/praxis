// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! OpenTelemetry and distributed tracing configuration.

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// TelemetryConfig
// -----------------------------------------------------------------------------

/// OpenTelemetry tracing export settings.
///
/// When `otlp_endpoint` is set (and the `otel` feature is compiled in),
/// Praxis exports spans to an OTLP-compatible collector via gRPC.
/// The `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable is used as a
/// fallback when `otlp_endpoint` is not set in config.
///
/// ```
/// use praxis_core::config::TelemetryConfig;
///
/// let telemetry = TelemetryConfig::default();
/// assert!(telemetry.otlp_endpoint.is_none());
///
/// let telemetry: TelemetryConfig =
///     serde_yaml::from_str("otlp_endpoint: \"http://localhost:4317\"").unwrap();
/// assert_eq!(
///     telemetry.otlp_endpoint.as_deref(),
///     Some("http://localhost:4317")
/// );
/// ```
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// OTLP collector endpoint (e.g. `http://localhost:4317`).
    ///
    /// When set, enables the OTLP trace exporter (requires the `otel`
    /// feature). Falls back to `OTEL_EXPORTER_OTLP_ENDPOINT` env var
    /// if not set in config.
    pub otlp_endpoint: Option<String>,
}

impl TelemetryConfig {
    /// Resolve the effective OTLP endpoint from config or environment.
    ///
    /// Returns the config value if set, otherwise checks
    /// `OTEL_EXPORTER_OTLP_ENDPOINT`. Returns `None` if neither is set.
    pub(crate) fn resolved_otlp_endpoint(&self) -> Option<String> {
        self.otlp_endpoint
            .clone()
            .or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok())
    }
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
    unsafe_code,
    reason = "tests use unwrap/expect/indexing and unsafe env var manipulation"
)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_no_endpoint() {
        let telemetry = TelemetryConfig::default();
        assert!(
            telemetry.otlp_endpoint.is_none(),
            "otlp_endpoint should default to None"
        );
    }

    #[test]
    fn parse_empty_yields_defaults() {
        let telemetry: TelemetryConfig = serde_yaml::from_str("{}").unwrap();
        assert!(
            telemetry.otlp_endpoint.is_none(),
            "empty yaml should default otlp_endpoint to None"
        );
    }

    #[test]
    fn parse_explicit_endpoint() {
        let telemetry: TelemetryConfig = serde_yaml::from_str("otlp_endpoint: \"http://collector:4317\"").unwrap();
        assert_eq!(
            telemetry.otlp_endpoint.as_deref(),
            Some("http://collector:4317"),
            "explicit otlp_endpoint should be parsed"
        );
    }

    #[test]
    fn reject_unknown_field() {
        let result = serde_yaml::from_str::<TelemetryConfig>("bogus_field: true");
        assert!(result.is_err(), "unknown field should be rejected");
    }

    #[test]
    fn resolved_endpoint_prefers_config() {
        let telemetry = TelemetryConfig {
            otlp_endpoint: Some("http://from-config:4317".to_owned()),
        };
        assert_eq!(
            telemetry.resolved_otlp_endpoint().as_deref(),
            Some("http://from-config:4317"),
            "config value should take precedence"
        );
    }

    #[test]
    fn resolved_endpoint_env_var_fallback_and_unset() {
        let telemetry = TelemetryConfig { otlp_endpoint: None };

        // SAFETY: env var mutation is not thread-safe. This test is the only
        // one touching OTEL_EXPORTER_OTLP_ENDPOINT, consolidated into a single
        // function to avoid races with parallel test execution.
        unsafe {
            std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://from-env:4317");
        }
        let with_env = telemetry.resolved_otlp_endpoint();
        // SAFETY: same single-test scope; restoring env to original state.
        unsafe {
            std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        }
        let without_env = telemetry.resolved_otlp_endpoint();

        assert_eq!(
            with_env.as_deref(),
            Some("http://from-env:4317"),
            "should fall back to OTEL_EXPORTER_OTLP_ENDPOINT env var"
        );
        assert!(
            without_env.is_none(),
            "should return None when neither config nor env is set"
        );
    }
}
