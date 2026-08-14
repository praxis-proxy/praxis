// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! OpenTelemetry and distributed tracing configuration.

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// OTel-standard environment variable for the OTLP exporter endpoint.
const OTLP_ENDPOINT_ENV_VAR: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

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
/// assert!(telemetry.sampling_rate.is_none());
///
/// let telemetry: TelemetryConfig =
///     serde_yaml::from_str("otlp_endpoint: \"http://localhost:4317\"").unwrap();
/// assert_eq!(
///     telemetry.otlp_endpoint.as_deref(),
///     Some("http://localhost:4317")
/// );
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// OTLP collector endpoint (e.g. `http://localhost:4317`).
    ///
    /// When set, enables the OTLP trace exporter (requires the `otel`
    /// feature). Falls back to `OTEL_EXPORTER_OTLP_ENDPOINT` env var
    /// if not set in config.
    pub otlp_endpoint: Option<String>,

    /// Head-based trace sampling rate between `0.0` (drop all) and `1.0`
    /// (sample all).
    ///
    /// When set, configures a `ParentBased(TraceIdRatioBased(rate))`
    /// sampler: root spans are sampled at the given rate while
    /// locally-created child spans inherit their parent's sampling
    /// decision.
    ///
    /// When `None` (the default), the `OTel` default sampler is used
    /// (`ParentBased(AlwaysOn)`), preserving backward compatibility.
    pub sampling_rate: Option<f64>,
}

impl TelemetryConfig {
    /// Snapshot telemetry settings by merging config with environment.
    ///
    /// Config values take precedence over environment variables.
    /// Call once at startup — the returned config should be stored
    /// rather than re-evaluated per request.
    pub(crate) fn resolve(&self) -> Self {
        Self {
            otlp_endpoint: self.otlp_endpoint.clone().or_else(|| {
                std::env::var(OTLP_ENDPOINT_ENV_VAR)
                    .ok()
                    .filter(|s| !s.trim().is_empty())
            }),
            sampling_rate: self.sampling_rate,
        }
    }

    /// Validate telemetry configuration values.
    ///
    /// Returns an error if `otlp_endpoint` is empty/whitespace-only or
    /// `sampling_rate` is outside the `0.0..=1.0` range (including NaN/Inf).
    pub(crate) fn validate(&self) -> Result<(), String> {
        if let Some(endpoint) = &self.otlp_endpoint
            && endpoint.trim().is_empty()
        {
            return Err("telemetry.otlp_endpoint must not be empty or whitespace-only".to_owned());
        }
        if let Some(rate) = self.sampling_rate
            && (!rate.is_finite() || !(0.0..=1.0).contains(&rate))
        {
            return Err(format!(
                "telemetry.sampling_rate must be between 0.0 and 1.0, got {rate}"
            ));
        }
        Ok(())
    }

    /// Build from explicit values (for testing without env var mutation).
    ///
    /// This deliberately bypasses [`resolve()`](Self::resolve) to avoid
    /// mutating process-wide environment variables in tests. It tests
    /// the *merge precedence* logic (config > env) in isolation. The
    /// real `resolve()` path is exercised by `resolve_preserves_sampling_rate`.
    #[cfg(test)]
    fn resolved(config_endpoint: Option<&str>, env_endpoint: Option<&str>) -> Self {
        Self {
            otlp_endpoint: config_endpoint.or(env_endpoint).map(ToOwned::to_owned),
            sampling_rate: None,
        }
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
    reason = "tests use unwrap/expect/indexing for brevity"
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
    fn defaults_to_no_sampling_rate() {
        let telemetry = TelemetryConfig::default();
        assert!(
            telemetry.sampling_rate.is_none(),
            "sampling_rate should default to None"
        );
    }

    #[test]
    fn parse_empty_yields_defaults() {
        let telemetry: TelemetryConfig = serde_yaml::from_str("{}").unwrap();
        assert!(
            telemetry.otlp_endpoint.is_none(),
            "empty yaml should default otlp_endpoint to None"
        );
        assert!(
            telemetry.sampling_rate.is_none(),
            "empty yaml should default sampling_rate to None"
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
    fn parse_explicit_sampling_rate() {
        let telemetry: TelemetryConfig = serde_yaml::from_str("sampling_rate: 0.5").unwrap();
        assert_eq!(
            telemetry.sampling_rate,
            Some(0.5),
            "explicit sampling_rate should be parsed"
        );
    }

    #[test]
    fn parse_sampling_rate_zero() {
        let telemetry: TelemetryConfig = serde_yaml::from_str("sampling_rate: 0.0").unwrap();
        assert_eq!(telemetry.sampling_rate, Some(0.0), "sampling_rate 0.0 should be parsed");
    }

    #[test]
    fn parse_sampling_rate_one() {
        let telemetry: TelemetryConfig = serde_yaml::from_str("sampling_rate: 1.0").unwrap();
        assert_eq!(telemetry.sampling_rate, Some(1.0), "sampling_rate 1.0 should be parsed");
    }

    #[test]
    fn parse_sampling_rate_one_percent() {
        let telemetry: TelemetryConfig = serde_yaml::from_str("sampling_rate: 0.01").unwrap();
        assert_eq!(
            telemetry.sampling_rate,
            Some(0.01),
            "sampling_rate 0.01 (1%) should be parsed"
        );
    }

    #[test]
    fn reject_unknown_field() {
        let result = serde_yaml::from_str::<TelemetryConfig>("bogus_field: true");
        assert!(result.is_err(), "unknown field should be rejected");
    }

    #[test]
    fn otlp_env_var_name_matches_otel_spec() {
        assert_eq!(
            OTLP_ENDPOINT_ENV_VAR, "OTEL_EXPORTER_OTLP_ENDPOINT",
            "env var name must match the OTel specification"
        );
    }

    #[test]
    fn resolve_prefers_config_over_env() {
        let resolved = TelemetryConfig::resolved(Some("http://config:4317"), Some("http://env:4317"));
        assert_eq!(
            resolved.otlp_endpoint.as_deref(),
            Some("http://config:4317"),
            "config value should take precedence over env"
        );
    }

    #[test]
    fn resolve_falls_back_to_env() {
        let resolved = TelemetryConfig::resolved(None, Some("http://env:4317"));
        assert_eq!(
            resolved.otlp_endpoint.as_deref(),
            Some("http://env:4317"),
            "should use env when config is None"
        );
    }

    #[test]
    fn resolve_none_when_both_unset() {
        let resolved = TelemetryConfig::resolved(None, None);
        assert!(
            resolved.otlp_endpoint.is_none(),
            "should return None when both are unset"
        );
    }

    #[test]
    fn resolve_preserves_sampling_rate() {
        let config = TelemetryConfig {
            otlp_endpoint: None,
            sampling_rate: Some(0.5),
        };
        let resolved = config.resolve();
        assert_eq!(
            resolved.sampling_rate,
            Some(0.5),
            "resolve should preserve sampling_rate"
        );
    }

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    #[test]
    fn validate_none_sampling_rate_ok() {
        let config = TelemetryConfig::default();
        assert!(config.validate().is_ok(), "None sampling_rate should pass validation");
    }

    #[test]
    fn validate_sampling_rate_zero_ok() {
        let config = TelemetryConfig {
            sampling_rate: Some(0.0),
            ..Default::default()
        };
        assert!(config.validate().is_ok(), "sampling_rate 0.0 should pass validation");
    }

    #[test]
    fn validate_sampling_rate_one_ok() {
        let config = TelemetryConfig {
            sampling_rate: Some(1.0),
            ..Default::default()
        };
        assert!(config.validate().is_ok(), "sampling_rate 1.0 should pass validation");
    }

    #[test]
    fn validate_sampling_rate_mid_range_ok() {
        let config = TelemetryConfig {
            sampling_rate: Some(0.01),
            ..Default::default()
        };
        assert!(config.validate().is_ok(), "sampling_rate 0.01 should pass validation");
    }

    #[test]
    fn validate_sampling_rate_negative_rejected() {
        let config = TelemetryConfig {
            sampling_rate: Some(-0.1),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("between 0.0 and 1.0"),
            "negative rate should be rejected: {err}"
        );
    }

    #[test]
    fn validate_sampling_rate_above_one_rejected() {
        let config = TelemetryConfig {
            sampling_rate: Some(1.5),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("between 0.0 and 1.0"),
            "rate above 1.0 should be rejected: {err}"
        );
    }

    #[test]
    fn validate_sampling_rate_nan_rejected() {
        let config = TelemetryConfig {
            sampling_rate: Some(f64::NAN),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("between 0.0 and 1.0"),
            "NaN sampling_rate should be rejected: {err}"
        );
    }

    #[test]
    fn validate_sampling_rate_infinity_rejected() {
        let config = TelemetryConfig {
            sampling_rate: Some(f64::INFINITY),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("between 0.0 and 1.0"),
            "Inf sampling_rate should be rejected: {err}"
        );
    }

    #[test]
    fn validate_sampling_rate_neg_infinity_rejected() {
        let config = TelemetryConfig {
            sampling_rate: Some(f64::NEG_INFINITY),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("between 0.0 and 1.0"),
            "-Inf sampling_rate should be rejected: {err}"
        );
    }

    #[test]
    fn validate_empty_otlp_endpoint_rejected() {
        let config = TelemetryConfig {
            otlp_endpoint: Some(String::new()),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("must not be empty"),
            "empty otlp_endpoint should be rejected: {err}"
        );
    }

    #[test]
    fn validate_whitespace_otlp_endpoint_rejected() {
        let config = TelemetryConfig {
            otlp_endpoint: Some("   ".to_owned()),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("must not be empty"),
            "whitespace-only otlp_endpoint should be rejected: {err}"
        );
    }
}
