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
    /// Snapshot telemetry settings by merging config with environment.
    ///
    /// Config values take precedence over environment variables.
    /// Call once at startup — the returned config should be stored
    /// rather than re-evaluated per request.
    pub(crate) fn resolve(&self) -> Self {
        Self {
            otlp_endpoint: self
                .otlp_endpoint
                .clone()
                .or_else(|| std::env::var(OTLP_ENDPOINT_ENV_VAR).ok()),
        }
    }

    /// Build from explicit values (for testing without env var mutation).
    ///
    /// This duplicates the merge logic from [`resolve`] rather than calling it,
    /// because `resolve` reads `std::env::var` which is process-global state.
    /// Mutating env vars in tests is inherently racy under `cargo test`'s
    /// default parallel execution, so we accept the small duplication to keep
    /// tests deterministic without `#[serial]` or mutex coordination.
    #[cfg(test)]
    fn resolved(config_endpoint: Option<&str>, env_endpoint: Option<&str>) -> Self {
        Self {
            otlp_endpoint: config_endpoint.or(env_endpoint).map(ToOwned::to_owned),
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
}
