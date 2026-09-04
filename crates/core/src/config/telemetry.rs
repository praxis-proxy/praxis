// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! OpenTelemetry and distributed tracing configuration.

use std::{collections::HashMap, fmt};

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// OTel-standard environment variable for resource attributes
/// (format: `key1=value1,key2=value2`).
const OTEL_RESOURCE_ATTRIBUTES_ENV_VAR: &str = "OTEL_RESOURCE_ATTRIBUTES";

/// OTel-standard environment variable for the service name.
const OTEL_SERVICE_NAME_ENV_VAR: &str = "OTEL_SERVICE_NAME";

/// OTel-standard environment variable for the OTLP exporter endpoint.
const OTLP_ENDPOINT_ENV_VAR: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

/// Standard `OTel` environment variable for OTLP exporter headers.
const OTLP_HEADERS_ENV_VAR: &str = "OTEL_EXPORTER_OTLP_HEADERS";

/// OTel-standard environment variable for the OTLP exporter protocol.
#[cfg(feature = "otel")]
pub(crate) const OTLP_PROTOCOL_ENV_VAR: &str = "OTEL_EXPORTER_OTLP_PROTOCOL";

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
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Batch export interval in seconds.
    ///
    /// Controls how frequently the batch span processor flushes pending spans
    /// to the OTLP collector. Defaults to 5 seconds when not set.
    pub batch_interval_secs: Option<u64>,

    /// Maximum number of spans per batch export.
    ///
    /// Controls the maximum batch size for the batch span processor.
    /// Defaults to 512 when not set.
    pub batch_size: Option<usize>,

    /// Deployment environment resource attribute (`deployment.environment`).
    ///
    /// Falls back to `deployment.environment` in the `OTEL_RESOURCE_ATTRIBUTES`
    /// env var when not set in config.
    pub environment: Option<String>,

    /// OTLP collector endpoint (e.g. `http://localhost:4317`).
    ///
    /// When set, enables the OTLP trace exporter (requires the `otel`
    /// feature). Falls back to `OTEL_EXPORTER_OTLP_ENDPOINT` env var
    /// if not set in config.
    pub otlp_endpoint: Option<String>,

    /// Custom headers for the OTLP exporter (e.g. API keys).
    ///
    /// Sent on every export request — as gRPC metadata for the default
    /// `grpc` protocol, or as HTTP headers for `http/protobuf`.
    #[serde(skip_serializing)]
    pub otlp_headers: Option<HashMap<String, String>>,

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

    /// `OTel` `service.name` resource attribute.
    ///
    /// Falls back to `OTEL_SERVICE_NAME` env var when not set in config.
    /// Defaults to `"praxis"` when neither is set.
    pub service_name: Option<String>,

    /// `OTel` `service.version` resource attribute.
    ///
    /// Falls back to `service.version` in the `OTEL_RESOURCE_ATTRIBUTES`
    /// env var when not set in config.
    pub service_version: Option<String>,
}

impl fmt::Debug for TelemetryConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelemetryConfig")
            .field("batch_interval_secs", &self.batch_interval_secs)
            .field("batch_size", &self.batch_size)
            .field("environment", &self.environment)
            .field("otlp_endpoint", &self.otlp_endpoint)
            .field(
                "otlp_headers",
                &self
                    .otlp_headers
                    .as_ref()
                    .map(|h| format!("<{} header(s) redacted>", h.len())),
            )
            .field("sampling_rate", &self.sampling_rate)
            .field("service_name", &self.service_name)
            .field("service_version", &self.service_version)
            .finish()
    }
}

impl TelemetryConfig {
    /// Default batch export interval in seconds.
    #[cfg(any(feature = "otel", test))]
    pub(crate) const DEFAULT_BATCH_INTERVAL_SECS: u64 = 5;
    /// Default maximum number of spans per batch export.
    #[cfg(any(feature = "otel", test))]
    pub(crate) const DEFAULT_BATCH_SIZE: usize = 512;
    /// Default `OTel` service name when not configured.
    #[cfg(any(feature = "otel", test))]
    pub(crate) const DEFAULT_SERVICE_NAME: &'static str = "praxis";

    /// Validate telemetry configuration values.
    ///
    /// # Errors
    ///
    /// Returns an error if `batch_size` or `batch_interval_secs` is
    /// explicitly set to zero, `otlp_endpoint` is empty/whitespace-only,
    /// or `sampling_rate` is outside the `0.0..=1.0` range.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.batch_size == Some(0) {
            return Err("telemetry.batch_size must be > 0".to_owned());
        }
        if self.batch_interval_secs == Some(0) {
            return Err("telemetry.batch_interval_secs must be > 0".to_owned());
        }
        if self.otlp_endpoint.as_ref().is_some_and(|e| e.trim().is_empty()) {
            return Err("telemetry.otlp_endpoint must not be empty (omit the field to disable OTLP)".to_owned());
        }
        if let Some(rate) = self.sampling_rate
            && (!rate.is_finite() || !(0.0..=1.0).contains(&rate))
        {
            return Err(format!(
                "telemetry.sampling_rate must be between 0.0 and 1.0, got {rate}"
            ));
        }
        if self.service_name.as_ref().is_some_and(|s| s.trim().is_empty()) {
            return Err("telemetry.service_name must not be empty when set".to_owned());
        }
        if self.service_version.as_ref().is_some_and(|s| s.trim().is_empty()) {
            return Err("telemetry.service_version must not be empty when set".to_owned());
        }
        Ok(())
    }

    /// Snapshot telemetry settings by merging config with environment.
    ///
    /// Config values take precedence over environment variables.
    /// Fallback order for `service_name`:
    ///   1. `service_name` in config
    ///   2. `OTEL_SERVICE_NAME` env var
    ///   3. `service.name` in `OTEL_RESOURCE_ATTRIBUTES` env var
    ///   4. `"praxis"` (via `DEFAULT_SERVICE_NAME` at the call site)
    ///
    /// Call once at startup — the returned config should be stored
    /// rather than re-evaluated per request.
    pub(crate) fn resolve(&self) -> Self {
        Self {
            batch_interval_secs: self.batch_interval_secs,
            batch_size: self.batch_size,
            environment: self
                .environment
                .clone()
                .or_else(|| extract_resource_attribute_from_env("deployment.environment")),
            otlp_endpoint: self.otlp_endpoint.clone().or_else(|| {
                std::env::var(OTLP_ENDPOINT_ENV_VAR)
                    .ok()
                    .filter(|s| !s.trim().is_empty())
            }),
            otlp_headers: self.otlp_headers.clone().or_else(parse_otlp_headers_from_env),
            sampling_rate: self.sampling_rate,
            service_name: self
                .service_name
                .clone()
                .or_else(|| {
                    std::env::var(OTEL_SERVICE_NAME_ENV_VAR)
                        .ok()
                        .filter(|s| !s.trim().is_empty())
                })
                .or_else(|| extract_resource_attribute_from_env("service.name")),
            service_version: self
                .service_version
                .clone()
                .or_else(|| extract_resource_attribute_from_env("service.version")),
        }
    }

    /// Build from explicit values (for testing without env var mutation).
    ///
    /// This intentionally bypasses [`resolve()`](Self::resolve) because
    /// `resolve()` reads real environment variables, and mutating the
    /// process environment in tests is inherently racy (`env::set_var`
    /// is `unsafe` since Rust 1.66 for good reason). Instead, callers
    /// pass the "would-have-come-from-env" value as `env_endpoint` and
    /// the helper simulates the config-then-env precedence inline.
    #[cfg(test)]
    fn resolved(config_endpoint: Option<&str>, env_endpoint: Option<&str>) -> Self {
        Self {
            otlp_endpoint: config_endpoint.or(env_endpoint).map(ToOwned::to_owned),
            ..Default::default()
        }
    }
}

// -----------------------------------------------------------------------------
// Resource Attribute Parsing
// -----------------------------------------------------------------------------

/// Extract a single attribute from the `OTEL_RESOURCE_ATTRIBUTES` env var.
///
/// The env var format is `key1=value1,key2=value2`. Returns the value
/// for the first matching `key`, or `None` if the env var is unset or
/// the key is absent.
fn extract_resource_attribute_from_env(key: &str) -> Option<String> {
    let attrs = std::env::var(OTEL_RESOURCE_ATTRIBUTES_ENV_VAR).ok()?;
    // Drop empty values (e.g. `service.version=`) so an empty env attribute
    // does not flow into the OTel Resource, matching the config-side
    // validation and the OTEL_SERVICE_NAME empty-filter in resolve().
    extract_resource_attribute(&attrs, key).filter(|s| !s.trim().is_empty())
}

/// Extract a single attribute value from an `OTel` resource-attributes string.
///
/// Parses the `key1=value1,key2=value2` format used by
/// `OTEL_RESOURCE_ATTRIBUTES`. Returns the trimmed value for the first
/// entry whose trimmed key matches `target_key`.
fn extract_resource_attribute(attrs: &str, target_key: &str) -> Option<String> {
    attrs
        .split(',')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| k.trim() == target_key)
        .map(|(_, v)| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

// -----------------------------------------------------------------------------
// OTLP Headers Environment Variable
// -----------------------------------------------------------------------------

/// Parse `OTEL_EXPORTER_OTLP_HEADERS` into a header map.
///
/// Format: `key1=value1,key2=value2`. Returns `None` if the env var
/// is unset or yields no valid pairs.
fn parse_otlp_headers_from_env() -> Option<HashMap<String, String>> {
    let raw = std::env::var(OTLP_HEADERS_ENV_VAR).ok()?;
    let headers: HashMap<String, String> = raw
        .split(',')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (percent_decode(k.trim()), percent_decode(v.trim())))
        .filter(|(k, _)| !k.is_empty())
        .collect();
    if headers.is_empty() { None } else { Some(headers) }
}

/// Percent-decode a string per RFC 3986.
fn percent_decode(input: &str) -> String {
    percent_encoding::percent_decode_str(input)
        .decode_utf8_lossy()
        .into_owned()
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
    fn debug_redacts_otlp_headers() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_owned(), "secret-token".to_owned());
        let config = TelemetryConfig {
            batch_interval_secs: Some(5),
            batch_size: Some(64),
            environment: Some("prod".to_owned()),
            otlp_endpoint: Some("http://collector:4317".to_owned()),
            otlp_headers: Some(headers),
            sampling_rate: Some(0.5),
            service_name: Some("svc".to_owned()),
            service_version: Some("1.2.3".to_owned()),
        };
        let rendered = format!("{config:?}");
        assert!(
            rendered.contains("<1 header(s) redacted>"),
            "OTLP header values must be redacted: {rendered}"
        );
        assert!(
            !rendered.contains("secret-token"),
            "OTLP header values must never appear in Debug output: {rendered}"
        );
    }

    #[test]
    fn debug_shows_absent_headers_as_none() {
        let config = TelemetryConfig::default();
        let rendered = format!("{config:?}");
        assert!(
            rendered.contains("otlp_headers: None"),
            "absent headers must render as None: {rendered}"
        );
    }

    // -------------------------------------------------------------------------
    // Default & Parse Tests
    // -------------------------------------------------------------------------

    #[test]
    fn defaults_to_no_endpoint() {
        let telemetry = TelemetryConfig::default();
        assert!(
            telemetry.otlp_endpoint.is_none(),
            "otlp_endpoint should default to None"
        );
    }

    #[test]
    fn defaults_all_new_fields_to_none() {
        let telemetry = TelemetryConfig::default();
        assert!(
            telemetry.batch_interval_secs.is_none(),
            "batch_interval_secs should default to None"
        );
        assert!(telemetry.batch_size.is_none(), "batch_size should default to None");
        assert!(telemetry.environment.is_none(), "environment should default to None");
        assert!(telemetry.otlp_headers.is_none(), "otlp_headers should default to None");
        assert!(
            telemetry.sampling_rate.is_none(),
            "sampling_rate should default to None"
        );
        assert!(telemetry.service_name.is_none(), "service_name should default to None");
        assert!(
            telemetry.service_version.is_none(),
            "service_version should default to None"
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
    fn parse_batch_fields() {
        let yaml = "batch_size: 1024\nbatch_interval_secs: 10\n";
        let telemetry: TelemetryConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(telemetry.batch_size, Some(1024), "batch_size should be parsed");
        assert_eq!(
            telemetry.batch_interval_secs,
            Some(10),
            "batch_interval_secs should be parsed"
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
    fn parse_resource_fields() {
        let yaml = r#"
service_name: "my-gateway"
service_version: "1.2.3"
environment: "production"
"#;
        let telemetry: TelemetryConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            telemetry.service_name.as_deref(),
            Some("my-gateway"),
            "service_name should be parsed"
        );
        assert_eq!(
            telemetry.service_version.as_deref(),
            Some("1.2.3"),
            "service_version should be parsed"
        );
        assert_eq!(
            telemetry.environment.as_deref(),
            Some("production"),
            "environment should be parsed"
        );
    }

    #[test]
    fn parse_otlp_headers() {
        let yaml = r#"
otlp_headers:
  x-api-key: "secret-key-123"
  x-custom: "value"
"#;
        let telemetry: TelemetryConfig = serde_yaml::from_str(yaml).unwrap();
        let headers = telemetry.otlp_headers.as_ref().expect("headers should be Some");
        assert_eq!(
            headers.get("x-api-key").map(String::as_str),
            Some("secret-key-123"),
            "x-api-key header should be parsed"
        );
        assert_eq!(
            headers.get("x-custom").map(String::as_str),
            Some("value"),
            "x-custom header should be parsed"
        );
    }

    #[test]
    fn parse_full_config_endpoint_and_batch() {
        let yaml = "otlp_endpoint: \"http://collector:4317\"\nbatch_size: 256\nbatch_interval_secs: 3\n";
        let telemetry: TelemetryConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            telemetry.otlp_endpoint.as_deref(),
            Some("http://collector:4317"),
            "otlp_endpoint mismatch"
        );
        assert_eq!(telemetry.batch_size, Some(256), "batch_size mismatch");
        assert_eq!(telemetry.batch_interval_secs, Some(3), "batch_interval_secs mismatch");
    }

    #[test]
    fn parse_full_config_resource_and_headers() {
        let yaml = "service_name: \"praxis-test\"\nservice_version: \"0.1.0\"\nenvironment: \"staging\"\notlp_headers:\n  authorization: \"Bearer tok\"\n";
        let telemetry: TelemetryConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            telemetry.service_name.as_deref(),
            Some("praxis-test"),
            "service_name mismatch"
        );
        assert_eq!(
            telemetry.service_version.as_deref(),
            Some("0.1.0"),
            "service_version mismatch"
        );
        assert_eq!(
            telemetry.environment.as_deref(),
            Some("staging"),
            "environment mismatch"
        );
        assert!(telemetry.otlp_headers.is_some(), "otlp_headers should be present");
    }

    #[test]
    fn reject_unknown_field() {
        let result = serde_yaml::from_str::<TelemetryConfig>("bogus_field: true");
        assert!(result.is_err(), "unknown field should be rejected");
    }

    // -------------------------------------------------------------------------
    // Env Var Constant Tests
    // -------------------------------------------------------------------------

    #[test]
    fn otlp_env_var_name_matches_otel_spec() {
        assert_eq!(
            OTLP_ENDPOINT_ENV_VAR, "OTEL_EXPORTER_OTLP_ENDPOINT",
            "env var name must match the OTel specification"
        );
    }

    #[test]
    fn service_name_env_var_matches_otel_spec() {
        assert_eq!(
            OTEL_SERVICE_NAME_ENV_VAR, "OTEL_SERVICE_NAME",
            "env var name must match the OTel specification"
        );
    }

    #[test]
    fn resource_attributes_env_var_matches_otel_spec() {
        assert_eq!(
            OTEL_RESOURCE_ATTRIBUTES_ENV_VAR, "OTEL_RESOURCE_ATTRIBUTES",
            "env var name must match the OTel specification"
        );
    }

    // -------------------------------------------------------------------------
    // Default Constant Tests
    // -------------------------------------------------------------------------

    #[test]
    fn default_constants_match_otel_sdk_defaults() {
        assert_eq!(
            TelemetryConfig::DEFAULT_BATCH_SIZE,
            512,
            "default batch size should match OTel SDK default"
        );
        assert_eq!(
            TelemetryConfig::DEFAULT_BATCH_INTERVAL_SECS,
            5,
            "default batch interval should match OTel SDK default (5s)"
        );
        assert_eq!(
            TelemetryConfig::DEFAULT_SERVICE_NAME,
            "praxis",
            "default service name should be 'praxis'"
        );
    }

    // -------------------------------------------------------------------------
    // Resolve Tests
    // -------------------------------------------------------------------------

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
            sampling_rate: Some(0.5),
            ..Default::default()
        };
        let resolved = config.resolve();
        assert_eq!(
            resolved.sampling_rate,
            Some(0.5),
            "resolve should preserve sampling_rate"
        );
    }

    #[test]
    fn resolve_passes_through_batch_fields() {
        let config = TelemetryConfig {
            batch_size: Some(1024),
            batch_interval_secs: Some(10),
            ..Default::default()
        };
        let resolved = config.resolve();
        assert_eq!(
            resolved.batch_size,
            Some(1024),
            "batch_size should pass through resolve"
        );
        assert_eq!(
            resolved.batch_interval_secs,
            Some(10),
            "batch_interval_secs should pass through resolve"
        );
    }

    #[test]
    fn resolve_passes_through_headers() {
        let mut headers = HashMap::new();
        headers.insert("x-api-key".to_owned(), "secret".to_owned());
        let config = TelemetryConfig {
            otlp_headers: Some(headers),
            ..Default::default()
        };
        let resolved = config.resolve();
        assert_eq!(
            resolved
                .otlp_headers
                .as_ref()
                .and_then(|h| h.get("x-api-key"))
                .map(String::as_str),
            Some("secret"),
            "otlp_headers should pass through resolve"
        );
    }

    #[test]
    fn resolve_uses_config_service_name_over_env() {
        // When config has a value, it should always be used regardless of env.
        let config = TelemetryConfig {
            service_name: Some("from-config".to_owned()),
            ..Default::default()
        };
        let resolved = config.resolve();
        assert_eq!(
            resolved.service_name.as_deref(),
            Some("from-config"),
            "config service_name should take precedence"
        );
    }

    #[test]
    fn resolve_uses_config_environment_over_env() {
        let config = TelemetryConfig {
            environment: Some("staging".to_owned()),
            ..Default::default()
        };
        let resolved = config.resolve();
        assert_eq!(
            resolved.environment.as_deref(),
            Some("staging"),
            "config environment should take precedence"
        );
    }

    #[test]
    fn resolve_uses_config_service_version_over_env() {
        let config = TelemetryConfig {
            service_version: Some("1.0.0".to_owned()),
            ..Default::default()
        };
        let resolved = config.resolve();
        assert_eq!(
            resolved.service_version.as_deref(),
            Some("1.0.0"),
            "config service_version should take precedence"
        );
    }

    // -------------------------------------------------------------------------
    // Validation Tests
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
    fn validate_rejects_zero_batch_size() {
        let config = TelemetryConfig {
            batch_size: Some(0),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("batch_size must be > 0"),
            "expected batch_size error, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_zero_batch_interval_secs() {
        let config = TelemetryConfig {
            batch_interval_secs: Some(0),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("batch_interval_secs must be > 0"),
            "expected batch_interval_secs error, got: {err}"
        );
    }

    #[test]
    fn validate_accepts_positive_batch_values() {
        let config = TelemetryConfig {
            batch_size: Some(512),
            batch_interval_secs: Some(5),
            ..Default::default()
        };
        assert!(config.validate().is_ok(), "positive values should pass validation");
    }

    #[test]
    fn validate_accepts_none_batch_values() {
        let config = TelemetryConfig::default();
        assert!(config.validate().is_ok(), "None values should pass validation");
    }

    #[test]
    fn validate_rejects_empty_otlp_endpoint() {
        let config = TelemetryConfig {
            otlp_endpoint: Some(String::new()),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("otlp_endpoint must not be empty"),
            "expected otlp_endpoint error, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_whitespace_only_otlp_endpoint() {
        let config = TelemetryConfig {
            otlp_endpoint: Some("   ".to_owned()),
            ..Default::default()
        };
        assert!(
            config.validate().is_err(),
            "whitespace-only endpoint should be rejected"
        );
    }

    #[test]
    fn validate_accepts_valid_otlp_endpoint() {
        let config = TelemetryConfig {
            otlp_endpoint: Some("http://collector:4317".to_owned()),
            ..Default::default()
        };
        assert!(config.validate().is_ok(), "valid endpoint should pass validation");
    }

    // -------------------------------------------------------------------------
    // Resource Attribute Extraction Tests
    // -------------------------------------------------------------------------

    #[test]
    fn extract_resource_attribute_single() {
        let attrs = "deployment.environment=production";
        assert_eq!(
            extract_resource_attribute(attrs, "deployment.environment"),
            Some("production".to_owned()),
            "should extract single attribute"
        );
    }

    #[test]
    fn extract_resource_attribute_multiple() {
        let attrs = "service.version=1.2.3,deployment.environment=staging,service.namespace=team-a";
        assert_eq!(
            extract_resource_attribute(attrs, "deployment.environment"),
            Some("staging".to_owned()),
            "should extract from multi-attribute string"
        );
        assert_eq!(
            extract_resource_attribute(attrs, "service.version"),
            Some("1.2.3".to_owned()),
            "should extract service.version from multi-attribute string"
        );
    }

    #[test]
    fn extract_resource_attribute_with_whitespace() {
        let attrs = " service.version = 1.0.0 , deployment.environment = prod ";
        assert_eq!(
            extract_resource_attribute(attrs, "service.version"),
            Some("1.0.0".to_owned()),
            "should trim whitespace around key and value"
        );
        assert_eq!(
            extract_resource_attribute(attrs, "deployment.environment"),
            Some("prod".to_owned()),
            "should trim whitespace around key and value"
        );
    }

    #[test]
    fn extract_resource_attribute_missing_key() {
        let attrs = "service.name=praxis,service.version=1.0.0";
        assert_eq!(
            extract_resource_attribute(attrs, "deployment.environment"),
            None,
            "should return None for missing key"
        );
    }

    #[test]
    fn extract_resource_attribute_empty_string() {
        assert_eq!(
            extract_resource_attribute("", "deployment.environment"),
            None,
            "should return None for empty attribute string"
        );
    }

    #[test]
    fn extract_resource_attribute_no_equals() {
        let attrs = "malformed-entry,deployment.environment=ok";
        assert_eq!(
            extract_resource_attribute(attrs, "deployment.environment"),
            Some("ok".to_owned()),
            "should skip entries without '=' and find valid ones"
        );
    }

    #[test]
    fn extract_resource_attribute_empty_value() {
        let attrs = "service.name=,deployment.environment=prod";
        assert_eq!(
            extract_resource_attribute(attrs, "service.name"),
            None,
            "empty value should return None to allow default fallback"
        );
        assert_eq!(
            extract_resource_attribute(attrs, "deployment.environment"),
            Some("prod".to_owned()),
            "non-empty value should still be extracted"
        );
    }
}
