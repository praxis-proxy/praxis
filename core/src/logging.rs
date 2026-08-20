// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tracing subscriber setup shared by all Praxis binaries.
//!
//! Composes a layered [`tracing_subscriber::Registry`] with:
//!
//! - **fmt layer** (always) — stdout text or JSON logging
//! - **OTLP layer** (opt-in, `otel` feature) — span export to an OTel Collector
//!
//! Set `PRAXIS_LOG_FORMAT=json` for structured JSON output.
//! Per-module overrides come from `runtime.log_overrides` in the config YAML.

use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _};

use crate::{config::Config, errors::ProxyError};

// -----------------------------------------------------------------------------
// TracingGuard
// -----------------------------------------------------------------------------

/// RAII guard that flushes and shuts down the `OTel` tracer provider on drop.
///
/// Store this in `main()` to ensure pending spans are exported on graceful
/// shutdown. Without the `otel` feature, this is a zero-size no-op.
///
/// ```no_run
/// let config = praxis_core::config::Config::load(None, "listeners: []").unwrap();
/// let _guard = praxis_core::logging::init_tracing(&config).unwrap();
/// ```
#[must_use = "dropping the guard immediately shuts down the tracer provider"]
pub struct TracingGuard {
    /// Tracer provider to shut down when the guard is dropped.
    #[cfg(feature = "otel")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

#[cfg(feature = "otel")]
impl Drop for TracingGuard {
    #[expect(clippy::print_stderr, reason = "tracing subscriber is being torn down")]
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take()
            && let Err(e) = provider.shutdown()
        {
            eprintln!("failed to shut down OTel tracer provider: {e}");
        }
    }
}

// -----------------------------------------------------------------------------
// Tracing Initialization
// -----------------------------------------------------------------------------

/// Initialize the global tracing subscriber.
///
/// Composes a [`tracing_subscriber::Registry`] with an [`EnvFilter`] and
/// a fmt layer (text or JSON). When the `otel` feature is enabled and an
/// OTLP endpoint is configured, adds an OTLP trace-export layer.
///
/// Returns a [`TracingGuard`] that flushes pending spans on drop.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] if any `log_overrides` entry is invalid
/// or (with the `otel` feature) if the OTLP exporter cannot be built.
///
/// ```no_run
/// let config = praxis_core::config::Config::load(None, "listeners: []").unwrap();
/// let _guard = praxis_core::logging::init_tracing(&config).unwrap();
/// ```
///
/// [`EnvFilter`]: tracing_subscriber::EnvFilter
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
pub fn init_tracing(config: &Config) -> Result<TracingGuard, ProxyError> {
    let env_filter = build_env_filter(config)?;
    let json = std::env::var("PRAXIS_LOG_FORMAT").is_ok_and(|v| v.eq_ignore_ascii_case("json"));
    let telemetry = config.telemetry.resolve();

    warn_if_otel_config_without_feature(telemetry.otlp_endpoint.is_some(), telemetry.sampling_rate.is_some());

    #[cfg(feature = "otel")]
    return init_with_otel(env_filter, json, &telemetry);

    #[cfg(not(feature = "otel"))]
    {
        init_fmt_only(env_filter, json);
        Ok(TracingGuard {})
    }
}

/// Validate log overrides from config without initializing the global subscriber.
///
/// Useful for configuration validation that needs to check log override
/// syntax without affecting the global tracing state.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] if any `log_overrides` entry is invalid.
///
/// ```
/// let yaml = r#"
/// listeners:
///   - name: test
///     address: "127.0.0.1:8080"
///     filter_chains: [main]
/// filter_chains:
///   - name: main
///     filters:
///       - filter: static_response
/// "#;
/// let config = praxis_core::config::Config::from_yaml(yaml).unwrap();
/// praxis_core::logging::validate_log_overrides(&config).unwrap();
/// ```
///
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
pub fn validate_log_overrides(config: &Config) -> Result<(), ProxyError> {
    build_env_filter(config)?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Subscriber Initialization
// -----------------------------------------------------------------------------

/// Initialize the layered subscriber with an optional OTLP layer.
#[cfg(feature = "otel")]
#[expect(
    clippy::large_stack_frames,
    reason = "tracing-subscriber layer composition creates deeply nested generic types; runs once at startup"
)]
fn init_with_otel(
    env_filter: tracing_subscriber::EnvFilter,
    json: bool,
    telemetry: &crate::config::TelemetryConfig,
) -> Result<TracingGuard, ProxyError> {
    use opentelemetry::trace::TracerProvider as _;

    let provider = build_otel_provider(telemetry)?;

    // `OpenTelemetryLayer<S>` requires `S` to match the composed subscriber type.
    // JSON and text fmt produce different types, preventing a shared binding.
    if json {
        let otel_layer = provider
            .as_ref()
            .map(|p| tracing_opentelemetry::layer().with_tracer(p.tracer("praxis")));
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(true),
            )
            .with(otel_layer)
            .init();
    } else {
        let otel_layer = provider
            .as_ref()
            .map(|p| tracing_opentelemetry::layer().with_tracer(p.tracer("praxis")));
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .with(otel_layer)
            .init();
    }

    Ok(TracingGuard { provider })
}

/// Initialize the layered subscriber with fmt only (no `otel` feature).
#[cfg(not(feature = "otel"))]
fn init_fmt_only(env_filter: tracing_subscriber::EnvFilter, json: bool) {
    if json {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(true),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }
}

// -----------------------------------------------------------------------------
// OTLP Provider Builder
// -----------------------------------------------------------------------------

/// Build the optional OTLP tracer provider.
///
/// Returns `Some(provider)` when an OTLP endpoint is configured,
/// `None` otherwise. Sets the global tracer provider.
///
/// Applies configured batch settings (size, interval), custom headers
/// (as gRPC metadata or HTTP headers), and resource attributes
/// (service name/version, deployment environment).
#[cfg(feature = "otel")]
fn build_otel_provider(
    config: &crate::config::TelemetryConfig,
) -> Result<Option<opentelemetry_sdk::trace::SdkTracerProvider>, ProxyError> {
    let Some(endpoint) = config.otlp_endpoint.as_deref() else {
        return Ok(None);
    };

    if let Ok(protocol) = std::env::var(crate::config::OTLP_PROTOCOL_ENV_VAR)
        && protocol != "grpc"
    {
        return Err(ProxyError::Config(format!(
            "Praxis supports only gRPC for OTLP export, but {}={protocol}",
            crate::config::OTLP_PROTOCOL_ENV_VAR,
        )));
    }

    let exporter = build_span_exporter(endpoint, config.otlp_headers.as_ref())?;
    let batch_processor = build_batch_processor(exporter, config);
    let resource = build_otel_resource(config);

    let mut provider_builder = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_span_processor(batch_processor)
        .with_resource(resource);

    // When a sampling rate is configured, wrap TraceIdRatioBased in
    // ParentBased so root spans are sampled at the given rate while
    // locally-created child spans inherit their parent's decision.
    if let Some(rate) = config.sampling_rate {
        provider_builder = provider_builder.with_sampler(opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(
            opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(rate),
        )));
    }

    let provider = provider_builder.build();

    opentelemetry::global::set_tracer_provider(provider.clone());

    Ok(Some(provider))
}

// -----------------------------------------------------------------------------
// OTLP Exporter Builder
// -----------------------------------------------------------------------------

/// Build the OTLP span exporter with endpoint and optional gRPC headers.
#[cfg(feature = "otel")]
fn build_span_exporter(
    endpoint: &str,
    headers: Option<&std::collections::HashMap<String, String>>,
) -> Result<opentelemetry_otlp::SpanExporter, ProxyError> {
    use opentelemetry_otlp::{WithExportConfig as _, WithTonicConfig as _};

    let mut builder = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint);

    if let Some(hdrs) = headers {
        builder = builder.with_metadata(build_metadata_map(hdrs)?);
    }

    builder
        .build()
        .map_err(|e| ProxyError::Config(format!("failed to build OTLP span exporter: {e}")))
}

// -----------------------------------------------------------------------------
// Batch Processor Builder
// -----------------------------------------------------------------------------

/// Build a batch span processor with configured size and interval.
///
/// Uses explicit defaults so Praxis controls batch behaviour even if the
/// `OTel` SDK changes its own defaults.
#[cfg(feature = "otel")]
fn build_batch_processor(
    exporter: opentelemetry_otlp::SpanExporter,
    config: &crate::config::TelemetryConfig,
) -> opentelemetry_sdk::trace::BatchSpanProcessor {
    let batch_size = config
        .batch_size
        .unwrap_or(crate::config::TelemetryConfig::DEFAULT_BATCH_SIZE);
    let batch_interval = config
        .batch_interval_secs
        .unwrap_or(crate::config::TelemetryConfig::DEFAULT_BATCH_INTERVAL_SECS);

    let batch_config = opentelemetry_sdk::trace::BatchConfigBuilder::default()
        .with_max_export_batch_size(batch_size)
        .with_max_queue_size(2048)
        .with_scheduled_delay(std::time::Duration::from_secs(batch_interval))
        .build();

    opentelemetry_sdk::trace::BatchSpanProcessor::builder(exporter)
        .with_batch_config(batch_config)
        .build()
}

// -----------------------------------------------------------------------------
// Resource Builder
// -----------------------------------------------------------------------------

/// Build the `OTel` [`Resource`] from configured service metadata.
///
/// Uses the SDK's [`EnvResourceDetector`] to pick up all attributes from
/// `OTEL_RESOURCE_ATTRIBUTES`, then layers config-supplied values on top
/// (config takes precedence over env-detected values).
///
/// [`Resource`]: opentelemetry_sdk::Resource
/// [`EnvResourceDetector`]: opentelemetry_sdk::resource::EnvResourceDetector
#[cfg(feature = "otel")]
fn build_otel_resource(config: &crate::config::TelemetryConfig) -> opentelemetry_sdk::Resource {
    use opentelemetry_sdk::resource::EnvResourceDetector;

    let service_name = config
        .service_name
        .clone()
        .unwrap_or_else(|| crate::config::TelemetryConfig::DEFAULT_SERVICE_NAME.to_owned());

    // Order matters: later attributes override earlier ones in the SDK builder.
    // Detector runs first (picks up OTEL_RESOURCE_ATTRIBUTES), then explicit
    // config values override any colliding keys.
    let mut builder = opentelemetry_sdk::Resource::builder()
        .with_detector(Box::new(EnvResourceDetector::new()))
        .with_service_name(service_name);

    if let Some(version) = &config.service_version {
        builder = builder.with_attribute(opentelemetry::KeyValue::new("service.version", version.clone()));
    }
    if let Some(env) = &config.environment {
        builder = builder.with_attribute(opentelemetry::KeyValue::new("deployment.environment", env.clone()));
    }

    builder.build()
}

// -----------------------------------------------------------------------------
// Metadata Builder
// -----------------------------------------------------------------------------

/// Build a tonic [`MetadataMap`] from the configured OTLP headers.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] if any header name or value is invalid.
///
/// [`MetadataMap`]: tonic::metadata::MetadataMap
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
#[cfg(feature = "otel")]
fn build_metadata_map(
    headers: &std::collections::HashMap<String, String>,
) -> Result<tonic::metadata::MetadataMap, ProxyError> {
    let mut metadata = tonic::metadata::MetadataMap::new();
    for (key, value) in headers {
        let name: tonic::metadata::MetadataKey<tonic::metadata::Ascii> = key
            .parse()
            .map_err(|e| ProxyError::Config(format!("invalid OTLP header name '{key}': {e}")))?;
        let val: tonic::metadata::MetadataValue<tonic::metadata::Ascii> = value
            .parse()
            .map_err(|e| ProxyError::Config(format!("invalid OTLP header value for '{key}': {e}")))?;
        metadata.insert(name, val);
    }
    Ok(metadata)
}

// -----------------------------------------------------------------------------
// Warnings
// -----------------------------------------------------------------------------

/// Warn if an OTLP endpoint is configured but the `otel` feature is not
/// compiled in.
#[cfg_attr(
    not(feature = "otel"),
    expect(clippy::print_stderr, reason = "tracing not yet initialized")
)]
fn warn_if_otel_config_without_feature(has_endpoint: bool, has_sampling: bool) {
    #[cfg(not(feature = "otel"))]
    if has_endpoint || has_sampling {
        eprintln!(
            "warning: telemetry OTel settings are configured but the `otel` feature is not \
             enabled; OTLP export and sampling are disabled. Rebuild with `--features otel` \
             to enable them."
        );
    }

    #[cfg(feature = "otel")]
    {
        let _ = has_endpoint;
        let _ = has_sampling;
    }
}

// -----------------------------------------------------------------------------
// EnvFilter Factory
// -----------------------------------------------------------------------------

/// Build an [`EnvFilter`] from `RUST_LOG` (or the given default) merged with any `log_overrides` from the config.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] listing every invalid log override entry.
///
/// [`EnvFilter`]: tracing_subscriber::EnvFilter
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
pub(crate) fn build_env_filter(config: &Config) -> Result<tracing_subscriber::EnvFilter, ProxyError> {
    let base = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if config.runtime.log_overrides.is_empty() {
        return Ok(base);
    }

    let directives = validate_and_build_directives(&base, &config.runtime.log_overrides)?;
    Ok(tracing_subscriber::EnvFilter::new(directives))
}

/// Validate all log override entries and build the combined directive string.
fn validate_and_build_directives(
    base: &tracing_subscriber::EnvFilter,
    overrides: &std::collections::HashMap<String, String>,
) -> Result<String, ProxyError> {
    let mut errors: Vec<String> = Vec::new();

    for (module, level) in overrides {
        if !is_valid_module_path(module) {
            errors.push(format!(
                "invalid module path '{module}' (must be alphanumeric, '_', or '::')"
            ));
        }
        if !is_valid_log_level(level) {
            errors.push(format!(
                "invalid level '{level}' for module '{module}' \
                 (must be error, warn, info, debug, or trace)"
            ));
        }
    }

    if !errors.is_empty() {
        return Err(ProxyError::Config(format!(
            "invalid log_overrides: {}",
            errors.join("; ")
        )));
    }

    let mut directives = base.to_string();
    for (module, level) in overrides {
        directives.push(',');
        directives.push_str(module);
        directives.push('=');
        directives.push_str(level);
    }

    Ok(directives)
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Returns `true` if `s` is a valid Rust module path and is non-empty.
fn is_valid_module_path(s: &str) -> bool {
    !s.is_empty()
        && s.split("::").all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                && segment.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

/// Returns `true` if `s` is one of the five tracing levels (case-insensitive).
fn is_valid_log_level(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "error" | "warn" | "info" | "debug" | "trace"
    )
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
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn empty_log_overrides_produces_valid_filter() {
        let config = config_with_overrides(HashMap::new());
        let filter = build_env_filter(&config).expect("empty overrides should succeed");
        let filter_str = filter.to_string();
        assert!(
            !filter_str.is_empty(),
            "filter with no overrides should still produce a non-empty directive string"
        );
    }

    #[test]
    fn log_overrides_appended_to_filter_string() {
        let mut overrides = HashMap::new();
        overrides.insert("praxis_filter".to_owned(), "trace".to_owned());
        overrides.insert("praxis_protocol".to_owned(), "debug".to_owned());

        let config = config_with_overrides(overrides);
        let filter = build_env_filter(&config).expect("valid overrides should succeed");
        let filter_str = filter.to_string();

        assert!(
            filter_str.contains("praxis_filter=trace"),
            "filter should contain praxis_filter=trace, got: {filter_str}"
        );
        assert!(
            filter_str.contains("praxis_protocol=debug"),
            "filter should contain praxis_protocol=debug, got: {filter_str}"
        );
    }

    #[test]
    fn invalid_module_path_is_rejected() {
        let mut overrides = HashMap::new();
        overrides.insert("trace,h2=off".to_owned(), "debug".to_owned());
        overrides.insert("praxis_core".to_owned(), "trace".to_owned());

        let config = config_with_overrides(overrides);
        let err = build_env_filter(&config).unwrap_err();
        let msg = err.to_string();

        assert!(
            msg.contains("invalid module path 'trace,h2=off'"),
            "error should identify the bad module path, got: {msg}"
        );
    }

    #[test]
    fn invalid_level_is_rejected() {
        let mut overrides = HashMap::new();
        overrides.insert("praxis_filter".to_owned(), "trace,h2=off".to_owned());
        overrides.insert("praxis_core".to_owned(), "debug".to_owned());

        let config = config_with_overrides(overrides);
        let err = build_env_filter(&config).unwrap_err();
        let msg = err.to_string();

        assert!(
            msg.contains("invalid level 'trace,h2=off'"),
            "error should identify the bad level, got: {msg}"
        );
    }

    #[test]
    fn multiple_invalid_overrides_reported_together() {
        let mut overrides = HashMap::new();
        overrides.insert("bad module".to_owned(), "info".to_owned());
        overrides.insert("praxis_core".to_owned(), "bogus".to_owned());

        let config = config_with_overrides(overrides);
        let err = build_env_filter(&config).unwrap_err();
        let msg = err.to_string();

        assert!(
            msg.contains("invalid module path 'bad module'"),
            "error should report bad module path, got: {msg}"
        );
        assert!(
            msg.contains("invalid level 'bogus'"),
            "error should report bad level, got: {msg}"
        );
    }

    #[test]
    fn empty_module_path_is_rejected() {
        assert!(!is_valid_module_path(""), "empty string should be invalid");
    }

    #[test]
    fn module_path_with_spaces_is_rejected() {
        assert!(!is_valid_module_path("praxis core"), "spaces should be invalid");
    }

    #[test]
    fn module_path_with_double_colon_segments() {
        assert!(
            is_valid_module_path("praxis_filter::pipeline"),
            "nested module path should be valid"
        );
    }

    #[test]
    fn module_path_with_empty_segment_is_rejected() {
        assert!(!is_valid_module_path("praxis::"), "trailing :: should be invalid");
        assert!(!is_valid_module_path("::praxis"), "leading :: should be invalid");
    }

    #[test]
    fn valid_log_levels_accepted() {
        for level in &["error", "warn", "info", "debug", "trace", "TRACE", "Info"] {
            assert!(is_valid_log_level(level), "{level} should be a valid log level");
        }
    }

    #[test]
    fn invalid_log_levels_rejected() {
        for level in &["off", "critical", "trace,h2=off", ""] {
            assert!(!is_valid_log_level(level), "{level} should be rejected as log level");
        }
    }

    #[test]
    fn telemetry_config_defaults_in_config() {
        let config = config_with_overrides(HashMap::new());
        assert!(
            config.telemetry.otlp_endpoint.is_none(),
            "telemetry.otlp_endpoint should default to None"
        );
        assert!(
            config.telemetry.sampling_rate.is_none(),
            "telemetry.sampling_rate should default to None"
        );
    }

    #[test]
    fn telemetry_config_parsed_in_config() {
        let yaml = r#"
listeners:
  - name: test
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
telemetry:
  otlp_endpoint: "http://collector:4317"
"#;
        let config = Config::from_yaml(yaml).expect("config with telemetry should parse");
        assert_eq!(
            config.telemetry.otlp_endpoint.as_deref(),
            Some("http://collector:4317"),
            "otlp_endpoint should be parsed from config"
        );
    }

    #[test]
    fn telemetry_sampling_rate_parsed_in_config() {
        let yaml = r#"
listeners:
  - name: test
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
telemetry:
  otlp_endpoint: "http://collector:4317"
  sampling_rate: 0.01
"#;
        let config = Config::from_yaml(yaml).expect("config with sampling_rate should parse");
        assert_eq!(
            config.telemetry.sampling_rate,
            Some(0.01),
            "sampling_rate should be parsed from config"
        );
    }

    #[test]
    fn telemetry_sampling_rate_out_of_range_rejected() {
        let yaml = r#"
listeners:
  - name: test
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
telemetry:
  sampling_rate: 2.0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("between 0.0 and 1.0"),
            "out-of-range sampling_rate should be rejected: {err}"
        );
    }

    #[test]
    fn telemetry_negative_sampling_rate_rejected() {
        let yaml = r#"
listeners:
  - name: test
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
telemetry:
  sampling_rate: -0.5
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("between 0.0 and 1.0"),
            "negative sampling_rate should be rejected: {err}"
        );
    }

    #[test]
    fn unknown_telemetry_field_rejected() {
        let yaml = r#"
listeners:
  - name: test
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
telemetry:
  bogus_field: true
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("bogus_field"),
            "unknown telemetry field should be rejected: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // OTel Feature Tests
    // -------------------------------------------------------------------------

    #[cfg(feature = "otel")]
    #[test]
    fn otel_provider_none_when_no_endpoint() {
        let config = crate::config::TelemetryConfig::default();
        let provider = build_otel_provider(&config).expect("should succeed with no endpoint");
        assert!(
            provider.is_none(),
            "provider should be None when no endpoint configured"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a minimal [`Config`] with the given log overrides.
    fn config_with_overrides(overrides: HashMap<String, String>) -> Config {
        let yaml = r#"
listeners:
  - name: test
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
"#;
        let mut config = Config::from_yaml(yaml).expect("test config should parse");
        config.runtime.log_overrides = overrides;
        config
    }
}
