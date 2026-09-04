// SPDX-License-Identifier: Apache-2.0
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

mod log_level;

use std::sync::Arc;

pub use log_level::{
    DEFAULT_OVERLAY_DURATION_SECS, GLOBAL_OVERLAY_KEY, LogLevelError, LogLevelOverlayView, LogLevelState,
    LogLevelStateResponse, MAX_OVERLAY_DURATION_SECS, PutLogLevelRequest,
};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{layer::SubscriberExt as _, reload, util::SubscriberInitExt as _};

use crate::{config::Config, errors::ProxyError};

// -----------------------------------------------------------------------------
// TracingGuard
// -----------------------------------------------------------------------------

/// RAII guard that flushes pending output on drop: it shuts down the `OTel`
/// tracer provider and stops the non-blocking log writer worker, flushing
/// any buffered log lines to their destination.
///
/// ```no_run
/// let config = praxis_core::config::Config::load(None, "listeners: []").unwrap();
/// let _guard = praxis_core::logging::init_tracing(&config).unwrap();
/// ```
#[must_use = "dropping the guard immediately shuts down the tracer provider"]
pub struct TracingGuard {
    #[cfg(feature = "otel")]
    /// Optional OTLP tracer provider held until shutdown.
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
    /// Optional non-blocking appender worker guard.
    worker_guard: Option<WorkerGuard>,
    /// Tokio runtime kept alive for the tonic gRPC exporter.
    #[cfg(feature = "otel")]
    _otel_runtime: Option<::tokio::runtime::Runtime>,
    /// Runtime log-level overlay state for the admin API.
    log_level: Arc<LogLevelState>,
}

impl TracingGuard {
    /// Shared runtime log-level state for admin `/api/log-level`.
    #[must_use]
    pub fn log_level_state(&self) -> Arc<LogLevelState> {
        Arc::clone(&self.log_level)
    }
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        #[cfg(feature = "otel")]
        if let Some(provider) = self.provider.take() {
            #[expect(clippy::print_stderr, reason = "tracing subscriber is being torn down")]
            if let Err(e) = provider.shutdown() {
                eprintln!("failed to shut down OTel tracer provider: {e}");
            }
        }

        // Drop worker guard to flush queued log lines, then runtime drops automatically.
        drop(self.worker_guard.take());
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
/// Returns [`ProxyError::Config`] if logging or log override settings are invalid,
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
    validate_logging(config)?;
    let baseline = build_baseline_directive(config)?;
    let env_filter = tracing_subscriber::EnvFilter::new(&baseline);
    let (filter_layer, reload_handle) = reload::Layer::new(env_filter);
    let log_level = LogLevelState::new(baseline, reload_handle);

    let json = std::env::var("PRAXIS_LOG_FORMAT").is_ok_and(|v| v.eq_ignore_ascii_case("json"));
    let telemetry = config.telemetry.resolve();
    let writer_bundle = writer::build_log_writer(&config.runtime.logging)?;

    warn_if_otel_config_without_feature(telemetry.otlp_endpoint.is_some(), telemetry.sampling_rate.is_some());

    #[cfg(feature = "otel")]
    return init_with_otel(filter_layer, json, &telemetry, writer_bundle, Arc::clone(&log_level));

    #[cfg(not(feature = "otel"))]
    {
        init_fmt_only(filter_layer, json, writer_bundle.writer);
        Ok(TracingGuard {
            worker_guard: writer_bundle.worker_guard,
            log_level,
        })
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

/// Validate `runtime.logging` without initializing the global subscriber.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] when logging settings are invalid.
pub fn validate_logging(config: &Config) -> Result<(), ProxyError> {
    config.runtime.logging.validate().map_err(ProxyError::Config)
}

// -----------------------------------------------------------------------------
// Log Writer Construction
// -----------------------------------------------------------------------------

mod writer {
    //! Builds tracing fmt-layer writers for `runtime.logging`.
    use std::{
        fs,
        io::{self, Write},
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };

    use tracing_appender::non_blocking::{NonBlocking, NonBlockingBuilder, WorkerGuard};
    use tracing_subscriber::fmt::writer::BoxMakeWriter;

    use crate::{
        config::{LogOutput, LoggingConfig},
        errors::ProxyError,
    };

    /// Non-blocking writer and optional background worker for shutdown flush.
    pub(super) struct LogWriterBundle {
        /// `MakeWriter` passed to the fmt layer.
        pub writer: BoxMakeWriter,
        /// Background worker guard; dropped after OTLP shutdown to flush queued lines.
        pub worker_guard: Option<WorkerGuard>,
    }

    /// Build the fmt-layer writer bundle from `runtime.logging`.
    pub(super) fn build_log_writer(cfg: &LoggingConfig) -> Result<LogWriterBundle, ProxyError> {
        cfg.validate().map_err(ProxyError::Config)?;

        match cfg.output {
            LogOutput::Stdout => Ok(build_stream_writer(io::stdout, cfg)),
            LogOutput::Stderr => Ok(build_stream_writer(io::stderr, cfg)),
            LogOutput::File => build_file_writer(cfg),
        }
    }

    /// Wrap stdout/stderr with optional non-blocking delivery.
    fn build_stream_writer<F, W>(make_writer: F, cfg: &LoggingConfig) -> LogWriterBundle
    where
        F: Fn() -> W + Send + Sync + 'static,
        W: Write + Send + 'static,
    {
        if cfg.non_blocking {
            let (non_blocking, guard) = wrap_non_blocking(make_writer(), cfg);
            LogWriterBundle {
                writer: BoxMakeWriter::new(non_blocking),
                worker_guard: Some(guard),
            }
        } else {
            LogWriterBundle {
                writer: BoxMakeWriter::new(make_writer),
                worker_guard: None,
            }
        }
    }

    /// Build an append-only, buffered file-backed writer.
    ///
    /// Praxis does not rotate log files; rotation and retention are
    /// delegated to the platform (journald, `logrotate`, container
    /// log drivers).
    fn build_file_writer(cfg: &LoggingConfig) -> Result<LogWriterBundle, ProxyError> {
        let path = cfg.file_path.as_ref().ok_or_else(|| {
            ProxyError::Config("runtime.logging.file_path is required when output is file".to_owned())
        })?;
        let path = PathBuf::from(path);

        ensure_parent_dir(&path)?;
        let raw: Box<dyn Write + Send + Sync> = Box::new(
            open_append_file(&path)
                .map_err(|e| ProxyError::Config(format!("failed to open log file '{}': {e}", path.display())))?,
        );

        if cfg.non_blocking {
            let (non_blocking, guard) = wrap_non_blocking(raw, cfg);
            Ok(LogWriterBundle {
                writer: BoxMakeWriter::new(non_blocking),
                worker_guard: Some(guard),
            })
        } else {
            let writer = SyncFileWriter(Arc::new(Mutex::new(raw)));
            Ok(LogWriterBundle {
                writer: BoxMakeWriter::new(move || writer.clone()),
                worker_guard: None,
            })
        }
    }

    /// Install a lossy non-blocking queue in front of `writer`.
    fn wrap_non_blocking<W: Write + Send + 'static>(writer: W, cfg: &LoggingConfig) -> (NonBlocking, WorkerGuard) {
        NonBlockingBuilder::default()
            .buffered_lines_limit(cfg.effective_buffer_size_lines())
            .lossy(true)
            .finish(writer)
    }

    /// Open a log file for append-only writes.
    fn open_append_file(path: &Path) -> io::Result<fs::File> {
        fs::OpenOptions::new().create(true).append(true).open(path)
    }

    /// Create parent directories for `path` when needed.
    fn ensure_parent_dir(path: &Path) -> Result<(), ProxyError> {
        let Some(parent) = path.parent() else {
            return Err(ProxyError::Config(format!(
                "log file path '{}' has no parent directory",
                path.display()
            )));
        };
        if parent.as_os_str().is_empty() {
            return Ok(());
        }
        fs::create_dir_all(parent)
            .map_err(|e| ProxyError::Config(format!("failed to create log directory '{}': {e}", parent.display())))
    }

    /// Mutex-backed synchronous writer used when `non_blocking: false`.
    #[derive(Clone)]
    struct SyncFileWriter(Arc<Mutex<Box<dyn Write + Send + Sync>>>);

    impl Write for SyncFileWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .map_err(|_e| io::Error::other("sync log writer lock poisoned"))?
                .write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0
                .lock()
                .map_err(|_e| io::Error::other("sync log writer lock poisoned"))?
                .flush()
        }
    }
}

// -----------------------------------------------------------------------------
// Subscriber Initialization
// -----------------------------------------------------------------------------

/// Initialize the layered subscriber with an optional OTLP layer.
#[cfg(feature = "otel")]
#[expect(
    clippy::too_many_lines,
    reason = "tracing-subscriber layer composition creates deeply nested generic types; runs once at startup"
)]
fn init_with_otel(
    filter_layer: reload::Layer<tracing_subscriber::EnvFilter, tracing_subscriber::Registry>,
    json: bool,
    telemetry: &crate::config::TelemetryConfig,
    writer_bundle: writer::LogWriterBundle,
    log_level: Arc<LogLevelState>,
) -> Result<TracingGuard, ProxyError> {
    use opentelemetry::trace::TracerProvider as _;

    let (provider, otel_runtime) = build_otel_provider(telemetry)?;
    let writer = writer_bundle.writer;
    let worker_guard = writer_bundle.worker_guard;

    if json {
        let otel_layer = provider
            .as_ref()
            .map(|p| tracing_opentelemetry::layer().with_tracer(p.tracer("praxis")));
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(writer)
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
            .with(filter_layer)
            .with(tracing_subscriber::fmt::layer().with_writer(writer))
            .with(otel_layer)
            .init();
    }

    Ok(TracingGuard {
        #[cfg(feature = "otel")]
        provider,
        worker_guard,
        #[cfg(feature = "otel")]
        _otel_runtime: otel_runtime,
        log_level,
    })
}

/// Initialize the layered subscriber with fmt only (no `otel` feature).
#[cfg(not(feature = "otel"))]
fn init_fmt_only(
    filter_layer: reload::Layer<tracing_subscriber::EnvFilter, tracing_subscriber::Registry>,
    json: bool,
    writer: tracing_subscriber::fmt::writer::BoxMakeWriter,
) {
    if json {
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(writer)
                    .with_current_span(true)
                    .with_span_list(true),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(tracing_subscriber::fmt::layer().with_writer(writer))
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
) -> Result<
    (
        Option<opentelemetry_sdk::trace::SdkTracerProvider>,
        Option<::tokio::runtime::Runtime>,
    ),
    ProxyError,
> {
    let Some(endpoint) = config.otlp_endpoint.as_deref() else {
        return Ok((None, None));
    };

    let runtime = build_exporter_runtime()?;

    // Both tonic (gRPC) and reqwest (HTTP) clients need a Tokio runtime context.
    // Enter the kept-alive runtime; nothing is awaited, setup is synchronous.
    let exporter = {
        let _guard = runtime.enter();
        let protocol = resolve_otlp_protocol();
        build_span_exporter(endpoint, config.otlp_headers.as_ref(), &protocol)?
    };
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

    Ok((Some(provider), Some(runtime)))
}

/// Build the single-worker Tokio runtime that owns the OTLP exporter's I/O.
///
/// Kept alive inside [`TracingGuard`] so the batch exporter keeps a reactor
/// for the process lifetime regardless of the caller's runtime.
#[cfg(feature = "otel")]
fn build_exporter_runtime() -> Result<::tokio::runtime::Runtime, ProxyError> {
    ::tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(|e| ProxyError::Config(format!("failed to create OTel runtime: {e}")))
}

// -----------------------------------------------------------------------------
// OTLP Exporter Builder
// -----------------------------------------------------------------------------

/// Resolve the OTLP export protocol from `OTEL_EXPORTER_OTLP_PROTOCOL`
/// env var, defaulting to `"grpc"`.
#[cfg(feature = "otel")]
fn resolve_otlp_protocol() -> String {
    std::env::var(crate::config::OTLP_PROTOCOL_ENV_VAR)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "grpc".to_owned())
}

/// Build the OTLP span exporter for the selected protocol.
#[cfg(feature = "otel")]
fn build_span_exporter(
    endpoint: &str,
    headers: Option<&std::collections::HashMap<String, String>>,
    protocol: &str,
) -> Result<opentelemetry_otlp::SpanExporter, ProxyError> {
    match protocol {
        "grpc" => build_grpc_exporter(endpoint, headers),
        "http/protobuf" => build_http_exporter(endpoint, headers),
        other => Err(ProxyError::Config(format!(
            "unsupported OTLP protocol \"{other}\"; supported: \"grpc\", \"http/protobuf\""
        ))),
    }
}

/// Build a gRPC (tonic) OTLP span exporter.
#[cfg(feature = "otel")]
fn build_grpc_exporter(
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
        .map_err(|e| ProxyError::Config(format!("failed to build OTLP gRPC exporter: {e}")))
}

/// Build an HTTP/protobuf OTLP span exporter.
#[cfg(feature = "otel")]
fn build_http_exporter(
    endpoint: &str,
    headers: Option<&std::collections::HashMap<String, String>>,
) -> Result<opentelemetry_otlp::SpanExporter, ProxyError> {
    use opentelemetry_otlp::{WithExportConfig as _, WithHttpConfig as _};

    // opentelemetry-otlp does not append the signal path when the endpoint is
    // set programmatically (unlike env-var config). If the endpoint has no path
    // or only "/", append the standard OTLP traces path.
    let endpoint = append_signal_path_if_needed(endpoint);

    let mut builder = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint);

    if let Some(hdrs) = headers {
        builder = builder.with_headers(hdrs.clone());
    }

    builder
        .build()
        .map_err(|e| ProxyError::Config(format!("failed to build OTLP HTTP exporter: {e}")))
}

/// Append `/v1/traces` to the endpoint if it has no path component.
///
/// When an endpoint like `http://host:4317` or `http://host:4317/` is
/// configured, the programmatic HTTP exporter does not automatically append
/// the signal path (unlike env-var based configuration). This function
/// detects endpoints with no meaningful path and appends the standard
/// OTLP traces signal path.
#[cfg(feature = "otel")]
fn append_signal_path_if_needed(endpoint: &str) -> String {
    // Parse the endpoint; if invalid, return as-is (the builder will error later)
    let Ok(url) = endpoint.parse::<http::Uri>() else {
        return endpoint.to_owned();
    };

    // Check if the path is empty or just "/"
    let path = url.path();
    if path.is_empty() || path == "/" {
        // Append the signal path
        format!("{}/v1/traces", endpoint.trim_end_matches('/'))
    } else {
        // Path already present; use as-is
        endpoint.to_owned()
    }
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

    // The queue must hold at least one full export batch, or spans beyond
    // the queue cap are silently dropped before they can ever be exported.
    let batch_config = opentelemetry_sdk::trace::BatchConfigBuilder::default()
        .with_max_export_batch_size(batch_size)
        .with_max_queue_size(batch_size.max(2_048))
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

/// Build the baseline directive string from `RUST_LOG` and `runtime.log_overrides`.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] when overrides are invalid.
pub fn build_baseline_directive(config: &Config) -> Result<String, ProxyError> {
    Ok(build_env_filter(config)?.to_string())
}

/// Returns `true` if `s` is a valid Rust module path and is non-empty.
pub(super) fn is_valid_module_path(s: &str) -> bool {
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

/// Returns `true` for admin overlay levels, including temporary `off`.
pub(super) fn is_valid_admin_log_level(s: &str) -> bool {
    is_valid_log_level(s) || s.eq_ignore_ascii_case("off")
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
    use crate::config::{LogOutput, LoggingConfig};

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

    #[test]
    fn logging_config_parsed_from_runtime() {
        let yaml = r#"
runtime:
  logging:
    output: file
    file_path: /tmp/praxis.log
    buffer_size: 8192
listeners:
  - name: test
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
"#;
        let config = Config::from_yaml(yaml).expect("logging config should parse");
        assert_eq!(config.runtime.logging.output, LogOutput::File);
        assert_eq!(config.runtime.logging.file_path.as_deref(), Some("/tmp/praxis.log"));
        assert_eq!(config.runtime.logging.buffer_size, Some(8192));
    }

    #[test]
    fn build_file_writer_opens_active_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.log");
        let cfg = LoggingConfig {
            output: LogOutput::File,
            file_path: Some(path.to_string_lossy().into_owned()),
            ..LoggingConfig::default()
        };
        let bundle = writer::build_log_writer(&cfg).expect("file writer should build");
        assert!(
            bundle.worker_guard.is_some(),
            "default non_blocking should install a worker guard"
        );
        drop(bundle.worker_guard);
    }

    // -------------------------------------------------------------------------
    // OTel Feature Tests
    // -------------------------------------------------------------------------

    #[cfg(feature = "otel")]
    #[test]
    fn otel_provider_none_when_no_endpoint() {
        let config = crate::config::TelemetryConfig::default();
        let (provider, runtime) = build_otel_provider(&config).expect("should succeed with no endpoint");
        assert!(
            provider.is_none(),
            "provider should be None when no endpoint configured"
        );
        assert!(
            runtime.is_none(),
            "no exporter runtime should be created without an endpoint"
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

    #[test]
    fn otel_warning_fires_for_endpoint_without_feature() {
        warn_if_otel_config_without_feature(true, false);
        warn_if_otel_config_without_feature(false, true);
        warn_if_otel_config_without_feature(true, true);
    }

    #[test]
    fn otel_warning_silent_without_otel_settings() {
        warn_if_otel_config_without_feature(false, false);
    }

    #[test]
    fn init_tracing_installs_global_subscriber() {
        // Global subscriber installation is once-per-process, so this is
        // the only test allowed to call init_tracing.
        let config = config_with_overrides(HashMap::new());
        let guard = init_tracing(&config).expect("tracing initialization should succeed");
        drop(guard);
    }
}
