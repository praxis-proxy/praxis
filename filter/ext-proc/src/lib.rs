// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Envoy-compatible external processing (`ext_proc`) filter for Praxis.
//!
//! This crate provides an [`HttpFilter`] that sends request and response
//! data to an external gRPC server for inspection or mutation via the
//! Envoy [`ext_proc`] protocol.
//!
//! The configuration surface mirrors the protocol-level fields of
//! Envoy's [`ExternalProcessor`] proto to simplify migration from
//! Envoy deployments. Fields for features not yet implemented are
//! accepted at parse time but rejected during validation with a
//! clear error.
//!
//! # Registration
//!
//! This filter is not included in [`FilterRegistry::with_builtins`].
//! Register it explicitly:
//!
//! ```ignore
//! use praxis_filter::FilterRegistry;
//!
//! let mut registry = FilterRegistry::with_builtins();
//! registry.register(
//!     "ext_proc",
//!     praxis_filter::http_builtin(praxis_ext_proc::ExtProcFilter::from_config),
//! ).unwrap();
//! ```
//!
//! [`HttpFilter`]: praxis_filter::HttpFilter
//! [`FilterRegistry::with_builtins`]: praxis_filter::FilterRegistry::with_builtins
//! [`ext_proc`]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/ext_proc/v3/external_processor.proto
//! [`ExternalProcessor`]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_proc/v3/ext_proc.proto

#![deny(unreachable_pub)]

mod callout;
#[expect(dead_code, reason = "wired into ExtProcFilter in follow-up PR")]
pub(crate) mod duplex;
mod mutations;
use std::time::Duration;

use async_trait::async_trait;
use praxis_filter::{FilterAction, FilterError, HttpFilter, HttpFilterContext, Rejection, parse_filter_config};
use serde::Deserialize;
use tonic::transport::{Channel, Endpoint};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default per-message timeout in milliseconds.
const DEFAULT_MESSAGE_TIMEOUT_MS: u64 = 200;

/// Default HTTP status code returned on processor errors.
const DEFAULT_STATUS_ON_ERROR: u16 = 500;

/// Default deferred close timeout in milliseconds (observability mode).
const DEFAULT_DEFERRED_CLOSE_TIMEOUT_MS: u64 = 5000;

// -----------------------------------------------------------------------------
// Phase
// -----------------------------------------------------------------------------

/// Processing phase for dispatching mutations to the correct target.
#[derive(Debug, Clone, Copy)]
enum Phase {
    /// Request headers phase.
    Request,

    /// Response headers phase.
    Response,
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request => f.write_str("request"),
            Self::Response => f.write_str("response"),
        }
    }
}

// -----------------------------------------------------------------------------
// ExtProcConfig
// -----------------------------------------------------------------------------

/// YAML configuration for the `ext_proc` filter.
///
/// Includes all protocol-level fields from Envoy's [`ExternalProcessor`]
/// proto so that existing `ext_proc` workloads can be ported with
/// minimal changes.
///
/// ```yaml
/// filter: ext_proc
/// target: "http://127.0.0.1:50051"
/// message_timeout_ms: 200
/// processing_mode:
///   request_header_mode: send
///   response_header_mode: send
///   request_body_mode: none
///   response_body_mode: none
/// ```
///
/// `failure_mode` is not part of this config. It is a pipeline-level
/// concern specified on the [`FilterEntry`] wrapper and enforced by
/// the pipeline executor.
///
/// # Envoy-specific fields not included
///
/// The following Envoy `ExternalProcessor` fields are not included
/// because they are tied to Envoy-internal subsystems with no Praxis
/// equivalent:
///
/// - `grpc_service` / `http_service` — Envoy service discovery config; use `target` URI instead
/// - `request_attributes` / `response_attributes` — Envoy attribute system
/// - `stat_prefix` — Envoy stats scoping
/// - `filter_metadata` — Envoy filter state for access logging
/// - `metadata_options` — Envoy dynamic metadata namespace forwarding/receiving
/// - `disable_clear_route_cache` / `route_cache_action` — Envoy route cache management
/// - `processing_request_modifier` / `on_processing_response` — Envoy extension point decorators (alpha)
///
/// [`FilterEntry`]: praxis_filter::FilterEntry
/// [`ExternalProcessor`]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_proc/v3/ext_proc.proto
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors Envoy ExternalProcessor proto fields"
)]
struct ExtProcConfig {
    /// When `true`, the content-length header is preserved after
    /// external processing body mutation. Only relevant for body
    /// send modes that enable mutation.
    #[serde(default)]
    allow_content_length_header: bool,

    /// Whether the external processor may override the processing
    /// mode via `mode_override` in its responses.
    #[serde(default)]
    allow_mode_override: bool,

    /// Allowlist of processing modes the processor may override to.
    /// Only evaluated when `allow_mode_override` is `true`.
    #[expect(clippy::allow_attributes, reason = "field stored for future use")]
    #[allow(dead_code, reason = "parsed for config compatibility; used in subsequent PRs")]
    #[serde(default)]
    allowed_override_modes: Vec<ProcessingModeConfig>,

    /// Timeout in milliseconds for deferred gRPC stream closure in
    /// observability mode. Default: 5000.
    #[expect(clippy::allow_attributes, reason = "field stored for future use")]
    #[allow(dead_code, reason = "parsed for config compatibility; used in subsequent PRs")]
    #[serde(default = "default_deferred_close_timeout_ms")]
    deferred_close_timeout_ms: u64,

    /// When `true`, `ImmediateResponse` messages from the processor
    /// are ignored.
    #[serde(default)]
    disable_immediate_response: bool,

    /// Controls which request/response headers are forwarded to the
    /// external processor. When unset, all headers are forwarded.
    #[expect(clippy::allow_attributes, reason = "field stored for future use")]
    #[allow(dead_code, reason = "parsed for config compatibility; used in subsequent PRs")]
    forward_rules: Option<ForwardRulesConfig>,

    /// Upper bound in milliseconds for `override_message_timeout`
    /// values sent by the external processor. When set, the server
    /// may extend the per-message timeout up to this limit.
    max_message_timeout_ms: Option<u64>,

    /// Per-message timeout in milliseconds.
    /// Maps to Envoy's `message_timeout`.
    #[serde(default = "default_message_timeout_ms")]
    message_timeout_ms: u64,

    /// Restricts which headers the external processor is allowed to
    /// mutate. When unset, all headers may be modified except
    /// pseudo-headers and `host`.
    #[expect(clippy::allow_attributes, reason = "field stored for future use")]
    #[allow(dead_code, reason = "parsed for config compatibility; used in subsequent PRs")]
    mutation_rules: Option<MutationRulesConfig>,

    /// Observation-only mode. When enabled, request/response data is
    /// sent to the processor but the pipeline does not wait for a
    /// response before continuing.
    #[serde(default)]
    observability_mode: bool,

    /// Controls which parts of the request/response are sent to the
    /// external processor. Maps to Envoy's `processing_mode`.
    #[serde(default)]
    processing_mode: ProcessingModeConfig,

    /// Send body to the processor as it arrives without waiting for
    /// the header response. Only applies to `streamed` body mode.
    #[serde(default)]
    send_body_without_waiting_for_header_response: bool,

    /// HTTP status code returned to the downstream client when the
    /// external processor returns an error, fails to respond, or
    /// cannot be reached. Default: 500.
    ///
    /// This takes precedence over the pipeline-level `failure_mode`:
    /// processor errors are converted to a rejection with this
    /// status code before the pipeline sees the result, so
    /// `failure_mode: open` does not produce fail-open behaviour
    /// for `ext_proc` callout errors.
    #[serde(default = "default_status_on_error")]
    status_on_error: u16,

    /// gRPC endpoint URI of the external processing server.
    target: String,
}

/// Returns the default message timeout in milliseconds.
fn default_message_timeout_ms() -> u64 {
    DEFAULT_MESSAGE_TIMEOUT_MS
}

/// Returns the default HTTP status on processor error.
fn default_status_on_error() -> u16 {
    DEFAULT_STATUS_ON_ERROR
}

/// Returns the default deferred close timeout in milliseconds.
fn default_deferred_close_timeout_ms() -> u64 {
    DEFAULT_DEFERRED_CLOSE_TIMEOUT_MS
}

// -----------------------------------------------------------------------------
// ProcessingModeConfig
// -----------------------------------------------------------------------------

/// Controls which parts of the HTTP request and response are
/// forwarded to the external processor.
///
/// Mirrors Envoy's [`ProcessingMode`] proto.
///
/// [`ProcessingMode`]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_proc/v3/processing_mode.proto
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessingModeConfig {
    /// How to handle request headers. Default: `send`.
    #[serde(default = "HeaderSendMode::send")]
    request_header_mode: HeaderSendMode,

    /// How to handle response headers. Default: `send`.
    #[serde(default = "HeaderSendMode::send")]
    response_header_mode: HeaderSendMode,

    /// How to handle the request body. Default: `none`.
    #[serde(default)]
    request_body_mode: BodySendMode,

    /// How to handle the response body. Default: `none`.
    #[serde(default)]
    response_body_mode: BodySendMode,

    /// How to handle request trailers. Default: `skip`.
    #[serde(default)]
    request_trailer_mode: HeaderSendMode,

    /// How to handle response trailers. Default: `skip`.
    #[serde(default)]
    response_trailer_mode: HeaderSendMode,
}

impl Default for ProcessingModeConfig {
    /// Envoy defaults: headers are sent, bodies are skipped,
    /// trailers are skipped.
    fn default() -> Self {
        Self {
            request_header_mode: HeaderSendMode::Send,
            response_header_mode: HeaderSendMode::Send,
            request_body_mode: BodySendMode::None,
            response_body_mode: BodySendMode::None,
            request_trailer_mode: HeaderSendMode::Skip,
            response_trailer_mode: HeaderSendMode::Skip,
        }
    }
}

// -----------------------------------------------------------------------------
// HeaderSendMode / BodySendMode
// -----------------------------------------------------------------------------

/// Controls whether headers or trailers are forwarded.
///
/// Default is `skip` (matching Envoy's trailer default). Header
/// fields that default to `send` use an explicit serde default.
#[derive(Debug, Default, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum HeaderSendMode {
    /// Forward to the external processor.
    Send,

    /// Do not forward.
    #[default]
    Skip,
}

impl HeaderSendMode {
    /// Serde default function for header fields (request/response).
    fn send() -> Self {
        Self::Send
    }
}

/// Controls whether and how the message body is forwarded.
#[derive(Debug, Default, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum BodySendMode {
    /// Do not send the body. This is the default.
    #[default]
    None,

    /// Stream body chunks as they arrive.
    Streamed,

    /// Buffer the entire body and send it at once.
    Buffered,

    /// Buffer up to the configured limit and send what fits.
    BufferedPartial,

    /// Full-duplex streaming with the external processor.
    FullDuplexStreamed,
}

impl std::fmt::Display for BodySendMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::Streamed => f.write_str("streamed"),
            Self::Buffered => f.write_str("buffered"),
            Self::BufferedPartial => f.write_str("buffered_partial"),
            Self::FullDuplexStreamed => f.write_str("full_duplex_streamed"),
        }
    }
}

impl BodySendMode {
    /// Whether this mode uses full-duplex streaming.
    pub(crate) fn is_full_duplex(self) -> bool {
        self == Self::FullDuplexStreamed
    }

    /// Convert to the protobuf [`BodySendMode`] enum integer value.
    ///
    /// [`BodySendMode`]: praxis_proto::envoy::service::ext_proc::v3::BodySendMode
    pub(crate) fn to_proto_i32(self) -> i32 {
        use praxis_proto::envoy::service::ext_proc::v3::BodySendMode as ProtoMode;
        match self {
            Self::None => ProtoMode::None as i32,
            Self::Streamed => ProtoMode::Streamed as i32,
            Self::Buffered => ProtoMode::Buffered as i32,
            Self::BufferedPartial => ProtoMode::BufferedPartial as i32,
            Self::FullDuplexStreamed => ProtoMode::FullDuplexStreamed as i32,
        }
    }
}

// -----------------------------------------------------------------------------
// MutationRulesConfig / ForwardRulesConfig
// -----------------------------------------------------------------------------

/// Restricts which header mutations the external processor may apply.
///
/// Mirrors Envoy's `HeaderMutationRules`. When not configured, all
/// headers except pseudo-headers and `host` may be modified.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationRulesConfig {
    /// Headers the processor is allowed to mutate (allowlist).
    #[expect(clippy::allow_attributes, reason = "field stored for future use")]
    #[allow(dead_code, reason = "parsed for config compatibility; used in subsequent PRs")]
    #[serde(default)]
    allow: Vec<String>,

    /// Headers the processor is not allowed to mutate (denylist).
    #[expect(clippy::allow_attributes, reason = "field stored for future use")]
    #[allow(dead_code, reason = "parsed for config compatibility; used in subsequent PRs")]
    #[serde(default)]
    deny: Vec<String>,
}

/// Controls which headers are forwarded to the external processor.
///
/// Mirrors Envoy's `HeaderForwardingRules`. When not configured,
/// all headers are forwarded.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardRulesConfig {
    /// Only forward headers matching these patterns.
    #[expect(clippy::allow_attributes, reason = "field stored for future use")]
    #[allow(dead_code, reason = "parsed for config compatibility; used in subsequent PRs")]
    #[serde(default)]
    allowed_headers: Vec<String>,

    /// Never forward headers matching these patterns.
    #[expect(clippy::allow_attributes, reason = "field stored for future use")]
    #[allow(dead_code, reason = "parsed for config compatibility; used in subsequent PRs")]
    #[serde(default)]
    disallowed_headers: Vec<String>,
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Reject config values for features not yet implemented.
///
/// Accepts the full config shape so that YAML is structurally valid.
/// Fields whose non-default values require unimplemented behaviour
/// produce a clear error rather than being silently ignored.
fn validate_config(cfg: &ExtProcConfig) -> Result<(), FilterError> {
    validate_core_fields(cfg)?;
    validate_processing_mode(cfg.processing_mode)?;

    if cfg.allow_mode_override {
        return Err("ext_proc: allow_mode_override is not yet supported".into());
    }
    if cfg.observability_mode {
        return Err("ext_proc: observability_mode is not yet supported".into());
    }
    if cfg.disable_immediate_response {
        return Err("ext_proc: disable_immediate_response is not yet supported".into());
    }
    if cfg.mutation_rules.is_some() {
        return Err("ext_proc: mutation_rules is not yet supported".into());
    }
    if cfg.forward_rules.is_some() {
        return Err("ext_proc: forward_rules is not yet supported".into());
    }
    if cfg.allow_content_length_header {
        return Err("ext_proc: allow_content_length_header is not yet supported".into());
    }
    if cfg.send_body_without_waiting_for_header_response {
        return Err("ext_proc: send_body_without_waiting_for_header_response is not yet supported".into());
    }
    if !cfg.allowed_override_modes.is_empty() {
        return Err("ext_proc: allowed_override_modes is not yet supported".into());
    }

    Ok(())
}

/// Validate core numeric fields.
fn validate_core_fields(cfg: &ExtProcConfig) -> Result<(), FilterError> {
    if !(100..=599).contains(&cfg.status_on_error) {
        let code = cfg.status_on_error;
        return Err(
            format!("ext_proc: status_on_error {code} is not a valid HTTP status code (must be 100..=599)").into(),
        );
    }
    if cfg.message_timeout_ms == 0 {
        return Err("ext_proc: message_timeout_ms must be greater than 0".into());
    }
    if cfg.deferred_close_timeout_ms > 0 && cfg.deferred_close_timeout_ms < cfg.message_timeout_ms {
        let close = cfg.deferred_close_timeout_ms;
        let msg = cfg.message_timeout_ms;
        return Err(
            format!("ext_proc: deferred_close_timeout_ms ({close}) must be >= message_timeout_ms ({msg})").into(),
        );
    }
    if let Some(max) = cfg.max_message_timeout_ms {
        if max == 0 {
            return Err("ext_proc: max_message_timeout_ms must be greater than 0".into());
        }
        if max < cfg.message_timeout_ms {
            let timeout = cfg.message_timeout_ms;
            return Err(
                format!("ext_proc: max_message_timeout_ms ({max}) must be >= message_timeout_ms ({timeout})").into(),
            );
        }
    }
    Ok(())
}

/// Reject unsupported [`ProcessingModeConfig`] values.
fn validate_processing_mode(pm: ProcessingModeConfig) -> Result<(), FilterError> {
    if pm.request_header_mode == HeaderSendMode::Skip {
        return Err("ext_proc: request_header_mode 'skip' is not yet supported".into());
    }
    if pm.response_header_mode == HeaderSendMode::Skip {
        return Err("ext_proc: response_header_mode 'skip' is not yet supported".into());
    }
    if pm.request_body_mode != BodySendMode::None {
        let mode = pm.request_body_mode;
        return Err(format!("ext_proc: request_body_mode '{mode}' is not yet supported (only 'none')").into());
    }
    if pm.response_body_mode != BodySendMode::None {
        let mode = pm.response_body_mode;
        return Err(format!("ext_proc: response_body_mode '{mode}' is not yet supported (only 'none')").into());
    }
    if pm.request_trailer_mode == HeaderSendMode::Send {
        return Err("ext_proc: request_trailer_mode 'send' is not yet supported".into());
    }
    if pm.response_trailer_mode == HeaderSendMode::Send {
        return Err("ext_proc: response_trailer_mode 'send' is not yet supported".into());
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// ExtProcFilter
// -----------------------------------------------------------------------------

/// External processing filter using the Envoy `ext_proc` gRPC protocol.
///
/// Validates the target URI and config at construction time (fail-fast)
/// and builds a lazily-connecting gRPC channel.
///
/// # YAML configuration
///
/// ```yaml
/// filter: ext_proc
/// target: "http://127.0.0.1:50051"
/// message_timeout_ms: 200
/// status_on_error: 500
/// processing_mode:
///   request_header_mode: send
///   response_header_mode: send
///   request_body_mode: none
///   response_body_mode: none
/// ```
#[derive(Debug)]
pub struct ExtProcFilter {
    /// Lazily-connecting gRPC channel to the external processor.
    channel: Channel,

    /// Per-message timeout for gRPC calls.
    message_timeout: Duration,

    /// Upper bound for processor-requested timeout overrides.
    max_message_timeout: Option<Duration>,

    /// HTTP status code returned on processor errors.
    status_on_error: u16,

    /// gRPC endpoint URI (retained for diagnostics).
    target: String,
}

impl ExtProcFilter {
    /// Create from parsed YAML config.
    ///
    /// Validates the target URI and all config fields at construction
    /// time. Unsupported non-default values are rejected with a clear
    /// error message.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is malformed, the
    /// target URI is invalid, or an unsupported feature is requested.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: ExtProcConfig = parse_filter_config("ext_proc", config)?;
        validate_config(&cfg)?;

        let endpoint: Endpoint = cfg.target.parse().map_err(|e| -> FilterError {
            let target = &cfg.target;
            format!("ext_proc: invalid target URI '{target}': {e}").into()
        })?;

        let channel = endpoint.connect_lazy();

        Ok(Box::new(Self {
            channel,
            max_message_timeout: cfg.max_message_timeout_ms.map(Duration::from_millis),
            message_timeout: Duration::from_millis(cfg.message_timeout_ms),
            status_on_error: cfg.status_on_error,
            target: cfg.target,
        }))
    }

    /// Convert a callout error into a rejection with [`status_on_error`].
    ///
    /// On success the action passes through unchanged. On error the
    /// processor failure is logged and a [`FilterAction::Reject`] is
    /// returned with the configured status code, matching Envoy's
    /// error-handling behaviour. Because the error is consumed here,
    /// the pipeline always sees `Ok(Reject(...))` — the pipeline-level
    /// `failure_mode` does not apply to `ext_proc` processor errors.
    ///
    /// [`status_on_error`]: ExtProcConfig::status_on_error
    fn call_or_reject(&self, result: Result<FilterAction, FilterError>) -> FilterAction {
        match result {
            Ok(action) => action,
            Err(e) => {
                tracing::warn!(
                    target = %self.target,
                    status = self.status_on_error,
                    error = %e,
                    "ext_proc: processor error, rejecting with status_on_error"
                );
                FilterAction::Reject(Rejection::status(self.status_on_error))
            },
        }
    }
}

#[async_trait]
impl HttpFilter for ExtProcFilter {
    fn name(&self) -> &'static str {
        "ext_proc"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(self.call_or_reject(
            callout::process_request_headers(
                self.channel.clone(),
                &self.target,
                self.message_timeout,
                self.max_message_timeout,
                ctx,
            )
            .await,
        ))
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(self.call_or_reject(
            callout::process_response_headers(
                self.channel.clone(),
                &self.target,
                self.message_timeout,
                self.max_message_timeout,
                ctx,
            )
            .await,
        ))
    }
}

#[cfg(test)]
mod tests;
