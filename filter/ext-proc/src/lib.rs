// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Envoy-compatible external processing (`ext_proc`) filter for Praxis.
//!
//! # Warning: Anti-Pattern
//!
//! **External processing is an anti-pattern.** It exists for backwards
//! compatibility with Envoy deployments and for rare situations where
//! no other solution is viable. Do not use it unless you are certain
//! it must be used.
//!
//! External processing adds a gRPC hop to every request, introducing
//! latency, operational complexity, and a new failure domain.
//! Praxis's native filter system — in-process, zero-copy, with
//! body streaming — handles the same use cases with less overhead
//! and no network boundary. Prefer writing a native [`HttpFilter`]
//! or using built-in filters (guardrails, body field extraction,
//! header transforms, classifier+branch chains) instead.
//!
//! The `ext-proc` feature is enabled by default so that existing
//! Envoy migrations work out of the box, but production deployments
//! should plan to replace `ext_proc` usage with native filters.
//!
//! # Overview
//!
//! This crate provides an [`HttpFilter`] that sends request and
//! response data to an external gRPC server for inspection or
//! mutation via the Envoy [`ext_proc`] protocol.
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
pub(crate) mod duplex;
mod mutations;
pub(crate) mod proto;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, HttpFilter, HttpFilterContext, Rejection, parse_filter_config,
};
use serde::Deserialize;
use tonic::transport::{Channel, Endpoint};

use crate::{
    duplex::{ExchangeConfig, ExchangeError, ExchangeEvent, ExtProcExchange},
    proto::envoy::service::ext_proc::v3::{BodyResponse, HttpBody, body_mutation, processing_request},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default per-message timeout in milliseconds.
const DEFAULT_MESSAGE_TIMEOUT_MS: u64 = 200;

/// Default HTTP status code returned on processor errors.
const DEFAULT_STATUS_ON_ERROR: u16 = 500;

/// Default deferred close timeout in milliseconds (observability mode).
const DEFAULT_DEFERRED_CLOSE_TIMEOUT_MS: u64 = 5000;

/// Default lifecycle timeout in milliseconds for coalesced drain.
const DEFAULT_LIFECYCLE_TIMEOUT_MS: u64 = 5000;

/// Maximum lifecycle timeout in milliseconds (5 minutes).
const MAX_LIFECYCLE_TIMEOUT_MS: u64 = 300_000;

/// Defense-in-depth cap for coalesced processor body mutations.
///
/// Matches Praxis's global absolute body ceiling without adding a
/// production dependency on `praxis-core` just for the constant.
const MAX_COALESCED_BODY_BYTES: usize = 67_108_864; // 64 MiB

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
    #[serde(default)]
    allowed_override_modes: Vec<ProcessingModeConfig>,

    /// Timeout in milliseconds for deferred gRPC stream closure in
    /// observability mode. Default: 5000.
    #[serde(default = "default_deferred_close_timeout_ms")]
    deferred_close_timeout_ms: u64,

    /// When `true`, `ImmediateResponse` messages from the processor
    /// are ignored.
    #[serde(default)]
    disable_immediate_response: bool,

    /// Controls which request/response headers are forwarded to the
    /// external processor. When unset, all headers are forwarded.
    forward_rules: Option<ForwardRulesConfig>,

    /// Maximum time in milliseconds to wait for deferred processor
    /// lifecycle responses in full-duplex coalesced mode. Default:
    /// 5000 (5 seconds). Covers the entire drain at request body
    /// EOS, not individual messages.
    #[serde(default = "default_lifecycle_timeout_ms")]
    lifecycle_timeout_ms: u64,

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

/// Returns the default lifecycle timeout in milliseconds.
fn default_lifecycle_timeout_ms() -> u64 {
    DEFAULT_LIFECYCLE_TIMEOUT_MS
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
pub(crate) enum BodySendMode {
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
    /// Convert to the proto [`BodySendMode`] enum integer value.
    ///
    /// Uses the generated proto enum names so the mapping stays
    /// correct if proto field numbers change.
    ///
    /// [`BodySendMode`]: crate::proto::envoy::service::ext_proc::v3::BodySendMode
    pub(crate) fn to_proto_i32(self) -> i32 {
        use crate::proto::envoy::service::ext_proc::v3::BodySendMode as ProtoMode;
        match self {
            Self::None => ProtoMode::None as i32,
            Self::Streamed => ProtoMode::Streamed as i32,
            Self::Buffered => ProtoMode::Buffered as i32,
            Self::BufferedPartial => ProtoMode::BufferedPartial as i32,
            Self::FullDuplexStreamed => ProtoMode::FullDuplexStreamed as i32,
        }
    }

    /// Whether this mode is full-duplex streamed.
    pub(crate) fn is_full_duplex(self) -> bool {
        self == Self::FullDuplexStreamed
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
    #[expect(dead_code, reason = "parsed for config compatibility; used in subsequent PRs")]
    #[serde(default)]
    allow: Vec<String>,

    /// Headers the processor is not allowed to mutate (denylist).
    #[expect(dead_code, reason = "parsed for config compatibility; used in subsequent PRs")]
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
    #[expect(dead_code, reason = "parsed for config compatibility; used in subsequent PRs")]
    #[serde(default)]
    allowed_headers: Vec<String>,

    /// Never forward headers matching these patterns.
    #[expect(dead_code, reason = "parsed for config compatibility; used in subsequent PRs")]
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
#[expect(clippy::too_many_lines, reason = "sequential field validation")]
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
    if cfg.lifecycle_timeout_ms == 0 {
        return Err("ext_proc: lifecycle_timeout_ms must be greater than 0".into());
    }
    if cfg.lifecycle_timeout_ms > MAX_LIFECYCLE_TIMEOUT_MS {
        let ms = cfg.lifecycle_timeout_ms;
        return Err(
            format!("ext_proc: lifecycle_timeout_ms ({ms}) exceeds maximum ({MAX_LIFECYCLE_TIMEOUT_MS})").into(),
        );
    }
    if cfg.lifecycle_timeout_ms < cfg.message_timeout_ms {
        let lc = cfg.lifecycle_timeout_ms;
        let msg = cfg.message_timeout_ms;
        return Err(format!("ext_proc: lifecycle_timeout_ms ({lc}) must be >= message_timeout_ms ({msg})").into());
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
///
/// Accepts `request_body_mode: full_duplex_streamed` alongside the
/// existing `none` default. Other body modes (`streamed`, `buffered`,
/// `buffered_partial`) remain unsupported.
///
/// For the partial request-routing milestone, full-duplex mode
/// requires `response_header_mode: skip` and rejects
/// `request_trailer_mode: send` because Pingora has no
/// request-trailer hooks.
#[expect(
    clippy::too_many_lines,
    reason = "sequential mode validation with full-duplex contract"
)]
fn validate_processing_mode(pm: ProcessingModeConfig) -> Result<(), FilterError> {
    if pm.request_header_mode == HeaderSendMode::Skip {
        return Err("ext_proc: request_header_mode 'skip' is not yet supported".into());
    }
    if pm.request_body_mode.is_full_duplex() {
        if pm.response_header_mode == HeaderSendMode::Send {
            return Err(
                "ext_proc: full-duplex request mode requires response_header_mode 'skip' until response lifecycle is implemented".into()
            );
        }
    } else if pm.response_header_mode == HeaderSendMode::Skip {
        return Err("ext_proc: response_header_mode 'skip' is not yet supported".into());
    }
    if !matches!(
        pm.request_body_mode,
        BodySendMode::None | BodySendMode::FullDuplexStreamed
    ) {
        let mode = pm.request_body_mode;
        return Err(format!(
            "ext_proc: request_body_mode '{mode}' is not yet supported (only 'none' or 'full_duplex_streamed')"
        )
        .into());
    }
    if pm.response_body_mode != BodySendMode::None {
        let mode = pm.response_body_mode;
        return Err(format!("ext_proc: response_body_mode '{mode}' is not yet supported (only 'none')").into());
    }
    if pm.request_trailer_mode == HeaderSendMode::Send {
        return Err(
            "ext_proc: request_trailer_mode 'send' is not yet supported (Pingora has no request-trailer hooks)".into(),
        );
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
pub struct ExtProcFilter {
    /// Parsed gRPC endpoint for deferred channel construction.
    ///
    /// The channel is created lazily via [`channel`] on the first
    /// request, inside the Tokio runtime that will drive I/O.
    /// Constructing it eagerly in `from_config` would bind it to
    /// the pipeline-construction runtime, which may differ from
    /// the request-processing runtime (e.g. Pingora).
    ///
    /// [`channel`]: Self::channel
    endpoint: Endpoint,

    /// Lazily-initialized gRPC channel, created on first use
    /// inside the request-processing Tokio runtime.
    lazy_channel: std::sync::OnceLock<Channel>,

    /// Per-message timeout for gRPC calls.
    message_timeout: Duration,

    /// Upper bound for processor-requested timeout overrides.
    max_message_timeout: Option<Duration>,

    /// Bounded lifecycle timeout for coalesced drain at request
    /// body EOS. Separate from per-message timeout.
    lifecycle_timeout: Duration,

    /// How the request body is forwarded to the processor.
    request_body_mode: BodySendMode,

    /// How the response body is forwarded to the processor.
    response_body_mode: BodySendMode,

    /// HTTP status code returned on processor errors.
    status_on_error: u16,

    /// gRPC endpoint URI (retained for diagnostics).
    target: String,
}

impl std::fmt::Debug for ExtProcFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtProcFilter")
            .field("target", &self.target)
            .field("message_timeout", &self.message_timeout)
            .field("request_body_mode", &self.request_body_mode)
            .field("status_on_error", &self.status_on_error)
            .finish_non_exhaustive()
    }
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

        let target_uri: http::Uri = cfg.target.parse().map_err(|e| -> FilterError {
            let target = &cfg.target;
            format!("ext_proc: invalid target URI '{target}': {e}").into()
        })?;
        let endpoint = Channel::builder(target_uri);

        let message_timeout = Duration::from_millis(cfg.message_timeout_ms);

        Ok(Box::new(Self {
            endpoint,
            lazy_channel: std::sync::OnceLock::new(),
            lifecycle_timeout: Duration::from_millis(cfg.lifecycle_timeout_ms),
            max_message_timeout: cfg.max_message_timeout_ms.map(Duration::from_millis),
            message_timeout,
            request_body_mode: cfg.processing_mode.request_body_mode,
            response_body_mode: cfg.processing_mode.response_body_mode,
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

    /// Get the gRPC channel, creating it lazily on first use.
    ///
    /// Uses [`OnceLock`] so initialization happens exactly once.
    /// `connect_lazy` defers the actual TCP/TLS handshake until
    /// the first gRPC call, so this method always returns a
    /// [`Channel`] without blocking.
    ///
    /// [`OnceLock`]: std::sync::OnceLock
    fn channel(&self) -> Channel {
        self.lazy_channel.get_or_init(|| self.endpoint.connect_lazy()).clone()
    }

    /// Convert an [`ExchangeError`] into a [`FilterError`].
    fn exchange_err(e: ExchangeError) -> FilterError {
        Box::new(e)
    }

    /// Build the [`ExchangeConfig`] for opening a duplex exchange.
    fn exchange_config(&self) -> ExchangeConfig {
        ExchangeConfig {
            message_timeout: self.message_timeout,
            max_message_timeout: self.max_message_timeout,
            request_body_mode: self.request_body_mode,
            response_body_mode: self.response_body_mode,
        }
    }

    /// Ensure the per-request exchange is open and request headers
    /// have been sent. Idempotent — returns immediately if headers
    /// were already sent.
    ///
    /// Stores [`ExtProcState`] in [`HttpFilterContext::filter_state`]
    /// so the exchange persists across `on_request` and
    /// `on_request_body` phases.
    fn ensure_exchange_and_send_headers(&self, ctx: &mut HttpFilterContext<'_>) -> Result<(), FilterError> {
        if ctx.get_filter_state::<ExtProcState>().is_some_and(|s| s.headers_sent) {
            return Ok(());
        }

        let headers = mutations::request_to_proto_headers(ctx);
        let headers_request = processing_request::Request::RequestHeaders(headers);

        let exchange =
            ExtProcExchange::open_with_request_headers(self.channel(), &self.exchange_config(), headers_request)
                .map_err(Self::exchange_err)?;

        let state = ExtProcState {
            exchange,
            headers_sent: true,
        };

        ctx.insert_filter_state(state);
        Ok(())
    }

    /// Drain the exchange after request body EOS: receive the
    /// deferred request-headers response, then all body responses.
    ///
    /// Applies header mutations from the headers response and
    /// coalesces streamed body response chunks into a single
    /// [`Bytes`] value that replaces `body`.
    ///
    /// Handles [`ImmediateResponse`] at any point by converting to
    /// [`FilterAction::Reject`].
    ///
    /// The exchange is temporarily removed from `filter_state` to
    /// satisfy the borrow checker — `receive()` needs `&mut exchange`
    /// while mutation helpers need `&mut ctx`. The exchange is
    /// reinserted before returning.
    ///
    /// [`ImmediateResponse`]: crate::proto::envoy::service::ext_proc::v3::ImmediateResponse
    async fn drain_exchange(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<FilterAction, FilterError> {
        // Take the exchange out of filter_state to avoid borrow
        // conflicts between `exchange.receive()` and `ctx` mutations.
        let mut state = ctx
            .remove_filter_state::<ExtProcState>()
            .ok_or_else(|| -> FilterError { "ext_proc: missing exchange state during drain".into() })?;

        let result = Self::drain_exchange_inner(&mut state, ctx, body).await;

        // Reinsert the exchange for potential later phases.
        ctx.insert_filter_state(state);

        result
    }

    /// Inner drain logic operating on an owned [`ExtProcState`].
    async fn drain_exchange_inner(
        state: &mut ExtProcState,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<FilterAction, FilterError> {
        if let Some(action) = Self::drain_header_response(state, ctx).await? {
            state.exchange.finish_sending();
            state.exchange.drain_trailing().await;
            return Ok(action);
        }

        let result = Self::drain_body_responses(state, ctx, body).await;
        state.exchange.finish_sending();
        state.exchange.drain_trailing().await;
        result
    }

    /// Receive and apply the deferred request-headers response.
    ///
    /// Returns `Some(FilterAction)` for terminal events
    /// ([`ImmediateResponse`]), `None` to continue draining.
    ///
    /// [`ImmediateResponse`]: crate::proto::envoy::service::ext_proc::v3::ImmediateResponse
    async fn drain_header_response(
        state: &mut ExtProcState,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<Option<FilterAction>, FilterError> {
        let event = state.exchange.receive().await.map_err(Self::exchange_err)?;

        match event {
            ExchangeEvent::RequestHeaders { response, metadata } => {
                apply_dynamic_metadata(metadata, ctx);
                mutations::apply_headers_response(&response, ctx, Phase::Request);
                Ok(None)
            },
            ExchangeEvent::Immediate { response, metadata } => {
                apply_dynamic_metadata(metadata, ctx);
                Ok(Some(mutations::immediate_to_rejection(&response)))
            },
            other => Err(format!("ext_proc: expected RequestHeaders or Immediate during drain, got {other:?}").into()),
        }
    }

    /// Receive body responses until EOS, coalescing chunks.
    #[expect(
        clippy::too_many_lines,
        reason = "body response loop with EOS and mutation extraction"
    )]
    async fn drain_body_responses(
        state: &mut ExtProcState,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<FilterAction, FilterError> {
        let mut coalesced = Vec::new();
        let mut has_body_mutation = false;
        let max_body_bytes = coalesced_body_limit(ctx);
        loop {
            let event = state.exchange.receive().await.map_err(Self::exchange_err)?;
            match event {
                ExchangeEvent::RequestBody { response, metadata } => {
                    apply_dynamic_metadata(metadata, ctx);
                    if let Some(common) = &response.response
                        && let Some(mutation) = &common.header_mutation
                    {
                        mutations::apply_request_header_mutation(mutation, ctx);
                    }
                    if let Some((chunk, is_eos)) = extract_streamed_body(&response) {
                        has_body_mutation = true;
                        let new_len = coalesced.len().checked_add(chunk.len()).ok_or_else(|| -> FilterError {
                            "ext_proc: coalesced body mutation size overflow".into()
                        })?;
                        if new_len > max_body_bytes {
                            return Err(
                                format!("ext_proc: coalesced body mutation exceeds {max_body_bytes} bytes").into(),
                            );
                        }
                        coalesced.extend_from_slice(&chunk);
                        if is_eos {
                            break;
                        }
                    } else {
                        break;
                    }
                },
                ExchangeEvent::Immediate { response, metadata } => {
                    apply_dynamic_metadata(metadata, ctx);
                    return Ok(mutations::immediate_to_rejection(&response));
                },
                other => {
                    return Err(
                        format!("ext_proc: expected RequestBody or Immediate during drain, got {other:?}").into(),
                    );
                },
            }
        }

        if has_body_mutation {
            *body = if coalesced.is_empty() {
                None
            } else {
                Some(Bytes::from(coalesced))
            };
        }
        Ok(FilterAction::Continue)
    }
}

/// Resolve the maximum bytes allowed for coalesced processor body
/// mutations in this request.
fn coalesced_body_limit(ctx: &HttpFilterContext<'_>) -> usize {
    match ctx.request_body_mode {
        BodyMode::StreamBuffer { max_bytes } => max_bytes.unwrap_or(MAX_COALESCED_BODY_BYTES),
        BodyMode::SizeLimit { max_bytes } => max_bytes.min(MAX_COALESCED_BODY_BYTES),
        _ => MAX_COALESCED_BODY_BYTES,
    }
}

// -----------------------------------------------------------------------------
// ExtProcState
// -----------------------------------------------------------------------------

/// Per-request state stored in [`HttpFilterContext::filter_state`].
///
/// Tracks the persistent duplex exchange and whether request
/// headers have been sent to the processor.
struct ExtProcState {
    /// Bidirectional exchange with the external processor.
    exchange: ExtProcExchange,

    /// Whether request headers have been committed to the exchange.
    headers_sent: bool,
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Apply `dynamic_metadata` from a processor response to the filter
/// context's structured metadata under the `ext_proc` namespace.
fn apply_dynamic_metadata(metadata: Option<prost_wkt_types::Struct>, ctx: &mut HttpFilterContext<'_>) {
    if let Some(md) = metadata {
        for (key, value) in md.fields {
            let json_value = proto_value_to_json(&value);
            ctx.set_structured_metadata("ext_proc", &key, json_value);
        }
    }
}

/// Convert a protobuf [`Value`] to a [`serde_json::Value`].
///
/// [`Value`]: prost_wkt_types::Value
pub(crate) fn proto_value_to_json(value: &prost_wkt_types::Value) -> serde_json::Value {
    match &value.kind {
        Some(prost_wkt_types::value::Kind::NumberValue(n)) => {
            serde_json::Number::from_f64(*n).map_or(serde_json::Value::Null, serde_json::Value::Number)
        },
        Some(prost_wkt_types::value::Kind::StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(prost_wkt_types::value::Kind::BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(prost_wkt_types::value::Kind::StructValue(s)) => {
            let map: serde_json::Map<String, serde_json::Value> = s
                .fields
                .iter()
                .map(|(k, v)| (k.clone(), proto_value_to_json(v)))
                .collect();
            serde_json::Value::Object(map)
        },
        Some(prost_wkt_types::value::Kind::ListValue(l)) => {
            let arr: Vec<serde_json::Value> = l.values.iter().map(proto_value_to_json).collect();
            serde_json::Value::Array(arr)
        },
        Some(prost_wkt_types::value::Kind::NullValue(_)) | None => serde_json::Value::Null,
    }
}

/// Extract the body bytes and EOS flag from a
/// [`BodyResponse`] containing a [`StreamedBodyResponse`].
///
/// Returns `None` when no body mutation is present — the caller
/// must preserve the original body. Returns `Some((bytes, eos))`
/// when a streamed body replacement is provided.
///
/// [`BodyResponse`]: crate::proto::envoy::service::ext_proc::v3::BodyResponse
/// [`StreamedBodyResponse`]: crate::proto::envoy::service::ext_proc::v3::StreamedBodyResponse
fn extract_streamed_body(response: &BodyResponse) -> Option<(Vec<u8>, bool)> {
    let bm = response.response.as_ref()?.body_mutation.as_ref()?;
    match &bm.mutation {
        Some(body_mutation::Mutation::StreamedResponse(sr)) => Some((sr.body.clone(), sr.end_of_stream)),
        _ => None,
    }
}

#[async_trait]
#[expect(
    clippy::too_many_lines,
    reason = "HttpFilter trait requires all hooks in one impl block"
)]
impl HttpFilter for ExtProcFilter {
    fn name(&self) -> &'static str {
        "ext_proc"
    }

    fn request_body_access(&self) -> BodyAccess {
        if self.request_body_mode.is_full_duplex() {
            BodyAccess::ReadWrite
        } else {
            BodyAccess::None
        }
    }

    fn request_body_mode(&self) -> BodyMode {
        if self.request_body_mode.is_full_duplex() {
            BodyMode::StreamBuffer { max_bytes: None }
        } else {
            BodyMode::Stream
        }
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if self.request_body_mode.is_full_duplex() {
            // Full-duplex: bootstrap the exchange and send headers,
            // then return Continue. Body processing happens in
            // on_request_body.
            let result = self.ensure_exchange_and_send_headers(ctx);
            return Ok(self.call_or_reject(result.map(|()| FilterAction::Continue)));
        }

        // Header-only mode: use the existing one-shot callout.
        Ok(self.call_or_reject(
            callout::process_request_headers(
                self.channel(),
                &self.target,
                self.message_timeout,
                self.max_message_timeout,
                ctx,
            )
            .await,
        ))
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !self.request_body_mode.is_full_duplex() {
            return Ok(FilterAction::Continue);
        }

        // Idempotent bootstrap — handles the case where
        // StreamBuffer pre-read invokes on_request_body before
        // on_request.
        let bootstrap_result = self.ensure_exchange_and_send_headers(ctx);
        if let Err(e) = bootstrap_result {
            return Ok(self.call_or_reject(Err(e)));
        }

        if !end_of_stream {
            // Intermediate chunk: forward bytes to the processor.
            let chunk_bytes = body.as_ref().map_or_else(Vec::new, |b| b.to_vec());
            let send_result = {
                let state = ctx
                    .get_filter_state_mut::<ExtProcState>()
                    .ok_or_else(|| -> FilterError { "ext_proc: missing exchange state".into() })?;
                state
                    .exchange
                    .send(processing_request::Request::RequestBody(HttpBody {
                        body: chunk_bytes,
                        end_of_stream: false,
                    }))
                    .await
                    .map_err(Self::exchange_err)
            };
            return Ok(self.call_or_reject(send_result.map(|()| FilterAction::Continue)));
        }

        // Synthetic EOS: send an empty terminal body marker.
        // The accumulated body was already sent incrementally
        // during pre-read. Do NOT resend it.
        let eos_result = {
            let state = ctx
                .get_filter_state_mut::<ExtProcState>()
                .ok_or_else(|| -> FilterError { "ext_proc: missing exchange state".into() })?;
            state
                .exchange
                .send(processing_request::Request::RequestBody(HttpBody {
                    body: Vec::new(),
                    end_of_stream: true,
                }))
                .await
        };
        match eos_result {
            Ok(()) => {},
            Err(ExchangeError::Closed) => {
                tracing::debug!(
                    target = %self.target,
                    "ext_proc: EOS body send skipped (exchange closed); proceeding to drain"
                );
            },
            Err(ExchangeError::SendFailed) => {
                tracing::warn!(
                    target = %self.target,
                    "ext_proc: EOS body send failed (channel closed); proceeding to drain"
                );
            },
            Err(e) => {
                return Ok(self.call_or_reject(Err(Self::exchange_err(e))));
            },
        }

        // Drain responses with a bounded lifecycle timeout.
        let drain_timeout = self.lifecycle_timeout;
        let drain_result = tokio::time::timeout(drain_timeout, self.drain_exchange(ctx, body)).await;

        match drain_result {
            Ok(Ok(action)) => Ok(action),
            Ok(Err(e)) => Ok(self.call_or_reject(Err(e))),
            Err(_elapsed) => {
                tracing::warn!(
                    target = %self.target,
                    timeout_ms = drain_timeout.as_millis(),
                    "ext_proc: lifecycle timeout during response drain"
                );
                Ok(FilterAction::Reject(Rejection::status(self.status_on_error)))
            },
        }
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if self.request_body_mode.is_full_duplex() {
            return Ok(FilterAction::Continue);
        }
        Ok(self.call_or_reject(
            callout::process_response_headers(
                self.channel(),
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
