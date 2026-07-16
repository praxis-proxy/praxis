// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration types and validation for the `ext_proc` filter.
//!
//! Defines the YAML-driven config surface ([`ExtProcConfig`]),
//! processing mode enums, and startup validation that rejects
//! unsupported feature combinations before a filter is constructed.

use praxis_filter::FilterError;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default per-message timeout in milliseconds.
pub(crate) const DEFAULT_MESSAGE_TIMEOUT_MS: u64 = 200;

/// Default HTTP status code returned on processor errors.
pub(crate) const DEFAULT_STATUS_ON_ERROR: u16 = 500;

/// Default deferred close timeout in milliseconds for best-effort
/// trailing stream cleanup.
pub(crate) const DEFAULT_DEFERRED_CLOSE_TIMEOUT_MS: u64 = 5000;

/// Default lifecycle timeout in milliseconds for coalesced drain.
pub(crate) const DEFAULT_LIFECYCLE_TIMEOUT_MS: u64 = 5000;

/// Maximum lifecycle timeout in milliseconds (5 minutes).
const MAX_LIFECYCLE_TIMEOUT_MS: u64 = 300_000;

/// Defense-in-depth cap for coalesced processor body mutations.
///
/// Matches Praxis's global absolute body ceiling without adding a
/// production dependency on `praxis-core` just for the constant.
pub(crate) const MAX_COALESCED_BODY_BYTES: usize = 67_108_864; // 64 MiB

// ---------------------------------------------------------------------------
// Phase
// ---------------------------------------------------------------------------

/// Processing phase for dispatching mutations to the correct target.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Phase {
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

// ---------------------------------------------------------------------------
// ExtProcConfig
// ---------------------------------------------------------------------------

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
pub(crate) struct ExtProcConfig {
    /// When `true`, the content-length header is preserved after
    /// external processing body mutation. Only relevant for body
    /// send modes that enable mutation.
    #[serde(default)]
    pub(crate) allow_content_length_header: bool,

    /// Whether the external processor may override the processing
    /// mode via `mode_override` in its responses.
    #[serde(default)]
    pub(crate) allow_mode_override: bool,

    /// Allowlist of processing modes the processor may override to.
    /// Only evaluated when `allow_mode_override` is `true`.
    #[serde(default)]
    pub(crate) allowed_override_modes: Vec<ProcessingModeConfig>,

    /// Best-effort timeout in milliseconds for trailing gRPC stream
    /// cleanup after the expected processor response is consumed.
    /// Zero skips cleanup entirely. Default: 5000.
    #[serde(default = "default_deferred_close_timeout_ms")]
    pub(crate) deferred_close_timeout_ms: u64,

    /// When `true`, `ImmediateResponse` messages from the processor
    /// are ignored.
    #[serde(default)]
    pub(crate) disable_immediate_response: bool,

    /// Controls which request/response headers are forwarded to the
    /// external processor. When unset, all headers are forwarded.
    pub(crate) forward_rules: Option<ForwardRulesConfig>,

    /// Maximum time in milliseconds to wait for deferred processor
    /// lifecycle responses in full-duplex coalesced mode. Default:
    /// 5000 (5 seconds). Covers the entire drain at request body
    /// EOS, not individual messages.
    #[serde(default = "default_lifecycle_timeout_ms")]
    pub(crate) lifecycle_timeout_ms: u64,

    /// Upper bound in milliseconds for `override_message_timeout`
    /// values sent by the external processor. When set, the server
    /// may extend the per-message timeout up to this limit.
    pub(crate) max_message_timeout_ms: Option<u64>,

    /// Per-message timeout in milliseconds.
    /// Maps to Envoy's `message_timeout`.
    #[serde(default = "default_message_timeout_ms")]
    pub(crate) message_timeout_ms: u64,

    /// Restricts which headers the external processor is allowed to
    /// mutate. When unset, all headers may be modified except
    /// pseudo-headers and `host`.
    pub(crate) mutation_rules: Option<MutationRulesConfig>,

    /// Observation-only mode. When enabled, request/response data is
    /// sent to the processor but the pipeline does not wait for a
    /// response before continuing.
    #[serde(default)]
    pub(crate) observability_mode: bool,

    /// Controls which parts of the request/response are sent to the
    /// external processor. Maps to Envoy's `processing_mode`.
    #[serde(default)]
    pub(crate) processing_mode: ProcessingModeConfig,

    /// Send body to the processor as it arrives without waiting for
    /// the header response. Only applies to `streamed` body mode.
    #[serde(default)]
    pub(crate) send_body_without_waiting_for_header_response: bool,

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
    pub(crate) status_on_error: u16,

    /// gRPC endpoint URI of the external processing server.
    pub(crate) target: String,
}

// ---------------------------------------------------------------------------
// ProcessingModeConfig
// ---------------------------------------------------------------------------

/// Controls which parts of the HTTP request and response are
/// forwarded to the external processor.
///
/// Mirrors Envoy's [`ProcessingMode`] proto.
///
/// [`ProcessingMode`]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_proc/v3/processing_mode.proto
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessingModeConfig {
    /// How to handle request headers. Default: `send`.
    #[serde(default = "HeaderSendMode::send")]
    pub(crate) request_header_mode: HeaderSendMode,

    /// How to handle response headers. Default: `send`.
    #[serde(default = "HeaderSendMode::send")]
    pub(crate) response_header_mode: HeaderSendMode,

    /// How to handle the request body. Default: `none`.
    #[serde(default)]
    pub(crate) request_body_mode: BodySendMode,

    /// How to handle the response body. Default: `none`.
    #[serde(default)]
    pub(crate) response_body_mode: BodySendMode,

    /// How to handle request trailers. Default: `skip`.
    #[serde(default)]
    pub(crate) request_trailer_mode: HeaderSendMode,

    /// How to handle response trailers. Default: `skip`.
    #[serde(default)]
    pub(crate) response_trailer_mode: HeaderSendMode,
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

// ---------------------------------------------------------------------------
// HeaderSendMode / BodySendMode
// ---------------------------------------------------------------------------

/// Controls whether headers or trailers are forwarded.
///
/// Default is `skip` (matching Envoy's trailer default). Header
/// fields that default to `send` use an explicit serde default.
#[derive(Debug, Default, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HeaderSendMode {
    /// Forward to the external processor.
    Send,

    /// Do not forward.
    #[default]
    Skip,
}

impl HeaderSendMode {
    /// Serde default function for header fields (request/response).
    pub(crate) fn send() -> Self {
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

// ---------------------------------------------------------------------------
// MutationRulesConfig / ForwardRulesConfig
// ---------------------------------------------------------------------------

/// Restricts which header mutations the external processor may apply.
///
/// Mirrors Envoy's `HeaderMutationRules`. When not configured, all
/// headers except pseudo-headers and `host` may be modified.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MutationRulesConfig {
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
pub(crate) struct ForwardRulesConfig {
    /// Only forward headers whose names match these entries.
    #[serde(default)]
    pub(crate) allowed_headers: Vec<String>,

    /// Never forward headers whose names match these entries.
    #[serde(default)]
    pub(crate) disallowed_headers: Vec<String>,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Reject config values for features not yet implemented.
///
/// Accepts the full config shape so that YAML is structurally valid.
/// Fields whose non-default values require unimplemented behaviour
/// produce a clear error rather than being silently ignored.
pub(crate) fn validate_config(cfg: &ExtProcConfig) -> Result<(), FilterError> {
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

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

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
/// Request and response trailers remain unsupported because Pingora
/// has no request-trailer hooks in this integration path.
fn validate_processing_mode(pm: ProcessingModeConfig) -> Result<(), FilterError> {
    if pm.request_header_mode == HeaderSendMode::Skip {
        return Err("ext_proc: request_header_mode 'skip' is not yet supported".into());
    }
    if !matches!(
        pm.request_body_mode,
        BodySendMode::None | BodySendMode::FullDuplexStreamed
    ) {
        let mode = pm.request_body_mode;
        return Err(format!(
            "ext_proc: request_body_mode '{mode}' is not yet supported \
             (only 'none' or 'full_duplex_streamed')"
        )
        .into());
    }
    if pm.response_body_mode != BodySendMode::None {
        let mode = pm.response_body_mode;
        return Err(format!("ext_proc: response_body_mode '{mode}' is not yet supported (only 'none')").into());
    }
    if pm.request_trailer_mode == HeaderSendMode::Send {
        return Err("ext_proc: request_trailer_mode 'send' is not yet supported \
             (Pingora has no request-trailer hooks)"
            .into());
    }
    if pm.response_trailer_mode == HeaderSendMode::Send {
        return Err("ext_proc: response_trailer_mode 'send' is not yet supported".into());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Serde default functions
// ---------------------------------------------------------------------------

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
