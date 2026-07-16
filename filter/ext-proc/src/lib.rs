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
pub(crate) mod config;
pub(crate) mod duplex;
mod mutations;
pub(crate) mod proto;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, HttpFilter, HttpFilterContext, Rejection, parse_filter_config,
};
use tonic::transport::{Channel, Endpoint};

use crate::{
    config::{BodySendMode, ExtProcConfig, HeaderSendMode, MAX_COALESCED_BODY_BYTES, Phase, validate_config},
    duplex::{ExchangeConfig, ExchangeError, ExchangeEvent, ExtProcExchange},
    proto::envoy::service::ext_proc::v3::{BodyResponse, HttpBody, body_mutation, processing_request},
};

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

    /// Compiled header-forwarding rules controlling which headers
    /// are sent to the external processor.
    forward_rules: mutations::ForwardRules,

    /// Lazily-initialized gRPC channel, created on first use
    /// inside the request-processing Tokio runtime.
    lazy_channel: std::sync::OnceLock<Channel>,

    /// Per-message timeout for gRPC calls.
    message_timeout: Duration,

    /// Upper bound for processor-requested timeout overrides.
    max_message_timeout: Option<Duration>,

    /// Best-effort timeout for trailing stream cleanup after the
    /// expected processor response has been consumed. Zero skips
    /// the drain entirely.
    deferred_close_timeout: Duration,

    /// Bounded lifecycle timeout for coalesced drain at request
    /// body EOS. Separate from per-message timeout.
    lifecycle_timeout: Duration,

    /// How the request body is forwarded to the processor.
    request_body_mode: BodySendMode,

    /// How the response body is forwarded to the processor.
    response_body_mode: BodySendMode,

    /// Whether response headers are forwarded to the processor.
    response_header_mode: HeaderSendMode,

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
            .field("response_header_mode", &self.response_header_mode)
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

        let forward_rules = match cfg.forward_rules {
            Some(fr) => mutations::ForwardRules::new(fr.allowed_headers, fr.disallowed_headers),
            None => mutations::ForwardRules::default(),
        };

        Ok(Box::new(Self {
            deferred_close_timeout: Duration::from_millis(cfg.deferred_close_timeout_ms),
            endpoint,
            forward_rules,
            lazy_channel: std::sync::OnceLock::new(),
            lifecycle_timeout: Duration::from_millis(cfg.lifecycle_timeout_ms),
            max_message_timeout: cfg.max_message_timeout_ms.map(Duration::from_millis),
            message_timeout,
            request_body_mode: cfg.processing_mode.request_body_mode,
            response_body_mode: cfg.processing_mode.response_body_mode,
            response_header_mode: cfg.processing_mode.response_header_mode,
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
                tracing::error!(
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

    /// Best-effort trailing cleanup for non-lifecycle exchange paths.
    ///
    /// Calls `finish_sending()` then drains remaining server data
    /// within `deferred_close_timeout`. If the timeout is zero or
    /// the drain times out, the exchange is dropped without waiting.
    async fn bounded_cleanup(&self, exchange: &mut ExtProcExchange) {
        exchange.finish_sending();
        if self.deferred_close_timeout.is_zero() {
            return;
        }
        if tokio::time::timeout(self.deferred_close_timeout, exchange.drain_trailing())
            .await
            .is_err()
        {
            tracing::debug!(
                target = %self.target,
                "ext_proc: deferred close timeout during trailing drain"
            );
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

        let headers = mutations::request_to_proto_headers(ctx, &self.forward_rules);
        let headers_request = processing_request::Request::RequestHeaders(headers);

        let exchange =
            ExtProcExchange::open_with_request_headers(self.channel(), &self.exchange_config(), headers_request)
                .map_err(Self::exchange_err)?;

        let state = ExtProcState {
            exchange,
            headers_sent: true,
            request_phase_complete: false,
        };

        ctx.insert_filter_state(state);
        Ok(())
    }

    /// Send request headers and wait for the matching processor response.
    async fn process_request_headers_on_exchange(
        &self,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        let mut state = self.open_and_send_request_headers(ctx).await?;
        let result = Self::drain_header_response(&mut state, ctx).await;

        self.complete_request_header_processing(state, ctx, result).await
    }

    /// Open an exchange and send request headers as the first message.
    async fn open_and_send_request_headers(&self, ctx: &HttpFilterContext<'_>) -> Result<ExtProcState, FilterError> {
        let headers = mutations::request_to_proto_headers(ctx, &self.forward_rules);
        let headers_request = processing_request::Request::RequestHeaders(headers);

        let mut state = ExtProcState {
            exchange: ExtProcExchange::open(self.channel(), &self.exchange_config()),
            headers_sent: false,
            request_phase_complete: false,
        };
        tokio::time::timeout(self.message_timeout, state.exchange.send(headers_request))
            .await
            .map_err(|_elapsed| -> FilterError { "ext_proc: message timeout during request headers".into() })?
            .map_err(Self::exchange_err)?;
        state.headers_sent = true;

        Ok(state)
    }

    /// Store, close, or fail the exchange after request-header processing.
    async fn complete_request_header_processing(
        &self,
        mut state: ExtProcState,
        ctx: &mut HttpFilterContext<'_>,
        result: Result<Option<FilterAction>, FilterError>,
    ) -> Result<FilterAction, FilterError> {
        match result {
            Ok(Some(action)) => {
                self.bounded_cleanup(&mut state.exchange).await;
                Ok(action)
            },
            Ok(None) if self.response_header_mode == HeaderSendMode::Send => {
                state.request_phase_complete = true;
                ctx.insert_filter_state(state);
                Ok(FilterAction::Continue)
            },
            Ok(None) => {
                state.request_phase_complete = true;
                self.bounded_cleanup(&mut state.exchange).await;
                Ok(FilterAction::Continue)
            },
            Err(e) => {
                state.exchange.finish_sending();
                Err(e)
            },
        }
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

        let finish_after_request = self.response_header_mode == HeaderSendMode::Skip;
        let result = Self::drain_exchange_inner(&mut state, ctx, body, finish_after_request).await;

        if !finish_after_request && matches!(result, Ok(FilterAction::Continue)) {
            ctx.insert_filter_state(state);
        }

        result
    }

    /// Inner drain logic operating on an owned [`ExtProcState`].
    async fn drain_exchange_inner(
        state: &mut ExtProcState,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        finish_after_request: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(action) = Self::drain_header_response(state, ctx).await? {
            state.exchange.finish_sending();
            state.exchange.drain_trailing().await;
            return Ok(action);
        }

        let result = Self::drain_body_responses(state, ctx, body).await;
        if finish_after_request || !matches!(result, Ok(FilterAction::Continue)) {
            state.exchange.finish_sending();
            state.exchange.drain_trailing().await;
        } else {
            state.request_phase_complete = true;
        }
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

    /// Send response headers on the existing exchange and apply the response.
    async fn process_response_headers_on_exchange(
        &self,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        let mut state = ctx
            .remove_filter_state::<ExtProcState>()
            .ok_or_else(|| -> FilterError { "ext_proc: missing exchange state during response headers".into() })?;

        let result = self.process_response_headers_inner(&mut state, ctx).await;
        if result.is_ok() {
            self.bounded_cleanup(&mut state.exchange).await;
        } else {
            state.exchange.finish_sending();
        }
        result
    }

    /// Inner response-header processing using an owned [`ExtProcState`].
    ///
    /// Send is bounded by `message_timeout`. Receive uses the
    /// exchange's active-processing deadline, which supports
    /// `override_message_timeout` from the processor.
    #[expect(clippy::too_many_lines, reason = "send + receive + classification match")]
    async fn process_response_headers_inner(
        &self,
        state: &mut ExtProcState,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        if !state.request_phase_complete {
            return Err("ext_proc: response headers reached before request phase completed".into());
        }

        let headers = mutations::response_to_proto_headers(ctx, &self.forward_rules);
        let timeout = self.message_timeout;
        tokio::time::timeout(
            timeout,
            state
                .exchange
                .send(processing_request::Request::ResponseHeaders(headers)),
        )
        .await
        .map_err(|_elapsed| -> FilterError { "ext_proc: message timeout sending response headers".into() })?
        .map_err(Self::exchange_err)?;

        let event = state.exchange.receive().await.map_err(Self::exchange_err)?;
        match event {
            ExchangeEvent::ResponseHeaders { response, metadata } => {
                apply_dynamic_metadata(metadata, ctx);
                mutations::apply_headers_response(&response, ctx, Phase::Response);
                Ok(FilterAction::Continue)
            },
            ExchangeEvent::Immediate { response, metadata } => {
                apply_dynamic_metadata(metadata, ctx);
                Ok(mutations::immediate_to_rejection(&response))
            },
            other => {
                Err(format!("ext_proc: expected ResponseHeaders or Immediate during response, got {other:?}").into())
            },
        }
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

    /// Whether request-phase processor responses have been consumed.
    request_phase_complete: bool,
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

        Ok(self.call_or_reject(self.process_request_headers_on_exchange(ctx).await))
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
        if self.response_header_mode == HeaderSendMode::Skip {
            return Ok(FilterAction::Continue);
        }

        if ctx.get_filter_state::<ExtProcState>().is_some() {
            return Ok(self.call_or_reject(self.process_response_headers_on_exchange(ctx).await));
        }

        // Fail closed: response_header_mode is send but no exchange
        // survived the request phase. This indicates a lifecycle bug
        // or request-phase error that consumed the exchange.
        Ok(self.call_or_reject(Err(
            "ext_proc: response_header_mode is send but no exchange state from request phase".into(),
        )))
    }
}

#[cfg(test)]
mod tests;
