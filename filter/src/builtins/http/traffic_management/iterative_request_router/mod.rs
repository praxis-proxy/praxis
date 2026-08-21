// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Iterative request router: a framework-level filter that executes
//! multiple sequential HTTP sub-requests through composable filter
//! chains before returning a final response to the client.
//!
//! # Header isolation
//!
//! Every transitioned step begins with empty headers. `Host` is
//! reconstructed from the selected destination. `Content-Type`,
//! `Accept`, authorization tokens, and custom headers are **not**
//! inherited from the previous step. Each step must explicitly
//! inject its own credentials and required representation headers
//! (e.g. via a `headers` or `credential_injection` filter).
//!
//! # Streaming support
//!
//! When a step's filters select [`SubRequestResponseMode::Streaming`],
//! IRR dispatches via `send_streaming()` instead of the buffered
//! `execute()` path. Header-safe failover transitions run before that
//! step exposes bytes. After clean EOF and response-body completion,
//! ordinary `on_result` rules may resume another step inside the same
//! committed downstream response.
//!
//! Header-safe failovers must precede completion-dependent transitions.
//! `BodyMode::StreamBuffer` remains incompatible with streaming-capable
//! step pipelines. Once the logical response is committed, failures can
//! only terminate its stream; they cannot replace its HTTP response.
//!
//! # Position requirement
//!
//! This filter must be the last filter in its parent chain because
//! it produces terminal responses that bypass remaining request-phase
//! filters. Place accounting and observability filters before it so
//! they participate in the response lifecycle.
//!
//! See proposal 00786 for the full design rationale.

mod config;
mod runner;
mod streaming;
#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests;

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderMap;
use pingora_core::upstreams::peer::HttpPeer;
use tracing::{debug, info, warn};

use self::{
    config::IterativeRequestRouterConfig,
    runner::{IrrStepRunner, OpenedStepKind, StepRuntime},
    streaming::{IrrStreamingBody, IrrStreamingSession, ensure_combined_retained_limit},
};
use crate::{
    FilterEntry, FilterError, FilterPipeline, FilterRegistry, IterationState, StreamTermination, SubRequest,
    SubRequestResponseMode, SubResponse,
    actions::{FilterAction, Rejection, StreamingResponseBody as _, StreamingTerminalResponse, TerminalResponse},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
    pipeline::subrequest::DEPTH_HEADER,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Streaming idle timeout (max time between chunks).
const STREAMING_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Whether transitions depend on response body content (filter result
/// predicates or body-dependent metadata).
#[cfg(test)]
pub(super) fn has_body_dependent_transitions(transitions: &[config::StepTransition]) -> bool {
    transitions
        .iter()
        .any(|t| t.filter.is_some() || t.key.is_some() || t.value.is_some())
}

/// Whether a transition can safely fail over before exposing a streamed body.
fn is_header_safe_failover(transition: &config::StepTransition) -> bool {
    transition.next.is_some()
        && !transition.default
        && transition.filter.is_none()
        && transition.key.is_none()
        && transition.value.is_none()
}

/// Whether the header-safe failover prefix is followed only by completion rules.
pub(super) fn streaming_transition_order_is_valid(transitions: &[config::StepTransition]) -> bool {
    let mut completion_seen = false;
    transitions.iter().all(|transition| {
        if is_header_safe_failover(transition) {
            !completion_seen
        } else {
            completion_seen = true;
            true
        }
    })
}

// ---------------------------------------------------------------------------
// IterativeRequestRouterFilter
// ---------------------------------------------------------------------------

/// Framework-level filter for iterative sub-request execution.
///
/// Holds named steps, each backed by a pre-built sub-pipeline.
/// During request processing, runs an iteration loop: execute each
/// step's request filters, make the HTTP call via Pingora's
/// `Connector`, execute its response filters, evaluate transition
/// rules, and continue or return the final response.
///
/// Streaming steps remain pull-based. Header-safe failover rules run before
/// any bytes are exposed; all other `on_result` rules run after clean EOF and
/// may resume another step inside the same committed downstream response.
///
/// # YAML configuration
///
/// ```yaml
/// filter: iterative_request_router
/// initial_step: model-call
/// steps:
///   - name: model-call
///     filters:
///       - filter: router
///         routes:
///           - cluster: llm-backend
///       - filter: load_balancer
///         clusters:
///           - name: llm-backend
///             endpoints: ["10.0.0.1:8000"]
///     on_result:
///       - default: true
///         done: true
/// ```
pub struct IterativeRequestRouterFilter {
    /// Name of the first step to execute.
    initial_step: Arc<str>,

    /// Maximum iterations.
    max_iterations: u32,

    /// Maximum response body bytes per sub-request.
    max_response_bytes: usize,

    /// Optional cumulative byte ceiling for a logical streamed response.
    max_stream_response_bytes: Option<usize>,

    /// Maximum accumulated state bytes.
    max_state_bytes: usize,

    /// Per-step timeout cap.
    step_timeout: Duration,

    /// Pre-built sub-pipelines keyed by step name.
    step_pipelines: HashMap<Arc<str>, Arc<FilterPipeline>>,

    /// Transition rules keyed by step name.
    step_transitions: HashMap<Arc<str>, Vec<config::StepTransition>>,

    /// Overall timeout.
    timeout: Duration,
}

impl IterativeRequestRouterFilter {
    /// Create from YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the config is invalid or step
    /// pipelines fail to build.
    pub fn from_config(value: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", value)?;
        Self::from_parsed_config(cfg, &FilterRegistry::with_builtins())
    }

    /// Create from YAML config, resolving step filters through the
    /// registry that owns the containing pipeline.
    pub(crate) fn from_config_with_registry(
        value: &serde_yaml::Value,
        registry: &FilterRegistry,
    ) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", value)?;
        Self::from_parsed_config(cfg, registry)
    }

    /// Validate parsed configuration and build each step pipeline.
    #[expect(clippy::too_many_lines, reason = "validation and named step construction")]
    fn from_parsed_config(
        cfg: IterativeRequestRouterConfig,
        registry: &FilterRegistry,
    ) -> Result<Box<dyn HttpFilter>, FilterError> {
        config::validate(&cfg)?;
        let timeout = Duration::from_millis(cfg.timeout_ms);
        if Instant::now().checked_add(timeout).is_none() {
            return Err(
                "iterative_request_router: timeout_ms exceeds the platform Instant range"
                    .to_owned()
                    .into(),
            );
        }

        let mut step_pipelines = HashMap::new();
        let mut step_transitions = HashMap::new();

        for step in cfg.steps {
            let name: Arc<str> = Arc::from(step.name.as_str());

            let mut entries: Vec<FilterEntry> = step.filters.into_iter().collect();
            let pipeline = FilterPipeline::build(&mut entries, registry)?;
            let ordering_errors =
                pipeline.ordering_errors(&entries, false, &praxis_core::config::SkipPipelineChecks::default());
            if !ordering_errors.is_empty() {
                return Err(format!(
                    "iterative_request_router: invalid step '{}': {}",
                    step.name,
                    ordering_errors.join("; ")
                )
                .into());
            }

            step_pipelines.insert(Arc::clone(&name), Arc::new(pipeline));
            step_transitions.insert(Arc::clone(&name), step.on_result);
        }

        for (name, pipeline) in &step_pipelines {
            if !pipeline.may_select_streaming_subrequest_response() {
                continue;
            }
            if let Some(transitions) = step_transitions.get(name) {
                for (i, transition) in transitions.iter().enumerate() {
                    if is_header_safe_failover(transition) && !streaming_transition_order_is_valid(transitions) {
                        return Err(format!(
                            "iterative_request_router: step '{name}' transition {i}: \
                             header-safe streaming failover rules must precede completion rules"
                        )
                        .into());
                    }
                    if transition.next.is_some()
                        && transition.filter.is_none()
                        && (transition.key.is_some() || transition.value.is_some())
                    {
                        return Err(format!(
                            "iterative_request_router: step '{name}' transition {i}: \
                             ambiguous streaming transition predicates"
                        )
                        .into());
                    }
                }
            }

            if matches!(
                pipeline.body_capabilities().response_body_mode,
                crate::body::BodyMode::StreamBuffer { .. }
            ) {
                return Err(format!(
                    "iterative_request_router: step '{name}': StreamBuffer \
                     response body mode is incompatible with streaming-capable \
                     pipelines"
                )
                .into());
            }
        }

        let step_timeout = cfg.step_timeout_ms.map_or(timeout, Duration::from_millis);

        Ok(Box::new(Self {
            initial_step: Arc::from(cfg.initial_step.as_str()),
            max_iterations: cfg.max_iterations,
            max_response_bytes: cfg.max_response_bytes,
            max_stream_response_bytes: cfg.max_stream_response_bytes,
            max_state_bytes: cfg.max_state_bytes,
            step_pipelines,
            step_timeout,
            step_transitions,
            timeout,
        }))
    }
}

#[async_trait]
impl HttpFilter for IterativeRequestRouterFilter {
    fn name(&self) -> &'static str {
        "iterative_request_router"
    }

    fn request_body_access(&self) -> crate::body::BodyAccess {
        crate::body::BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> crate::body::BodyMode {
        crate::body::BodyMode::StreamBuffer {
            max_bytes: Some(self.max_state_bytes),
        }
    }

    fn visit_nested_pipelines(&mut self, visitor: &mut dyn FnMut(&mut FilterPipeline)) {
        for pipeline in self.step_pipelines.values_mut() {
            if let Some(pipeline) = Arc::get_mut(pipeline) {
                visitor(pipeline);
            } else {
                debug_assert!(false, "IRR step pipelines must be uniquely owned during configuration");
            }
        }
    }

    fn apply_insecure_options(&self, options: &praxis_core::config::InsecureOptions) {
        for pipeline in self.step_pipelines.values() {
            pipeline.apply_insecure_options(options);
        }
    }

    /// Validate the request, then run the iteration at the router's normal
    /// request-header position after preceding filters have completed.
    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let depth = parse_depth(ctx.request);
        if depth >= config::max_depth() {
            warn!(
                depth,
                max = config::max_depth(),
                "iterative_request_router: max depth exceeded"
            );
            return Ok(FilterAction::Reject(Rejection::status(508)));
        }

        if ctx.subrequest_client().is_none() {
            return Err("iterative_request_router: no sub-request \
                 client available"
                .to_owned()
                .into());
        }

        let request_body = ctx.buffered_request_body.take().ok_or_else(|| -> FilterError {
            "iterative_request_router: buffered request body unavailable"
                .to_owned()
                .into()
        })?;

        Box::pin(self.run_iterations_with_runner(ctx, request_body)).await
    }
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "lifecycle implementation is kept separate from construction"
)]
impl IterativeRequestRouterFilter {
    /// Run the logical request through the reusable one-step executor.
    #[expect(clippy::too_many_lines, reason = "the loop owns explicit state transitions")]
    #[expect(
        clippy::large_stack_frames,
        reason = "opening a step reconstructs a full filter context"
    )]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "opened streaming steps are consumed by their selected lifecycle"
    )]
    async fn run_iterations_with_runner(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        request_body: Bytes,
    ) -> Result<FilterAction, FilterError> {
        let depth = parse_depth(ctx.request);
        let client = ctx
            .subrequest_client()
            .ok_or_else(|| -> FilterError { "iterative_request_router: no sub-request client".to_owned().into() })?
            .clone();
        let max_response_bytes = effective_response_limit(self.max_response_bytes, ctx.response_body_mode);
        let original_request = SubRequest {
            method: ctx.request.method.clone(),
            uri: ctx.request.uri.clone(),
            headers: ctx.request.headers.clone(),
            body: request_body,
        };
        let mut state = IterationState {
            original_request: original_request.clone(),
            previous_response: None,
            accumulator: HashMap::new(),
            iteration: 0,
            max_iterations: self.max_iterations,
            deadline: Instant::now().checked_add(self.timeout).ok_or_else(|| -> FilterError {
                "iterative_request_router: deadline exceeds the platform Instant range"
                    .to_owned()
                    .into()
            })?,
            max_response_bytes,
            depth,
        };
        if state.retained_bytes() > self.max_state_bytes {
            return Ok(FilterAction::Reject(Rejection::status(413)));
        }

        let runner = IrrStepRunner::new(
            client,
            depth,
            max_response_bytes,
            self.max_state_bytes,
            StepRuntime {
                client_addr: ctx.client_addr,
                downstream_tls: ctx.downstream_tls,
                peer_identity: ctx.peer_identity.clone(),
                request_start: ctx.request_start,
            },
            self.step_pipelines.clone(),
            self.step_timeout,
        );
        let mut current_step = Arc::clone(&self.initial_step);
        let mut current_request = original_request;
        let mut extensions = std::mem::take(&mut ctx.extensions);
        let mut pending_chunks = VecDeque::new();
        let mut pending_bytes = 0_usize;

        loop {
            if state.iteration >= self.max_iterations {
                ctx.extensions = extensions;
                warn!(
                    iterations = state.iteration,
                    max = self.max_iterations,
                    "iterative_request_router: max iterations exhausted"
                );
                return Ok(FilterAction::Reject(Rejection::status(508)));
            }
            if state
                .deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO)
                .is_zero()
            {
                ctx.extensions = extensions;
                warn!(
                    iterations = state.iteration,
                    "iterative_request_router: deadline exceeded"
                );
                return Ok(FilterAction::Reject(Rejection::status(504)));
            }

            let opened = match Box::pin(runner.open_step(&current_step, &current_request, &state, extensions)).await {
                Ok(opened) => opened,
                Err(error) => {
                    let (error, restored_extensions) = error.into_parts();
                    ctx.extensions = restored_extensions;
                    return Err(error);
                },
            };
            let runner::OpenedStep { continuation, kind } = opened;

            match kind {
                OpenedStepKind::Streaming { body, outcome } => {
                    let transitions = self.step_transitions.get(&current_step).map_or(&[][..], Vec::as_slice);
                    if !streaming_transition_order_is_valid(transitions) {
                        (*body).cancel().await;
                        ctx.extensions = continuation.into_parent_extensions();
                        return Err(format!(
                            "iterative_request_router: step '{current_step}' selected streaming with interleaved transition phases"
                        )
                        .into());
                    }
                    match evaluate_header_transitions(transitions, &outcome) {
                        TransitionResult::Next(next_step) => {
                            debug!(
                                from = current_step.as_ref(),
                                to = next_step.as_ref(),
                                "streaming header failover before response commitment"
                            );
                            let mut skipped = IrrStreamingBody::new(body, continuation);
                            if let Err(error) = skipped.suppress().await {
                                ctx.extensions = skipped.into_continuation().into_parent_extensions();
                                return Err(error);
                            }
                            let mut completion = match skipped.into_continuation().into_completion() {
                                Ok(completion) => completion,
                                Err(error) => {
                                    let (error, restored_extensions) = error.into_parts();
                                    ctx.extensions = restored_extensions;
                                    return Err(error);
                                },
                            };
                            completion.state.previous_response = None;
                            completion.state.iteration += 1;
                            if completion.state.retained_bytes() > self.max_state_bytes {
                                ctx.extensions = completion.extensions;
                                return Ok(FilterAction::Reject(Rejection::status(413)));
                            }
                            let next_body = completion
                                .next_iteration_body
                                .unwrap_or_else(|| current_request.body.clone());
                            state = completion.state;
                            extensions = completion.extensions;
                            current_request = SubRequest {
                                method: current_request.method.clone(),
                                uri: current_request.uri.clone(),
                                headers: HeaderMap::new(),
                                body: next_body,
                            };
                            current_step = next_step;
                        },
                        TransitionResult::Done | TransitionResult::NoMatch => {
                            let Some(active_state) = continuation.extensions.get::<IterationState>() else {
                                (*body).cancel().await;
                                ctx.extensions = continuation.into_parent_extensions();
                                return Err(
                                    "iterative_request_router: iteration state missing before stream handoff"
                                        .to_owned()
                                        .into(),
                                );
                            };
                            if ensure_combined_retained_limit(
                                active_state.retained_bytes(),
                                pending_chunks.iter().map(Bytes::len),
                                self.max_state_bytes,
                            )
                            .is_err()
                            {
                                (*body).cancel().await;
                                let completion = match continuation.into_completion() {
                                    Ok(completion) => completion,
                                    Err(error) => {
                                        let (error, restored_extensions) = error.into_parts();
                                        ctx.extensions = restored_extensions;
                                        return Err(error);
                                    },
                                };
                                ctx.extensions = completion.extensions;
                                return Ok(FilterAction::Reject(Rejection::status(413)));
                            }
                            let status = normalize_response_status(outcome.response.status);
                            let headers = outcome.response.headers.clone();
                            let terminal = StreamingTerminalResponse::new(
                                status,
                                Box::new(IrrStreamingSession::new(
                                    runner,
                                    Arc::clone(&current_step),
                                    current_request,
                                    outcome,
                                    body,
                                    continuation,
                                    pending_chunks,
                                    self.step_transitions.clone(),
                                    self.max_state_bytes,
                                    self.max_stream_response_bytes,
                                )),
                            )
                            .with_headers(headers);
                            return Ok(FilterAction::StreamingTerminalResponse(Box::new(terminal)));
                        },
                    }
                },
                OpenedStepKind::Complete(mut outcome) => {
                    let completion = match continuation.into_completion() {
                        Ok(completion) => completion,
                        Err(error) => {
                            let (error, restored_extensions) = error.into_parts();
                            ctx.extensions = restored_extensions;
                            return Err(error);
                        },
                    };
                    let abnormal_stream_completion = completion.termination.is_some();
                    let handled_abnormal_stream_completion = completion
                        .termination
                        .as_ref()
                        .is_some_and(StreamTermination::is_handled);
                    let completed_pending_chunks = completion.pending_chunks;
                    state = completion.state;
                    state.previous_response = Some(outcome.response.clone());
                    state.iteration += 1;
                    let next_iteration_body = completion.next_iteration_body;
                    let filter_results = completion.filter_results;
                    extensions = completion.extensions;
                    if state.retained_bytes() > self.max_state_bytes {
                        ctx.extensions = extensions;
                        return Ok(FilterAction::Reject(Rejection::status(413)));
                    }

                    info!(
                        step = current_step.as_ref(),
                        iteration = state.iteration - 1,
                        status = outcome.response.status,
                        body_bytes = outcome.response.body.len(),
                        "sub-request complete"
                    );
                    let transitions = self.step_transitions.get(&current_step).map_or(&[][..], Vec::as_slice);
                    match evaluate_transitions(transitions, &outcome, &filter_results) {
                        TransitionResult::Next(next_step) => {
                            if !abnormal_stream_completion {
                                let appended = append_pending_chunks(
                                    &mut pending_chunks,
                                    completed_pending_chunks,
                                    pending_bytes,
                                    self.max_state_bytes,
                                    state.retained_bytes(),
                                );
                                let Ok(updated_pending_bytes) = appended else {
                                    ctx.extensions = extensions;
                                    return Ok(FilterAction::Reject(Rejection::status(413)));
                                };
                                pending_bytes = updated_pending_bytes;
                            }
                            let next_body = next_iteration_body.unwrap_or_else(|| current_request.body.clone());
                            current_request = SubRequest {
                                method: current_request.method.clone(),
                                uri: current_request.uri.clone(),
                                headers: HeaderMap::new(),
                                body: next_body,
                            };
                            current_step = next_step;
                        },
                        TransitionResult::Done | TransitionResult::NoMatch => {
                            if handled_abnormal_stream_completion {
                                let combined_bytes = pending_chunks
                                    .iter()
                                    .chain(completed_pending_chunks.iter())
                                    .chain(std::iter::once(&outcome.response.body))
                                    .try_fold(0_usize, |total, chunk| total.checked_add(chunk.len()))
                                    .ok_or_else(|| -> FilterError {
                                        "iterative_request_router: completion body byte count overflow".into()
                                    })?;
                                if combined_bytes > max_response_bytes {
                                    ctx.extensions = extensions;
                                    return Err(
                                        "iterative_request_router: abnormal completion exceeds response body limit"
                                            .to_owned()
                                            .into(),
                                    );
                                }
                                let mut combined = Vec::with_capacity(combined_bytes);
                                for chunk in pending_chunks.drain(..) {
                                    combined.extend_from_slice(&chunk);
                                }
                                for chunk in completed_pending_chunks {
                                    combined.extend_from_slice(&chunk);
                                }
                                combined.extend_from_slice(&outcome.response.body);
                                outcome.response.body = Bytes::from(combined);
                            } else if abnormal_stream_completion {
                                pending_chunks.clear();
                                outcome.response.body = Bytes::new();
                            } else if !pending_chunks.is_empty() || !completed_pending_chunks.is_empty() {
                                ctx.extensions = extensions;
                                return Err(
                                    "iterative_request_router: stream chunks were emitted without a streaming response"
                                        .to_owned()
                                        .into(),
                                );
                            }
                            ctx.extensions = extensions;
                            return Ok(FilterAction::TerminalResponse(Box::new(build_terminal_response(
                                &outcome.response,
                                current_request.method == http::Method::HEAD,
                            ))));
                        },
                    }
                },
            }
        }
    }
}

/// Append locally emitted chunks while preserving the shared retained-state bound.
fn append_pending_chunks(
    target: &mut VecDeque<Bytes>,
    chunks: VecDeque<Bytes>,
    current_bytes: usize,
    max_state_bytes: usize,
    retained_bytes: usize,
) -> Result<usize, FilterError> {
    let added_bytes = chunks.iter().try_fold(0_usize, |total, chunk| {
        total
            .checked_add(chunk.len())
            .ok_or_else(|| -> FilterError { "iterative_request_router: pending stream byte count overflow".into() })
    })?;
    let pending_bytes = current_bytes
        .checked_add(added_bytes)
        .ok_or_else(|| -> FilterError { "iterative_request_router: pending stream byte count overflow".into() })?;
    if retained_bytes
        .checked_add(pending_bytes)
        .is_none_or(|total| total > max_state_bytes)
    {
        return Err(
            "iterative_request_router: retained state and pending stream output exceed configured limit"
                .to_owned()
                .into(),
        );
    }
    target.extend(chunks);
    Ok(pending_bytes)
}

// ---------------------------------------------------------------------------
// Transition Evaluation
// ---------------------------------------------------------------------------

/// A step's response together with metadata about where it came from.
pub(super) struct StepOutcome {
    /// The sub-request response.
    pub(super) response: SubResponse,
    /// Where the response originated.
    pub(super) origin: config::ResponseOrigin,
    /// Transport error classification, if any.
    pub(super) transport_error: Option<config::TransportErrorKind>,
}

/// Result of evaluating step transition rules.
pub(super) enum TransitionResult {
    /// Return the current response to the client.
    Done,

    /// Transition to the named step.
    Next(Arc<str>),

    /// No transition matched.
    NoMatch,
}

/// Convert transport failures into a gateway status and error classification.
pub(super) fn classify_transport_failure(
    error: &praxis_core::subrequest::SubRequestError,
) -> (u16, config::TransportErrorKind) {
    use praxis_core::subrequest::SubRequestError;
    match error {
        SubRequestError::AdmissionTimeout { .. } => (503, config::TransportErrorKind::AdmissionTimeout),
        SubRequestError::CircuitOpen { .. } => (503, config::TransportErrorKind::CircuitOpen),
        SubRequestError::Connect(_) => (502, config::TransportErrorKind::Connect),
        SubRequestError::DeadlineExceeded => (504, config::TransportErrorKind::DeadlineExceeded),
        SubRequestError::ResponseTooLarge { .. } => (502, config::TransportErrorKind::ResponseTooLarge),
        _ => (502, config::TransportErrorKind::Io),
    }
}

/// Convert a nested filter's local response into transition input.
fn subresponse_from_rejection(rejection: Rejection) -> SubResponse {
    let status = normalize_response_status(rejection.status);
    let mut headers = HeaderMap::new();
    for (name, value) in rejection.headers {
        let Ok(name) = http::HeaderName::try_from(name) else {
            continue;
        };
        let Ok(value) = http::HeaderValue::try_from(value) else {
            continue;
        };
        headers.append(name, value);
    }
    if let Some(header_map) = rejection.header_map {
        for (name, value) in header_map.iter() {
            headers.append(name.clone(), value.clone());
        }
    }
    let mut response = SubResponse {
        status,
        headers,
        body: rejection.body.unwrap_or_default(),
    };
    sanitize_subresponse_headers(&mut response.headers);
    response
}

/// Keep final locally generated statuses inside the terminal response range.
/// Informational, invalid upstream, or invalid custom-filter values become 502.
fn normalize_response_status(status: u16) -> u16 {
    if (200..=599).contains(&status) { status } else { 502 }
}

/// Evaluate transition rules against a step outcome.
pub(super) fn evaluate_transitions(
    transitions: &[config::StepTransition],
    outcome: &StepOutcome,
    filter_results: &HashMap<&str, crate::results::FilterResultSet>,
) -> TransitionResult {
    for t in transitions {
        if t.default || matches_transition(t, outcome, filter_results) {
            if t.done {
                return TransitionResult::Done;
            }
            if let Some(next) = &t.next {
                return TransitionResult::Next(Arc::from(next.as_str()));
            }
            return TransitionResult::Done;
        }
    }

    TransitionResult::NoMatch
}

/// Evaluate only the ordered header-safe failover prefix.
pub(super) fn evaluate_header_transitions(
    transitions: &[config::StepTransition],
    outcome: &StepOutcome,
) -> TransitionResult {
    for transition in transitions
        .iter()
        .take_while(|transition| is_header_safe_failover(transition))
    {
        if matches_transition(transition, outcome, &HashMap::new())
            && let Some(next) = &transition.next
        {
            return TransitionResult::Next(Arc::from(next.as_str()));
        }
    }
    TransitionResult::NoMatch
}

/// Check if a transition matches the outcome and/or filter results.
fn matches_transition(
    transition: &config::StepTransition,
    outcome: &StepOutcome,
    filter_results: &HashMap<&str, crate::results::FilterResultSet>,
) -> bool {
    let status_ok = transition
        .status
        .as_ref()
        .is_none_or(|codes| codes.contains(&outcome.response.status));

    let origin_ok = transition.origin.is_none_or(|expected| expected == outcome.origin);

    let transport_ok = transition
        .transport_error
        .is_none_or(|expected| outcome.transport_error == Some(expected));

    let result_ok = match (
        transition.filter.as_deref(),
        transition.key.as_deref(),
        transition.value.as_deref(),
    ) {
        (Some(filter_name), Some(key), Some(value)) => {
            crate::matches_filter_result(filter_results, filter_name, key, value)
        },
        (None, None, None) => true,
        _ => false,
    };

    status_ok && origin_ok && transport_ok && result_ok
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Parse the iterative depth from request headers.
fn parse_depth(request: &crate::Request) -> u8 {
    request
        .headers
        .get(DEPTH_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Strip all reserved internal headers from sub-request headers
/// so the core executor re-injects depth via
/// [`FrameworkHeaders`](praxis_core::subrequest::FrameworkHeaders).
///
/// The depth header uses a reserved `x-praxis-*` prefix, so it
/// is covered by the [`is_reserved`] check.
///
/// [`is_reserved`]: praxis_core::reserved_headers::is_reserved
fn strip_reserved_headers(headers: &mut HeaderMap) {
    let to_remove: Vec<http::header::HeaderName> = headers
        .keys()
        .filter(|name| praxis_core::reserved_headers::is_reserved(name.as_str()))
        .cloned()
        .collect();
    for name in to_remove {
        headers.remove(&name);
    }
}

/// Apply request mutations emitted across the step's header and body
/// filter phases before dispatching its upstream request.
fn apply_request_header_mutations(headers: &mut HeaderMap, ctx: &HttpFilterContext<'_>) {
    for name in &ctx.request_headers_to_remove {
        headers.remove(name);
    }
    for (name, value) in &ctx.request_headers_to_set {
        headers.insert(name.clone(), value.clone());
    }
    for (name, value) in &ctx.extra_request_headers {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            headers.insert(name, value);
        }
    }
}

/// Apply body pre-read mutations to the request snapshot that header
/// filters use for classification and routing.
fn apply_pre_read_header_mutations(headers: &mut HeaderMap, ctx: &HttpFilterContext<'_>) {
    if ctx.pre_read_mutations.is_empty() {
        apply_request_header_mutations(headers, ctx);
        return;
    }

    for mutation in &ctx.pre_read_mutations {
        match mutation {
            crate::TrustedHeaderMutation::Remove(name) => {
                headers.remove(name);
            },
            crate::TrustedHeaderMutation::Set(name, value) => {
                headers.insert(name.clone(), value.clone());
            },
            crate::TrustedHeaderMutation::Add(name, value) => {
                if let Ok(value) = http::HeaderValue::from_str(value) {
                    headers.append(name.clone(), value);
                }
            },
        }
    }
}

/// Remove inbound message-framing headers after request-body filters
/// have potentially changed the payload. The subrequest executor adds
/// the correct `Content-Length` for non-empty bodies.
fn strip_request_framing_headers(headers: &mut HeaderMap) {
    headers.remove(http::header::CONTENT_LENGTH);
    headers.remove(http::header::TRANSFER_ENCODING);
}

/// Headers that apply only to one HTTP connection and must not cross it.
const REQUEST_HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Response-side hop-by-hop headers.
const RESPONSE_HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Apply the same forwarding boundary as the normal upstream path.
fn sanitize_subrequest_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop_headers(headers, REQUEST_HOP_BY_HOP);
    strip_reserved_headers(headers);
    strip_request_framing_headers(headers);
}

/// Supply the selected upstream authority without carrying a prior step's Host.
fn ensure_destination_host(headers: &mut HeaderMap, address: &str) -> Result<(), FilterError> {
    if !headers.contains_key(http::header::HOST) {
        let value = http::HeaderValue::from_str(address).map_err(|error| -> FilterError {
            format!("iterative_request_router: invalid upstream Host: {error}").into()
        })?;
        headers.insert(http::header::HOST, value);
    }
    Ok(())
}

/// Remove connection-scoped and proxy-internal response metadata.
fn sanitize_subresponse_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop_headers(headers, RESPONSE_HOP_BY_HOP);
    strip_reserved_headers(headers);
}

/// Remove the static hop-by-hop set and headers named by `Connection`.
fn strip_hop_by_hop_headers(headers: &mut HeaderMap, static_headers: &[&str]) {
    let connection_values: Vec<_> = headers.get_all(http::header::CONNECTION).iter().cloned().collect();
    for name in static_headers {
        headers.remove(*name);
    }
    for value in connection_values {
        let Ok(value) = value.to_str() else { continue };
        for token in value.split(',').map(str::trim).filter(|token| !token.is_empty()) {
            headers.remove(token);
        }
    }
}

/// Whether a fully buffered nested body exceeds its pipeline mode's
/// configured ceiling.
fn body_exceeds_limit(mode: crate::body::BodyMode, body_len: usize) -> bool {
    match mode {
        crate::body::BodyMode::SizeLimit { max_bytes }
        | crate::body::BodyMode::StreamBuffer {
            max_bytes: Some(max_bytes),
        } => body_len > max_bytes,
        crate::body::BodyMode::Stream | crate::body::BodyMode::StreamBuffer { max_bytes: None } => false,
    }
}

/// Whether a response exceeds either the iterative router's global
/// per-step ceiling or the nested pipeline's body-mode ceiling.
fn response_body_exceeds_limits(mode: crate::body::BodyMode, max_response_bytes: usize, body_len: usize) -> bool {
    body_len > max_response_bytes || body_exceeds_limit(mode, body_len)
}

/// Clamp the router-specific response cap to the listener's global body mode.
fn effective_response_limit(configured: usize, parent_mode: crate::body::BodyMode) -> usize {
    match parent_mode {
        crate::body::BodyMode::SizeLimit { max_bytes }
        | crate::body::BodyMode::StreamBuffer {
            max_bytes: Some(max_bytes),
        } => configured.min(max_bytes),
        crate::body::BodyMode::Stream | crate::body::BodyMode::StreamBuffer { max_bytes: None } => configured,
    }
}

/// Extract only the listener-level streaming ceiling from a nested pipeline.
///
/// The IRR `max_response_bytes` setting is intentionally buffered-only. A
/// nested `SizeLimit` is produced by listener body-limit propagation and must
/// still constrain the live transport.
fn streaming_transport_limit(mode: crate::body::BodyMode) -> Option<usize> {
    match mode {
        crate::body::BodyMode::SizeLimit { max_bytes } => Some(max_bytes),
        crate::body::BodyMode::Stream | crate::body::BodyMode::StreamBuffer { .. } => None,
    }
}

/// Whether a step filter grew the shared iteration state past its ceiling.
fn iteration_state_exceeds_limit(ctx: &HttpFilterContext<'_>, max_state_bytes: usize) -> bool {
    ctx.extensions
        .get::<IterationState>()
        .is_some_and(|state| state.retained_bytes() > max_state_bytes)
}

/// Runtime resources inherited from the pipeline that contains the
/// iterative router.
#[derive(Clone, Copy)]
struct SubPipelineRuntimeResources<'a> {
    /// Original downstream client address.
    client_addr: Option<std::net::IpAddr>,

    /// Whether the original downstream connection uses TLS.
    downstream_tls: bool,

    /// Shared endpoint-health state.
    health_registry: Option<&'a praxis_core::health::HealthRegistry>,

    /// Shared request ID generator.
    id_generator: &'a praxis_core::id::IdGenerator,

    /// Named runtime key-value stores.
    kv_stores: Option<&'a praxis_core::kv::KvStoreRegistry>,

    /// Verified downstream mTLS identity.
    peer_identity: Option<&'a Arc<praxis_tls::TlsPeerIdentity>>,

    /// Start time of the containing client request.
    request_start: Instant,

    /// Shared client used for recursive subrequests.
    subrequest_client: Option<&'a praxis_core::subrequest::SubRequestClient>,

    /// Server-provided wall-clock source.
    time_source: &'a dyn praxis_core::time::TimeSource,
}

/// Build a [`HttpFilterContext`] for running a step's sub-pipeline,
/// inheriting server-injected resources from the containing request.
#[expect(clippy::too_many_lines, reason = "all fields must be initialized")]
fn build_sub_filter_context<'a>(
    pipeline: &'a FilterPipeline,
    request: &'a crate::Request,
    runtime: SubPipelineRuntimeResources<'a>,
) -> HttpFilterContext<'a> {
    HttpFilterContext {
        buffered_request_body: None,
        body_done_indices: Vec::new(),
        branch_iterations: HashMap::new(),
        client_addr: runtime.client_addr,
        cluster: None,
        current_filter_id: None,
        downstream_tls: runtime.downstream_tls,
        extensions: crate::extensions::RequestExtensions::default(),
        executed_filter_indices: Vec::new(),
        extra_request_headers: Vec::new(),
        filter_metadata: HashMap::new(),
        filter_results: HashMap::new(),
        filter_state: HashMap::new(),
        health_registry: runtime.health_registry,
        id_generator: runtime.id_generator,
        kv_stores: runtime.kv_stores,
        metrics_route: None,
        peer_identity: runtime.peer_identity.cloned(),
        pre_read_mutations: Vec::new(),
        request,
        request_body_bytes: 0,
        request_body_mode: pipeline.body_capabilities().request_body_mode,
        request_headers_to_remove: Vec::new(),
        request_headers_to_set: Vec::new(),
        request_start: runtime.request_start,
        response_body_bytes: 0,
        response_body_mode: pipeline.body_capabilities().response_body_mode,
        response_header: None,
        response_headers_modified: false,
        rewritten_path: None,
        selected_endpoint_index: None,
        attempted_endpoints: Vec::new(),
        retry_policy: None,
        route_retry_policy: None,
        cluster_retry_state: None,
        cluster_retry_state_released: false,
        endpoint_reselector: None,
        structured_metadata: HashMap::new(),
        subrequest_client: runtime.subrequest_client,
        subrequest_response_mode: SubRequestResponseMode::Buffered,
        time_source: runtime.time_source,
        upstream: None,
    }
}

/// Convert a Praxis [`Upstream`] to a Pingora [`HttpPeer`].
///
/// Applies TLS settings (CA, client cert, verify toggle) and
/// connection options (timeouts) from the upstream config. Derives
/// SNI from the address hostname when not explicitly configured.
///
/// [`Upstream`]: praxis_core::connectivity::Upstream
async fn build_peer(
    upstream: &praxis_core::connectivity::Upstream,
) -> Result<HttpPeer, praxis_core::connectivity::peer::AddressResolutionError> {
    use praxis_core::connectivity::peer as peer_utils;

    let addr: &str = &upstream.address;
    let socket_addr = peer_utils::resolve_address(addr).await?;
    let tls_enabled = upstream.tls.is_some();
    let sni = upstream
        .tls
        .as_ref()
        .and_then(|t| t.sni().map(str::to_owned))
        .unwrap_or_else(|| {
            if tls_enabled {
                peer_utils::derive_sni(addr)
            } else {
                String::new()
            }
        });

    let mut peer = HttpPeer::new(socket_addr, tls_enabled, sni);
    peer_utils::apply_connection_options(&mut peer, &upstream.connection);

    if let Some(tls) = &upstream.tls {
        peer_utils::apply_cached_tls(&mut peer, tls, addr);
    }

    Ok(peer)
}

/// Build a [`TerminalResponse`] carrying the sub-request response.
fn build_terminal_response(response: &SubResponse, preserve_content_length: bool) -> TerminalResponse {
    let status = normalize_response_status(response.status);
    let mut headers = HeaderMap::new();
    for (name, value) in &response.headers {
        if (name == http::header::CONTENT_LENGTH && !preserve_content_length) || name == http::header::TRANSFER_ENCODING
        {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    if !preserve_content_length && status != 204 && status != 304 {
        let content_length = response.body.len().to_string();
        if let Ok(value) = http::HeaderValue::from_str(&content_length) {
            headers.insert(http::header::CONTENT_LENGTH, value);
        }
    }
    let mut terminal = TerminalResponse::new(status).with_headers(headers);
    if !response.body.is_empty() {
        terminal = terminal.with_body(response.body.clone());
    }
    terminal
}
