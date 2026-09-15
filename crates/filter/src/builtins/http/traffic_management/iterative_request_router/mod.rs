// SPDX-License-Identifier: Apache-2.0
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
//! When a step's filters select [`SubRequestResponseMode::Streaming`](crate::SubRequestResponseMode::Streaming),
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
use tracing::{debug, info, warn};

use self::{
    config::IterativeRequestRouterConfig,
    runner::{IrrStepRunner, OpenedStepKind},
    streaming::{IrrStreamingSession, ensure_combined_retained_limit, step_completion_from},
};
use crate::{
    FilterEntry, FilterError, FilterPipeline, FilterRegistry, IterationState, NextIterationBody, RequestExtensions,
    StreamTermination, SubRequest, SubResponse,
    actions::{FilterAction, Rejection, StreamingResponseBody as _, StreamingTerminalResponse, TerminalResponse},
    extensions::SelectedClusterApplication,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
    filtered_subrequest::{FilteredStreamingBody, SubrequestRuntime, normalize_response_status},
    pipeline::subrequest::DEPTH_HEADER,
};

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

/// Strip the router-owned iteration extensions before handing state back to the
/// parent request context.
///
/// The generic executor already removes its own transient mechanisms; the
/// router additionally injects [`IterationState`] and [`NextIterationBody`],
/// which must not leak into the parent pipeline. Applying this to the executor's
/// parent-facing extensions restores the exact end state of the pre-extraction
/// router.
pub(super) fn strip_iteration_extensions(mut extensions: RequestExtensions) -> RequestExtensions {
    extensions.remove::<IterationState>();
    extensions.remove::<NextIterationBody>();
    extensions
}

/// Drop any selected-cluster application metadata a prior step published, so a
/// new step never inherits it through the threaded [`RequestExtensions`].
///
/// Called at each iteration boundary — the top of the run loop and the top of a
/// streaming resume (`IrrStreamingSession::open_next`) — before the
/// max-iteration and deadline guards can early-return the threaded extensions to
/// the parent, and before the step's body hooks run (which precede its load
/// balancer under a `StreamBuffer` pre-read). The step's load balancer
/// republishes for the current step during `on_request`, so the terminal step's
/// value survives while no early exit and no pre-selection hook observes a stale
/// one.
pub(super) fn clear_selected_application(extensions: &mut RequestExtensions) {
    extensions.remove::<SelectedClusterApplication>();
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

    fn produces_terminal_response(&self) -> bool {
        // IRR resolves a sub-request and returns its response as a terminal
        // action, so it can never run inside a filtered sub-request's outbound
        // chain. Declaring the capability lets bind-time validation reject it
        // without relying on a name match.
        true
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

    /// Documents referenced by filters inside the step pipelines. The top-level
    /// pipeline walk that drives config hot reload does not recurse into nested
    /// pipelines, so the router surfaces its step-filter documents here;
    /// otherwise editing them (e.g. a policy document) would not trigger a
    /// reload.
    fn referenced_files(&self) -> Vec<std::path::PathBuf> {
        self.step_pipelines
            .values()
            .flat_map(|pipeline| pipeline.referenced_files())
            .collect()
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
            SubrequestRuntime {
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
            clear_selected_application(&mut extensions);
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
                        ctx.extensions = strip_iteration_extensions(continuation.into_parent_extensions());
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
                            let mut skipped = FilteredStreamingBody::new(body, continuation);
                            if let Err(error) = skipped.suppress().await {
                                ctx.extensions =
                                    strip_iteration_extensions(skipped.into_continuation().into_parent_extensions());
                                return Err(error);
                            }
                            let mut completion =
                                match step_completion_from(skipped.into_continuation().into_completion()) {
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
                            let Some(active_state) = continuation.extensions().get::<IterationState>() else {
                                (*body).cancel().await;
                                ctx.extensions = strip_iteration_extensions(continuation.into_parent_extensions());
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
                                let completion = match step_completion_from(continuation.into_completion()) {
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
                    let completion = match step_completion_from(continuation.into_completion()) {
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
