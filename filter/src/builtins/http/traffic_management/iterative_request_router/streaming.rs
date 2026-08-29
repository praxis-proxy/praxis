// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Streaming response lifecycle types for the iterative request router.
//!
//! The iterative request router runs step pipelines across multiple
//! sub-requests. When a step's pipeline selects streaming mode,
//! `on_request()` returns a terminal streaming response whose body
//! is owned by [`IrrStreamingSession`].
//!
//! [`IrrStreamingSession`] pulls upstream chunks through each step's
//! response-body filters until the stream ends, then runs the step's
//! completion lifecycle exactly once and evaluates the next transition.
//! A matching `next` opens another step without recommitting downstream
//! response headers.
//!
//! [`StepResponseContinuation`] holds all state needed to run body
//! filters after `on_request()` returns: the step pipeline, request
//! and response snapshots, filter extensions, filter state, metadata,
//! and a completion guard. The continuation owns an `Arc<FilterPipeline>`
//! so the pipeline outlives the router filter.

use std::{
    any::Any,
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use async_trait::async_trait;
use bytes::Bytes;
use praxis_core::subrequest::SubResponseBody;

use crate::{
    FilterError, FilterPipeline, IterationState, NextIterationBody, StreamTermination, StreamTerminationCause,
    actions::StreamingResponseBody,
    context::PendingStreamChunks,
    extensions::RequestExtensions,
    results::{FilterResultSet, RetainedFilterResults},
};

/// State made available after a step's completion hook has run.
pub(super) struct StepCompletion {
    /// Shared request extensions after step completion.
    pub(super) extensions: RequestExtensions,
    /// Results retained across all step phases.
    pub(super) filter_results: HashMap<&'static str, FilterResultSet>,
    /// Optional request body for the next step.
    pub(super) next_iteration_body: Option<Bytes>,
    /// Bounded locally emitted chunks.
    pub(super) pending_chunks: VecDeque<Bytes>,
    /// Updated iteration state.
    pub(super) state: IterationState,
    /// Typed abnormal source termination, when present.
    pub(super) termination: Option<StreamTermination>,
}

/// A completion conversion failure together with recoverable parent state.
pub(super) struct StepCompletionError {
    /// Underlying lifecycle error.
    error: FilterError,
    /// Parent-owned extensions recovered from the failed continuation.
    extensions: RequestExtensions,
}

impl StepCompletionError {
    /// Split the error from the extensions its caller must restore.
    pub(super) fn into_parts(self) -> (FilterError, RequestExtensions) {
        (self.error, self.extensions)
    }
}

/// State continuation for streaming a step's response body.
///
/// Owns the step pipeline, request/response snapshots, and all
/// per-filter state needed to run response-body filters after
/// `on_request()` returns. The `Arc<FilterPipeline>` outlives
/// the router filter, enabling body hooks to execute while the
/// router's `on_request` has already completed.
pub(super) struct StepResponseContinuation {
    /// Arc-wrapped step pipeline for executing response-body filters.
    pub(super) pipeline: Arc<FilterPipeline>,
    /// Snapshot of the step's request for filter context reconstruction.
    pub(super) request_snapshot: crate::Request,
    /// Snapshot of the step's response headers for filter context reconstruction.
    pub(super) response_snapshot: crate::Response,
    /// Request extensions that persist across body chunks.
    pub(super) extensions: RequestExtensions,
    /// Per-filter state that persists across body chunks.
    pub(super) filter_state: HashMap<usize, Box<dyn Any + Send + Sync>>,
    /// Filter results that persist across body chunks.
    pub(super) filter_results: HashMap<&'static str, FilterResultSet>,
    /// Filter metadata that persists across body chunks.
    pub(super) filter_metadata: HashMap<String, String>,
    /// Structured metadata that persists across body chunks.
    pub(super) structured_metadata: HashMap<String, serde_json::Value>,
    /// Tracks which filters executed during request phase.
    pub(super) executed_filter_indices: Vec<bool>,
    /// Tracks which filters completed their body hooks.
    pub(super) body_done_indices: Vec<bool>,
    /// Accumulated response body bytes seen so far.
    pub(super) response_body_bytes: u64,
    /// Response body mode from pipeline capabilities.
    pub(super) response_body_mode: crate::body::BodyMode,
    /// Whether the completion lifecycle has run.
    pub(super) completed: bool,
    /// Original downstream client address for body filter context.
    pub(super) client_addr: Option<std::net::IpAddr>,
    /// Whether the original downstream connection uses TLS.
    pub(super) downstream_tls: bool,
    /// Start time of the containing client request.
    pub(super) request_start: std::time::Instant,
    /// Absolute deadline shared by header and body processing for this step.
    pub(super) step_deadline: std::time::Instant,
    /// Verified downstream mTLS identity.
    pub(super) peer_identity: Option<Arc<praxis_tls::TlsPeerIdentity>>,
}

impl StepResponseContinuation {
    /// Capture all owned step context after response headers have run.
    #[expect(
        clippy::too_many_arguments,
        reason = "capture owns the complete response continuation boundary"
    )]
    pub(super) fn capture(
        pipeline: Arc<FilterPipeline>,
        request_snapshot: crate::Request,
        response_snapshot: crate::Response,
        ctx: &mut crate::filter::HttpFilterContext<'_>,
        completed: bool,
        step_deadline: std::time::Instant,
    ) -> Self {
        Self {
            pipeline,
            request_snapshot,
            response_snapshot,
            extensions: std::mem::take(&mut ctx.extensions),
            filter_state: std::mem::take(&mut ctx.filter_state),
            filter_results: std::mem::take(&mut ctx.filter_results),
            filter_metadata: std::mem::take(&mut ctx.filter_metadata),
            structured_metadata: std::mem::take(&mut ctx.structured_metadata),
            executed_filter_indices: std::mem::take(&mut ctx.executed_filter_indices),
            body_done_indices: std::mem::take(&mut ctx.body_done_indices),
            response_body_bytes: ctx.response_body_bytes,
            response_body_mode: ctx.response_body_mode,
            completed,
            client_addr: ctx.client_addr,
            downstream_tls: ctx.downstream_tls,
            request_start: ctx.request_start,
            step_deadline,
            peer_identity: ctx.peer_identity.clone(),
        }
    }

    /// Recover only caller-owned extensions when an internal invariant fails.
    pub(super) fn into_parent_extensions(mut self) -> RequestExtensions {
        self.extensions.remove::<IterationState>();
        self.extensions.remove::<NextIterationBody>();
        self.extensions.remove::<PendingStreamChunks>();
        self.extensions.remove::<RetainedFilterResults>();
        self.extensions.remove::<StreamTermination>();
        self.extensions
    }

    /// Consume the completed continuation into transition inputs.
    pub(super) fn into_completion(mut self) -> Result<StepCompletion, StepCompletionError> {
        let Some(state) = self.extensions.remove::<IterationState>() else {
            return Err(StepCompletionError {
                error: "iterative_request_router: iteration state missing after step completion"
                    .to_owned()
                    .into(),
                extensions: self.into_parent_extensions(),
            });
        };
        let next_iteration_body = self.extensions.remove::<NextIterationBody>().map(|body| body.0);
        let pending_chunks = self
            .extensions
            .remove::<PendingStreamChunks>()
            .map_or_else(VecDeque::new, PendingStreamChunks::into_chunks);
        let termination = self.extensions.remove::<StreamTermination>();
        let mut filter_results = self.extensions.remove::<RetainedFilterResults>().unwrap_or_default().0;
        filter_results.extend(self.filter_results);
        Ok(StepCompletion {
            extensions: self.extensions,
            filter_results,
            next_iteration_body,
            pending_chunks,
            state,
            termination,
        })
    }
}

/// Streaming body implementation for iterative request router steps.
///
/// Pulls upstream chunks through the step's response-body filters,
/// accumulates state in the owned [`StepResponseContinuation`],
/// and runs the step's completion lifecycle exactly once after
/// upstream EOF.
///
/// The `upstream` field is `Option<SubResponseBody>` because
/// `SubResponseBody::cancel()` consumes `self`. Standard Rust
/// pattern: `.take()` to move it out for cancellation.
pub(super) struct IrrStreamingBody {
    /// Upstream streaming body handle. `None` after cancellation.
    upstream: Option<Box<SubResponseBody>>,
    /// Owned state for running step response-body filters.
    continuation: StepResponseContinuation,
    /// Whether the stream has finished (EOF or error).
    finished: bool,
    /// Completion-hook body output held until IRR selects a transition.
    deferred_completion_output: Option<Bytes>,
    /// Per-callback local output waiting to be pulled downstream.
    pending_chunks: VecDeque<Bytes>,
}

impl IrrStreamingBody {
    /// Create a new streaming body for a step's response.
    pub(super) fn new(upstream: Box<SubResponseBody>, continuation: StepResponseContinuation) -> Self {
        Self {
            upstream: Some(upstream),
            continuation,
            finished: false,
            deferred_completion_output: None,
            pending_chunks: VecDeque::new(),
        }
    }

    /// Consume the body wrapper after EOF and recover its owned step state.
    pub(super) fn into_continuation(self) -> StepResponseContinuation {
        self.continuation
    }

    /// Consume a finished body into its continuation and deferred output.
    fn into_finished_parts(self) -> (StepResponseContinuation, Option<Bytes>) {
        (self.continuation, self.deferred_completion_output)
    }

    /// Exchange extensions with the outer protocol lifecycle.
    fn exchange_extensions(&mut self, extensions: &mut RequestExtensions) {
        std::mem::swap(&mut self.continuation.extensions, extensions);
    }

    /// Run the step's response-body filters on a single chunk.
    ///
    /// Reconstructs a temporary `HttpFilterContext` from the
    /// continuation's owned state, runs the pipeline's body
    /// execution, then writes state changes back to the
    /// continuation for the next chunk.
    #[expect(clippy::too_many_lines, reason = "context reconstruction requires many fields")]
    fn run_step_body_filters(&mut self, body: &mut Option<Bytes>, end_of_stream: bool) -> Result<(), FilterError> {
        let cont = &mut self.continuation;
        let mut ctx = crate::filter::HttpFilterContext {
            buffered_request_body: None,
            body_done_indices: std::mem::take(&mut cont.body_done_indices),
            branch_iterations: HashMap::new(),
            client_addr: cont.client_addr,
            cluster: None,
            current_filter_id: None,
            downstream_tls: cont.downstream_tls,
            extensions: std::mem::take(&mut cont.extensions),
            executed_filter_indices: std::mem::take(&mut cont.executed_filter_indices),
            extra_request_headers: Vec::new(),
            filter_metadata: std::mem::take(&mut cont.filter_metadata),
            filter_results: std::mem::take(&mut cont.filter_results),
            filter_state: std::mem::take(&mut cont.filter_state),
            health_registry: cont.pipeline.health_registry(),
            id_generator: cont.pipeline.id_generator(),
            kv_stores: cont.pipeline.kv_stores(),
            metrics_route: None,
            peer_identity: cont.peer_identity.clone(),
            pre_read_mutations: Vec::new(),
            request: &cont.request_snapshot,
            request_body_bytes: 0,
            request_body_mode: cont.pipeline.body_capabilities().request_body_mode,
            request_headers_to_remove: Vec::new(),
            request_headers_to_set: Vec::new(),
            request_start: cont.request_start,
            response_body_bytes: cont.response_body_bytes,
            response_body_mode: cont.response_body_mode,
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
            pinned_endpoint_address: None,
            session_stores: None,
            structured_metadata: std::mem::take(&mut cont.structured_metadata),
            subrequest_client: cont.pipeline.subrequest_client(),
            subrequest_response_mode: crate::context::SubRequestResponseMode::Streaming,
            time_source: cont.pipeline.time_source(),
            upstream: None,
        };

        let result = cont.pipeline.execute_http_response_body_with_response_header(
            &mut ctx,
            body,
            end_of_stream,
            Some(&cont.response_snapshot),
        );

        cont.body_done_indices = ctx.body_done_indices;
        cont.executed_filter_indices = ctx.executed_filter_indices;
        cont.extensions = ctx.extensions;
        cont.filter_metadata = ctx.filter_metadata;
        cont.filter_results = ctx.filter_results;
        cont.filter_state = ctx.filter_state;
        cont.response_body_bytes = ctx.response_body_bytes;
        cont.structured_metadata = ctx.structured_metadata;

        match result? {
            crate::actions::FilterAction::Reject(_) => {
                Err("iterative_request_router: step body filter rejected during stream"
                    .to_owned()
                    .into())
            },
            _ => Ok(()),
        }
    }

    /// Run the step's completion lifecycle exactly once.
    ///
    /// Called after upstream EOF. Runs body filters with
    /// `end_of_stream: true` to let them emit any buffered
    /// completion chunk (e.g. a closing SSE comment or JSON
    /// array bracket).
    fn complete_step(&mut self) -> Result<Option<Bytes>, FilterError> {
        if self.continuation.completed {
            return Ok(None);
        }
        self.continuation.completed = true;
        let mut body: Option<Bytes> = None;
        self.run_step_body_filters(&mut body, true)?;
        Ok(body)
    }

    /// Handle a chunk received from the upstream.
    fn handle_upstream_chunk(&mut self, chunk: Bytes) -> Result<Option<Bytes>, FilterError> {
        let mut body = Some(chunk);
        self.run_step_body_filters(&mut body, false)?;
        let emitted = self
            .continuation
            .extensions
            .get_mut::<PendingStreamChunks>()
            .map_or_else(VecDeque::new, PendingStreamChunks::drain_chunks);
        self.pending_chunks.extend(emitted);
        self.pending_chunks.extend(body.filter(|bytes| !bytes.is_empty()));
        Ok(self.pending_chunks.pop_front())
    }

    /// Complete the step after a response-body filter failure.
    async fn handle_filter_error(&mut self, error: FilterError) -> Result<Option<Bytes>, FilterError> {
        if let Some(upstream_body) = self.upstream.take() {
            (*upstream_body).cancel().await;
        }
        self.continuation
            .extensions
            .insert(StreamTermination::new(StreamTerminationCause::Filter));
        let completion = self.complete_step().map_err(|completion_error| -> FilterError {
            format!(
                "iterative_request_router: response filter failed ({error}); completion also failed ({completion_error})"
            )
            .into()
        })?;
        self.finished = true;
        self.deferred_completion_output = self.handled_completion_output(completion);
        Ok(None)
    }

    /// Handle upstream EOF.
    fn handle_upstream_eof(&mut self) -> Result<Option<Bytes>, FilterError> {
        let completion = self.complete_step()?;
        self.finished = true;
        self.deferred_completion_output = completion.filter(|bytes| !bytes.is_empty());
        Ok(None)
    }

    /// Handle an upstream error.
    async fn handle_upstream_error(
        &mut self,
        e: praxis_core::subrequest::SubRequestError,
    ) -> Result<Option<Bytes>, FilterError> {
        if let Some(upstream_body) = self.upstream.take() {
            (*upstream_body).cancel().await;
        }
        self.continuation
            .extensions
            .insert(StreamTermination::new(termination_cause(&e)));
        let completion = self.complete_step()?;
        self.finished = true;
        self.deferred_completion_output = self.handled_completion_output(completion);
        Ok(None)
    }

    /// Expose an abnormal completion body only when a filter explicitly
    /// converted the failure into a valid terminal sequence.
    fn handled_completion_output(&self, completion: Option<Bytes>) -> Option<Bytes> {
        self.continuation
            .extensions
            .get::<StreamTermination>()
            .is_some_and(StreamTermination::is_handled)
            .then_some(completion)
            .flatten()
            .filter(|bytes| !bytes.is_empty())
    }
}

/// Map transport detail to the provider-neutral completion classification.
fn termination_cause(error: &praxis_core::subrequest::SubRequestError) -> StreamTerminationCause {
    use praxis_core::subrequest::SubRequestError;
    match error {
        SubRequestError::AdmissionTimeout { .. } => StreamTerminationCause::AdmissionTimeout,
        SubRequestError::CircuitOpen { .. } => StreamTerminationCause::CircuitOpen,
        SubRequestError::Connect(_) => StreamTerminationCause::Connect,
        SubRequestError::DeadlineExceeded => StreamTerminationCause::DeadlineExceeded,
        SubRequestError::StreamIdleTimeout { .. } => StreamTerminationCause::IdleTimeout,
        SubRequestError::ResponseTooLarge { .. } => StreamTerminationCause::ResponseTooLarge,
        _ => StreamTerminationCause::Io,
    }
}

#[async_trait]
impl StreamingResponseBody for IrrStreamingBody {
    #[expect(clippy::too_many_lines, reason = "pull loop applies deadlines and completion state")]
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
        if let Some(chunk) = self.pending_chunks.pop_front() {
            return Ok(Some(chunk));
        }
        if self.finished {
            return Ok(None);
        }

        loop {
            let upstream = self.upstream.as_mut().ok_or_else(|| -> FilterError {
                "iterative_request_router: upstream already consumed".to_owned().into()
            })?;

            let remaining = self
                .continuation
                .step_deadline
                .checked_duration_since(std::time::Instant::now())
                .unwrap_or_default();
            let next = if remaining.is_zero() {
                Err(praxis_core::subrequest::SubRequestError::DeadlineExceeded)
            } else {
                tokio::time::timeout(remaining, upstream.next_chunk())
                    .await
                    .unwrap_or(Err(praxis_core::subrequest::SubRequestError::DeadlineExceeded))
            };

            match next {
                Ok(Some(chunk)) => match self.handle_upstream_chunk(chunk) {
                    Ok(Some(bytes)) => return Ok(Some(bytes)),
                    Ok(None) => {},
                    Err(error) => return Box::pin(self.handle_filter_error(error)).await,
                },
                Ok(None) => return self.handle_upstream_eof(),
                Err(e) => return Box::pin(self.handle_upstream_error(e)).await,
            }
        }
    }

    async fn suppress(&mut self) -> Result<(), FilterError> {
        if !self.finished {
            self.finished = true;
            if let Some(upstream_body) = self.upstream.take() {
                (*upstream_body).cancel().await;
            }
            self.complete_step()?;
        }
        Ok(())
    }

    async fn cancel(&mut self) {
        if !self.finished {
            self.finished = true;
            if let Some(upstream_body) = self.upstream.take() {
                (*upstream_body).cancel().await;
            }
        }
    }

    fn swap_extensions(&mut self, extensions: &mut RequestExtensions) {
        self.exchange_extensions(extensions);
    }
}

/// A committed logical response that can span multiple IRR steps.
pub(super) struct IrrStreamingSession {
    /// Active step body, when a streamed step is being consumed.
    current: Option<IrrStreamingBody>,
    /// Outcome corresponding to `current`.
    current_outcome: Option<super::StepOutcome>,
    /// Request inherited or replaced for the current step.
    current_request: crate::SubRequest,
    /// Current configured step name.
    current_step: Arc<str>,
    /// Whether the logical response reached a terminal state.
    done: bool,
    /// Unhandled failure returned after final pending chunks drain.
    deferred_error: Option<FilterError>,
    /// Cumulative downstream payload bytes produced by this session.
    emitted_bytes: usize,
    /// Extensions held between active steps.
    extensions: Option<RequestExtensions>,
    /// Whether EOF follows the pending local output queue.
    finish_after_pending: bool,
    /// Retained-state and pending-output ceiling.
    max_state_bytes: usize,
    /// Optional logical streamed-response byte ceiling.
    max_stream_response_bytes: Option<usize>,
    /// Step selected after the current completion.
    next_step: Option<Arc<str>>,
    /// Locally emitted or terminal buffered chunks awaiting delivery.
    pending_chunks: VecDeque<Bytes>,
    /// Reusable one-step executor.
    runner: super::runner::IrrStepRunner,
    /// Iteration state held between active steps.
    state: Option<IterationState>,
    /// Ordered transition rules for every named step.
    step_transitions: HashMap<Arc<str>, Vec<super::config::StepTransition>>,
}

impl IrrStreamingSession {
    /// Create a logical session from the already opened first streamed step.
    #[expect(
        clippy::too_many_arguments,
        reason = "session owns the complete logical response state"
    )]
    pub(super) fn new(
        runner: super::runner::IrrStepRunner,
        current_step: Arc<str>,
        current_request: crate::SubRequest,
        outcome: super::StepOutcome,
        body: Box<SubResponseBody>,
        continuation: StepResponseContinuation,
        pending_chunks: VecDeque<Bytes>,
        step_transitions: HashMap<Arc<str>, Vec<super::config::StepTransition>>,
        max_state_bytes: usize,
        max_stream_response_bytes: Option<usize>,
    ) -> Self {
        Self {
            current: Some(IrrStreamingBody::new(body, continuation)),
            current_outcome: Some(outcome),
            current_request,
            current_step,
            done: false,
            deferred_error: None,
            emitted_bytes: 0,
            extensions: None,
            finish_after_pending: false,
            max_state_bytes,
            max_stream_response_bytes,
            next_step: None,
            pending_chunks,
            runner,
            state: None,
            step_transitions,
        }
    }

    /// Account for one outgoing chunk against the logical byte ceiling.
    fn checked_chunk(&mut self, chunk: Bytes) -> Result<Option<Bytes>, FilterError> {
        let total = self
            .emitted_bytes
            .checked_add(chunk.len())
            .ok_or_else(|| -> FilterError { "iterative_request_router: stream byte count overflow".into() })?;
        if self.max_stream_response_bytes.is_some_and(|limit| total > limit) {
            return Err("iterative_request_router: logical stream byte limit exceeded"
                .to_owned()
                .into());
        }
        self.emitted_bytes = total;
        Ok(Some(chunk))
    }

    /// Transition rules for the current step.
    fn transitions(&self) -> &[super::config::StepTransition] {
        self.step_transitions.get(&self.current_step).map_or(&[], Vec::as_slice)
    }

    /// Persist a completed step and select the next session phase.
    #[expect(
        clippy::too_many_lines,
        reason = "completion handles limits, failures, and transitions"
    )]
    fn apply_completion(
        &mut self,
        mut completion: StepCompletion,
        outcome: &super::StepOutcome,
        completion_output: Option<Bytes>,
        terminal_body: Option<Bytes>,
    ) -> Result<(), FilterError> {
        completion.state.previous_response = Some(outcome.response.clone());
        completion.state.iteration += 1;
        if let Err(error) = ensure_combined_retained_limit(
            completion.state.retained_bytes(),
            self.pending_chunks.iter().map(Bytes::len),
            self.max_state_bytes,
        ) {
            self.extensions = Some(completion.extensions);
            self.state = Some(completion.state);
            return Err(error);
        }
        let transition = super::evaluate_transitions(self.transitions(), outcome, &completion.filter_results);
        let abnormal_completion = completion.termination.is_some();
        let unhandled_termination = completion
            .termination
            .as_ref()
            .is_some_and(|termination| !termination.is_handled());
        if unhandled_termination
            && matches!(
                transition,
                super::TransitionResult::Done | super::TransitionResult::NoMatch
            )
        {
            let cause = completion.termination.as_ref().map(StreamTermination::cause);
            self.extensions = Some(completion.extensions);
            self.state = Some(completion.state);
            self.deferred_error =
                Some(format!("iterative_request_router: unhandled upstream stream termination: {cause:?}").into());
            return Ok(());
        }
        let completion_output = (!abnormal_completion || !matches!(transition, super::TransitionResult::Next(_)))
            .then_some(completion_output)
            .flatten()
            .filter(|body| !body.is_empty());
        if abnormal_completion && matches!(transition, super::TransitionResult::Next(_)) {
            completion.pending_chunks.clear();
        }
        let terminal_body = matches!(
            transition,
            super::TransitionResult::Done | super::TransitionResult::NoMatch
        )
        .then_some(terminal_body)
        .flatten()
        .filter(|body| !body.is_empty());
        if let Err(error) = ensure_combined_retained_limit(
            completion.state.retained_bytes(),
            self.pending_chunks
                .iter()
                .chain(completion.pending_chunks.iter())
                .chain(completion_output.iter())
                .chain(terminal_body.iter())
                .map(Bytes::len),
            self.max_state_bytes,
        ) {
            self.extensions = Some(completion.extensions);
            self.state = Some(completion.state);
            return Err(error);
        }
        self.pending_chunks.extend(completion.pending_chunks);
        self.pending_chunks.extend(completion_output);
        self.extensions = Some(completion.extensions);
        self.state = Some(completion.state);
        match transition {
            super::TransitionResult::Next(next) => {
                let next_body = completion
                    .next_iteration_body
                    .unwrap_or_else(|| self.current_request.body.clone());
                self.current_request = crate::SubRequest {
                    method: self.current_request.method.clone(),
                    uri: self.current_request.uri.clone(),
                    headers: http::HeaderMap::new(),
                    body: next_body,
                };
                self.next_step = Some(next);
            },
            super::TransitionResult::Done | super::TransitionResult::NoMatch => {
                self.pending_chunks.extend(terminal_body);
                self.finish_after_pending = true;
            },
        }
        Ok(())
    }

    /// Consume the current body after clean or typed completion.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "consuming the body also consumes its continuation"
    )]
    fn finish_current(&mut self) -> Result<(), FilterError> {
        let current = self
            .current
            .take()
            .ok_or_else(|| -> FilterError { "iterative_request_router: current stream missing at EOF".into() })?;
        let (continuation, completion_output) = current.into_finished_parts();
        let completion = match continuation.into_completion() {
            Ok(completion) => completion,
            Err(error) => {
                let (error, restored_extensions) = error.into_parts();
                self.extensions = Some(restored_extensions);
                return Err(error);
            },
        };
        let outcome = self
            .current_outcome
            .take()
            .ok_or_else(|| -> FilterError { "iterative_request_router: current step outcome missing at EOF".into() })?;
        self.apply_completion(completion, &outcome, completion_output, None)
    }

    /// Open and classify the next selected step.
    #[expect(clippy::too_many_lines, reason = "next step may fail over, buffer, or stream")]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "opened step is destructured across match arms"
    )]
    #[expect(
        clippy::large_stack_frames,
        reason = "opening a step reconstructs its filter context"
    )]
    async fn open_next(&mut self) -> Result<(), FilterError> {
        let next = self
            .next_step
            .take()
            .ok_or_else(|| -> FilterError { "iterative_request_router: next step missing".into() })?;
        self.current_step = next;
        let state = self.state.take().ok_or_else(|| -> FilterError {
            "iterative_request_router: iteration state missing between steps".into()
        })?;
        if state.iteration >= state.max_iterations {
            return Err("iterative_request_router: max iterations exhausted".to_owned().into());
        }
        let extensions = self.extensions.take().unwrap_or_default();
        let opened =
            match Box::pin(
                self.runner
                    .open_step(&self.current_step, &self.current_request, &state, extensions),
            )
            .await
            {
                Ok(opened) => opened,
                Err(error) => {
                    let (error, restored_extensions) = error.into_parts();
                    self.extensions = Some(restored_extensions);
                    self.state = Some(state);
                    return Err(error);
                },
            };
        let super::runner::OpenedStep { continuation, kind } = opened;
        match kind {
            super::runner::OpenedStepKind::Streaming { body, outcome } => {
                if !super::streaming_transition_order_is_valid(self.transitions()) {
                    (*body).cancel().await;
                    self.extensions = Some(continuation.into_parent_extensions());
                    self.state = Some(state);
                    return Err(format!(
                        "iterative_request_router: step '{}' selected streaming with interleaved transition phases",
                        self.current_step
                    )
                    .into());
                }
                match super::evaluate_header_transitions(self.transitions(), &outcome) {
                    super::TransitionResult::Next(next) => {
                        let mut skipped = IrrStreamingBody::new(body, continuation);
                        if let Err(error) = skipped.suppress().await {
                            self.extensions = Some(skipped.into_continuation().into_parent_extensions());
                            self.state = Some(state);
                            return Err(error);
                        }
                        let mut completion = match skipped.into_continuation().into_completion() {
                            Ok(completion) => completion,
                            Err(error) => {
                                let (error, restored_extensions) = error.into_parts();
                                self.extensions = Some(restored_extensions);
                                self.state = Some(state);
                                return Err(error);
                            },
                        };
                        completion.state.previous_response = None;
                        completion.state.iteration += 1;
                        if let Err(error) = ensure_combined_retained_limit(
                            completion.state.retained_bytes(),
                            self.pending_chunks.iter().map(Bytes::len),
                            self.max_state_bytes,
                        ) {
                            self.extensions = Some(completion.extensions);
                            self.state = Some(completion.state);
                            return Err(error);
                        }
                        self.extensions = Some(completion.extensions);
                        self.state = Some(completion.state);
                        self.current_request = crate::SubRequest {
                            method: self.current_request.method.clone(),
                            uri: self.current_request.uri.clone(),
                            headers: http::HeaderMap::new(),
                            body: completion
                                .next_iteration_body
                                .unwrap_or_else(|| self.current_request.body.clone()),
                        };
                        self.next_step = Some(next);
                    },
                    super::TransitionResult::Done | super::TransitionResult::NoMatch => {
                        self.current = Some(IrrStreamingBody::new(body, continuation));
                        self.current_outcome = Some(outcome);
                    },
                }
            },
            super::runner::OpenedStepKind::Complete(outcome) => {
                let completion = match continuation.into_completion() {
                    Ok(completion) => completion,
                    Err(error) => {
                        let (error, restored_extensions) = error.into_parts();
                        self.extensions = Some(restored_extensions);
                        self.state = Some(state);
                        return Err(error);
                    },
                };
                let abnormal_completion = completion.termination.is_some();
                let completion_output = abnormal_completion.then(|| outcome.response.body.clone());
                let terminal_body = (!abnormal_completion).then(|| outcome.response.body.clone());
                self.apply_completion(completion, &outcome, completion_output, terminal_body)?;
            },
        }
        Ok(())
    }
}

/// Enforce the shared retained-state and pending-output ceiling using the
/// final state produced by the complete response-filter lifecycle.
pub(super) fn ensure_combined_retained_limit(
    state_bytes: usize,
    mut chunk_lengths: impl Iterator<Item = usize>,
    limit: usize,
) -> Result<(), FilterError> {
    let retained = chunk_lengths.try_fold(state_bytes, |retained, chunk_len| {
        retained
            .checked_add(chunk_len)
            .ok_or_else(|| -> FilterError { "iterative_request_router: retained state size overflow".into() })
    })?;
    if retained > limit {
        return Err("iterative_request_router: retained state limit exceeded"
            .to_owned()
            .into());
    }
    Ok(())
}

#[async_trait]
impl StreamingResponseBody for IrrStreamingSession {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
        loop {
            if let Some(chunk) = self.pending_chunks.pop_front() {
                return self.checked_chunk(chunk);
            }
            if let Some(error) = self.deferred_error.take() {
                self.done = true;
                return Err(error);
            }
            if self.finish_after_pending || self.done {
                self.done = true;
                return Ok(None);
            }
            if let Some(current) = self.current.as_mut() {
                if let Some(chunk) = current.next_chunk().await? {
                    return self.checked_chunk(chunk);
                }
                self.finish_current()?;
                continue;
            }
            if self.next_step.is_some() {
                Box::pin(self.open_next()).await?;
                continue;
            }
            return Err("iterative_request_router: streaming session has no runnable phase"
                .to_owned()
                .into());
        }
    }

    async fn suppress(&mut self) -> Result<(), FilterError> {
        loop {
            self.pending_chunks.clear();
            if let Some(error) = self.deferred_error.take() {
                self.done = true;
                return Err(error);
            }
            if self.finish_after_pending || self.done {
                self.done = true;
                return Ok(());
            }
            if let Some(current) = self.current.as_mut() {
                current.suppress().await?;
                self.finish_current()?;
                continue;
            }
            if self.next_step.is_some() {
                Box::pin(self.open_next()).await?;
                continue;
            }
            return Err(
                "iterative_request_router: suppressed streaming session has no runnable phase"
                    .to_owned()
                    .into(),
            );
        }
    }

    async fn cancel(&mut self) {
        if let Some(current) = self.current.as_mut() {
            current.cancel().await;
        }
        self.current = None;
        self.pending_chunks.clear();
        self.next_step = None;
        self.done = true;
    }

    fn swap_extensions(&mut self, extensions: &mut RequestExtensions) {
        if let Some(current) = self.current.as_mut() {
            current.swap_extensions(extensions);
        } else if let Some(owned) = self.extensions.as_mut() {
            std::mem::swap(owned, extensions);
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::ensure_combined_retained_limit;

    #[test]
    fn completion_rechecks_final_state_with_pending_output() {
        let chunks = [Bytes::from_static(b"123")];
        let result = ensure_combined_retained_limit(8, chunks.iter().map(Bytes::len), 10);
        assert!(
            result
                .as_ref()
                .is_err_and(|error| error.to_string().contains("retained state limit")),
            "combined limit failure should identify retained state: {result:?}"
        );
    }

    #[test]
    fn completion_accepts_exact_combined_retained_limit() {
        let chunks = [Bytes::from_static(b"12")];
        let result = ensure_combined_retained_limit(8, chunks.iter().map(Bytes::len), 10);
        assert!(
            result.is_ok(),
            "final state and pending chunks should be accepted at the exact limit: {result:?}"
        );
    }
}
