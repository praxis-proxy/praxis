// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Streaming response lifecycle for the iterative request router.
//!
//! The iterative request router runs step pipelines across multiple
//! sub-requests. When a step's pipeline selects streaming mode,
//! `on_request()` returns a terminal streaming response whose body
//! is owned by [`IrrStreamingSession`].
//!
//! [`IrrStreamingSession`] pulls upstream chunks through each step's
//! response-body filters — via the generic [`FilteredStreamingBody`] — until
//! the stream ends, then runs the step's completion lifecycle exactly once
//! and evaluates the next transition. A matching `next` opens another step
//! without recommitting downstream response headers.
//!
//! [`step_completion_from`] adapts the executor's caller-agnostic
//! [`SubrequestCompletion`] into the router's [`StepCompletion`], recovering
//! the router's [`IterationState`] and [`NextIterationBody`] from the returned
//! extensions.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use async_trait::async_trait;
use bytes::Bytes;
use praxis_core::subrequest::SubResponseBody;

use crate::{
    FilterError, IterationState, NextIterationBody, StreamTermination,
    actions::StreamingResponseBody,
    extensions::RequestExtensions,
    filtered_subrequest::{FilteredStreamingBody, FilteredSubrequestContinuation, SubrequestCompletion},
    results::FilterResultSet,
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

/// Adapt the executor's generic completion into the router's step vocabulary.
///
/// The generic [`SubrequestCompletion`] already lifted the executor-owned
/// mechanisms into typed fields and left caller-injected types in its
/// extensions. This recovers the router's [`IterationState`] and
/// [`NextIterationBody`]; a missing iteration state is a lifecycle error whose
/// recoverable extensions have both router-owned types stripped, matching the
/// parent-facing end state of every other exit path.
pub(super) fn step_completion_from(completion: SubrequestCompletion) -> Result<StepCompletion, StepCompletionError> {
    let SubrequestCompletion {
        mut extensions,
        filter_results,
        pending_chunks,
        termination,
    } = completion;
    let Some(state) = extensions.remove::<IterationState>() else {
        return Err(StepCompletionError {
            error: "iterative_request_router: iteration state missing after step completion"
                .to_owned()
                .into(),
            extensions: super::strip_iteration_extensions(extensions),
        });
    };
    let next_iteration_body = extensions.remove::<NextIterationBody>().map(|body| body.0);
    Ok(StepCompletion {
        extensions,
        filter_results,
        next_iteration_body,
        pending_chunks,
        state,
        termination,
    })
}

/// A committed logical response that can span multiple IRR steps.
pub(super) struct IrrStreamingSession {
    /// Active step body, when a streamed step is being consumed.
    current: Option<FilteredStreamingBody>,
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
        continuation: FilteredSubrequestContinuation,
        pending_chunks: VecDeque<Bytes>,
        step_transitions: HashMap<Arc<str>, Vec<super::config::StepTransition>>,
        max_state_bytes: usize,
        max_stream_response_bytes: Option<usize>,
    ) -> Self {
        Self {
            current: Some(FilteredStreamingBody::new(body, continuation)),
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
        let completion = match step_completion_from(continuation.into_completion()) {
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
        if let Some(extensions) = self.extensions.as_mut() {
            super::clear_selected_application(extensions);
        }
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
                    self.extensions = Some(super::strip_iteration_extensions(continuation.into_parent_extensions()));
                    self.state = Some(state);
                    return Err(format!(
                        "iterative_request_router: step '{}' selected streaming with interleaved transition phases",
                        self.current_step
                    )
                    .into());
                }
                match super::evaluate_header_transitions(self.transitions(), &outcome) {
                    super::TransitionResult::Next(next) => {
                        let mut skipped = FilteredStreamingBody::new(body, continuation);
                        if let Err(error) = skipped.suppress().await {
                            self.extensions = Some(super::strip_iteration_extensions(
                                skipped.into_continuation().into_parent_extensions(),
                            ));
                            self.state = Some(state);
                            return Err(error);
                        }
                        let mut completion = match step_completion_from(skipped.into_continuation().into_completion()) {
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
                        self.current = Some(FilteredStreamingBody::new(body, continuation));
                        self.current_outcome = Some(outcome);
                    },
                }
            },
            super::runner::OpenedStepKind::Complete(outcome) => {
                let completion = match step_completion_from(continuation.into_completion()) {
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
