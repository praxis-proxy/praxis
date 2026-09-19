// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Pull-based streaming body for a filtered sub-request's response.
//!
//! Pulls upstream chunks through the sub-request pipeline's response-body
//! filters, accumulates state in the owned [`FilteredSubrequestContinuation`],
//! and runs the completion lifecycle exactly once after upstream EOF.

use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use praxis_core::subrequest::SubResponseBody;
use tracing::warn;

use super::{continuation::FilteredSubrequestContinuation, transport::termination_cause};
use crate::{
    FilterError, StreamTermination, StreamTerminationCause, actions::StreamingResponseBody,
    context::PendingStreamChunks, extensions::RequestExtensions,
};

/// Streaming body implementation for a filtered sub-request's response.
pub(crate) struct FilteredStreamingBody {
    /// Upstream streaming body handle. `None` after cancellation.
    upstream: Option<Box<SubResponseBody>>,
    /// Owned state for running the sub-request's response-body filters.
    continuation: FilteredSubrequestContinuation,
    /// Whether the stream has finished (EOF or error).
    finished: bool,
    /// Completion-hook body output held until the caller selects a transition.
    deferred_completion_output: Option<Bytes>,
    /// Per-callback local output waiting to be pulled downstream.
    pending_chunks: VecDeque<Bytes>,
}

impl FilteredStreamingBody {
    /// Create a new streaming body for a sub-request's response.
    pub(crate) fn new(upstream: Box<SubResponseBody>, continuation: FilteredSubrequestContinuation) -> Self {
        Self {
            upstream: Some(upstream),
            continuation,
            finished: false,
            deferred_completion_output: None,
            pending_chunks: VecDeque::new(),
        }
    }

    /// Consume the body wrapper after EOF and recover its owned step state.
    pub(crate) fn into_continuation(self) -> FilteredSubrequestContinuation {
        self.continuation
    }

    /// Consume a finished body into its continuation and deferred output.
    pub(crate) fn into_finished_parts(self) -> (FilteredSubrequestContinuation, Option<Bytes>) {
        (self.continuation, self.deferred_completion_output)
    }

    /// Exchange extensions with the outer protocol lifecycle.
    fn exchange_extensions(&mut self, extensions: &mut RequestExtensions) {
        std::mem::swap(&mut self.continuation.extensions, extensions);
    }

    /// Run the sub-request's response-body filters on a single chunk.
    #[expect(clippy::too_many_lines, reason = "context reconstruction requires many fields")]
    fn run_step_body_filters(&mut self, body: &mut Option<Bytes>, end_of_stream: bool) -> Result<(), FilterError> {
        let remaining_read_timeout;
        let stream_deadline;
        let result = {
            let cont = &mut self.continuation;
            let mut ctx = crate::filter::HttpFilterContext {
                grpc_completion: None,
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
                prior_pre_read_mutations: Vec::new(),
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
                upstream_reached: false,
                rewritten_path: None,
                selected_endpoint_index: None,
                attempted_endpoints: Vec::new(),
                retry_policy: None,
                route_retry_policy: None,
                cluster_retry_state: None,
                cluster_retry_state_released: false,
                endpoint_reselector: None,
                pinned_endpoint_address: None,
                session_stores: cont.pipeline.session_stores(),
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

            remaining_read_timeout = leftover_stream_read_timeout(&mut ctx);
            stream_deadline = leftover_stream_deadline(&mut ctx);

            cont.body_done_indices = ctx.body_done_indices;
            cont.executed_filter_indices = ctx.executed_filter_indices;
            cont.extensions = ctx.extensions;
            cont.filter_metadata = ctx.filter_metadata;
            cont.filter_results = ctx.filter_results;
            cont.filter_state = ctx.filter_state;
            cont.response_body_bytes = ctx.response_body_bytes;
            cont.structured_metadata = ctx.structured_metadata;

            result
        };

        if let crate::actions::FilterAction::Reject(_) = result? {
            return Err("filtered_subrequest: step body filter rejected during stream"
                .to_owned()
                .into());
        }
        apply_leftover_read_timeout(&mut self.upstream, remaining_read_timeout);
        apply_leftover_stream_deadline(&mut self.upstream, stream_deadline);
        Ok(())
    }

    /// Run the sub-request's completion lifecycle exactly once.
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
        warn!("filtered_subrequest: response body filter failed: {error}");
        if let Some(upstream_body) = self.upstream.take() {
            (*upstream_body).cancel().await;
        }
        self.continuation
            .extensions
            .insert(StreamTermination::new(StreamTerminationCause::Filter));
        let completion = self.complete_step().map_err(|completion_error| -> FilterError {
            format!(
                "filtered_subrequest: response filter failed ({error}); completion also failed ({completion_error})"
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

#[async_trait]
impl StreamingResponseBody for FilteredStreamingBody {
    #[expect(clippy::too_many_lines, reason = "pull loop applies deadlines and completion state")]
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
        if let Some(chunk) = self.pending_chunks.pop_front() {
            return Ok(Some(chunk));
        }
        if self.finished {
            return Ok(None);
        }

        loop {
            let upstream = self
                .upstream
                .as_mut()
                .ok_or_else(|| -> FilterError { "filtered_subrequest: upstream already consumed".to_owned().into() })?;

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

/// Leftover per-read timeout from this body-filter pass.
///
/// Prefers [`crate::HttpFilterContext::cap_stream_read_timeout`], which recaps
/// the live body. A reconstructed `ctx.upstream` is only a fallback for
/// filters that still mutate the detached peer.
fn leftover_stream_read_timeout(ctx: &mut crate::filter::HttpFilterContext<'_>) -> Option<Duration> {
    ctx.take_stream_read_timeout_cap()
        .or_else(|| ctx.upstream.as_ref().and_then(|peer| peer.connection.read_timeout))
}

/// Copy leftover budget onto the live streaming body after body filters.
fn apply_leftover_read_timeout(body: &mut Option<Box<SubResponseBody>>, leftover: Option<Duration>) {
    if let Some(timeout) = leftover
        && let Some(upstream) = body.as_mut()
    {
        upstream.cap_read_timeout(timeout);
    }
}

fn leftover_stream_deadline(ctx: &mut crate::filter::HttpFilterContext<'_>) -> Option<std::time::Instant> {
    ctx.take_stream_deadline_cap()
}

fn std_instant_to_tokio(deadline: std::time::Instant) -> tokio::time::Instant {
    let now_std = std::time::Instant::now();
    let now_tokio = tokio::time::Instant::now();
    now_tokio + deadline.saturating_duration_since(now_std)
}

fn apply_leftover_stream_deadline(body: &mut Option<Box<SubResponseBody>>, deadline: Option<std::time::Instant>) {
    if let Some(deadline) = deadline
        && let Some(upstream) = body.as_mut()
    {
        upstream.cap_stream_deadline(std_instant_to_tokio(deadline));
    }
}

/// Single-round streaming body handed back to an application callout.
///
/// Wraps [`FilteredStreamingBody`] and closes the two gaps a bare wrapper would
/// leave for a caller that only pulls [`next_chunk`](StreamingResponseBody::next_chunk):
///
/// - At upstream EOF the inner body withholds its completion output (a terminal SSE event, a closing bracket) in favor
///   of `into_finished_parts`. This adapter drains and emits it before yielding the terminal `None`, so the chain's
///   last bytes are not silently dropped.
/// - An upstream termination the chain did not convert into a valid terminal sequence is surfaced as an error after
///   already-emitted chunks drain, rather than passing off a truncated stream as a clean end.
///
/// It also enforces the callout's response byte ceiling across emitted chunks.
/// This is the single-step analog of the iterative request router's
/// `IrrStreamingSession`; it has no transitions because a callout runs exactly
/// one bound chain.
pub(crate) struct CalloutStreamingBody {
    /// Active upstream-backed body; `None` once completion has been drained.
    inner: Option<FilteredStreamingBody>,
    /// Completion chunks queued ahead of the terminal `None`.
    pending: VecDeque<Bytes>,
    /// Extensions recovered after `inner` is consumed, for `swap_extensions`.
    held_extensions: Option<RequestExtensions>,
    /// Error surfaced after `pending` drains (unhandled termination).
    deferred_error: Option<FilterError>,
    /// Cumulative emitted bytes, checked against `max_response_bytes`.
    emitted_bytes: usize,
    /// Response byte ceiling for the logical stream.
    max_response_bytes: usize,
    /// Whether the terminal `None` has been reached.
    finished: bool,
}

impl CalloutStreamingBody {
    /// Wrap an opened streaming body with completion flushing and a byte ceiling.
    pub(crate) fn new(inner: FilteredStreamingBody, max_response_bytes: usize) -> Self {
        Self {
            inner: Some(inner),
            pending: VecDeque::new(),
            held_extensions: None,
            deferred_error: None,
            emitted_bytes: 0,
            max_response_bytes,
            finished: false,
        }
    }

    /// Account one outgoing chunk against the response byte ceiling, ending the
    /// stream if it does not fit.
    ///
    /// A breach is *terminal*. The rejected chunk is never emitted, so
    /// `emitted_bytes` does not advance; without marking the stream finished a
    /// caller that polled again would resume around the hole and keep delivering
    /// later chunks against the stale count, handing the consumer a body with a
    /// gap in it instead of an error-terminated stream. Marking it finished and
    /// dropping queued chunks makes the next poll report end-of-stream, matching
    /// the `deferred_error` arm of [`next_chunk`](CalloutStreamingBody::next_chunk).
    ///
    /// The inner body is deliberately left in place: tearing it down here would
    /// have to drop the upstream synchronously, whereas a subsequent
    /// [`cancel`](CalloutStreamingBody::cancel) or
    /// [`suppress`](CalloutStreamingBody::suppress) can still cancel it
    /// asynchronously and recover the parent extensions.
    fn checked(&mut self, chunk: Bytes) -> Result<Option<Bytes>, FilterError> {
        let outcome = self.account(chunk);
        if outcome.is_err() {
            self.finished = true;
            self.pending.clear();
        }
        outcome
    }

    /// Add `chunk` to the emitted-byte total, rejecting a counter overflow or a
    /// breach of the response ceiling.
    fn account(&mut self, chunk: Bytes) -> Result<Option<Bytes>, FilterError> {
        let total = self
            .emitted_bytes
            .checked_add(chunk.len())
            .ok_or_else(|| -> FilterError { "filtered_subrequest: stream byte count overflow".into() })?;
        if total > self.max_response_bytes {
            return Err("filtered_subrequest: streaming response exceeds configured body limit"
                .to_owned()
                .into());
        }
        self.emitted_bytes = total;
        Ok(Some(chunk))
    }

    /// Consume the inner body at EOF, queueing completion output or recording an
    /// unhandled termination to surface after buffered chunks drain.
    fn drain_completion(&mut self) -> Result<(), FilterError> {
        let (continuation, completion_output) = self
            .inner
            .take()
            .ok_or_else(|| -> FilterError { "filtered_subrequest: streaming body already consumed".into() })?
            .into_finished_parts();
        let completion = continuation.into_completion();
        self.held_extensions = Some(completion.extensions);
        if let Some(termination) = completion.termination.as_ref().filter(|t| !t.is_handled()) {
            let cause = termination.cause();
            self.deferred_error =
                Some(format!("filtered_subrequest: unhandled upstream stream termination: {cause:?}").into());
            return Ok(());
        }
        self.pending.extend(completion.pending_chunks);
        self.pending.extend(completion_output.filter(|bytes| !bytes.is_empty()));
        self.finished = true;
        Ok(())
    }
}

#[async_trait]
impl StreamingResponseBody for CalloutStreamingBody {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
        loop {
            if let Some(chunk) = self.pending.pop_front() {
                return self.checked(chunk);
            }
            if let Some(error) = self.deferred_error.take() {
                self.finished = true;
                self.inner = None;
                return Err(error);
            }
            if self.finished {
                return Ok(None);
            }
            let inner = self
                .inner
                .as_mut()
                .ok_or_else(|| -> FilterError { "filtered_subrequest: streaming body has no active source".into() })?;
            match inner.next_chunk().await? {
                Some(chunk) => return self.checked(chunk),
                None => self.drain_completion()?,
            }
        }
    }

    async fn suppress(&mut self) -> Result<(), FilterError> {
        self.pending.clear();
        self.deferred_error = None;
        // Recover the parent extensions before propagating any completion error:
        // the completion lifecycle writes them back into the continuation even
        // when a body filter rejects, so `held_extensions` must be populated on
        // every path out (matching `cancel` and `drain_completion`).
        let outcome = if let Some(mut inner) = self.inner.take() {
            let result = inner.suppress().await;
            self.held_extensions = Some(inner.into_continuation().into_parent_extensions());
            result
        } else {
            Ok(())
        };
        self.finished = true;
        outcome
    }

    async fn cancel(&mut self) {
        self.pending.clear();
        self.deferred_error = None;
        if let Some(mut inner) = self.inner.take() {
            inner.cancel().await;
            self.held_extensions = Some(inner.into_continuation().into_parent_extensions());
        }
        self.finished = true;
    }

    fn swap_extensions(&mut self, extensions: &mut RequestExtensions) {
        if let Some(inner) = self.inner.as_mut() {
            inner.swap_extensions(extensions);
        } else if let Some(held) = self.held_extensions.as_mut() {
            std::mem::swap(held, extensions);
        }
    }
}
