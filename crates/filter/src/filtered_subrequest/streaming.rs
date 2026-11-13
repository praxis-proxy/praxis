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

/// Present only while a cancelled streaming sub-request runs its completion
/// body hooks. Their output is discarded, but earlier chunks or response
/// headers may already have been delivered. Filters that remember stream
/// delivery must ignore this synthetic completion pass while preserving any
/// delivery evidence recorded before suppression.
#[derive(Clone, Copy, Debug)]
pub struct StreamBodySuppressed;

/// The streaming callout's response exceeded its configured byte ceiling.
///
/// Callers can downcast a [`FilterError`] to this type to distinguish a body
/// limit from an upstream stream failure.
#[derive(Debug, thiserror::Error)]
#[error("filtered_subrequest: streaming response exceeds configured body limit ({limit} bytes)")]
pub struct CalloutResponseTooLarge {
    /// Configured cumulative response byte ceiling.
    pub limit: usize,
}

/// One logical callback output, paired with its own independent byte charges.
struct PendingOutput {
    /// Remaining bytes of this logical output chunk.
    body: Bytes,
    /// Unsent bytes remain prepared rather than committed.
    #[cfg(feature = "bandwidth")]
    plan: Option<crate::PaceReservation>,
}

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
    pending_chunks: VecDeque<PendingOutput>,
    /// Callout admission ceiling checked before waiting on any logical output.
    remaining_limit: Option<(usize, usize)>,
    /// Transport byte ceiling that ended this stream, when it overflowed.
    transport_overflow_limit: Option<usize>,
    /// A cancelled release must not let a later pull skip missing output.
    release_in_progress: bool,
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
            remaining_limit: None,
            transport_overflow_limit: None,
            release_in_progress: false,
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
                executed_branch_filters: Vec::new(),
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
                hedge_policy: None,
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
    fn filter_upstream_chunk(&mut self, chunk: Bytes) -> Result<Option<Bytes>, FilterError> {
        let mut body = Some(chunk);
        self.run_step_body_filters(&mut body, false)?;
        Ok(body)
    }

    /// Collect emitted and callback bytes without confusing their independent charges.
    fn enqueue_filtered(&mut self, body: Option<Bytes>) {
        let emitted = self
            .continuation
            .extensions
            .get_mut::<PendingStreamChunks>()
            .map_or_else(VecDeque::new, PendingStreamChunks::drain_chunks);
        for body in emitted {
            #[cfg(feature = "bandwidth")]
            let plan = crate::bandwidth::generated_download_plan(
                &self.continuation.extensions,
                u64::try_from(body.len()).unwrap_or(u64::MAX),
            );
            self.pending_chunks.push_back(PendingOutput {
                body,
                #[cfg(feature = "bandwidth")]
                plan,
            });
        }
        if let Some(body) = body.filter(|body| !body.is_empty()) {
            #[cfg(feature = "bandwidth")]
            let plan = crate::bandwidth::take_download(&mut self.continuation.extensions);
            self.pending_chunks.push_back(PendingOutput {
                body,
                #[cfg(feature = "bandwidth")]
                plan,
            });
        } else {
            crate::cancel_download_pace(&mut self.continuation.extensions);
        }
    }

    /// Admit the complete logical output before a wait can consume its allowance.
    fn check_output_limit(&mut self, bytes: usize) -> Result<(), FilterError> {
        if let Some((_, limit)) = self.remaining_limit.filter(|(remaining, _)| bytes > *remaining) {
            crate::cancel_download_pace(&mut self.continuation.extensions);
            return Err(Box::new(CalloutResponseTooLarge { limit }));
        }
        Ok(())
    }

    /// Keep queued bytes and the active permit on the future so cancellation refunds them.
    #[cfg_attr(
        not(feature = "bandwidth"),
        expect(clippy::unused_async, reason = "only bandwidth admission waits")
    )]
    async fn release_pending(&mut self) -> Result<Option<Bytes>, FilterError> {
        let mut pending = std::mem::take(&mut self.pending_chunks);
        let Some(output) = pending.pop_front() else {
            return Ok(None);
        };
        self.check_output_limit(output.body.len())?;
        #[cfg(feature = "bandwidth")]
        let mut output = output;
        #[cfg(feature = "bandwidth")]
        if let Some(plan) = output.plan.as_mut() {
            self.release_in_progress = true;
            let admitted = plan
                .acquire_prefix(output.body.len(), Some(self.continuation.step_deadline))
                .await;
            self.release_in_progress = false;
            let (bytes, permit) = admitted?;
            let prefix = output.body.split_to(bytes);
            permit.commit_bytes(bytes);
            if !output.body.is_empty() {
                pending.push_front(output);
            }
            self.pending_chunks = pending;
            return Ok(Some(prefix));
        }
        self.pending_chunks = pending;
        Ok(Some(output.body))
    }

    /// Pace completion only after the outer callout ceiling has accepted all its output.
    #[cfg_attr(
        not(feature = "bandwidth"),
        expect(clippy::unused_async, reason = "only bandwidth admission waits")
    )]
    async fn release_completion(&mut self, body: Option<Bytes>) -> Result<Option<Bytes>, FilterError> {
        let emitted = self
            .continuation
            .extensions
            .get_mut::<PendingStreamChunks>()
            .map(PendingStreamChunks::take_pending);
        let emitted_len = emitted.as_ref().map_or(0, PendingStreamChunks::len_bytes);
        let total = emitted_len.saturating_add(body.as_ref().map_or(0, Bytes::len));
        self.check_output_limit(total)?;
        #[cfg(feature = "bandwidth")]
        {
            let plan = crate::bandwidth::generated_download_plan(
                &self.continuation.extensions,
                u64::try_from(emitted_len).unwrap_or(u64::MAX),
            );
            self.release_in_progress = true;
            let result = async {
                super::pace::finish_plan(plan, self.continuation.step_deadline).await?;
                super::pace::pace_download(&mut self.continuation.extensions, self.continuation.step_deadline).await
            }
            .await;
            self.release_in_progress = false;
            result?;
        }
        if let Some(emitted) = emitted {
            self.continuation.extensions.insert(emitted);
        }
        Ok(body.filter(|bytes| !bytes.is_empty()))
    }

    /// Release a normal callback incrementally, retaining completion output for its caller.
    async fn release_filtered(&mut self, body: Option<Bytes>) -> Result<Option<Bytes>, FilterError> {
        if self.finished {
            self.deferred_completion_output = self.release_completion(body).await?;
            return Ok(None);
        }
        self.enqueue_filtered(body);
        Box::pin(self.release_pending()).await
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
        crate::cancel_download_pace(&mut self.continuation.extensions);
        let completion = self.complete_step().map_err(|completion_error| -> FilterError {
            format!(
                "filtered_subrequest: response filter failed ({error}); completion also failed ({completion_error})"
            )
            .into()
        })?;
        self.finished = true;
        self.deferred_completion_output = Box::pin(self.paced_completion(completion)).await?;
        Ok(None)
    }

    /// Handle an upstream error.
    async fn handle_upstream_error(
        &mut self,
        e: praxis_core::subrequest::SubRequestError,
    ) -> Result<Option<Bytes>, FilterError> {
        if let praxis_core::subrequest::SubRequestError::ResponseTooLarge { limit, .. } = &e {
            self.transport_overflow_limit = Some(*limit);
        }
        if let Some(upstream_body) = self.upstream.take() {
            (*upstream_body).cancel().await;
        }
        self.continuation
            .extensions
            .insert(StreamTermination::new(termination_cause(&e)));
        let completion = self.complete_step()?;
        self.finished = true;
        self.deferred_completion_output = Box::pin(self.paced_completion(completion)).await?;
        Ok(None)
    }

    /// Wait for a completion chunk that will be released, or refund one that will not.
    async fn paced_completion(&mut self, completion: Option<Bytes>) -> Result<Option<Bytes>, FilterError> {
        let output = self.handled_completion_output(completion);
        let handled = self
            .continuation
            .extensions
            .get::<StreamTermination>()
            .is_some_and(StreamTermination::is_handled);
        if handled {
            self.release_completion(output).await
        } else {
            crate::cancel_download_pace(&mut self.continuation.extensions);
            Ok(None)
        }
    }

    /// Read the next upstream chunk, preserving its transport error.
    async fn read_upstream_chunk(
        &mut self,
    ) -> Result<Result<Option<Bytes>, praxis_core::subrequest::SubRequestError>, FilterError> {
        let upstream = self
            .upstream
            .as_mut()
            .ok_or_else(|| -> FilterError { "filtered_subrequest: upstream already consumed".to_owned().into() })?;
        // Let SubResponseBody observe the absolute step deadline itself.
        // An outer timeout here drops its future before the body can run
        // its timeout cleanup and record DeadlineExceeded on the CLIENT
        // span. The body also enforces its own read/idle limits, so this
        // cap is the single authoritative bound for the next read.
        upstream.cap_stream_deadline(std_instant_to_tokio(self.continuation.step_deadline));
        Ok(upstream.next_chunk().await)
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

    /// Pull until a body filter produces output or the upstream finishes.
    async fn pull_filtered(&mut self) -> Result<Option<Bytes>, FilterError> {
        loop {
            let next = Box::pin(self.read_upstream_chunk()).await?;

            let body = match next {
                Ok(Some(chunk)) => match self.filter_upstream_chunk(chunk) {
                    Ok(bytes) => bytes,
                    Err(error) => return Box::pin(self.handle_filter_error(error)).await,
                },
                Ok(None) => {
                    self.finished = true;
                    match self.complete_step() {
                        Ok(completion) => completion,
                        Err(error) => {
                            crate::cancel_download_pace(&mut self.continuation.extensions);
                            return Err(error);
                        },
                    }
                },
                Err(e) => return Box::pin(self.handle_upstream_error(e)).await,
            };
            let output = Box::pin(self.release_filtered(body)).await?;
            if output.is_some() || self.finished {
                return Ok(output);
            }
        }
    }
}

#[async_trait]
impl StreamingResponseBody for FilteredStreamingBody {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
        if self.release_in_progress {
            self.cancel().await;
            return Err("filtered_subrequest: output release was cancelled".into());
        }
        if !self.pending_chunks.is_empty() {
            return Box::pin(self.release_pending()).await;
        }
        if self.finished {
            return Ok(None);
        }
        self.pull_filtered().await
    }

    async fn suppress(&mut self) -> Result<(), FilterError> {
        if !self.finished {
            self.finished = true;
            if let Some(upstream_body) = self.upstream.take() {
                (*upstream_body).cancel().await;
            }
            self.continuation.extensions.insert(StreamBodySuppressed);
            let completion = self.complete_step();
            crate::cancel_download_pace(&mut self.continuation.extensions);
            let _ = self.continuation.extensions.remove::<StreamBodySuppressed>();
            completion?;
        }
        Ok(())
    }

    async fn cancel(&mut self) {
        self.release_in_progress = false;
        self.pending_chunks.clear();
        self.deferred_completion_output = None;
        self.continuation.extensions.remove::<PendingStreamChunks>();
        crate::cancel_bandwidth(&mut self.continuation.extensions);
        self.finished = true;
        if let Some(upstream_body) = self.upstream.take() {
            (*upstream_body).cancel().await;
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

/// Take the absolute stream deadline requested by the current body-filter pass.
fn leftover_stream_deadline(ctx: &mut crate::filter::HttpFilterContext<'_>) -> Option<std::time::Instant> {
    ctx.take_stream_deadline_cap()
}

/// Convert the filter context's standard monotonic instant to Tokio's instant
/// without sampling either clock.
///
/// Tokio's direct conversion preserves the supplied absolute cutoff, including
/// when Tokio's clock is paused in a test.
fn std_instant_to_tokio(deadline: std::time::Instant) -> tokio::time::Instant {
    tokio::time::Instant::from_std(deadline)
}

/// Apply an absolute stream deadline to the live response body.
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

    /// Set the remaining ceiling before the inner body can pace or emit bytes.
    async fn next_bounded_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
        let result = {
            let inner = self
                .inner
                .as_mut()
                .ok_or_else(|| -> FilterError { "filtered_subrequest: streaming body has no active source".into() })?;
            inner.remaining_limit = Some((
                self.max_response_bytes.saturating_sub(self.emitted_bytes),
                self.max_response_bytes,
            ));
            inner.next_chunk().await
        };
        if result.is_err() {
            self.finished = true;
        }
        result
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
            .ok_or_else(|| -> FilterError {
                Box::new(CalloutResponseTooLarge {
                    limit: self.max_response_bytes,
                })
            })?;
        if total > self.max_response_bytes {
            return Err(Box::new(CalloutResponseTooLarge {
                limit: self.max_response_bytes,
            }));
        }
        self.emitted_bytes = total;
        Ok(Some(chunk))
    }

    /// Consume the inner body at EOF, queueing completion output or recording an
    /// unhandled termination to surface after buffered chunks drain.
    fn drain_completion(&mut self) -> Result<(), FilterError> {
        let transport_overflow_limit = self.inner.as_ref().and_then(|inner| inner.transport_overflow_limit);
        let (continuation, completion_output) = self
            .inner
            .take()
            .ok_or_else(|| -> FilterError { "filtered_subrequest: streaming body already consumed".into() })?
            .into_finished_parts();
        let completion = continuation.into_completion();
        self.held_extensions = Some(completion.extensions);
        if let Some(termination) = completion.termination.as_ref().filter(|t| !t.is_handled()) {
            let cause = termination.cause();
            self.deferred_error = Some(match transport_overflow_limit {
                Some(limit) if cause == StreamTerminationCause::ResponseTooLarge => {
                    Box::new(CalloutResponseTooLarge { limit })
                },
                _ => format!("filtered_subrequest: unhandled upstream stream termination: {cause:?}").into(),
            });
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
            let chunk = self.next_bounded_chunk().await?;
            match chunk {
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

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::unwrap_used,
    reason = "streaming deadline integration setup"
)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        sync::Arc,
        time::{Duration, Instant},
    };

    use async_trait::async_trait;
    use bytes::Bytes;
    use http::HeaderMap;
    use praxis_core::subrequest::{StreamLimits, SubRequest, SubRequestClient, SubRequestError};

    use super::{CalloutResponseTooLarge, CalloutStreamingBody, FilteredStreamingBody, std_instant_to_tokio};

    #[cfg(feature = "bandwidth")]
    #[tokio::test]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "into_continuation consumes the body and drops its upstream before the final assertions"
    )]
    async fn cancelling_a_pacing_wait_neither_leaks_output_nor_holds_budget() {
        let (addr, resume, backend) = spawn_continuing_backend().await;
        praxis_tls::provider::install();
        let client = SubRequestClient::new(praxis_core::subrequest::SubRequestConnector::new(1, None));
        let request = SubRequest {
            method: http::Method::GET,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
        };
        let response = Box::pin(client.send_streaming(
            &praxis_core::egress::PeerSpec::plain(addr),
            &request,
            Duration::from_secs(5),
            StreamLimits {
                idle_timeout: Duration::from_secs(30),
                max_stream_duration: None,
                max_total_bytes: None,
            },
            None,
        ))
        .await
        .unwrap();
        let snapshot = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&snapshot);
        ctx.response_body_mode = crate::BodyMode::Stream;
        ctx.extensions.insert(crate::context::PendingStreamChunks::new(100));
        ctx.emit_stream_chunk(Bytes::from_static(b"one")).unwrap();
        ctx.emit_stream_chunk(Bytes::from_static(b"two")).unwrap();
        let schedule = crate::bandwidth::Schedule::new(1, 0);
        crate::bandwidth::push_download_schedule(&mut ctx.extensions, Arc::clone(&schedule));
        crate::bandwidth::push_download(&mut ctx.extensions, schedule.prepare(1000));
        let continuation = super::super::continuation::FilteredSubrequestContinuation::capture(
            Arc::new(crate::FilterPipeline::from_filters(vec![])),
            snapshot.clone(),
            crate::Response {
                headers: HeaderMap::new(),
                status: http::StatusCode::OK,
            },
            &mut ctx,
            false,
            Instant::now() + Duration::from_secs(2000),
        );
        drop(ctx);
        let mut body = FilteredStreamingBody::new(Box::new(response.body), continuation);
        let cancelled = tokio::time::timeout(
            Duration::from_millis(50),
            crate::StreamingResponseBody::next_chunk(&mut body),
        )
        .await;
        assert!(cancelled.is_err(), "the body must still be waiting for its reservation");
        resume.send(()).unwrap();
        backend.await.unwrap();
        let resumed = tokio::time::timeout(
            Duration::from_millis(50),
            crate::StreamingResponseBody::next_chunk(&mut body),
        )
        .await;
        let error = resumed
            .expect("an abandoned release must fail immediately")
            .unwrap_err();
        assert!(error.to_string().contains("output release was cancelled"));
        let next = schedule.reserve(1000);
        assert!(
            next.delay() <= Duration::from_secs(1000),
            "cancelling a wait must immediately refund its bytes"
        );
        drop(next);
        crate::StreamingResponseBody::cancel(&mut body).await;
        let completion = body.into_continuation().into_completion();
        assert!(
            completion.pending_chunks.is_empty(),
            "cancelled output must not escape through the continuation"
        );
        drop(completion);
    }


    #[cfg(feature = "bandwidth")]
    fn paced_output(
        rate: u64,
        burst: u64,
        emitted: usize,
        callback: usize,
    ) -> (FilteredStreamingBody, Arc<crate::bandwidth::Schedule>) {
        let snapshot = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&snapshot);
        let schedule = crate::bandwidth::Schedule::new(rate, burst);
        crate::bandwidth::push_download_schedule(&mut ctx.extensions, Arc::clone(&schedule));
        ctx.enable_stream_chunk_emission(10000);
        if emitted != 0 {
            ctx.emit_stream_chunk(Bytes::from(vec![b'e'; emitted])).unwrap();
        }
        if callback != 0 {
            crate::bandwidth::push_download(&mut ctx.extensions, schedule.prepare(u64::try_from(callback).unwrap()));
        }
        let continuation = super::super::continuation::FilteredSubrequestContinuation::capture(
            Arc::new(crate::FilterPipeline::from_filters(vec![])),
            snapshot.clone(),
            crate::Response {
                headers: HeaderMap::new(),
                status: http::StatusCode::OK,
            },
            &mut ctx,
            false,
            Instant::now() + Duration::from_secs(1),
        );
        let mut body = FilteredStreamingBody {
            upstream: None,
            continuation,
            finished: false,
            deferred_completion_output: None,
            pending_chunks: VecDeque::new(),
            remaining_limit: None,
            transport_overflow_limit: None,
            release_in_progress: false,
        };
        body.enqueue_filtered((callback != 0).then(|| Bytes::from(vec![b'b'; callback])));
        (body, schedule)
    }

    #[cfg(feature = "bandwidth")]
    #[tokio::test]
    async fn abandoned_callback_release_fails_before_later_output() {
        let (inner, schedule) = paced_output(1, 0, 0, 100);
        let mut body = CalloutStreamingBody::new(inner, 10_000);
        tokio::time::timeout(
            Duration::from_millis(10),
            crate::StreamingResponseBody::next_chunk(&mut body),
        )
        .await
        .expect_err("cancel the pending output before admission completes");
        body.inner
            .as_mut()
            .unwrap()
            .enqueue_filtered(Some(Bytes::from_static(b"later")));
        let error = crate::StreamingResponseBody::next_chunk(&mut body).await.unwrap_err();
        assert!(error.to_string().contains("output release was cancelled"));
        assert!(
            crate::StreamingResponseBody::next_chunk(&mut body)
                .await
                .unwrap()
                .is_none()
        );
        assert!(body.inner.as_ref().unwrap().pending_chunks.is_empty());
        assert!(!body.inner.as_ref().unwrap().release_in_progress);
        let delay = schedule.reserve(1).delay();
        drop(body);
        assert!(delay <= Duration::from_secs(1));
    }

    #[cfg(feature = "bandwidth")]
    #[tokio::test]
    async fn abandoned_completion_release_errors_instead_of_clean_eof() {
        for emitted in [false, true] {
            let (mut inner, schedule) = paced_output(1, 0, 0, 100);
            inner.pending_chunks.clear();
            crate::bandwidth::push_download(&mut inner.continuation.extensions, schedule.prepare(100));
            if emitted {
                let snapshot = crate::test_utils::make_request(http::Method::GET, "/");
                let mut ctx = crate::test_utils::make_filter_context(&snapshot);
                ctx.enable_stream_chunk_emission(100);
                ctx.emit_stream_chunk(Bytes::from_static(b"emitted completion"))
                    .unwrap();
                inner
                    .continuation
                    .extensions
                    .insert(ctx.extensions.remove::<crate::context::PendingStreamChunks>().unwrap());
            }
            inner.finished = true;
            inner.continuation.completed = true;
            tokio::time::timeout(
                Duration::from_millis(10),
                inner.release_filtered(Some(Bytes::from_static(b"completion"))),
            )
            .await
            .expect_err("cancel each completion wait before it can release output");
            let mut body = CalloutStreamingBody::new(inner, 10_000);
            let error = crate::StreamingResponseBody::next_chunk(&mut body).await.unwrap_err();
            assert!(error.to_string().contains("output release was cancelled"));
            assert!(
                crate::StreamingResponseBody::next_chunk(&mut body)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(body.inner.as_ref().unwrap().deferred_completion_output.is_none());
            let delay = schedule.reserve(1).delay();
            drop(body);
            assert!(delay <= Duration::from_secs(1));
        }
    }

    #[cfg(feature = "bandwidth")]
    #[tokio::test]
    async fn returned_pacing_error_clears_the_release_marker() {
        let (mut body, schedule) = paced_output(1, 0, 0, 100);
        body.continuation.step_deadline = Instant::now();
        body.release_pending().await.unwrap_err();
        assert!(!body.release_in_progress);
        crate::bandwidth::push_download(&mut body.continuation.extensions, schedule.prepare(3));
        body.release_completion(Some(Bytes::from_static(b"end")))
            .await
            .unwrap_err();
        assert!(!body.release_in_progress);
    }

    #[cfg(feature = "bandwidth")]
    #[tokio::test]
    async fn emitted_output_is_paced_independently_of_the_callback_body() {
        for callback in [0, 100] {
            let (mut body, _schedule) = paced_output(1000, 0, 100, callback);
            let started = Instant::now();
            let mut bytes = Vec::new();
            while !body.pending_chunks.is_empty() {
                bytes.extend_from_slice(&body.release_pending().await.unwrap().unwrap());
            }
            assert_eq!(bytes.len(), 100 + callback);
            assert!(
                started.elapsed() >= Duration::from_millis(u64::try_from(90 + callback).unwrap()),
                "emitted bytes and the callback body each consume shared allowance"
            );
            assert!(bytes.starts_with(&[b'e'; 100]));
        }
    }

    #[cfg(feature = "bandwidth")]
    #[tokio::test]
    async fn oversized_callout_output_fails_before_pacing_and_preserves_the_shared_burst() {
        let (mut body, schedule) = paced_output(1, 100, 0, 200);
        body.remaining_limit = Some((50, 50));
        let started = Instant::now();
        let error = body.release_pending().await.unwrap_err();
        assert_eq!(error.downcast_ref::<CalloutResponseTooLarge>().unwrap().limit, 50);
        assert!(started.elapsed() < Duration::from_millis(50));
        assert!(
            schedule.prepare(100).delay().is_zero(),
            "unreleased output cannot consume the burst"
        );
    }

    #[cfg(feature = "bandwidth")]
    #[tokio::test]
    async fn oversized_emitted_output_reports_the_configured_limit_before_a_bandwidth_deadline() {
        let (mut body, _schedule) = paced_output(1, 0, 100, 0);
        body.remaining_limit = Some((10, 50));
        let error = body.release_pending().await.unwrap_err();
        assert_eq!(error.downcast_ref::<CalloutResponseTooLarge>().unwrap().limit, 50);
    }

    #[test]
    fn streaming_callout_limit_error_is_typed_and_terminal() {
        let mut body = CalloutStreamingBody {
            inner: None,
            pending: VecDeque::new(),
            held_extensions: None,
            deferred_error: None,
            emitted_bytes: 0,
            max_response_bytes: 4,
            finished: false,
        };

        body.checked(Bytes::from_static(b"1234"))
            .expect("the first four bytes fit the ceiling");
        let error = body
            .checked(Bytes::from_static(b"5"))
            .expect_err("the fifth byte exceeds the ceiling");
        assert_eq!(
            error.downcast_ref::<CalloutResponseTooLarge>().map(|e| e.limit),
            Some(4)
        );
        assert!(body.finished, "the rejected chunk must terminate the stream");
        drop(body);
    }

    struct ExpiredDeadlineFilter;

    #[async_trait]
    impl crate::HttpFilter for ExpiredDeadlineFilter {
        fn name(&self) -> &'static str {
            "expired_deadline_test_filter"
        }

        async fn on_request(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
        ) -> Result<crate::FilterAction, crate::FilterError> {
            Ok(crate::FilterAction::Continue)
        }

        fn response_body_access(&self) -> crate::BodyAccess {
            crate::BodyAccess::ReadOnly(crate::BodyRequirement::Optional)
        }

        fn on_response_body(
            &self,
            ctx: &mut crate::HttpFilterContext<'_>,
            _body: &mut Option<Bytes>,
            _end_of_stream: bool,
        ) -> Result<crate::FilterAction, crate::FilterError> {
            ctx.cap_stream_deadline(Instant::now() - Duration::from_secs(1));
            Ok(crate::FilterAction::Continue)
        }
    }

    async fn spawn_stalling_backend() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use tokio::io::AsyncWriteExt as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            drop(tokio::io::AsyncReadExt::read(&mut socket, &mut request).await);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
                .await
                .unwrap();
            socket.flush().await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        (addr, handle)
    }

    #[cfg(feature = "bandwidth")]
    async fn spawn_continuing_backend() -> (
        std::net::SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        use tokio::io::AsyncWriteExt as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (resume, resumed) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            drop(tokio::io::AsyncReadExt::read(&mut socket, &mut request).await);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
                .await
                .unwrap();
            resumed.await.unwrap();
            socket.write_all(b"5\r\nlater\r\n0\r\n\r\n").await.unwrap();
        });
        (addr, resume, handle)
    }

    #[tokio::test]
    async fn body_filter_deadline_is_applied_to_live_body() {
        use praxis_core::egress::PeerSpec;

        let (addr, backend) = spawn_stalling_backend().await;
        praxis_tls::provider::install();
        let connector = praxis_core::subrequest::SubRequestConnector::new(1, None);
        let client = SubRequestClient::new(connector);
        let peer = PeerSpec::plain(addr);
        let request = SubRequest {
            method: http::Method::GET,
            uri: http::Uri::from_static("/deadline-wire"),
            headers: HeaderMap::new(),
            body: Bytes::new(),
        };
        let response = Box::pin(client.send_streaming(
            &peer,
            &request,
            Duration::from_secs(5),
            StreamLimits {
                idle_timeout: Duration::from_secs(30),
                max_stream_duration: None,
                max_total_bytes: None,
            },
            None,
        ))
        .await
        .unwrap();

        let mut registry = crate::FilterRegistry::with_builtins();
        registry
            .register(
                "expired_deadline_test_filter",
                crate::FilterFactory::Http(Arc::new(|_| Ok(Box::new(ExpiredDeadlineFilter)))),
            )
            .unwrap();
        let mut entries = vec![praxis_core::config::FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "expired_deadline_test_filter".into(),
            config: serde_yaml::Value::Null,
            name: None,
            response_conditions: vec![],
            failure_mode: praxis_core::config::FailureMode::default(),
        }];
        let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());
        let continuation = super::super::continuation::FilteredSubrequestContinuation {
            pipeline,
            request_snapshot: crate::Request {
                headers: HeaderMap::new(),
                method: http::Method::GET,
                uri: http::Uri::from_static("/deadline-wire"),
            },
            response_snapshot: crate::Response {
                headers: HeaderMap::new(),
                status: http::StatusCode::OK,
            },
            extensions: crate::RequestExtensions::default(),
            filter_state: HashMap::new(),
            filter_results: HashMap::new(),
            filter_metadata: HashMap::new(),
            structured_metadata: HashMap::new(),
            executed_filter_indices: vec![true],
            body_done_indices: vec![false],
            response_body_bytes: 0,
            response_body_mode: crate::BodyMode::Stream,
            completed: false,
            client_addr: None,
            downstream_tls: false,
            request_start: Instant::now(),
            step_deadline: Instant::now() + Duration::from_secs(30),
            peer_identity: None,
        };
        let mut filtered = FilteredStreamingBody::new(Box::new(response.body), continuation);
        let mut body = Some(Bytes::from_static(b"first chunk"));

        filtered.run_step_body_filters(&mut body, false).unwrap();
        let err = filtered
            .upstream
            .as_mut()
            .expect("the live upstream body must remain attached")
            .next_chunk()
            .await
            .unwrap_err();
        drop(filtered);
        backend.abort();

        assert!(
            matches!(err, SubRequestError::DeadlineExceeded),
            "the body filter's expired absolute deadline must reach the live body: {err}"
        );
    }

    #[tokio::test]
    async fn step_deadline_is_observed_by_the_underlying_stream_body() {
        use praxis_core::egress::PeerSpec;

        let (addr, backend) = spawn_stalling_backend().await;
        praxis_tls::provider::install();
        let connector = praxis_core::subrequest::SubRequestConnector::new(1, None);
        let client = SubRequestClient::new(connector);
        let peer = PeerSpec::plain(addr);
        let request = SubRequest {
            method: http::Method::GET,
            uri: http::Uri::from_static("/step-deadline-wire"),
            headers: HeaderMap::new(),
            body: Bytes::new(),
        };
        let response = Box::pin(client.send_streaming(
            &peer,
            &request,
            Duration::from_secs(5),
            StreamLimits {
                idle_timeout: Duration::from_secs(30),
                max_stream_duration: None,
                max_total_bytes: None,
            },
            None,
        ))
        .await
        .unwrap();

        let registry = crate::FilterRegistry::with_builtins();
        let pipeline = Arc::new(crate::FilterPipeline::build(&mut [], &registry).unwrap());
        let step_deadline = Instant::now() + Duration::from_secs(5);
        let continuation = super::super::continuation::FilteredSubrequestContinuation {
            pipeline,
            request_snapshot: crate::Request {
                headers: HeaderMap::new(),
                method: http::Method::GET,
                uri: http::Uri::from_static("/step-deadline-wire"),
            },
            response_snapshot: crate::Response {
                headers: HeaderMap::new(),
                status: http::StatusCode::OK,
            },
            extensions: crate::RequestExtensions::default(),
            filter_state: HashMap::new(),
            filter_results: HashMap::new(),
            filter_metadata: HashMap::new(),
            structured_metadata: HashMap::new(),
            executed_filter_indices: Vec::new(),
            body_done_indices: Vec::new(),
            response_body_bytes: 0,
            response_body_mode: crate::BodyMode::Stream,
            completed: false,
            client_addr: None,
            downstream_tls: false,
            request_start: Instant::now(),
            step_deadline,
            peer_identity: None,
        };
        let mut filtered = FilteredStreamingBody::new(Box::new(response.body), continuation);
        assert_eq!(
            crate::actions::StreamingResponseBody::next_chunk(&mut filtered)
                .await
                .unwrap(),
            Some(Bytes::from_static(b"hello")),
            "the first chunk arrives before the step deadline"
        );
        filtered.continuation.step_deadline = Instant::now() + Duration::from_millis(150);
        assert_eq!(
            crate::actions::StreamingResponseBody::next_chunk(&mut filtered)
                .await
                .unwrap(),
            None,
            "deadline termination is handled by the streaming completion path"
        );
        assert!(filtered.finished, "the expired step must finish the stream");
        assert_eq!(
            filtered
                .continuation
                .extensions
                .get::<crate::StreamTermination>()
                .map(crate::StreamTermination::cause),
            Some(crate::StreamTerminationCause::DeadlineExceeded),
            "the inner SubResponseBody must report its own step deadline"
        );
        drop(filtered);
        backend.abort();
    }

    #[test]
    fn std_instant_to_tokio_preserves_a_future_deadline() {
        let deadline = Instant::now() + Duration::from_secs(1);
        let converted = std_instant_to_tokio(deadline);
        assert!(
            converted > tokio::time::Instant::now(),
            "a future standard deadline must remain in the future after conversion"
        );
        assert_eq!(
            converted.into_std(),
            deadline,
            "direct conversion must preserve the absolute deadline"
        );
    }

    #[test]
    fn std_instant_to_tokio_clamps_an_expired_deadline() {
        let deadline = Instant::now() - Duration::from_secs(1);
        let converted = std_instant_to_tokio(deadline);
        assert!(
            converted <= tokio::time::Instant::now(),
            "an expired standard deadline must not become a future Tokio deadline"
        );
        assert_eq!(
            converted.into_std(),
            deadline,
            "direct conversion must preserve an expired absolute deadline"
        );
    }
}
