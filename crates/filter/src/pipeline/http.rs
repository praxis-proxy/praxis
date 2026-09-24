// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! HTTP pipeline execution: request, response, and body filter phases.
//!
//! Implements the three async execution loops on [`FilterPipeline`]:
//! request filters run forward with branch evaluation and index
//! tracking, response filters run in reverse over the subset that
//! executed during the request phase, and body filters stream chunks
//! through filters that declared non-`None` [`BodyAccess`].
//!
//! Delegates per-filter dispatch and metrics to [`http_utils`].
//!
//! [`FilterPipeline`]: super::FilterPipeline
//! [`BodyAccess`]: crate::body::BodyAccess
//! [`http_utils`]: super::http_utils

use std::pin::Pin;

use bytes::Bytes;
use tracing::{debug, trace, warn};

use super::{
    FilterPipeline,
    branch::{BranchOutcome, ResolvedBranch, branch_filter_executed},
    filter::PipelineFilter,
    http_utils::{
        BodyFilterOutcome, HeaderFilterOutcome, accumulate_body_bytes, as_request_body_filter, as_response_body_filter,
        released_or_continue, run_request_body_filter, run_request_filter, run_response_body_filter,
        run_response_filter, run_selected_upstream_request_body_filter, skip_by_response_conditions,
    },
};
use crate::{
    FilterError,
    actions::{FilterAction, Rejection, SelectedUpstreamBodyOutcome},
    any_filter::AnyFilter,
    condition::should_execute_bound_selected,
    context::{EffectiveHeaders, HttpFilterContext},
    trace_context::{TraceContext, ensure_trace_context},
};
#[cfg(feature = "bound-upstream-request-body")]
use crate::{actions::BoundUpstreamBodyOutcome, condition::SelectedUpstream, extensions::BoundRequestBodyRewrite};

// -----------------------------------------------------------------------------
// FilterPipeline HTTP
// -----------------------------------------------------------------------------

#[expect(
    clippy::multiple_inherent_impl,
    reason = "pipeline concerns are split across modules"
)]
impl FilterPipeline {
    /// Run all HTTP request filters in order.
    ///
    /// Tracks which filter indices actually executed so the
    /// response phase can skip filters that were bypassed
    /// (e.g. by `SkipTo`).
    ///
    /// A `terminal`/`client` branch rejoin whose sub-chain produced no
    /// response fails closed with a 500 rather than forwarding
    /// upstream.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if any filter fails.
    #[expect(clippy::indexing_slicing, reason = "while loop bounds idx")]
    #[expect(clippy::too_many_lines, reason = "filter identity tracking adds lines per branch")]
    pub async fn execute_http_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if self.enables_trace_propagation(ctx.request) {
            ensure_trace_context(ctx);
        }
        ctx.executed_filter_indices.clear();
        ctx.executed_filter_indices.resize(self.filters.len(), false);
        ctx.executed_branch_filters.clear();
        ctx.body_done_indices.clear();
        ctx.body_done_indices.resize(self.filters.len(), false);
        let mut idx = 0;
        while idx < self.filters.len() {
            let pf = &self.filters[idx];
            let http_filter = match &pf.filter {
                AnyFilter::Http(f) => f.as_ref(),
                AnyFilter::Tcp(_) => {
                    idx += 1;
                    continue;
                },
            };
            // Unconditioned filters skip the binding and selection lookups
            // entirely; this is the common hot path.
            if !pf.conditions.is_empty()
                && !should_execute_bound_selected(
                    &pf.conditions,
                    ctx.request,
                    ctx.bound_upstream_view(),
                    super::http_utils::ctx_selected_upstream(ctx),
                )
            {
                trace!(filter = http_filter.name(), "skipped by conditions");
                idx += 1;
                continue;
            }
            ctx.current_filter_id = Some(pf.filter_id);
            let outcome =
                run_request_filter(http_filter, ctx, pf.failure_mode, self.record_filter_duration_metrics).await;
            ctx.current_filter_id = None;
            match outcome? {
                HeaderFilterOutcome::Rejected(r) => {
                    ctx.executed_filter_indices[idx] = true;
                    return Ok(FilterAction::Reject(r));
                },
                HeaderFilterOutcome::TerminalResponse(terminal) => {
                    ctx.executed_filter_indices[idx] = true;
                    return Ok(FilterAction::TerminalResponse(terminal));
                },
                HeaderFilterOutcome::StreamingTerminalResponse(terminal) => {
                    ctx.executed_filter_indices[idx] = true;
                    return Ok(FilterAction::StreamingTerminalResponse(terminal));
                },
                HeaderFilterOutcome::Continue => {},
            }
            ctx.executed_filter_indices[idx] = true;
            // Freeze before this filter's branches run so they, every later
            // filter, and any ReEnter pass all see the one binding.
            #[cfg(feature = "upstream-binding")]
            if published_first_binding(http_filter, ctx) {
                ctx.freeze_bound_upstream();
                #[cfg(feature = "bound-upstream-request-body")]
                if let FilterAction::Reject(r) = self.run_bound_upstream_request_body(ctx).await? {
                    return Ok(FilterAction::Reject(r));
                }
            }
            match super::evaluate::evaluate_branches(&pf.branches, ctx).await? {
                BranchOutcome::Continue => idx += 1,
                BranchOutcome::Terminal => {
                    if ctx.cluster.is_some() {
                        // The branch set a cluster via `router` + `load_balancer`,
                        // so upstream forwarding is intended. Stop the pipeline
                        // and let the proxy forward to the selected cluster.
                        return Ok(FilterAction::Continue);
                    }
                    // A `terminal`/`client` rejoin whose sub-chain produced no
                    // response and selected no cluster. Fail closed with a 500
                    // rather than proxying upstream with the remaining filters
                    // (cors, csrf, auth, ...) skipped.
                    warn!(
                        filter = http_filter.name(),
                        "terminal branch produced no response and selected no cluster; \
                         stopping the pipeline with 500 instead of forwarding upstream"
                    );
                    return Ok(FilterAction::Reject(Rejection::status(500)));
                },
                BranchOutcome::SkipTo(t) => idx = t,
                BranchOutcome::ReEnter(t) => {
                    // Do not clear executed_filter_indices for the re-entered
                    // span: once a filter's on_request has run in any pass it
                    // must keep its on_response paired, and re-execution re-marks
                    // it idempotently. Clearing here dropped on_response for
                    // filters that ran on the first pass but were short-circuited
                    // (rejected, or skipped by conditions) on the second.
                    idx = t;
                },
                BranchOutcome::Reject(r) => return Ok(FilterAction::Reject(r)),
                BranchOutcome::TerminalResponse(t) => return Ok(FilterAction::TerminalResponse(t)),
                BranchOutcome::StreamingTerminalResponse(t) => {
                    return Ok(FilterAction::StreamingTerminalResponse(t));
                },
            }
        }
        Ok(FilterAction::Continue)
    }

    /// Run all HTTP response filters in reverse order.
    ///
    /// Skips filters that did not execute during the request
    /// phase (tracked by [`executed_filter_indices`]). Branch filters
    /// that ran `on_request` unwind in reverse just before their host
    /// filter.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if any filter fails.
    ///
    /// [`executed_filter_indices`]: HttpFilterContext::executed_filter_indices
    pub async fn execute_http_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        // Reset body-done tracking at the request -> response boundary. The
        // request-body and response-body loops share body_done_indices, so a
        // filter with both request- and response-body access that returned
        // BodyDone during the request-body phase would otherwise be skipped
        // in the response-body phase. This hook runs once before any response
        // body chunk, and its result is written back to the protocol cache.
        ctx.body_done_indices.clear();
        ctx.body_done_indices.resize(self.filters.len(), false);
        for (idx, pf) in self.filters.iter().enumerate().rev() {
            if ctx.executed_filter_indices.get(idx) == Some(&false) {
                trace!(
                    filter = pf.filter.name(),
                    "skipped on_response (not executed in request phase)"
                );
                continue;
            }
            // Any future precomputed list of response-hook filters must keep
            // every top-level host whose branch subtree holds a filter with a
            // real on_response, or this unwind silently disappears.
            if !pf.branches.is_empty()
                && let Some(rejection) = self.unwind_branches(&pf.branches, ctx).await?
            {
                return Ok(FilterAction::Reject(rejection));
            }
            if let Some(rejection) = self.run_response_hook(pf, ctx).await? {
                return Ok(FilterAction::Reject(rejection));
            }
        }
        Ok(FilterAction::Continue)
    }

    /// Run `on_response` for the filters of `branches` that ran `on_request`.
    ///
    /// Walks the branches, and each branch's filters, in reverse so the
    /// unwind mirrors request order; a filter's nested branches unwind
    /// just before the filter itself. Re-entrance does not repeat the
    /// hook: each branch filter runs `on_response` at most once per
    /// request, at its pipeline position, like a top-level filter.
    ///
    /// Returns the first rejection a hook produced, if any.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if a branch filter fails with a closed
    /// `failure_mode`.
    async fn unwind_branches(
        &self,
        branches: &[ResolvedBranch],
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<Option<Rejection>, FilterError> {
        for pf in branches.iter().rev().flat_map(|branch| branch.filters.iter().rev()) {
            if !branch_filter_executed(&ctx.executed_branch_filters, pf.filter_id) {
                trace!(
                    filter = pf.filter.name(),
                    "skipped branch on_response (not executed in request phase)"
                );
                continue;
            }
            if !pf.branches.is_empty()
                && let Some(rejection) = self.unwind_branches_boxed(&pf.branches, ctx).await?
            {
                return Ok(Some(rejection));
            }
            if let Some(rejection) = self.run_response_hook(pf, ctx).await? {
                return Ok(Some(rejection));
            }
        }
        Ok(None)
    }

    /// Boxed entry point breaking the async recursion cycle for nested
    /// branches (branches within branches).
    fn unwind_branches_boxed<'a>(
        &'a self,
        branches: &'a [ResolvedBranch],
        ctx: &'a mut HttpFilterContext<'_>,
    ) -> UnwindFuture<'a> {
        Box::pin(self.unwind_branches(branches, ctx))
    }

    /// Run one filter's `on_response`, honouring its response conditions
    /// and `failure_mode`.
    ///
    /// Returns the rejection the hook produced, if any.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the filter fails with a closed
    /// `failure_mode`.
    async fn run_response_hook(
        &self,
        pf: &PipelineFilter,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<Option<Rejection>, FilterError> {
        let AnyFilter::Http(http_filter) = &pf.filter else {
            return Ok(None);
        };
        if skip_by_response_conditions(http_filter.as_ref(), &pf.response_conditions, ctx) {
            return Ok(None);
        }
        ctx.current_filter_id = Some(pf.filter_id);
        let outcome = run_response_filter(
            http_filter.as_ref(),
            ctx,
            pf.failure_mode,
            self.record_filter_duration_metrics,
        )
        .await;
        ctx.current_filter_id = None;
        match outcome? {
            HeaderFilterOutcome::Continue
            | HeaderFilterOutcome::TerminalResponse(_)
            | HeaderFilterOutcome::StreamingTerminalResponse(_) => Ok(None),
            HeaderFilterOutcome::Rejected(rejection) => Ok(Some(rejection)),
        }
    }

    /// Run all HTTP request body filters in order.
    ///
    /// Filters that previously returned [`BodyDone`] are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if any body filter fails.
    ///
    /// [`BodyDone`]: FilterAction::BodyDone
    #[expect(clippy::too_many_lines, reason = "body hook loop with metrics dispatch")]
    pub async fn execute_http_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        ensure_body_done_indices(ctx, self.filters.len());
        accumulate_body_bytes(&mut ctx.request_body_bytes, body.as_ref());
        let request_phase_tracked = request_phase_tracked(ctx, self.filters.len());
        let mut released = false;
        // Walk only filters that declared request-body access; declared
        // access is a per-filter constant, so non-body filters cost
        // nothing per chunk.
        for &idx in &self.request_body_filter_indices {
            if !request_phase_tracked {
                self.ensure_matching_trace_context(ctx);
            }
            let Some(pf) = self.filters.get(idx) else {
                continue;
            };
            if ctx.body_done_indices.get(idx) == Some(&true) {
                trace!(filter = pf.filter.name(), "skipped body (body_done)");
                continue;
            }
            if skipped_in_request_phase(ctx, request_phase_tracked, idx) {
                trace!(
                    filter = pf.filter.name(),
                    "skipped request body (not executed in request phase)"
                );
                continue;
            }
            let Some(http_filter) = as_request_body_filter(pf, ctx, request_phase_tracked)? else {
                continue;
            };
            ctx.current_filter_id = Some(pf.filter_id);
            let outcome = run_request_body_filter(
                http_filter,
                ctx,
                body,
                end_of_stream,
                pf.failure_mode,
                self.record_filter_duration_metrics,
            )
            .await;
            ctx.current_filter_id = None;
            match outcome? {
                BodyFilterOutcome::Continue => {},
                BodyFilterOutcome::Released => released = true,
                BodyFilterOutcome::BodyDone => {
                    if let Some(done) = ctx.body_done_indices.get_mut(idx) {
                        *done = true;
                    }
                },
                BodyFilterOutcome::Rejected(r) => return Ok(FilterAction::Reject(r)),
            }
        }
        if !request_phase_tracked {
            self.ensure_matching_trace_context(ctx);
        }
        Ok(released_or_continue(released))
    }

    /// Initialize correlation when a trace filter matches the evolving pre-read headers.
    ///
    /// Only for a `StreamBuffer` pre-read, which runs before the request phase.
    /// Once the request phase has run, it decided whether `trace_context` ran,
    /// and re-matching against the rewritten request would start a context for
    /// a request whose trace filter was skipped.
    ///
    /// A header the pre-read filters left ambiguous counts as no match: early
    /// correlation is best-effort and must not fail the request.
    fn ensure_matching_trace_context(&self, ctx: &mut HttpFilterContext<'_>) {
        if ctx.extensions.get::<TraceContext>().is_some() {
            return;
        }
        match self.enables_trace_propagation_from(ctx.request, &EffectiveHeaders(ctx)) {
            Ok(true) => ensure_trace_context(ctx),
            Ok(false) => {},
            Err(error) => debug!(%error, "trace_context: pre-read headers are ambiguous; not starting early"),
        }
    }

    /// Run all selected-upstream request body filters in pipeline order.
    ///
    /// Runs after the request phase has selected an upstream cluster, over
    /// the fully buffered request body (`body`). Only filters that
    /// executed during the request phase participate: one that branch
    /// control flow skipped over (via `SkipTo` or a terminal branch) is
    /// skipped here too, mirroring the request- and response-body phases.
    /// Conditions are not re-evaluated; this phase reuses the request
    /// phase's [`executed_filter_indices`] gating. Short-circuits on the
    /// first [`SelectedUpstreamBodyOutcome::Reject`].
    ///
    /// Unlike [`execute_http_request_body`], `body` is a working value
    /// distinct from the pipeline's canonical request body: participants
    /// may rewrite it for the selected upstream without disturbing the
    /// buffered body the request phase produced.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if a selected-upstream body filter fails
    /// with a closed `failure_mode`.
    ///
    /// [`executed_filter_indices`]: HttpFilterContext::executed_filter_indices
    /// [`execute_http_request_body`]: FilterPipeline::execute_http_request_body
    /// [`SelectedUpstreamBodyOutcome::Reject`]: crate::SelectedUpstreamBodyOutcome::Reject
    #[expect(clippy::too_many_lines, reason = "body hook loop with per-filter skip checks")]
    pub async fn execute_http_selected_upstream_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<FilterAction, FilterError> {
        let request_phase_tracked = request_phase_tracked(ctx, self.filters.len());
        // Walk only filters that declared selected-upstream request-body
        // access; declared access is a per-filter constant, so other
        // filters cost nothing.
        for &idx in &self.selected_upstream_request_body_filter_indices {
            let Some(pf) = self.filters.get(idx) else {
                continue;
            };
            if skipped_in_request_phase(ctx, request_phase_tracked, idx) {
                trace!(
                    filter = pf.filter.name(),
                    "skipped selected-upstream request body (not executed in request phase)"
                );
                continue;
            }
            let AnyFilter::Http(http_filter) = &pf.filter else {
                continue;
            };
            ctx.current_filter_id = Some(pf.filter_id);
            let outcome = run_selected_upstream_request_body_filter(
                http_filter.as_ref(),
                ctx,
                body,
                pf.failure_mode,
                self.record_filter_duration_metrics,
            )
            .await;
            ctx.current_filter_id = None;
            match outcome? {
                SelectedUpstreamBodyOutcome::Continue => {},
                SelectedUpstreamBodyOutcome::Reject(rejection) => return Ok(FilterAction::Reject(rejection)),
            }
        }
        Ok(FilterAction::Continue)
    }

    /// Run the bound-upstream request-body participants once, right after the
    /// first binding froze.
    ///
    /// Called from [`execute_http_request`] after the binding filter's
    /// `on_request` and before its branch chains evaluate. The freeze doubles
    /// as the once-per-request marker, so a `ReEnter` pass or IRR continuation
    /// never reaches here again. A writer's output is size-checked and recorded
    /// as the body to forward.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if a participant fails with a closed
    /// `failure_mode`.
    ///
    /// [`execute_http_request`]: FilterPipeline::execute_http_request
    #[cfg(feature = "bound-upstream-request-body")]
    async fn run_bound_upstream_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        if self.bound_upstream_request_body_filter_indices.is_empty() {
            return Ok(FilterAction::Continue);
        }
        let (action, rewrote) = self.execute_http_bound_upstream_request_body(ctx).await?;
        if rewrote && matches!(action, FilterAction::Continue) {
            let rewritten = ctx.buffered_request_body.clone().unwrap_or_default();
            if rewritten.len() > self.selected_upstream_request_body_limit() {
                return Ok(FilterAction::Reject(Rejection::status(413)));
            }
            ctx.extensions.insert(BoundRequestBodyRewrite(rewritten));
        }
        Ok(action)
    }

    /// Drain the bound-upstream request-body participants over the buffered
    /// request body.
    ///
    /// Unlike [`execute_http_selected_upstream_request_body`], which the
    /// protocol layer drives over a caller-owned working body after upstream
    /// selection, this barrier runs inside the request phase and mutates
    /// [`buffered_request_body`] in place with a take/commit pattern: the body
    /// is moved out, threaded through each participant as a borrow distinct
    /// from `&mut ctx`, and committed back even when a participant rejects.
    /// Participants see `None` for an empty body, as the hook documents.
    ///
    /// Each participant is gated by its own request conditions against the
    /// frozen binding view rather than [`executed_filter_indices`], which is
    /// not yet set for participants ordered after the binding filter when the
    /// barrier fires. The returned flag is `true` when a read-write participant
    /// ran, so the caller records a rewrite only when one can exist.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if a participant fails with a closed
    /// `failure_mode`.
    ///
    /// [`buffered_request_body`]: HttpFilterContext::buffered_request_body
    /// [`executed_filter_indices`]: HttpFilterContext::executed_filter_indices
    /// [`execute_http_selected_upstream_request_body`]: FilterPipeline::execute_http_selected_upstream_request_body
    #[cfg(feature = "bound-upstream-request-body")]
    #[expect(
        clippy::too_many_lines,
        reason = "body hook loop with take/commit and per-filter skip checks"
    )]
    async fn execute_http_bound_upstream_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<(FilterAction, bool), FilterError> {
        let had_buffer = ctx.buffered_request_body.is_some();
        let mut body = ctx.buffered_request_body.take();
        let mut result = Ok(FilterAction::Continue);
        let mut rewrote = false;
        for &idx in &self.bound_upstream_request_body_filter_indices {
            let Some(pf) = self.filters.get(idx) else {
                continue;
            };
            // This barrier fires inside the request phase, before the load
            // balancer publishes an upstream selection, so any `selected_upstream`
            // predicate on a participant fails closed (`SelectedUpstream::none`).
            if !pf.conditions.is_empty()
                && !should_execute_bound_selected(
                    &pf.conditions,
                    ctx.request,
                    ctx.bound_upstream_view(),
                    SelectedUpstream::none(),
                )
            {
                trace!(
                    filter = pf.filter.name(),
                    "skipped bound-upstream request body (conditions)"
                );
                continue;
            }
            let AnyFilter::Http(http_filter) = &pf.filter else {
                continue;
            };
            ctx.current_filter_id = Some(pf.filter_id);
            body = body.filter(|bytes| !bytes.is_empty());
            let outcome = super::http_utils::run_bound_upstream_request_body_filter(
                http_filter.as_ref(),
                ctx,
                &mut body,
                pf.failure_mode,
                self.record_filter_duration_metrics,
            )
            .await;
            ctx.current_filter_id = None;
            match outcome {
                Ok((BoundUpstreamBodyOutcome::Continue, wrote)) => rewrote |= wrote,
                Ok((BoundUpstreamBodyOutcome::Reject(rejection), _)) => {
                    result = Ok(FilterAction::Reject(rejection));
                    break;
                },
                Err(e) => {
                    result = Err(e);
                    break;
                },
            }
        }
        // Later request filters (the IRR) expect a buffer whenever the
        // pre-read produced one, even if a participant removed the body.
        ctx.buffered_request_body = body.or_else(|| had_buffer.then(Bytes::new));
        result.map(|action| (action, rewrote))
    }

    /// Run all HTTP response body filters in reverse order.
    ///
    /// Filters that previously returned [`BodyDone`] are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if any body filter fails.
    ///
    /// [`BodyDone`]: FilterAction::BodyDone
    pub fn execute_http_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !self.body_capabilities.any_response_body_condition {
            return self.execute_http_response_body_with_response_header(ctx, body, end_of_stream, None);
        }
        // Temporarily move the exclusive header borrow out of the context
        // so a shared view can be passed alongside `&mut ctx` — no header
        // map clone per body chunk.
        let response_header = ctx.response_header.take();
        let result =
            self.execute_http_response_body_with_response_header(ctx, body, end_of_stream, response_header.as_deref());
        ctx.response_header = response_header;
        result
    }

    /// Run all HTTP response body filters in reverse order, using `response_header`
    /// to evaluate `response_conditions` after the protocol layer has left the
    /// response-header phase.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if any body filter fails.
    #[expect(clippy::too_many_lines, reason = "body hook loop with per-filter skip checks")]
    pub fn execute_http_response_body_with_response_header(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        response_header: Option<&crate::context::Response>,
    ) -> Result<FilterAction, FilterError> {
        ensure_body_done_indices(ctx, self.filters.len());
        accumulate_body_bytes(&mut ctx.response_body_bytes, body.as_ref());
        let request_phase_tracked = request_phase_tracked(ctx, self.filters.len());
        let mut released = false;
        // Walk only filters that declared response-body access (in
        // reverse); non-body filters cost nothing per chunk.
        for &idx in self.response_body_filter_indices.iter().rev() {
            let Some(pf) = self.filters.get(idx) else {
                continue;
            };
            if ctx.body_done_indices.get(idx) == Some(&true) {
                trace!(filter = pf.filter.name(), "skipped body (body_done)");
                continue;
            }
            if skipped_in_request_phase(ctx, request_phase_tracked, idx) {
                trace!(
                    filter = pf.filter.name(),
                    "skipped response body (not executed in request phase)"
                );
                continue;
            }
            let Some(http_filter) = as_response_body_filter(&pf.filter, &pf.response_conditions, response_header)
            else {
                continue;
            };
            ctx.current_filter_id = Some(pf.filter_id);
            let outcome = run_response_body_filter(
                http_filter,
                ctx,
                body,
                end_of_stream,
                pf.failure_mode,
                self.record_filter_duration_metrics,
            );
            ctx.current_filter_id = None;
            match outcome? {
                BodyFilterOutcome::Continue => {},
                BodyFilterOutcome::Released => released = true,
                BodyFilterOutcome::BodyDone => {
                    if let Some(done) = ctx.body_done_indices.get_mut(idx) {
                        *done = true;
                    }
                },
                BodyFilterOutcome::Rejected(r) => return Ok(FilterAction::Reject(r)),
            }
        }
        Ok(released_or_continue(released))
    }

    /// Run response-trailer filters over the upstream trailers.
    ///
    /// Returns the bytes the first filter produced, if any. Those bytes
    /// replace the downstream trailers entirely, appended to the body as
    /// its last chunk — which is how a gRPC status reaches a client that
    /// cannot read HTTP trailers.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if a filter fails to process the trailers.
    pub fn execute_http_response_trailers(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        trailers: &mut http::HeaderMap,
    ) -> Result<Option<Bytes>, FilterError> {
        let request_phase_tracked = request_phase_tracked(ctx, self.filters.len());
        for &idx in self.response_trailer_filter_indices.iter().rev() {
            let Some(pf) = self.filters.get(idx) else {
                continue;
            };
            if skipped_in_request_phase(ctx, request_phase_tracked, idx) {
                trace!(
                    filter = pf.filter.name(),
                    "skipped response trailers (not executed in request phase)"
                );
                continue;
            }
            let AnyFilter::Http(http_filter) = &pf.filter else {
                continue;
            };
            ctx.current_filter_id = Some(pf.filter_id);
            let produced = http_filter.on_response_trailers(ctx, trailers);
            ctx.current_filter_id = None;
            if let Some(bytes) = produced? {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }
}

// -----------------------------------------------------------------------------
// Branch Unwinding
// -----------------------------------------------------------------------------

/// Future returned by [`FilterPipeline::unwind_branches_boxed`].
type UnwindFuture<'a> = Pin<Box<dyn Future<Output = Result<Option<Rejection>, FilterError>> + Send + 'a>>;

// -----------------------------------------------------------------------------
// Binding Utilities
// -----------------------------------------------------------------------------

/// Whether `filter` just published the request's first logical binding.
#[cfg(feature = "upstream-binding")]
fn published_first_binding(filter: &dyn crate::filter::HttpFilter, ctx: &HttpFilterContext<'_>) -> bool {
    filter.binds_upstream() && !ctx.bound_upstream_frozen() && ctx.bound_cluster().is_some()
}

// -----------------------------------------------------------------------------
// Body Done Utilities
// -----------------------------------------------------------------------------

/// Ensure `body_done_indices` is sized to match the filter count.
fn ensure_body_done_indices(ctx: &mut HttpFilterContext<'_>, filter_count: usize) {
    if ctx.body_done_indices.len() != filter_count {
        ctx.body_done_indices.resize(filter_count, false);
    }
}

/// Whether the request phase has populated [`executed_filter_indices`].
///
/// [`execute_http_request`] clears and resizes the vector to the filter
/// count, so a matching length means the request phase has run and the
/// entries are meaningful. Any other length means it has not, which is
/// the normal state during a `StreamBuffer` pre-read: that runs the
/// request-body hooks *before* the request phase, so there is nothing to
/// gate on and every eligible filter must run.
///
/// [`executed_filter_indices`]: HttpFilterContext::executed_filter_indices
/// [`execute_http_request`]: FilterPipeline::execute_http_request
fn request_phase_tracked(ctx: &HttpFilterContext<'_>, filter_count: usize) -> bool {
    ctx.executed_filter_indices.len() == filter_count
}

/// Whether a filter was bypassed during the request phase and so must
/// also be bypassed for body hooks.
///
/// Mirrors the rule [`execute_http_response`] applies to response
/// headers: a filter that branch control flow skipped over (via
/// `SkipTo` or a terminal branch) has not seen the request, so handing
/// it the body would run half a filter's lifecycle.
///
/// [`execute_http_response`]: FilterPipeline::execute_http_response
fn skipped_in_request_phase(ctx: &HttpFilterContext<'_>, tracked: bool, idx: usize) -> bool {
    tracked && ctx.executed_filter_indices.get(idx) == Some(&false)
}
