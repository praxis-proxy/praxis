// SPDX-License-Identifier: MIT
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

use bytes::Bytes;
use tracing::{trace, warn};

use super::{
    FilterPipeline,
    branch::BranchOutcome,
    http_utils::{
        BodyFilterOutcome, HeaderFilterOutcome, accumulate_body_bytes, as_request_body_filter, as_response_body_filter,
        released_or_continue, run_request_body_filter, run_request_filter, run_response_body_filter,
        run_response_filter, skip_by_response_conditions,
    },
};
use crate::{
    FilterError,
    actions::{FilterAction, Rejection},
    any_filter::AnyFilter,
    condition::should_execute,
    context::HttpFilterContext,
};

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
        ctx.executed_filter_indices.clear();
        ctx.executed_filter_indices.resize(self.filters.len(), false);
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
            if !should_execute(&pf.conditions, ctx.request) {
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
                    return Ok(FilterAction::TerminalResponse(Box::new(terminal)));
                },
                HeaderFilterOutcome::StreamingTerminalResponse(terminal) => {
                    ctx.executed_filter_indices[idx] = true;
                    return Ok(FilterAction::StreamingTerminalResponse(terminal));
                },
                HeaderFilterOutcome::Continue => {},
            }
            ctx.executed_filter_indices[idx] = true;
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
                    ctx.executed_filter_indices[t..=idx].fill(false);
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
    /// phase (tracked by [`executed_filter_indices`]).
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if any filter fails.
    ///
    /// [`executed_filter_indices`]: HttpFilterContext::executed_filter_indices
    #[expect(clippy::too_many_lines, reason = "streaming terminal variant adds one match arm")]
    pub async fn execute_http_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        for (idx, pf) in self.filters.iter().enumerate().rev() {
            if ctx.executed_filter_indices.get(idx) == Some(&false) {
                trace!(
                    filter = pf.filter.name(),
                    "skipped on_response (not executed in request phase)"
                );
                continue;
            }
            let http_filter = match &pf.filter {
                AnyFilter::Http(f) => f.as_ref(),
                AnyFilter::Tcp(_) => continue,
            };
            if skip_by_response_conditions(http_filter, &pf.response_conditions, ctx) {
                continue;
            }
            ctx.current_filter_id = Some(pf.filter_id);
            let outcome =
                run_response_filter(http_filter, ctx, pf.failure_mode, self.record_filter_duration_metrics).await;
            ctx.current_filter_id = None;
            match outcome? {
                HeaderFilterOutcome::Continue
                | HeaderFilterOutcome::TerminalResponse(_)
                | HeaderFilterOutcome::StreamingTerminalResponse(_) => {},
                HeaderFilterOutcome::Rejected(rejection) => {
                    return Ok(FilterAction::Reject(rejection));
                },
            }
        }
        Ok(FilterAction::Continue)
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
        for (idx, pf) in self.filters.iter().enumerate() {
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
            // Declared body access is a per-filter constant; the pre-computed
            // flag skips non-body filters without a per-chunk virtual call.
            if !self.request_body_access_by_idx.get(idx).copied().unwrap_or(true) {
                continue;
            }
            let Some(http_filter) = as_request_body_filter(&pf.filter, &pf.conditions, ctx.request) else {
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
        Ok(released_or_continue(released))
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
        for (idx, pf) in self.filters.iter().enumerate().rev() {
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
            // Declared body access is a per-filter constant; the pre-computed
            // flag skips non-body filters without a per-chunk virtual call.
            if !self.response_body_access_by_idx.get(idx).copied().unwrap_or(true) {
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
/// headers: a filter that branch control flow skipped over — via
/// `SkipTo` or a terminal branch — has not seen the request, so handing
/// it the body would run half a filter's lifecycle.
///
/// [`execute_http_response`]: FilterPipeline::execute_http_response
fn skipped_in_request_phase(ctx: &HttpFilterContext<'_>, tracked: bool, idx: usize) -> bool {
    tracked && ctx.executed_filter_indices.get(idx) == Some(&false)
}
