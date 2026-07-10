// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! HTTP pipeline execution: request, response, and body filter phases.

use bytes::Bytes;
use tracing::trace;

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
    FilterError, actions::FilterAction, any_filter::AnyFilter, condition::should_execute, context::HttpFilterContext,
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
                HeaderFilterOutcome::Rejected(r) => return Ok(FilterAction::Reject(r)),
                HeaderFilterOutcome::Continue => {},
            }
            ctx.executed_filter_indices[idx] = true;
            match super::evaluate::evaluate_branches(&pf.branches, ctx).await? {
                BranchOutcome::Continue => idx += 1,
                BranchOutcome::Terminal => return Ok(FilterAction::Continue),
                BranchOutcome::SkipTo(t) => idx = t,
                BranchOutcome::ReEnter(t) => {
                    ctx.executed_filter_indices[t..=idx].fill(false);
                    idx = t;
                },
                BranchOutcome::Reject(r) => return Ok(FilterAction::Reject(r)),
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
                HeaderFilterOutcome::Continue => {},
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
    #[expect(clippy::indexing_slicing, reason = "idx bounded by filters.len()")]
    #[expect(clippy::too_many_lines, reason = "body hook loop with metrics dispatch")]
    pub async fn execute_http_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        ensure_body_done_indices(ctx, self.filters.len());
        accumulate_body_bytes(&mut ctx.request_body_bytes, body);
        let mut released = false;
        for (idx, pf) in self.filters.iter().enumerate() {
            if ctx.body_done_indices.get(idx) == Some(&true) {
                trace!(filter = pf.filter.name(), "skipped body (body_done)");
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
                    ctx.body_done_indices[idx] = true;
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
        let response_header = ctx.response_header.as_ref().map(|resp| crate::context::Response {
            headers: resp.headers.clone(),
            status: resp.status,
        });
        self.execute_http_response_body_with_response_header(ctx, body, end_of_stream, response_header.as_ref())
    }

    /// Run all HTTP response body filters in reverse order, using `response_header`
    /// to evaluate `response_conditions` after the protocol layer has left the
    /// response-header phase.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if any body filter fails.
    #[expect(clippy::indexing_slicing, reason = "idx bounded by filters.len()")]
    pub fn execute_http_response_body_with_response_header(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        response_header: Option<&crate::context::Response>,
    ) -> Result<FilterAction, FilterError> {
        ensure_body_done_indices(ctx, self.filters.len());
        accumulate_body_bytes(&mut ctx.response_body_bytes, body);
        let mut released = false;
        for (idx, pf) in self.filters.iter().enumerate().rev() {
            if ctx.body_done_indices.get(idx) == Some(&true) {
                trace!(filter = pf.filter.name(), "skipped body (body_done)");
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
                BodyFilterOutcome::BodyDone => ctx.body_done_indices[idx] = true,
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
