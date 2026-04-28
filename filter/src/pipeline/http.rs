// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! HTTP pipeline execution: request, response, and body filter phases.

use bytes::Bytes;
use tracing::{debug, trace};

use super::{
    FilterPipeline,
    branch::BranchOutcome,
    check_failure_mode,
    filter::PipelineFilter,
    http_utils::{
        BodyFilterOutcome, accumulate_body_bytes, as_request_body_filter, as_response_body_filter,
        dispatch_body_result, released_or_continue, run_response_filter, skip_by_response_conditions,
    },
};
use crate::{
    FilterError, actions::FilterAction, any_filter::AnyFilter, condition::should_execute, context::HttpFilterContext,
};

// -----------------------------------------------------------------------------
// FilterPipeline HTTP
// -----------------------------------------------------------------------------

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
    #[allow(clippy::indexing_slicing, reason = "while loop bounds idx")]
    pub async fn execute_http_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        ctx.executed_filter_indices = vec![false; self.filters.len()];
        let mut idx = 0;
        while idx < self.filters.len() {
            let pf = &self.filters[idx];

            match run_request_filter(pf, ctx).await? {
                RequestFilterResult::Skip => {
                    idx += 1;
                    continue;
                },
                RequestFilterResult::Reject(r) => return Ok(FilterAction::Reject(r)),
                RequestFilterResult::Continue => {},
            }

            ctx.executed_filter_indices[idx] = true;

            let branch_outcome = super::evaluate::evaluate_branches(&pf.branches, ctx).await?;
            match branch_outcome {
                BranchOutcome::Continue => idx += 1,
                BranchOutcome::Terminal => return Ok(FilterAction::Continue),
                BranchOutcome::SkipTo(t) | BranchOutcome::ReEnter(t) => idx = t,
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
            trace!(filter = http_filter.name(), "on_response");
            let action = run_response_filter(http_filter, ctx, pf.failure_mode).await?;
            if let Some(rejection) = action {
                return Ok(FilterAction::Reject(rejection));
            }
        }
        Ok(FilterAction::Continue)
    }

    /// Run all HTTP request body filters in order.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if any body filter fails.
    pub async fn execute_http_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        accumulate_body_bytes(&mut ctx.request_body_bytes, body);
        let mut released = false;
        for pf in &self.filters {
            let Some(http_filter) = as_request_body_filter(&pf.filter, &pf.conditions, ctx.request) else {
                continue;
            };
            trace!(filter = http_filter.name(), "on_request_body");
            match dispatch_body_result(
                http_filter.on_request_body(ctx, body, end_of_stream).await,
                http_filter.name(),
                "request body",
                pf.failure_mode,
            )? {
                BodyFilterOutcome::Continue => {},
                BodyFilterOutcome::Released => released = true,
                BodyFilterOutcome::Rejected(r) => return Ok(FilterAction::Reject(r)),
            }
        }
        Ok(released_or_continue(released))
    }

    /// Run all HTTP response body filters in reverse order.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if any body filter fails.
    pub fn execute_http_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        accumulate_body_bytes(&mut ctx.response_body_bytes, body);
        let mut released = false;
        for pf in self.filters.iter().rev() {
            let Some(http_filter) = as_response_body_filter(&pf.filter, &pf.response_conditions, ctx) else {
                continue;
            };
            trace!(filter = http_filter.name(), "on_response_body");
            match dispatch_body_result(
                http_filter.on_response_body(ctx, body, end_of_stream),
                http_filter.name(),
                "response body",
                pf.failure_mode,
            )? {
                BodyFilterOutcome::Continue => {},
                BodyFilterOutcome::Released => released = true,
                BodyFilterOutcome::Rejected(r) => return Ok(FilterAction::Reject(r)),
            }
        }
        Ok(released_or_continue(released))
    }
}

// -----------------------------------------------------------------------------
// Request Filter Utilities
// -----------------------------------------------------------------------------

/// Outcome of running a single request filter.
enum RequestFilterResult {
    /// Filter executed successfully; continue pipeline.
    Continue,

    /// Filter rejected the request.
    Reject(crate::actions::Rejection),

    /// Filter was skipped (TCP or conditions).
    Skip,
}

/// Run a single request filter, handling conditions and tracing.
async fn run_request_filter(
    pf: &PipelineFilter,
    ctx: &mut HttpFilterContext<'_>,
) -> Result<RequestFilterResult, FilterError> {
    let http_filter = match &pf.filter {
        AnyFilter::Http(f) => f.as_ref(),
        AnyFilter::Tcp(_) => return Ok(RequestFilterResult::Skip),
    };
    if !should_execute(&pf.conditions, ctx.request) {
        trace!(filter = http_filter.name(), "skipped by conditions");
        return Ok(RequestFilterResult::Skip);
    }
    trace!(filter = http_filter.name(), "on_request");
    match http_filter.on_request(ctx).await {
        Ok(FilterAction::Continue | FilterAction::Release) => Ok(RequestFilterResult::Continue),
        Ok(FilterAction::Reject(rejection)) => {
            debug!(
                filter = http_filter.name(),
                status = rejection.status,
                "filter rejected request"
            );
            Ok(RequestFilterResult::Reject(rejection))
        },
        Err(e) => {
            check_failure_mode(http_filter.name(), e, "request", pf.failure_mode)?;
            Ok(RequestFilterResult::Continue)
        },
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use bytes::Bytes;
    use praxis_core::config::{FailureMode, ResponseCondition, ResponseConditionMatch};

    use super::super::http_utils::{
        accumulate_body_bytes, dispatch_body_result, released_or_continue, skip_by_response_conditions,
    };
    use crate::{FilterAction, FilterError, actions::Rejection};

    #[test]
    fn accumulate_body_bytes_increments_with_some() {
        let mut counter = 0u64;
        let body = Some(Bytes::from_static(b"hello"));
        accumulate_body_bytes(&mut counter, &body);
        assert_eq!(counter, 5, "counter should equal body length");
    }

    #[test]
    fn accumulate_body_bytes_multiple_chunks() {
        let mut counter = 0u64;
        accumulate_body_bytes(&mut counter, &Some(Bytes::from_static(b"abc")));
        accumulate_body_bytes(&mut counter, &Some(Bytes::from_static(b"de")));
        assert_eq!(counter, 5, "counter should accumulate across calls");
    }

    #[test]
    fn accumulate_body_bytes_noop_with_none() {
        let mut counter = 10u64;
        accumulate_body_bytes(&mut counter, &None);
        assert_eq!(counter, 10, "counter should be unchanged when body is None");
    }

    #[test]
    fn accumulate_body_bytes_noop_with_empty() {
        let mut counter = 0u64;
        accumulate_body_bytes(&mut counter, &Some(Bytes::new()));
        assert_eq!(counter, 0, "counter should be unchanged when body is empty");
    }

    #[test]
    fn released_or_continue_true_returns_release() {
        assert!(
            matches!(released_or_continue(true), FilterAction::Release),
            "true should yield Release"
        );
    }

    #[test]
    fn released_or_continue_false_returns_continue() {
        assert!(
            matches!(released_or_continue(false), FilterAction::Continue),
            "false should yield Continue"
        );
    }

    #[test]
    fn skip_by_response_conditions_empty_conditions() {
        let filter = crate::builtins::StaticResponseFilter::from_config(
            &serde_yaml::from_str::<serde_yaml::Value>("status: 200").unwrap(),
        )
        .unwrap();
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut resp = crate::test_utils::make_response();
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.response_header = Some(&mut resp);
        assert!(
            !skip_by_response_conditions(filter.as_ref(), &[], &ctx),
            "empty conditions should not skip"
        );
    }

    #[test]
    fn skip_by_response_conditions_matching_when_does_not_skip() {
        let filter = crate::builtins::StaticResponseFilter::from_config(
            &serde_yaml::from_str::<serde_yaml::Value>("status: 200").unwrap(),
        )
        .unwrap();
        let conds = vec![ResponseCondition::When(ResponseConditionMatch {
            status: Some(vec![200]),
            headers: None,
        })];
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut resp = crate::test_utils::make_response();
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.response_header = Some(&mut resp);
        assert!(
            !skip_by_response_conditions(filter.as_ref(), &conds, &ctx),
            "matching 'when' condition should not skip"
        );
    }

    #[test]
    fn skip_by_response_conditions_non_matching_when_skips() {
        let filter = crate::builtins::StaticResponseFilter::from_config(
            &serde_yaml::from_str::<serde_yaml::Value>("status: 200").unwrap(),
        )
        .unwrap();
        let conds = vec![ResponseCondition::When(ResponseConditionMatch {
            status: Some(vec![404]),
            headers: None,
        })];
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut resp = crate::test_utils::make_response();
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.response_header = Some(&mut resp);
        assert!(
            skip_by_response_conditions(filter.as_ref(), &conds, &ctx),
            "non-matching 'when' condition should skip"
        );
    }

    #[test]
    fn skip_by_response_conditions_no_response_header_does_not_skip() {
        let filter = crate::builtins::StaticResponseFilter::from_config(
            &serde_yaml::from_str::<serde_yaml::Value>("status: 200").unwrap(),
        )
        .unwrap();
        let conds = vec![ResponseCondition::When(ResponseConditionMatch {
            status: Some(vec![200]),
            headers: None,
        })];
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(
            !skip_by_response_conditions(filter.as_ref(), &conds, &ctx),
            "no response header should not skip"
        );
    }

    #[test]
    fn dispatch_body_result_continue() {
        let outcome =
            dispatch_body_result(Ok(FilterAction::Continue), "test", "request body", FailureMode::Closed).unwrap();
        assert!(
            matches!(outcome, super::super::http_utils::BodyFilterOutcome::Continue),
            "Continue action should produce Continue outcome"
        );
    }

    #[test]
    fn dispatch_body_result_release() {
        let outcome =
            dispatch_body_result(Ok(FilterAction::Release), "test", "request body", FailureMode::Closed).unwrap();
        assert!(
            matches!(outcome, super::super::http_utils::BodyFilterOutcome::Released),
            "Release action should produce Released outcome"
        );
    }

    #[test]
    fn dispatch_body_result_reject() {
        let outcome = dispatch_body_result(
            Ok(FilterAction::Reject(Rejection::status(403))),
            "test",
            "request body",
            FailureMode::Closed,
        )
        .unwrap();
        assert!(
            matches!(outcome, super::super::http_utils::BodyFilterOutcome::Rejected(r) if r.status == 403),
            "Reject action should produce Rejected outcome with correct status"
        );
    }

    #[test]
    fn dispatch_body_result_error_closed() {
        let err: FilterError = "boom".into();
        let result = dispatch_body_result(Err(err), "test", "request body", FailureMode::Closed);
        assert!(result.is_err(), "error result should propagate as Err when closed");
        assert!(
            result.unwrap_err().to_string().contains("boom"),
            "error message should be preserved"
        );
    }

    #[test]
    fn dispatch_body_result_error_open() {
        let err: FilterError = "boom".into();
        let result = dispatch_body_result(Err(err), "test", "request body", FailureMode::Open);
        assert!(result.is_ok(), "error result should be Ok when fail-open");
        assert!(
            matches!(result.unwrap(), super::super::http_utils::BodyFilterOutcome::Continue),
            "fail-open error should produce Continue outcome"
        );
    }
}
