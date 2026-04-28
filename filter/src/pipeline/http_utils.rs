// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Utility functions for HTTP pipeline execution.

use bytes::Bytes;
use praxis_core::config::FailureMode;
use tracing::{debug, trace, warn};

use super::check_failure_mode;
use crate::{
    FilterError,
    actions::{FilterAction, Rejection},
    any_filter::AnyFilter,
    body::BodyAccess,
    condition::{should_execute, should_execute_response_ref},
    context::HttpFilterContext,
};

// -----------------------------------------------------------------------------
// Body Filter Utilities
// -----------------------------------------------------------------------------

/// Add chunk size to accumulator.
pub(super) fn accumulate_body_bytes(counter: &mut u64, body: &Option<Bytes>) {
    if let Some(b) = body.as_ref() {
        *counter += b.len() as u64;
    }
}

/// Return `Release` or `Continue` based on `released` flag.
pub(super) fn released_or_continue(released: bool) -> FilterAction {
    if released {
        FilterAction::Release
    } else {
        FilterAction::Continue
    }
}

/// Extract an HTTP filter eligible for request body processing.
pub(super) fn as_request_body_filter<'a>(
    filter: &'a AnyFilter,
    conditions: &[praxis_core::config::Condition],
    request: &crate::context::Request,
) -> Option<&'a dyn crate::filter::HttpFilter> {
    let http_filter = match filter {
        AnyFilter::Http(f) => f.as_ref(),
        AnyFilter::Tcp(_) => return None,
    };
    if http_filter.request_body_access() == BodyAccess::None {
        return None;
    }
    if !should_execute(conditions, request) {
        trace!(filter = http_filter.name(), "body hook skipped by conditions");
        return None;
    }
    Some(http_filter)
}

/// Extract an HTTP filter eligible for response body processing.
pub(super) fn as_response_body_filter<'a>(
    filter: &'a AnyFilter,
    resp_conditions: &[praxis_core::config::ResponseCondition],
    ctx: &HttpFilterContext<'_>,
) -> Option<&'a dyn crate::filter::HttpFilter> {
    let http_filter = match filter {
        AnyFilter::Http(f) => f.as_ref(),
        AnyFilter::Tcp(_) => return None,
    };
    if http_filter.response_body_access() == BodyAccess::None {
        return None;
    }
    if skip_by_response_conditions(http_filter, resp_conditions, ctx) {
        return None;
    }
    Some(http_filter)
}

// -----------------------------------------------------------------------------
// Filter Dispatch Utilities
// -----------------------------------------------------------------------------

/// Outcome of a single body filter invocation.
#[derive(Debug)]
pub(super) enum BodyFilterOutcome {
    /// Filter passed; continue to next.
    Continue,

    /// Filter released the body.
    Released,

    /// Filter rejected with the given rejection.
    Rejected(Rejection),
}

/// Classify a body filter result into a [`BodyFilterOutcome`], logging on reject/error.
///
/// When `failure_mode` is [`FailureMode::Open`], errors are logged as
/// warnings and the filter is treated as if it returned `Continue`.
pub(super) fn dispatch_body_result(
    result: Result<FilterAction, FilterError>,
    filter_name: &str,
    phase: &str,
    failure_mode: FailureMode,
) -> Result<BodyFilterOutcome, FilterError> {
    match result {
        Ok(FilterAction::Continue) => Ok(BodyFilterOutcome::Continue),
        Ok(FilterAction::Release) => {
            debug!(filter = filter_name, "filter released body");
            Ok(BodyFilterOutcome::Released)
        },
        Ok(FilterAction::Reject(rejection)) => {
            debug!(
                filter = filter_name,
                status = rejection.status,
                "filter rejected {phase}"
            );
            Ok(BodyFilterOutcome::Rejected(rejection))
        },
        Err(e) => {
            check_failure_mode(filter_name, e, phase, failure_mode)?;
            Ok(BodyFilterOutcome::Continue)
        },
    }
}

/// Returns `true` if the filter should be skipped due to
/// response conditions not matching.
pub(super) fn skip_by_response_conditions(
    http_filter: &dyn crate::filter::HttpFilter,
    resp_conditions: &[praxis_core::config::ResponseCondition],
    ctx: &HttpFilterContext<'_>,
) -> bool {
    if !resp_conditions.is_empty()
        && let Some(resp) = ctx.response_header.as_ref()
        && !should_execute_response_ref(resp_conditions, resp.status, &resp.headers)
    {
        trace!(filter = http_filter.name(), "skipped by response conditions");
        return true;
    }
    false
}

/// Run a single response filter and track header modification.
///
/// When `failure_mode` is [`FailureMode::Open`], errors are logged as
/// warnings and the filter is treated as if it returned `Continue`.
pub(super) async fn run_response_filter(
    http_filter: &dyn crate::filter::HttpFilter,
    ctx: &mut HttpFilterContext<'_>,
    failure_mode: FailureMode,
) -> Result<Option<Rejection>, FilterError> {
    let pre_len = ctx.response_header.as_ref().map_or(0, |r| r.headers.len());
    match http_filter.on_response(ctx).await {
        Ok(FilterAction::Continue | FilterAction::Release) => {
            if !ctx.response_headers_modified {
                let post_len = ctx.response_header.as_ref().map_or(0, |r| r.headers.len());
                if pre_len != post_len {
                    ctx.response_headers_modified = true;
                }
            }
            Ok(None)
        },
        Ok(FilterAction::Reject(rejection)) => {
            warn!(
                filter = http_filter.name(),
                status = rejection.status,
                "filter rejected response"
            );
            Ok(Some(rejection))
        },
        Err(e) => {
            check_failure_mode(http_filter.name(), e, "response", failure_mode)?;
            Ok(None)
        },
    }
}
