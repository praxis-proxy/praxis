// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

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
    context::{HttpFilterContext, Response},
    metrics::{PHASE_REQUEST, PHASE_RESPONSE, STREAM_BODY, STREAM_HEADERS, record_filter_duration},
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
    response_header: Option<&Response>,
) -> Option<&'a dyn crate::filter::HttpFilter> {
    let http_filter = match filter {
        AnyFilter::Http(f) => f.as_ref(),
        AnyFilter::Tcp(_) => return None,
    };
    if http_filter.response_body_access() == BodyAccess::None {
        return None;
    }
    if skip_by_response_conditions_with_header(http_filter, resp_conditions, response_header) {
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
    /// Filter completed body inspection; skip on remaining chunks.
    BodyDone,

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
        Ok(FilterAction::BodyDone) => {
            debug!(filter = filter_name, "filter signaled body done");
            Ok(BodyFilterOutcome::BodyDone)
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
    let response_header = ctx.response_header.as_deref();
    skip_by_response_conditions_with_header(http_filter, resp_conditions, response_header)
}

/// Returns `true` if response conditions fail against the provided header.
pub(super) fn skip_by_response_conditions_with_header(
    http_filter: &dyn crate::filter::HttpFilter,
    resp_conditions: &[praxis_core::config::ResponseCondition],
    response_header: Option<&Response>,
) -> bool {
    let Some(resp) = response_header else {
        return false;
    };
    if !resp_conditions.is_empty() && !should_execute_response_ref(resp_conditions, resp.status, &resp.headers) {
        trace!(filter = http_filter.name(), "skipped by response conditions");
        return true;
    }
    false
}

// -----------------------------------------------------------------------------
// Filter Hook Runners
// -----------------------------------------------------------------------------

/// Outcome of running a single header filter hook (`on_request` or `on_response`).
pub(super) enum HeaderFilterOutcome {
    /// Filter executed successfully; continue pipeline.
    Continue,

    /// Filter rejected the request or response.
    Rejected(Rejection),
}

/// Run a single request header filter hook with tracing and metrics.
#[expect(clippy::too_many_lines, reason = "metrics instrumentation adds branches per hook")]
pub(super) async fn run_request_filter(
    http_filter: &dyn crate::filter::HttpFilter,
    ctx: &mut HttpFilterContext<'_>,
    failure_mode: FailureMode,
    metrics_enabled: bool,
) -> Result<HeaderFilterOutcome, FilterError> {
    trace!(filter = http_filter.name(), "on_request");
    let request_result = if metrics_enabled {
        let start = std::time::Instant::now();
        let result = http_filter.on_request(ctx).await;
        record_filter_duration(
            http_filter.name(),
            PHASE_REQUEST,
            STREAM_HEADERS,
            start.elapsed().as_secs_f64(),
        );
        result
    } else {
        http_filter.on_request(ctx).await
    };
    match request_result {
        Ok(FilterAction::Continue | FilterAction::Release | FilterAction::BodyDone) => {
            Ok(HeaderFilterOutcome::Continue)
        },
        Ok(FilterAction::Reject(rejection)) => {
            debug!(
                filter = http_filter.name(),
                status = rejection.status,
                "filter rejected request"
            );
            Ok(HeaderFilterOutcome::Rejected(rejection))
        },
        Err(e) => {
            check_failure_mode(http_filter.name(), e, "request", failure_mode)?;
            Ok(HeaderFilterOutcome::Continue)
        },
    }
}

/// Run a single request body filter hook with tracing and metrics.
#[expect(clippy::too_many_arguments, reason = "metrics_enabled flag is required per hook")]
pub(super) async fn run_request_body_filter(
    http_filter: &dyn crate::filter::HttpFilter,
    ctx: &mut HttpFilterContext<'_>,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    failure_mode: FailureMode,
    metrics_enabled: bool,
) -> Result<BodyFilterOutcome, FilterError> {
    trace!(filter = http_filter.name(), "on_request_body");
    let body_result = if metrics_enabled {
        let start = std::time::Instant::now();
        let result = http_filter.on_request_body(ctx, body, end_of_stream).await;
        record_filter_duration(
            http_filter.name(),
            PHASE_REQUEST,
            STREAM_BODY,
            start.elapsed().as_secs_f64(),
        );
        result
    } else {
        http_filter.on_request_body(ctx, body, end_of_stream).await
    };
    dispatch_body_result(body_result, http_filter.name(), "request body", failure_mode)
}

/// Run a single response body filter hook with tracing and metrics.
#[expect(clippy::too_many_arguments, reason = "metrics_enabled flag is required per hook")]
pub(super) fn run_response_body_filter(
    http_filter: &dyn crate::filter::HttpFilter,
    ctx: &mut HttpFilterContext<'_>,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    failure_mode: FailureMode,
    metrics_enabled: bool,
) -> Result<BodyFilterOutcome, FilterError> {
    trace!(filter = http_filter.name(), "on_response_body");
    let body_result = if metrics_enabled {
        let start = std::time::Instant::now();
        let result = http_filter.on_response_body(ctx, body, end_of_stream);
        record_filter_duration(
            http_filter.name(),
            PHASE_RESPONSE,
            STREAM_BODY,
            start.elapsed().as_secs_f64(),
        );
        result
    } else {
        http_filter.on_response_body(ctx, body, end_of_stream)
    };
    dispatch_body_result(body_result, http_filter.name(), "response body", failure_mode)
}

/// Run a single response header filter and track header modification.
///
/// When `failure_mode` is [`FailureMode::Open`], errors are logged as
/// warnings and the filter is treated as if it returned `Continue`.
#[expect(clippy::too_many_lines, reason = "metrics instrumentation adds branches per hook")]
pub(super) async fn run_response_filter(
    http_filter: &dyn crate::filter::HttpFilter,
    ctx: &mut HttpFilterContext<'_>,
    failure_mode: FailureMode,
    metrics_enabled: bool,
) -> Result<HeaderFilterOutcome, FilterError> {
    trace!(filter = http_filter.name(), "on_response");
    let pre_len = ctx.response_header.as_ref().map_or(0, |r| r.headers.len());
    let response_result = if metrics_enabled {
        let start = std::time::Instant::now();
        let result = http_filter.on_response(ctx).await;
        record_filter_duration(
            http_filter.name(),
            PHASE_RESPONSE,
            STREAM_HEADERS,
            start.elapsed().as_secs_f64(),
        );
        result
    } else {
        http_filter.on_response(ctx).await
    };
    match response_result {
        Ok(FilterAction::Continue | FilterAction::Release | FilterAction::BodyDone) => {
            if !ctx.response_headers_modified {
                let post_len = ctx.response_header.as_ref().map_or(0, |r| r.headers.len());
                if pre_len != post_len {
                    ctx.response_headers_modified = true;
                }
            }
            Ok(HeaderFilterOutcome::Continue)
        },
        Ok(FilterAction::Reject(rejection)) => {
            warn!(
                filter = http_filter.name(),
                status = rejection.status,
                "filter rejected response"
            );
            Ok(HeaderFilterOutcome::Rejected(rejection))
        },
        Err(e) => {
            check_failure_mode(http_filter.name(), e, "response", failure_mode)?;
            Ok(HeaderFilterOutcome::Continue)
        },
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::HttpFilter;

    #[test]
    fn accumulate_body_bytes_some_adds_to_counter() {
        let mut counter = 0_u64;
        let body = Some(Bytes::from_static(b"hello"));
        accumulate_body_bytes(&mut counter, &body);
        assert_eq!(counter, 5, "counter should equal byte length of body");
    }

    #[test]
    fn accumulate_body_bytes_none_does_not_change_counter() {
        let mut counter = 42_u64;
        accumulate_body_bytes(&mut counter, &None);
        assert_eq!(counter, 42, "counter should remain unchanged for None body");
    }

    #[test]
    fn accumulate_body_bytes_multiple_sums_correctly() {
        let mut counter = 0_u64;
        accumulate_body_bytes(&mut counter, &Some(Bytes::from_static(b"abc")));
        accumulate_body_bytes(&mut counter, &Some(Bytes::from_static(b"defgh")));
        accumulate_body_bytes(&mut counter, &None);
        accumulate_body_bytes(&mut counter, &Some(Bytes::from_static(b"ij")));
        assert_eq!(counter, 10, "counter should be sum of all Some chunk lengths");
    }

    #[test]
    fn released_or_continue_true_returns_release() {
        assert!(
            matches!(released_or_continue(true), FilterAction::Release),
            "true should produce FilterAction::Release"
        );
    }

    #[test]
    fn released_or_continue_false_returns_continue() {
        assert!(
            matches!(released_or_continue(false), FilterAction::Continue),
            "false should produce FilterAction::Continue"
        );
    }

    #[test]
    fn dispatch_body_result_ok_continue() {
        let outcome = dispatch_body_result(Ok(FilterAction::Continue), "test", "request", FailureMode::Closed).unwrap();
        assert!(
            matches!(outcome, BodyFilterOutcome::Continue),
            "Ok(Continue) should produce BodyFilterOutcome::Continue"
        );
    }

    #[test]
    fn dispatch_body_result_ok_release() {
        let outcome = dispatch_body_result(Ok(FilterAction::Release), "test", "request", FailureMode::Closed).unwrap();
        assert!(
            matches!(outcome, BodyFilterOutcome::Released),
            "Ok(Release) should produce BodyFilterOutcome::Released"
        );
    }

    #[test]
    fn dispatch_body_result_ok_reject() {
        let rejection = Rejection::status(429);
        let outcome = dispatch_body_result(
            Ok(FilterAction::Reject(rejection)),
            "test",
            "request",
            FailureMode::Closed,
        )
        .unwrap();
        assert!(
            matches!(&outcome, BodyFilterOutcome::Rejected(r) if r.status == 429),
            "Ok(Reject(429)) should produce BodyFilterOutcome::Rejected with status 429"
        );
    }

    #[test]
    fn dispatch_body_result_ok_body_done() {
        let outcome = dispatch_body_result(Ok(FilterAction::BodyDone), "test", "request", FailureMode::Closed).unwrap();
        assert!(
            matches!(outcome, BodyFilterOutcome::BodyDone),
            "Ok(BodyDone) should produce BodyFilterOutcome::BodyDone"
        );
    }

    #[test]
    fn dispatch_body_result_err_failure_mode_open_swallows_error() {
        let err: FilterError = "test error".into();
        let outcome = dispatch_body_result(Err(err), "test", "request", FailureMode::Open).unwrap();
        assert!(
            matches!(outcome, BodyFilterOutcome::Continue),
            "error with FailureMode::Open should produce BodyFilterOutcome::Continue"
        );
    }

    #[test]
    fn dispatch_body_result_err_failure_mode_closed_propagates() {
        let err: FilterError = "test error".into();
        let result = dispatch_body_result(Err(err), "test", "request", FailureMode::Closed);
        assert!(result.is_err(), "error with FailureMode::Closed should propagate");
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
        use praxis_core::config::{ResponseCondition, ResponseConditionMatch};

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
        use praxis_core::config::{ResponseCondition, ResponseConditionMatch};

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
        use praxis_core::config::{ResponseCondition, ResponseConditionMatch};

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
    fn skip_by_response_conditions_unless_match_skips() {
        use http::StatusCode;
        use praxis_core::config::{ResponseCondition, ResponseConditionMatch};

        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut resp = crate::test_utils::make_response();
        resp.status = StatusCode::BAD_REQUEST;

        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.response_header = Some(&mut resp);

        let conditions = vec![ResponseCondition::Unless(ResponseConditionMatch {
            status: Some(vec![400]),
            headers: None,
        })];

        let filter = StubFilter;
        assert!(
            skip_by_response_conditions(&filter, &conditions, &ctx),
            "Unless with matching status should cause skip"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Minimal HTTP filter stub for unit tests.
    struct StubFilter;

    #[async_trait::async_trait]
    impl HttpFilter for StubFilter {
        fn name(&self) -> &'static str {
            "stub"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }
}
