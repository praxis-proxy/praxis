// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Utility functions for HTTP pipeline execution.
//!
//! Provides the per-filter dispatch helpers called by the execution
//! loops in [`http`]: `run_request_filter`, `run_response_filter`,
//! and their body-phase counterparts. Also handles body byte
//! accumulation, response condition evaluation, failure-mode
//! fallback, and optional per-filter duration metrics.
//!
//! [`http`]: super::http

use bytes::Bytes;
use praxis_core::config::FailureMode;
use tracing::{Instrument as _, debug, info_span, trace, warn};

use super::check_failure_mode;
use crate::{
    FilterError,
    actions::{FilterAction, Rejection},
    any_filter::AnyFilter,
    condition::{should_execute, should_execute_response_ref},
    context::{HttpFilterContext, Response},
    metrics::{PHASE_REQUEST, PHASE_RESPONSE, STREAM_BODY, STREAM_HEADERS, record_filter_duration},
};

// -----------------------------------------------------------------------------
// Body Filter Utilities
// -----------------------------------------------------------------------------

/// Add chunk size to accumulator.
pub(super) fn accumulate_body_bytes(counter: &mut u64, body: Option<&Bytes>) {
    if let Some(b) = body {
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
///
/// `conditions_resolved` says the request phase already evaluated this
/// filter's conditions (a skipped filter is unmarked in
/// `executed_filter_indices` and filtered out before this call), so the
/// per-chunk re-walk of path/method/header conditions is skipped; the
/// untracked pre-read path still evaluates them here.
pub(super) fn as_request_body_filter<'a>(
    filter: &'a AnyFilter,
    conditions: &[praxis_core::config::Condition],
    request: &crate::context::Request,
    conditions_resolved: bool,
) -> Option<&'a dyn crate::filter::HttpFilter> {
    // Callers reach here only via the precomputed body-filter index
    // lists, which already encode `request_body_access() != None`.
    let http_filter = match filter {
        AnyFilter::Http(f) => f.as_ref(),
        AnyFilter::Tcp(_) => return None,
    };
    if !conditions_resolved && !should_execute(conditions, request) {
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
    // Callers reach here only via the precomputed body-filter index
    // lists, which already encode `response_body_access() != None`.
    let http_filter = match filter {
        AnyFilter::Http(f) => f.as_ref(),
        AnyFilter::Tcp(_) => return None,
    };
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
        Ok(FilterAction::Continue | FilterAction::TerminalResponse(_) | FilterAction::StreamingTerminalResponse(_)) => {
            Ok(BodyFilterOutcome::Continue)
        },
        Ok(FilterAction::Release) => {
            debug!(filter = filter_name, "filter released body");
            Ok(BodyFilterOutcome::Released)
        },
        Ok(FilterAction::Reject(rejection)) => {
            warn!(
                filter = filter_name,
                status = rejection.status,
                "{phase} rejected by filter"
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

    /// Filter produced a complete terminal response (request phase only).
    /// Boxed end-to-end so the ~100-byte payload is neither unboxed here
    /// nor re-boxed by the caller.
    TerminalResponse(Box<crate::actions::TerminalResponse>),

    /// Filter produced a streaming terminal response (request phase only).
    StreamingTerminalResponse(Box<crate::actions::StreamingTerminalResponse>),
}

/// Run a single request header filter hook with tracing and metrics.
#[expect(clippy::too_many_lines, reason = "metrics instrumentation adds branches per hook")]
pub(super) async fn run_request_filter(
    http_filter: &dyn crate::filter::HttpFilter,
    ctx: &mut HttpFilterContext<'_>,
    failure_mode: FailureMode,
    metrics_enabled: bool,
) -> Result<HeaderFilterOutcome, FilterError> {
    let filter_span = info_span!(
        "filter",
        "otel.name" = %format_args!("filter:{}:request", http_filter.name()),
        "filter.name" = http_filter.name(),
        "filter.phase" = "request",
        "filter.result" = tracing::field::Empty,
    );
    let request_result = async {
        trace!("on_request");
        let result = if metrics_enabled {
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
        // Recording from inside the instrumented future spares the span
        // clone (a subscriber clone_span/try_close pair per hook).
        record_filter_result(&tracing::Span::current(), &result);
        result
    }
    .instrument(filter_span)
    .await;
    match request_result {
        Ok(FilterAction::Continue | FilterAction::Release | FilterAction::BodyDone) => {
            Ok(HeaderFilterOutcome::Continue)
        },
        Ok(FilterAction::Reject(rejection)) => {
            warn!(
                filter = http_filter.name(),
                status = rejection.status,
                "request rejected by filter"
            );
            Ok(HeaderFilterOutcome::Rejected(rejection))
        },
        Ok(FilterAction::TerminalResponse(terminal)) => {
            debug!(
                filter = http_filter.name(),
                status = terminal.status,
                "filter produced terminal response"
            );
            Ok(HeaderFilterOutcome::TerminalResponse(terminal))
        },
        Ok(FilterAction::StreamingTerminalResponse(terminal)) => {
            debug!(
                filter = http_filter.name(),
                status = terminal.status,
                "filter produced streaming terminal response"
            );
            Ok(HeaderFilterOutcome::StreamingTerminalResponse(terminal))
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
    let filter_span = info_span!(
        "filter",
        "otel.name" = %format_args!("filter:{}:request_body", http_filter.name()),
        "filter.name" = http_filter.name(),
        "filter.phase" = "request_body",
        "filter.result" = tracing::field::Empty,
    );
    let body_result = async {
        trace!("on_request_body");
        let result = if metrics_enabled {
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
        record_filter_result(&tracing::Span::current(), &result);
        result
    }
    .instrument(filter_span)
    .await;
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
    let filter_span = info_span!(
        "filter",
        "otel.name" = %format_args!("filter:{}:response_body", http_filter.name()),
        "filter.name" = http_filter.name(),
        "filter.phase" = "response_body",
        "filter.result" = tracing::field::Empty,
    );
    let _entered = filter_span.enter();
    trace!("on_response_body");
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
    record_filter_result(&filter_span, &body_result);
    dispatch_body_result(body_result, http_filter.name(), "response body", failure_mode)
}

/// Run a single response header filter.
///
/// When `failure_mode` is [`FailureMode::Open`], errors are logged as
/// warnings and the filter is treated as if it returned `Continue`.
///
/// This hook does **not** infer header modification. Comparing the header
/// count before and after the filter misses same-count edits (a removal
/// paired with an addition), and the protocol layer relies on that signal
/// to pick a write-back strategy. Detection therefore lives at the
/// write-back site, which compares the actual header name sequence.
/// [`response_headers_modified`] remains available for filters to set as
/// an explicit hint.
///
/// [`response_headers_modified`]: HttpFilterContext::response_headers_modified
#[expect(clippy::too_many_lines, reason = "metrics instrumentation adds branches per hook")]
pub(super) async fn run_response_filter(
    http_filter: &dyn crate::filter::HttpFilter,
    ctx: &mut HttpFilterContext<'_>,
    failure_mode: FailureMode,
    metrics_enabled: bool,
) -> Result<HeaderFilterOutcome, FilterError> {
    let filter_span = info_span!(
        "filter",
        "otel.name" = %format_args!("filter:{}:response", http_filter.name()),
        "filter.name" = http_filter.name(),
        "filter.phase" = "response",
        "filter.result" = tracing::field::Empty,
    );
    let response_result = async {
        trace!("on_response");
        let result = if metrics_enabled {
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
        record_filter_result(&tracing::Span::current(), &result);
        result
    }
    .instrument(filter_span)
    .await;
    match response_result {
        Ok(
            FilterAction::Continue
            | FilterAction::Release
            | FilterAction::BodyDone
            | FilterAction::TerminalResponse(_)
            | FilterAction::StreamingTerminalResponse(_),
        ) => Ok(HeaderFilterOutcome::Continue),
        Ok(FilterAction::Reject(rejection)) => {
            warn!(
                filter = http_filter.name(),
                status = rejection.status,
                "response rejected by filter"
            );
            Ok(HeaderFilterOutcome::Rejected(rejection))
        },
        Err(e) => {
            check_failure_mode(http_filter.name(), e, "response", failure_mode)?;
            Ok(HeaderFilterOutcome::Continue)
        },
    }
}

/// Record the filter result on the span's `filter.result` field.
fn record_filter_result(span: &tracing::Span, result: &Result<FilterAction, FilterError>) {
    let label = match result {
        Ok(FilterAction::Continue) => "continue",
        Ok(FilterAction::Release) => "release",
        Ok(FilterAction::BodyDone) => "body_done",
        Ok(FilterAction::Reject(_)) => "reject",
        Ok(FilterAction::TerminalResponse(_)) => "terminal",
        Ok(FilterAction::StreamingTerminalResponse(_)) => "streaming_terminal",
        Err(_) => "error",
    };
    span.record("filter.result", label);
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
    use super::*;
    use crate::HttpFilter;

    #[test]
    fn accumulate_body_bytes_some_adds_to_counter() {
        let mut counter = 0_u64;
        let body = Some(Bytes::from_static(b"hello"));
        accumulate_body_bytes(&mut counter, body.as_ref());
        assert_eq!(counter, 5, "counter should equal byte length of body");
    }

    #[test]
    fn accumulate_body_bytes_none_does_not_change_counter() {
        let mut counter = 42_u64;
        accumulate_body_bytes(&mut counter, None);
        assert_eq!(counter, 42, "counter should remain unchanged for None body");
    }

    #[test]
    fn accumulate_body_bytes_multiple_sums_correctly() {
        let mut counter = 0_u64;
        accumulate_body_bytes(&mut counter, Some(&Bytes::from_static(b"abc")));
        accumulate_body_bytes(&mut counter, Some(&Bytes::from_static(b"defgh")));
        accumulate_body_bytes(&mut counter, None);
        accumulate_body_bytes(&mut counter, Some(&Bytes::from_static(b"ij")));
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
    // Span Event Tests
    // -------------------------------------------------------------------------

    #[test]
    fn dispatch_body_result_rejection_returns_status() {
        let rejection = Rejection::status(413);
        let outcome = dispatch_body_result(
            Ok(FilterAction::Reject(rejection)),
            "size_limit",
            "request body",
            FailureMode::Closed,
        )
        .unwrap();
        assert!(
            matches!(&outcome, BodyFilterOutcome::Rejected(r) if r.status == 413),
            "body rejection should carry status 413 for span event"
        );
    }

    #[test]
    fn dispatch_body_result_response_rejection_returns_status() {
        let rejection = Rejection::status(500);
        let outcome = dispatch_body_result(
            Ok(FilterAction::Reject(rejection)),
            "transform_filter",
            "response body",
            FailureMode::Closed,
        )
        .unwrap();
        assert!(
            matches!(&outcome, BodyFilterOutcome::Rejected(r) if r.status == 500),
            "response body rejection should carry status 500 for span event"
        );
    }

    #[tokio::test]
    async fn run_request_filter_rejection_returns_rejected_outcome() {
        let filter = RejectingFilter(429);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let outcome = run_request_filter(&filter, &mut ctx, FailureMode::Closed, false)
            .await
            .unwrap();
        assert!(
            matches!(&outcome, HeaderFilterOutcome::Rejected(r) if r.status == 429),
            "rejecting filter should produce Rejected outcome with status for span event"
        );
    }

    #[tokio::test]
    async fn run_response_filter_rejection_returns_rejected_outcome() {
        let filter = ResponseRejectingFilter(503);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let outcome = run_response_filter(&filter, &mut ctx, FailureMode::Closed, false)
            .await
            .unwrap();
        assert!(
            matches!(&outcome, HeaderFilterOutcome::Rejected(r) if r.status == 503),
            "response rejection should produce Rejected outcome with status for span event"
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

    /// HTTP filter that always rejects requests with the given status.
    struct RejectingFilter(u16);

    #[async_trait::async_trait]
    impl HttpFilter for RejectingFilter {
        fn name(&self) -> &'static str {
            "rejecting_filter"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Reject(Rejection::status(self.0)))
        }
    }

    /// HTTP filter that always rejects responses with the given status.
    struct ResponseRejectingFilter(u16);

    #[async_trait::async_trait]
    impl HttpFilter for ResponseRejectingFilter {
        fn name(&self) -> &'static str {
            "response_rejecting_filter"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        async fn on_response(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Reject(Rejection::status(self.0)))
        }
    }
}
