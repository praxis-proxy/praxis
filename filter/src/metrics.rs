// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Per-filter execution timing metrics.

use metrics::histogram;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Histogram for filter hook execution duration in seconds.
const FILTER_DURATION_SECONDS: &str = "praxis_filter_duration_seconds";

/// Request direction label value.
pub(crate) const PHASE_REQUEST: &str = "request";

/// Response direction label value.
pub(crate) const PHASE_RESPONSE: &str = "response";

/// Header hook label value (`on_request`, `on_response`).
pub(crate) const STREAM_HEADERS: &str = "headers";

/// Body hook label value (`on_request_body`, `on_response_body`).
pub(crate) const STREAM_BODY: &str = "body";

// -----------------------------------------------------------------------------
// Metric Recording
// -----------------------------------------------------------------------------

/// Record wall-clock duration for a single filter hook invocation.
pub(crate) fn record_filter_duration(
    filter: &'static str,
    phase: &'static str,
    stream: &'static str,
    duration_secs: f64,
) {
    histogram!(
        FILTER_DURATION_SECONDS,
        "filter" => filter,
        "phase" => phase,
        "stream" => stream,
    )
    .record(duration_secs);
}
