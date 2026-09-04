// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Per-filter execution timing and traffic-management metrics.

use metrics::{SharedString, counter, gauge, histogram};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Histogram for filter hook execution duration in seconds.
const FILTER_DURATION_SECONDS: &str = "praxis_filter_duration_seconds";

/// Gauge for circuit breaker open state (`1` = open/half-open, `0` = closed).
const CIRCUIT_BREAKER_OPEN: &str = "praxis_circuit_breaker_open";

/// Counter for load-balancer panic-mode selections.
const LB_PANIC_MODE_TOTAL: &str = "praxis_lb_panic_mode_total";

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

/// Set the circuit-breaker open gauge for a cluster.
///
/// Half-open is treated as open (`1.0`).
pub(crate) fn set_circuit_breaker_state(cluster_name: SharedString, open: bool) {
    gauge!(CIRCUIT_BREAKER_OPEN, "cluster" => cluster_name).set(if open { 1.0 } else { 0.0 });
}

/// Increment the load-balancer panic-mode counter for a cluster.
pub(crate) fn record_lb_panic_mode(cluster: SharedString) {
    counter!(LB_PANIC_MODE_TOTAL, "cluster" => cluster).increment(1);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn record_emits_correct_metric_name_and_label_keys() {
        crate::test_utils::install_metrics_recorder();

        record_filter_duration("label_key_test", PHASE_REQUEST, STREAM_HEADERS, 0.001);

        let rendered = crate::test_utils::render_metrics();
        assert_metric_labels(&rendered, "label_key_test", "request", "headers");
    }

    #[test]
    fn record_distinguishes_request_and_response_phases() {
        crate::test_utils::install_metrics_recorder();

        record_filter_duration("phase_test", PHASE_REQUEST, STREAM_HEADERS, 0.001);
        record_filter_duration("phase_test", PHASE_RESPONSE, STREAM_HEADERS, 0.002);

        let rendered = crate::test_utils::render_metrics();
        assert_metric_labels(&rendered, "phase_test", "request", "headers");
        assert_metric_labels(&rendered, "phase_test", "response", "headers");
    }

    #[test]
    fn record_distinguishes_headers_and_body_streams() {
        crate::test_utils::install_metrics_recorder();

        record_filter_duration("stream_test", PHASE_REQUEST, STREAM_HEADERS, 0.001);
        record_filter_duration("stream_test", PHASE_REQUEST, STREAM_BODY, 0.002);

        let rendered = crate::test_utils::render_metrics();
        assert_metric_labels(&rendered, "stream_test", "request", "headers");
        assert_metric_labels(&rendered, "stream_test", "request", "body");
    }

    #[test]
    fn phase_constants_have_expected_values() {
        assert_eq!(PHASE_REQUEST, "request", "PHASE_REQUEST label value");
        assert_eq!(PHASE_RESPONSE, "response", "PHASE_RESPONSE label value");
    }

    #[test]
    fn stream_constants_have_expected_values() {
        assert_eq!(STREAM_HEADERS, "headers", "STREAM_HEADERS label value");
        assert_eq!(STREAM_BODY, "body", "STREAM_BODY label value");
    }

    #[test]
    fn metric_name_constant_matches_expected() {
        assert_eq!(
            FILTER_DURATION_SECONDS, "praxis_filter_duration_seconds",
            "histogram metric name"
        );
    }

    // -----------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------

    fn assert_metric_labels(rendered: &str, filter: &str, phase: &str, stream: &str) {
        let filter_label = format!("filter=\"{filter}\"");
        let phase_label = format!("phase=\"{phase}\"");
        let stream_label = format!("stream=\"{stream}\"");
        assert!(
            rendered.lines().any(|line| {
                line.starts_with("praxis_filter_duration_seconds")
                    && line.contains(&filter_label)
                    && line.contains(&phase_label)
                    && line.contains(&stream_label)
            }),
            "expected metric praxis_filter_duration_seconds with \
             filter={filter} phase={phase} stream={stream}:\n{rendered}"
        );
    }
}
