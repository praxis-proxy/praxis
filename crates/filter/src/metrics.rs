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

#[cfg(feature = "cloud-events-filter")]
/// Counter for `CloudEvents` publication outcomes.
const CLOUD_EVENTS_PUBLISH_TOTAL: &str = "praxis_cloud_events_publish_total";

#[cfg(feature = "cloud-events-filter")]
/// Histogram for `CloudEvents` publication latency in seconds.
const CLOUD_EVENTS_PUBLISH_DURATION_SECONDS: &str = "praxis_cloud_events_publish_duration_seconds";

#[cfg(feature = "cloud-events-filter")]
/// Counter for `CloudEvents` events skipped before publication.
const CLOUD_EVENTS_SKIPPED_TOTAL: &str = "praxis_cloud_events_skipped_total";

/// Request direction label value.
pub(crate) const PHASE_REQUEST: &str = "request";

/// Response direction label value.
pub(crate) const PHASE_RESPONSE: &str = "response";

/// Selected-upstream direction label value (`on_selected_upstream_request_body`).
///
/// A distinct phase from [`PHASE_REQUEST`] so the post-selection body pass
/// is separable in dashboards: a filter active in both the normal
/// request-body phase and the selected-upstream phase would otherwise
/// produce indistinguishable histogram entries.
pub(crate) const PHASE_SELECTED_UPSTREAM: &str = "selected_upstream";

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

#[cfg(feature = "cloud-events-filter")]
/// Record one `CloudEvents` publication outcome and its latency.
pub(crate) fn record_cloud_events_publish(
    outcome: &'static str,
    failure_class: &'static str,
    status: Option<u16>,
    latency_secs: f64,
) {
    let status_class = status.map_or("none", http_status_class);
    counter!(
        CLOUD_EVENTS_PUBLISH_TOTAL,
        "outcome" => outcome,
        "failure_class" => failure_class,
        "status_class" => status_class,
    )
    .increment(1);
    histogram!(CLOUD_EVENTS_PUBLISH_DURATION_SECONDS, "outcome" => outcome).record(latency_secs);
}

#[cfg(feature = "cloud-events-filter")]
/// Classify an HTTP status into a bounded metric label.
fn http_status_class(status: u16) -> &'static str {
    match status / 100 {
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

#[cfg(feature = "cloud-events-filter")]
/// Record one `CloudEvents` publication attempt.
pub(crate) fn record_cloud_events_attempt() {
    counter!(
        CLOUD_EVENTS_PUBLISH_TOTAL,
        "outcome" => "attempt",
        "failure_class" => "none",
        "status_class" => "none",
    )
    .increment(1);
}

#[cfg(feature = "cloud-events-filter")]
/// Record an event skipped before an outbound publication attempt.
pub(crate) fn record_cloud_events_skipped(reason: &'static str) {
    counter!(CLOUD_EVENTS_SKIPPED_TOTAL, "reason" => reason).increment(1);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

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
    fn record_distinguishes_request_and_selected_upstream_phases() {
        crate::test_utils::install_metrics_recorder();

        record_filter_duration("sel_phase_test", PHASE_REQUEST, STREAM_BODY, 0.001);
        record_filter_duration("sel_phase_test", PHASE_SELECTED_UPSTREAM, STREAM_BODY, 0.002);

        let rendered = crate::test_utils::render_metrics();
        assert_metric_labels(&rendered, "sel_phase_test", "request", "body");
        assert_metric_labels(&rendered, "sel_phase_test", "selected_upstream", "body");
    }

    #[test]
    fn phase_constants_have_expected_values() {
        assert_eq!(PHASE_REQUEST, "request", "PHASE_REQUEST label value");
        assert_eq!(PHASE_RESPONSE, "response", "PHASE_RESPONSE label value");
        assert_eq!(
            PHASE_SELECTED_UPSTREAM, "selected_upstream",
            "PHASE_SELECTED_UPSTREAM label value"
        );
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

    #[cfg(feature = "cloud-events-filter")]
    #[test]
    fn cloud_events_metrics_expose_operational_labels() {
        crate::test_utils::install_metrics_recorder();

        record_cloud_events_publish("success", "none", Some(204), 0.001);
        record_cloud_events_publish("failure", "http_status", Some(500), 0.002);
        record_cloud_events_skipped("size_limit");

        let rendered = crate::test_utils::render_metrics();
        assert!(rendered.contains("praxis_cloud_events_publish_total"));
        assert!(rendered.contains("outcome=\"success\""));
        assert!(rendered.contains("failure_class=\"http_status\""));
        assert!(rendered.contains("status_class=\"5xx\""));
        assert!(rendered.contains("praxis_cloud_events_skipped_total"));
        assert!(rendered.contains("reason=\"size_limit\""));
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

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
