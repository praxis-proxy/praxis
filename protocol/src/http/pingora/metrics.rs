// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Prometheus metrics: recorder installation, HTTP request metric recording, and scrape rendering.

use std::sync::OnceLock;

use metrics::{counter, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Counter for completed HTTP requests.
const HTTP_REQUESTS_TOTAL: &str = "praxis_http_requests_total";

/// Histogram for HTTP request duration in seconds.
const HTTP_REQUEST_DURATION_SECONDS: &str = "praxis_http_request_duration_seconds";

// -----------------------------------------------------------------------------
// Recorder Installation
// -----------------------------------------------------------------------------

/// Global handle to the Prometheus exporter.
static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the global Prometheus metrics recorder.
///
/// Must be called exactly once during server startup. Subsequent
/// calls are no-ops and return the existing handle.
///
/// # Panics
///
/// Panics if the global recorder cannot be installed (another
/// recorder was already set by a different subsystem).
pub fn install_prometheus_recorder() -> &'static PrometheusHandle {
    #[allow(
        clippy::expect_used,
        reason = "recorder installation is a one-time startup operation"
    )]
    PROMETHEUS_HANDLE.get_or_init(|| {
        let builder = PrometheusBuilder::new();
        builder
            .install_recorder()
            .expect("failed to install Prometheus recorder")
    })
}

/// Render all collected metrics in Prometheus text exposition format.
///
/// Returns `None` if the recorder has not been installed.
pub fn render_prometheus() -> Option<String> {
    PROMETHEUS_HANDLE.get().map(PrometheusHandle::render)
}

// -----------------------------------------------------------------------------
// Status Class
// -----------------------------------------------------------------------------

/// Map an HTTP status code to its class label (`"1xx"`, `"2xx"`, etc.).
///
/// Returns `"unknown"` for zero (no response written) or codes
/// outside the 100–599 range.
///
/// ```
/// use praxis_protocol::http::pingora::metrics::status_class;
///
/// assert_eq!(status_class(200), "2xx");
/// assert_eq!(status_class(404), "4xx");
/// assert_eq!(status_class(0), "unknown");
/// ```
pub fn status_class(code: u16) -> &'static str {
    match code {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "unknown",
    }
}

/// Map an HTTP method to a bounded label value.
///
/// Returns the method string for the nine standard methods
/// defined in [RFC 9110]; all others collapse to `"OTHER"`.
///
/// ```
/// use praxis_protocol::http::pingora::metrics::method_label;
///
/// assert_eq!(method_label("GET"), "GET");
/// assert_eq!(method_label("PURGE"), "OTHER");
/// ```
///
/// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110#section-9.1
pub fn method_label(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "PATCH" => "PATCH",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "CONNECT" => "CONNECT",
        _ => "OTHER",
    }
}

// -----------------------------------------------------------------------------
// Metric Recording
// -----------------------------------------------------------------------------

/// Labels for a completed HTTP request.
pub struct RequestMetricLabels<'a> {
    /// HTTP method (e.g. `"GET"`).
    pub method: &'a str,
    /// Status class (e.g. `"2xx"`).
    pub status_class: &'a str,
    /// Route name or `"unknown"`.
    pub route: &'a str,
    /// Cluster name or `"none"`.
    pub cluster: &'a str,
}

/// Record HTTP request metrics for a completed request.
pub fn record_request_metrics(labels: &RequestMetricLabels<'_>, duration_secs: f64) {
    let label_set = [
        ("method", labels.method.to_owned()),
        ("status_class", labels.status_class.to_owned()),
        ("route", labels.route.to_owned()),
        ("cluster", labels.cluster.to_owned()),
    ];

    counter!(HTTP_REQUESTS_TOTAL, &label_set).increment(1);
    histogram!(HTTP_REQUEST_DURATION_SECONDS, &label_set).record(duration_secs);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn status_class_1xx() {
        assert_eq!(status_class(100), "1xx", "100 should be 1xx");
        assert_eq!(status_class(199), "1xx", "199 should be 1xx");
    }

    #[test]
    fn status_class_2xx() {
        assert_eq!(status_class(200), "2xx", "200 should be 2xx");
        assert_eq!(status_class(204), "2xx", "204 should be 2xx");
        assert_eq!(status_class(299), "2xx", "299 should be 2xx");
    }

    #[test]
    fn status_class_3xx() {
        assert_eq!(status_class(301), "3xx", "301 should be 3xx");
        assert_eq!(status_class(399), "3xx", "399 should be 3xx");
    }

    #[test]
    fn status_class_4xx() {
        assert_eq!(status_class(400), "4xx", "400 should be 4xx");
        assert_eq!(status_class(404), "4xx", "404 should be 4xx");
        assert_eq!(status_class(499), "4xx", "499 should be 4xx");
    }

    #[test]
    fn status_class_5xx() {
        assert_eq!(status_class(500), "5xx", "500 should be 5xx");
        assert_eq!(status_class(503), "5xx", "503 should be 5xx");
        assert_eq!(status_class(599), "5xx", "599 should be 5xx");
    }

    #[test]
    fn status_class_zero_is_unknown() {
        assert_eq!(status_class(0), "unknown", "0 should be unknown");
    }

    #[test]
    fn status_class_out_of_range_is_unknown() {
        assert_eq!(status_class(600), "unknown", "600 should be unknown");
        assert_eq!(status_class(99), "unknown", "99 should be unknown");
    }

    #[test]
    fn method_label_standard_methods() {
        for m in [
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT",
        ] {
            assert_eq!(method_label(m), m, "{m} should pass through");
        }
    }

    #[test]
    fn method_label_custom_methods_collapse_to_other() {
        assert_eq!(method_label("PURGE"), "OTHER", "PURGE should be OTHER");
        assert_eq!(method_label("FOOBAR"), "OTHER", "FOOBAR should be OTHER");
        assert_eq!(method_label(""), "OTHER", "empty should be OTHER");
    }
}
