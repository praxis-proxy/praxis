// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Prometheus metrics: recorder installation, HTTP/upstream/config metric
//! recording, and scrape rendering.

use std::sync::OnceLock;

use metrics::{SharedString, counter, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Counter for completed HTTP requests.
const HTTP_REQUESTS_TOTAL: &str = "praxis_http_requests_total";

/// Histogram for HTTP request duration in seconds.
const HTTP_REQUEST_DURATION_SECONDS: &str = "praxis_http_request_duration_seconds";

/// Histogram for HTTP request body size in bytes.
const HTTP_REQUEST_BODY_BYTES: &str = "praxis_http_request_body_bytes";

/// Histogram for HTTP response body size in bytes.
const HTTP_RESPONSE_BODY_BYTES: &str = "praxis_http_response_body_bytes";

/// Gauge for concurrent in-flight proxy sessions per listener.
///
/// For HTTP, each active request holds a guard for its lifetime (so the
/// series tracks in-flight requests more than raw TCP sockets). For TCP,
/// each accepted connection holds a guard while the session is open.
///
/// When multiple TCP listeners share one Pingora service group, the
/// `listener` label is resolved from the connection's local bind address
/// (see TCP proxy listener-name map).
const CONNECTIONS_ACTIVE: &str = "praxis_connections_active";

/// Counter for connections rejected by overload protection.
const OVERLOAD_REJECTS_TOTAL: &str = "praxis_overload_rejects_total";

/// Histogram for upstream connect duration in seconds.
const UPSTREAM_CONNECT_DURATION_SECONDS: &str = "praxis_upstream_connect_duration_seconds";

/// Counter for upstream connect failures.
const UPSTREAM_CONNECT_FAILURES_TOTAL: &str = "praxis_upstream_connect_failures_total";

/// Counter for upstream connect-failure retries.
const UPSTREAM_RETRIES_TOTAL: &str = "praxis_upstream_retries_total";

/// Gauge for healthy endpoints per cluster.
const UPSTREAM_HEALTHY_ENDPOINTS: &str = "praxis_upstream_healthy_endpoints";

/// Gauge for total endpoints per cluster.
const UPSTREAM_TOTAL_ENDPOINTS: &str = "praxis_upstream_total_endpoints";

/// Counter for endpoint health state transitions.
const UPSTREAM_HEALTH_TRANSITIONS_TOTAL: &str = "praxis_upstream_health_transitions_total";

/// Counter for config reload attempts.
const CONFIG_RELOAD_TOTAL: &str = "praxis_config_reload_total";

/// Gauge for unix timestamp of last successful config reload.
const CONFIG_RELOAD_LAST_SUCCESS_TIMESTAMP: &str = "praxis_config_reload_last_success_timestamp";

/// Overload reject reason: process memory pressure.
pub(crate) const OVERLOAD_REASON_MEMORY: &str = "memory";

/// Overload reject reason: process-wide connection limit.
pub(crate) const OVERLOAD_REASON_GLOBAL_CONNECTIONS: &str = "global_connections";

/// Overload reject reason: per-listener connection limit.
pub(crate) const OVERLOAD_REASON_LISTENER_CONNECTIONS: &str = "listener_connections";

/// Retry result: connect eventually succeeded after at least one retry.
pub(crate) const RETRY_RESULT_SUCCESS: &str = "success";

/// Retry result: retries gave up or were exhausted.
pub(crate) const RETRY_RESULT_EXHAUSTED: &str = "exhausted";

/// Health transition result: endpoint became healthy.
pub(crate) const HEALTH_RESULT_HEALTHY: &str = "healthy";

/// Health transition result: endpoint became unhealthy.
pub(crate) const HEALTH_RESULT_UNHEALTHY: &str = "unhealthy";

/// Config reload result: success.
pub(crate) const RELOAD_RESULT_SUCCESS: &str = "success";

/// Config reload result: failure.
pub(crate) const RELOAD_RESULT_FAILURE: &str = "failure";

/// Histogram bucket upper bounds for HTTP body sizes in bytes.
///
/// Defaults from `PrometheusBuilder` target request durations in seconds
/// (`0.005`…`10`), which collapse almost every body into `+Inf`.
const BODY_SIZE_BUCKETS_BYTES: &[f64] = &[
    64.0,
    256.0,
    1_024.0,
    4_096.0,
    16_384.0,
    65_536.0,
    262_144.0,
    1_048_576.0,
    10_485_760.0,
];

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
    #[expect(
        clippy::expect_used,
        reason = "recorder installation is a one-time startup operation"
    )]
    PROMETHEUS_HANDLE.get_or_init(|| {
        PrometheusBuilder::new()
            .set_buckets_for_metric(
                Matcher::Full(HTTP_REQUEST_BODY_BYTES.to_owned()),
                BODY_SIZE_BUCKETS_BYTES,
            )
            .expect("body request histogram buckets must be non-empty")
            .set_buckets_for_metric(
                Matcher::Full(HTTP_RESPONSE_BODY_BYTES.to_owned()),
                BODY_SIZE_BUCKETS_BYTES,
            )
            .expect("body response histogram buckets must be non-empty")
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

/// Returns `true` if the Prometheus recorder has been installed.
pub(crate) fn is_recorder_installed() -> bool {
    PROMETHEUS_HANDLE.get().is_some()
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
///
/// Static labels (`method`, `status_class`) use `&'static str`
/// so the metrics facade can intern them without per-request allocation.
/// `cluster` and `route` are dynamic [`SharedString`] values.
///
/// [`SharedString`]: ::metrics::SharedString
pub(crate) struct RequestMetricLabels {
    /// Cluster name or `"none"`.
    pub cluster: SharedString,
    /// HTTP method (e.g. `"GET"`).
    pub method: &'static str,
    /// Route path-match pattern or `"unknown"`.
    pub route: SharedString,
    /// Status class (e.g. `"2xx"`).
    pub status_class: &'static str,
}

/// Record HTTP request metrics for a completed request.
pub(crate) fn record_request_metrics(labels: RequestMetricLabels, duration_secs: f64) {
    let cluster = labels.cluster;
    let route = labels.route;
    counter!(
        HTTP_REQUESTS_TOTAL,
        "method" => labels.method,
        "status_class" => labels.status_class,
        "route" => route.clone(),
        "cluster" => cluster.clone()
    )
    .increment(1);
    histogram!(
        HTTP_REQUEST_DURATION_SECONDS,
        "method" => labels.method,
        "status_class" => labels.status_class,
        "route" => route,
        "cluster" => cluster
    )
    .record(duration_secs);
}

/// Record HTTP request and response body size histograms.
pub(crate) fn record_body_size_metrics(
    method: &'static str,
    status_class: &'static str,
    cluster: SharedString,
    request_body_bytes: u64,
    response_body_bytes: u64,
) {
    #[expect(
        clippy::cast_precision_loss,
        reason = "body byte counts as histogram observations; exact integer precision not required"
    )]
    {
        histogram!(
            HTTP_REQUEST_BODY_BYTES,
            "method" => method,
            "status_class" => status_class,
            "cluster" => cluster.clone()
        )
        .record(request_body_bytes as f64);
        histogram!(
            HTTP_RESPONSE_BODY_BYTES,
            "method" => method,
            "status_class" => status_class,
            "cluster" => cluster
        )
        .record(response_body_bytes as f64);
    }
}

/// Increment the active-connections gauge for a listener.
pub(crate) fn inc_connections_active(listener: SharedString) {
    if !is_recorder_installed() {
        return;
    }
    gauge!(CONNECTIONS_ACTIVE, "listener" => listener).increment(1.0);
}

/// Decrement the active-connections gauge for a listener.
pub(crate) fn dec_connections_active(listener: SharedString) {
    if !is_recorder_installed() {
        return;
    }
    gauge!(CONNECTIONS_ACTIVE, "listener" => listener).decrement(1.0);
}

/// RAII guard that decrements `praxis_connections_active` on drop.
///
/// Acquired once per HTTP request / TCP session. See the
/// `CONNECTIONS_ACTIVE` constant docs for HTTP vs TCP semantics and
/// grouped TCP listener labeling.
pub struct ActiveConnectionGuard {
    /// Listener name label.
    listener: SharedString,
}

impl ActiveConnectionGuard {
    /// Increment the gauge and return a guard that decrements on drop.
    pub(crate) fn acquire(listener: SharedString) -> Self {
        inc_connections_active(listener.clone());
        Self { listener }
    }
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        dec_connections_active(self.listener.clone());
    }
}

/// Record an overload rejection.
pub(crate) fn record_overload_reject(reason: &'static str) {
    if !is_recorder_installed() {
        return;
    }
    counter!(OVERLOAD_REJECTS_TOTAL, "reason" => reason).increment(1);
}

/// Record upstream connect duration for a cluster.
pub(crate) fn record_upstream_connect_duration(cluster: SharedString, duration_secs: f64) {
    if !is_recorder_installed() {
        return;
    }
    histogram!(UPSTREAM_CONNECT_DURATION_SECONDS, "cluster" => cluster).record(duration_secs);
}

/// Record an upstream connect failure.
pub(crate) fn record_upstream_connect_failure(cluster: SharedString) {
    if !is_recorder_installed() {
        return;
    }
    counter!(UPSTREAM_CONNECT_FAILURES_TOTAL, "cluster" => cluster).increment(1);
}

/// Record an upstream connect-failure retry outcome.
pub(crate) fn record_upstream_retry(cluster: SharedString, result: &'static str) {
    if !is_recorder_installed() {
        return;
    }
    counter!(UPSTREAM_RETRIES_TOTAL, "cluster" => cluster, "result" => result).increment(1);
}

/// Refresh cluster endpoint health gauges.
pub(crate) fn set_upstream_endpoint_gauges(cluster: SharedString, healthy: usize, total: usize) {
    if !is_recorder_installed() {
        return;
    }
    #[expect(clippy::cast_precision_loss, reason = "endpoint counts fit f64 exactly below 2^53")]
    {
        gauge!(UPSTREAM_HEALTHY_ENDPOINTS, "cluster" => cluster.clone()).set(healthy as f64);
        gauge!(UPSTREAM_TOTAL_ENDPOINTS, "cluster" => cluster).set(total as f64);
    }
}

/// Zero health gauges for clusters that lost active health checks on reload.
///
/// Prometheus does not drop series automatically; clearing removed clusters
/// prevents stale `healthy`/`total` values from lingering after config change.
pub fn clear_stale_upstream_health_gauges<'a>(
    previous_health_clusters: impl IntoIterator<Item = &'a str>,
    current_health_clusters: impl IntoIterator<Item = &'a str>,
) {
    if !is_recorder_installed() {
        return;
    }
    let current: std::collections::HashSet<&str> = current_health_clusters.into_iter().collect();
    for name in previous_health_clusters {
        if !current.contains(name) {
            set_upstream_endpoint_gauges(SharedString::from(name.to_owned()), 0, 0);
        }
    }
}

/// Publish current healthy/total gauges for every cluster in a health registry.
///
/// Called on reload so scrapes reflect the new registry immediately instead of
/// waiting for the first probe round.
pub fn seed_upstream_health_gauges(registry: &praxis_core::health::HealthRegistry) {
    if !is_recorder_installed() {
        return;
    }
    for (name, state) in registry.iter() {
        let (healthy, total) = state.endpoint_counts();
        set_upstream_endpoint_gauges(SharedString::from(name.as_ref().to_owned()), healthy, total);
    }
}

/// Record an endpoint health state transition and refresh gauges.
pub(crate) fn record_health_transition(cluster: SharedString, result: &'static str, healthy: usize, total: usize) {
    if !is_recorder_installed() {
        return;
    }
    counter!(
        UPSTREAM_HEALTH_TRANSITIONS_TOTAL,
        "cluster" => cluster.clone(),
        "result" => result
    )
    .increment(1);
    set_upstream_endpoint_gauges(cluster, healthy, total);
}

/// Count healthy endpoints in a cluster health entry.
pub(crate) fn count_healthy_endpoints(health: &praxis_core::health::ClusterHealthEntry) -> (usize, usize) {
    health.endpoint_counts()
}

/// Record a successful config reload.
pub fn record_config_reload_success() {
    if !is_recorder_installed() {
        return;
    }
    counter!(CONFIG_RELOAD_TOTAL, "result" => RELOAD_RESULT_SUCCESS).increment(1);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64());
    gauge!(CONFIG_RELOAD_LAST_SUCCESS_TIMESTAMP).set(ts);
}

/// Record a failed config reload.
pub fn record_config_reload_failure() {
    if !is_recorder_installed() {
        return;
    }
    counter!(CONFIG_RELOAD_TOTAL, "result" => RELOAD_RESULT_FAILURE).increment(1);
}

/// [`SharedString`] for the `"none"` cluster label.
///
/// [`SharedString`]: ::metrics::SharedString
pub(crate) fn cluster_none() -> SharedString {
    SharedString::const_str("none")
}

/// [`SharedString`] for the `"unknown"` route label.
///
/// [`SharedString`]: ::metrics::SharedString
pub(crate) fn route_unknown() -> SharedString {
    SharedString::const_str("unknown")
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
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

    #[test]
    fn record_helpers_noop_without_recorder() {
        // Must not panic when the Prometheus recorder is absent.
        record_overload_reject(OVERLOAD_REASON_MEMORY);
        record_upstream_connect_failure(cluster_none());
        record_upstream_retry(cluster_none(), RETRY_RESULT_SUCCESS);
        record_upstream_connect_duration(cluster_none(), 0.01);
        set_upstream_endpoint_gauges(cluster_none(), 1, 2);
        record_health_transition(cluster_none(), HEALTH_RESULT_HEALTHY, 1, 2);
        record_config_reload_success();
        record_config_reload_failure();
        clear_stale_upstream_health_gauges(["gone"], std::iter::empty::<&str>());
        let _guard = ActiveConnectionGuard::acquire(SharedString::const_str("test"));
    }

    #[test]
    fn overload_reject_reasons_appear_in_scrape() {
        install_prometheus_recorder();
        record_overload_reject(OVERLOAD_REASON_MEMORY);
        record_overload_reject(OVERLOAD_REASON_GLOBAL_CONNECTIONS);
        record_overload_reject(OVERLOAD_REASON_LISTENER_CONNECTIONS);
        let body = render_prometheus().expect("recorder should render");
        for reason in [
            OVERLOAD_REASON_MEMORY,
            OVERLOAD_REASON_GLOBAL_CONNECTIONS,
            OVERLOAD_REASON_LISTENER_CONNECTIONS,
        ] {
            let needle = format!("praxis_overload_rejects_total{{reason=\"{reason}\"}}");
            assert!(body.contains(&needle), "expected `{needle}` in scrape:\n{body}");
        }
    }

    #[test]
    fn body_size_histograms_use_byte_buckets() {
        install_prometheus_recorder();
        record_body_size_metrics("GET", "2xx", cluster_none(), 500, 4_000);
        let body = render_prometheus().expect("recorder should render");
        assert!(
            body.contains("praxis_http_request_body_bytes_bucket") && body.contains("le=\"1024\""),
            "request body histogram should use byte buckets, not duration defaults:\n{body}"
        );
        assert!(
            body.contains("praxis_http_response_body_bytes_bucket") && body.contains("le=\"4096\""),
            "response body histogram should use byte buckets:\n{body}"
        );
        assert!(
            !body.contains("praxis_http_request_body_bytes_bucket{le=\"0.005\"}")
                && !body.contains("praxis_http_request_body_bytes_bucket{method=\"GET\",status_class=\"2xx\",cluster=\"\",le=\"0.005\"}"),
            "request body histogram must not use duration default buckets:\n{body}"
        );
    }

    #[test]
    fn clear_stale_upstream_health_gauges_zeros_removed_clusters() {
        install_prometheus_recorder();
        set_upstream_endpoint_gauges(SharedString::from("old-cluster".to_owned()), 2, 3);
        set_upstream_endpoint_gauges(SharedString::from("kept-cluster".to_owned()), 1, 1);
        clear_stale_upstream_health_gauges(["old-cluster", "kept-cluster"], ["kept-cluster"]);
        let body = render_prometheus().expect("recorder should render");
        assert!(
            body.contains("praxis_upstream_healthy_endpoints{cluster=\"old-cluster\"} 0"),
            "removed cluster healthy gauge should be zeroed:\n{body}"
        );
        assert!(
            body.contains("praxis_upstream_total_endpoints{cluster=\"old-cluster\"} 0"),
            "removed cluster total gauge should be zeroed:\n{body}"
        );
        assert!(
            body.contains("praxis_upstream_healthy_endpoints{cluster=\"kept-cluster\"} 1"),
            "kept cluster should retain its value:\n{body}"
        );
    }

    #[test]
    fn seed_upstream_health_gauges_publishes_registry_counts() {
        use std::sync::Arc;

        use praxis_core::health::{ClusterHealthEntry, EndpointHealth};

        install_prometheus_recorder();
        let endpoints = vec![EndpointHealth::new(), EndpointHealth::new()];
        endpoints[0].mark_unhealthy();
        let entry = Arc::new(ClusterHealthEntry::new(
            endpoints,
            vec![Arc::from("a:1"), Arc::from("b:1")],
            None,
            None,
        ));
        let registry = Arc::new([(Arc::from("backend"), entry)].into_iter().collect());
        seed_upstream_health_gauges(&registry);
        let body = render_prometheus().expect("recorder should render");
        assert!(
            body.contains("praxis_upstream_healthy_endpoints{cluster=\"backend\"} 1"),
            "seed should publish healthy count:\n{body}"
        );
        assert!(
            body.contains("praxis_upstream_total_endpoints{cluster=\"backend\"} 2"),
            "seed should publish total count:\n{body}"
        );
    }

    #[test]
    fn count_healthy_endpoints_counts_correctly() {
        use std::sync::Arc;

        use praxis_core::health::{ClusterHealthEntry, EndpointHealth};

        let endpoints = vec![EndpointHealth::new(), EndpointHealth::new(), EndpointHealth::new()];
        endpoints[1].mark_unhealthy();
        let entry = ClusterHealthEntry::new(
            endpoints,
            vec![Arc::from("a:1"), Arc::from("b:1"), Arc::from("c:1")],
            None,
            None,
        );
        let (healthy, total) = count_healthy_endpoints(&entry);
        assert_eq!(total, 3, "total should be 3");
        assert_eq!(healthy, 2, "two endpoints should be healthy");
    }
}
