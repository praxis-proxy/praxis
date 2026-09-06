// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Prometheus metrics: recorder installation, HTTP/upstream/config metric
//! recording, and scrape rendering.

use std::sync::OnceLock;

use metrics::{Label, SharedString, counter, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use praxis_core::config::{MetricLabel, MetricLabelsConfig};

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

/// Gauge for in-flight HTTP requests per listener.
///
/// Each active request holds an RAII guard for its lifetime, so the
/// decrement runs on every terminal path, including client aborts and
/// reset HTTP/2 streams. TCP connections are tracked separately by
/// `praxis_tcp_active_connections`.
const HTTP_ACTIVE_REQUESTS: &str = "praxis_http_active_requests";

/// Counter for connections rejected by overload protection.
const OVERLOAD_REJECTS_TOTAL: &str = "praxis_overload_rejects_total";

/// Counter for requests sent to upstream endpoints.
const UPSTREAM_REQUESTS_TOTAL: &str = "praxis_upstream_requests_total";

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

/// Counter for proxy errors not already counted by a dedicated metric.
const ERRORS_TOTAL: &str = "praxis_errors_total";

/// Error type: a filter rejected the request.
pub(crate) const ERROR_TYPE_FILTER_REJECT: &str = "filter_reject";

/// Error type: an upstream connect, read or write timed out.
pub(crate) const ERROR_TYPE_TIMEOUT: &str = "timeout";

/// Error type: the upstream could not be reached.
pub(crate) const ERROR_TYPE_UPSTREAM_UNAVAILABLE: &str = "upstream_unavailable";

/// Error type: the upstream was reached but the exchange failed.
pub(crate) const ERROR_TYPE_UPSTREAM_PROTOCOL: &str = "upstream_protocol";

/// Error type: the downstream client connection failed.
pub(crate) const ERROR_TYPE_DOWNSTREAM: &str = "downstream";

/// Error type: an internal proxy fault.
pub(crate) const ERROR_TYPE_INTERNAL: &str = "internal";

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

/// Label dimensions to emit, installed once at startup.
static LABEL_CONFIG: OnceLock<MetricLabelsConfig> = OnceLock::new();

/// Every dimension enabled: the default, and the fallback before install.
static ALL_LABELS: OnceLock<MetricLabelsConfig> = OnceLock::new();

/// Install the label dimensions to emit.
///
/// Must be called once during startup, before any metric is recorded.
/// Later calls are ignored: a gauge guard acquired before a change and
/// released after it would increment one series and decrement another.
pub fn install_metric_labels(labels: MetricLabelsConfig) {
    let _existing = LABEL_CONFIG.set(labels);
}

/// The installed label dimensions, defaulting to all enabled.
pub(crate) fn metric_labels() -> &'static MetricLabelsConfig {
    LABEL_CONFIG
        .get()
        .unwrap_or_else(|| ALL_LABELS.get_or_init(MetricLabelsConfig::default))
}

/// Build a label set, dropping the dimensions that are disabled.
///
/// Only reached when at least one dimension is off; the all-enabled path
/// uses the static-label macro form and allocates nothing.
fn selected_labels(pairs: &[(&'static str, Option<SharedString>)]) -> Vec<Label> {
    pairs
        .iter()
        .filter_map(|(name, value)| value.clone().map(|value| Label::new(*name, value)))
        .collect()
}

/// The value for a dimension, or `None` when that dimension is disabled.
fn label_if(enabled: bool, value: SharedString) -> Option<SharedString> {
    enabled.then_some(value)
}

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
// Stats snapshot (`GET /api/stats`)
// -----------------------------------------------------------------------------

/// Parsed operational counters for [`collect_stats_metrics`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatsMetricsSnapshot {
    /// In-flight HTTP requests per listener (`praxis_http_active_requests`).
    pub http_active_by_listener: std::collections::HashMap<String, u64>,
    /// Aggregate in-flight HTTP requests when the listener label is disabled.
    pub http_active_aggregate: Option<u64>,
    /// Open TCP sessions per listener (`praxis_tcp_active_connections`).
    pub tcp_active_by_listener: std::collections::HashMap<String, u64>,
    /// Aggregate open TCP sessions when the listener label is disabled.
    pub tcp_active_aggregate: Option<u64>,
    /// Upstream requests grouped by cluster (`praxis_upstream_requests_total`).
    pub upstream_requests_by_cluster: std::collections::HashMap<String, u64>,
    /// Aggregate upstream requests when the cluster label is disabled.
    pub upstream_requests_aggregate: Option<u64>,
    /// Upstream connect failures grouped by cluster.
    pub connect_failures_by_cluster: std::collections::HashMap<String, u64>,
    /// Aggregate upstream connect failures when the cluster label is disabled.
    pub connect_failures_aggregate: Option<u64>,
}

/// Extract operational counters needed by `/api/stats` from Prometheus text.
#[expect(clippy::too_many_lines, reason = "metric name dispatch table")]
pub fn collect_stats_metrics(prometheus_text: &str) -> StatsMetricsSnapshot {
    let mut snapshot = StatsMetricsSnapshot::default();
    for line in prometheus_text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, labels, value)) = parse_prometheus_sample(line) else {
            continue;
        };
        match name {
            HTTP_ACTIVE_REQUESTS => {
                if let Some(listener) = labels.get("listener") {
                    snapshot.http_active_by_listener.insert(listener.clone(), value);
                } else {
                    snapshot.http_active_aggregate = Some(value);
                }
            },
            "praxis_tcp_active_connections" => {
                if let Some(listener) = labels.get("listener") {
                    snapshot.tcp_active_by_listener.insert(listener.clone(), value);
                } else {
                    snapshot.tcp_active_aggregate = Some(value);
                }
            },
            UPSTREAM_REQUESTS_TOTAL => {
                if let Some(cluster) = labels.get("cluster") {
                    *snapshot
                        .upstream_requests_by_cluster
                        .entry(cluster.clone())
                        .or_insert(0) += value;
                } else {
                    snapshot.upstream_requests_aggregate =
                        Some(snapshot.upstream_requests_aggregate.unwrap_or(0) + value);
                }
            },
            UPSTREAM_CONNECT_FAILURES_TOTAL => {
                if let Some(cluster) = labels.get("cluster") {
                    *snapshot.connect_failures_by_cluster.entry(cluster.clone()).or_insert(0) += value;
                } else {
                    snapshot.connect_failures_aggregate =
                        Some(snapshot.connect_failures_aggregate.unwrap_or(0) + value);
                }
            },
            _ => {},
        }
    }
    snapshot
}

/// Parsed Prometheus sample: metric name, label map, and integer value.
type PrometheusSample<'a> = (&'a str, std::collections::HashMap<String, String>, u64);

/// Parse one Prometheus text sample line into metric name, labels, and value.
fn parse_prometheus_sample(line: &str) -> Option<PrometheusSample<'_>> {
    let (name_and_labels, value_str) = line.rsplit_once(' ')?;
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "Prometheus counter/gauge values are non-negative integers"
    )]
    let value = {
        let parsed = value_str.parse::<f64>().ok()?;
        parsed.round() as u64
    };
    let (name, labels) = if let Some((name, label_blob)) = name_and_labels.split_once('{') {
        let label_blob = label_blob.strip_suffix('}')?;
        (name, parse_prometheus_labels(label_blob))
    } else {
        (name_and_labels, std::collections::HashMap::new())
    };
    Some((name, labels, value))
}

/// Parse `{key="value",...}` label sets from Prometheus text exposition.
fn parse_prometheus_labels(input: &str) -> std::collections::HashMap<String, String> {
    let mut labels = std::collections::HashMap::new();
    let mut rest = input;
    while !rest.is_empty() {
        let Some((pair, tail)) = rest.split_once(',') else {
            if let Some((key, value)) = parse_prometheus_label_pair(rest) {
                labels.insert(key, value);
            }
            break;
        };
        if let Some((key, value)) = parse_prometheus_label_pair(pair) {
            labels.insert(key, value);
        }
        rest = tail;
    }
    labels
}

/// Parse one `key="value"` pair from a Prometheus label set fragment.
fn parse_prometheus_label_pair(pair: &str) -> Option<(String, String)> {
    let (key, value) = pair.split_once('=')?;
    let value = value.strip_prefix('"')?.strip_suffix('"')?;
    Some((key.to_owned(), value.to_owned()))
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

/// Build the enabled subset of the request-metric labels.
fn selected_request_labels(labels: RequestMetricLabels) -> Vec<Label> {
    let selected = metric_labels();
    let pairs = [
        (
            "method",
            label_if(
                selected.is_enabled(MetricLabel::Method),
                SharedString::const_str(labels.method),
            ),
        ),
        (
            "status_class",
            label_if(
                selected.is_enabled(MetricLabel::StatusClass),
                SharedString::const_str(labels.status_class),
            ),
        ),
        ("route", label_if(selected.is_enabled(MetricLabel::Route), labels.route)),
        (
            "cluster",
            label_if(selected.is_enabled(MetricLabel::Cluster), labels.cluster),
        ),
    ];
    selected_labels(&pairs)
}

/// Record HTTP request metrics for a completed request.
pub(crate) fn record_request_metrics(labels: RequestMetricLabels, duration_secs: f64) {
    if !is_recorder_installed() {
        return;
    }
    if !metric_labels().all_enabled() {
        let emitted = selected_request_labels(labels);
        counter!(HTTP_REQUESTS_TOTAL, emitted.clone()).increment(1);
        histogram!(HTTP_REQUEST_DURATION_SECONDS, emitted).record(duration_secs);
        return;
    }
    record_request_metrics_all_labels(labels, duration_secs);
}

/// Record request metrics with the full default label set.
///
/// Kept on the static-label macro form so the default configuration emits
/// exactly the series it did before label selection existed, with no
/// per-request allocation.
fn record_request_metrics_all_labels(labels: RequestMetricLabels, duration_secs: f64) {
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

/// Build the enabled subset of the body-size histogram labels.
fn selected_body_labels(method: &'static str, status_class: &'static str, cluster: SharedString) -> Vec<Label> {
    let selected = metric_labels();
    let pairs = [
        (
            "method",
            label_if(
                selected.is_enabled(MetricLabel::Method),
                SharedString::const_str(method),
            ),
        ),
        (
            "status_class",
            label_if(
                selected.is_enabled(MetricLabel::StatusClass),
                SharedString::const_str(status_class),
            ),
        ),
        ("cluster", label_if(selected.is_enabled(MetricLabel::Cluster), cluster)),
    ];
    selected_labels(&pairs)
}

/// Record body-size histograms with the full default label set.
fn record_body_size_all_labels(
    method: &'static str,
    status_class: &'static str,
    cluster: SharedString,
    request_bytes: f64,
    response_bytes: f64,
) {
    histogram!(
        HTTP_REQUEST_BODY_BYTES,
        "method" => method,
        "status_class" => status_class,
        "cluster" => cluster.clone()
    )
    .record(request_bytes);
    histogram!(
        HTTP_RESPONSE_BODY_BYTES,
        "method" => method,
        "status_class" => status_class,
        "cluster" => cluster
    )
    .record(response_bytes);
}

/// Record HTTP request and response body size histograms.
pub(crate) fn record_body_size_metrics(
    method: &'static str,
    status_class: &'static str,
    cluster: SharedString,
    request_body_bytes: u64,
    response_body_bytes: u64,
) {
    if !is_recorder_installed() {
        return;
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "body byte counts as histogram observations; exact integer precision not required"
    )]
    let (request_bytes, response_bytes) = (request_body_bytes as f64, response_body_bytes as f64);

    if !metric_labels().all_enabled() {
        let emitted = selected_body_labels(method, status_class, cluster);
        histogram!(HTTP_REQUEST_BODY_BYTES, emitted.clone()).record(request_bytes);
        histogram!(HTTP_RESPONSE_BODY_BYTES, emitted).record(response_bytes);
        return;
    }
    record_body_size_all_labels(method, status_class, cluster, request_bytes, response_bytes);
}

/// RAII guard that decrements `praxis_http_active_requests` on drop.
///
/// Acquired once per HTTP request. Pingora owns the request context by
/// value, so the drop runs on every terminal path (including a client
/// abort or an HTTP/2 stream reset, which skip the `logging` callback
/// entirely).
pub struct ActiveRequestGuard {
    /// Listener name label.
    listener: SharedString,
}

impl ActiveRequestGuard {
    /// Increment the gauge and return a guard that decrements on drop.
    pub(crate) fn acquire(listener: SharedString) -> Self {
        if is_recorder_installed() {
            if metric_labels().is_enabled(MetricLabel::Listener) {
                gauge!(HTTP_ACTIVE_REQUESTS, "listener" => listener.clone()).increment(1.0);
            } else {
                gauge!(HTTP_ACTIVE_REQUESTS).increment(1.0);
            }
        }
        Self { listener }
    }
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        if is_recorder_installed() {
            if metric_labels().is_enabled(MetricLabel::Listener) {
                gauge!(HTTP_ACTIVE_REQUESTS, "listener" => self.listener.clone()).decrement(1.0);
            } else {
                gauge!(HTTP_ACTIVE_REQUESTS).decrement(1.0);
            }
        }
    }
}

/// Record a proxy error.
///
/// Counted once per request, from the logging hook. Overload rejections and
/// upstream connect failures have dedicated counters and are not repeated
/// here; this counter covers the causes those miss.
pub(crate) fn record_error(error_type: &'static str) {
    if !is_recorder_installed() {
        return;
    }
    counter!(ERRORS_TOTAL, "type" => error_type).increment(1);
}

/// Classify a Pingora error into a bounded `type` label value.
///
/// Connect failures map to `upstream_unavailable` and are also counted by
/// `praxis_upstream_connect_failures_total`; the overlap is deliberate so
/// that `praxis_errors_total` is a complete error denominator on its own.
pub(crate) fn error_type_for(etype: &::pingora_core::ErrorType, source: &::pingora_core::ErrorSource) -> &'static str {
    use ::pingora_core::ErrorSource::{Downstream, Internal, Unset};

    if matches!(source, Downstream) {
        return ERROR_TYPE_DOWNSTREAM;
    }
    if is_timeout(etype) {
        return ERROR_TYPE_TIMEOUT;
    }
    if is_unreachable(etype) {
        return ERROR_TYPE_UPSTREAM_UNAVAILABLE;
    }
    if matches!(source, Internal | Unset) {
        return ERROR_TYPE_INTERNAL;
    }
    ERROR_TYPE_UPSTREAM_PROTOCOL
}

/// Whether the error is a connect, handshake, read or write timeout.
fn is_timeout(etype: &::pingora_core::ErrorType) -> bool {
    use ::pingora_core::ErrorType::{ConnectTimedout, ReadTimedout, TLSHandshakeTimedout, WriteTimedout};

    matches!(
        etype,
        ConnectTimedout | TLSHandshakeTimedout | ReadTimedout | WriteTimedout
    )
}

/// Whether the error means the upstream was never reached.
fn is_unreachable(etype: &::pingora_core::ErrorType) -> bool {
    use ::pingora_core::ErrorType::{BindError, ConnectError, ConnectNoRoute, ConnectRefused, SocketError};

    matches!(
        etype,
        ConnectRefused | ConnectNoRoute | ConnectError | BindError | SocketError
    )
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
    if metric_labels().is_enabled(MetricLabel::Cluster) {
        histogram!(UPSTREAM_CONNECT_DURATION_SECONDS, "cluster" => cluster).record(duration_secs);
    } else {
        histogram!(UPSTREAM_CONNECT_DURATION_SECONDS).record(duration_secs);
    }
}

/// Record a request that reached an upstream endpoint.
///
/// Counted once per request, from the logging hook, so a request retried
/// across endpoints increments once against the endpoint that answered
/// rather than once per attempt. Requests that never reached an upstream
/// (filter rejections, connect failures) are not counted here.
pub(crate) fn record_upstream_request(cluster: SharedString, endpoint: SharedString, status_class: &'static str) {
    if !is_recorder_installed() {
        return;
    }
    let selected = metric_labels();
    if !selected.all_enabled() {
        let pairs = [
            ("cluster", label_if(selected.is_enabled(MetricLabel::Cluster), cluster)),
            (
                "endpoint",
                label_if(selected.is_enabled(MetricLabel::Endpoint), endpoint),
            ),
            (
                "status_class",
                label_if(
                    selected.is_enabled(MetricLabel::StatusClass),
                    SharedString::const_str(status_class),
                ),
            ),
        ];
        counter!(UPSTREAM_REQUESTS_TOTAL, selected_labels(&pairs)).increment(1);
        return;
    }
    counter!(
        UPSTREAM_REQUESTS_TOTAL,
        "cluster" => cluster,
        "endpoint" => endpoint,
        "status_class" => status_class
    )
    .increment(1);
}

/// Record an upstream connect failure.
pub(crate) fn record_upstream_connect_failure(cluster: SharedString) {
    if !is_recorder_installed() {
        return;
    }
    if metric_labels().is_enabled(MetricLabel::Cluster) {
        counter!(UPSTREAM_CONNECT_FAILURES_TOTAL, "cluster" => cluster).increment(1);
    } else {
        counter!(UPSTREAM_CONNECT_FAILURES_TOTAL).increment(1);
    }
}

/// Record an upstream connect-failure retry outcome.
pub(crate) fn record_upstream_retry(cluster: SharedString, result: &'static str) {
    if !is_recorder_installed() {
        return;
    }
    if metric_labels().is_enabled(MetricLabel::Cluster) {
        counter!(UPSTREAM_RETRIES_TOTAL, "cluster" => cluster, "result" => result).increment(1);
    } else {
        counter!(UPSTREAM_RETRIES_TOTAL, "result" => result).increment(1);
    }
}

/// Refresh cluster endpoint health gauges.
///
/// The `cluster` label is structural here and is kept even when the
/// `cluster` dimension is disabled: these gauges are keyed by cluster and
/// set (not incremented), so dropping the label would collapse every
/// cluster onto one last-writer-wins series rather than merely lowering
/// cardinality. Disabling `cluster` therefore drops it from the additive
/// cluster metrics (counters and the connect-duration histogram) but not
/// from the per-cluster health gauges.
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
pub fn clear_stale_upstream_health_gauges<'a, P: IntoIterator<Item = &'a str>, C: IntoIterator<Item = &'a str>>(
    previous_health_clusters: P,
    current_health_clusters: C,
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
    if metric_labels().is_enabled(MetricLabel::Cluster) {
        counter!(
            UPSTREAM_HEALTH_TRANSITIONS_TOTAL,
            "cluster" => cluster.clone(),
            "result" => result
        )
        .increment(1);
    } else {
        counter!(UPSTREAM_HEALTH_TRANSITIONS_TOTAL, "result" => result).increment(1);
    }
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
        record_error(ERROR_TYPE_INTERNAL);
        record_upstream_request(cluster_none(), SharedString::const_str("10.0.0.1:80"), "2xx");
        record_upstream_retry(cluster_none(), RETRY_RESULT_SUCCESS);
        record_upstream_connect_duration(cluster_none(), 0.01);
        set_upstream_endpoint_gauges(cluster_none(), 1, 2);
        record_health_transition(cluster_none(), HEALTH_RESULT_HEALTHY, 1, 2);
        record_config_reload_success();
        record_config_reload_failure();
        clear_stale_upstream_health_gauges(["gone"], std::iter::empty::<&str>());
        let _request_guard = ActiveRequestGuard::acquire(SharedString::const_str("test"));
    }

    #[test]
    fn active_request_guard_returns_to_zero_on_drop() {
        install_prometheus_recorder();
        let listener = SharedString::const_str("active-request-guard-listener");
        let guard = ActiveRequestGuard::acquire(listener.clone());
        let held = render_prometheus().expect("recorder should render");
        assert!(
            held.contains("praxis_http_active_requests{listener=\"active-request-guard-listener\"} 1"),
            "gauge should read 1 while the guard is held:\n{held}"
        );
        drop(guard);
        let released = render_prometheus().expect("recorder should render");
        assert!(
            released.contains("praxis_http_active_requests{listener=\"active-request-guard-listener\"} 0"),
            "gauge should return to 0 once the guard drops:\n{released}"
        );
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
    fn upstream_requests_carry_cluster_endpoint_and_status_class() {
        install_prometheus_recorder();
        record_upstream_request(
            SharedString::const_str("api"),
            SharedString::const_str("10.0.0.7:8080"),
            "5xx",
        );
        let body = render_prometheus().expect("recorder should render");
        assert!(
            body.contains(
                "praxis_upstream_requests_total{cluster=\"api\",endpoint=\"10.0.0.7:8080\",status_class=\"5xx\"} 1"
            ),
            "counter should carry all three labels:\n{body}"
        );
    }

    #[test]
    fn selected_labels_drops_disabled_dimensions() {
        let pairs = [
            ("method", Some(SharedString::const_str("GET"))),
            ("route", None),
            ("cluster", Some(SharedString::const_str("api"))),
        ];
        let emitted = selected_labels(&pairs);
        let names: Vec<&str> = emitted.iter().map(Label::key).collect();
        assert_eq!(names, vec!["method", "cluster"], "a disabled dimension must be absent");
    }

    #[test]
    fn selected_labels_preserves_order_and_values() {
        let pairs = [
            ("cluster", Some(SharedString::const_str("api"))),
            ("endpoint", Some(SharedString::const_str("10.0.0.1:80"))),
        ];
        let emitted = selected_labels(&pairs);
        let rendered: Vec<(&str, &str)> = emitted.iter().map(|l| (l.key(), l.value())).collect();
        assert_eq!(
            rendered,
            vec![("cluster", "api"), ("endpoint", "10.0.0.1:80")],
            "enabled dimensions keep their order and values"
        );
    }

    #[test]
    fn label_if_gates_on_the_flag() {
        assert_eq!(
            label_if(true, SharedString::const_str("x")).as_deref(),
            Some("x"),
            "an enabled dimension keeps its value"
        );
        assert_eq!(
            label_if(false, SharedString::const_str("x")),
            None,
            "a disabled dimension yields no value"
        );
    }

    #[test]
    fn metric_labels_default_to_all_enabled() {
        assert!(
            metric_labels().all_enabled(),
            "without an explicit install every dimension must stay on, so the \
             recorders keep their allocation-free fast path"
        );
    }

    #[test]
    fn error_types_appear_in_scrape() {
        install_prometheus_recorder();
        for error_type in [
            ERROR_TYPE_FILTER_REJECT,
            ERROR_TYPE_TIMEOUT,
            ERROR_TYPE_UPSTREAM_UNAVAILABLE,
            ERROR_TYPE_UPSTREAM_PROTOCOL,
            ERROR_TYPE_DOWNSTREAM,
            ERROR_TYPE_INTERNAL,
        ] {
            record_error(error_type);
            let body = render_prometheus().expect("recorder should render");
            let needle = format!("praxis_errors_total{{type=\"{error_type}\"}}");
            assert!(body.contains(&needle), "expected `{needle}` in scrape:\n{body}");
        }
    }

    #[test]
    fn error_type_for_maps_pingora_errors_to_bounded_values() {
        use ::pingora_core::{ErrorSource, ErrorType};

        assert_eq!(
            error_type_for(&ErrorType::ConnectTimedout, &ErrorSource::Upstream),
            ERROR_TYPE_TIMEOUT,
            "connect timeout is a timeout"
        );
        assert_eq!(
            error_type_for(&ErrorType::ConnectRefused, &ErrorSource::Upstream),
            ERROR_TYPE_UPSTREAM_UNAVAILABLE,
            "a refused connect means the upstream was unreachable"
        );
        assert_eq!(
            error_type_for(&ErrorType::ReadError, &ErrorSource::Upstream),
            ERROR_TYPE_UPSTREAM_PROTOCOL,
            "a mid-exchange read error is a protocol failure"
        );
        assert_eq!(
            error_type_for(&ErrorType::ReadTimedout, &ErrorSource::Downstream),
            ERROR_TYPE_DOWNSTREAM,
            "downstream source wins over the error kind"
        );
        assert_eq!(
            error_type_for(&ErrorType::InternalError, &ErrorSource::Internal),
            ERROR_TYPE_INTERNAL,
            "internal source is an internal fault"
        );
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
    fn collect_stats_metrics_sums_cluster_counters() {
        let text = r#"
praxis_http_active_requests{listener="web"} 2
praxis_tcp_active_connections{listener="tcp-in"} 1
praxis_upstream_requests_total{cluster="backend",endpoint="127.0.0.1:1",status_class="2xx"} 3
praxis_upstream_requests_total{cluster="backend",endpoint="127.0.0.1:2",status_class="5xx"} 1
praxis_upstream_connect_failures_total{cluster="backend"} 2
"#;
        let snap = collect_stats_metrics(text);
        assert_eq!(
            snap.http_active_by_listener.get("web"),
            Some(&2),
            "HTTP active per listener should parse"
        );
        assert_eq!(
            snap.tcp_active_by_listener.get("tcp-in"),
            Some(&1),
            "TCP active per listener should parse"
        );
        assert_eq!(
            snap.upstream_requests_by_cluster.get("backend"),
            Some(&4),
            "upstream requests should sum by cluster"
        );
        assert_eq!(
            snap.connect_failures_by_cluster.get("backend"),
            Some(&2),
            "connect failures should parse by cluster"
        );
    }

    #[test]
    fn collect_stats_metrics_parses_unlabeled_upstream_counters() {
        let text = r#"
praxis_upstream_requests_total{status_class="2xx"} 5
praxis_upstream_connect_failures_total 2
"#;
        let snap = collect_stats_metrics(text);
        assert_eq!(
            snap.upstream_requests_aggregate,
            Some(5),
            "unlabeled upstream requests should aggregate"
        );
        assert_eq!(
            snap.connect_failures_aggregate,
            Some(2),
            "unlabeled connect failures should aggregate"
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
