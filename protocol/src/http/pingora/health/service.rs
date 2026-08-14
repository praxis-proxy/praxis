// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Admin health-check HTTP service.

use std::sync::Arc;

use async_trait::async_trait;
use http::Response;
use pingora_core::{
    apps::http_app::ServeHttp,
    protocols::http::ServerSession,
    server::Server,
    services::{
        background::{BackgroundService, background_service},
        listening::Service,
    },
};
use praxis_core::{health::HealthRegistry, kv::KvStoreRegistry};
use tokio::time::Duration;
use tracing::{error, info};

use super::{listener_meta::ListenerMetaStore, pipelines_admin};
use crate::http::pingora::{json::json_response, kv::dispatch_kv_request, metrics};

/// Recorder upkeep runs independently of Prometheus scrape traffic.
const PROMETHEUS_UPKEEP_INTERVAL: Duration = Duration::from_secs(5);

// -----------------------------------------------------------------------------
// JSON Escaping
// -----------------------------------------------------------------------------

/// Escape a string for safe inclusion in a JSON string value
/// per [RFC 8259 Section 7].
///
/// Escapes `\`, `"`, and all control characters (U+0000 through
/// U+001F). Uses short escapes for `\n`, `\r`, and `\t`; all other
/// control characters use `\uXXXX` format.
///
/// ```ignore
/// use praxis_protocol::http::pingora::health::escape_json_string;
///
/// assert_eq!(escape_json_string("simple"), "simple");
/// assert_eq!(escape_json_string(r#"a"b"#), r#"a\"b"#);
/// assert_eq!(escape_json_string("a\nb"), r"a\nb");
/// ```
///
/// [RFC 8259 Section 7]: https://datatracker.ietf.org/doc/html/rfc8259#section-7
pub(in crate::http::pingora) fn escape_json_string(s: &str) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() && (c as u32) <= 0x1F => {
                _ = write!(out, "\\u{:04x}", c as u32);
            },
            c => out.push(c),
        }
    }
    out
}

// -----------------------------------------------------------------------------
// PingoraHealthService
// -----------------------------------------------------------------------------

/// HTTP service for health check endpoints.
///
/// `/healthy` returns 200 once the server is accepting connections (liveness).
/// `/ready` returns cluster health details when a [`HealthRegistry`] is
/// present, or a simple `{"status":"ok"}` otherwise.
///
/// When `verbose` is `false` (default), `/ready` returns aggregate counts
/// only (total clusters, healthy, degraded) without cluster names.
/// When `verbose` is `true`, per-cluster detail is included.
///
/// [`HealthRegistry`]: praxis_core::health::HealthRegistry
///
/// ```ignore
/// use praxis_protocol::http::pingora::health::PingoraHealthService;
///
/// let _svc = PingoraHealthService::new(None, false);
/// ```
pub struct PingoraHealthService {
    /// Shared health registry for per-cluster status reporting.
    registry: Option<HealthRegistry>,

    /// When `true`, include per-cluster detail in `/ready` responses.
    verbose: bool,
}

impl PingoraHealthService {
    /// Create a health service with an optional health registry.
    ///
    /// When `verbose` is `true`, per-cluster detail is included
    /// in `/ready` responses.
    ///
    /// ```
    /// use praxis_protocol::http::pingora::health::PingoraHealthService;
    ///
    /// let svc = PingoraHealthService::new(None, false);
    /// assert_eq!(svc.ready_response().0, 200);
    /// ```
    pub fn new(registry: Option<HealthRegistry>, verbose: bool) -> Self {
        Self { registry, verbose }
    }

    /// Build the `/ready` response status and body.
    ///
    /// When a health registry is present, returns health status.
    /// In non-verbose mode (default), returns aggregate counts only
    /// (total, healthy, degraded) without cluster names. In verbose
    /// mode, includes per-cluster detail.
    ///
    /// ```
    /// use praxis_protocol::http::pingora::health::PingoraHealthService;
    ///
    /// let svc = PingoraHealthService::new(None, false);
    /// let (status, body) = svc.ready_response();
    /// assert_eq!(status, 200);
    /// assert!(body.contains("ok"));
    /// ```
    pub fn ready_response(&self) -> (u16, String) {
        compute_ready_response(self.registry.as_ref(), self.verbose)
    }
}

// -----------------------------------------------------------------------------
// PingoraAdminService
// -----------------------------------------------------------------------------

/// Combined admin service that routes health, metrics, and KV endpoints
/// through a single Pingora [`Service`].
///
/// Eliminates the port contention bug where separate services binding to
/// the same admin port via `SO_REUSEPORT` caused non-deterministic
/// connection routing (health probes hitting the KV service and getting 404).
///
/// [`Service`]: pingora_core::services::listening::Service
pub struct PingoraAdminService {
    /// Shared health registry for per-cluster status reporting.
    health_registry: Option<HealthRegistry>,

    /// Optional KV store registry for admin CRUD endpoints.
    kv_registry: Option<KvStoreRegistry>,

    /// Optional live pipelines + metadata for `GET /api/pipelines`.
    pipelines: Option<pipelines_admin::PipelinesAdminState>,

    /// When `true`, include per-cluster detail in `/ready` responses.
    verbose: bool,
}

impl PingoraAdminService {
    /// Create a combined admin service.
    ///
    /// `kv_registry` enables `/api/kv/*` endpoints when `Some`.
    /// `pipelines` enables `GET /api/pipelines` when `Some`.
    pub fn new(
        health_registry: Option<HealthRegistry>,
        kv_registry: Option<KvStoreRegistry>,
        pipelines: Option<(Arc<crate::ListenerPipelines>, ListenerMetaStore)>,
        verbose: bool,
    ) -> Self {
        Self {
            health_registry,
            kv_registry,
            pipelines: pipelines.map(|(pipelines, meta)| pipelines_admin::PipelinesAdminState { pipelines, meta }),
            verbose,
        }
    }

    /// Build the `/ready` response status and body.
    fn ready_response(&self) -> (u16, String) {
        compute_ready_response(self.health_registry.as_ref(), self.verbose)
    }
}

#[async_trait]
impl ServeHttp for PingoraAdminService {
    async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
        let req = http_session.req_header();
        let path = req.uri.path().to_owned();
        let method = req.method.as_str().to_owned();
        let query = req.uri.query().map(str::to_owned);

        if path.starts_with("/api/kv/") {
            if let Some(registry) = &self.kv_registry {
                return dispatch_kv_request(registry, http_session).await;
            }
            return json_response(404, br#"{"error":"not found"}"#);
        }

        if path == "/api/pipelines" {
            return match &self.pipelines {
                Some(state) => {
                    pipelines_admin::pipelines_response(&state.pipelines, &state.meta, &method, query.as_deref())
                },
                None => json_response(404, br#"{"error":"not found"}"#),
            };
        }

        match path.as_str() {
            "/healthy" => json_response(200, br#"{"status":"ok"}"#),
            "/metrics" => prometheus_response(),
            "/ready" => {
                let (status, body) = self.ready_response();
                json_response(status, body.as_bytes())
            },
            _ => json_response(404, br#"{"error":"not found"}"#),
        }
    }
}

/// Build an HTTP response containing Prometheus text exposition format.
///
/// Returns 200 with `text/plain; version=0.0.4` content type when the
/// recorder is installed, or 503 if it has not been initialised.
#[expect(clippy::expect_used, reason = "valid static response")]
fn prometheus_response() -> Response<Vec<u8>> {
    match metrics::render_prometheus() {
        Some(body) => Response::builder()
            .status(200)
            .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            .body(body.into_bytes())
            .expect("valid prometheus response"),
        None => Response::builder()
            .status(503)
            .header("Content-Type", "text/plain")
            .body(b"metrics recorder not installed\n".to_vec())
            .expect("valid error response"),
    }
}

/// Optional registries and flags for [`add_admin_endpoints_to_pingora_server`].
#[derive(Default)]
pub struct AdminEndpointOptions {
    /// Shared health registry for `/ready` cluster status.
    pub health_registry: Option<HealthRegistry>,

    /// Shared KV stores for `/api/kv/*`.
    pub kv_registry: Option<KvStoreRegistry>,

    /// Live pipelines + metadata for `GET /api/pipelines`.
    pub pipelines: Option<(Arc<crate::ListenerPipelines>, ListenerMetaStore)>,

    /// When `true`, include per-cluster detail in `/ready`.
    pub verbose: bool,
}

/// Pingora-managed recorder maintenance service.
struct PrometheusUpkeepService {
    /// Exporter handle used by each recorder maintenance pass.
    handle: metrics_exporter_prometheus::PrometheusHandle,
}

/// Recorder installed for the combined admin endpoint.
///
/// The concrete exporter handle stays private so applications cannot create a
/// second lifecycle for the recorder. Pass this value to
/// [`add_admin_endpoints_to_pingora_server_with_recorder`].
pub struct PrometheusAdminRecorder {
    /// Exporter handle shared by metrics rendering and recorder upkeep.
    handle: metrics_exporter_prometheus::PrometheusHandle,
}

/// Install the admin Prometheus recorder before startup instrumentation runs.
#[must_use]
pub fn install_prometheus_admin_recorder() -> PrometheusAdminRecorder {
    PrometheusAdminRecorder {
        handle: metrics::install_prometheus_recorder().clone(),
    }
}

#[async_trait]
impl BackgroundService for PrometheusUpkeepService {
    async fn start(&self, shutdown: pingora_core::server::ShutdownWatch) {
        let handle = self.handle.clone();
        run_prometheus_upkeep(
            shutdown,
            PROMETHEUS_UPKEEP_INTERVAL,
            Arc::new(move || handle.run_upkeep()),
        )
        .await;
    }
}

/// Closure used for one recorder maintenance pass.
type UpkeepFn = Arc<dyn Fn() + Send + Sync>;

/// Run non-overlapping upkeep passes until Pingora begins shutdown.
async fn run_prometheus_upkeep(
    mut shutdown: pingora_core::server::ShutdownWatch,
    interval: Duration,
    upkeep: UpkeepFn,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            () = tokio::time::sleep(interval) => {
                let upkeep = Arc::clone(&upkeep);
                let task = tokio::task::spawn_blocking(move || upkeep());
                tokio::select! {
                    // Dropping the JoinHandle does not cancel a pass that is already
                    // running, but shutdown remains responsive and no new pass is
                    // scheduled.
                    _ = shutdown.changed() => break,
                    result = task => {
                        if let Err(error) = result {
                            error!(?error, "Prometheus recorder upkeep task failed");
                        }
                    }
                }
            }
        }
    }
}

/// Add admin endpoints to a Pingora server.
///
/// Installs the global Prometheus metrics recorder and binds a
/// [`PingoraAdminService`] to `admin_addr`, exposing `/ready`,
/// `/healthy`, `/metrics`, (when `kv_registry` is `Some`)
/// `/api/kv/*`, and (when `pipelines` is `Some`) `GET /api/pipelines`
/// on a single port.
///
/// ```ignore
/// use pingora_core::server::Server;
/// use praxis_protocol::http::pingora::health::{
///     AdminEndpointOptions, add_admin_endpoints_to_pingora_server,
/// };
///
/// let mut server = Server::new(None).unwrap();
/// server.bootstrap();
/// add_admin_endpoints_to_pingora_server(
///     &mut server,
///     "127.0.0.1:9090",
///     AdminEndpointOptions::default(),
/// );
/// ```
pub fn add_admin_endpoints_to_pingora_server(server: &mut Server, admin_addr: &str, options: AdminEndpointOptions) {
    add_admin_endpoints_to_pingora_server_with_recorder(
        server,
        admin_addr,
        options,
        install_prometheus_admin_recorder(),
    );
}

/// Add admin endpoints using an already-installed Prometheus recorder.
///
/// This entry point lets applications install the recorder before
/// startup instrumentation begins while keeping `/metrics` and upkeep on the
/// same handle.
pub fn add_admin_endpoints_to_pingora_server_with_recorder(
    server: &mut Server,
    admin_addr: &str,
    options: AdminEndpointOptions,
    recorder: PrometheusAdminRecorder,
) {
    let verbose = options.verbose;
    let handle = recorder.handle;
    let upkeep = PrometheusUpkeepService { handle };
    server.add_service(background_service("Prometheus upkeep", upkeep));
    let admin = PingoraAdminService::new(options.health_registry, options.kv_registry, options.pipelines, verbose);
    let mut service = Service::new("admin".to_owned(), admin);
    service.add_tcp(admin_addr);
    info!(address = %admin_addr, verbose, "admin endpoints enabled (health + metrics + kv + pipelines)");
    server.add_service(service);
}

/// Backward-compatible alias for [`add_admin_endpoints_to_pingora_server`].
pub fn add_health_endpoint_to_pingora_server(
    server: &mut Server,
    admin_addr: &str,
    registry: Option<HealthRegistry>,
    verbose: bool,
) {
    add_admin_endpoints_to_pingora_server(
        server,
        admin_addr,
        AdminEndpointOptions {
            health_registry: registry,
            verbose,
            ..AdminEndpointOptions::default()
        },
    );
}

#[async_trait]
impl ServeHttp for PingoraHealthService {
    async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
        let path = http_session.req_header().uri.path().to_owned();

        match path.as_str() {
            "/healthy" => json_response(200, br#"{"status":"ok"}"#),
            "/metrics" => prometheus_response(),
            "/ready" => {
                let (status, body) = self.ready_response();
                json_response(status, body.as_bytes())
            },
            _ => json_response(404, br#"{"error":"not found"}"#),
        }
    }
}

// -----------------------------------------------------------------------------
// Ready Response
// -----------------------------------------------------------------------------

/// Build the `/ready` response status and body from a health registry.
///
/// Shared by [`PingoraHealthService`] and [`PingoraAdminService`].
fn compute_ready_response(registry: Option<&HealthRegistry>, verbose: bool) -> (u16, String) {
    let Some(registry) = registry else {
        return (200, r#"{"status":"ok"}"#.to_owned());
    };

    if registry.is_empty() {
        return (
            200,
            r#"{"status":"ok","clusters":{"total":0,"healthy":0,"degraded":0}}"#.to_owned(),
        );
    }

    let agg = aggregate_health(registry, verbose);
    let status_str = if agg.any_down { "degraded" } else { "ok" };
    let status_code: u16 = if agg.any_down { 503 } else { 200 };

    let body = format_ready_body(status_str, &agg);
    (status_code, body)
}

// -----------------------------------------------------------------------------
// Aggregation Utilities
// -----------------------------------------------------------------------------

/// Aggregated cluster health counts for `/ready` responses.
struct HealthAggregate {
    /// Total number of clusters.
    total: u32,

    /// Clusters with at least one healthy endpoint.
    healthy: u32,

    /// Clusters with zero healthy endpoints.
    degraded: u32,

    /// Whether any cluster has zero healthy endpoints.
    any_down: bool,

    /// Verbose per-cluster JSON detail (only when verbose mode is on).
    verbose_detail: Option<String>,
}

/// Walk the registry and compute aggregate counts.
fn aggregate_health(registry: &HealthRegistry, verbose: bool) -> HealthAggregate {
    let mut agg = HealthAggregate {
        total: 0,
        healthy: 0,
        degraded: 0,
        any_down: false,
        verbose_detail: verbose.then(|| String::from("{")),
    };
    let mut first = true;
    for (name, state) in registry.iter() {
        let (h, total) = state.endpoint_counts();
        agg.total += 1;
        if h == 0 {
            agg.any_down = true;
            agg.degraded += 1;
        } else {
            agg.healthy += 1;
        }
        append_verbose_detail(&mut agg.verbose_detail, &mut first, name, h, total);
    }
    if let Some(vj) = &mut agg.verbose_detail {
        vj.push('}');
    }
    agg
}

/// Append a single cluster's detail to the verbose JSON string.
fn append_verbose_detail(detail: &mut Option<String>, first: &mut bool, name: &str, healthy: usize, total: usize) {
    use std::fmt::Write as _;

    let Some(vj) = detail else { return };
    if !*first {
        vj.push(',');
    }
    *first = false;
    let escaped = escape_json_string(name);
    let unhealthy = total - healthy;
    _ = write!(
        vj,
        r#""{escaped}":{{"healthy":{healthy},"unhealthy":{unhealthy},"total":{total}}}"#,
    );
}

/// Format the ready response body from aggregated health data.
fn format_ready_body(status_str: &str, agg: &HealthAggregate) -> String {
    let (total, healthy, degraded) = (agg.total, agg.healthy, agg.degraded);
    if let Some(detail) = &agg.verbose_detail {
        format!(
            r#"{{"status":"{status_str}","clusters":{{"total":{total},"healthy":{healthy},"degraded":{degraded},"detail":{detail}}}}}"#,
        )
    } else {
        format!(
            r#"{{"status":"{status_str}","clusters":{{"total":{total},"healthy":{healthy},"degraded":{degraded}}}}}"#,
        )
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use praxis_core::health::{ClusterHealthEntry, EndpointHealth};
    use tokio::sync::Notify;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn prometheus_upkeep_waits_for_interval_and_does_not_catch_up() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let calls = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(Notify::new());
        let observed = Arc::clone(&calls);
        let observed_completed = Arc::clone(&completed);
        let task = tokio::spawn(run_prometheus_upkeep(
            shutdown_rx,
            Duration::from_secs(5),
            Arc::new(move || {
                observed.fetch_add(1, Ordering::SeqCst);
                observed_completed.notify_one();
            }),
        ));

        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 0, "upkeep must not run immediately");

        tokio::time::advance(Duration::from_secs(15)).await;
        completed.notified().await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "missed intervals must not queue passes"
        );

        shutdown_tx.send(true).unwrap();
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn prometheus_upkeep_stops_before_the_first_pass() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let task = tokio::spawn(run_prometheus_upkeep(
            shutdown_rx,
            Duration::from_secs(5),
            Arc::new(move || {
                observed.fetch_add(1, Ordering::SeqCst);
            }),
        ));

        shutdown_tx.send(true).unwrap();
        task.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn prometheus_upkeep_observes_shutdown_during_a_blocking_pass() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let started = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(AtomicUsize::new(0));
        let started_signal = Arc::new(Notify::new());
        let observed_started = Arc::clone(&started);
        let observed_release = Arc::clone(&release);
        let observed_signal = Arc::clone(&started_signal);
        let task = tokio::spawn(run_prometheus_upkeep(
            shutdown_rx,
            Duration::from_secs(5),
            Arc::new(move || {
                observed_started.store(1, Ordering::SeqCst);
                observed_signal.notify_one();
                while observed_release.load(Ordering::SeqCst) == 0 {
                    std::thread::yield_now();
                }
            }),
        ));

        tokio::time::advance(Duration::from_secs(5)).await;
        started_signal.notified().await;
        assert_eq!(started.load(Ordering::SeqCst), 1);

        shutdown_tx.send(true).unwrap();
        task.await.unwrap();
        release.store(1, Ordering::SeqCst);
    }

    #[test]
    fn json_response_200() {
        let resp = json_response(200, b"{}");
        assert_eq!(resp.status(), 200, "status should be 200");
        assert_eq!(
            resp.headers()["Content-Type"],
            "application/json",
            "content-type should be JSON"
        );
        assert_eq!(resp.body(), b"{}", "body should match input");
    }

    #[test]
    fn json_response_404() {
        let resp = json_response(404, br#"{"error":"not found"}"#);
        assert_eq!(resp.status(), 404, "status should be 404");
        assert_eq!(resp.body(), br#"{"error":"not found"}"#, "body should match input");
    }

    #[test]
    fn json_response_content_type_is_application_json() {
        let resp = json_response(503, b"{}");
        assert_eq!(
            resp.headers()["Content-Type"],
            "application/json",
            "content-type should be application/json"
        );
    }

    #[test]
    fn ready_no_registry_returns_200() {
        let svc = PingoraHealthService::new(None, false);
        let (status, body) = svc.ready_response();
        assert_eq!(status, 200, "no registry should return 200");
        assert!(body.contains("ok"), "body should contain ok");
    }

    #[test]
    fn ready_empty_registry_returns_200() {
        let registry: HealthRegistry = Arc::new(HashMap::new());
        let svc = PingoraHealthService::new(Some(registry), false);
        let (status, body) = svc.ready_response();
        assert_eq!(status, 200, "empty registry should return 200");
        assert!(body.contains("ok"), "body should contain ok");
        assert!(body.contains("clusters"), "body should contain clusters key");
    }

    #[test]
    fn ready_all_healthy_returns_200_aggregate() {
        let mut map = HashMap::new();
        map.insert(Arc::from("backend"), make_health_entry(2));
        let registry: HealthRegistry = Arc::new(map);
        let svc = PingoraHealthService::new(Some(registry), false);
        let (status, body) = svc.ready_response();
        assert_eq!(status, 200, "all-healthy should return 200");
        assert!(body.contains(r#""total":1"#), "should report 1 total cluster: {body}");
        assert!(
            body.contains(r#""healthy":1"#),
            "should report 1 healthy cluster: {body}"
        );
        assert!(body.contains(r#""degraded":0"#), "should report 0 degraded: {body}");
        assert!(
            !body.contains("backend"),
            "non-verbose should not contain cluster names: {body}"
        );
    }

    #[test]
    fn ready_all_healthy_verbose_returns_detail() {
        let mut map = HashMap::new();
        map.insert(Arc::from("backend"), make_health_entry(2));
        let registry: HealthRegistry = Arc::new(map);
        let svc = PingoraHealthService::new(Some(registry), true);
        let (status, body) = svc.ready_response();
        assert_eq!(status, 200, "all-healthy verbose should return 200");
        assert!(body.contains("backend"), "verbose should contain cluster names: {body}");
        assert!(body.contains("detail"), "verbose should contain detail key: {body}");
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&body);
        assert!(parsed.is_ok(), "output should be valid JSON: {body}");
    }

    #[test]
    fn ready_some_unhealthy_returns_200() {
        let mut map = HashMap::new();
        let entry = make_health_entry(2);
        entry.endpoints()[1].mark_unhealthy();
        map.insert(Arc::from("backend"), entry);
        let registry: HealthRegistry = Arc::new(map);
        let svc = PingoraHealthService::new(Some(registry), false);
        let (status, body) = svc.ready_response();
        assert_eq!(status, 200, "partial healthy should return 200");
        assert!(
            body.contains(r#""healthy":1"#),
            "should report 1 healthy cluster: {body}"
        );
        assert!(
            body.contains(r#""degraded":0"#),
            "partially healthy still counts as healthy: {body}"
        );
    }

    #[test]
    fn ready_all_unhealthy_returns_503() {
        let mut map = HashMap::new();
        let entry = make_health_entry(1);
        entry.endpoints()[0].mark_unhealthy();
        map.insert(Arc::from("backend"), entry);
        let registry: HealthRegistry = Arc::new(map);
        let svc = PingoraHealthService::new(Some(registry), false);
        let (status, body) = svc.ready_response();
        assert_eq!(status, 503, "all-unhealthy should return 503");
        assert!(body.contains("degraded"), "status should be degraded: {body}");
        assert!(body.contains(r#""degraded":1"#), "should report 1 degraded: {body}");
        assert!(
            !body.contains("backend"),
            "non-verbose should not contain cluster names: {body}"
        );
    }

    #[test]
    fn ready_multiple_clusters_one_down_returns_503() {
        let mut map = HashMap::new();
        map.insert(Arc::from("good"), make_health_entry(1));
        let bad = make_health_entry(1);
        bad.endpoints()[0].mark_unhealthy();
        map.insert(Arc::from("bad"), bad);
        let registry: HealthRegistry = Arc::new(map);
        let svc = PingoraHealthService::new(Some(registry), false);
        let (status, body) = svc.ready_response();
        assert_eq!(status, 503, "any cluster with zero healthy should trigger 503");
        assert!(body.contains(r#""total":2"#), "should report 2 total clusters: {body}");
        assert!(
            !body.contains("good"),
            "non-verbose should not contain cluster names: {body}"
        );
        assert!(
            !body.contains("bad"),
            "non-verbose should not contain cluster names: {body}"
        );
    }

    #[test]
    fn ready_verbose_escapes_cluster_names_with_special_chars() {
        let mut map = HashMap::new();
        map.insert(Arc::from(r#"back"end"#), make_health_entry(1));
        let registry: HealthRegistry = Arc::new(map);
        let svc = PingoraHealthService::new(Some(registry), true);
        let (_status, body) = svc.ready_response();
        assert!(
            body.contains(r#"back\"end"#),
            "cluster name with quotes should be escaped in verbose mode: {body}"
        );
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&body);
        assert!(parsed.is_ok(), "output should be valid JSON: {body}");
    }

    #[test]
    fn escape_json_string_handles_backslash() {
        assert_eq!(escape_json_string(r"a\b"), r"a\\b", "backslash should be escaped");
    }

    #[test]
    fn escape_json_string_handles_quote() {
        assert_eq!(escape_json_string(r#"a"b"#), r#"a\"b"#, "quote should be escaped");
    }

    #[test]
    fn escape_json_string_handles_newline_cr_tab() {
        assert_eq!(
            escape_json_string("a\nb\rc\td"),
            "a\\nb\\rc\\td",
            "newline, carriage return, tab should use short escapes"
        );
    }

    #[test]
    fn escape_json_string_handles_other_control_chars() {
        let input = String::from_utf8(vec![0x00, 0x01, 0x1F]).unwrap();
        let expected = ["\\u0000", "\\u0001", "\\u001f"].concat();
        assert_eq!(
            escape_json_string(&input),
            expected,
            "other control chars should use \\uXXXX format"
        );
    }

    #[test]
    fn escape_json_string_noop_for_plain() {
        assert_eq!(
            escape_json_string("simple"),
            "simple",
            "plain string should pass through"
        );
    }

    #[test]
    fn prometheus_response_returns_200_with_valid_content_type() {
        metrics::install_prometheus_recorder();
        ::metrics::counter!("praxis_test_prometheus_response_total").increment(1);
        let resp = prometheus_response();
        assert_eq!(resp.status(), 200, "should be 200 when recorder is installed");
        assert_eq!(
            resp.headers()["Content-Type"],
            "text/plain; version=0.0.4; charset=utf-8",
            "content-type should be Prometheus text format"
        );
        let body = std::str::from_utf8(resp.body()).expect("prometheus body should be valid UTF-8");
        assert!(!body.is_empty(), "prometheus body should not be empty");
        assert!(
            body.contains("praxis_test_prometheus_response_total"),
            "prometheus body should contain recorded test metric: {body}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`ClusterHealthState`] with `n` healthy endpoints for tests.
    fn make_health_entry(n: usize) -> praxis_core::health::ClusterHealthState {
        let eps: Vec<EndpointHealth> = (0..n).map(|_| EndpointHealth::new()).collect();
        let addrs: Vec<Arc<str>> = (0..n).map(|i| Arc::from(format!("10.0.0.{i}:80"))).collect();
        Arc::new(ClusterHealthEntry::new(eps, addrs, None, None))
    }
}
