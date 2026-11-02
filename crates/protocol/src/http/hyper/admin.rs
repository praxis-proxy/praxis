// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! hyper glue for the admin, health and metrics listeners.
//!
//! What the hyper backend supplies for the management surface, as the
//! Pingora glue does for Pingora: an [`AdminRequest`] view of a hyper
//! request, an HTTP/1 listener per management address that hands each
//! request to the backend-neutral handlers, and the registration of those
//! listeners and of the recorder upkeep task on the [`HyperRuntime`].
//!
//! [`AdminRequest`]: crate::http::health::AdminRequest
//! [`HyperRuntime`]: praxis_core::server::HyperRuntime

use std::{convert::Infallible, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, Uri, request::Parts};
use http_body_util::{BodyExt as _, Full};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    server::graceful::GracefulShutdown,
};
use praxis_core::{
    health::HealthRegistry,
    server::{HyperRuntime, hyper::ShutdownWatch},
};
use tokio::net::{TcpSocket, TcpStream};
use tracing::{debug, error, info};

use crate::{
    http::pingora::health::{
        AdminEndpointOptions, AdminRequest, BodyReadError, ListenerMetaStore, PROMETHEUS_UPKEEP_INTERVAL,
        PingoraAdminService, PingoraHealthService, PrometheusAdminRecorder, admin_host,
        install_prometheus_admin_recorder, run_prometheus_upkeep,
    },
    tcp::hyper::{LISTEN_BACKLOG, bind_listener_socket},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// How long an accept loop pauses after a failed `accept`, so a process out
/// of file descriptors does not spin on the error.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100); // 100 ms

/// How long a management client may take to send a request's headers.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5); // 5 s

// -----------------------------------------------------------------------------
// Runtime Registration
// -----------------------------------------------------------------------------

/// Bind the `/api/*` admin listener on the runtime.
///
/// When `admin_addr` is loopback, requests with a non-loopback `Host` are
/// rejected. Register recorder upkeep separately if `/api/stats` is enabled.
/// The address is bound here; one that cannot be bound is logged and the
/// listener skipped, and the rest of the server still starts.
///
/// ```
/// use praxis_core::{
///     config::{Config, DEFAULT_CONFIG},
///     server::{HyperRuntime, ServerRuntime as _},
/// };
/// use praxis_protocol::{
///     backend::admin::AdminEndpointOptions, http::hyper::admin::add_admin_api,
/// };
///
/// let config = Config::from_yaml(DEFAULT_CONFIG).unwrap();
/// let mut runtime = HyperRuntime::new(&config);
/// add_admin_api(&mut runtime, "127.0.0.1:0", AdminEndpointOptions::default());
/// runtime.run_with_shutdown(Box::pin(std::future::ready(())));
/// ```
pub fn add_admin_api(runtime: &mut HyperRuntime, admin_addr: &str, options: AdminEndpointOptions) {
    let Some(listener) = bind_listener("admin", admin_addr) else {
        return;
    };
    let verbose = options.verbose;
    let require_loopback_host = admin_host::is_loopback_host(admin_addr);
    let admin = PingoraAdminService::from_options(admin_addr, options);

    info!(
        address = %admin_addr,
        verbose,
        require_loopback_host,
        "admin endpoints enabled (kv + pipelines + log-level + stats)"
    );
    serve_on(runtime, "admin", listener, ManagementHandler::Admin(admin));
}

/// Add the health and metrics listener on the runtime, installing the
/// Prometheus recorder and its upkeep.
///
/// Use [`add_health_endpoint_with_pipelines`] when the caller already owns
/// the recorder's lifecycle.
pub fn add_health_endpoint(
    runtime: &mut HyperRuntime,
    metrics_addr: &str,
    registry: Option<HealthRegistry>,
    verbose: bool,
) {
    let recorder = install_prometheus_admin_recorder();
    add_prometheus_upkeep(runtime, recorder);
    add_health_endpoint_with_pipelines(runtime, metrics_addr, registry, verbose, None);
}

/// Add the health and metrics listener on the runtime with live pipeline
/// readiness, leaving the recorder lifecycle to the caller.
///
/// When `metrics_addr` is loopback, requests with a non-loopback `Host` are
/// rejected. The address is bound here; one that cannot be bound is logged
/// and the listener skipped.
///
/// ```
/// use praxis_core::{
///     config::{Config, DEFAULT_CONFIG},
///     server::{HyperRuntime, ServerRuntime as _},
/// };
/// use praxis_protocol::http::hyper::admin::add_health_endpoint_with_pipelines;
///
/// let config = Config::from_yaml(DEFAULT_CONFIG).unwrap();
/// let mut runtime = HyperRuntime::new(&config);
/// add_health_endpoint_with_pipelines(&mut runtime, "127.0.0.1:0", None, false, None);
/// runtime.run_with_shutdown(Box::pin(std::future::ready(())));
/// ```
pub fn add_health_endpoint_with_pipelines(
    runtime: &mut HyperRuntime,
    metrics_addr: &str,
    registry: Option<HealthRegistry>,
    verbose: bool,
    pipelines: Option<(Arc<crate::ListenerPipelines>, ListenerMetaStore)>,
) {
    let Some(listener) = bind_listener("metrics", metrics_addr) else {
        return;
    };
    let require_loopback_host = admin_host::is_loopback_host(metrics_addr);
    let health = PingoraHealthService::new(registry, verbose).require_loopback_host(require_loopback_host);
    let health = match pipelines {
        Some((pipelines, meta)) => health.with_live_pipelines(pipelines, meta),
        None => health,
    };

    info!(address = %metrics_addr, verbose, "metrics endpoints enabled (health + metrics)");
    serve_on(runtime, "metrics", listener, ManagementHandler::Health(health));
}

/// Register recorder upkeep on the runtime.
///
/// Install the recorder with [`install_prometheus_admin_recorder`] before
/// startup instrumentation runs, then hand it here; upkeep stops with the
/// runtime.
///
/// [`install_prometheus_admin_recorder`]: crate::http::health::install_prometheus_admin_recorder
pub fn add_prometheus_upkeep(runtime: &mut HyperRuntime, recorder: PrometheusAdminRecorder) {
    let handle = recorder.handle;
    runtime.add_service("Prometheus upkeep", move |shutdown| {
        run_prometheus_upkeep(
            shutdown,
            PROMETHEUS_UPKEEP_INTERVAL,
            Arc::new(move || handle.run_upkeep()),
        )
    });
}

// -----------------------------------------------------------------------------
// ManagementHandler
// -----------------------------------------------------------------------------

/// The backend-neutral handler a management listener serves.
enum ManagementHandler {
    /// The `/api/*` admin API.
    Admin(PingoraAdminService),

    /// The health and metrics endpoints.
    Health(PingoraHealthService),
}

impl ManagementHandler {
    /// Answer one request on this listener.
    async fn respond(&self, req: &mut HyperAdminRequest) -> Response<Vec<u8>> {
        match self {
            Self::Admin(admin) => admin.respond(req).await,
            Self::Health(health) => health.respond(req),
        }
    }
}

// -----------------------------------------------------------------------------
// Serving
// -----------------------------------------------------------------------------

/// Register the runtime service `name` that serves `handler` on `socket`.
fn serve_on(runtime: &mut HyperRuntime, name: &'static str, socket: TcpSocket, handler: ManagementHandler) {
    let handler = Arc::new(handler);
    runtime.add_required_service(name, move |shutdown| serve_management(name, socket, handler, shutdown));
}

/// Listen on `socket` and serve management connections until `shutdown`
/// flips, then let the requests in flight finish. `name` labels the
/// listener in logs.
async fn serve_management(
    name: &'static str,
    socket: TcpSocket,
    handler: Arc<ManagementHandler>,
    mut shutdown: ShutdownWatch,
) {
    let listener = match socket.listen(LISTEN_BACKLOG) {
        Ok(listener) => listener,
        Err(err) => {
            error!(listener = name, error = %err, "management listener could not listen; it will not accept");
            return;
        },
    };
    let builder = connection_builder();
    let connections = GracefulShutdown::new();

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => serve_connection(&builder, &connections, stream, &handler),
                Err(err) => {
                    error!(listener = name, error = %err, "management accept failed");
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                },
            },
        }
    }

    drop(listener);
    info!(
        listener = name,
        connections = connections.count(),
        "management listener stopped accepting"
    );
    connections.shutdown().await;
}

/// The HTTP/1 settings every management connection is served with.
fn connection_builder() -> http1::Builder {
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(true)
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    builder
}

/// Serve one management connection on its own task, watched by
/// `connections` so a shutdown lets its current request finish.
fn serve_connection(
    builder: &http1::Builder,
    connections: &GracefulShutdown,
    stream: TcpStream,
    handler: &Arc<ManagementHandler>,
) {
    let handler = Arc::clone(handler);
    let service = service_fn(move |req| {
        let handler = Arc::clone(&handler);
        async move { Ok::<_, Infallible>(respond(&handler, req).await) }
    });
    let connection = connections.watch(builder.serve_connection(TokioIo::new(stream), service));

    drop(tokio::spawn(async move {
        if let Err(err) = connection.await {
            debug!(error = %err, "management connection closed with an error");
        }
    }));
}

/// Answer one management request with `handler`.
async fn respond(handler: &ManagementHandler, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let (parts, body) = req.into_parts();
    let mut admin_req = HyperAdminRequest { body, parts };
    handler
        .respond(&mut admin_req)
        .await
        .map(|content| Full::new(Bytes::from(content)))
}

// -----------------------------------------------------------------------------
// HyperAdminRequest
// -----------------------------------------------------------------------------

/// A hyper request as the management handlers see it.
struct HyperAdminRequest {
    /// The request body, read only by the routes that take one.
    body: Incoming,

    /// The method, target and headers.
    parts: Parts,
}

impl AdminRequest for HyperAdminRequest {
    fn method(&self) -> &Method {
        &self.parts.method
    }

    fn uri(&self) -> &Uri {
        &self.parts.uri
    }

    fn headers(&self) -> &HeaderMap {
        &self.parts.headers
    }

    async fn read_body(&mut self, limit: usize) -> Result<Vec<u8>, BodyReadError> {
        let mut buf = Vec::new();

        while let Some(frame) = self.body.frame().await {
            let frame = frame.map_err(|err| BodyReadError::Io(err.to_string()))?;
            let Ok(chunk) = frame.into_data() else {
                continue;
            };
            if buf.len().saturating_add(chunk.len()) > limit {
                return Err(BodyReadError::TooLarge);
            }
            buf.extend_from_slice(&chunk);
        }

        Ok(buf)
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Bind the socket a management listener serves on; a failure is logged and
/// yields `None`.
fn bind_listener(name: &'static str, addr: &str) -> Option<TcpSocket> {
    match bind_listener_socket(addr) {
        Ok(socket) => Some(socket),
        Err(err) => {
            error!(
                listener = name, address = %addr, error = %err,
                "failed to bind the management listener; it is disabled"
            );
            None
        },
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
        io::{Read as _, Write as _},
        net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream},
        thread,
        time::Instant,
    };

    use praxis_core::{
        config::Config,
        health::{ClusterHealthEntry, EndpointHealth},
        kv::KvStoreRegistry,
        server::ServerRuntime as _,
    };
    use tokio::sync::oneshot;

    use super::*;
    use crate::http::health::{ProcessVersionInfo, StatsAdminState, new_cluster_meta_store, new_listener_meta_store};

    #[test]
    fn health_listener_serves_liveness_and_readiness() {
        let addr = free_addr();
        let mut runtime = empty_runtime();
        add_health_endpoint_with_pipelines(&mut runtime, &addr, None, false, None);
        let _running = start(runtime);

        let healthy = get(&addr, "/healthy");
        let ready = get(&addr, "/ready");

        assert_eq!(healthy.status, 200, "/healthy must be 200");
        assert_eq!(
            healthy.body, br#"{"status":"ok"}"#,
            "/healthy must carry the JSON status"
        );
        assert_eq!(ready.status, 200, "/ready without a registry must be 200");
        assert!(
            healthy.head.contains("content-type: application/json"),
            "the handler's headers must reach the client:\n{}",
            healthy.head
        );
    }

    #[test]
    fn health_listener_relays_degraded_readiness() {
        let entry = ClusterHealthEntry::new(vec![EndpointHealth::new()], vec![Arc::from("10.0.0.1:80")], None, None);
        entry.endpoints()[0].mark_unhealthy();
        let degraded: HealthRegistry = Arc::new([(Arc::from("backend"), Arc::new(entry))].into_iter().collect());
        let addr = free_addr();
        let mut runtime = empty_runtime();
        add_health_endpoint_with_pipelines(&mut runtime, &addr, Some(degraded), false, None);
        let _running = start(runtime);

        let ready = get(&addr, "/ready");

        assert_eq!(ready.status, 503, "a fully degraded cluster must make /ready 503");
        assert!(
            String::from_utf8_lossy(&ready.body).contains("degraded"),
            "the 503 must carry the handler's body"
        );
    }

    #[test]
    fn readiness_follows_a_cluster_from_degraded_to_recovered() {
        let entry = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new()],
            vec![Arc::from("10.0.0.1:80")],
            None,
            None,
        ));
        entry.endpoints()[0].mark_unhealthy();
        let registry: HealthRegistry = Arc::new([(Arc::from("backend"), Arc::clone(&entry))].into_iter().collect());
        let addr = free_addr();
        let mut runtime = empty_runtime();
        add_health_endpoint_with_pipelines(&mut runtime, &addr, Some(registry), false, None);
        let _running = start(runtime);

        let degraded = get(&addr, "/ready");
        entry.endpoints()[0].mark_healthy();
        let recovered = get(&addr, "/ready");

        assert_eq!(
            degraded.status, 503,
            "/ready must be 503 while the cluster has no healthy endpoint"
        );
        assert_eq!(recovered.status, 200, "/ready must be 200 once the endpoint recovers");
    }

    #[test]
    fn health_endpoint_installs_the_recorder_and_serves_metrics() {
        let addr = free_addr();
        let mut runtime = empty_runtime();
        add_health_endpoint(&mut runtime, &addr, None, false);
        let _running = start(runtime);

        let metrics = get(&addr, "/metrics");

        assert_eq!(
            metrics.status, 200,
            "/metrics must be 200 once the recorder is installed"
        );
        assert!(
            metrics.head.contains("content-type: text/plain; version=0.0.4"),
            "/metrics must be Prometheus text:\n{}",
            metrics.head
        );
    }

    #[test]
    fn admin_listener_serves_stats() {
        let addr = free_addr();
        let options = AdminEndpointOptions {
            stats: Some(StatsAdminState {
                started_at: Instant::now(),
                version: ProcessVersionInfo {
                    semver: "0.0.0".to_owned(),
                    display: "0.0.0".to_owned(),
                    git_sha: None,
                },
                listener_meta: new_listener_meta_store(HashMap::new()),
                cluster_meta: new_cluster_meta_store(HashMap::new()),
            }),
            ..AdminEndpointOptions::default()
        };
        let mut runtime = empty_runtime();
        add_admin_api(&mut runtime, &addr, options);
        let _running = start(runtime);

        let stats = get(&addr, "/api/stats");

        assert_eq!(stats.status, 200, "/api/stats must be 200 when stats are enabled");
        assert!(
            String::from_utf8_lossy(&stats.body).contains("\"uptime_secs\""),
            "/api/stats must carry the snapshot"
        );
    }

    #[test]
    fn admin_listener_reads_kv_bodies_within_the_limit() {
        let (addr, registry, _running) = kv_admin();

        let put = request(&addr, &put_kv("/api/kv/test/color", b"red"));

        assert_eq!(put.status, 200, "a small PUT must be stored");
        assert_eq!(
            registry.get("test").unwrap().get("color").as_deref(),
            Some("red"),
            "the PUT body must reach the store"
        );
    }

    #[test]
    fn admin_listener_rejects_an_oversized_kv_body_with_413() {
        let (addr, registry, _running) = kv_admin();
        let oversized = vec![b'x'; OVERSIZED_KV_BODY_BYTES];

        let put = request(&addr, &put_kv("/api/kv/test/color", &oversized));

        assert_eq!(put.status, 413, "a body over the KV limit must be 413");
        assert_eq!(
            registry.get("test").unwrap().get("color").as_deref(),
            Some("blue"),
            "a rejected PUT must leave the store untouched"
        );
    }

    #[test]
    fn admin_listener_survives_clients_that_leave_mid_request() {
        let (addr, registry, _running) = kv_admin();
        let mut half_head = connect(&addr);
        half_head
            .write_all(b"GET /api/kv/test/color HTTP/1.1\r\nHost: local")
            .unwrap();
        drop(half_head);
        let mut half_body = connect(&addr);
        half_body
            .write_all(b"PUT /api/kv/test/color HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\ngre")
            .unwrap();
        drop(half_body);

        let after = get(&addr, "/api/kv/test/color");

        assert_eq!(
            after.status, 200,
            "the listener must keep serving after abandoned requests"
        );
        assert_eq!(
            registry.get("test").unwrap().get("color").as_deref(),
            Some("blue"),
            "an abandoned PUT must not store part of its body"
        );
    }

    #[test]
    fn loopback_listeners_reject_a_non_loopback_host_with_421() {
        let (admin_addr, _registry, _admin) = kv_admin();
        let metrics_addr = free_addr();
        let mut runtime = empty_runtime();
        add_health_endpoint_with_pipelines(&mut runtime, &metrics_addr, None, false, None);
        let _metrics = start(runtime);

        for (addr, path) in [(&admin_addr, "/api/kv/test"), (&metrics_addr, "/healthy")] {
            let raw = format!("GET {path} HTTP/1.1\r\nHost: attacker.example\r\nConnection: close\r\n\r\n");
            let rebound = request(addr, raw.as_bytes());
            assert_eq!(rebound.status, 421, "GET {path} with a rebound Host must be 421");
        }
    }

    #[test]
    fn unbindable_address_skips_the_listener() {
        let occupied = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let addr = occupied.local_addr().unwrap().to_string();
        let mut runtime = empty_runtime();

        add_health_endpoint_with_pipelines(&mut runtime, &addr, None, false, None);
        add_admin_api(&mut runtime, &addr, AdminEndpointOptions::default());

        assert!(
            !format!("{runtime:?}").contains("name: \""),
            "a listener that cannot bind must not register a service: {runtime:?}"
        );
    }

    #[test]
    fn prometheus_upkeep_stops_with_the_runtime() {
        let mut runtime = empty_runtime();
        add_prometheus_upkeep(&mut runtime, install_prometheus_admin_recorder());
        let stopping = Instant::now();

        drop(start(runtime));

        assert!(
            stopping.elapsed() < Duration::from_secs(5),
            "the upkeep service must stop on the shutdown watch"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A KV request body one byte over the admin API's 1 MiB limit.
    const OVERSIZED_KV_BODY_BYTES: usize = 1_048_577; // 1 MiB + 1

    /// A parsed HTTP/1 response.
    struct Reply {
        /// The response body.
        body: Vec<u8>,

        /// The status line and headers, lowercased.
        head: String,

        /// The status code.
        status: u16,
    }

    /// A `HyperRuntime` serving on its own thread until dropped.
    struct Running {
        /// Resolves the runtime's shutdown future.
        stop: Option<oneshot::Sender<()>>,

        /// The thread `run_with_shutdown` blocks.
        thread: Option<thread::JoinHandle<()>>,
    }

    impl Drop for Running {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                _ = stop.send(());
            }
            if let Some(thread) = self.thread.take() {
                drop(thread.join());
            }
        }
    }

    /// Connect to `addr` once its listener is up, with a read timeout so a
    /// broken listener fails the test instead of hanging it.
    #[expect(clippy::disallowed_methods, reason = "blocking test utility, not async")]
    fn connect(addr: &str) -> StdTcpStream {
        let started = Instant::now();
        let stream = loop {
            match StdTcpStream::connect(addr) {
                Ok(stream) => break stream,
                Err(err) => {
                    assert!(
                        started.elapsed() < Duration::from_secs(5),
                        "{addr} never started listening: {err}"
                    );
                    thread::sleep(Duration::from_millis(10));
                },
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        stream
    }

    /// A runtime with two worker threads and nothing registered.
    fn empty_runtime() -> HyperRuntime {
        let config = Config::from_yaml(&format!(
            "{}\nruntime:\n  threads: 2\n",
            praxis_core::config::DEFAULT_CONFIG
        ))
        .unwrap();
        HyperRuntime::new(&config)
    }

    /// A loopback address with a port nothing is listening on right now.
    fn free_addr() -> String {
        let probe = StdTcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().to_string()
    }

    /// `GET path` on `addr` with a loopback `Host`.
    fn get(addr: &str, path: &str) -> Reply {
        let raw = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        request(addr, raw.as_bytes())
    }

    /// Start an admin listener whose `test` KV store holds `color=blue`.
    fn kv_admin() -> (String, KvStoreRegistry, Running) {
        let registry = KvStoreRegistry::new();
        registry.get_or_create_memory("test").set("color", Arc::from("blue"));
        let addr = free_addr();
        let options = AdminEndpointOptions {
            kv_registry: Some(registry.clone()),
            ..AdminEndpointOptions::default()
        };
        let mut runtime = empty_runtime();
        add_admin_api(&mut runtime, &addr, options);
        (addr, registry, start(runtime))
    }

    /// A raw `PUT` of `body` to `path` with a loopback `Host`.
    fn put_kv(path: &str, body: &[u8]) -> Vec<u8> {
        let len = body.len();
        let mut raw =
            format!("PUT {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n")
                .into_bytes();
        raw.extend_from_slice(body);
        raw
    }

    /// Send `raw` to `addr` and read the response until the server closes.
    fn request(addr: &str, raw: &[u8]) -> Reply {
        let mut stream = connect(addr);
        stream.write_all(raw).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();

        let split = response.windows(4).position(|window| window == b"\r\n\r\n").unwrap();
        let head = String::from_utf8_lossy(&response[..split]).to_ascii_lowercase();
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        Reply {
            body: response[split.saturating_add(4)..].to_vec(),
            head,
            status,
        }
    }

    /// Run `runtime` on its own thread until the returned guard drops.
    fn start(runtime: HyperRuntime) -> Running {
        let (stop, stopped) = oneshot::channel::<()>();
        let thread = thread::spawn(move || {
            runtime.run_with_shutdown(Box::pin(async move {
                _ = stopped.await;
            }));
        });
        Running {
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}
