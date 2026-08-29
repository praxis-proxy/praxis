// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Background health check runner that probes endpoints on a timer.

use std::{sync::Arc, time::Duration};

use praxis_core::{
    config::{Cluster, HealthCheckType},
    health::{ClusterHealthState, HealthRegistry},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace};

use super::probe::tcp_probe;

// -----------------------------------------------------------------------------
// HealthCheckParams
// -----------------------------------------------------------------------------

/// Bundled parameters for a single cluster's health check loop.
struct HealthCheckParams {
    /// Human-readable cluster name for logging.
    cluster_name: Arc<str>,

    /// Endpoint addresses to probe.
    endpoints: Vec<String>,

    /// Probe type: [`Http`] or [`Tcp`].
    ///
    /// [`Http`]: HealthCheckType::Http
    /// [`Tcp`]: HealthCheckType::Tcp
    check_type: HealthCheckType,

    /// Pre-built HTTP probe request bytes (ignored for TCP).
    http_request: String,

    /// Expected HTTP status code (ignored for TCP).
    expected_status: u16,

    /// Time between probe rounds.
    interval: Duration,

    /// Per-endpoint probe timeout.
    timeout: Duration,

    /// Consecutive successes needed to mark healthy.
    healthy_threshold: u32,

    /// Consecutive failures needed to mark unhealthy.
    unhealthy_threshold: u32,

    /// Shared health state for all endpoints in this cluster.
    state: ClusterHealthState,
}

// -----------------------------------------------------------------------------
// Runner
// -----------------------------------------------------------------------------

/// Spawn background health check tasks for all clusters that have health checks configured.
///
/// ```ignore
/// use praxis_core::{config::Cluster, health::build_health_registry};
/// use praxis_protocol::http::pingora::health::runner::spawn_health_checks;
/// use tokio_util::sync::CancellationToken;
///
/// let clusters: Vec<Cluster> = vec![];
/// let registry = build_health_registry(&clusters);
/// let shutdown = CancellationToken::new();
/// spawn_health_checks(&clusters, &registry, &shutdown);
/// ```
pub fn spawn_health_checks(clusters: &[Cluster], registry: &HealthRegistry, shutdown: &CancellationToken) {
    for cluster in clusters {
        let Some(hc) = &cluster.health_check else {
            continue;
        };
        let Some(state) = registry.get(&cluster.name) else {
            continue;
        };

        info!(
            cluster = %cluster.name,
            check_type = %hc.check_type,
            interval_ms = hc.interval_ms,
            timeout_ms = hc.timeout_ms,
            endpoints = cluster.endpoints.len(),
            "spawning health check task"
        );

        let params = build_health_params(cluster, hc, state);
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            run_health_check_loop(&params, shutdown).await;
        });
    }
}

/// Build [`HealthCheckParams`] from a cluster and its health config.
fn build_health_params(
    cluster: &Cluster,
    hc: &praxis_core::config::HealthCheckConfig,
    state: &ClusterHealthState,
) -> HealthCheckParams {
    HealthCheckParams {
        cluster_name: Arc::clone(&cluster.name),
        endpoints: cluster.endpoints.iter().map(|e| e.address().to_owned()).collect(),
        check_type: hc.check_type,
        // The probe request only varies with the configured path, so it
        // is built once per task rather than per probe.
        http_request: crate::http::pingora::health::probe::build_http_probe_request(&hc.path),
        expected_status: hc.expected_status,
        interval: Duration::from_millis(hc.interval_ms),
        timeout: Duration::from_millis(hc.timeout_ms),
        healthy_threshold: hc.healthy_threshold,
        unhealthy_threshold: hc.unhealthy_threshold,
        state: Arc::clone(state),
    }
}

/// Main loop for a single cluster's health check task.
async fn run_health_check_loop(params: &HealthCheckParams, shutdown: CancellationToken) {
    debug!(cluster = %params.cluster_name, "health check loop started");

    probe_all_endpoints(params, &shutdown).await;

    let mut ticker = tokio::time::interval(params.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;

    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                info!(cluster = %params.cluster_name, "health check shutting down");
                return;
            }
            _ = ticker.tick() => {
                probe_all_endpoints(params, &shutdown).await;
            }
        }
    }
}

/// Probe all endpoints in a cluster and update health state.
///
/// Returns early without recording further results once `shutdown` is
/// cancelled so a respawned health registry cannot be overwritten by
/// in-flight probes from the previous generation.
async fn probe_all_endpoints(params: &HealthCheckParams, shutdown: &CancellationToken) {
    use futures::stream::{FuturesUnordered, StreamExt as _};

    let futures: FuturesUnordered<_> = params
        .endpoints
        .iter()
        .enumerate()
        .map(|(idx, addr)| spawn_probe(idx, addr, params))
        .collect();

    futures::pin_mut!(futures);
    while let Some((idx, addr, success)) = futures.next().await {
        if shutdown.is_cancelled() {
            debug!(
                cluster = %params.cluster_name,
                "discarding remaining probe results after health check shutdown"
            );
            return;
        }
        record_probe_result(params, idx, addr, success);
    }

    // Refresh the aggregate gauges once per completed round; writing
    // them per endpoint repeated the same registry lookups and health
    // scan E times per interval. Transitions still record immediately.
    refresh_endpoint_gauges(params);
}

/// Spawn a single endpoint probe future.
async fn spawn_probe<'ep>(idx: usize, addr: &'ep str, params: &HealthCheckParams) -> (usize, &'ep str, bool) {
    debug!(
        cluster = %params.cluster_name,
        endpoint = %addr,
        check_type = %params.check_type,
        "probing health check endpoint"
    );
    let success = match params.check_type {
        HealthCheckType::Http => {
            crate::http::pingora::health::probe::http_probe_with_request(
                addr,
                &params.http_request,
                params.expected_status,
                params.timeout,
            )
            .await
        },
        HealthCheckType::Tcp => tcp_probe(addr, params.timeout).await,
        HealthCheckType::Grpc => {
            tracing::error!("gRPC health checks not yet implemented");
            false
        },
    };
    (idx, addr, success)
}

/// Record a probe result, updating health state and logging transitions.
#[expect(clippy::indexing_slicing, reason = "bounds checked")]
fn record_probe_result(params: &HealthCheckParams, idx: usize, addr: &str, success: bool) {
    if idx >= params.state.endpoints().len() {
        return;
    }
    let transitioned = if success {
        trace!(cluster = %params.cluster_name, endpoint = %addr, "probe succeeded");
        params.state.endpoints()[idx].record_success(params.healthy_threshold)
    } else {
        trace!(cluster = %params.cluster_name, endpoint = %addr, "probe failed");
        params.state.endpoints()[idx].record_failure(params.unhealthy_threshold)
    };
    publish_probe_metrics(params, addr, success, transitioned);
}

/// Emit transition logs and counters; aggregate gauges refresh once per
/// round via [`refresh_endpoint_gauges`] (transitions also refresh them
/// immediately through `record_health_transition`).
fn publish_probe_metrics(params: &HealthCheckParams, addr: &str, success: bool, transitioned: bool) {
    if !transitioned {
        return;
    }
    let result = if success {
        info!(cluster = %params.cluster_name, endpoint = %addr, "endpoint transitioned to healthy");
        crate::http::pingora::metrics::HEALTH_RESULT_HEALTHY
    } else {
        info!(cluster = %params.cluster_name, endpoint = %addr, "endpoint transitioned to unhealthy");
        crate::http::pingora::metrics::HEALTH_RESULT_UNHEALTHY
    };
    let cluster = ::metrics::SharedString::from(Arc::clone(&params.cluster_name));
    let (healthy, total) = crate::http::pingora::metrics::count_healthy_endpoints(&params.state);
    crate::http::pingora::metrics::record_health_transition(cluster, result, healthy, total);
}

/// Write the cluster's aggregate health gauges from current state.
fn refresh_endpoint_gauges(params: &HealthCheckParams) {
    let (healthy, total) = crate::http::pingora::metrics::count_healthy_endpoints(&params.state);
    crate::http::pingora::metrics::set_upstream_endpoint_gauges(
        ::metrics::SharedString::from(Arc::clone(&params.cluster_name)),
        healthy,
        total,
    );
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use praxis_core::health::{ClusterHealthEntry, EndpointHealth};
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn probe_all_marks_unreachable_unhealthy() {
        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new()],
            vec![Arc::from("placeholder:80")],
            None,
            None,
        ));
        let params = test_params(vec!["127.0.0.1:1".to_owned()], Arc::clone(&state), (1, 1));

        probe_all_endpoints(&params, &CancellationToken::new()).await;

        assert!(
            !state.endpoints()[0].is_healthy(),
            "unreachable endpoint should become unhealthy"
        );
    }

    #[tokio::test]
    async fn probe_all_marks_reachable_healthy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new()],
            vec![Arc::from("placeholder:80")],
            None,
            None,
        ));
        state.endpoints()[0].mark_unhealthy();

        let params = test_params(vec![addr], Arc::clone(&state), (1, 1));

        let probe = tokio::spawn({
            async move {
                probe_all_endpoints(&params, &CancellationToken::new()).await;
            }
        });

        let (_socket, _peer) = listener.accept().await.unwrap();
        probe.await.unwrap();
        assert!(
            state.endpoints()[0].is_healthy(),
            "reachable endpoint should become healthy"
        );
    }

    #[tokio::test]
    async fn cancelled_probe_round_skips_recording() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new()],
            vec![Arc::from("placeholder:80")],
            None,
            None,
        ));
        assert!(state.endpoints()[0].is_healthy(), "endpoint starts healthy");

        let mut params = test_params(vec![addr], Arc::clone(&state), (1, 1));
        params.check_type = HealthCheckType::Http;
        params.timeout = Duration::from_secs(2);

        let shutdown = CancellationToken::new();
        let probe = tokio::spawn({
            let shutdown = shutdown.clone();
            async move {
                probe_all_endpoints(&params, &shutdown).await;
            }
        });

        // Accept so the probe is in-flight, cancel, then drop the socket so the
        // probe fails quickly — the cancelled generation must not record it.
        let (socket, _peer) = listener.accept().await.unwrap();
        shutdown.cancel();
        drop(socket);
        probe.await.unwrap();

        assert!(
            state.endpoints()[0].is_healthy(),
            "cancelled probe must not record failure against the old registry"
        );
    }

    #[tokio::test]
    async fn spawn_and_shutdown() {
        let shutdown = CancellationToken::new();
        spawn_health_checks(&[], &Arc::new(std::collections::HashMap::new()), &shutdown);
        shutdown.cancel();
    }

    #[tokio::test]
    async fn threshold_requires_multiple_failures() {
        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new()],
            vec![Arc::from("placeholder:80")],
            None,
            None,
        ));
        let params = test_params(vec!["127.0.0.1:1".to_owned()], Arc::clone(&state), (1, 3));
        let shutdown = CancellationToken::new();

        probe_all_endpoints(&params, &shutdown).await;
        assert!(
            state.endpoints()[0].is_healthy(),
            "one failure with threshold 3 should stay healthy"
        );

        probe_all_endpoints(&params, &shutdown).await;
        assert!(
            state.endpoints()[0].is_healthy(),
            "two failures with threshold 3 should stay healthy"
        );

        probe_all_endpoints(&params, &shutdown).await;
        assert!(
            !state.endpoints()[0].is_healthy(),
            "three failures with threshold 3 should mark unhealthy"
        );
    }

    #[tokio::test]
    async fn http_probe_marks_healthy_with_matching_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new()],
            vec![Arc::from("placeholder:80")],
            None,
            None,
        ));
        state.endpoints()[0].mark_unhealthy();

        let mut params = test_params(vec![addr], Arc::clone(&state), (1, 1));
        params.check_type = HealthCheckType::Http;

        let probe = tokio::spawn(async move {
            probe_all_endpoints(&params, &CancellationToken::new()).await;
        });

        let (mut socket, _peer) = listener.accept().await.unwrap();
        let mut buf = [0_u8; 512];
        let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut socket, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();

        probe.await.unwrap();
        assert!(
            state.endpoints()[0].is_healthy(),
            "HTTP probe with matching 200 status should mark endpoint healthy"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build test params for a single endpoint with TCP probing.
    fn test_params(endpoints: Vec<String>, state: ClusterHealthState, thresholds: (u32, u32)) -> HealthCheckParams {
        HealthCheckParams {
            cluster_name: "test".into(),
            endpoints,
            check_type: HealthCheckType::Tcp,
            http_request: super::super::probe::build_http_probe_request("/"),
            expected_status: 200,
            interval: Duration::from_millis(100),
            timeout: Duration::from_millis(50),
            healthy_threshold: thresholds.0,
            unhealthy_threshold: thresholds.1,
            state,
        }
    }
}
