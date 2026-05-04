// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Background health check runner that probes endpoints on a timer.

use std::{sync::Arc, time::Duration};

use praxis_core::{
    config::{Cluster, HealthCheckType},
    health::{ClusterHealthState, HealthRegistry},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace};

use super::probe::{http_probe, tcp_probe};

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

    /// HTTP path to probe (ignored for TCP).
    path: String,

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
        let Some(ref hc) = cluster.health_check else {
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
        path: hc.path.clone(),
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

    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                info!(cluster = %params.cluster_name, "health check shutting down");
                return;
            }
            () = tokio::time::sleep(params.interval) => {
                probe_all_endpoints(params).await;
            }
        }
    }
}

/// Probe all endpoints in a cluster and update health state.
async fn probe_all_endpoints(params: &HealthCheckParams) {
    use futures::stream::{FuturesUnordered, StreamExt};

    let futures: FuturesUnordered<_> = params
        .endpoints
        .iter()
        .enumerate()
        .map(|(idx, addr)| spawn_probe(idx, addr.clone(), params))
        .collect();

    futures::pin_mut!(futures);
    while let Some((idx, addr, success)) = futures.next().await {
        record_probe_result(params, idx, &addr, success);
    }
}

/// Spawn a single endpoint probe future.
async fn spawn_probe(idx: usize, addr: String, params: &HealthCheckParams) -> (usize, String, bool) {
    debug!(
        cluster = %params.cluster_name,
        endpoint = %addr,
        check_type = %params.check_type,
        "probing health check endpoint"
    );
    let success = match params.check_type {
        HealthCheckType::Http => http_probe(&addr, &params.path, params.expected_status, params.timeout).await,
        HealthCheckType::Tcp => tcp_probe(&addr, params.timeout).await,
        HealthCheckType::Grpc => {
            tracing::warn!("gRPC health checks not yet implemented");
            false
        },
    };
    (idx, addr, success)
}

/// Record a probe result, updating health state and logging transitions.
#[allow(clippy::indexing_slicing, reason = "bounds checked")]
fn record_probe_result(params: &HealthCheckParams, idx: usize, addr: &str, success: bool) {
    if idx >= params.state.endpoints().len() {
        return;
    }
    if success {
        trace!(cluster = %params.cluster_name, endpoint = %addr, "probe succeeded");
        if params.state.endpoints()[idx].record_success(params.healthy_threshold) {
            info!(cluster = %params.cluster_name, endpoint = %addr, "endpoint transitioned to healthy");
        }
    } else {
        trace!(cluster = %params.cluster_name, endpoint = %addr, "probe failed");
        if params.state.endpoints()[idx].record_failure(params.unhealthy_threshold) {
            info!(cluster = %params.cluster_name, endpoint = %addr, "endpoint transitioned to unhealthy");
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use std::sync::Arc;

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

        probe_all_endpoints(&params).await;

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
                probe_all_endpoints(&params).await;
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

        probe_all_endpoints(&params).await;
        assert!(
            state.endpoints()[0].is_healthy(),
            "one failure with threshold 3 should stay healthy"
        );

        probe_all_endpoints(&params).await;
        assert!(
            state.endpoints()[0].is_healthy(),
            "two failures with threshold 3 should stay healthy"
        );

        probe_all_endpoints(&params).await;
        assert!(
            !state.endpoints()[0].is_healthy(),
            "three failures with threshold 3 should mark unhealthy"
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
            path: "/".to_owned(),
            expected_status: 200,
            interval: Duration::from_millis(100),
            timeout: Duration::from_millis(50),
            healthy_threshold: thresholds.0,
            unhealthy_threshold: thresholds.1,
            state,
        }
    }
}
