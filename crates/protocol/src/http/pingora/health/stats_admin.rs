// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `GET /api/stats` admin handler (#125 Phase 1).

use std::{collections::BTreeMap, sync::Arc, time::Instant};

use http::Response;
use praxis_core::{config::ProtocolKind, health::HealthRegistry};
use serde::Serialize;

use super::{
    cluster_meta::{ClusterMeta, ClusterMetaStore},
    listener_meta::{ListenerMeta, ListenerMetaStore},
    pipelines_admin,
};
use crate::http::pingora::{json::json_response, metrics};

// -----------------------------------------------------------------------------
// State
// -----------------------------------------------------------------------------

/// Build-time and runtime metadata for `/api/stats`.
#[derive(Clone, Debug, Serialize)]
pub struct ProcessVersionInfo {
    /// Cargo package semver (e.g. `0.5.4`).
    pub semver: String,
    /// Same string as `praxis --version` / startup log.
    pub display: String,
    /// Short git SHA when available at build time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    /// Whether the build tree had uncommitted changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dirty: Option<bool>,
}

/// Handles for `/api/stats` snapshot assembly.
pub struct StatsAdminState {
    /// Process start instant for uptime calculation.
    pub started_at: Instant,
    /// Version identity from the server binary.
    pub version: ProcessVersionInfo,
    /// Hot-swappable listener metadata.
    pub listener_meta: ListenerMetaStore,
    /// Hot-swappable cluster endpoint metadata.
    pub cluster_meta: ClusterMetaStore,
}

// -----------------------------------------------------------------------------
// Response DTOs
// -----------------------------------------------------------------------------

/// Top-level `GET /api/stats` body.
#[derive(Debug, Serialize)]
struct StatsResponse {
    /// Seconds since process start.
    uptime_secs: u64,
    /// Build/runtime version identity.
    version: ProcessVersionInfo,
    /// Documented schema gaps (not placeholder zeros).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    gaps: BTreeMap<&'static str, &'static str>,
    /// Per-listener operational counters.
    listeners: Vec<ListenerStatsView>,
    /// Per-cluster operational snapshots.
    clusters: Vec<ClusterStatsView>,
}

/// Per-listener operational counters.
#[derive(Debug, Serialize)]
struct ListenerStatsView {
    /// Listener name.
    name: String,
    /// Protocol kind (`http` / `tcp`).
    protocol: ProtocolKind,
    /// Whether listener TLS is configured.
    tls: bool,
    /// Active HTTP requests or open TCP sessions for this listener.
    active_connections: u64,
}

/// Per-cluster operational snapshot.
#[derive(Debug, Serialize)]
struct ClusterStatsView {
    /// Cluster name.
    name: String,
    /// Healthy upstream endpoints at snapshot time.
    healthy_endpoints: u64,
    /// Total configured upstream endpoints.
    total_endpoints: u64,
    /// Sum of `praxis_upstream_requests_total` for this cluster.
    upstream_requests_total: u64,
    /// Sum of `praxis_upstream_connect_failures_total` for this cluster.
    upstream_connect_failures_total: u64,
    /// Per-endpoint health rows.
    endpoints: Vec<EndpointStatsView>,
}

/// Per-endpoint health row.
#[derive(Debug, Serialize)]
struct EndpointStatsView {
    /// Upstream socket (`host:port`).
    address: String,
    /// Active health-check state at snapshot time.
    healthy: bool,
}

// -----------------------------------------------------------------------------
// Dispatch
// -----------------------------------------------------------------------------

/// Prefer the health registry pinned by live pipelines for **current** listeners
/// (post-reload) over the startup snapshot held on the admin service.
pub(super) fn resolve_health_registry(
    admin_registry: Option<&HealthRegistry>,
    pipelines: Option<&pipelines_admin::PipelinesAdminState>,
    listener_meta: &ListenerMetaStore,
) -> Option<HealthRegistry> {
    let Some(state) = pipelines else {
        return admin_registry.cloned();
    };
    let meta = listener_meta.load();
    let current_listeners: std::collections::HashSet<String> = meta.keys().cloned().collect();
    for name in state.pipelines.listener_names() {
        if !current_listeners.contains(name) {
            continue;
        }
        let Some(slot) = state.pipelines.get(name) else {
            continue;
        };
        if let Some(registry) = slot.load().health_registry() {
            return Some(Arc::clone(registry));
        }
    }
    // No live pipeline exposes a registry (e.g. health checks removed on reload).
    // Do not fall back to the startup admin snapshot — it would report stale probe state.
    None
}

/// Handle `GET`/`HEAD` `/api/stats`.
pub(super) fn stats_response(
    health_registry: Option<&HealthRegistry>,
    state: &StatsAdminState,
    method: &str,
) -> Response<Vec<u8>> {
    if method != "GET" && method != "HEAD" {
        return method_not_allowed();
    }

    let body = match build_stats_response(health_registry, state) {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(%error, "stats admin serialization failed");
            return json_response(500, br#"{"error":"serialization failed"}"#);
        },
    };

    let resp = json_response(200, &body);
    if method == "HEAD" { as_head_response(resp) } else { resp }
}

/// Assemble the JSON body for `GET /api/stats`.
fn build_stats_response(
    health_registry: Option<&HealthRegistry>,
    state: &StatsAdminState,
) -> Result<Vec<u8>, serde_json::Error> {
    let prom = metrics::render_prometheus().unwrap_or_default();
    let snapshot = metrics::collect_stats_metrics(&prom);
    let listener_meta = state.listener_meta.load();
    let cluster_meta = state.cluster_meta.load();

    let gaps = stats_gaps(&snapshot);

    let mut listeners: Vec<ListenerStatsView> = listener_meta
        .values()
        .map(|meta| listener_stats_view(meta, &snapshot))
        .collect();
    listeners.sort_by(|a, b| a.name.cmp(&b.name));

    let mut clusters: Vec<ClusterStatsView> = cluster_meta
        .values()
        .map(|meta| cluster_stats_view(meta, health_registry, &snapshot))
        .collect();
    clusters.sort_by(|a, b| a.name.cmp(&b.name));

    serde_json::to_vec(&StatsResponse {
        uptime_secs: state.started_at.elapsed().as_secs(),
        version: state.version.clone(),
        gaps,
        listeners,
        clusters,
    })
}

/// Document known Phase 1 schema limitations.
fn stats_gaps(snapshot: &metrics::StatsMetricsSnapshot) -> BTreeMap<&'static str, &'static str> {
    let mut gaps = BTreeMap::from([(
        "per_listener_http_requests",
        "praxis_http_requests_total has no listener label",
    )]);
    if snapshot.http_active_by_listener.is_empty() && snapshot.http_active_aggregate.is_some() {
        gaps.insert(
            "per_listener_http_active",
            "listener label disabled on metrics.labels; per-listener active_connections may read 0",
        );
    }
    if snapshot.tcp_active_by_listener.is_empty() && snapshot.tcp_active_aggregate.is_some() {
        gaps.insert(
            "per_listener_tcp_active",
            "listener label disabled on metrics.labels; per-listener TCP active_connections may read 0",
        );
    }
    if snapshot.upstream_requests_by_cluster.is_empty() && snapshot.upstream_requests_aggregate.is_some() {
        gaps.insert(
            "per_cluster_upstream_requests",
            "cluster label disabled on metrics.labels; per-cluster upstream_requests_total may read 0",
        );
    }
    if snapshot.connect_failures_by_cluster.is_empty() && snapshot.connect_failures_aggregate.is_some() {
        gaps.insert(
            "per_cluster_upstream_connect_failures",
            "cluster label disabled on metrics.labels; per-cluster upstream_connect_failures_total may read 0",
        );
    }
    gaps
}

/// Build one listener row from metadata and metric snapshot.
fn listener_stats_view(meta: &ListenerMeta, snapshot: &metrics::StatsMetricsSnapshot) -> ListenerStatsView {
    let active_connections = match meta.protocol {
        ProtocolKind::Http => snapshot.http_active_by_listener.get(&meta.name).copied().unwrap_or(0),
        ProtocolKind::Tcp => snapshot.tcp_active_by_listener.get(&meta.name).copied().unwrap_or(0),
    };

    ListenerStatsView {
        name: meta.name.clone(),
        protocol: meta.protocol,
        tls: meta.tls,
        active_connections,
    }
}

/// Build one cluster row from metadata, health registry, and metric snapshot.
fn cluster_stats_view(
    meta: &ClusterMeta,
    health_registry: Option<&HealthRegistry>,
    snapshot: &metrics::StatsMetricsSnapshot,
) -> ClusterStatsView {
    let endpoints = endpoint_rows(meta, health_registry);
    let healthy_endpoints = u64::try_from(endpoints.iter().filter(|ep| ep.healthy).count()).unwrap_or(0);
    let total_endpoints = u64::try_from(endpoints.len()).unwrap_or(0);

    ClusterStatsView {
        name: meta.name.clone(),
        healthy_endpoints,
        total_endpoints,
        upstream_requests_total: snapshot
            .upstream_requests_by_cluster
            .get(&meta.name)
            .copied()
            .unwrap_or(0),
        upstream_connect_failures_total: snapshot
            .connect_failures_by_cluster
            .get(&meta.name)
            .copied()
            .unwrap_or(0),
        endpoints,
    }
}

/// Build endpoint health rows for one cluster.
#[expect(clippy::too_many_lines, reason = "registry vs config-only branches")]
fn endpoint_rows(meta: &ClusterMeta, health_registry: Option<&HealthRegistry>) -> Vec<EndpointStatsView> {
    let Some(registry) = health_registry else {
        return meta
            .endpoints
            .iter()
            .map(|address| EndpointStatsView {
                address: address.clone(),
                healthy: true,
            })
            .collect();
    };

    let Some(state) = registry.get(meta.name.as_str()) else {
        return meta
            .endpoints
            .iter()
            .map(|address| EndpointStatsView {
                address: address.clone(),
                healthy: true,
            })
            .collect();
    };

    let live: std::collections::HashMap<_, _> = state
        .endpoint_statuses()
        .into_iter()
        .map(|(addr, healthy)| (addr.to_string(), healthy))
        .collect();

    let mut rows: Vec<_> = meta
        .endpoints
        .iter()
        .map(|address| EndpointStatsView {
            address: address.clone(),
            healthy: live.get(address).copied().unwrap_or(true),
        })
        .collect();
    rows.sort_by(|a, b| a.address.cmp(&b.address));
    rows
}

/// Strip the body for HEAD. [`json_response`] sets `Content-Length` from the GET
/// body; remove it after clearing the body so framing follows the empty vec
/// (RFC 9110 §8.6 — do not send a misleading `Content-Length: 0`).
fn as_head_response(mut resp: Response<Vec<u8>>) -> Response<Vec<u8>> {
    *resp.body_mut() = Vec::new();
    resp.headers_mut().remove(http::header::CONTENT_LENGTH);
    resp
}

/// 405 with `Allow: GET, HEAD` per RFC 9110 Section 15.5.6.
#[expect(clippy::expect_used, reason = "valid static response")]
fn method_not_allowed() -> Response<Vec<u8>> {
    let body = br#"{"error":"method not allowed"}"#;
    Response::builder()
        .status(405)
        .header("Content-Type", "application/json")
        .header("Content-Length", body.len())
        .header("Allow", "GET, HEAD")
        .body(body.to_vec())
        .expect("valid 405 response")
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use praxis_core::health::{ClusterHealthEntry, EndpointHealth};

    use super::*;
    use crate::http::pingora::health::{
        cluster_meta::{cluster_meta_from_config, new_cluster_meta_store},
        listener_meta::{listener_meta_from_config, new_listener_meta_store},
    };

    fn sample_state() -> StatsAdminState {
        let config = praxis_core::config::Config::from_yaml(
            r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
clusters:
  - name: backend
    endpoints:
      - address: "127.0.0.1:9000"
filter_chains:
  - name: main
    filters: [{ filter: static_response, status: 200 }]
"#,
        )
        .expect("config should parse");
        StatsAdminState {
            started_at: Instant::now(),
            version: ProcessVersionInfo {
                semver: "0.0.0".to_owned(),
                display: "0.0.0".to_owned(),
                git_sha: None,
                dirty: None,
            },
            listener_meta: new_listener_meta_store(listener_meta_from_config(&config)),
            cluster_meta: new_cluster_meta_store(cluster_meta_from_config(&config)),
        }
    }

    #[test]
    fn stats_get_returns_version_and_gaps() {
        let state = sample_state();
        let resp = stats_response(None, &state, "GET");
        assert_eq!(resp.status().as_u16(), 200, "GET /api/stats should succeed");
        let json: serde_json::Value = serde_json::from_slice(resp.body()).expect("valid JSON");
        assert_eq!(json["version"]["semver"], "0.0.0", "semver should be present");
        assert!(
            json["gaps"]["per_listener_http_requests"].is_string(),
            "per-listener HTTP request gap should be documented: {json}"
        );
        assert_eq!(json["listeners"][0]["name"], "web", "listener row expected");
        assert_eq!(json["clusters"][0]["name"], "backend", "cluster row expected");
    }

    #[test]
    fn stats_head_returns_empty_body() {
        let state = sample_state();
        let resp = stats_response(None, &state, "HEAD");
        assert_eq!(resp.status().as_u16(), 200, "HEAD should succeed");
        assert!(resp.body().is_empty(), "HEAD must not include a body");
        assert_eq!(
            resp.headers().get("Content-Length"),
            None,
            "HEAD should not send Content-Length after body is cleared"
        );
    }

    #[test]
    fn endpoint_rows_use_health_registry_when_present() {
        let meta = ClusterMeta {
            name: "backend".to_owned(),
            endpoints: vec!["10.0.0.1:80".to_owned(), "10.0.0.2:80".to_owned()],
        };
        let entry = ClusterHealthEntry::new(
            vec![EndpointHealth::new(), EndpointHealth::new()],
            vec![Arc::from("10.0.0.1:80"), Arc::from("10.0.0.2:80")],
            None,
            None,
        );
        if let Some(ep) = entry.endpoints().get(1) {
            ep.mark_unhealthy();
        }
        let registry: HealthRegistry = Arc::new([(Arc::from("backend"), Arc::new(entry))].into_iter().collect());

        let rows = endpoint_rows(&meta, Some(&registry));
        assert_eq!(rows.len(), 2, "two endpoint rows expected");
        let down = rows
            .iter()
            .find(|r| r.address == "10.0.0.2:80")
            .expect("second endpoint");
        assert!(!down.healthy, "unhealthy endpoint should be false");
    }
}
