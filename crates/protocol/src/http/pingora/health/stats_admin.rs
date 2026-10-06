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
    /// Human-readable identity: `{semver}` or `{semver} ({git_sha})` when a
    /// build-time git SHA is available. Derived from [`Self::semver`] and
    /// [`Self::git_sha`]; matches `praxis --version` on clean release builds.
    pub display: String,
    /// Short git SHA when available at build time (never includes a dirty flag).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
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
    /// Open file descriptors against the process limit, where tracked.
    #[serde(skip_serializing_if = "Option::is_none")]
    file_descriptors: Option<FileDescriptorStatsView>,
    /// Documented schema gaps (not placeholder zeros).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    gaps: BTreeMap<&'static str, &'static str>,
    /// Per-listener operational counters.
    listeners: Vec<ListenerStatsView>,
    /// Per-cluster operational snapshots.
    clusters: Vec<ClusterStatsView>,
}

/// Process file descriptor usage.
#[derive(Debug, Serialize)]
struct FileDescriptorStatsView {
    /// Descriptors open at the last sample.
    open: u64,
    /// Soft `RLIMIT_NOFILE` the process runs with.
    limit: u64,
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
        file_descriptors: praxis_core::fd::usage().map(|usage| FileDescriptorStatsView {
            open: usage.open,
            limit: usage.limit,
        }),
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
/// (RFC 9110 §8.6: do not send a misleading `Content-Length: 0`).
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
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_methods,
    clippy::significant_drop_tightening,
    clippy::too_many_lines,
    unused_comparisons,
    reason = "tests"
)]
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

    #[test]
    fn resolve_health_registry_prefers_live_over_stale_startup() {
        let startup: HealthRegistry = Arc::new(
            [(
                Arc::from("backend"),
                Arc::new(ClusterHealthEntry::new(
                    vec![EndpointHealth::new()],
                    vec![Arc::from("10.0.0.1:80")],
                    None,
                    None,
                )),
            )]
            .into_iter()
            .collect(),
        );

        let empty_meta = new_listener_meta_store(std::collections::HashMap::new());
        assert!(
            resolve_health_registry(Some(&startup), None, &empty_meta).is_some(),
            "with no live pipelines the startup registry is used"
        );

        let state = pipelines_admin::PipelinesAdminState {
            pipelines: Arc::new(crate::ListenerPipelines::new(std::collections::HashMap::new())),
            meta: new_listener_meta_store(std::collections::HashMap::new()),
        };
        assert!(
            resolve_health_registry(Some(&startup), Some(&state), &state.meta).is_none(),
            "must not fall back to the stale startup registry when pipelines are live"
        );
    }

    #[test]
    fn resolve_health_registry_returns_none_when_no_admin_registry() {
        let empty_meta = new_listener_meta_store(std::collections::HashMap::new());
        let result = resolve_health_registry(None, None, &empty_meta);
        assert!(result.is_none(), "should return None when no admin registry");
    }

    #[test]
    fn stats_post_method_not_allowed() {
        let state = sample_state();
        let resp = stats_response(None, &state, "POST");
        assert_eq!(resp.status().as_u16(), 405, "POST should return 405");
        assert_eq!(
            resp.headers().get("Allow").and_then(|v| v.to_str().ok()),
            Some("GET, HEAD"),
            "405 response should include Allow header"
        );
        let json: serde_json::Value = serde_json::from_slice(resp.body()).expect("valid JSON");
        assert_eq!(json["error"], "method not allowed");
    }

    #[test]
    fn stats_put_method_not_allowed() {
        let state = sample_state();
        let resp = stats_response(None, &state, "PUT");
        assert_eq!(resp.status().as_u16(), 405, "PUT should return 405");
    }

    #[test]
    fn stats_delete_method_not_allowed() {
        let state = sample_state();
        let resp = stats_response(None, &state, "DELETE");
        assert_eq!(resp.status().as_u16(), 405, "DELETE should return 405");
    }

    #[test]
    fn stats_patch_method_not_allowed() {
        let state = sample_state();
        let resp = stats_response(None, &state, "PATCH");
        assert_eq!(resp.status().as_u16(), 405, "PATCH should return 405");
    }

    #[test]
    fn stats_options_method_not_allowed() {
        let state = sample_state();
        let resp = stats_response(None, &state, "OPTIONS");
        assert_eq!(resp.status().as_u16(), 405, "OPTIONS should return 405");
    }

    #[test]
    fn stats_get_includes_uptime() {
        let state = sample_state();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let resp = stats_response(None, &state, "GET");
        let json: serde_json::Value = serde_json::from_slice(resp.body()).expect("valid JSON");
        let _uptime = json["uptime_secs"].as_u64().expect("uptime should be u64");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stats_get_reports_file_descriptors_once_tracked() {
        praxis_core::fd::init(1_048_576, false);
        let resp = stats_response(None, &sample_state(), "GET");
        let json: serde_json::Value = serde_json::from_slice(resp.body()).expect("valid JSON");
        let limit = json["file_descriptors"]["limit"].as_u64();
        let open = json["file_descriptors"]["open"].as_u64();
        assert_eq!(limit, Some(1_048_576), "the tracked limit must be reported: {json}");
        assert!(
            open.is_some_and(|count| count >= 3),
            "open descriptors must be reported: {json}"
        );
    }

    #[test]
    fn stats_get_with_git_sha() {
        let mut state = sample_state();
        state.version = ProcessVersionInfo {
            semver: "1.2.3".to_owned(),
            display: "1.2.3 (abc1234)".to_owned(),
            git_sha: Some("abc1234".to_owned()),
        };
        let resp = stats_response(None, &state, "GET");
        let json: serde_json::Value = serde_json::from_slice(resp.body()).expect("valid JSON");
        assert_eq!(json["version"]["semver"], "1.2.3");
        assert_eq!(json["version"]["display"], "1.2.3 (abc1234)");
        assert_eq!(json["version"]["git_sha"], "abc1234");
    }

    #[test]
    fn stats_gaps_http_active_aggregate_only() {
        let snapshot = metrics::StatsMetricsSnapshot {
            http_active_by_listener: std::collections::HashMap::new(),
            http_active_aggregate: Some(42),
            tcp_active_by_listener: std::collections::HashMap::new(),
            tcp_active_aggregate: None,
            upstream_requests_by_cluster: std::collections::HashMap::new(),
            upstream_requests_aggregate: None,
            connect_failures_by_cluster: std::collections::HashMap::new(),
            connect_failures_aggregate: None,
        };
        let gaps = stats_gaps(&snapshot);
        assert!(
            gaps.contains_key("per_listener_http_active"),
            "should document per-listener HTTP active gap"
        );
        assert!(
            gaps.contains_key("per_listener_http_requests"),
            "should always document per-listener HTTP requests gap"
        );
    }

    #[test]
    fn stats_gaps_tcp_active_aggregate_only() {
        let snapshot = metrics::StatsMetricsSnapshot {
            http_active_by_listener: std::collections::HashMap::new(),
            http_active_aggregate: None,
            tcp_active_by_listener: std::collections::HashMap::new(),
            tcp_active_aggregate: Some(10),
            upstream_requests_by_cluster: std::collections::HashMap::new(),
            upstream_requests_aggregate: None,
            connect_failures_by_cluster: std::collections::HashMap::new(),
            connect_failures_aggregate: None,
        };
        let gaps = stats_gaps(&snapshot);
        assert!(
            gaps.contains_key("per_listener_tcp_active"),
            "should document per-listener TCP active gap"
        );
    }

    #[test]
    fn stats_gaps_upstream_requests_aggregate_only() {
        let snapshot = metrics::StatsMetricsSnapshot {
            http_active_by_listener: std::collections::HashMap::new(),
            http_active_aggregate: None,
            tcp_active_by_listener: std::collections::HashMap::new(),
            tcp_active_aggregate: None,
            upstream_requests_by_cluster: std::collections::HashMap::new(),
            upstream_requests_aggregate: Some(100),
            connect_failures_by_cluster: std::collections::HashMap::new(),
            connect_failures_aggregate: None,
        };
        let gaps = stats_gaps(&snapshot);
        assert!(
            gaps.contains_key("per_cluster_upstream_requests"),
            "should document per-cluster upstream requests gap"
        );
    }

    #[test]
    fn stats_gaps_connect_failures_aggregate_only() {
        let snapshot = metrics::StatsMetricsSnapshot {
            http_active_by_listener: std::collections::HashMap::new(),
            http_active_aggregate: None,
            tcp_active_by_listener: std::collections::HashMap::new(),
            tcp_active_aggregate: None,
            upstream_requests_by_cluster: std::collections::HashMap::new(),
            upstream_requests_aggregate: None,
            connect_failures_by_cluster: std::collections::HashMap::new(),
            connect_failures_aggregate: Some(5),
        };
        let gaps = stats_gaps(&snapshot);
        assert!(
            gaps.contains_key("per_cluster_upstream_connect_failures"),
            "should document per-cluster connect failures gap"
        );
    }

    #[test]
    fn stats_gaps_all_aggregates() {
        let snapshot = metrics::StatsMetricsSnapshot {
            http_active_by_listener: std::collections::HashMap::new(),
            http_active_aggregate: Some(10),
            tcp_active_by_listener: std::collections::HashMap::new(),
            tcp_active_aggregate: Some(5),
            upstream_requests_by_cluster: std::collections::HashMap::new(),
            upstream_requests_aggregate: Some(100),
            connect_failures_by_cluster: std::collections::HashMap::new(),
            connect_failures_aggregate: Some(2),
        };
        let gaps = stats_gaps(&snapshot);
        assert_eq!(gaps.len(), 5, "should have all 5 gap entries");
        assert!(gaps.contains_key("per_listener_http_requests"));
        assert!(gaps.contains_key("per_listener_http_active"));
        assert!(gaps.contains_key("per_listener_tcp_active"));
        assert!(gaps.contains_key("per_cluster_upstream_requests"));
        assert!(gaps.contains_key("per_cluster_upstream_connect_failures"));
    }

    #[test]
    fn listener_stats_view_tcp_protocol() {
        let meta = ListenerMeta {
            name: "tcp_listener".to_owned(),
            address: "127.0.0.1:8080".to_owned(),
            protocol: ProtocolKind::Tcp,
            tls: true,
            chain_names: vec![],
        };
        let mut snapshot = metrics::StatsMetricsSnapshot::default();
        snapshot.tcp_active_by_listener.insert("tcp_listener".to_owned(), 15);

        let view = listener_stats_view(&meta, &snapshot);
        assert_eq!(view.name, "tcp_listener");
        assert_eq!(view.protocol, ProtocolKind::Tcp);
        assert!(view.tls, "TLS should be enabled");
        assert_eq!(view.active_connections, 15);
    }

    #[test]
    fn listener_stats_view_http_protocol() {
        let meta = ListenerMeta {
            name: "http_listener".to_owned(),
            address: "127.0.0.1:8081".to_owned(),
            protocol: ProtocolKind::Http,
            tls: false,
            chain_names: vec![],
        };
        let mut snapshot = metrics::StatsMetricsSnapshot::default();
        snapshot.http_active_by_listener.insert("http_listener".to_owned(), 25);

        let view = listener_stats_view(&meta, &snapshot);
        assert_eq!(view.name, "http_listener");
        assert_eq!(view.protocol, ProtocolKind::Http);
        assert!(!view.tls, "TLS should be disabled");
        assert_eq!(view.active_connections, 25);
    }

    #[test]
    fn listener_stats_view_missing_metrics() {
        let meta = ListenerMeta {
            name: "new_listener".to_owned(),
            address: "127.0.0.1:8082".to_owned(),
            protocol: ProtocolKind::Http,
            tls: false,
            chain_names: vec![],
        };
        let snapshot = metrics::StatsMetricsSnapshot::default();

        let view = listener_stats_view(&meta, &snapshot);
        assert_eq!(view.active_connections, 0, "missing metrics should default to 0");
    }

    #[test]
    fn cluster_stats_view_with_metrics() {
        let meta = ClusterMeta {
            name: "cluster1".to_owned(),
            endpoints: vec!["10.0.0.1:80".to_owned()],
        };
        let mut snapshot = metrics::StatsMetricsSnapshot::default();
        snapshot
            .upstream_requests_by_cluster
            .insert("cluster1".to_owned(), 1000);
        snapshot.connect_failures_by_cluster.insert("cluster1".to_owned(), 5);

        let view = cluster_stats_view(&meta, None, &snapshot);
        assert_eq!(view.name, "cluster1");
        assert_eq!(view.total_endpoints, 1);
        assert_eq!(view.upstream_requests_total, 1000);
        assert_eq!(view.upstream_connect_failures_total, 5);
    }

    #[test]
    fn cluster_stats_view_missing_metrics() {
        let meta = ClusterMeta {
            name: "cluster2".to_owned(),
            endpoints: vec!["10.0.0.1:80".to_owned(), "10.0.0.2:80".to_owned()],
        };
        let snapshot = metrics::StatsMetricsSnapshot::default();

        let view = cluster_stats_view(&meta, None, &snapshot);
        assert_eq!(view.upstream_requests_total, 0, "missing metrics should default to 0");
        assert_eq!(view.upstream_connect_failures_total, 0);
    }

    #[test]
    fn endpoint_rows_no_registry_all_healthy() {
        let meta = ClusterMeta {
            name: "cluster".to_owned(),
            endpoints: vec![
                "10.0.0.1:80".to_owned(),
                "10.0.0.2:80".to_owned(),
                "10.0.0.3:80".to_owned(),
            ],
        };

        let rows = endpoint_rows(&meta, None);
        assert_eq!(rows.len(), 3);
        for row in &rows {
            assert!(row.healthy, "all endpoints should be healthy without registry");
        }
    }

    #[test]
    fn endpoint_rows_registry_missing_cluster() {
        let meta = ClusterMeta {
            name: "other_cluster".to_owned(),
            endpoints: vec!["10.0.0.1:80".to_owned()],
        };
        let entry = ClusterHealthEntry::new(vec![EndpointHealth::new()], vec![Arc::from("10.0.0.1:80")], None, None);
        let registry: HealthRegistry = Arc::new(
            [(Arc::from("different_cluster"), Arc::new(entry))]
                .into_iter()
                .collect(),
        );

        let rows = endpoint_rows(&meta, Some(&registry));
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].healthy,
            "should default to healthy when registry exists but cluster missing"
        );
    }

    #[test]
    fn endpoint_rows_sorted_by_address() {
        let meta = ClusterMeta {
            name: "backend".to_owned(),
            endpoints: vec![
                "10.0.0.3:80".to_owned(),
                "10.0.0.1:80".to_owned(),
                "10.0.0.2:80".to_owned(),
            ],
        };
        let entry = ClusterHealthEntry::new(
            vec![EndpointHealth::new(), EndpointHealth::new(), EndpointHealth::new()],
            vec![
                Arc::from("10.0.0.3:80"),
                Arc::from("10.0.0.1:80"),
                Arc::from("10.0.0.2:80"),
            ],
            None,
            None,
        );
        let registry: HealthRegistry = Arc::new([(Arc::from("backend"), Arc::new(entry))].into_iter().collect());

        let rows = endpoint_rows(&meta, Some(&registry));
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].address, "10.0.0.1:80", "should be sorted");
        assert_eq!(rows[1].address, "10.0.0.2:80");
        assert_eq!(rows[2].address, "10.0.0.3:80");
    }

    #[test]
    fn endpoint_rows_missing_from_registry() {
        let meta = ClusterMeta {
            name: "backend".to_owned(),
            endpoints: vec![
                "10.0.0.1:80".to_owned(),
                "10.0.0.2:80".to_owned(),
                "10.0.0.99:80".to_owned(),
            ],
        };
        let entry = ClusterHealthEntry::new(
            vec![EndpointHealth::new(), EndpointHealth::new()],
            vec![Arc::from("10.0.0.1:80"), Arc::from("10.0.0.2:80")],
            None,
            None,
        );
        let registry: HealthRegistry = Arc::new([(Arc::from("backend"), Arc::new(entry))].into_iter().collect());

        let rows = endpoint_rows(&meta, Some(&registry));
        assert_eq!(rows.len(), 3);
        let missing = rows
            .iter()
            .find(|r| r.address == "10.0.0.99:80")
            .expect("missing endpoint should be in rows");
        assert!(missing.healthy, "endpoint not in registry should default to healthy");
    }

    #[test]
    fn as_head_response_clears_body_and_content_length() {
        let body = br#"{"some":"data"}"#;
        let resp = Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            .header("Content-Length", body.len())
            .body(body.to_vec())
            .expect("valid response");

        let head_resp = as_head_response(resp);
        assert!(head_resp.body().is_empty(), "body should be empty");
        assert_eq!(
            head_resp.headers().get(http::header::CONTENT_LENGTH),
            None,
            "Content-Length should be removed"
        );
        assert_eq!(
            head_resp.headers().get("Content-Type").and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "other headers should remain"
        );
    }

    #[test]
    fn method_not_allowed_response_structure() {
        let resp = method_not_allowed();
        assert_eq!(resp.status().as_u16(), 405);
        assert_eq!(
            resp.headers().get("Content-Type").and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            resp.headers().get("Allow").and_then(|v| v.to_str().ok()),
            Some("GET, HEAD")
        );
        let json: serde_json::Value = serde_json::from_slice(resp.body()).expect("valid JSON");
        assert_eq!(json["error"], "method not allowed");
    }

    #[test]
    fn process_version_info_without_git_sha() {
        let version = ProcessVersionInfo {
            semver: "0.1.0".to_owned(),
            display: "0.1.0".to_owned(),
            git_sha: None,
        };
        let json = serde_json::to_value(&version).expect("should serialize");
        assert_eq!(json["semver"], "0.1.0");
        assert_eq!(json["display"], "0.1.0");
        assert!(json.get("git_sha").is_none(), "git_sha should be skipped when None");
    }

    #[test]
    fn process_version_info_with_git_sha() {
        let version = ProcessVersionInfo {
            semver: "0.2.0".to_owned(),
            display: "0.2.0 (deadbeef)".to_owned(),
            git_sha: Some("deadbeef".to_owned()),
        };
        let json = serde_json::to_value(&version).expect("should serialize");
        assert_eq!(json["semver"], "0.2.0");
        assert_eq!(json["display"], "0.2.0 (deadbeef)");
        assert_eq!(json["git_sha"], "deadbeef");
    }

    #[test]
    fn stats_response_multiple_listeners_sorted() {
        let config = praxis_core::config::Config::from_yaml(
            r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: zebra
    address: "127.0.0.1:8083"
    filter_chains: [main]
  - name: alpha
    address: "127.0.0.1:8081"
    filter_chains: [main]
  - name: beta
    address: "127.0.0.1:8082"
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

        let state = StatsAdminState {
            started_at: Instant::now(),
            version: ProcessVersionInfo {
                semver: "0.0.0".to_owned(),
                display: "0.0.0".to_owned(),
                git_sha: None,
            },
            listener_meta: new_listener_meta_store(listener_meta_from_config(&config)),
            cluster_meta: new_cluster_meta_store(cluster_meta_from_config(&config)),
        };

        let resp = stats_response(None, &state, "GET");
        let json: serde_json::Value = serde_json::from_slice(resp.body()).expect("valid JSON");
        let listeners = json["listeners"].as_array().expect("listeners should be array");
        assert_eq!(listeners.len(), 3);
        assert_eq!(listeners[0]["name"], "alpha", "listeners should be sorted");
        assert_eq!(listeners[1]["name"], "beta");
        assert_eq!(listeners[2]["name"], "zebra");
    }

    #[test]
    fn stats_response_multiple_clusters_sorted() {
        let config = praxis_core::config::Config::from_yaml(
            r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
clusters:
  - name: zoo
    endpoints:
      - address: "127.0.0.1:9003"
  - name: apple
    endpoints:
      - address: "127.0.0.1:9001"
  - name: banana
    endpoints:
      - address: "127.0.0.1:9002"
filter_chains:
  - name: main
    filters: [{ filter: static_response, status: 200 }]
"#,
        )
        .expect("config should parse");

        let state = StatsAdminState {
            started_at: Instant::now(),
            version: ProcessVersionInfo {
                semver: "0.0.0".to_owned(),
                display: "0.0.0".to_owned(),
                git_sha: None,
            },
            listener_meta: new_listener_meta_store(listener_meta_from_config(&config)),
            cluster_meta: new_cluster_meta_store(cluster_meta_from_config(&config)),
        };

        let resp = stats_response(None, &state, "GET");
        let json: serde_json::Value = serde_json::from_slice(resp.body()).expect("valid JSON");
        let clusters = json["clusters"].as_array().expect("clusters should be array");
        assert_eq!(clusters.len(), 3);
        assert_eq!(clusters[0]["name"], "apple", "clusters should be sorted");
        assert_eq!(clusters[1]["name"], "banana");
        assert_eq!(clusters[2]["name"], "zoo");
    }
}
