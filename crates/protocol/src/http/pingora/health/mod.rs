// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Health check infrastructure: admin endpoints, probes, and background runner.

/// Cluster endpoint metadata for `/api/stats`. Kept ungated for reload.
pub mod cluster_meta;
/// Listener metadata for `GET /api/pipelines`. Kept ungated: the reload
/// path maintains this store even when the admin API is not compiled in.
pub mod listener_meta;
/// `/api/log-level` admin dispatch.
#[cfg(feature = "admin-api")]
mod log_level_admin;
#[cfg(feature = "admin-api")]
mod pipelines_admin;
/// Health check probe functions (HTTP and TCP).
pub mod probe;
/// Background health check runner.
pub mod runner;
/// Admin HTTP service (`/ready`, `/healthy`, `/metrics`, `/api/*`).
#[cfg(feature = "admin-api")]
mod service;
#[cfg(feature = "admin-api")]
mod stats_admin;

pub use cluster_meta::{ClusterMeta, ClusterMetaStore, cluster_meta_from_config, new_cluster_meta_store};
pub use listener_meta::{ListenerMeta, ListenerMetaStore, listener_meta_from_config, new_listener_meta_store};
#[cfg(feature = "admin-api")]
pub(in crate::http::pingora) use service::escape_json_string;
#[cfg(feature = "admin-api")]
pub use service::{
    AdminEndpointOptions, PingoraAdminService, PingoraHealthService, PrometheusAdminRecorder,
    add_admin_endpoints_to_pingora_server, add_admin_endpoints_to_pingora_server_with_recorder,
    add_health_endpoint_to_pingora_server, install_prometheus_admin_recorder,
};
#[cfg(feature = "admin-api")]
pub use stats_admin::{ProcessVersionInfo, StatsAdminState};
