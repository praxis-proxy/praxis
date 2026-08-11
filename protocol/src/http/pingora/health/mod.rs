// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Health check infrastructure: admin endpoints, probes, and background runner.

/// Listener metadata for `GET /api/pipelines`.
pub mod listener_meta;
/// `GET /api/pipelines` admin dispatch.
mod pipelines_admin;
/// Health check probe functions (HTTP and TCP).
pub mod probe;
/// Background health check runner.
pub mod runner;
/// Admin health-check HTTP service (`/ready`, `/healthy`).
mod service;

pub use listener_meta::{ListenerMeta, ListenerMetaStore, listener_meta_from_config, new_listener_meta_store};
pub(in crate::http::pingora) use service::escape_json_string;
pub use service::{
    AdminEndpointOptions, PingoraAdminService, PingoraHealthService, add_admin_endpoints_to_pingora_server,
    add_health_endpoint_to_pingora_server,
};
