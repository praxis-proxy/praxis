// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Health check infrastructure: admin endpoints, probes, and background runner.

/// Health check probe functions (HTTP and TCP).
pub mod probe;
/// Background health check runner.
pub mod runner;
/// Admin health-check HTTP service (`/ready`, `/healthy`).
mod service;

pub(in crate::http::pingora) use service::escape_json_string;
pub use service::{
    PingoraAdminService, PingoraHealthService, add_admin_endpoints_to_pingora_server,
    add_health_endpoint_to_pingora_server,
};
