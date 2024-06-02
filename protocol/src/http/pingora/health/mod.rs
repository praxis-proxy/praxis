// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! Health check infrastructure: admin endpoints, probes, and background runner.

/// Health check probe functions (HTTP and TCP).
pub mod probe;
/// Background health check runner.
pub mod runner;
/// Admin health-check HTTP service (`/ready`, `/healthy`).
mod service;

pub use service::{PingoraHealthService, add_health_endpoint_to_pingora_server};
