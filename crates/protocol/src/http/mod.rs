// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! HTTP protocol implementation.
//!
//! The backend-neutral parts (health probes and metadata, Prometheus
//! metrics, the admin and KV handlers) are reachable at [`health`],
//! [`metrics`] and `kv`; the Pingora adapter around them lives in
//! [`pingora`] behind the feature of the same name.
//!
//! [`health`]: crate::http::health
//! [`metrics`]: crate::http::metrics
//! [`pingora`]: crate::http::pingora

/// Pingora-backed HTTP implementation, plus the backend-neutral health,
/// metrics and admin modules it grew up around.
pub mod pingora;

#[cfg(feature = "admin-api")]
pub use pingora::health::PingoraHealthService;
#[cfg(feature = "admin-api")]
pub use pingora::kv;
#[cfg(feature = "pingora")]
pub use pingora::{PingoraHttp, handler::load_http_handler};
pub use pingora::{health, metrics};
