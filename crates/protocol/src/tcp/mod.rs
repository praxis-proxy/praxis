// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Raw TCP/L4 bidirectional forwarding protocol.

/// Listener grouping and group-consistency validation (backend-neutral).
mod groups;
/// TCP connection metrics (Prometheus counters, gauges and histograms).
#[cfg(feature = "pingora")]
pub(crate) mod metrics;
/// Bidirectional TCP proxy application.
#[cfg(feature = "pingora")]
pub(crate) mod proxy;
/// TCP protocol service construction and registration.
#[cfg(feature = "pingora")]
mod service;
/// TLS and plain listener registration for the Pingora TCP service.
#[cfg(feature = "pingora")]
mod tls;

pub use groups::validate_tcp_groups;
#[cfg(feature = "pingora")]
pub use service::PingoraTcp;
