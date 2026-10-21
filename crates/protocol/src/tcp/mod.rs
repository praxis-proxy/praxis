// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Raw TCP/L4 bidirectional forwarding protocol.

/// Listener grouping and group-consistency validation (backend-neutral).
mod groups;
/// The hyper backend's TCP service (accept loop and TLS) and the listener
/// sockets every hyper listener binds.
#[cfg(feature = "hyper")]
pub(crate) mod hyper;
/// TCP connection metrics (Prometheus counters, gauges and histograms).
#[cfg(any(feature = "pingora", feature = "hyper"))]
pub(crate) mod metrics;
/// Bidirectional TCP proxy application, shared by every backend.
#[cfg(any(feature = "pingora", feature = "hyper"))]
pub(crate) mod proxy;
/// TCP protocol service construction and registration.
#[cfg(feature = "pingora")]
mod service;
/// TLS and plain listener registration for the Pingora TCP service.
#[cfg(feature = "pingora")]
mod tls;

pub use groups::validate_tcp_groups;
#[cfg(feature = "hyper")]
pub use hyper::HyperTcp;
#[cfg(feature = "pingora")]
pub use service::PingoraTcp;
