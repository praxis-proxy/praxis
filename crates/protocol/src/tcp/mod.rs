// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Raw TCP/L4 bidirectional forwarding protocol.

/// TCP connection metrics (Prometheus counters, gauges and histograms).
pub(crate) mod metrics;
/// Bidirectional TCP proxy application.
pub(crate) mod proxy;
/// TCP protocol service construction and registration.
mod service;
/// TLS configuration and listener grouping utilities.
mod tls;

pub use service::PingoraTcp;
