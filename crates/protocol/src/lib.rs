// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::iter_over_hash_type,
    clippy::min_ident_chars,
    clippy::mod_module_files,
    clippy::partial_pub_fields,
    clippy::pub_underscore_fields,
    clippy::shadow_unrelated,
    clippy::single_char_lifetime_names,
    clippy::wildcard_enum_match_arm,
    reason = "TODO(conventions-sync): fix violations and remove"
)]

//! Protocol adapters for Praxis.
//!
//! `praxis-protocol` sits below `server` and above `filter` in the
//! crate dependency flow `server -> protocol -> filter -> core -> tls`.
//! It binds the [`praxis_filter`] pipeline engine to Pingora's HTTP and
//! TCP proxy services, so that inbound connections are served, filters
//! run at the right lifecycle points, and requests are forwarded to
//! upstream clusters.
//!
//! Responsibilities:
//! - HTTP protocol implementations and Pingora adapters ([`http`]).
//! - Raw TCP/L4 forwarding ([`tcp`]).
//! - Active health-check probes and admin/observability endpoints.
//! - TLS listener setup (the `tls_setup` module), plus holding the certificate hot-reload watcher shutdown handles so
//!   those watchers can be stopped early ([`CertWatcherShutdowns`]).
//!
//! Boundary with Pingora: Pingora owns request-smuggling prevention,
//! HTTP/2 backpressure, connection-pool safety, and HTTP/1.1 upgrade
//! detection with bidirectional forwarding (WebSocket and similar).
//! Praxis code in this crate and in [`praxis_filter`] owns hop-by-hop
//! header stripping (with conditional preservation for upgrade
//! requests), Host validation, `X-Forwarded-*` injection, and retry
//! logic.

mod cert_watcher_shutdowns;
pub use cert_watcher_shutdowns::CertWatcherShutdowns;

mod pipelines;
pub use pipelines::ListenerPipelines;

mod protocol;
pub use protocol::Protocol;

/// Process-wide connection limit.
pub mod connections;
/// HTTP protocol implementations.
pub mod http;
/// Raw TCP/L4 forwarding protocol.
pub mod tcp;

/// Shared TLS settings builder for HTTP and TCP listeners.
pub(crate) mod tls_setup;
