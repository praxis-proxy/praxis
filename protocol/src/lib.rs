// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

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
//! - TLS listener setup (`tls_setup`) and keeping certificate hot-reload watchers alive for the process lifetime
//!   ([`CertWatcherShutdowns`]).
//!
//! Boundary with Pingora: Pingora owns request-smuggling prevention,
//! HTTP/2 backpressure, connection-pool safety, and HTTP/1.1 upgrade
//! detection with bidirectional forwarding (WebSocket and similar).
//! Praxis code in this crate and in [`praxis_filter`] owns hop-by-hop
//! header stripping (with conditional preservation for upgrade
//! requests), Host validation, `X-Forwarded-*` injection, and retry
//! logic.

use praxis_core::{PingoraServerRuntime, ProxyError, config::Config};
use tokio::sync::watch;

mod pipelines;
pub use pipelines::ListenerPipelines;

/// Process-wide connection limit.
pub mod connections;
/// HTTP protocol implementations.
pub mod http;
/// Raw TCP/L4 forwarding protocol.
pub mod tcp;

/// Shared TLS settings builder for HTTP and TCP listeners.
pub(crate) mod tls_setup;

// -----------------------------------------------------------------------------
// CertWatcherShutdowns
// -----------------------------------------------------------------------------

/// Collected TLS certificate watcher shutdown senders.
///
/// Keeps [`watch::Sender`]s alive so that background [`CertWatcher`]
/// tasks run until the process exits. Dropping these senders signals
/// the watchers to stop.
///
/// [`watch::Sender`]: tokio::sync::watch::Sender
/// [`CertWatcher`]: praxis_tls::watcher::CertWatcher
pub struct CertWatcherShutdowns {
    /// Shutdown senders kept alive for the server lifetime.
    _senders: Vec<watch::Sender<bool>>,
}

impl CertWatcherShutdowns {
    /// Wrap collected shutdown senders.
    pub fn new(senders: Vec<watch::Sender<bool>>) -> Self {
        Self { _senders: senders }
    }
}

// -----------------------------------------------------------------------------
// Protocol
// -----------------------------------------------------------------------------

/// A protocol implementation that registers services onto a shared server runtime.
pub trait Protocol: Send {
    /// Register this protocol's services. Does not block.
    ///
    /// Returns any TLS certificate watcher shutdown senders. The
    /// caller must keep these alive until server shutdown; dropping
    /// them signals the watcher tasks to stop.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] if listener binding or setup fails.
    ///
    /// [`ProxyError`]: praxis_core::ProxyError
    fn register(
        self: Box<Self>,
        server: &mut PingoraServerRuntime,
        config: &Config,
        pipelines: &ListenerPipelines,
    ) -> Result<Vec<watch::Sender<bool>>, ProxyError>;
}
