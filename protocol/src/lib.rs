// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

#![deny(unsafe_code)]
#![deny(unreachable_pub)]

//! Protocol adapters for Praxis.

use praxis_core::{PingoraServerRuntime, ProxyError, config::Config};
use tokio::sync::watch;

mod pipelines;
pub use pipelines::ListenerPipelines;

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
