// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Shutdown handles for the TLS certificate hot-reload watchers.
//!
//! The server keeps a [`CertWatcherShutdowns`] for the process lifetime so the
//! certificate watchers spawned during protocol registration can be stopped
//! early if needed.

use tokio::sync::watch;

/// Collected TLS certificate watcher shutdown senders.
///
/// Background [`CertWatcher`] tasks run for the process lifetime. These
/// [`watch::Sender`]s are held so a watcher can be asked to stop early via
/// `send(true)`; dropping them does not stop the watchers (they end at process
/// exit).
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
