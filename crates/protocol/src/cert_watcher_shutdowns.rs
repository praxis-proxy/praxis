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
    senders: Vec<watch::Sender<bool>>,
}

impl CertWatcherShutdowns {
    /// Wrap collected shutdown senders.
    pub fn new(senders: Vec<watch::Sender<bool>>) -> Self {
        Self { senders }
    }

    /// Explicitly stop every certificate watcher after the server returns.
    pub fn shutdown(self) {
        for sender in &self.senders {
            _ = sender.send(true);
        }
    }
}

/// Roll back watchers started during a fallible registration.
#[cfg(any(feature = "pingora", feature = "hyper"))]
#[derive(Default)]
pub(crate) struct RegistrationWatchers {
    /// Watchers started by the current registration.
    senders: Vec<watch::Sender<bool>>,
}

#[cfg(any(feature = "pingora", feature = "hyper"))]
impl RegistrationWatchers {
    /// Borrow the collection used by existing listener registration helpers.
    pub(crate) fn senders_mut(&mut self) -> &mut Vec<watch::Sender<bool>> {
        &mut self.senders
    }

    /// Transfer the handles after registration succeeds.
    pub(crate) fn finish(mut self) -> Vec<watch::Sender<bool>> {
        std::mem::take(&mut self.senders)
    }
}

#[cfg(any(feature = "pingora", feature = "hyper"))]
impl Drop for RegistrationWatchers {
    fn drop(&mut self) {
        for sender in &self.senders {
            _ = sender.send(true);
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_shutdown_signals_every_watcher() {
        let (first, first_rx) = watch::channel(false);
        let (second, second_rx) = watch::channel(false);
        CertWatcherShutdowns::new(vec![first, second]).shutdown();
        assert!(*first_rx.borrow(), "first watcher must stop");
        assert!(*second_rx.borrow(), "second watcher must stop");
    }

    #[test]
    fn ordinary_drop_preserves_watcher_value() {
        let (sender, receiver) = watch::channel(false);
        drop(CertWatcherShutdowns::new(vec![sender]));
        assert!(!*receiver.borrow(), "ordinary drop must not signal shutdown");
    }
}
