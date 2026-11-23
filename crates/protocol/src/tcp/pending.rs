// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Pending Pingora TLS admissions keyed by the socket digest's allocation.

use std::sync::{Arc, Mutex, Weak};

use async_trait::async_trait;
use pingora_core::{
    listeners::PreTlsProcess,
    protocols::{GetSocketDigest as _, SocketDigest, l4::stream::Stream as L4Stream},
};
use tokio::task::JoinHandle;

use super::proxy::{TcpAdmission, TcpAdmissionGate};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Dead handshake cleanup interval, independent of subsequent group traffic.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

// -----------------------------------------------------------------------------
// Pending Admissions
// -----------------------------------------------------------------------------

/// A TLS handshake's digest identity and its owned admission claim.
struct PendingEntry {
    /// Weak identity, never keeping a failed handshake alive.
    digest: Weak<SocketDigest>,
    /// Claim transferred into the successful session or dropped on failure.
    admission: TcpAdmission,
}

/// Per-group admission handoff and dead-handshake reclamation.
pub(super) struct PendingAdmissions {
    /// Handshakes not yet handed to `process_new`.
    entries: Mutex<Vec<PendingEntry>>,
    /// Sweep task, aborted when the last owner drops.
    sweeper: Mutex<Option<JoinHandle<()>>>,
}

impl PendingAdmissions {
    /// Create an empty group registry.
    pub(super) fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            sweeper: Mutex::new(None),
        }
    }

    /// Register the exact socket digest before TLS starts.
    pub(super) fn insert(self: &Arc<Self>, digest: &Arc<SocketDigest>, admission: TcpAdmission) -> bool {
        let weak = Arc::downgrade(digest);
        let mut entries = self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|entry| entry.digest.upgrade().is_some());
        if entries.iter().any(|entry| Weak::ptr_eq(&entry.digest, &weak)) {
            return false;
        }
        entries.push(PendingEntry {
            digest: weak,
            admission,
        });
        drop(entries);
        self.start_sweeper();
        true
    }

    /// Transfer one token to the successful TLS stream, failing closed if absent.
    pub(super) fn take(&self, digest: &Arc<SocketDigest>) -> Option<TcpAdmission> {
        let weak = Arc::downgrade(digest);
        let mut entries = self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = entries.iter().position(|entry| Weak::ptr_eq(&entry.digest, &weak))?;
        Some(entries.swap_remove(index).admission)
    }

    /// Release only claims whose socket digests are no longer alive.
    pub(super) fn prune_dead(&self) {
        let mut entries = self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|entry| entry.digest.upgrade().is_some());
    }

    /// Start one periodic sweep after the runtime begins polling callbacks.
    fn start_sweeper(self: &Arc<Self>) {
        let mut guard = self.sweeper.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.is_some() {
            return;
        }
        let weak = Arc::downgrade(self);
        *guard = Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                ticker.tick().await;
                let Some(registry) = weak.upgrade() else {
                    break;
                };
                registry.prune_dead();
            }
        }));
    }
}

impl Drop for PendingAdmissions {
    fn drop(&mut self) {
        if let Ok(sweeper) = self.sweeper.get_mut()
            && let Some(task) = sweeper.take()
        {
            task.abort();
        }
    }
}

// -----------------------------------------------------------------------------
// Pre-TLS Callback
// -----------------------------------------------------------------------------

/// Acquires the shared gate before Pingora starts a TLS handshake.
pub(super) struct PreTlsAdmission {
    /// Shared process and TCP group gate.
    pub(super) gate: Arc<TcpAdmissionGate>,
    /// Group handoff registry.
    pub(super) pending: Arc<PendingAdmissions>,
}

#[async_trait]
impl PreTlsProcess for PreTlsAdmission {
    async fn process(&self, stream: &mut L4Stream) -> pingora_core::Result<()> {
        let digest = stream.get_socket_digest().ok_or_else(|| {
            pingora_core::Error::explain(pingora_core::ErrorType::InternalError, "missing TCP socket digest")
        })?;
        let remote = digest
            .peer_addr()
            .map_or_else(|| "unknown".to_owned(), ToString::to_string);
        self.pending.prune_dead();
        if !self.pending.insert(
            &digest,
            self.gate.try_admit(&remote).ok_or_else(|| {
                pingora_core::Error::explain(pingora_core::ErrorType::ConnectionClosed, "TCP admission rejected")
            })?,
        ) {
            return Err(pingora_core::Error::explain(
                pingora_core::ErrorType::InternalError,
                "duplicate TCP socket digest admission",
            ));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[cfg(unix)]
#[expect(clippy::expect_used, reason = "test assertions identify missing admissions")]
mod tests {
    use tokio::sync::Semaphore;

    use super::*;

    #[tokio::test(start_paused = true)]
    #[expect(
        clippy::too_many_lines,
        reason = "identity, handoff, and dead-sweep lifecycle assertions"
    )]
    async fn pending_admission_tracks_digest_lifetime() {
        let group = Arc::new(Semaphore::new(1));
        let gate = TcpAdmissionGate::new(Some(Arc::clone(&group)), None);
        let pending = Arc::new(PendingAdmissions::new());
        let digest = Arc::new(SocketDigest::from_raw_fd(-1));
        assert!(
            pending.insert(&digest, gate.try_admit("test").expect("first admission")),
            "first identity is unique"
        );
        let other = Arc::new(SocketDigest::from_raw_fd(-1));
        assert!(
            pending.take(&other).is_none(),
            "the same raw FD is not the same identity"
        );
        assert!(
            !pending.insert(
                &digest,
                TcpAdmissionGate::new(None, None)
                    .try_admit("test")
                    .expect("duplicate claim")
            ),
            "duplicate identity is rejected"
        );
        assert!(gate.try_admit("test").is_none(), "pending TLS consumes the group slot");
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_millis(750)).await;
        assert_eq!(
            group.available_permits(),
            0,
            "a live digest survives several sweep ticks"
        );
        let handed_off = pending.take(&digest).expect("same digest receives its token");
        assert!(pending.take(&digest).is_none(), "handoff occurs only once");
        drop(handed_off);
        assert_eq!(group.available_permits(), 1, "session drop releases the same slot");

        let abandoned = Arc::new(SocketDigest::from_raw_fd(-1));
        assert!(
            pending.insert(&abandoned, gate.try_admit("test").expect("slot recovered")),
            "second identity is unique"
        );
        drop(abandoned);
        tokio::time::advance(std::time::Duration::from_millis(750)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            group.available_permits(),
            1,
            "dead handshake recovers without group traffic"
        );
        let weak = Arc::downgrade(&pending);
        drop(pending);
        assert!(weak.upgrade().is_none(), "sweeper holds no strong registry owner");
    }
}
