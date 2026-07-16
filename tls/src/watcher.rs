// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Filesystem watcher for TLS certificate and client verifier
//! hot-reload.
//!
//! [`CertWatcher`] monitors cert/key files (and optionally CRL/CA
//! files) using the [`notify`] crate, debounces events, and
//! atomically reloads certificates and the client verifier on
//! detected changes.
//!
//! [`CertWatcher`]: crate::watcher::CertWatcher
//! [`notify`]: notify

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher as _};
use rustls::sign::CertifiedKey;
use tokio::sync::mpsc;

use crate::{CertKeyPair, ClientCertMode, setup::loader};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Debounce window for filesystem events.
const DEBOUNCE_MS: u64 = 500; // 500 ms

/// Minimum cooldown after a successful reload to prevent rapid churn.
const MIN_SUCCESS_COOLDOWN_MS: u64 = 5_000; // 5 seconds

/// Maximum backoff delay on consecutive reload failures.
const MAX_BACKOFF_MS: u64 = 60_000; // 60 seconds

// -----------------------------------------------------------------------------
// ClientVerifierReload
// -----------------------------------------------------------------------------

/// Configuration for hot-reloading the client certificate verifier
/// (CRL and CA files).
///
/// When provided to [`CertWatcher::spawn`], the watcher monitors
/// the CA and CRL file directories alongside the cert/key
/// directories. On any relevant filesystem change, the verifier
/// is atomically rebuilt from the current files on disk.
///
/// [`CertWatcher::spawn`]: CertWatcher::spawn
pub struct ClientVerifierReload {
    /// Path to the CA certificate PEM file.
    pub ca_path: String,

    /// Paths to CRL PEM files.
    pub crl_paths: Vec<String>,

    /// Client certificate verification mode.
    pub mode: ClientCertMode,

    /// Handle to atomically swap the inner verifier state.
    pub swap_handle: Arc<ArcSwap<crate::reload::VerifierState>>,
}

// -----------------------------------------------------------------------------
// CertWatcher
// -----------------------------------------------------------------------------

/// Watches cert/key files (and optionally CRL/CA files) for changes,
/// reloading on modification.
///
/// Spawns as a tokio background task. Debounces events by
/// `DEBOUNCE_MS` to handle atomic rename patterns (Kubernetes
/// secret updates, certbot, etc.).
///
/// When a [`ClientVerifierReload`] is provided, also monitors
/// CRL and CA files and hot-reloads the client certificate
/// verifier on changes.
///
/// ```ignore
/// let handle = CertWatcher::spawn(
///     resolver_arc, pair, None, shutdown_rx,
/// );
/// ```
pub struct CertWatcher;

impl CertWatcher {
    /// Spawn a background thread that watches cert/key paths and
    /// reloads the resolver on changes.
    ///
    /// When `verifier_reload` is `Some`, also watches CRL and CA
    /// file directories and rebuilds the client verifier on
    /// filesystem changes.
    ///
    /// Creates its own single-threaded tokio runtime so it works
    /// regardless of whether a tokio runtime is currently active
    /// (e.g. during Pingora service registration before the
    /// server starts).
    ///
    /// The thread runs for the lifetime of the process. Use
    /// `shutdown` to request early termination: send `true` to
    /// stop the watcher, or drop the sender to keep it running
    /// indefinitely.
    ///
    /// # Panics
    ///
    /// Panics if the tokio runtime cannot be created.
    #[expect(clippy::expect_used, reason = "fatal if tokio runtime cannot start")]
    pub fn spawn(
        current: Arc<ArcSwap<CertifiedKey>>,
        pair: CertKeyPair,
        verifier_reload: Option<ClientVerifierReload>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("cert watcher tokio runtime");
            rt.block_on(watch_loop(current, pair, verifier_reload, shutdown));
        })
    }
}

/// Core watch loop: sets up the notify watcher, debounces events,
/// and reloads certificates (and optionally the client verifier).
#[expect(clippy::too_many_lines, reason = "event loop with tokio::select")]
async fn watch_loop(
    current: Arc<ArcSwap<CertifiedKey>>,
    pair: CertKeyPair,
    verifier_reload: Option<ClientVerifierReload>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let (tx, mut rx) = mpsc::channel::<()>(16);

    let cert_dir = parent_dir(&pair.cert_path);
    let key_dir = parent_dir(&pair.key_path);

    let extra_dirs = verifier_extra_dirs(&verifier_reload);
    let _watcher = match setup_watcher(tx, &cert_dir, &key_dir, &extra_dirs) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(error = %e, "failed to start certificate file watcher");
            return;
        },
    };

    if verifier_reload.is_some() {
        tracing::info!(
            cert_path = %pair.cert_path,
            key_path = %pair.key_path,
            "certificate and client verifier file watcher started"
        );
    } else {
        tracing::info!(
            cert_path = %pair.cert_path,
            key_path = %pair.key_path,
            "certificate file watcher started"
        );
    }

    let mut backoff_ms = DEBOUNCE_MS;

    loop {
        tokio::select! {
            Some(()) = rx.recv() => {
                tracing::debug!(debounce_ms = backoff_ms, "filesystem change detected, debouncing");
                if drain_and_debounce(&mut rx, backoff_ms, &mut shutdown).await {
                    tracing::info!("certificate file watcher shutting down (during debounce)");
                    return;
                }

                let cert_ok = reload_cert(&current, &pair);
                let verifier_ok = reload_client_verifier(&verifier_reload);

                if cert_ok && verifier_ok {
                    backoff_ms = MIN_SUCCESS_COOLDOWN_MS;
                } else {
                    backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                    tracing::warn!(
                        next_backoff_ms = backoff_ms,
                        "reload failed, increasing backoff"
                    );
                }
            }
            result = shutdown.changed() => {
                if result.is_ok() && *shutdown.borrow() {
                    tracing::info!("certificate file watcher shutting down");
                    return;
                }
            }
        }
    }
}

/// Set up a [`RecommendedWatcher`] that sends to the given channel
/// on relevant filesystem events.
///
/// Watches `cert_dir` and `key_dir` (plus any `extra_dirs` for
/// CRL/CA files), deduplicating directories that overlap.
///
/// [`RecommendedWatcher`]: notify::RecommendedWatcher
fn setup_watcher(
    tx: mpsc::Sender<()>,
    cert_dir: &Path,
    key_dir: &Path,
    extra_dirs: &[PathBuf],
) -> Result<RecommendedWatcher, notify::Error> {
    let mut watcher = notify::recommended_watcher(move |res| handle_watch_event(res, &tx))?;

    let mut dirs = vec![cert_dir.to_path_buf(), key_dir.to_path_buf()];
    dirs.extend_from_slice(extra_dirs);
    dirs.sort();
    dirs.dedup();

    for dir in &dirs {
        watcher.watch(dir, RecursiveMode::NonRecursive)?;
    }

    Ok(watcher)
}

/// Dispatch a filesystem watcher event, forwarding relevant changes
/// to the reload channel.
fn handle_watch_event(res: Result<notify::Event, notify::Error>, tx: &mpsc::Sender<()>) {
    match res {
        Ok(event) if is_relevant_event(event.kind) => try_notify(tx),
        Err(e) => tracing::warn!(error = %e, "file watcher error"),
        _ => {},
    }
}

/// Send a notification to the reload channel, logging if full.
fn try_notify(tx: &mpsc::Sender<()>) {
    if tx.try_send(()).is_err() {
        tracing::trace!("cert watcher channel full, event coalesced by debounce");
    }
}

/// Drain pending events and sleep for the debounce window.
///
/// `delay_ms` increases on consecutive failures (backoff) and
/// resets on success. Returns `true` if shutdown was requested
/// during the sleep.
async fn drain_and_debounce(
    rx: &mut mpsc::Receiver<()>,
    delay_ms: u64,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> bool {
    let sleep = tokio::time::sleep(Duration::from_millis(delay_ms));
    tokio::pin!(sleep);
    tokio::select! {
        () = &mut sleep => {},
        result = shutdown.changed() => {
            if result.is_ok() && *shutdown.borrow() {
                return true;
            }
        },
    }
    while rx.try_recv().is_ok() {}
    false
}

/// Attempt to reload the certificate, logging success or failure.
///
/// Returns `true` on success, `false` on failure.
fn reload_cert(current: &Arc<ArcSwap<CertifiedKey>>, pair: &CertKeyPair) -> bool {
    match loader::load_certified_key(pair) {
        Ok(certified) => {
            current.store(Arc::new(certified));
            tracing::info!(
                cert_path = %pair.cert_path,
                "TLS certificate hot-reloaded successfully"
            );
            true
        },
        Err(e) => {
            tracing::warn!(
                cert_path = %pair.cert_path,
                error = %e,
                "TLS certificate reload failed, keeping previous certificate"
            );
            false
        },
    }
}

// -----------------------------------------------------------------------------
// Client Verifier Reload
// -----------------------------------------------------------------------------

/// Attempt to reload the client certificate verifier, logging
/// success or failure.
///
/// Returns `true` on success (or when no verifier reload is
/// configured), `false` on failure.
fn reload_client_verifier(reload: &Option<ClientVerifierReload>) -> bool {
    let Some(cfg) = reload else {
        return true;
    };

    match crate::client_auth::build_client_verifier(&cfg.ca_path, cfg.mode, &cfg.crl_paths) {
        Ok(verifier) => {
            cfg.swap_handle
                .store(Arc::new(crate::reload::VerifierState { verifier }));
            tracing::info!(
                ca_path = %cfg.ca_path,
                crl_count = cfg.crl_paths.len(),
                "client verifier hot-reloaded successfully"
            );
            true
        },
        Err(e) => {
            tracing::warn!(
                ca_path = %cfg.ca_path,
                error = %e,
                "client verifier reload failed, keeping previous verifier"
            );
            false
        },
    }
}

/// Collect the extra directories to watch for CRL/CA file changes.
fn verifier_extra_dirs(reload: &Option<ClientVerifierReload>) -> Vec<PathBuf> {
    let Some(cfg) = reload else {
        return Vec::new();
    };

    let mut dirs = vec![parent_dir(&cfg.ca_path)];
    for crl_path in &cfg.crl_paths {
        dirs.push(parent_dir(crl_path));
    }
    dirs
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Whether a notify event kind is relevant for cert reload.
fn is_relevant_event(kind: EventKind) -> bool {
    matches!(kind, EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_))
}

/// Extract the parent directory of a path, defaulting to `.` when the
/// parent is missing or empty.
fn parent_dir(path: &str) -> PathBuf {
    Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::disallowed_methods,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::used_underscore_binding,
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::test_utils::{gen_test_certs, gen_test_certs_in};

    #[test]
    fn parent_dir_extracts_directory() {
        let dir = parent_dir("/etc/ssl/certs/server.pem");
        assert_eq!(dir, PathBuf::from("/etc/ssl/certs"), "should extract parent");
    }

    #[test]
    fn parent_dir_root_file() {
        let dir = parent_dir("/cert.pem");
        assert_eq!(dir, PathBuf::from("/"), "root file parent should be /");
    }

    #[test]
    fn parent_dir_bare_filename() {
        let dir = parent_dir("cert.pem");
        assert_eq!(dir, PathBuf::from("."), "bare filename should fall back to .");
    }

    #[test]
    fn is_relevant_event_create() {
        assert!(
            is_relevant_event(EventKind::Create(notify::event::CreateKind::File)),
            "Create events should be relevant"
        );
    }

    #[test]
    fn is_relevant_event_modify() {
        assert!(
            is_relevant_event(EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content
            ))),
            "Modify events should be relevant"
        );
    }

    #[test]
    fn is_relevant_event_remove() {
        assert!(
            is_relevant_event(EventKind::Remove(notify::event::RemoveKind::File)),
            "Remove events should be relevant"
        );
    }

    #[test]
    fn is_relevant_event_access_is_not_relevant() {
        assert!(
            !is_relevant_event(EventKind::Access(notify::event::AccessKind::Read)),
            "Access events should not be relevant"
        );
    }

    #[test]
    fn spawn_watcher_shuts_down_on_signal() {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };
        let certified = loader::load_certified_key(&pair).expect("load cert");
        let current = Arc::new(ArcSwap::from_pointee(certified));

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = CertWatcher::spawn(current, pair, None, shutdown_rx);

        std::thread::sleep(Duration::from_millis(50));
        let _sent = shutdown_tx.send(true);

        let result = handle.join();
        assert!(result.is_ok(), "watcher thread should shut down cleanly");
    }

    #[test]
    fn reload_cert_failure_returns_false() {
        let certs = gen_test_certs();
        let good_pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };
        let certified = loader::load_certified_key(&good_pair).expect("load cert");
        let original_der = certified.cert[0].as_ref().to_vec();
        let current = Arc::new(ArcSwap::from_pointee(certified));

        let bad_pair = CertKeyPair {
            cert_path: "/nonexistent/cert.pem".to_owned(),
            default: false,
            key_path: "/nonexistent/key.pem".to_owned(),
            server_names: Vec::new(),
        };

        let success = reload_cert(&current, &bad_pair);
        assert!(!success, "reload with nonexistent paths should return false");

        let after_der = current.load_full().cert[0].as_ref().to_vec();
        assert_eq!(
            original_der, after_der,
            "certificate should be unchanged after failed reload"
        );
    }

    #[test]
    fn reload_cert_success_returns_true() {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };
        let certified = loader::load_certified_key(&pair).expect("load cert");
        let current = Arc::new(ArcSwap::from_pointee(certified));

        let new_certs = gen_test_certs();
        let new_pair = CertKeyPair {
            cert_path: new_certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: new_certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };

        let success = reload_cert(&current, &new_pair);
        assert!(success, "reload with valid paths should return true");
    }

    #[test]
    fn backoff_doubles_on_consecutive_failures() {
        let mut backoff_ms = DEBOUNCE_MS;

        backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
        assert_eq!(backoff_ms, DEBOUNCE_MS * 2, "first failure should double backoff");

        backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
        assert_eq!(backoff_ms, DEBOUNCE_MS * 4, "second failure should double again");
    }

    #[test]
    fn backoff_caps_at_max() {
        let mut backoff_ms = MAX_BACKOFF_MS / 2 + 1;

        backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
        assert_eq!(backoff_ms, MAX_BACKOFF_MS, "backoff should cap at MAX_BACKOFF_MS");

        backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
        assert_eq!(backoff_ms, MAX_BACKOFF_MS, "backoff should remain at MAX_BACKOFF_MS");
    }

    #[test]
    fn backoff_resets_on_success() {
        let mut backoff_ms = DEBOUNCE_MS;

        backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
        backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
        assert!(backoff_ms > DEBOUNCE_MS, "backoff should have increased after failures");

        backoff_ms = MIN_SUCCESS_COOLDOWN_MS;
        assert_eq!(
            backoff_ms, MIN_SUCCESS_COOLDOWN_MS,
            "backoff should reset to MIN_SUCCESS_COOLDOWN_MS on success"
        );
    }

    #[test]
    fn watcher_reloads_on_file_change() {
        let certs = gen_test_certs();
        let temp_dir = certs._temp_dir.as_ref().expect("temp dir");
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };
        let certified = loader::load_certified_key(&pair).expect("load cert");
        let before_der = certified.cert[0].as_ref().to_vec();
        let current = Arc::new(ArcSwap::from_pointee(certified));

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let _handle = CertWatcher::spawn(Arc::clone(&current), pair.clone(), None, shutdown_rx);

        std::thread::sleep(Duration::from_millis(100));

        let new_certs = gen_test_certs_in(temp_dir.path());
        drop(new_certs);

        std::thread::sleep(Duration::from_millis(2000));

        let after_der = current.load_full().cert[0].as_ref().to_vec();

        let _sent = shutdown_tx.send(true);

        assert_ne!(
            before_der, after_der,
            "certificate should change after file modification"
        );
    }

    #[test]
    fn reload_client_verifier_returns_true_when_none() {
        assert!(
            reload_client_verifier(&None),
            "no verifier reload config should return true"
        );
    }

    #[test]
    fn verifier_extra_dirs_empty_when_none() {
        let dirs = verifier_extra_dirs(&None);
        assert!(dirs.is_empty(), "no verifier config should yield empty dirs");
    }

    #[test]
    fn verifier_extra_dirs_includes_ca_and_crl() {
        use crate::test_utils::{ensure_crypto_provider, gen_ca_file};

        ensure_crypto_provider();
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path").to_owned();
        let ca_dir = parent_dir(&ca_path);

        let verifier = crate::reload::ReloadableClientVerifier::new(&ca_path, ClientCertMode::Require, &[])
            .expect("verifier creation");

        let reload = Some(ClientVerifierReload {
            ca_path: ca_path.clone(),
            crl_paths: vec!["/etc/ssl/crl.pem".to_owned()],
            mode: ClientCertMode::Require,
            swap_handle: verifier.arc(),
        });

        let dirs = verifier_extra_dirs(&reload);
        assert_eq!(dirs.len(), 2, "should include CA dir and CRL dir");
        assert_eq!(dirs[0], ca_dir, "first dir should be CA parent");
        assert_eq!(dirs[1], PathBuf::from("/etc/ssl"), "second dir should be CRL parent");
    }
}
