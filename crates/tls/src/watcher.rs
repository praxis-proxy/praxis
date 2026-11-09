// SPDX-License-Identifier: Apache-2.0
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
    io::Read as _,
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

/// Backoff value after a successful reload. It only seeds the failure retry
/// timer, which is idle after a success; each newly detected change debounces
/// for [`DEBOUNCE_MS`] and restarts the backoff, whether the filesystem
/// reported it or the fallback poll found it.
const MIN_SUCCESS_COOLDOWN_MS: u64 = 5_000; // 5 seconds

/// Maximum backoff delay on consecutive reload failures.
const MAX_BACKOFF_MS: u64 = 60_000; // 60 seconds

/// Fallback interval for filesystems whose atomic updates generate no events.
const CERTIFICATE_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Chunk size for streaming a file digest, so large CRLs are never loaded whole.
const DIGEST_BUFFER_BYTES: usize = 16 * 1024; // 16 KiB

// Completed certificate polls on this thread. Tests use it to wait for an
// explicit poll instead of inferring completion from a sleep. Thread-local
// keeps parallel tests from waking each other.
#[cfg(test)]
thread_local! {
    /// Number of polls this thread has finished.
    static POLLS_COMPLETED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

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

    /// SPIFFE IDs authorized at a `RequireNamed` handshake. Empty accepts any
    /// valid X.509-SVID leaf.
    pub trusted_spiffe_ids: Vec<String>,

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
    /// `file_hashes` is the polling baseline read before the startup load.
    /// Taking it before the load keeps a rotation that lands between the load
    /// and this call visible: the first poll sees the new digests and reloads,
    /// so the served certificate always matches the files. A baseline hashed
    /// after the load would instead record the new bytes while the loaded
    /// state is still the old one, and the poll would skip the change.
    pub fn spawn(
        current: Arc<ArcSwap<CertifiedKey>>,
        pair: CertKeyPair,
        verifier_reload: Option<ClientVerifierReload>,
        shutdown: tokio::sync::watch::Receiver<bool>,
        file_hashes: Vec<Option<[u8; 32]>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(err) => {
                    tracing::warn!(error = %err, "failed to start certificate watcher runtime; hot reload disabled");
                    return;
                },
            };
            rt.block_on(watch_loop(current, pair, verifier_reload, file_hashes, shutdown));
        })
    }
}

/// How the watch loop should react to a change on the shutdown channel.
enum ShutdownAction {
    /// Shutdown was requested; stop the loop.
    Shutdown,
    /// A spurious wake-up (value unchanged); keep polling the channel.
    KeepPolling,
    /// The shutdown sender was dropped; stop polling this arm so the loop
    /// does not busy-spin on a perpetually-ready error.
    StopPolling,
}

/// Decide how to react to a shutdown-channel change.
///
/// `changed_ok` is whether [`watch::Receiver::changed`] returned `Ok` (the
/// sender is still alive); `requested` is the current channel value. A
/// dropped sender yields `changed_ok == false`.
///
/// [`watch::Receiver::changed`]: tokio::sync::watch::Receiver::changed
fn on_shutdown_change(changed_ok: bool, requested: bool) -> ShutdownAction {
    match (changed_ok, requested) {
        (true, true) => ShutdownAction::Shutdown,
        (true, false) => ShutdownAction::KeepPolling,
        (false, _) => ShutdownAction::StopPolling,
    }
}

/// Core watch loop: sets up the notify watcher, debounces events,
/// and reloads certificates (and optionally the client verifier).
async fn watch_loop(
    current: Arc<ArcSwap<CertifiedKey>>,
    pair: CertKeyPair,
    verifier_reload: Option<ClientVerifierReload>,
    file_hashes: Vec<Option<[u8; 32]>>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let (tx, rx) = mpsc::channel::<()>(16);

    let cert_dir = parent_dir(&pair.cert_path);
    let key_dir = parent_dir(&pair.key_path);

    let extra_dirs = verifier_extra_dirs(verifier_reload.as_ref());
    let _watcher = match setup_watcher(tx, &cert_dir, &key_dir, &extra_dirs) {
        Ok(watcher) => Some(watcher),
        Err(err) => {
            tracing::warn!(error = %err, "failed to start certificate file watcher; using polling");
            None
        },
    };

    watch_events(current, pair, verifier_reload, file_hashes, shutdown, rx).await;
}

/// Watches a notification stream and polls watched files for missed changes.
#[expect(
    clippy::too_many_arguments,
    reason = "the event loop borrows every watcher input for the process lifetime"
)]
#[expect(clippy::too_many_lines, reason = "event loop with tokio::select")]
async fn watch_events(
    current: Arc<ArcSwap<CertifiedKey>>,
    pair: CertKeyPair,
    verifier_reload: Option<ClientVerifierReload>,
    mut file_hashes: Vec<Option<[u8; 32]>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    mut rx: mpsc::Receiver<()>,
) {
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
    let mut watch_shutdown = true;
    let mut retry_pending = false;
    let mut certificate_poll = tokio::time::interval(CERTIFICATE_POLL_INTERVAL);
    certificate_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            Some(()) = rx.recv() => {
                tracing::debug!(debounce_ms = DEBOUNCE_MS, "filesystem change detected, debouncing");
                if drain_and_debounce(&mut rx, DEBOUNCE_MS, &mut shutdown).await {
                    tracing::info!("certificate file watcher shutting down (during debounce)");
                    return;
                }

                backoff_ms = DEBOUNCE_MS;
                retry_pending = !reload_tracked(&current, &pair, verifier_reload.as_ref(), &mut backoff_ms, &mut file_hashes).await;
            }
            _ = certificate_poll.tick(), if !retry_pending => {
                let observed = watched_file_hashes(&pair, verifier_reload.as_ref()).await;
                if observed != file_hashes || observed.iter().any(Option::is_none) {
                    backoff_ms = DEBOUNCE_MS;
                    retry_pending = !reload_tracked(&current, &pair, verifier_reload.as_ref(), &mut backoff_ms, &mut file_hashes).await;
                }
                #[cfg(test)]
                POLLS_COMPLETED.with(|completed| completed.set(completed.get().saturating_add(1)));
            }
            () = tokio::time::sleep(Duration::from_millis(backoff_ms)), if retry_pending => {
                tracing::info!("retrying the failed certificate reload");
                retry_pending = !reload_tracked(&current, &pair, verifier_reload.as_ref(), &mut backoff_ms, &mut file_hashes).await;
            }
            result = shutdown.changed(), if watch_shutdown => {
                // Copy the flag out of the borrow guard before the match so the
                // temporary Ref does not live across the arms.
                let requested = *shutdown.borrow();
                match on_shutdown_change(result.is_ok(), requested) {
                    ShutdownAction::Shutdown => {
                        tracing::info!("certificate file watcher shutting down");
                        return;
                    },
                    ShutdownAction::KeepPolling => {},
                    ShutdownAction::StopPolling => {
                        // The shutdown sender was dropped. The watcher runs for
                        // the process lifetime, so stop polling this arm (parking
                        // select! on rx.recv()) rather than spinning on a
                        // perpetually-ready Err; early termination is only via
                        // send(true), which keeps a live sender.
                        watch_shutdown = false;
                    },
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
        Err(err) => tracing::warn!(error = %err, "file watcher error"),
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

/// Reloads and records a digest baseline that matches what the load installed.
///
/// Digests are taken before and after the load. When they differ, a file
/// changed while it was being read, so no baseline is recorded and the caller
/// schedules another reload. Recording the pre-load digests would leave a
/// baseline for bytes that were never installed, and the next poll would skip
/// the change.
async fn reload_tracked(
    current: &Arc<ArcSwap<CertifiedKey>>,
    pair: &CertKeyPair,
    verifier: Option<&ClientVerifierReload>,
    backoff_ms: &mut u64,
    file_hashes: &mut Vec<Option<[u8; 32]>>,
) -> bool {
    let before = watched_file_hashes(pair, verifier).await;
    if !reload_with_backoff(current, pair, verifier, backoff_ms) {
        return false;
    }
    let after = watched_file_hashes(pair, verifier).await;
    if before == after {
        *file_hashes = after;
        true
    } else {
        tracing::debug!("watched files changed during the reload; scheduling another");
        false
    }
}

/// Reload the certificate and client verifier and update `backoff_ms`,
/// returning whether both loaded. A failure is retried on the backoff timer,
/// so a file caught mid-write heals without waiting for the next change.
fn reload_with_backoff(
    current: &Arc<ArcSwap<CertifiedKey>>,
    pair: &CertKeyPair,
    verifier_reload: Option<&ClientVerifierReload>,
    backoff_ms: &mut u64,
) -> bool {
    let cert_ok = reload_cert(current, pair);
    let verifier_ok = reload_client_verifier(verifier_reload);
    let reloaded = cert_ok && verifier_ok;
    *backoff_ms = next_backoff(reloaded, *backoff_ms);
    if !reloaded {
        tracing::warn!(
            cert_ok,
            verifier_ok,
            retry_in_ms = *backoff_ms,
            "certificate or client verifier reload failed; retrying after backoff"
        );
    }
    reloaded
}

/// The delay before the next reload: a cooldown after a success, or the
/// previous delay doubled, up to [`MAX_BACKOFF_MS`], after a failure.
fn next_backoff(reloaded: bool, backoff_ms: u64) -> u64 {
    if reloaded {
        MIN_SUCCESS_COOLDOWN_MS
    } else {
        backoff_ms.saturating_mul(2).min(MAX_BACKOFF_MS)
    }
}

/// Fingerprints every certificate, key, CA and CRL monitored by the watcher.
///
/// The reads and hashing run on the blocking pool so a slow filesystem or a
/// large CRL cannot stall the watcher's runtime while a poll is in flight.
async fn watched_file_hashes(pair: &CertKeyPair, verifier: Option<&ClientVerifierReload>) -> Vec<Option<[u8; 32]>> {
    let (ca_path, crl_paths) = verifier_paths(verifier);
    let paths = watched_paths(pair, ca_path, crl_paths);
    let count = paths.len();
    tokio::task::spawn_blocking(move || paths.iter().map(|path| file_digest(path)).collect())
        .await
        .unwrap_or_else(|_| vec![None; count])
}

/// Paths the watcher fingerprints, shared with the startup snapshot.
///
/// The order is the primary certificate, its key, then the client CA and any
/// CRLs. Both the startup baseline and polling must use this one function so a
/// mismatch in order or membership cannot masquerade as an unchanged file.
pub(crate) fn watched_paths(pair: &CertKeyPair, ca_path: Option<&str>, crl_paths: &[String]) -> Vec<String> {
    let mut paths = vec![pair.cert_path.clone(), pair.key_path.clone()];
    if let Some(ca_path) = ca_path {
        paths.push(ca_path.to_owned());
        paths.extend(crl_paths.iter().cloned());
    }
    paths
}

/// Split a verifier reload into the CA and CRL inputs [`watched_paths`] takes.
fn verifier_paths(verifier: Option<&ClientVerifierReload>) -> (Option<&str>, &[String]) {
    match verifier {
        Some(verifier) => (Some(verifier.ca_path.as_str()), verifier.crl_paths.as_slice()),
        None => (None, &[]),
    }
}

/// Fingerprints the watched files on the calling thread.
///
/// Test helper that mirrors the pre-load snapshot the startup path takes.
#[cfg(test)]
fn file_hashes_now(pair: &CertKeyPair, verifier: Option<&ClientVerifierReload>) -> Vec<Option<[u8; 32]>> {
    let (ca_path, crl_paths) = verifier_paths(verifier);
    watched_paths(pair, ca_path, crl_paths)
        .iter()
        .map(|path| file_digest(path))
        .collect()
}

/// SHA-256 of one watched file, or `None` when it cannot be read.
///
/// The setup path uses it to snapshot the files before the startup load.
pub(crate) fn file_digest(path: &str) -> Option<[u8; 32]> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256()).ok()?;
    let mut buffer = zeroize::Zeroizing::new(vec![0_u8; DIGEST_BUFFER_BYTES]);
    loop {
        let read = file.read(buffer.as_mut_slice()).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(buffer.get(..read)?).ok()?;
    }
    let digest = hasher.finish().ok()?;
    digest.as_ref().try_into().ok()
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
        Err(err) => {
            tracing::warn!(
                cert_path = %pair.cert_path,
                error = %err,
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
fn reload_client_verifier(reload: Option<&ClientVerifierReload>) -> bool {
    let Some(cfg) = reload else {
        return true;
    };

    match crate::client_auth::build_client_verifier(&cfg.ca_path, cfg.mode, &cfg.crl_paths, &cfg.trusted_spiffe_ids) {
        Ok(verifier) => {
            cfg.swap_handle
                .store(Arc::new(crate::reload::VerifierState::new(verifier, cfg.mode)));
            tracing::info!(
                ca_path = %cfg.ca_path,
                crl_count = cfg.crl_paths.len(),
                "client verifier hot-reloaded successfully"
            );
            true
        },
        Err(err) => {
            tracing::warn!(
                ca_path = %cfg.ca_path,
                error = %err,
                "client verifier reload failed, keeping previous verifier"
            );
            false
        },
    }
}

/// Collect the extra directories to watch for CRL/CA file changes.
fn verifier_extra_dirs(reload: Option<&ClientVerifierReload>) -> Vec<PathBuf> {
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
        .filter(|parent| !parent.as_os_str().is_empty())
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
    fn shutdown_change_decisions() {
        assert!(matches!(on_shutdown_change(true, true), ShutdownAction::Shutdown));
        assert!(matches!(on_shutdown_change(true, false), ShutdownAction::KeepPolling));
        assert!(
            matches!(on_shutdown_change(false, false), ShutdownAction::StopPolling),
            "a dropped sender (changed() -> Err) must stop polling, not spin"
        );
        assert!(
            matches!(on_shutdown_change(false, true), ShutdownAction::StopPolling),
            "a dropped sender must stop polling regardless of the last observed value"
        );
    }

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
        let baseline = file_hashes_now(&pair, None);
        let handle = CertWatcher::spawn(current, pair, None, shutdown_rx, baseline);

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
    fn a_failed_reload_doubles_the_retry_delay_up_to_the_cap() {
        assert_eq!(
            next_backoff(false, DEBOUNCE_MS),
            DEBOUNCE_MS * 2,
            "a failure must double the delay before the retry"
        );
        assert_eq!(
            next_backoff(false, MAX_BACKOFF_MS),
            MAX_BACKOFF_MS,
            "repeated failures must keep retrying at the cap, not stop"
        );
        assert_eq!(
            next_backoff(true, MAX_BACKOFF_MS),
            MIN_SUCCESS_COOLDOWN_MS,
            "a success must reset to the cooldown"
        );
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
        let temp_dir = certs.temp_dir.as_ref().expect("temp dir");
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
        let baseline = file_hashes_now(&pair, None);
        let _handle = CertWatcher::spawn(Arc::clone(&current), pair.clone(), None, shutdown_rx, baseline);

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

    #[tokio::test(start_paused = true)]
    #[expect(clippy::too_many_lines, reason = "end-to-end polling setup and assertion")]
    async fn polling_reloads_when_notify_setup_fails() {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };
        let current = Arc::new(ArcSwap::from_pointee(
            loader::load_certified_key(&pair).expect("load cert"),
        ));
        let before = current.load_full();
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing_dir = directory.path().join("missing");
        let missing_pair = CertKeyPair {
            cert_path: missing_dir.join("cert.pem").to_str().expect("cert path").to_owned(),
            key_path: missing_dir.join("key.pem").to_str().expect("key path").to_owned(),
            ..pair
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(watch_loop(
            Arc::clone(&current),
            missing_pair.clone(),
            None,
            vec![None, None],
            shutdown_rx,
        ));
        tokio::task::yield_now().await;
        let rotated = gen_test_certs();
        std::fs::create_dir(&missing_dir).expect("create missing directory");
        std::fs::copy(&rotated.cert_path, &missing_pair.cert_path).expect("copy cert");
        std::fs::copy(&rotated.key_path, &missing_pair.key_path).expect("copy key");
        tokio::time::advance(CERTIFICATE_POLL_INTERVAL).await;
        wait_until(|| before.cert != current.load().cert).await;
        shutdown_tx.send(true).expect("stop polling");
        task.await.expect("watch task");
        assert_ne!(
            before.cert,
            current.load().cert,
            "polling alone must reload after notify setup fails"
        );
    }

    #[tokio::test(start_paused = true)]
    #[expect(clippy::too_many_lines, reason = "startup rotation fixture and polling assertions")]
    async fn startup_baseline_taken_before_the_load_reloads_a_changed_file() {
        let certs = gen_test_certs();
        let directory = certs.temp_dir.as_ref().expect("temp dir");
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };
        let current = Arc::new(ArcSwap::from_pointee(
            loader::load_certified_key(&pair).expect("load cert"),
        ));
        let loaded = current.load_full().cert[0].as_ref().to_vec();
        // The startup path snapshots the files before loading them, so the
        // baseline describes the certificate the load is expected to read.
        let startup_baseline = file_hashes_now(&pair, None);

        // A projection swap lands between that load and the watcher start.
        let rotated = gen_test_certs_in(directory.path());
        let expected = loader::load_certified_key(&pair).expect("load rotated cert").cert[0]
            .as_ref()
            .to_vec();
        drop(rotated);
        assert_ne!(loaded, expected, "the fixture must rotate the certificate");

        let (_notifications, events) = mpsc::channel(1);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(watch_events(
            Arc::clone(&current),
            pair,
            None,
            startup_baseline,
            shutdown_rx,
            events,
        ));
        tokio::time::advance(CERTIFICATE_POLL_INTERVAL).await;
        wait_until(|| current.load().cert[0].as_ref() != loaded.as_slice()).await;
        assert_eq!(
            current.load().cert[0].as_ref(),
            expected.as_slice(),
            "the first poll must install a rotation that landed after the startup load"
        );
        shutdown_tx.send(true).expect("stop polling");
        task.await.expect("watch task");
    }

    #[tokio::test(start_paused = true)]
    #[expect(
        clippy::too_many_lines,
        reason = "CA-only and CRL-only polling and notification assertions"
    )]
    async fn polling_installs_client_trust_without_filesystem_notifications() {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().unwrap().to_owned(),
            key_path: certs.key_path.to_str().unwrap().to_owned(),
            default: false,
            server_names: Vec::new(),
        };
        let current = Arc::new(ArcSwap::from_pointee(loader::load_certified_key(&pair).unwrap()));
        let server_chain = current.load_full().cert.clone();
        let original = tempfile::tempdir().unwrap();
        let replacement = tempfile::tempdir().unwrap();
        let original_trust = gen_ca_and_crl(original.path(), "Original Client CA");
        let replacement_trust = gen_ca_and_crl(replacement.path(), "Replacement Client CA");
        let crls = format!(
            "{}\n{}",
            std::fs::read_to_string(&original_trust.crl_path).unwrap(),
            std::fs::read_to_string(&replacement_trust.crl_path).unwrap()
        );
        std::fs::write(&original_trust.crl_path, crls).unwrap();
        let ca_path = original_trust.ca_path.to_str().unwrap().to_owned();
        let crl_path = original_trust.crl_path.to_str().unwrap().to_owned();
        let verifier = crate::reload::ReloadableClientVerifier::new(
            &ca_path,
            ClientCertMode::Require,
            std::slice::from_ref(&crl_path),
            &[],
        )
        .unwrap();
        let swap = verifier.arc();
        let reload = ClientVerifierReload {
            ca_path: ca_path.clone(),
            crl_paths: vec![crl_path.clone()],
            mode: ClientCertMode::Require,
            trusted_spiffe_ids: Vec::new(),
            swap_handle: Arc::clone(&swap),
        };
        let (notifications, events) = mpsc::channel(1);
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        let baseline = file_hashes_now(&pair, Some(&reload));
        let task = tokio::spawn(watch_events(
            Arc::clone(&current),
            pair,
            Some(reload),
            baseline,
            shutdown,
            events,
        ));
        // The first interval tick is immediate. Consume it so a later poll
        // counter increment can only come from the poll this test schedules.
        wait_for(|| polls_completed() > 0).await;
        let before = swap.load_full();
        let now = rustls::pki_types::UnixTime::now();
        assert!(
            before
                .verifier
                .verify_client_cert(&original_trust.leaf, &[], now)
                .is_ok(),
            "the original CA must initially be trusted"
        );
        assert!(
            before
                .verifier
                .verify_client_cert(&replacement_trust.leaf, &[], now)
                .is_err(),
            "the replacement CA must initially be untrusted"
        );
        std::fs::copy(&replacement_trust.ca_path, &ca_path).unwrap();
        advance_one_poll().await;
        let after_ca = swap.load_full();
        assert!(
            !Arc::ptr_eq(&before, &after_ca),
            "CA-only polling must install a new verifier"
        );
        assert!(
            after_ca
                .verifier
                .verify_client_cert(&replacement_trust.leaf, &[], now)
                .is_ok(),
            "CA-only polling must trust a client issued by the new CA"
        );
        std::fs::write(&crl_path, &replacement_trust.revoked_crl).unwrap();
        advance_one_poll().await;
        let after_crl = swap.load_full();
        assert!(
            !Arc::ptr_eq(&after_ca, &after_crl),
            "CRL-only polling must install a new verifier"
        );
        assert!(
            matches!(
                after_crl.verifier.verify_client_cert(&replacement_trust.leaf, &[], now),
                Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Revoked))
            ),
            "CRL-only polling must reject the newly revoked client"
        );
        let polls_before_notification = polls_completed();
        let notification_ca = crate::test_utils::gen_ca_file();
        std::fs::copy(&notification_ca.ca_path, &ca_path).unwrap();
        notifications.send(()).await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(DEBOUNCE_MS)).await;
        // Do not advance the poll interval here: the reload must come from the
        // notification, not from a poll racing it to the same file change.
        wait_for(|| !Arc::ptr_eq(&after_crl, &swap.load_full())).await;
        let after_notification = swap.load_full();
        assert!(
            !Arc::ptr_eq(&after_crl, &after_notification),
            "a notification reload must install a new verifier"
        );
        assert_eq!(
            polls_completed(),
            polls_before_notification,
            "the notification reload must not be a poll in disguise"
        );
        advance_one_poll().await;
        assert!(
            Arc::ptr_eq(&after_notification, &swap.load_full()),
            "a successful notification reload must not be repeated by the next poll"
        );
        stop.send(true).unwrap();
        task.await.unwrap();
        assert_eq!(
            server_chain,
            current.load().cert,
            "trust-file changes leave the server certificate unchanged"
        );
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "certificate and trust-file fixtures")]
    fn polling_detects_ca_and_crl_changes_with_an_unchanged_server_certificate() {
        use crate::test_utils::gen_ca_file;
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("CA path").to_owned();
        let verifier = crate::reload::ReloadableClientVerifier::new(&ca_path, ClientCertMode::Require, &[], &[])
            .expect("client verifier");
        let crl = tempfile::NamedTempFile::new().expect("CRL file");
        let reload = ClientVerifierReload {
            ca_path,
            crl_paths: vec![crl.path().to_str().expect("CRL path").to_owned()],
            mode: ClientCertMode::Require,
            trusted_spiffe_ids: Vec::new(),
            swap_handle: verifier.arc(),
        };
        let original = file_hashes_now(&pair, Some(&reload));
        let replacement = gen_ca_file();
        std::fs::copy(&replacement.ca_path, &reload.ca_path).expect("replace CA");
        let ca_changed = file_hashes_now(&pair, Some(&reload));
        assert_ne!(original, ca_changed, "CA-only changes must trigger polling reload");
        std::fs::write(crl.path(), b"changed CRL").expect("replace CRL");
        assert_ne!(
            ca_changed,
            file_hashes_now(&pair, Some(&reload)),
            "CRL-only changes must trigger polling reload"
        );
    }

    #[test]
    fn reload_client_verifier_returns_true_when_none() {
        assert!(
            reload_client_verifier(None),
            "no verifier reload config should return true"
        );
    }

    #[test]
    fn verifier_extra_dirs_empty_when_none() {
        let dirs = verifier_extra_dirs(None);
        assert!(dirs.is_empty(), "no verifier config should yield empty dirs");
    }

    #[test]
    fn verifier_extra_dirs_includes_ca_and_crl() {
        use crate::test_utils::{ensure_crypto_provider, gen_ca_file};

        ensure_crypto_provider();
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path").to_owned();
        let ca_dir = parent_dir(&ca_path);

        let verifier = crate::reload::ReloadableClientVerifier::new(&ca_path, ClientCertMode::Require, &[], &[])
            .expect("verifier creation");

        let reload = Some(ClientVerifierReload {
            ca_path: ca_path.clone(),
            crl_paths: vec!["/etc/ssl/crl.pem".to_owned()],
            mode: ClientCertMode::Require,
            trusted_spiffe_ids: Vec::new(),
            swap_handle: verifier.arc(),
        });

        let dirs = verifier_extra_dirs(reload.as_ref());
        assert_eq!(dirs.len(), 2, "should include CA dir and CRL dir");
        assert_eq!(dirs[0], ca_dir, "first dir should be CA parent");
        assert_eq!(dirs[1], PathBuf::from("/etc/ssl"), "second dir should be CRL parent");
    }
    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    /// Waits until `condition` holds, advancing the paused clock between polls.
    ///
    /// Blocking hash tasks complete in real time, while timers only fire when
    /// virtual time moves, so each iteration advances both.
    async fn wait_until(mut condition: impl FnMut() -> bool) {
        for _ in 0..100 {
            if condition() {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
            tokio::task::yield_now().await;
            tokio::time::advance(CERTIFICATE_POLL_INTERVAL).await;
        }
    }

    /// Waits until `condition` holds without moving the paused clock.
    ///
    /// Use this when a timer-driven branch (such as a poll) must not run while
    /// waiting for another branch, so a reload cannot be attributed to the
    /// wrong trigger.
    async fn wait_for(mut condition: impl FnMut() -> bool) {
        for _ in 0..1000 {
            if condition() {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
            tokio::task::yield_now().await;
        }
        assert!(condition(), "condition did not become true in time");
    }

    /// Advances exactly one poll interval and waits for that poll to finish.
    async fn advance_one_poll() {
        let before = polls_completed();
        tokio::time::advance(CERTIFICATE_POLL_INTERVAL).await;
        wait_for(|| polls_completed() > before).await;
    }

    /// Completed certificate polls on this thread.
    fn polls_completed() -> u64 {
        POLLS_COMPLETED.with(std::cell::Cell::get)
    }

    /// Client identity and trust files used to prove polling changes decisions.
    struct ClientTrustFixture {
        /// Trust anchor PEM installed by a CA-only update.
        ca_path: PathBuf,
        /// Initially empty CRL PEM for this CA.
        crl_path: PathBuf,
        /// Client leaf with serial one, signed by this CA.
        leaf: rustls::pki_types::CertificateDer<'static>,
        /// Replacement CRL revoking the fixture leaf.
        revoked_crl: String,
    }

    /// Generates a CA, client leaf, and empty/revoked CRLs for polling tests.
    fn gen_ca_and_crl(dir: &Path, common_name: &str) -> ClientTrustFixture {
        let ca_key = rcgen::KeyPair::generate().expect("CA key generation");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-sign");
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut leaf_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf_params.serial_number = Some(1_u64.into());
        leaf_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        leaf_params.subject_alt_names = vec![rcgen::SanType::URI("spiffe://example.org/client".try_into().unwrap())];
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let ca_path = dir.join("ca.pem");
        let crl_path = dir.join("crl.pem");
        std::fs::write(&ca_path, ca_cert.pem()).expect("write CA PEM");
        std::fs::write(&crl_path, client_crl(&issuer, false)).expect("write CRL PEM");
        ClientTrustFixture {
            ca_path,
            crl_path,
            leaf: leaf.der().clone(),
            revoked_crl: client_crl(&issuer, true),
        }
    }

    /// Signs an empty CRL or one that revokes the polling fixture client.
    fn client_crl(issuer: &rcgen::Issuer<'_, rcgen::KeyPair>, revoke: bool) -> String {
        let revoked_certs = if revoke {
            vec![rcgen::RevokedCertParams {
                serial_number: 1_u64.into(),
                revocation_time: rcgen::date_time_ymd(2026, 1, 1),
                reason_code: None,
                invalidity_date: None,
            }]
        } else {
            Vec::new()
        };
        rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2026, 1, 1),
            next_update: rcgen::date_time_ymd(2036, 1, 1),
            crl_number: u64::from(revoke).into(),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(issuer)
        .expect("CRL signing")
        .pem()
        .expect("CRL PEM encoding")
    }
}
