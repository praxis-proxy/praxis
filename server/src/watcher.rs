// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! File watcher for hot config reload.
//!
//! Monitors the config file for changes, debounces filesystem
//! events, and triggers [`reload_pipelines`] on each valid change.
//!
//! [`reload_pipelines`]: crate::reload::reload_pipelines

use std::{
    collections::hash_map::DefaultHasher,
    hash::Hasher as _,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher as _};
use praxis_core::config::Config;
use praxis_filter::FilterRegistry;
use praxis_protocol::ListenerPipelines;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::reload::reload_pipelines;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Debounce window for filesystem events.
const DEBOUNCE_MS: u64 = 500;

/// Initial backoff delay (in seconds) after a config reload failure.
const BACKOFF_BASE_SECS: u64 = 1;

/// Maximum backoff delay (in seconds) between reload attempts.
const BACKOFF_MAX_SECS: u64 = 60;

/// Test-only startup wait for the background notify watcher.
#[cfg(test)]
const WATCHER_STARTUP_MS: u64 = 750;

// -----------------------------------------------------------------------------
// WatcherParams
// -----------------------------------------------------------------------------

/// Bundled parameters for the config file watcher.
pub(crate) struct WatcherParams {
    /// Path to the config file to watch.
    pub(crate) config_path: PathBuf,

    /// Health check shutdown token, swapped on each reload.
    pub(crate) health_shutdown: Arc<Mutex<CancellationToken>>,

    /// Hash of the config file content at server startup, used to
    /// detect changes that occurred before the watcher was ready.
    pub(crate) initial_content_hash: u64,

    /// Initial config for diffing against reloaded versions.
    pub(crate) initial_config: Config,

    /// KV store registry, preserved across reloads.
    pub(crate) kv_stores: praxis_core::kv::KvStoreRegistry,

    /// Live pipeline storage, swapped atomically on reload.
    pub(crate) pipelines: Arc<ListenerPipelines>,

    /// Documents the configured filters read, beyond the main config.
    ///
    /// These are watched and hashed alongside it, so editing one triggers a
    /// reload. Collected once at startup and not updated afterward.
    ///
    /// The set only changes when the main config does, and that edit reloads on
    /// its own because the main config passes the hash gate. What the reload does
    /// not do is start watching the result: a document a filter points to only
    /// after a reload is neither in this vec nor in the watched directories, so
    /// later edits to it go unnoticed until the proxy restarts. Refreshing the
    /// set means re-registering watch directories mid-loop and updating the
    /// event filter, which belongs in its own change.
    pub(crate) referenced_files: Vec<PathBuf>,

    /// Listener metadata for admin `/api/pipelines`, swapped on reload.
    pub(crate) listener_meta: praxis_protocol::http::pingora::health::ListenerMetaStore,

    /// Filter registry for building new pipelines.
    pub(crate) registry: Arc<FilterRegistry>,

    /// Token for clean watcher shutdown.
    pub(crate) shutdown: CancellationToken,

    /// Shared sub-request client for iterative sub-requests.
    pub(crate) subrequest_client: praxis_core::subrequest::SubRequestClient,

    /// Runtime log-level state refreshed after successful reload.
    pub(crate) log_level: Option<Arc<praxis_core::logging::LogLevelState>>,
}

// -----------------------------------------------------------------------------
// Watcher
// -----------------------------------------------------------------------------

/// Spawn a background thread that watches the config file and
/// triggers pipeline reloads on changes.
///
/// The thread runs until the `shutdown` token is cancelled or
/// the process exits.
///
/// # Panics
///
/// Panics if the tokio runtime cannot be created.
#[expect(clippy::expect_used, reason = "fatal if tokio runtime cannot start")]
pub(crate) fn spawn_config_watcher(params: WatcherParams) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("config watcher tokio runtime");
        rt.block_on(watch_loop(params));
    })
}

/// Core watch loop: set up the notify watcher, debounce events,
/// and trigger reloads.
async fn watch_loop(params: WatcherParams) {
    let (tx, mut rx) = mpsc::channel::<()>(16);

    let watch_dirs = watch_dirs_for(&params.config_path, &params.referenced_files);

    let _watcher = match setup_watcher(tx, &watch_dirs, &params.config_path, &params.referenced_files) {
        Ok(w) => w,
        Err(e) => {
            error!(error = %e, "failed to start config file watcher");
            return;
        },
    };

    info!(
        path = %params.config_path.display(),
        referenced_documents = params.referenced_files.len(),
        watched_directories = watch_dirs.len(),
        "config file watcher started",
    );
    run_event_loop(&mut rx, &params).await;
}

/// How long remains before another reload attempt is allowed.
///
/// Returns `None` when no attempt is being held back, either because
/// nothing has failed yet or because the backoff window has elapsed.
fn backoff_remaining(consecutive_failures: u32, last_failure: Option<Instant>) -> Option<Duration> {
    let last = last_failure?;
    let remaining = backoff_duration(consecutive_failures).checked_sub(last.elapsed())?;
    if remaining.is_zero() { None } else { Some(remaining) }
}

/// Whether the backoff period has elapsed since the last failure.
fn should_skip_for_backoff(consecutive_failures: u32, last_failure: Option<Instant>) -> bool {
    let Some(remaining) = backoff_remaining(consecutive_failures, last_failure) else {
        return false;
    };
    warn!(
        consecutive_failures,
        backoff_secs = backoff_duration(consecutive_failures).as_secs(),
        remaining_secs = remaining.as_secs(),
        "config reload deferred, backing off after repeated failures",
    );
    true
}

/// Sleep for `delay`, or never resolve when there is nothing to wait for.
///
/// Lets the event loop keep one uniform `select!` arm whether or not a
/// deferred reload is pending.
async fn sleep_or_pending(delay: Option<Duration>) {
    match delay {
        Some(delay) => tokio::time::sleep(delay).await,
        None => std::future::pending().await,
    }
}

/// Process filesystem events until shutdown is requested.
#[expect(clippy::too_many_lines, reason = "startup pre-check and reload orchestration")]
async fn run_event_loop(rx: &mut mpsc::Receiver<()>, params: &WatcherParams) {
    let mut current_config = params.initial_config.clone();
    let mut content_hash = params.initial_content_hash;
    let mut consecutive_failures: u32 = 0;
    let mut last_failure: Option<Instant> = None;

    // Check for changes that may have occurred between config load and watcher startup
    handle_reload(
        &params.config_path,
        &params.referenced_files,
        &mut current_config,
        &mut content_hash,
        &params.registry,
        &params.pipelines,
        &params.listener_meta,
        &params.health_shutdown,
        &params.kv_stores,
        &params.subrequest_client,
        params.log_level.as_ref(),
    );

    // A change seen while backing off is remembered rather than dropped,
    // and retried when the window expires. The filesystem will not
    // re-notify us about an edit we already consumed.
    let mut reload_pending = false;

    loop {
        let retry_in = if reload_pending {
            backoff_remaining(consecutive_failures, last_failure)
        } else {
            None
        };

        tokio::select! {
            Some(()) = rx.recv() => {
                tracing::debug!(debounce_ms = DEBOUNCE_MS, "config file change detected, debouncing");
                drain_and_debounce(rx).await;
                reload_pending = true;
            }
            () = sleep_or_pending(retry_in) => {
                tracing::debug!("backoff elapsed, retrying deferred config reload");
            }
            () = params.shutdown.cancelled() => {
                info!("config file watcher shutting down");
                return;
            }
        }

        if !reload_pending || should_skip_for_backoff(consecutive_failures, last_failure) {
            continue;
        }

        let ok = handle_reload(
            &params.config_path,
            &params.referenced_files,
            &mut current_config,
            &mut content_hash,
            &params.registry,
            &params.pipelines,
            &params.listener_meta,
            &params.health_shutdown,
            &params.kv_stores,
            &params.subrequest_client,
            params.log_level.as_ref(),
        );
        update_reload_backoff(ok, &mut consecutive_failures, &mut last_failure);
        // Cleared on success; a failed attempt stays pending so the timer
        // arm retries it once the (now longer) backoff window elapses.
        reload_pending = !ok;
    }
}

/// Reset or advance consecutive-failure backoff state after a reload attempt.
fn update_reload_backoff(ok: bool, consecutive_failures: &mut u32, last_failure: &mut Option<Instant>) {
    if ok {
        *consecutive_failures = 0;
        *last_failure = None;
    } else {
        *consecutive_failures = consecutive_failures.saturating_add(1);
        *last_failure = Some(Instant::now());
    }
}

/// Read the config file and reload pipelines if content has changed.
///
/// Returns `true` when the reload succeeds or when content is unchanged
/// (no-op). Returns `false` on any error (read, parse, pipeline build).
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "orchestration function"
)]
fn handle_reload(
    config_path: &PathBuf,
    referenced_files: &[PathBuf],
    current_config: &mut Config,
    content_hash: &mut u64,
    registry: &FilterRegistry,
    pipelines: &ListenerPipelines,
    listener_meta: &praxis_protocol::http::pingora::health::ListenerMetaStore,
    health_shutdown: &Arc<Mutex<CancellationToken>>,
    kv_stores: &praxis_core::kv::KvStoreRegistry,
    subrequest_client: &praxis_core::subrequest::SubRequestClient,
    log_level: Option<&Arc<praxis_core::logging::LogLevelState>>,
) -> bool {
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!(
                path = %config_path.display(),
                error = %e,
                "failed to read config file for reload"
            );
            praxis_protocol::http::pingora::metrics::record_config_reload_failure();
            return false;
        },
    };

    let new_hash = composite_hash(&content, referenced_files);
    if new_hash == *content_hash {
        tracing::debug!("config file content unchanged, skipping reload");
        return true;
    }

    // The hash is recorded only once the reload succeeds. Recording it up front
    // would strand the operator's edit: a reload that fails for a transient
    // reason, such as an identity provider being briefly unreachable while a
    // policy document is validated, would leave the new content hashed as
    // already-seen, so the unchanged-content check would skip every subsequent
    // attempt and the edit would never take effect. Leaving the old hash in
    // place lets the existing consecutive-failure backoff retry the same
    // content until it succeeds.

    let new_config = match Config::from_yaml(&content) {
        Ok(c) => c,
        Err(e) => {
            error!(
                path = %config_path.display(),
                error = %e,
                "config reload failed: invalid config"
            );
            praxis_protocol::http::pingora::metrics::record_config_reload_failure();
            return false;
        },
    };

    match reload_pipelines(
        &new_config,
        current_config,
        registry,
        pipelines,
        listener_meta,
        health_shutdown,
        kv_stores,
        subrequest_client,
        log_level,
    ) {
        Ok(()) => {
            *current_config = new_config;
            *content_hash = new_hash;
            praxis_protocol::http::pingora::metrics::record_config_reload_success();
            true
        },
        Err(e) => {
            error!(error = %e, "config reload failed");
            praxis_protocol::http::pingora::metrics::record_config_reload_failure();
            false
        },
    }
}

// -----------------------------------------------------------------------------
// PathFilter
// -----------------------------------------------------------------------------

/// Path-based event filter for the config file watcher.
///
/// When the config file is itself a symlink (Kubernetes `ConfigMap`
/// mounts, release-symlink deployments), all directory events are
/// accepted because symlink-target rotations produce events for
/// intermediate paths (e.g. `..data`) that cannot be predicted at
/// startup. The content-hash check in [`handle_reload`] prevents
/// unnecessary pipeline rebuilds.
///
/// When the config is a regular file, events are filtered against
/// both the original and canonical paths for cross-platform
/// compatibility (macOS `FSEvents` reports canonical paths; Linux
/// `inotify` reports lexical paths).
struct PathFilter {
    /// Absolute lexical config path (unresolved `..` components
    /// preserved) for matching `inotify`-reported paths on Linux.
    absolute: PathBuf,
    /// Accept all events without path filtering (symlinked configs).
    accept_all: bool,
    /// Canonical config path for matching on platforms that report
    /// resolved paths.
    canonical: PathBuf,
    /// Original config path as supplied by the caller.
    original: PathBuf,
    /// Documents referenced by the config, in every spelling a platform might
    /// report: as given, made absolute, and canonicalized.
    referenced: Vec<PathBuf>,
}

impl PathFilter {
    /// Build a filter for the given config path.
    fn new(config_path: &std::path::Path, referenced: &[PathBuf]) -> Self {
        let is_symlink = config_path.symlink_metadata().is_ok_and(|m| m.is_symlink());

        let canonical = std::fs::canonicalize(config_path).unwrap_or_else(|_| config_path.to_path_buf());

        let absolute = if config_path.is_absolute() {
            config_path.to_path_buf()
        } else {
            std::env::current_dir().map_or_else(|_| config_path.to_path_buf(), |cwd| cwd.join(config_path))
        };

        // Each referenced document is matched in every spelling a platform might
        // report, the same way the main config is: macOS reports canonical paths,
        // Linux reports lexical ones.
        let mut expanded = Vec::with_capacity(referenced.len() * 3);
        for path in referenced {
            expanded.push(path.clone());
            if let Ok(c) = std::fs::canonicalize(path) {
                expanded.push(c);
            }
            // An absolute path is already covered by the push above; only a
            // relative one needs its cwd-joined spelling.
            if !path.is_absolute()
                && let Ok(cwd) = std::env::current_dir()
            {
                expanded.push(cwd.join(path));
            }
        }
        expanded.sort();
        expanded.dedup();

        Self {
            absolute,
            accept_all: is_symlink,
            canonical,
            original: config_path.to_path_buf(),
            referenced: expanded,
        }
    }

    /// Whether a filesystem event should trigger a reload attempt.
    fn matches(&self, event: &notify::Event) -> bool {
        self.accept_all
            || event.paths.iter().any(|p| {
                p == &self.canonical
                    || p == &self.absolute
                    || p == &self.original
                    || self.referenced.iter().any(|r| r == p)
            })
    }
}

/// Set up a [`RecommendedWatcher`] that sends to the given channel
/// on relevant filesystem events targeting the config file.
///
/// Events for unrelated files in the same directory are ignored
/// (unless the config path is a symlink — see [`PathFilter`]).
///
/// [`RecommendedWatcher`]: notify::RecommendedWatcher
fn setup_watcher(
    tx: mpsc::Sender<()>,
    watch_dirs: &[PathBuf],
    config_path: &std::path::Path,
    referenced: &[PathBuf],
) -> Result<RecommendedWatcher, notify::Error> {
    let filter = PathFilter::new(config_path, referenced);
    let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| match res {
        Ok(event) if is_relevant_event(event.kind) && filter.matches(&event) => {
            if tx.try_send(()).is_err() {
                tracing::trace!("config watcher channel full, event coalesced by debounce");
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "config file watcher error");
        },
        _ => {},
    })?;

    // A referenced document commonly lives outside the main config's directory,
    // so one watch is not enough. Each directory is registered separately and
    // non-recursively, keeping the existing blast radius per directory.
    for dir in watch_dirs {
        watcher.watch(dir, RecursiveMode::NonRecursive)?;
    }
    Ok(watcher)
}

/// Drain pending events and sleep for the debounce window.
async fn drain_and_debounce(rx: &mut mpsc::Receiver<()>) {
    tokio::time::sleep(Duration::from_millis(DEBOUNCE_MS)).await;
    while rx.try_recv().is_ok() {}
}

/// Whether a notify event kind is relevant for config reload.
fn is_relevant_event(kind: EventKind) -> bool {
    matches!(kind, EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_))
}

/// Resolve the directory to watch for a given config path.
///
/// Falls back to `.` when the path has no non-empty parent, covering
/// bare filenames like `praxis.yaml` where [`std::path::Path::parent`] returns
/// `Some("")` rather than `None`.
fn watch_dir_for_path(path: &std::path::Path) -> PathBuf {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf()
}

/// Directories to watch: the main config's, plus one per referenced document.
///
/// A referenced document commonly lives outside the main config's directory, so
/// one watch is not enough. Sorted and de-duplicated, since documents alongside
/// the config need no second watch.
fn watch_dirs_for(config_path: &std::path::Path, referenced: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs = vec![watch_dir_for_path(config_path)];
    for path in referenced {
        dirs.push(watch_dir_for_path(path));
    }
    dirs.sort();
    dirs.dedup();
    dirs
}

/// Compute the backoff duration for a given consecutive failure count.
///
/// Starts at [`BACKOFF_BASE_SECS`] and doubles with each subsequent
/// failure, capped at [`BACKOFF_MAX_SECS`].
///
/// ```
/// # use std::time::Duration;
/// // First failure → 1s, second → 2s, third → 4s, ...
/// ```
fn backoff_duration(consecutive_failures: u32) -> Duration {
    let exp = consecutive_failures.saturating_sub(1).min(63);
    let secs = BACKOFF_BASE_SECS
        .saturating_mul(1_u64.checked_shl(exp).unwrap_or(u64::MAX))
        .min(BACKOFF_MAX_SECS);
    Duration::from_secs(secs)
}

/// Compute a hash of file content for change detection.
/// Hash of the main config plus every document it references.
///
/// Referenced documents have to be included, not just the main config. A filter
/// that loads an external document would otherwise never pick up edits to it: the
/// main config stays byte-identical, the unchanged-content check suppresses the
/// rebuild, and the filter keeps serving what it loaded at startup. The only trace
/// is a debug line saying the config was unchanged, which is true and misleading.
/// See praxis-proxy/praxis#900.
///
/// Paths are hashed in the order given, which the caller keeps stable, and the
/// path itself is folded in alongside the content so that swapping two documents'
/// contents still changes the hash. An unreadable document hashes as a distinct
/// marker rather than as empty, so a document disappearing is a change.
pub(crate) fn composite_hash(main: &str, referenced: &[PathBuf]) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write(main.as_bytes());
    for path in referenced {
        hasher.write(path.as_os_str().as_encoded_bytes());
        match std::fs::read(path) {
            Ok(bytes) => hasher.write(&bytes),
            Err(_) => hasher.write(b"<unreadable>"),
        }
    }
    hasher.finish()
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
    clippy::too_many_lines,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;

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
    fn is_relevant_event_access_not_relevant() {
        assert!(
            !is_relevant_event(EventKind::Access(notify::event::AccessKind::Read)),
            "Access events should not be relevant"
        );
    }

    #[test]
    fn is_relevant_event_remove() {
        assert!(
            is_relevant_event(EventKind::Remove(notify::event::RemoveKind::File)),
            "remove events should be relevant"
        );
    }

    // -------------------------------------------------------------------------
    // PathFilter unit tests
    // -------------------------------------------------------------------------

    #[test]
    fn path_filter_matches_original_path() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yaml");
        std::fs::write(&config, "test").unwrap();

        let filter = PathFilter::new(&config, &[]);
        let event = make_event(vec![config.clone()]);
        assert!(filter.matches(&event), "should match original path");
    }

    #[test]
    fn path_filter_matches_canonical_path() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yaml");
        std::fs::write(&config, "test").unwrap();

        let filter = PathFilter::new(&config, &[]);
        let canonical = std::fs::canonicalize(&config).unwrap();
        let event = make_event(vec![canonical]);
        assert!(filter.matches(&event), "should match canonical path (macOS FSEvents)");
    }

    #[test]
    fn path_filter_rejects_unrelated_path() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yaml");
        std::fs::write(&config, "test").unwrap();

        let filter = PathFilter::new(&config, &[]);
        let event = make_event(vec![dir.path().join("other.txt")]);
        assert!(!filter.matches(&event), "should reject unrelated path");
    }

    #[test]
    fn path_filter_accepts_all_for_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real-config.yaml");
        std::fs::write(&target, "test").unwrap();
        let link = dir.path().join("config.yaml");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let filter = PathFilter::new(&link, &[]);
        assert!(filter.accept_all, "symlinked config should set accept_all");

        let event = make_event(vec![dir.path().join("..data")]);
        assert!(
            filter.matches(&event),
            "symlinked config should accept events for unrelated paths"
        );
    }

    #[test]
    fn path_filter_matches_absolute_lexical_path() {
        let _lock = CWD_MUTEX.get_or_init(Mutex::default).lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let _cwd = CwdGuard::new(dir.path());

        let subdir_rel = PathBuf::from("conf");
        std::fs::create_dir(&subdir_rel).unwrap();
        let config_rel = subdir_rel.join("config.yaml");
        std::fs::write(&config_rel, "test").unwrap();

        let filter = PathFilter::new(&config_rel, &[]);

        tracing::info!("simulating inotify-reported cwd-joined absolute path");
        let cwd = std::env::current_dir().unwrap();
        let abs_lexical = cwd.join(&config_rel);
        let event = make_event(vec![abs_lexical]);
        assert!(
            filter.matches(&event),
            "should match absolute lexical path from inotify on Linux"
        );
    }

    #[test]
    fn path_filter_matches_parent_relative_path() {
        let _lock = CWD_MUTEX.get_or_init(Mutex::default).lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let subdir = dir.path().join("sub");
        std::fs::create_dir(&subdir).unwrap();
        let _cwd = CwdGuard::new(&subdir);

        let config_abs = dir.path().join("config.yaml");
        std::fs::write(&config_abs, "test").unwrap();

        let relative = PathBuf::from("..").join("config.yaml");
        let filter = PathFilter::new(&relative, &[]);

        tracing::info!("verifying canonical match: absolute field stores cwd + ../config.yaml with .. preserved");
        let canonical = std::fs::canonicalize(&config_abs).unwrap();
        let event = make_event(vec![canonical]);
        assert!(
            filter.matches(&event),
            "should match canonical path for parent-relative config"
        );

        tracing::info!("verifying cwd-joined form matches");
        let cwd = std::env::current_dir().unwrap();
        let abs_with_dotdot = cwd.join(&relative);
        let dotdot_event = make_event(vec![abs_with_dotdot]);
        assert!(
            filter.matches(&dotdot_event),
            "should match cwd-joined path retaining .. components"
        );
    }

    #[test]
    fn path_filter_regular_file_not_accept_all() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yaml");
        std::fs::write(&config, "test").unwrap();

        let filter = PathFilter::new(&config, &[]);
        assert!(!filter.accept_all, "regular file should not set accept_all");
    }

    // -------------------------------------------------------------------------
    // Integration tests
    // -------------------------------------------------------------------------

    /// The gate must notice a referenced document changing while the main config
    /// stays byte-identical. This is the core of praxis-proxy/praxis#900: hashing
    /// the main config alone left a filter serving whatever document it loaded at
    /// startup, with no signal that the file on disk had moved on.
    #[test]
    fn referenced_document_change_is_detected_with_main_config_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let doc = dir.path().join("policy.yaml");
        std::fs::write(&doc, "plugins: []\n").unwrap();

        let refs = vec![doc.clone()];
        let before = composite_hash(VALID_YAML, &refs);

        // Only the referenced document changes.
        std::fs::write(&doc, "plugins: [{name: added}]\n").unwrap();
        let after = composite_hash(VALID_YAML, &refs);

        assert_ne!(
            before, after,
            "editing a referenced document must change the gate's hash, or the reload is suppressed",
        );
    }

    /// A document that disappears is a change, not a no-op. Hashing a missing file
    /// as empty would make deletion invisible.
    #[test]
    fn referenced_document_removal_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let doc = dir.path().join("policy.yaml");
        std::fs::write(&doc, "plugins: []\n").unwrap();
        let refs = vec![doc.clone()];
        let present = composite_hash(VALID_YAML, &refs);

        std::fs::remove_file(&doc).unwrap();
        assert_ne!(
            present,
            composite_hash(VALID_YAML, &refs),
            "a removed document is a change"
        );
    }

    /// Two documents swapping contents must still register as a change, which is
    /// why the path is folded into the hash alongside the content.
    #[test]
    fn swapping_two_referenced_documents_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.yaml");
        let b = dir.path().join("b.yaml");
        std::fs::write(&a, "one\n").unwrap();
        std::fs::write(&b, "two\n").unwrap();
        let refs = vec![a.clone(), b.clone()];
        let before = composite_hash(VALID_YAML, &refs);

        std::fs::write(&a, "two\n").unwrap();
        std::fs::write(&b, "one\n").unwrap();
        assert_ne!(
            before,
            composite_hash(VALID_YAML, &refs),
            "swapped contents are a change"
        );
    }

    /// A filesystem event for a referenced document must pass the path filter, even
    /// though that document is not the main config.
    #[test]
    fn path_filter_matches_a_referenced_document() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("praxis.yaml");
        let doc = dir.path().join("policy.yaml");
        std::fs::write(&config, VALID_YAML).unwrap();
        std::fs::write(&doc, "plugins: []\n").unwrap();

        let filter = PathFilter::new(&config, std::slice::from_ref(&doc));
        let event = notify::Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(notify::event::DataChange::Content)),
            paths: vec![doc],
            attrs: notify::event::EventAttributes::default(),
        };
        assert!(filter.matches(&event), "a referenced document's event must be accepted");
    }

    /// A referenced document configured as a relative path must match the
    /// cwd-joined spelling inotify reports on Linux.
    #[test]
    fn path_filter_matches_a_relative_referenced_document_by_absolute_spelling() {
        let _lock = CWD_MUTEX.get_or_init(Mutex::default).lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let _cwd = CwdGuard::new(dir.path());

        let config = PathBuf::from("praxis.yaml");
        let doc_rel = PathBuf::from("policy.yaml");
        std::fs::write(&config, VALID_YAML).unwrap();
        std::fs::write(&doc_rel, "plugins: []\n").unwrap();

        let filter = PathFilter::new(&config, std::slice::from_ref(&doc_rel));

        let abs_lexical = std::env::current_dir().unwrap().join(&doc_rel);
        assert!(
            filter.matches(&make_event(vec![abs_lexical])),
            "a relative referenced document must match its cwd-joined spelling"
        );
    }

    /// Adding referenced documents must not widen the filter: a sibling file
    /// nothing references is still rejected.
    #[test]
    fn path_filter_rejects_a_document_that_is_not_referenced() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("praxis.yaml");
        let doc = dir.path().join("policy.yaml");
        std::fs::write(&config, VALID_YAML).unwrap();
        std::fs::write(&doc, "plugins: []\n").unwrap();

        let filter = PathFilter::new(&config, std::slice::from_ref(&doc));
        let event = make_event(vec![dir.path().join("unrelated.yaml")]);
        assert!(
            !filter.matches(&event),
            "a file nobody references must not trigger a reload"
        );
    }

    /// A document outside the main config's directory needs its own watch.
    #[test]
    fn watch_dirs_include_a_referenced_documents_own_directory() {
        let dirs = watch_dirs_for(
            std::path::Path::new("/etc/praxis/praxis.yaml"),
            &[PathBuf::from("/var/lib/praxis/policy.yaml")],
        );
        assert_eq!(
            dirs,
            vec![PathBuf::from("/etc/praxis"), PathBuf::from("/var/lib/praxis")],
            "both directories must be watched"
        );
    }

    /// Documents alongside the main config need no second watch.
    #[test]
    fn watch_dirs_collapse_documents_in_the_config_directory() {
        let dirs = watch_dirs_for(
            std::path::Path::new("/etc/praxis/praxis.yaml"),
            &[
                PathBuf::from("/etc/praxis/policy.yaml"),
                PathBuf::from("/etc/praxis/other.yaml"),
            ],
        );
        assert_eq!(dirs, vec![PathBuf::from("/etc/praxis")], "one directory, watched once");
    }

    /// A reload that fails must not advance the content hash.
    ///
    /// Advancing it would strand the operator's edit: the unchanged-content check
    /// would then skip every retry, so a transient failure would become permanent
    /// and the edit would never take effect no matter how long the provider took
    /// to recover.
    #[test]
    fn failed_reload_leaves_hash_unchanged_so_the_edit_is_retried() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("praxis.yaml");
        std::fs::write(&config_path, VALID_YAML).unwrap();

        let mut config = Config::from_yaml(VALID_YAML).unwrap();
        let registry = FilterRegistry::with_builtins();
        let health_registry = Arc::new(std::collections::HashMap::new());
        let kv_stores = praxis_core::kv::KvStoreRegistry::new();
        let subrequest_client =
            praxis_core::subrequest::SubRequestClient::new(praxis_core::subrequest::SubRequestConnector::new(8, None));
        let pipelines =
            crate::pipelines::resolve_pipelines(&config, &registry, &health_registry, &kv_stores, &subrequest_client)
                .unwrap();
        let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let listener_meta = praxis_protocol::http::pingora::health::new_listener_meta_store(
            praxis_protocol::http::pingora::health::listener_meta_from_config(&config),
        );

        let original_hash = composite_hash(VALID_YAML, &[]);
        let mut hash = original_hash;

        // An edit that cannot be parsed stands in for any failing reload.
        std::fs::write(&config_path, "this: is: not: valid: praxis: config\n").unwrap();
        let ok = handle_reload(
            &config_path,
            &[],
            &mut config,
            &mut hash,
            &registry,
            &pipelines,
            &listener_meta,
            &health_shutdown,
            &kv_stores,
            &subrequest_client,
            None,
        );

        assert!(!ok, "an unparseable config must report failure");
        assert_eq!(
            hash, original_hash,
            "a failed reload must leave the hash untouched, or the retry is skipped forever",
        );

        // Recovery: the same path now holds something valid, and because the hash
        // was never advanced the attempt is not short-circuited.
        std::fs::write(&config_path, VALID_YAML).unwrap();
        let recovered = handle_reload(
            &config_path,
            &[],
            &mut config,
            &mut hash,
            &registry,
            &pipelines,
            &listener_meta,
            &health_shutdown,
            &kv_stores,
            &subrequest_client,
            None,
        );
        assert!(recovered, "a subsequent valid config must reload");
    }

    #[test]
    fn watcher_exits_on_cancellation() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("praxis.yaml");
        std::fs::write(&config_path, VALID_YAML).unwrap();

        let config = Config::from_yaml(VALID_YAML).unwrap();
        let registry = Arc::new(FilterRegistry::with_builtins());
        let health_registry = Arc::new(std::collections::HashMap::new());
        let kv_stores = praxis_core::kv::KvStoreRegistry::new();
        let subrequest_client =
            praxis_core::subrequest::SubRequestClient::new(praxis_core::subrequest::SubRequestConnector::new(8, None));
        let pipelines = Arc::new(
            crate::pipelines::resolve_pipelines(&config, &registry, &health_registry, &kv_stores, &subrequest_client)
                .unwrap(),
        );
        let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let shutdown = CancellationToken::new();

        let handle = spawn_config_watcher(WatcherParams {
            config_path,
            health_shutdown,
            initial_content_hash: composite_hash(VALID_YAML, &[]),
            initial_config: config.clone(),
            kv_stores: praxis_core::kv::KvStoreRegistry::new(),
            pipelines,
            referenced_files: Vec::new(),
            listener_meta: praxis_protocol::http::pingora::health::new_listener_meta_store(
                praxis_protocol::http::pingora::health::listener_meta_from_config(&config),
            ),
            registry,
            shutdown: shutdown.clone(),
            subrequest_client: praxis_core::subrequest::SubRequestClient::new(
                praxis_core::subrequest::SubRequestConnector::new(8, None),
            ),
            log_level: None,
        });

        std::thread::sleep(Duration::from_millis(100));
        shutdown.cancel();
        let result = handle.join();
        assert!(result.is_ok(), "watcher thread should exit cleanly on cancel");
    }

    #[test]
    fn watcher_reloads_on_file_change() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("praxis.yaml");
        std::fs::write(&config_path, VALID_YAML).unwrap();

        let config = Config::from_yaml(VALID_YAML).unwrap();
        let registry = Arc::new(FilterRegistry::with_builtins());
        let health_registry = Arc::new(std::collections::HashMap::new());
        let kv_stores = praxis_core::kv::KvStoreRegistry::new();
        let subrequest_client =
            praxis_core::subrequest::SubRequestClient::new(praxis_core::subrequest::SubRequestConnector::new(8, None));
        let pipelines = Arc::new(
            crate::pipelines::resolve_pipelines(&config, &registry, &health_registry, &kv_stores, &subrequest_client)
                .unwrap(),
        );
        let old_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let shutdown = CancellationToken::new();

        let _handle = spawn_config_watcher(WatcherParams {
            config_path: config_path.clone(),
            health_shutdown,
            initial_content_hash: composite_hash(VALID_YAML, &[]),
            initial_config: config.clone(),
            kv_stores: praxis_core::kv::KvStoreRegistry::new(),
            referenced_files: Vec::new(),
            pipelines: Arc::clone(&pipelines),
            listener_meta: praxis_protocol::http::pingora::health::new_listener_meta_store(
                praxis_protocol::http::pingora::health::listener_meta_from_config(&config),
            ),
            registry: Arc::clone(&registry),
            shutdown: shutdown.clone(),
            subrequest_client: praxis_core::subrequest::SubRequestClient::new(
                praxis_core::subrequest::SubRequestConnector::new(8, None),
            ),
            log_level: None,
        });

        std::thread::sleep(Duration::from_millis(WATCHER_STARTUP_MS));

        std::fs::write(&config_path, VALID_YAML_CHANGED).unwrap();

        poll_until(Duration::from_secs(5), || {
            Arc::as_ptr(&pipelines.get("web").unwrap().load()) != old_ptr
        });

        let new_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        assert_ne!(old_ptr, new_ptr, "pipeline should be swapped after config file change");

        shutdown.cancel();
    }

    #[test]
    fn watcher_survives_invalid_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("praxis.yaml");
        std::fs::write(&config_path, VALID_YAML).unwrap();

        let config = Config::from_yaml(VALID_YAML).unwrap();
        let registry = Arc::new(FilterRegistry::with_builtins());
        let health_registry = Arc::new(std::collections::HashMap::new());
        let kv_stores = praxis_core::kv::KvStoreRegistry::new();
        let subrequest_client =
            praxis_core::subrequest::SubRequestClient::new(praxis_core::subrequest::SubRequestConnector::new(8, None));
        let pipelines = Arc::new(
            crate::pipelines::resolve_pipelines(&config, &registry, &health_registry, &kv_stores, &subrequest_client)
                .unwrap(),
        );
        let old_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let shutdown = CancellationToken::new();

        let _handle = spawn_config_watcher(WatcherParams {
            config_path: config_path.clone(),
            health_shutdown,
            initial_content_hash: composite_hash(VALID_YAML, &[]),
            initial_config: config.clone(),
            kv_stores: praxis_core::kv::KvStoreRegistry::new(),
            referenced_files: Vec::new(),
            pipelines: Arc::clone(&pipelines),
            listener_meta: praxis_protocol::http::pingora::health::new_listener_meta_store(
                praxis_protocol::http::pingora::health::listener_meta_from_config(&config),
            ),
            registry: Arc::clone(&registry),
            shutdown: shutdown.clone(),
            subrequest_client: praxis_core::subrequest::SubRequestClient::new(
                praxis_core::subrequest::SubRequestConnector::new(8, None),
            ),
            log_level: None,
        });

        std::thread::sleep(Duration::from_millis(WATCHER_STARTUP_MS));

        std::fs::write(&config_path, "invalid: [[[yaml").unwrap();

        std::thread::sleep(Duration::from_millis(DEBOUNCE_MS + 200));

        let current_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        assert_eq!(
            old_ptr, current_ptr,
            "pipeline should be untouched after invalid config"
        );

        std::thread::sleep(Duration::from_secs(BACKOFF_BASE_SECS));
        std::fs::write(&config_path, VALID_YAML_CHANGED).unwrap();

        poll_until(Duration::from_secs(5), || {
            Arc::as_ptr(&pipelines.get("web").unwrap().load()) != old_ptr
        });

        let new_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        assert_ne!(old_ptr, new_ptr, "pipeline should recover after valid config");

        shutdown.cancel();
    }

    #[test]
    fn watch_dir_for_path_bare_filename() {
        assert_eq!(
            watch_dir_for_path(std::path::Path::new("praxis.yaml")),
            PathBuf::from("."),
            "bare filename should resolve to current directory"
        );
    }

    #[test]
    fn watch_dir_for_path_with_directory() {
        assert_eq!(
            watch_dir_for_path(std::path::Path::new("/etc/praxis/praxis.yaml")),
            PathBuf::from("/etc/praxis"),
            "absolute path should use its parent directory"
        );
    }

    #[test]
    fn watcher_starts_with_bare_filename() {
        let _lock = CWD_MUTEX.get_or_init(Mutex::default).lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let _cwd = CwdGuard::new(dir.path());

        std::fs::write("praxis.yaml", VALID_YAML).unwrap();

        let config = Config::from_yaml(VALID_YAML).unwrap();
        let registry = Arc::new(FilterRegistry::with_builtins());
        let health_registry = Arc::new(std::collections::HashMap::new());
        let kv_stores = praxis_core::kv::KvStoreRegistry::new();
        let subrequest_client =
            praxis_core::subrequest::SubRequestClient::new(praxis_core::subrequest::SubRequestConnector::new(8, None));
        let pipelines = Arc::new(
            crate::pipelines::resolve_pipelines(&config, &registry, &health_registry, &kv_stores, &subrequest_client)
                .unwrap(),
        );
        let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let shutdown = CancellationToken::new();

        let handle = spawn_config_watcher(WatcherParams {
            config_path: PathBuf::from("praxis.yaml"),
            health_shutdown,
            initial_content_hash: composite_hash(VALID_YAML, &[]),
            initial_config: config.clone(),
            kv_stores,
            pipelines,
            referenced_files: Vec::new(),
            listener_meta: praxis_protocol::http::pingora::health::new_listener_meta_store(
                praxis_protocol::http::pingora::health::listener_meta_from_config(&config),
            ),
            registry,
            shutdown: shutdown.clone(),
            subrequest_client: praxis_core::subrequest::SubRequestClient::new(
                praxis_core::subrequest::SubRequestConnector::new(8, None),
            ),
            log_level: None,
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
            assert!(
                !handle.is_finished(),
                "watcher exited early: bare filename caused empty-path notify error"
            );
        }
        shutdown.cancel();
        handle.join().unwrap();
    }

    #[test]
    fn hash_content_deterministic() {
        let a = composite_hash("hello world", &[]);
        let b = composite_hash("hello world", &[]);
        assert_eq!(a, b, "same content should produce the same hash");
    }

    #[test]
    fn hash_content_differs_for_different_input() {
        let a = composite_hash("status: 200", &[]);
        let b = composite_hash("status: 201", &[]);
        assert_ne!(a, b, "different content should produce different hashes");
    }

    #[test]
    fn watcher_skips_reload_on_unchanged_content() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("praxis.yaml");
        std::fs::write(&config_path, VALID_YAML).unwrap();

        let config = Config::from_yaml(VALID_YAML).unwrap();
        let registry = Arc::new(FilterRegistry::with_builtins());
        let health_registry = Arc::new(std::collections::HashMap::new());
        let kv_stores = praxis_core::kv::KvStoreRegistry::new();
        let subrequest_client =
            praxis_core::subrequest::SubRequestClient::new(praxis_core::subrequest::SubRequestConnector::new(8, None));
        let pipelines = Arc::new(
            crate::pipelines::resolve_pipelines(&config, &registry, &health_registry, &kv_stores, &subrequest_client)
                .unwrap(),
        );
        let old_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let shutdown = CancellationToken::new();

        let _handle = spawn_config_watcher(WatcherParams {
            config_path: config_path.clone(),
            health_shutdown,
            initial_content_hash: composite_hash(VALID_YAML, &[]),
            initial_config: config.clone(),
            kv_stores: praxis_core::kv::KvStoreRegistry::new(),
            referenced_files: Vec::new(),
            pipelines: Arc::clone(&pipelines),
            listener_meta: praxis_protocol::http::pingora::health::new_listener_meta_store(
                praxis_protocol::http::pingora::health::listener_meta_from_config(&config),
            ),
            registry: Arc::clone(&registry),
            shutdown: shutdown.clone(),
            subrequest_client: praxis_core::subrequest::SubRequestClient::new(
                praxis_core::subrequest::SubRequestConnector::new(8, None),
            ),
            log_level: None,
        });

        std::thread::sleep(Duration::from_millis(WATCHER_STARTUP_MS));

        std::fs::write(&config_path, VALID_YAML).unwrap();

        std::thread::sleep(Duration::from_millis(DEBOUNCE_MS * 3));

        let current_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        assert_eq!(
            old_ptr, current_ptr,
            "pipeline should not be swapped when content is unchanged"
        );

        std::fs::write(&config_path, VALID_YAML_CHANGED).unwrap();

        poll_until(Duration::from_secs(5), || {
            Arc::as_ptr(&pipelines.get("web").unwrap().load()) != old_ptr
        });

        let new_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        assert_ne!(
            old_ptr, new_ptr,
            "pipeline should be swapped after actual content change"
        );

        shutdown.cancel();
    }

    #[test]
    fn watcher_ignores_unrelated_file_changes() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("praxis.yaml");
        std::fs::write(&config_path, VALID_YAML).unwrap();

        let config = Config::from_yaml(VALID_YAML).unwrap();
        let registry = Arc::new(FilterRegistry::with_builtins());
        let health_registry = Arc::new(std::collections::HashMap::new());
        let kv_stores = praxis_core::kv::KvStoreRegistry::new();
        let subrequest_client =
            praxis_core::subrequest::SubRequestClient::new(praxis_core::subrequest::SubRequestConnector::new(8, None));
        let pipelines = Arc::new(
            crate::pipelines::resolve_pipelines(&config, &registry, &health_registry, &kv_stores, &subrequest_client)
                .unwrap(),
        );
        let old_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let shutdown = CancellationToken::new();

        tracing::info!("seeding watcher with stale hash so any reload attempt rebuilds the pipeline");
        let _handle = spawn_config_watcher(WatcherParams {
            config_path: config_path.clone(),
            health_shutdown,
            initial_content_hash: 0,
            initial_config: config.clone(),
            kv_stores: praxis_core::kv::KvStoreRegistry::new(),
            referenced_files: Vec::new(),
            pipelines: Arc::clone(&pipelines),
            listener_meta: praxis_protocol::http::pingora::health::new_listener_meta_store(
                praxis_protocol::http::pingora::health::listener_meta_from_config(&config),
            ),
            registry: Arc::clone(&registry),
            shutdown: shutdown.clone(),
            subrequest_client: praxis_core::subrequest::SubRequestClient::new(
                praxis_core::subrequest::SubRequestConnector::new(8, None),
            ),
            log_level: None,
        });

        tracing::info!("waiting for startup pre-check reload (mismatched hash triggers swap)");
        poll_until(Duration::from_secs(5), || {
            Arc::as_ptr(&pipelines.get("web").unwrap().load()) != old_ptr
        });
        let after_startup = Arc::as_ptr(&pipelines.get("web").unwrap().load());

        tracing::info!("writing only unrelated files, no config touches");
        for i in 0..5 {
            let unrelated = dir.path().join(format!("unrelated-{i}.tmp"));
            std::fs::write(&unrelated, format!("noise {i}")).unwrap();
        }

        std::thread::sleep(Duration::from_millis(DEBOUNCE_MS * 3));

        let current_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        assert_eq!(
            after_startup, current_ptr,
            "pipeline should not be swapped when only unrelated files change"
        );

        shutdown.cancel();
    }

    #[test]
    fn watcher_reloads_symlinked_config() {
        let dir = tempfile::tempdir().unwrap();

        let target_v1 = dir.path().join("config-v1.yaml");
        std::fs::write(&target_v1, VALID_YAML).unwrap();

        let link = dir.path().join("praxis.yaml");
        std::os::unix::fs::symlink(&target_v1, &link).unwrap();

        let config = Config::from_yaml(VALID_YAML).unwrap();
        let registry = Arc::new(FilterRegistry::with_builtins());
        let health_registry = Arc::new(std::collections::HashMap::new());
        let kv_stores = praxis_core::kv::KvStoreRegistry::new();
        let subrequest_client =
            praxis_core::subrequest::SubRequestClient::new(praxis_core::subrequest::SubRequestConnector::new(8, None));
        let pipelines = Arc::new(
            crate::pipelines::resolve_pipelines(&config, &registry, &health_registry, &kv_stores, &subrequest_client)
                .unwrap(),
        );
        let old_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let shutdown = CancellationToken::new();

        let _handle = spawn_config_watcher(WatcherParams {
            config_path: link.clone(),
            health_shutdown,
            initial_content_hash: composite_hash(VALID_YAML, &[]),
            initial_config: config.clone(),
            kv_stores: praxis_core::kv::KvStoreRegistry::new(),
            referenced_files: Vec::new(),
            pipelines: Arc::clone(&pipelines),
            listener_meta: praxis_protocol::http::pingora::health::new_listener_meta_store(
                praxis_protocol::http::pingora::health::listener_meta_from_config(&config),
            ),
            registry: Arc::clone(&registry),
            shutdown: shutdown.clone(),
            subrequest_client: praxis_core::subrequest::SubRequestClient::new(
                praxis_core::subrequest::SubRequestConnector::new(8, None),
            ),
            log_level: None,
        });

        std::thread::sleep(Duration::from_millis(WATCHER_STARTUP_MS));

        tracing::info!("rotating symlink target (simulates K8s ConfigMap rotation)");
        let target_v2 = dir.path().join("config-v2.yaml");
        std::fs::write(&target_v2, VALID_YAML_CHANGED).unwrap();
        let tmp_link = dir.path().join("praxis.yaml.tmp");
        std::os::unix::fs::symlink(&target_v2, &tmp_link).unwrap();
        std::fs::rename(&tmp_link, &link).unwrap();

        poll_until(Duration::from_secs(5), || {
            Arc::as_ptr(&pipelines.get("web").unwrap().load()) != old_ptr
        });

        let new_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        assert_ne!(
            old_ptr, new_ptr,
            "pipeline should be swapped after symlink target rotation"
        );

        shutdown.cancel();
    }

    #[test]
    fn backoff_duration_starts_at_base() {
        assert_eq!(
            backoff_duration(1),
            Duration::from_secs(BACKOFF_BASE_SECS),
            "first failure should use base backoff"
        );
    }

    #[test]
    fn backoff_duration_doubles_each_failure() {
        assert_eq!(
            backoff_duration(2),
            Duration::from_secs(2),
            "second failure should double"
        );
        assert_eq!(
            backoff_duration(3),
            Duration::from_secs(4),
            "third failure should be 4s"
        );
        assert_eq!(
            backoff_duration(4),
            Duration::from_secs(8),
            "fourth failure should be 8s"
        );
    }

    #[test]
    fn backoff_duration_caps_at_max() {
        assert_eq!(
            backoff_duration(7),
            Duration::from_secs(BACKOFF_MAX_SECS),
            "large failure counts should cap at max"
        );
        assert_eq!(
            backoff_duration(100),
            Duration::from_secs(BACKOFF_MAX_SECS),
            "very large failure counts should cap at max"
        );
    }

    #[test]
    fn backoff_duration_zero_failures() {
        assert_eq!(
            backoff_duration(0),
            Duration::from_secs(BACKOFF_BASE_SECS),
            "zero failures should still use base backoff"
        );
    }

    #[test]
    fn backoff_remaining_is_none_without_a_failure() {
        assert!(
            backoff_remaining(0, None).is_none(),
            "nothing is being held back before the first failure"
        );
    }

    #[test]
    fn backoff_remaining_is_none_once_the_window_elapses() {
        let long_ago = Instant::now() - Duration::from_secs(BACKOFF_MAX_SECS * 2);
        assert!(
            backoff_remaining(10, Some(long_ago)).is_none(),
            "an elapsed window should not hold back a retry"
        );
    }

    #[test]
    fn backoff_remaining_reports_time_left_inside_the_window() {
        let remaining =
            backoff_remaining(1, Some(Instant::now())).expect("a fresh failure should hold back the next attempt");
        assert!(
            remaining <= Duration::from_secs(BACKOFF_BASE_SECS),
            "remaining must not exceed the window, got {remaining:?}"
        );
    }

    /// A fix that lands while the watcher is backing off must still be
    /// applied, even though it produces no further filesystem events.
    #[test]
    fn deferred_reload_is_retried_after_backoff_without_a_new_event() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("praxis.yaml");
        std::fs::write(&config_path, VALID_YAML).unwrap();

        let config = Config::from_yaml(VALID_YAML).unwrap();
        let registry = Arc::new(FilterRegistry::with_builtins());
        let health_registry = Arc::new(std::collections::HashMap::new());
        let kv_stores = praxis_core::kv::KvStoreRegistry::new();
        let subrequest_client =
            praxis_core::subrequest::SubRequestClient::new(praxis_core::subrequest::SubRequestConnector::new(8, None));
        let pipelines = Arc::new(
            crate::pipelines::resolve_pipelines(&config, &registry, &health_registry, &kv_stores, &subrequest_client)
                .unwrap(),
        );
        let old_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        let shutdown = CancellationToken::new();

        let _handle = spawn_config_watcher(WatcherParams {
            config_path: config_path.clone(),
            health_shutdown: Arc::new(Mutex::new(CancellationToken::new())),
            initial_content_hash: composite_hash(VALID_YAML, &[]),
            initial_config: config.clone(),
            kv_stores: praxis_core::kv::KvStoreRegistry::new(),
            pipelines: Arc::clone(&pipelines),
            referenced_files: Vec::new(),
            listener_meta: praxis_protocol::http::pingora::health::new_listener_meta_store(
                praxis_protocol::http::pingora::health::listener_meta_from_config(&config),
            ),
            registry: Arc::clone(&registry),
            shutdown: shutdown.clone(),
            subrequest_client: praxis_core::subrequest::SubRequestClient::new(
                praxis_core::subrequest::SubRequestConnector::new(8, None),
            ),
            log_level: None,
        });

        std::thread::sleep(Duration::from_millis(WATCHER_STARTUP_MS));

        // Fail once to arm the backoff window.
        std::fs::write(&config_path, "invalid: [[[yaml").unwrap();
        std::thread::sleep(Duration::from_millis(DEBOUNCE_MS + 200));

        // Write the fix inside the backoff window. The watcher consumes
        // this event while still backing off, so the retry has to come
        // from the timer rather than from another notification.
        std::fs::write(&config_path, VALID_YAML_CHANGED).unwrap();
        std::thread::sleep(Duration::from_millis(DEBOUNCE_MS + 200));

        std::thread::sleep(Duration::from_secs(BACKOFF_BASE_SECS + 1));

        let current_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        assert_ne!(
            old_ptr, current_ptr,
            "the corrected config should be applied once the backoff elapses, with no further file events"
        );

        shutdown.cancel();
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a `notify::Event` with the given paths (for `PathFilter` unit tests).
    fn make_event(paths: Vec<PathBuf>) -> notify::Event {
        let mut event = notify::Event::new(EventKind::Modify(notify::event::ModifyKind::Data(
            notify::event::DataChange::Content,
        )));
        event.paths = paths;
        event
    }

    /// Poll `predicate` every 20ms until it returns `true` or `timeout` elapses.
    fn poll_until(timeout: Duration, predicate: impl Fn() -> bool) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if predicate() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Serializes tests that mutate the process working directory.
    static CWD_MUTEX: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();

    /// RAII guard that restores the process working directory on drop.
    struct CwdGuard(PathBuf);

    impl CwdGuard {
        /// Change to `path` and capture the original directory for restore.
        fn new(path: &std::path::Path) -> Self {
            let original = std::env::current_dir().unwrap();
            std::env::set_current_dir(path).unwrap();
            Self(original)
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.0).expect("failed to restore working directory");
        }
    }

    /// Valid YAML config for watcher tests.
    const VALID_YAML: &str = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;

    /// Modified valid YAML (different status) for watcher tests.
    const VALID_YAML_CHANGED: &str = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 201
"#;
}
