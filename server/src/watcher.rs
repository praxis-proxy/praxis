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

    /// Initial config for diffing against reloaded versions.
    pub(crate) initial_config: Config,

    /// KV store registry, preserved across reloads.
    pub(crate) kv_stores: praxis_core::kv::KvStoreRegistry,

    /// Live pipeline storage, swapped atomically on reload.
    pub(crate) pipelines: Arc<ListenerPipelines>,

    /// Filter registry for building new pipelines.
    pub(crate) registry: Arc<FilterRegistry>,

    /// Token for clean watcher shutdown.
    pub(crate) shutdown: CancellationToken,
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

    let watch_dir = watch_dir_for_path(&params.config_path);

    let _watcher = match setup_watcher(tx, &watch_dir) {
        Ok(w) => w,
        Err(e) => {
            error!(error = %e, "failed to start config file watcher");
            return;
        },
    };

    info!(path = %params.config_path.display(), "config file watcher started");
    run_event_loop(&mut rx, &params).await;
}

/// Whether the backoff period has elapsed since the last failure.
fn should_skip_for_backoff(consecutive_failures: u32, last_failure: Option<Instant>) -> bool {
    let Some(last) = last_failure else { return false };
    let backoff = backoff_duration(consecutive_failures);
    let elapsed = last.elapsed();
    if elapsed < backoff {
        let remaining = backoff - elapsed;
        warn!(
            consecutive_failures,
            backoff_secs = backoff.as_secs(),
            remaining_secs = remaining.as_secs(),
            "config reload skipped, backing off after repeated failures",
        );
        return true;
    }
    false
}

/// Process filesystem events until shutdown is requested.
async fn run_event_loop(rx: &mut mpsc::Receiver<()>, params: &WatcherParams) {
    let mut current_config = params.initial_config.clone();
    let mut content_hash = std::fs::read_to_string(&params.config_path).map_or(0, |c| hash_content(&c));
    let mut consecutive_failures: u32 = 0;
    let mut last_failure: Option<Instant> = None;

    loop {
        tokio::select! {
            Some(()) = rx.recv() => {
                tracing::debug!(debounce_ms = DEBOUNCE_MS, "config file change detected, debouncing");
                drain_and_debounce(rx).await;

                if should_skip_for_backoff(consecutive_failures, last_failure) {
                    continue;
                }

                let ok = handle_reload(
                    &params.config_path, &mut current_config, &mut content_hash,
                    &params.registry, &params.pipelines, &params.health_shutdown, &params.kv_stores,
                );
                if ok { consecutive_failures = 0; last_failure = None; }
                else {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    last_failure = Some(Instant::now());
                }
            }
            () = params.shutdown.cancelled() => {
                info!("config file watcher shutting down");
                return;
            }
        }
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
    current_config: &mut Config,
    content_hash: &mut u64,
    registry: &FilterRegistry,
    pipelines: &ListenerPipelines,
    health_shutdown: &Arc<Mutex<CancellationToken>>,
    kv_stores: &praxis_core::kv::KvStoreRegistry,
) -> bool {
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!(
                path = %config_path.display(),
                error = %e,
                "failed to read config file for reload"
            );
            return false;
        },
    };

    let new_hash = hash_content(&content);
    if new_hash == *content_hash {
        tracing::debug!("config file content unchanged, skipping reload");
        return true;
    }
    *content_hash = new_hash;

    let new_config = match Config::from_yaml(&content) {
        Ok(c) => c,
        Err(e) => {
            error!(
                path = %config_path.display(),
                error = %e,
                "config reload failed: invalid config"
            );
            return false;
        },
    };

    match reload_pipelines(
        &new_config,
        current_config,
        registry,
        pipelines,
        health_shutdown,
        kv_stores,
    ) {
        Ok(()) => {
            *current_config = new_config;
            true
        },
        Err(e) => {
            error!(error = %e, "config reload failed");
            false
        },
    }
}

/// Set up a [`RecommendedWatcher`] that sends to the given channel
/// on relevant filesystem events.
///
/// [`RecommendedWatcher`]: notify::RecommendedWatcher
fn setup_watcher(tx: mpsc::Sender<()>, watch_dir: &std::path::Path) -> Result<RecommendedWatcher, notify::Error> {
    let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| match res {
        Ok(event) if is_relevant_event(event.kind) && tx.try_send(()).is_err() => {
            tracing::trace!("config watcher channel full, event coalesced by debounce");
        },
        Err(e) => {
            tracing::warn!(error = %e, "config file watcher error");
        },
        _ => {},
    })?;

    watcher.watch(watch_dir, RecursiveMode::NonRecursive)?;
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
fn hash_content(content: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write(content.as_bytes());
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

    #[test]
    fn watcher_exits_on_cancellation() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("praxis.yaml");
        std::fs::write(&config_path, VALID_YAML).unwrap();

        let config = Config::from_yaml(VALID_YAML).unwrap();
        let registry = Arc::new(FilterRegistry::with_builtins());
        let health_registry = Arc::new(std::collections::HashMap::new());
        let kv_stores = praxis_core::kv::KvStoreRegistry::new();
        let pipelines =
            Arc::new(crate::pipelines::resolve_pipelines(&config, &registry, &health_registry, &kv_stores).unwrap());
        let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let shutdown = CancellationToken::new();

        let handle = spawn_config_watcher(WatcherParams {
            config_path,
            health_shutdown,
            initial_config: config,
            kv_stores: praxis_core::kv::KvStoreRegistry::new(),
            pipelines,
            registry,
            shutdown: shutdown.clone(),
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
        let pipelines =
            Arc::new(crate::pipelines::resolve_pipelines(&config, &registry, &health_registry, &kv_stores).unwrap());
        let old_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let shutdown = CancellationToken::new();

        let _handle = spawn_config_watcher(WatcherParams {
            config_path: config_path.clone(),
            health_shutdown,
            initial_config: config,
            kv_stores: praxis_core::kv::KvStoreRegistry::new(),
            pipelines: Arc::clone(&pipelines),
            registry: Arc::clone(&registry),
            shutdown: shutdown.clone(),
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
        let pipelines =
            Arc::new(crate::pipelines::resolve_pipelines(&config, &registry, &health_registry, &kv_stores).unwrap());
        let old_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let shutdown = CancellationToken::new();

        let _handle = spawn_config_watcher(WatcherParams {
            config_path: config_path.clone(),
            health_shutdown,
            initial_config: config,
            kv_stores: praxis_core::kv::KvStoreRegistry::new(),
            pipelines: Arc::clone(&pipelines),
            registry: Arc::clone(&registry),
            shutdown: shutdown.clone(),
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
        let pipelines =
            Arc::new(crate::pipelines::resolve_pipelines(&config, &registry, &health_registry, &kv_stores).unwrap());
        let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let shutdown = CancellationToken::new();

        let handle = spawn_config_watcher(WatcherParams {
            config_path: PathBuf::from("praxis.yaml"),
            health_shutdown,
            initial_config: config,
            kv_stores,
            pipelines,
            registry,
            shutdown: shutdown.clone(),
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
        let a = hash_content("hello world");
        let b = hash_content("hello world");
        assert_eq!(a, b, "same content should produce the same hash");
    }

    #[test]
    fn hash_content_differs_for_different_input() {
        let a = hash_content("status: 200");
        let b = hash_content("status: 201");
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
        let pipelines =
            Arc::new(crate::pipelines::resolve_pipelines(&config, &registry, &health_registry, &kv_stores).unwrap());
        let old_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let shutdown = CancellationToken::new();

        let _handle = spawn_config_watcher(WatcherParams {
            config_path: config_path.clone(),
            health_shutdown,
            initial_config: config,
            kv_stores: praxis_core::kv::KvStoreRegistry::new(),
            pipelines: Arc::clone(&pipelines),
            registry: Arc::clone(&registry),
            shutdown: shutdown.clone(),
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

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

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
