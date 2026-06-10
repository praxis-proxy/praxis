// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! File watcher for hot config reload.
//!
//! Monitors the config file for changes, debounces filesystem
//! events, and triggers [`reload_pipelines`] on each valid change.
//!
//! [`reload_pipelines`]: crate::reload::reload_pipelines

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use praxis_core::config::Config;
use praxis_filter::FilterRegistry;
use praxis_protocol::ListenerPipelines;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::reload::reload_pipelines;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Debounce window for filesystem events.
const DEBOUNCE_MS: u64 = 500;

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
#[allow(clippy::expect_used, reason = "fatal if tokio runtime cannot start")]
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

/// Process filesystem events until shutdown is requested.
async fn run_event_loop(rx: &mut mpsc::Receiver<()>, params: &WatcherParams) {
    let mut current_config = params.initial_config.clone();
    loop {
        tokio::select! {
            Some(()) = rx.recv() => {
                tracing::debug!(debounce_ms = DEBOUNCE_MS, "config file change detected, debouncing");
                drain_and_debounce(rx).await;
                handle_reload(
                    &params.config_path,
                    &mut current_config,
                    &params.registry,
                    &params.pipelines,
                    &params.health_shutdown,
                    &params.kv_stores,
                );
            }
            () = params.shutdown.cancelled() => {
                info!("config file watcher shutting down");
                return;
            }
        }
    }
}

/// Read the config file, parse it, and attempt a reload.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "orchestration function"
)]
fn handle_reload(
    config_path: &PathBuf,
    current_config: &mut Config,
    registry: &FilterRegistry,
    pipelines: &ListenerPipelines,
    health_shutdown: &Arc<Mutex<CancellationToken>>,
    kv_stores: &praxis_core::kv::KvStoreRegistry,
) {
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!(
                path = %config_path.display(),
                error = %e,
                "failed to read config file for reload"
            );
            return;
        },
    };

    let new_config = match Config::from_yaml(&content) {
        Ok(c) => c,
        Err(e) => {
            error!(
                path = %config_path.display(),
                error = %e,
                "config reload failed: invalid config"
            );
            return;
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
        },
        Err(e) => {
            error!(error = %e, "config reload failed");
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
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

        std::thread::sleep(Duration::from_millis(200));

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

        std::thread::sleep(Duration::from_millis(200));

        std::fs::write(&config_path, "invalid: [[[yaml").unwrap();

        std::thread::sleep(Duration::from_millis(DEBOUNCE_MS + 200));

        let current_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        assert_eq!(
            old_ptr, current_ptr,
            "pipeline should be untouched after invalid config"
        );

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

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
            assert!(
                !handle.is_finished(),
                "watcher exited early: bare filename caused empty-path notify error"
            );
        }
        shutdown.cancel();
        handle.join().unwrap();
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Poll `predicate` every 20ms until it returns `true` or `timeout` elapses.
    fn poll_until(timeout: Duration, predicate: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
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
