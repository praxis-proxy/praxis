// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Runtime log-level overlay state and `EnvFilter` hot reload (#798).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::task::AbortHandle;
use tracing_subscriber::{EnvFilter, reload};

use super::{build_baseline_directive, is_valid_admin_log_level, is_valid_module_path};
use crate::{config::Config, errors::ProxyError};

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Admin log-level API errors mapped to HTTP status codes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogLevelError {
    /// Client error (400).
    BadRequest(String),
    /// Server error (500).
    Internal(String),
}

impl std::fmt::Display for LogLevelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRequest(message) | Self::Internal(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for LogLevelError {}

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Map key for the global (default) overlay.
pub const GLOBAL_OVERLAY_KEY: &str = "";

/// Default temporary overlay duration when `duration_secs` is omitted (5 minutes).
pub const DEFAULT_OVERLAY_DURATION_SECS: u64 = 300;

/// Maximum allowed overlay duration (24 hours).
pub const MAX_OVERLAY_DURATION_SECS: u64 = 86_400;

// -----------------------------------------------------------------------------
// Request / response DTOs
// -----------------------------------------------------------------------------

/// `PUT /api/log-level` request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutLogLevelRequest {
    /// Tracing level (`error`..`trace` or `off`).
    pub level: String,
    /// Optional module target; omit for a global overlay.
    pub module: Option<String>,
    /// Overlay lifetime in seconds; defaults to [`DEFAULT_OVERLAY_DURATION_SECS`].
    pub duration_secs: Option<u64>,
}

/// One active runtime overlay returned by `GET /api/log-level`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LogLevelOverlayView {
    /// Module target; absent for global overlays.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Effective tracing level for this overlay.
    pub level: String,
    /// UTC expiry time (RFC 3339).
    pub expires_at: String,
}

/// `GET /api/log-level` response body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LogLevelStateResponse {
    /// Startup baseline rebuilt from `RUST_LOG` + `runtime.log_overrides`.
    pub baseline_directive: String,
    /// Active admin overlays.
    pub overlays: Vec<LogLevelOverlayView>,
    /// Informational rebuild of baseline + overlays.
    pub effective_directive: String,
}

// -----------------------------------------------------------------------------
// Internal overlay state
// -----------------------------------------------------------------------------

/// One active runtime overlay and its revert timer handle.
struct OverlayEntry {
    /// Effective tracing level for this overlay.
    level: String,
    /// UTC expiry time for informational `GET` responses.
    expires_at: DateTime<Utc>,
    /// Handle used to cancel a superseded or deleted revert task.
    revert_abort: AbortHandle,
    /// Monotonic id distinguishing this overlay from any later one at the
    /// same target, so a stale revert task cannot evict a newer replacement.
    generation: u64,
}

/// Mutable log-level state guarded by [`LogLevelState::inner`].
struct LogLevelInner {
    /// Startup baseline rebuilt from `RUST_LOG` + `runtime.log_overrides`.
    baseline_directive: String,
    /// Active admin overlays keyed by target (`""` for global).
    overlays: HashMap<String, OverlayEntry>,
    /// Hot-swap handle for the live `EnvFilter`.
    reload_handle: reload::Handle<EnvFilter, tracing_subscriber::Registry>,
    /// Monotonic source of [`OverlayEntry::generation`] values.
    next_generation: u64,
}

impl LogLevelInner {
    /// Return the next overlay generation, advancing the counter.
    fn take_generation(&mut self) -> u64 {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        generation
    }
}

// -----------------------------------------------------------------------------
// LogLevelState
// -----------------------------------------------------------------------------

/// Shared runtime log-level overlay state and reload handle.
pub struct LogLevelState {
    /// Serialize filter changes through completion of tracing's cache rebuild.
    updates: Mutex<()>,
    /// Serializes overlay mutation, baseline refresh, and filter reload.
    inner: Mutex<LogLevelInner>,
}

impl LogLevelState {
    /// Create state from the startup baseline and reload handle.
    #[must_use]
    pub fn new(
        baseline_directive: String,
        reload_handle: reload::Handle<EnvFilter, tracing_subscriber::Registry>,
    ) -> Arc<Self> {
        Arc::new(Self {
            updates: Mutex::new(()),
            inner: Mutex::new(LogLevelInner {
                baseline_directive,
                overlays: HashMap::new(),
                reload_handle,
                next_generation: 0,
            }),
        })
    }

    /// Apply a validated admin `PUT` and schedule auto-revert.
    ///
    /// The overlay is committed only when the rebuilt `EnvFilter` reloads
    /// successfully; on failure the previous overlay (if any) is restored,
    /// so `GET` never reports an overlay the live filter does not apply.
    ///
    /// # Errors
    ///
    /// Returns [`LogLevelError::BadRequest`] for invalid inputs or
    /// [`LogLevelError::Internal`] when filter reload fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "reload and snapshot must share one lock guard"
    )]
    pub fn apply_put(self: &Arc<Self>, request: &PutLogLevelRequest) -> Result<LogLevelStateResponse, LogLevelError> {
        let duration_secs = request.duration_secs.unwrap_or(DEFAULT_OVERLAY_DURATION_SECS);
        validate_put_request(request.module.as_deref(), &request.level, duration_secs)?;

        let target = overlay_target_key(request.module.as_deref());
        let _update = self.updates.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut guard = self.inner.lock().expect("log level state lock poisoned");
        let (expires_at, deadline) = overlay_deadlines(duration_secs);
        let previous = guard.overlays.remove(&target);

        let generation = guard.take_generation();
        let abort_handle = spawn_revert_task(Arc::clone(self), target.clone(), deadline, generation);

        guard.overlays.insert(
            target.clone(),
            OverlayEntry {
                level: normalize_level(&request.level),
                expires_at,
                revert_abort: abort_handle,
                generation,
            },
        );

        if let Err(error) = reload_locked(&guard) {
            // Roll back: drop the new overlay (and its timer), restore the old one
            // with its original revert timer still running.
            remove_overlay_locked(&mut guard, &target);
            if let Some(previous) = previous {
                guard.overlays.insert(target, previous);
            }
            return Err(error);
        }
        if let Some(previous) = previous {
            previous.revert_abort.abort();
        }
        Ok(snapshot_locked(&guard))
    }

    /// Return the current structured state for `GET` / `HEAD`.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    pub fn snapshot(self: &Arc<Self>) -> LogLevelStateResponse {
        let guard = self.inner.lock().expect("log level state lock poisoned");
        snapshot_locked(&guard)
    }

    /// Remove overlay(s) per `DELETE` query parameters.
    ///
    /// # Errors
    ///
    /// Returns [`LogLevelError::BadRequest`] for invalid query combinations or
    /// [`LogLevelError::Internal`] when filter reload fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    pub fn delete_overlays(
        self: &Arc<Self>,
        module: Option<&str>,
        all: bool,
    ) -> Result<LogLevelStateResponse, LogLevelError> {
        if all && module.is_some() {
            return Err(LogLevelError::BadRequest(
                "cannot combine ?all=true with ?module=; use one or the other".to_owned(),
            ));
        }

        let _update = self.updates.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut guard = self.inner.lock().expect("log level state lock poisoned");

        if all {
            let keys: Vec<String> = guard.overlays.keys().cloned().collect();
            for key in keys {
                remove_overlay_locked(&mut guard, &key);
            }
        } else {
            let target = overlay_target_key(module);
            if guard.overlays.contains_key(&target) {
                remove_overlay_locked(&mut guard, &target);
            }
        }

        reload_locked(&guard)?;
        Ok(snapshot_locked(&guard))
    }

    /// Refresh the stored baseline from a successfully reloaded config.
    ///
    /// Active overlays and revert timers are preserved.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Config`] when overrides are invalid or filter
    /// reload fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn refresh_baseline(self: &Arc<Self>, config: &Config) -> Result<(), ProxyError> {
        self.refresh_baseline_with(config, || Ok(()))
    }

    /// Prepare a baseline, then publish it only if `publish` succeeds.
    ///
    /// The callback must contain only the short state commit. Tracing invokes
    /// subscriber callbacks after it returns, outside the caller's publication
    /// gate. A revoked commit leaves both the filter and baseline unchanged.
    ///
    /// # Errors
    /// Returns a converted configuration/reload error, or the publication error.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "guard is moved into modify and dropped before subscriber callbacks"
    )]
    pub fn refresh_baseline_with<T, E, Publish>(self: &Arc<Self>, config: &Config, publish: Publish) -> Result<T, E>
    where
        E: From<ProxyError>,
        Publish: FnOnce() -> Result<T, E>,
    {
        let baseline = build_baseline_directive(config).map_err(E::from)?;
        let _update = self.updates.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut guard = self.inner.lock().expect("log level state lock poisoned");
        let directive = build_effective_directive(&baseline, &guard.overlays);
        let filter = env_filter_from_directive(&directive).map_err(E::from)?;
        let handle = guard.reload_handle.clone();
        let mut result = None;
        handle
            .modify(|active| {
                result = Some(publish().inspect(|_published| {
                    *active = filter;
                    guard.baseline_directive = baseline;
                }));
                // Interest-cache rebuilding happens after this closure returns.
                drop(guard);
            })
            .map_err(|error| E::from(ProxyError::Config(error.to_string())))?;
        result.expect("tracing modify synchronously executes its closure")
    }

    /// Remove one overlay after its revert timer fires (internal).
    ///
    /// Reverts only when the overlay currently at `target` is the exact one
    /// this task was scheduled for (`generation`). A later `PUT` to the same
    /// target installs a new generation, so a stale timer (whose abort may
    /// have lost the race against its own wakeup) becomes a no-op instead of
    /// evicting the newer overlay.
    fn revert_target(self: &Arc<Self>, target: &str, generation: u64) {
        let _update = self.updates.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        if guard
            .overlays
            .get(target)
            .is_some_and(|entry| entry.generation == generation)
        {
            remove_overlay_locked(&mut guard, target);
            if let Err(error) = reload_locked(&guard) {
                tracing::error!(%error, %target, "failed to reload env filter after overlay revert");
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Directive rebuild
// -----------------------------------------------------------------------------

/// Rebuild the informational effective directive from baseline + overlays.
fn build_effective_directive(baseline: &str, overlays: &HashMap<String, OverlayEntry>) -> String {
    let mut directives = baseline.to_owned();
    let mut keys: Vec<&String> = overlays.keys().collect();
    keys.sort();
    for key in keys {
        let Some(entry) = overlays.get(key) else {
            continue;
        };
        directives.push(',');
        if key.is_empty() {
            directives.push_str(&entry.level);
        } else {
            directives.push_str(key);
            directives.push('=');
            directives.push_str(&entry.level);
        }
    }
    directives
}

/// Parse an effective directive string into an [`EnvFilter`].
///
/// # Errors
///
/// Returns [`ProxyError::Config`] when the directive is invalid.
pub(crate) fn env_filter_from_directive(directive: &str) -> Result<EnvFilter, ProxyError> {
    EnvFilter::try_new(directive).map_err(|error| ProxyError::Config(format!("invalid log filter directive: {error}")))
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Validate a `PUT` body before applying overlays.
pub(crate) fn validate_put_request(module: Option<&str>, level: &str, duration_secs: u64) -> Result<(), LogLevelError> {
    if let Some(module) = module {
        if module.is_empty() {
            return Err(LogLevelError::BadRequest(
                "module must not be empty; omit the field for a global overlay".to_owned(),
            ));
        }
        if !is_valid_module_path(module) {
            return Err(LogLevelError::BadRequest(format!(
                "invalid module path '{module}' (must be alphanumeric, '_', or '::')"
            )));
        }
    }

    if !is_valid_admin_log_level(level) {
        return Err(LogLevelError::BadRequest(format!(
            "invalid level '{level}' (must be error, warn, info, debug, trace, or off)"
        )));
    }

    if duration_secs == 0 {
        return Err(LogLevelError::BadRequest("duration_secs must be at least 1".to_owned()));
    }
    if duration_secs > MAX_OVERLAY_DURATION_SECS {
        return Err(LogLevelError::BadRequest(format!(
            "duration_secs must be at most {MAX_OVERLAY_DURATION_SECS}"
        )));
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Map an optional module target to the overlay map key.
fn overlay_target_key(module: Option<&str>) -> String {
    module.unwrap_or(GLOBAL_OVERLAY_KEY).to_owned()
}

/// Normalize admin level names to lowercase for stable directives.
fn normalize_level(level: &str) -> String {
    level.to_ascii_lowercase()
}

/// Build a `GET` response snapshot from a held lock guard.
fn snapshot_locked(guard: &LogLevelInner) -> LogLevelStateResponse {
    let mut overlays: Vec<LogLevelOverlayView> = guard
        .overlays
        .iter()
        .map(|(target, entry)| LogLevelOverlayView {
            module: if target.is_empty() { None } else { Some(target.clone()) },
            level: entry.level.clone(),
            expires_at: entry.expires_at.to_rfc3339(),
        })
        .collect();
    overlays.sort_by(|left, right| left.module.cmp(&right.module));

    let effective_directive = build_effective_directive(&guard.baseline_directive, &guard.overlays);
    LogLevelStateResponse {
        baseline_directive: guard.baseline_directive.clone(),
        overlays,
        effective_directive,
    }
}

/// Rebuild and hot-swap the live `EnvFilter` from the held state.
fn reload_locked(guard: &LogLevelInner) -> Result<(), LogLevelError> {
    let directive = build_effective_directive(&guard.baseline_directive, &guard.overlays);
    let filter = env_filter_from_directive(&directive).map_err(|error| LogLevelError::Internal(error.to_string()))?;
    guard
        .reload_handle
        .reload(filter)
        .map_err(|error| LogLevelError::Internal(format!("failed to reload env filter: {error}")))
}

/// Remove one overlay entry and cancel its revert timer.
fn remove_overlay_locked(guard: &mut LogLevelInner, target: &str) {
    if let Some(existing) = guard.overlays.remove(target) {
        existing.revert_abort.abort();
    }
}

/// Derive the advertised expiry and timer deadline when the overlay is installed.
fn overlay_deadlines(duration_secs: u64) -> (DateTime<Utc>, tokio::time::Instant) {
    let ttl = chrono::Duration::seconds(i64::try_from(duration_secs).unwrap_or(i64::MAX));
    let expires_at = Utc::now().checked_add_signed(ttl).unwrap_or(DateTime::<Utc>::MAX_UTC);
    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_secs(duration_secs))
        .unwrap_or_else(tokio::time::Instant::now);
    (expires_at, deadline)
}

/// Revert at the installation deadline, even if the task's first poll is delayed.
fn spawn_revert_task(
    state: Arc<LogLevelState>,
    target: String,
    deadline: tokio::time::Instant,
    generation: u64,
) -> AbortHandle {
    let handle = tokio::spawn(async move {
        tokio::time::sleep_until(deadline).await;
        state.revert_target(&target, generation);
    });
    handle.abort_handle()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::indexing_slicing,
    clippy::min_ident_chars,
    clippy::shadow_unrelated,
    reason = "tests"
)]
mod tests {
    use std::sync::OnceLock;

    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    /// Small valid config whose baseline is distinguishable from the old filter.
    fn publication_config() -> Config {
        let mut config = Config::from_yaml("listeners:\n  - name: web\n    address: '127.0.0.1:0'\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters: []\n").unwrap();
        config
            .runtime
            .log_overrides
            .insert("praxis_test".to_owned(), "debug".to_owned());
        config
    }

    #[test]
    fn revoked_baseline_commit_keeps_filter_and_state_unchanged() {
        let (layer, handle) = reload::Layer::new(EnvFilter::new("warn"));
        let _subscriber = tracing_subscriber::registry().with(layer);
        let state = LogLevelState::new("warn".to_owned(), handle.clone());
        let result: Result<(), ProxyError> = state.refresh_baseline_with(&publication_config(), || {
            Err(ProxyError::Config("publication revoked".to_owned()))
        });
        assert!(
            matches!(&result, Err(ProxyError::Config(error)) if error == "publication revoked"),
            "the publication callback must run and its rejection must propagate"
        );
        assert_eq!(state.snapshot().baseline_directive, "warn");
        assert_eq!(handle.clone_current().unwrap().to_string(), "warn");
    }

    #[test]
    fn missing_subscriber_does_not_publish_baseline_or_pipelines() {
        let (layer, handle) = reload::Layer::<EnvFilter, tracing_subscriber::Registry>::new(EnvFilter::new("warn"));
        drop(layer);
        let state = LogLevelState::new("warn".to_owned(), handle);
        let mut published = false;
        let result: Result<(), ProxyError> = state.refresh_baseline_with(&publication_config(), || {
            published = true;
            Ok(())
        });
        assert!(result.is_err());
        assert!(!published);
        assert_eq!(state.snapshot().baseline_directive, "warn");
    }

    #[test]
    fn subscriber_callbacks_run_after_publication_and_state_unlock() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            mpsc,
        };
        let (started, observed) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let committed = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(Mutex::new(()));
        let (layer, handle) = reload::Layer::new(EnvFilter::new("warn"));
        let subscriber = tracing_subscriber::registry().with(layer).with(BlockingRegistration {
            committed: Arc::clone(&committed),
            started,
            wait: Mutex::new(wait),
        });
        let dispatch = tracing::Dispatch::new(subscriber);
        let worker_dispatch = dispatch.clone();
        let state = LogLevelState::new("warn".to_owned(), handle);
        let worker_state = Arc::clone(&state);
        let worker_gate = Arc::clone(&gate);
        let worker = std::thread::Builder::new()
            .name("baseline-publication".to_owned())
            .spawn(move || {
                tracing::dispatcher::with_default(&worker_dispatch, || {
                    tracing::warn!("seed registration before arming publication probe");
                    worker_state
                        .refresh_baseline_with(&publication_config(), || {
                            let _guard = worker_gate.lock().unwrap();
                            committed.store(true, Ordering::Relaxed);
                            Ok::<_, ProxyError>(())
                        })
                        .unwrap();
                });
            })
            .unwrap();
        observed.recv_timeout(Duration::from_secs(5)).unwrap();
        let publication_unlocked = gate.try_lock().is_ok();
        let (snapshot_sent, snapshot_received) = mpsc::channel();
        let snapshot_state = Arc::clone(&state);
        let probe = std::thread::spawn(move || {
            let _sent = snapshot_sent.send(snapshot_state.snapshot());
        });
        let snapshot = snapshot_received.recv_timeout(Duration::from_secs(1));
        let (updating, attempted) = mpsc::channel();
        let (updated, completed) = mpsc::channel();
        let overlay_state = Arc::clone(&state);
        let admin = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let _started = updating.send(());
            let result = runtime.block_on(async {
                overlay_state.apply_put(&PutLogLevelRequest {
                    level: "debug".to_owned(),
                    module: Some("overlay_test".to_owned()),
                    duration_secs: Some(300),
                })
            });
            let _sent = updated.send(result);
        });
        attempted.recv_timeout(Duration::from_secs(5)).unwrap();
        let early_update = completed.recv_timeout(Duration::from_millis(50));
        let earliest_expiry = Utc::now().checked_add_signed(chrono::Duration::seconds(300)).unwrap();
        release.send(()).unwrap();
        worker.join().unwrap();
        probe.join().unwrap();
        admin.join().unwrap();
        assert!(publication_unlocked, "a stalled subscriber must not hold publication");
        let snapshot = snapshot.expect("snapshot must finish before the callback is released");
        assert!(
            snapshot.baseline_directive.contains("praxis_test=debug"),
            "snapshot must see committed baseline"
        );
        assert!(
            snapshot.overlays.is_empty(),
            "overlay mutation must wait for the earlier cache rebuild"
        );
        assert!(
            matches!(early_update, Err(mpsc::RecvTimeoutError::Timeout)),
            "cache rebuilds must not overlap"
        );
        assert!(
            completed.recv_timeout(Duration::from_secs(5)).unwrap().is_ok(),
            "queued overlay must complete"
        );
        assert!(
            state
                .inner
                .lock()
                .unwrap()
                .overlays
                .get("overlay_test")
                .unwrap()
                .expires_at
                >= earliest_expiry,
            "queued PUT expiry must start at installation, after the cache-rebuild wait"
        );
    }
    /// Stall one interest-cache callback only after the worker commits.
    struct BlockingRegistration {
        /// One-shot flag armed by publication.
        committed: Arc<std::sync::atomic::AtomicBool>,
        /// Let the test inspect locks while registration is blocked.
        started: std::sync::mpsc::Sender<()>,
        /// Release on an explicit signal or sender drop during unwinding.
        wait: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for BlockingRegistration {
        fn register_callsite(&self, _metadata: &'static tracing::Metadata<'static>) -> tracing::subscriber::Interest {
            if std::thread::current().name() == Some("baseline-publication")
                && self.committed.swap(false, std::sync::atomic::Ordering::Relaxed)
            {
                let _sent = self.started.send(());
                let _released = self.wait.lock().unwrap().recv();
            }
            tracing::subscriber::Interest::always()
        }
    }

    /// Serializes overlay mutation tests that share one global [`LogLevelState`].
    #[allow(
        unused_qualifications,
        reason = "test-only std mutex avoids import clash with parent"
    )]
    static OVERLAY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn shared_test_state() -> Arc<LogLevelState> {
        static STATE: OnceLock<Arc<LogLevelState>> = OnceLock::new();
        Arc::clone(STATE.get_or_init(|| {
            let baseline = "info".to_owned();
            let (filter_layer, reload_handle) = reload::Layer::new(EnvFilter::new(&baseline));
            // Keep the reloadable layer alive for the whole test run without
            // installing a global subscriber; init_tracing_installs_global_subscriber
            // is the sole owner of the process-global subscriber.
            let _ = Box::leak(Box::new(tracing_subscriber::registry().with(filter_layer)));
            LogLevelState::new(baseline, reload_handle)
        }))
    }

    fn reset_overlays(state: &Arc<LogLevelState>) {
        drop(state.delete_overlays(None, true));
    }

    #[test]
    fn validate_put_rejects_empty_module() {
        let err = validate_put_request(Some(""), "debug", 300).unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_put_rejects_zero_duration() {
        let err = validate_put_request(None, "debug", 0).unwrap_err();
        assert!(err.to_string().contains("at least 1"));
    }

    #[test]
    fn validate_put_rejects_excessive_duration() {
        let err = validate_put_request(None, "debug", MAX_OVERLAY_DURATION_SECS + 1).unwrap_err();
        assert!(err.to_string().contains("at most"));
    }

    #[test]
    fn validate_put_accepts_off_level() {
        validate_put_request(None, "off", 60).expect("off should be valid for admin overlays");
    }

    #[tokio::test(start_paused = true)]
    async fn failed_reload_rolls_back_overlay() {
        let (filter_layer, reload_handle) = reload::Layer::new(EnvFilter::new("info"));
        drop(filter_layer);
        let state = LogLevelState::new("info".to_owned(), reload_handle);

        let err = state
            .apply_put(&PutLogLevelRequest {
                level: "debug".to_owned(),
                module: None,
                duration_secs: Some(60),
            })
            .expect_err("reload against a dropped layer must fail");
        assert!(
            matches!(err, LogLevelError::Internal(_)),
            "reload failure should surface as Internal: {err}"
        );

        let snap = state.snapshot();
        assert!(
            snap.overlays.is_empty(),
            "failed PUT must not leave a phantom overlay visible: {snap:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stale_revert_does_not_evict_newer_overlay() {
        let (filter_layer, reload_handle) = reload::Layer::new(EnvFilter::new("info"));
        let _ = Box::leak(Box::new(tracing_subscriber::registry().with(filter_layer)));
        let state = LogLevelState::new("info".to_owned(), reload_handle);

        let put = |level: &str| PutLogLevelRequest {
            level: level.to_owned(),
            module: Some("praxis_filter".to_owned()),
            duration_secs: Some(300),
        };

        state.apply_put(&put("debug")).expect("first put (generation 0)");
        state.apply_put(&put("trace")).expect("second put (generation 1)");

        state.revert_target("praxis_filter", 0);
        let snap = state.snapshot();
        let overlay = snap
            .overlays
            .iter()
            .find(|o| o.module.as_deref() == Some("praxis_filter"));
        assert!(
            overlay.is_some_and(|o| o.level == "trace"),
            "a stale-generation revert must not evict the newer overlay: {snap:?}"
        );

        state.revert_target("praxis_filter", 1);
        assert!(
            state
                .snapshot()
                .overlays
                .iter()
                .all(|o| o.module.as_deref() != Some("praxis_filter")),
            "the current-generation revert should remove the overlay"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn overlay_put_revert_and_delete_lifecycle() {
        let _lock = OVERLAY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = shared_test_state();
        reset_overlays(&state);

        let snap = state.snapshot();
        assert_eq!(snap.effective_directive, "info");

        state
            .apply_put(&PutLogLevelRequest {
                level: "debug".to_owned(),
                module: None,
                duration_secs: Some(300),
            })
            .expect("global overlay");
        state
            .apply_put(&PutLogLevelRequest {
                level: "trace".to_owned(),
                module: Some("praxis_filter".to_owned()),
                duration_secs: Some(300),
            })
            .expect("module overlay");
        let snap = state.snapshot();
        assert_eq!(snap.overlays.len(), 2, "global and module overlays: {snap:?}");

        let cleared = state.delete_overlays(None, true).expect("delete all");
        assert!(cleared.overlays.is_empty());
        assert_eq!(cleared.effective_directive, "info");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn overlay_auto_reverts_after_duration() {
        let (layer, handle) = reload::Layer::new(EnvFilter::new("info"));
        let _subscriber = tracing_subscriber::registry().with(layer);
        let state = LogLevelState::new("info".to_owned(), handle);
        state
            .apply_put(&PutLogLevelRequest {
                level: "trace".to_owned(),
                module: Some("praxis_filter".to_owned()),
                duration_secs: Some(10),
            })
            .expect("module overlay");
        assert!(
            !state.snapshot().overlays.is_empty(),
            "the overlay must be installed before its deadline"
        );
        tokio::time::advance(Duration::from_secs(10)).await;
        for _ in 0..100 {
            if state.snapshot().overlays.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        let snapshot = state.snapshot();
        assert!(
            snapshot.overlays.is_empty(),
            "revert must run after its installation deadline, even with a delayed first poll: {snapshot:?}"
        );
        assert_eq!(snapshot.effective_directive, "info", "expiry must restore the baseline");
    }
    #[test]
    fn log_level_error_display() {
        let bad_request = LogLevelError::BadRequest("invalid input".to_owned());
        assert_eq!(bad_request.to_string(), "invalid input");

        let internal = LogLevelError::Internal("reload failed".to_owned());
        assert_eq!(internal.to_string(), "reload failed");
    }

    #[test]
    fn log_level_error_equality() {
        let err1 = LogLevelError::BadRequest("test".to_owned());
        let err2 = LogLevelError::BadRequest("test".to_owned());
        let err3 = LogLevelError::BadRequest("other".to_owned());
        let err4 = LogLevelError::Internal("test".to_owned());

        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
        assert_ne!(err1, err4);
    }

    #[test]
    fn log_level_error_clone() {
        let original = LogLevelError::BadRequest("test".to_owned());
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn validate_put_rejects_invalid_log_level() {
        let err = validate_put_request(None, "verbose", 300).unwrap_err();
        assert!(err.to_string().contains("invalid level"));
        assert!(err.to_string().contains("verbose"));

        let err = validate_put_request(None, "warning", 300).unwrap_err();
        assert!(err.to_string().contains("invalid level"));

        let err = validate_put_request(None, "", 300).unwrap_err();
        assert!(err.to_string().contains("invalid level"));

        let err = validate_put_request(None, "invalid", 300).unwrap_err();
        assert!(err.to_string().contains("invalid level"));
    }

    #[test]
    fn validate_put_accepts_all_valid_levels() {
        validate_put_request(None, "error", 60).expect("error should be valid");
        validate_put_request(None, "warn", 60).expect("warn should be valid");
        validate_put_request(None, "info", 60).expect("info should be valid");
        validate_put_request(None, "debug", 60).expect("debug should be valid");
        validate_put_request(None, "trace", 60).expect("trace should be valid");
        validate_put_request(None, "off", 60).expect("off should be valid");
    }

    #[test]
    fn validate_put_accepts_case_insensitive_levels() {
        validate_put_request(None, "ERROR", 60).expect("ERROR should be valid");
        validate_put_request(None, "Debug", 60).expect("Debug should be valid");
        validate_put_request(None, "TRACE", 60).expect("TRACE should be valid");
        validate_put_request(None, "OfF", 60).expect("OfF should be valid");
    }

    #[test]
    fn validate_put_rejects_invalid_module_paths() {
        // Empty is checked separately
        let err = validate_put_request(Some("invalid path"), "info", 60).unwrap_err();
        assert!(err.to_string().contains("invalid module path"));

        let err = validate_put_request(Some("123invalid"), "info", 60).unwrap_err();
        assert!(err.to_string().contains("invalid module path"));

        let err = validate_put_request(Some("::praxis"), "info", 60).unwrap_err();
        assert!(err.to_string().contains("invalid module path"));

        let err = validate_put_request(Some("praxis::"), "info", 60).unwrap_err();
        assert!(err.to_string().contains("invalid module path"));

        let err = validate_put_request(Some("praxis:::filter"), "info", 60).unwrap_err();
        assert!(err.to_string().contains("invalid module path"));
    }

    #[test]
    fn validate_put_accepts_valid_module_paths() {
        validate_put_request(Some("praxis"), "info", 60).expect("simple module");
        validate_put_request(Some("praxis_core"), "info", 60).expect("underscore module");
        validate_put_request(Some("praxis::filter"), "info", 60).expect("nested module");
        validate_put_request(Some("praxis_core::logging"), "info", 60).expect("mixed module");
        validate_put_request(Some("_internal"), "info", 60).expect("leading underscore");
    }

    #[test]
    fn normalize_level_lowercases() {
        assert_eq!(normalize_level("ERROR"), "error");
        assert_eq!(normalize_level("Warn"), "warn");
        assert_eq!(normalize_level("INFO"), "info");
        assert_eq!(normalize_level("DeBuG"), "debug");
        assert_eq!(normalize_level("trace"), "trace");
        assert_eq!(normalize_level("OFF"), "off");
    }

    #[test]
    fn overlay_target_key_mapping() {
        assert_eq!(overlay_target_key(None), GLOBAL_OVERLAY_KEY);
        assert_eq!(overlay_target_key(Some("praxis")), "praxis");
        assert_eq!(overlay_target_key(Some("praxis::filter")), "praxis::filter");
        assert_eq!(overlay_target_key(Some("")), "");
    }

    #[test]
    fn build_effective_directive_empty_overlays() {
        let overlays = HashMap::new();
        let directive = build_effective_directive("info", &overlays);
        assert_eq!(directive, "info");
    }

    #[tokio::test]
    async fn build_effective_directive_single_global() {
        let mut overlays = HashMap::new();
        overlays.insert(
            GLOBAL_OVERLAY_KEY.to_owned(),
            OverlayEntry {
                level: "debug".to_owned(),
                expires_at: Utc::now() + chrono::Duration::seconds(300),
                revert_abort: tokio::spawn(async {}).abort_handle(),
                generation: 0,
            },
        );
        let directive = build_effective_directive("info", &overlays);
        assert_eq!(directive, "info,debug");
    }

    #[tokio::test]
    async fn build_effective_directive_multiple_modules() {
        let mut overlays = HashMap::new();
        overlays.insert(
            "praxis_filter".to_owned(),
            OverlayEntry {
                level: "trace".to_owned(),
                expires_at: Utc::now() + chrono::Duration::seconds(300),
                revert_abort: tokio::spawn(async {}).abort_handle(),
                generation: 0,
            },
        );
        overlays.insert(
            "praxis_core".to_owned(),
            OverlayEntry {
                level: "debug".to_owned(),
                expires_at: Utc::now() + chrono::Duration::seconds(300),
                revert_abort: tokio::spawn(async {}).abort_handle(),
                generation: 1,
            },
        );
        let directive = build_effective_directive("info", &overlays);
        // Keys are sorted
        assert!(
            directive == "info,praxis_core=debug,praxis_filter=trace"
                || directive == "info,praxis_filter=trace,praxis_core=debug",
            "got: {directive}"
        );
    }

    #[tokio::test]
    async fn build_effective_directive_global_and_module() {
        let mut overlays = HashMap::new();
        overlays.insert(
            GLOBAL_OVERLAY_KEY.to_owned(),
            OverlayEntry {
                level: "warn".to_owned(),
                expires_at: Utc::now() + chrono::Duration::seconds(300),
                revert_abort: tokio::spawn(async {}).abort_handle(),
                generation: 0,
            },
        );
        overlays.insert(
            "praxis".to_owned(),
            OverlayEntry {
                level: "trace".to_owned(),
                expires_at: Utc::now() + chrono::Duration::seconds(300),
                revert_abort: tokio::spawn(async {}).abort_handle(),
                generation: 1,
            },
        );
        let directive = build_effective_directive("info", &overlays);
        // Empty key comes first after sorting
        assert!(
            directive == "info,warn,praxis=trace" || directive == "info,praxis=trace,warn",
            "got: {directive}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn delete_overlays_nonexistent_module() {
        let _lock = OVERLAY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = shared_test_state();
        reset_overlays(&state);

        // Deleting a non-existent module should succeed (no-op)
        let result = state
            .delete_overlays(Some("nonexistent"), false)
            .expect("should succeed even if module doesn't exist");
        assert!(result.overlays.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn delete_overlays_empty_state() {
        let _lock = OVERLAY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = shared_test_state();
        reset_overlays(&state);

        // Deleting all from empty state should succeed
        let result = state.delete_overlays(None, true).expect("delete all from empty");
        assert!(result.overlays.is_empty());

        // Deleting specific module from empty state should succeed
        let result = state
            .delete_overlays(Some("praxis"), false)
            .expect("delete specific from empty");
        assert!(result.overlays.is_empty());

        // Deleting global from empty state should succeed
        let result = state.delete_overlays(None, false).expect("delete global from empty");
        assert!(result.overlays.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn delete_specific_module_leaves_others() {
        let _lock = OVERLAY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = shared_test_state();
        reset_overlays(&state);

        state
            .apply_put(&PutLogLevelRequest {
                level: "debug".to_owned(),
                module: None,
                duration_secs: Some(300),
            })
            .expect("global overlay");
        state
            .apply_put(&PutLogLevelRequest {
                level: "trace".to_owned(),
                module: Some("praxis_filter".to_owned()),
                duration_secs: Some(300),
            })
            .expect("module overlay");
        state
            .apply_put(&PutLogLevelRequest {
                level: "debug".to_owned(),
                module: Some("praxis_core".to_owned()),
                duration_secs: Some(300),
            })
            .expect("another module overlay");

        let snap = state.snapshot();
        assert_eq!(snap.overlays.len(), 3);

        // Delete just praxis_filter
        let result = state
            .delete_overlays(Some("praxis_filter"), false)
            .expect("delete specific module");
        assert_eq!(result.overlays.len(), 2);
        assert!(
            result
                .overlays
                .iter()
                .all(|o| o.module.as_deref() != Some("praxis_filter")),
            "praxis_filter should be removed"
        );
        assert!(
            result.overlays.iter().any(|o| o.module.is_none()),
            "global should remain"
        );
        assert!(
            result
                .overlays
                .iter()
                .any(|o| o.module.as_deref() == Some("praxis_core")),
            "praxis_core should remain"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn delete_global_overlay_leaves_modules() {
        let _lock = OVERLAY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = shared_test_state();
        reset_overlays(&state);

        state
            .apply_put(&PutLogLevelRequest {
                level: "debug".to_owned(),
                module: None,
                duration_secs: Some(300),
            })
            .expect("global overlay");
        state
            .apply_put(&PutLogLevelRequest {
                level: "trace".to_owned(),
                module: Some("praxis_filter".to_owned()),
                duration_secs: Some(300),
            })
            .expect("module overlay");

        // Delete just the global overlay
        let result = state.delete_overlays(None, false).expect("delete global");
        assert_eq!(result.overlays.len(), 1);
        assert_eq!(result.overlays[0].module, Some("praxis_filter".to_owned()));
    }

    #[test]
    fn log_level_inner_generation_wraps() {
        let mut inner = LogLevelInner {
            baseline_directive: "info".to_owned(),
            overlays: HashMap::new(),
            reload_handle: {
                let (layer, handle) = reload::Layer::new(EnvFilter::new("info"));
                drop(layer);
                handle
            },
            next_generation: u64::MAX - 1,
        };

        assert_eq!(inner.take_generation(), u64::MAX - 1);
        assert_eq!(inner.take_generation(), u64::MAX);
        // Wraps to 0
        assert_eq!(inner.take_generation(), 0);
        assert_eq!(inner.take_generation(), 1);
    }

    #[test]
    fn put_log_level_request_deserialize() {
        let yaml = "
level: debug
module: praxis_filter
duration_secs: 600
";
        let req: PutLogLevelRequest = serde_yaml::from_str(yaml).expect("should deserialize");
        assert_eq!(req.level, "debug");
        assert_eq!(req.module, Some("praxis_filter".to_owned()));
        assert_eq!(req.duration_secs, Some(600));
    }

    #[test]
    fn put_log_level_request_deserialize_minimal() {
        let yaml = "
level: info
";
        let req: PutLogLevelRequest = serde_yaml::from_str(yaml).expect("should deserialize");
        assert_eq!(req.level, "info");
        assert_eq!(req.module, None);
        assert_eq!(req.duration_secs, None);
    }

    #[test]
    fn log_level_overlay_view_serialize() {
        let view = LogLevelOverlayView {
            module: Some("praxis".to_owned()),
            level: "debug".to_owned(),
            expires_at: "2026-09-19T12:00:00Z".to_owned(),
        };
        let yaml = serde_yaml::to_string(&view).expect("should serialize");
        assert!(yaml.contains("module: praxis"));
        assert!(yaml.contains("level: debug"));
        assert!(yaml.contains("expires_at"));
    }

    #[test]
    fn log_level_overlay_view_serialize_no_module() {
        let view = LogLevelOverlayView {
            module: None,
            level: "warn".to_owned(),
            expires_at: "2026-09-19T12:00:00Z".to_owned(),
        };
        let yaml = serde_yaml::to_string(&view).expect("should serialize");
        assert!(!yaml.contains("module:"));
        assert!(yaml.contains("level: warn"));
    }

    #[test]
    fn log_level_state_response_serialize() {
        let response = LogLevelStateResponse {
            baseline_directive: "info".to_owned(),
            overlays: vec![LogLevelOverlayView {
                module: Some("praxis".to_owned()),
                level: "debug".to_owned(),
                expires_at: "2026-09-19T12:00:00Z".to_owned(),
            }],
            effective_directive: "info,praxis=debug".to_owned(),
        };
        let yaml = serde_yaml::to_string(&response).expect("should serialize");
        assert!(yaml.contains("baseline_directive: info"));
        assert!(yaml.contains("effective_directive"));
    }

    #[test]
    fn env_filter_from_directive_valid() {
        env_filter_from_directive("info").expect("simple directive");
        env_filter_from_directive("debug,praxis=trace").expect("with module override");
        env_filter_from_directive("warn,praxis::filter=debug,praxis::core=info").expect("multiple overrides");
    }

    #[test]
    fn env_filter_from_directive_invalid() {
        let err = env_filter_from_directive("[invalid").expect_err("malformed directive");
        assert!(err.to_string().contains("invalid log filter directive"));
    }

    #[tokio::test(start_paused = true)]
    async fn apply_put_supersedes_previous_overlay() {
        let _lock = OVERLAY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = shared_test_state();
        reset_overlays(&state);

        // First overlay
        state
            .apply_put(&PutLogLevelRequest {
                level: "debug".to_owned(),
                module: Some("praxis".to_owned()),
                duration_secs: Some(300),
            })
            .expect("first overlay");
        let snap = state.snapshot();
        assert_eq!(snap.overlays.len(), 1);
        assert_eq!(snap.overlays[0].level, "debug");

        // Second overlay to same target
        state
            .apply_put(&PutLogLevelRequest {
                level: "trace".to_owned(),
                module: Some("praxis".to_owned()),
                duration_secs: Some(300),
            })
            .expect("second overlay");
        let snap = state.snapshot();
        assert_eq!(snap.overlays.len(), 1);
        assert_eq!(snap.overlays[0].level, "trace");

        // Clean up
        reset_overlays(&state);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn refresh_baseline_preserves_overlays() {
        let _lock = OVERLAY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = shared_test_state();
        reset_overlays(&state);

        state
            .apply_put(&PutLogLevelRequest {
                level: "trace".to_owned(),
                module: Some("praxis_test".to_owned()),
                duration_secs: Some(300),
            })
            .expect("overlay before refresh");

        let config_yaml = "
listeners:
  - name: test
    address: 127.0.0.1:0
    protocol: http
    filter_chains:
      - test_chain
filter_chains:
  - name: test_chain
    filters: []
";
        let config = Config::load(None, config_yaml).expect("valid config");
        state.refresh_baseline(&config).expect("refresh baseline");

        let snap = state.snapshot();
        assert_eq!(snap.overlays.len(), 1, "overlay should survive baseline refresh");
        assert_eq!(snap.overlays[0].level, "trace");
        assert_eq!(snap.overlays[0].module, Some("praxis_test".to_owned()));

        // Clean up to avoid interfering with other tests
        reset_overlays(&state);
    }
}
