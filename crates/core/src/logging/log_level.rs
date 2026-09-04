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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
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
        let level = normalize_level(&request.level);
        let expires_at = Utc::now() + chrono::Duration::seconds(i64::try_from(duration_secs).unwrap_or(i64::MAX));

        let mut guard = self.inner.lock().expect("log level state lock poisoned");
        let previous = guard.overlays.remove(&target);

        let generation = guard.take_generation();
        let abort_handle = spawn_revert_task(Arc::clone(self), target.clone(), duration_secs, generation);

        guard.overlays.insert(
            target.clone(),
            OverlayEntry {
                level,
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
    #[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "baseline update and reload must share one lock guard"
    )]
    pub fn refresh_baseline(self: &Arc<Self>, config: &Config) -> Result<(), ProxyError> {
        let baseline = build_baseline_directive(config)?;
        let mut guard = self.inner.lock().expect("log level state lock poisoned");
        guard.baseline_directive = baseline;
        reload_locked(&guard).map_err(|error| ProxyError::Config(error.to_string()))?;
        Ok(())
    }

    /// Remove one overlay after its revert timer fires (internal).
    ///
    /// Reverts only when the overlay currently at `target` is the exact one
    /// this task was scheduled for (`generation`). A later `PUT` to the same
    /// target installs a new generation, so a stale timer (whose abort may
    /// have lost the race against its own wakeup) becomes a no-op instead of
    /// evicting the newer overlay.
    fn revert_target(self: &Arc<Self>, target: &str, generation: u64) {
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
// Helpers
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
    overlays.sort_by(|a, b| a.module.cmp(&b.module));

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

/// Spawn a task that reverts one overlay after `duration_secs`.
fn spawn_revert_task(state: Arc<LogLevelState>, target: String, duration_secs: u64, generation: u64) -> AbortHandle {
    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(duration_secs)).await;
        state.revert_target(&target, generation);
    });
    handle.abort_handle()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use std::sync::OnceLock;

    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

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
        // A reload handle whose layer was never installed (and is dropped)
        // makes reload_locked fail, exercising the rollback path.
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
        // Fresh state so overlay generations are deterministic (0, then 1).
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

        // The first overlay's revert timer firing late (its abort may have lost
        // the race with its own wakeup) must not evict the newer overlay.
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

        // The current-generation revert does remove it.
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
    #[expect(
        clippy::too_many_lines,
        reason = "setup, timer advance, and assertions in one async test"
    )]
    async fn overlay_auto_reverts_after_duration() {
        let state = shared_test_state();
        {
            let _lock = OVERLAY_TEST_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            reset_overlays(&state);

            state
                .apply_put(&PutLogLevelRequest {
                    level: "trace".to_owned(),
                    module: Some("praxis_filter".to_owned()),
                    duration_secs: Some(10),
                })
                .expect("module overlay");
            let snap = state.snapshot();
            assert!(
                snap.effective_directive.contains("praxis_filter=trace"),
                "overlay should be active: {snap:?}"
            );
        }

        // Let the revert task register its sleep before advancing fake time.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;

        let _lock = OVERLAY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let snap = state.snapshot();
        assert!(
            snap.overlays.is_empty(),
            "overlay should revert after duration: {snap:?}"
        );
        assert_eq!(snap.effective_directive, "info");
    }
}
