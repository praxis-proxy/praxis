// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Process-wide connection limit.
//!
//! Complements per-listener `max_connections` with a global
//! ceiling across all listeners. Initialized once at server
//! startup from [`RuntimeConfig::max_connections`].
//!
//! [`RuntimeConfig::max_connections`]: praxis_core::config::RuntimeConfig::max_connections

use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

// -----------------------------------------------------------------------------
// Global Semaphore
// -----------------------------------------------------------------------------

/// Process-wide connection semaphore.
static GLOBAL_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();

/// Cap passed to [`init_global_limit`]. The semaphore does not remember it.
static GLOBAL_MAX: AtomicUsize = AtomicUsize::new(0);

/// Initialize the global connection limit.
///
/// Called once during server startup. Subsequent calls are no-ops.
pub fn init_global_limit(max: usize) {
    GLOBAL_LIMIT.get_or_init(|| {
        GLOBAL_MAX.store(max, Ordering::Relaxed);
        Arc::new(Semaphore::new(max))
    });
}

/// Connections in use and the configured cap, when a cap exists.
///
/// In use is the cap minus the permits still available. The count is racy
/// with acquire and release, which is enough for a pressure gauge.
pub fn global_usage() -> Option<(usize, usize)> {
    let sem = GLOBAL_LIMIT.get()?;
    let max = GLOBAL_MAX.load(Ordering::Relaxed);
    (max > 0).then_some((max.saturating_sub(sem.available_permits()), max))
}

/// Try to acquire a global connection permit.
///
/// Returns one of three states:
///
/// - `(false, None)` — no global limit is configured.
/// - `(false, Some(permit))` — permit was acquired.
/// - `(true, None)` — limit is exhausted.
pub fn try_acquire_global() -> (bool, Option<OwnedSemaphorePermit>) {
    let Some(sem) = GLOBAL_LIMIT.get() else {
        return (false, None);
    };

    if let Ok(permit) = Arc::clone(sem).try_acquire_owned() {
        (false, Some(permit))
    } else {
        (true, None)
    }
}

// Unit tests for `global_usage` are in the `global_connection_limit`
// integration test. Calling `init_global_limit` in a unit test permanently
// caps the protocol unit-test process and can break parallel Hyper tests.
