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

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn usage_counts_a_held_permit() {
        init_global_limit(4);
        let (_exceeded, permit) = try_acquire_global();
        let (in_use, max) = global_usage().expect("a cap was installed");
        assert_eq!(max, 4, "the cap is the value passed to init");
        assert_eq!(in_use, 1, "one held permit is one connection in use");
        drop(permit);
        let (in_use, _) = global_usage().expect("a cap was installed");
        assert_eq!(in_use, 0, "dropping the permit returns the connection");
    }
}
