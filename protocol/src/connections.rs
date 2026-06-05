// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Process-wide connection limit.
//!
//! Complements per-listener `max_connections` with a global
//! ceiling across all listeners. Initialized once at server
//! startup from [`RuntimeConfig::max_connections`].
//!
//! [`RuntimeConfig::max_connections`]: praxis_core::config::RuntimeConfig::max_connections

use std::sync::{Arc, OnceLock};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

// ---------------------------------------------------------------------------
// Global Semaphore
// ---------------------------------------------------------------------------

/// Process-wide connection semaphore.
static GLOBAL_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();

/// Initialize the global connection limit.
///
/// Called once during server startup. Subsequent calls are no-ops.
pub fn init_global_limit(max: usize) {
    GLOBAL_LIMIT.get_or_init(|| Arc::new(Semaphore::new(max)));
}

/// Try to acquire a global connection permit.
///
/// Returns `None` when no global limit is configured or the
/// permit was acquired. Returns `Some(permit)` on success.
/// Callers check `is_none()` after filtering out the
/// "no limit configured" case via the two-field tuple.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn no_init_returns_not_exceeded() {
        let (exceeded, permit) = try_acquire_global();
        assert!(!exceeded, "uninitialized global should not exceed");
        assert!(permit.is_none(), "uninitialized global should return no permit");
    }
}
