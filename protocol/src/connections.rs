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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn global_limit_lifecycle() {
        let (exceeded, permit) = try_acquire_global();
        assert!(!exceeded, "uninitialized global should not report exceeded");
        assert!(permit.is_none(), "uninitialized global should return no permit");

        init_global_limit(2);

        let (exceeded, first) = try_acquire_global();
        assert!(!exceeded, "first acquire should not exceed limit");
        let first = first.expect("first acquire should return a permit");

        let (exceeded, second) = try_acquire_global();
        assert!(!exceeded, "second acquire should not exceed limit");
        let second = second.expect("second acquire should return a permit");

        let (exceeded, permit) = try_acquire_global();
        assert!(exceeded, "third acquire should exceed limit of 2");
        assert!(permit.is_none(), "exhausted limit should return no permit");

        drop(first);

        let (exceeded, reclaimed) = try_acquire_global();
        assert!(!exceeded, "acquire after drop should not exceed limit");
        assert!(reclaimed.is_some(), "released slot should yield a permit");

        drop(second);
    }
}
