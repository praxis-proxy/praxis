// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Process-wide connection limit.
//!
//! Complements per-listener `max_connections` with a global
//! ceiling across all listeners. Initialized once at server
//! startup from [`RuntimeConfig::max_connections`].
//!
//! [`ConnectionPermits`] bundles the two permits a single
//! downstream connection holds so both are released together.
//!
//! [`ConnectionPermits`]: crate::connections::ConnectionPermits
//! [`RuntimeConfig::max_connections`]: praxis_core::config::RuntimeConfig::max_connections

use std::sync::{Arc, OnceLock};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

// -----------------------------------------------------------------------------
// Global Semaphore
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Connection Permits
// -----------------------------------------------------------------------------

/// Admission permits held for the lifetime of one downstream connection.
///
/// Bundles the process-wide permit from [`try_acquire_global`] with the
/// per-listener permit so both are released together by RAII when the last
/// holder drops.
///
/// The HTTP path shares the bundle behind an [`Arc`] because Pingora passes
/// the per-request context to `persist_connection_context` by shared
/// reference: the permits cannot be moved out of it, but a clone of the
/// `Arc` can be parked on the connection and handed back to the next
/// keep-alive request. Sharing rather than re-acquiring is what makes the
/// limit count connections instead of requests.
///
/// ```
/// use praxis_protocol::connections::ConnectionPermits;
///
/// assert!(ConnectionPermits::bundle(None, None).is_none());
/// ```
pub struct ConnectionPermits {
    /// Permit from the process-wide semaphore, when `runtime.max_connections` is set.
    _global: Option<OwnedSemaphorePermit>,

    /// Permit from the listener semaphore, when the listener sets `max_connections`.
    _listener: Option<OwnedSemaphorePermit>,
}

impl ConnectionPermits {
    /// Bundle already-acquired permits into a shareable handle.
    ///
    /// Returns `None` when neither limit is configured, so the unlimited
    /// default costs no allocation.
    pub fn bundle(global: Option<OwnedSemaphorePermit>, listener: Option<OwnedSemaphorePermit>) -> Option<Arc<Self>> {
        (global.is_some() || listener.is_some()).then(|| {
            Arc::new(Self {
                _global: global,
                _listener: listener,
            })
        })
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
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

    #[test]
    fn bundle_holds_permits_until_last_clone_drops() {
        let sem = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&sem).try_acquire_owned().expect("first acquire");

        let bundle = ConnectionPermits::bundle(None, Some(permit)).expect("bundle with a permit");
        let carried = Arc::clone(&bundle);
        drop(bundle);
        assert_eq!(
            sem.available_permits(),
            0,
            "a surviving clone must keep the permit held"
        );

        drop(carried);
        assert_eq!(
            sem.available_permits(),
            1,
            "dropping the last clone must release the permit"
        );
    }

    #[test]
    fn bundle_holds_global_permit_until_last_clone_drops() {
        // The global slot is bundled and carried exactly like the listener
        // slot, so it needs its own coverage: every other test leaves it
        // `None`, which would let the `runtime.max_connections` half of the
        // connection scoping regress unnoticed.
        let sem = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&sem).try_acquire_owned().expect("first acquire");

        let bundle = ConnectionPermits::bundle(Some(permit), None).expect("bundle with a global permit");
        let carried = Arc::clone(&bundle);
        drop(bundle);
        assert_eq!(
            sem.available_permits(),
            0,
            "a surviving clone must keep the global permit held"
        );

        drop(carried);
        assert_eq!(
            sem.available_permits(),
            1,
            "dropping the last clone must release the global permit"
        );
    }

    #[test]
    fn bundle_holds_both_permits_together() {
        let global_sem = Arc::new(Semaphore::new(1));
        let listener_sem = Arc::new(Semaphore::new(1));

        let bundle = ConnectionPermits::bundle(
            Some(Arc::clone(&global_sem).try_acquire_owned().expect("global acquire")),
            Some(Arc::clone(&listener_sem).try_acquire_owned().expect("listener acquire")),
        )
        .expect("bundle with both permits");

        assert_eq!(global_sem.available_permits(), 0, "global permit should be held");
        assert_eq!(listener_sem.available_permits(), 0, "listener permit should be held");

        drop(bundle);
        assert_eq!(global_sem.available_permits(), 1, "global permit should be released");
        assert_eq!(
            listener_sem.available_permits(),
            1,
            "listener permit should be released"
        );
    }

    #[test]
    fn bundle_without_limits_allocates_nothing() {
        assert!(
            ConnectionPermits::bundle(None, None).is_none(),
            "an unlimited listener should not allocate a bundle"
        );
    }
}
