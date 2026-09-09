// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Test-only helpers shared by the crate's unit tests.

#![expect(clippy::expect_used, reason = "tests")]

use std::{
    path::PathBuf,
    sync::{Mutex, MutexGuard, OnceLock, PoisonError},
};

/// Serializes every test that mutates the process working directory.
static CWD_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

/// RAII guard that switches the process working directory and restores it on
/// drop.
///
/// The working directory is process-global and unit tests run as parallel
/// threads of a single binary, so every test that changes it has to take the
/// same lock; per-module mutexes would serialize nothing against each other.
/// The lock is part of the guard for that reason: acquiring it is not something
/// a caller can forget.
pub(crate) struct CwdGuard {
    /// Directory to restore when the guard is dropped.
    original: PathBuf,

    /// Held for the guard's lifetime so no other test moves the directory.
    _lock: MutexGuard<'static, ()>,
}

impl CwdGuard {
    /// Change to `path`, capturing the current directory for restore.
    ///
    /// A poisoned lock is recovered rather than propagated: a panicking
    /// working-directory test must not cascade into unrelated ones.
    pub(crate) fn new(path: &std::path::Path) -> Self {
        let lock = CWD_MUTEX
            .get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let original = std::env::current_dir().expect("current working directory");
        std::env::set_current_dir(path).expect("failed to change working directory");
        Self { original, _lock: lock }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.original).expect("failed to restore working directory");
    }
}
