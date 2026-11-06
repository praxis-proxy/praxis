// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Allocator callbacks for returning unused pages under memory pressure.

use std::ffi::CStr;

/// Purge unused pages from every jemalloc arena, reporting success.
/// Only register this callback when jemalloc is the process allocator.
pub fn jemalloc_purge() -> bool {
    purge(c"arena.4096.purge")
}

/// Execute a jemalloc purge control and report whether the allocator accepted it.
fn purge(command: &CStr) -> bool {
    // tikv-jemalloc-ctl has safe epoch/stat readers, but no typed API for the
    // argument-free arena.<all>.purge command. Its raw control API is unsafe too,
    // so keep the required FFI boundary here rather than exposing raw pointers.
    // Remove this exception when a safe purge API exists: praxis-proxy/praxis#1514.
    #[expect(
        unsafe_code,
        reason = "jemalloc's argument-free arena purge has no safe typed control API"
    )]
    // SAFETY: command is NUL-terminated and alive for the call. Null buffers
    // with length zero provide no caller-owned input or output buffers.
    // Purging frees no live allocation; jemalloc synchronizes its arena state.
    let result = unsafe {
        tikv_jemalloc_sys::mallctl(
            command.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        tracing::debug!(code = result, "jemalloc heap purge failed");
    }
    result == 0
}

/// Refresh allocator statistics and read live allocated bytes for wiring tests.
/// This measures live memory, so purging unused pages need not change it.
#[doc(hidden)]
pub fn allocated_bytes() -> Option<usize> {
    tikv_jemalloc_ctl::epoch::advance().ok()?;
    tikv_jemalloc_ctl::stats::allocated::read().ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn jemalloc_purge_succeeds() {
        assert!(super::jemalloc_purge());
    }

    #[test]
    fn invalid_allocator_control_reports_failure() {
        assert!(!super::purge(c"praxis.invalid.purge"));
    }
}
