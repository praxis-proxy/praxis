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
    #[expect(
        unsafe_code,
        reason = "jemalloc mallctl FFI; null buffers request a command without reading or writing memory"
    )]
    // SAFETY: command is NUL-terminated and alive for the call. Null buffers
    // with length zero request no memory access. Purging frees no live allocation.
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
    let mut epoch = 1_u64;
    let mut allocated = 0_usize;
    let mut length = size_of::<usize>();
    #[expect(
        unsafe_code,
        reason = "jemalloc mallctl writes exactly the typed output buffers whose sizes are passed"
    )]
    // SAFETY: all control names are static C strings. The epoch input and the
    // allocated output are live, correctly aligned typed objects with matching sizes.
    let ok = unsafe {
        tikv_jemalloc_sys::mallctl(
            c"epoch".as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::from_mut(&mut epoch).cast(),
            size_of::<u64>(),
        ) == 0
            && tikv_jemalloc_sys::mallctl(
                c"stats.allocated".as_ptr(),
                std::ptr::from_mut(&mut allocated).cast(),
                &raw mut length,
                std::ptr::null_mut(),
                0,
            ) == 0
    };
    ok.then_some(allocated)
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
