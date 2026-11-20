// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Allocator callbacks for returning unused pages under memory pressure.

use std::ffi::CStr;

/// Purge unused pages from every jemalloc arena, reporting success.
/// Safe independently of the global allocator: this operates only on jemalloc's
/// own arenas. Register it only when jemalloc serves the process allocations.
pub fn jemalloc_purge() -> bool {
    /// 4096 is `MALLCTL_ARENAS_ALL`, not an arena count or a byte limit.
    /// tikv-jemalloc-sys does not export this pseudo-index.
    const PURGE_ALL_ARENAS: &CStr = c"arena.4096.purge";
    // tikv-jemalloc-ctl has safe epoch/stat readers, but no typed API for the
    // argument-free arena.<all>.purge command. Its raw control API is unsafe too,
    // so keep the required FFI boundary here rather than exposing raw pointers.
    // Remove this exception when a safe purge API exists: praxis-proxy/praxis#1514.
    #[expect(
        unsafe_code,
        reason = "jemalloc's argument-free arena purge has no safe typed control API"
    )]
    // SAFETY: the binding has no Rust # Safety section. The documented contract
    // comes from jemalloc 5.3.1's mallctl(3):
    // https://jemalloc.net/jemalloc.3.html
    // - The name is a valid NUL-terminated string: a static CStr here.
    // - Null oldp/oldlenp and null newp with newlen=0 supply no caller buffers.
    // - arena.<i>.purge is a void control for unused dirty pages; the fixed MALLCTL_ARENAS_ALL command cannot
    //   invalidate live Rust allocations.
    // Implementation assumptions were checked against the jemalloc source in
    // locked tikv-jemalloc-sys 0.7.1+5.3.1-0-g81034ce1f1373e37dc865038e1bc8eeecf559ce8:
    // - je_mallctl calls malloc_init() before ctl_byname(), so no prior allocator initialization or global-allocator
    //   identity is required.
    // - ctl and per-arena decay paths synchronize allocator state, permitting concurrent calls and allocations. See
    //   src/jemalloc.c and src/ctl.c.
    // Manually re-audit these assumptions on EVERY allocator upgrade; the
    // purge_contract_matches_locked_allocator test is an upgrade tripwire,
    // not a proof of the C implementation's safety.
    let result = unsafe {
        tikv_jemalloc_sys::mallctl(
            PURGE_ALL_ARENAS.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        )
    };
    purge_succeeded(result)
}

/// Preserve the allocator error code in diagnostics and report command failure.
fn purge_succeeded(result: std::ffi::c_int) -> bool {
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
    fn allocator_control_error_reports_failure() {
        assert!(!super::purge_succeeded(nix::libc::ENOENT));
        assert!(!super::purge_succeeded(nix::libc::EAGAIN));
    }

    #[test]
    fn purge_contract_matches_locked_allocator() {
        let lock = include_str!("../../../Cargo.lock");
        assert!(
            lock.split("[[package]]").any(|package| {
                package.lines().any(|line| line == "name = \"tikv-jemalloc-sys\"")
                    && package
                        .lines()
                        .any(|line| line == "version = \"0.7.1+5.3.1-0-g81034ce1f1373e37dc865038e1bc8eeecf559ce8\"")
            }),
            "allocator changed: manually re-audit jemalloc_purge's safety contract before updating this guard"
        );
    }
}
