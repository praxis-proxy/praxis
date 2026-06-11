// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Process-wide memory pressure monitoring.
//!
//! Tracks resident set size (RSS) via `/proc/self/statm` on
//! Linux and sheds load when a configured threshold is exceeded.
//! Sampling is cached: at most one `/proc` read per
//! `CHECK_INTERVAL_MS`.

use std::sync::{
    OnceLock,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum interval between `/proc/self/statm` reads.
const CHECK_INTERVAL_MS: u64 = 1000;

/// Assumed page size for converting `/proc/self/statm` pages to bytes.
///
/// 4 `KiB` on all supported Linux architectures (`x86_64`, `aarch64`).
#[cfg(target_os = "linux")]
const PAGE_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// Process-wide singleton
// ---------------------------------------------------------------------------

/// Global memory pressure monitor, initialized once at startup.
static INSTANCE: OnceLock<MemoryPressure> = OnceLock::new();

/// Initialize the global memory pressure monitor.
///
/// Called once during server startup. Subsequent calls are no-ops.
///
/// ```
/// praxis_core::memory::init(1_073_741_824); // 1 GiB threshold
/// ```
pub fn init(threshold: usize) {
    INSTANCE.get_or_init(|| MemoryPressure::new(threshold));
}

/// Check whether current RSS exceeds the configured threshold.
///
/// Returns `false` when no monitor has been initialized (memory
/// pressure monitoring is disabled).
///
/// ```
/// // No init → never exceeded
/// assert!(!praxis_core::memory::is_exceeded());
/// ```
pub fn is_exceeded() -> bool {
    INSTANCE.get().is_some_and(MemoryPressure::is_exceeded)
}

// ---------------------------------------------------------------------------
// MemoryPressure
// ---------------------------------------------------------------------------

/// RSS-based memory pressure detector with cached sampling.
///
/// Reads `/proc/self/statm` at most every `CHECK_INTERVAL_MS`
/// and compares RSS against a fixed threshold. All fields are
/// atomic for lock-free concurrent access from multiple worker
/// threads.
///
/// ```
/// use praxis_core::memory::MemoryPressure;
///
/// let mp = MemoryPressure::new(1_073_741_824); // 1 GiB
/// // First check triggers a /proc read (on Linux).
/// let _ = mp.is_exceeded();
/// ```
pub struct MemoryPressure {
    /// RSS byte count from the most recent `/proc` read.
    cached_rss: AtomicUsize,
    /// Epoch milliseconds of the most recent sample.
    last_check_ms: AtomicU64,
    /// Maximum RSS in bytes before shedding load.
    threshold: usize,
}

impl MemoryPressure {
    /// Create a monitor with the given byte threshold.
    ///
    /// ```
    /// use praxis_core::memory::MemoryPressure;
    ///
    /// let mp = MemoryPressure::new(512 * 1024 * 1024); // 512 MiB
    /// assert!(!mp.is_exceeded());
    /// ```
    pub fn new(threshold: usize) -> Self {
        Self {
            cached_rss: AtomicUsize::new(0),
            last_check_ms: AtomicU64::new(0),
            threshold,
        }
    }

    /// Whether the most-recent RSS sample exceeds the threshold.
    ///
    /// Lazily samples `/proc/self/statm` when the cached value
    /// is older than `CHECK_INTERVAL_MS`.
    pub fn is_exceeded(&self) -> bool {
        self.maybe_refresh();
        self.cached_rss.load(Ordering::Relaxed) > self.threshold
    }

    /// Refresh the cached RSS if stale.
    fn maybe_refresh(&self) {
        let now = epoch_ms();
        let last = self.last_check_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) < CHECK_INTERVAL_MS {
            return;
        }
        if self
            .last_check_ms
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        if let Some(rss) = sample_rss() {
            self.cached_rss.store(rss, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// Platform Helpers
// ---------------------------------------------------------------------------

/// Current epoch time in milliseconds.
fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Read current RSS from `/proc/self/statm`.
///
/// Returns `None` on non-Linux or on parse failure.
#[cfg(target_os = "linux")]
fn sample_rss() -> Option<usize> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let rss_pages: usize = statm.split_whitespace().nth(1)?.parse().ok()?;
    rss_pages.checked_mul(PAGE_SIZE)
}

/// No-op on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn sample_rss() -> Option<usize> {
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn new_monitor_starts_at_zero_rss() {
        let mp = MemoryPressure::new(1024);
        assert_eq!(
            mp.cached_rss.load(Ordering::Relaxed),
            0,
            "initial cached RSS should be zero"
        );
    }

    #[test]
    fn very_large_threshold_never_exceeded() {
        let mp = MemoryPressure::new(usize::MAX);
        assert!(!mp.is_exceeded(), "usize::MAX threshold should never be exceeded");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sample_rss_returns_positive_value() {
        let rss = sample_rss();
        assert!(rss.is_some_and(|v| v > 0), "RSS should be a positive value on Linux");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tiny_threshold_is_exceeded() {
        let mp = MemoryPressure::new(1);
        assert!(mp.is_exceeded(), "1-byte threshold should always be exceeded");
    }

    #[test]
    fn is_exceeded_without_init_returns_false() {
        assert!(
            !is_exceeded(),
            "global is_exceeded should return false when uninitialized"
        );
    }

    #[test]
    fn epoch_ms_returns_nonzero() {
        assert!(epoch_ms() > 0, "epoch_ms should return a positive value");
    }
}
