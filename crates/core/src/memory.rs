// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Process-wide memory pressure monitoring.
//!
//! Tracks resident set size (RSS) via `/proc/self/status` on
//! Linux and sheds load when a configured threshold is exceeded.
//! The global monitor is sampled by a background task; the
//! per-request check reads only the cached sample.

use std::sync::{
    OnceLock,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Minimum interval between `/proc/self/status` reads.
const CHECK_INTERVAL_MS: u64 = 1000; // 1 s

/// How often a background task should call [`refresh`].
pub const SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(CHECK_INTERVAL_MS);

/// Sample age after which [`is_exceeded`] samples on the calling thread,
/// in case no background task is refreshing it.
const FALLBACK_STALE_MS: u64 = 3000; // 3 s, three sample intervals

// -----------------------------------------------------------------------------
// Process-wide singleton
// -----------------------------------------------------------------------------

/// Global memory pressure monitor, initialized once at startup.
static INSTANCE: OnceLock<MemoryPressure> = OnceLock::new();

/// Initialize the global memory pressure monitor and take a first sample.
///
/// Called once during server startup. Subsequent calls are no-ops. The
/// caller should keep the sample current by calling [`refresh`] every
/// [`SAMPLE_INTERVAL`] from a background task, so [`is_exceeded`] does not
/// read `/proc` on the request path.
///
/// ```
/// praxis_core::memory::init(1_073_741_824); // 1 GiB threshold
/// praxis_core::memory::refresh();
/// ```
pub fn init(threshold: usize) {
    INSTANCE.get_or_init(|| MemoryPressure::new(threshold)).refresh();
}

/// Sample RSS now for the global monitor. A no-op before [`init`].
pub fn refresh() {
    if let Some(monitor) = INSTANCE.get() {
        monitor.refresh();
    }
}

/// Whether the latest RSS sample exceeds the configured threshold.
///
/// Reads the cached sample, and samples on the calling thread only if no
/// [`refresh`] has run for a few intervals. Returns `false` when no monitor
/// has been initialized (memory pressure monitoring is disabled).
///
/// ```
/// // No init → never exceeded
/// assert!(!praxis_core::memory::is_exceeded());
/// ```
pub fn is_exceeded() -> bool {
    INSTANCE.get().is_some_and(|monitor| {
        monitor.refresh_if_older_than(FALLBACK_STALE_MS);
        monitor.exceeds_last_sample()
    })
}

// -----------------------------------------------------------------------------
// MemoryPressure
// -----------------------------------------------------------------------------

/// RSS-based memory pressure detector with cached sampling.
///
/// Reads `/proc/self/status` at most every `CHECK_INTERVAL_MS`
/// and compares RSS against a fixed threshold.
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
    /// Lazily samples `/proc/self/status` when the cached value
    /// is older than `CHECK_INTERVAL_MS`.
    pub fn is_exceeded(&self) -> bool {
        self.maybe_refresh();
        self.exceeds_last_sample()
    }

    /// Whether the cached RSS sample exceeds the threshold, without sampling.
    fn exceeds_last_sample(&self) -> bool {
        self.cached_rss.load(Ordering::Relaxed) > self.threshold
    }

    /// Sample RSS now, regardless of the cached sample's age.
    fn refresh(&self) {
        self.last_check_ms.store(epoch_ms(), Ordering::Relaxed);
        if let Some(rss) = sample_rss() {
            self.cached_rss.store(rss, Ordering::Relaxed);
        }
    }

    /// Refresh the cached RSS if stale.
    fn maybe_refresh(&self) {
        self.refresh_if_older_than(CHECK_INTERVAL_MS);
    }

    /// Refresh the cached RSS if it is at least `max_age_ms` old.
    fn refresh_if_older_than(&self, max_age_ms: u64) {
        let now = epoch_ms();
        let last = self.last_check_ms.load(Ordering::Relaxed);
        if !is_sample_stale(last, now, max_age_ms) {
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

// -----------------------------------------------------------------------------
// Platform Utilities
// -----------------------------------------------------------------------------

/// Whether a cached RSS sample taken at `last_ms` is stale relative to
/// `now_ms` and must be refreshed.
///
/// True once `max_age_ms` has elapsed, and also when the clock moved
/// backward (`now_ms < last_ms`). The interval is measured on the wall clock
/// (`epoch_ms`), so an NTP correction, manual clock set, or VM restore that
/// steps time backward would otherwise freeze RSS sampling (and the
/// load-shedding verdict) until the clock climbed back past
/// `last_ms + max_age_ms`.
fn is_sample_stale(last_ms: u64, now_ms: u64, max_age_ms: u64) -> bool {
    now_ms < last_ms || now_ms.saturating_sub(last_ms) >= max_age_ms
}

/// Current epoch time in milliseconds.
fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|dur| u64::try_from(dur.as_millis()).ok())
        .unwrap_or(0)
}

/// Read current RSS from the `VmRSS` line in `/proc/self/status`.
///
/// Uses `VmRSS` (reported in kB) instead of `/proc/self/statm`
/// (reported in pages) to avoid dependence on the kernel page
/// size, which varies across architectures (4 `KiB` on `x86_64`,
/// 4/16/64 `KiB` on `aarch64` depending on kernel config).
///
/// Returns `None` on non-Linux or on parse failure.
#[cfg(target_os = "linux")]
fn sample_rss() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: usize = rest.trim().strip_suffix("kB")?.trim().parse().ok()?;
            return kb.checked_mul(1024);
        }
    }
    None
}

/// No-op on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn sample_rss() -> Option<usize> {
    None
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
        assert!(
            rss.is_some_and(|bytes| bytes > 0),
            "RSS should be a positive value on Linux"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tiny_threshold_is_exceeded() {
        let mp = MemoryPressure::new(1);
        assert!(mp.is_exceeded(), "1-byte threshold should always be exceeded");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_cached_check_reads_only_the_last_sample() {
        let mp = MemoryPressure::new(1);
        assert!(
            !mp.exceeds_last_sample(),
            "before any sample the cached RSS is zero, so the request-path check must not read /proc"
        );
        mp.refresh();
        assert!(
            mp.exceeds_last_sample(),
            "after a refresh the cached RSS is above a 1-byte threshold"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_stale_sample_heals_without_a_background_refresh() {
        let mp = MemoryPressure::new(1);
        mp.refresh_if_older_than(FALLBACK_STALE_MS);
        assert!(
            mp.exceeds_last_sample(),
            "a never-sampled monitor is stale, so the fallback must sample it"
        );
    }

    #[test]
    fn is_exceeded_without_init_returns_false() {
        assert!(
            !is_exceeded(),
            "global is_exceeded should return false when uninitialized"
        );
    }

    #[test]
    fn sample_staleness_handles_forward_and_backward_clock() {
        assert!(
            !is_sample_stale(1_000, 1_000 + CHECK_INTERVAL_MS - 1, CHECK_INTERVAL_MS),
            "fresh within the interval is not stale"
        );
        assert!(
            is_sample_stale(1_000, 1_000 + CHECK_INTERVAL_MS, CHECK_INTERVAL_MS),
            "elapsed interval is stale"
        );
        assert!(
            is_sample_stale(1_000, 500, CHECK_INTERVAL_MS),
            "backward clock step is stale, so sampling resumes instead of freezing"
        );
    }

    #[test]
    fn epoch_ms_returns_nonzero() {
        assert!(epoch_ms() > 0, "epoch_ms should return a positive value");
    }
}
