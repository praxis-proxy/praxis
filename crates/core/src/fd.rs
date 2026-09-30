// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Process-wide file descriptor pressure monitoring.
//!
//! Every connection, pooled connection, and DNS lookup holds a descriptor.
//! Running out fails them all at once with `EMFILE`, so the proxy sheds new
//! requests with 503 while a small reserve of descriptors is still free,
//! keeping room for its own listeners, health probes, logs, and DNS.
//!
//! Where the kernel counts open descriptors in constant time (Linux 6.2 and
//! later), admissions re-read the count whenever it is over a millisecond
//! old. Elsewhere a background task samples it. On top of the last sample
//! the monitor adds what admitted requests are about to open (two
//! descriptors for each request still waiting on its upstream: that
//! connection and one callout) and two for every upstream connection opened
//! since (it and the client connection it serves), so a burst cannot race
//! past the limit between samples.

use std::{
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Background sampling interval where counting is constant time, which only
/// keeps the gauges current since admissions re-sample themselves.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(250);

/// Sample age after which an admission re-reads a constant-time count.
const EAGER_MAX_AGE_MS: u64 = 1;

/// Background sampling interval where counting lists `/proc/self/fd` and
/// fewer than [`CHEAP_LISTING_BELOW`] descriptors are open, so a burst is
/// caught sooner without re-sampling on the request path.
const LISTING_SAMPLE_INTERVAL: Duration = Duration::from_millis(50);

/// Open descriptor count below which listing `/proc/self/fd` is cheap enough
/// to sample at [`LISTING_SAMPLE_INTERVAL`].
const CHEAP_LISTING_BELOW: u64 = 4_096;

/// Sample age after which [`try_admit`] samples on the calling thread, in
/// case no background task is refreshing it.
const FALLBACK_STALE_MS: u64 = 1_000; // 1 s

/// Fewest descriptors held in reserve below the limit before shedding.
const MIN_RESERVE: u64 = 64;

/// Divisor of the limit that sizes the reserve on large limits (5%).
const RESERVE_DIVISOR: u64 = 20;

/// Descriptors an admitted request still waiting on its upstream is
/// assumed to open: that connection and one callout.
const PENDING_COST: u64 = 2;

/// Descriptors a new upstream connection is assumed to add until the next
/// sample: itself and the client connection it serves.
const CONNECT_COST: u64 = 2;

// -----------------------------------------------------------------------------
// Process-wide singleton
// -----------------------------------------------------------------------------

/// Global descriptor pressure monitor, initialized once at startup.
static INSTANCE: OnceLock<FdPressure> = OnceLock::new();

/// Initialize the global monitor for a process `limit` (the soft
/// `RLIMIT_NOFILE`) and take a first sample. `shed` controls whether
/// [`try_admit`] ever sheds; usage is tracked either way.
///
/// Called once during server startup. Subsequent calls are no-ops, and so
/// is this call on platforms where open descriptors cannot be counted.
///
/// ```
/// praxis_core::fd::init(1_024, true);
/// if let Some(usage) = praxis_core::fd::usage() {
///     assert_eq!(usage.limit, 1_024);
///     assert!(usage.open > 0);
/// }
/// ```
pub fn init(limit: u64, shed: bool) {
    if count_open_fds().is_some() {
        INSTANCE.get_or_init(|| FdPressure::new(limit, shed)).refresh();
    }
}

/// Sample descriptor usage now for the global monitor. A no-op before
/// [`init`].
pub fn refresh() {
    if let Some(monitor) = INSTANCE.get() {
        monitor.refresh();
    }
}

/// Admit one new request or TCP connection, or return `None` when it must
/// be shed because descriptors are nearly exhausted.
///
/// Hold the returned [`Admission`] for the life of the request, and call
/// [`Admission::connected`] once its upstream connection is established.
/// Always admits when no monitor has been initialized or shedding is
/// disabled.
///
/// ```
/// // No init → always admitted
/// let mut admission = praxis_core::fd::try_admit().expect("admitted");
/// admission.connected(true);
/// ```
pub fn try_admit() -> Option<Admission<'static>> {
    INSTANCE
        .get()
        .map_or(Some(Admission::untracked()), FdPressure::try_admit)
}

/// How long a background task should wait before the next [`refresh`].
///
/// ```
/// assert!(praxis_core::fd::sample_interval() <= std::time::Duration::from_millis(250));
/// ```
pub fn sample_interval() -> Duration {
    INSTANCE.get().map_or(SAMPLE_INTERVAL, FdPressure::sample_interval)
}

/// Latest descriptor usage, or `None` before [`init`] or where descriptors
/// are not counted.
pub fn usage() -> Option<FdUsage> {
    INSTANCE.get().map(FdPressure::usage)
}

// -----------------------------------------------------------------------------
// Admission
// -----------------------------------------------------------------------------

/// An admitted request's claim on descriptors it has yet to open, released
/// once its upstream connects or it is dropped.
#[derive(Debug)]
#[must_use = "dropping the admission releases its claim immediately"]
pub struct Admission<'mon> {
    /// Monitor holding the claim, or `None` once settled or when untracked.
    monitor: Option<&'mon FdPressure>,
}

impl Admission<'_> {
    /// Record that the upstream connection is established: `new_socket` when
    /// it opened a descriptor rather than reusing a pooled connection. Later
    /// calls do nothing.
    pub fn connected(&mut self, new_socket: bool) {
        if let Some(monitor) = self.monitor.take() {
            monitor.settle(new_socket);
        }
    }

    /// An admission with no claim anywhere.
    const fn untracked() -> Self {
        Self { monitor: None }
    }
}

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        if let Some(monitor) = self.monitor.take() {
            monitor.settle(false);
        }
    }
}

// -----------------------------------------------------------------------------
// FdUsage
// -----------------------------------------------------------------------------

/// A descriptor usage sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FdUsage {
    /// Soft `RLIMIT_NOFILE` the process runs with.
    pub limit: u64,

    /// Descriptors open at the last sample.
    pub open: u64,
}

// -----------------------------------------------------------------------------
// FdPressure
// -----------------------------------------------------------------------------

/// Descriptor pressure detector with cached sampling and admission
/// accounting.
///
/// ```
/// use praxis_core::fd::FdPressure;
///
/// let pressure = FdPressure::new(1_048_576, true);
/// pressure.refresh();
/// let admission = pressure.try_admit();
/// assert!(admission.is_some());
/// assert_eq!(pressure.threshold(), 996_148);
/// ```
#[derive(Debug)]
pub struct FdPressure {
    /// Descriptors open at the most recent sample.
    cached_open: AtomicU64,

    /// New upstream connections opened since the most recent sample.
    connected: AtomicU64,

    /// Whether counting is cheap enough for admissions to re-sample.
    eager: bool,

    /// Milliseconds since [`clock_base`] at the most recent sample.
    last_check_ms: AtomicU64,

    /// Soft `RLIMIT_NOFILE`.
    limit: u64,

    /// Admitted requests still waiting on their upstream connection.
    pending: AtomicU64,

    /// Whether requests are ever shed.
    shed: bool,

    /// Predicted usage at which requests are shed.
    threshold: u64,
}

impl FdPressure {
    /// Create a monitor for a process `limit`; `shed` enables shedding.
    pub fn new(limit: u64, shed: bool) -> Self {
        let threshold = shed_threshold(limit);
        Self {
            cached_open: AtomicU64::new(0),
            connected: AtomicU64::new(0),
            eager: count_from_size().is_some(),
            last_check_ms: AtomicU64::new(0),
            limit,
            pending: AtomicU64::new(0),
            shed,
            threshold,
        }
    }

    /// Sample descriptor usage now, regardless of the cached sample's age.
    pub fn refresh(&self) {
        self.last_check_ms.store(elapsed_ms(), Ordering::Relaxed);
        self.store_sample();
    }

    /// Open descriptor count at which requests are shed: the limit less a
    /// reserve of 5% or 64 descriptors, whichever is larger.
    pub const fn threshold(&self) -> u64 {
        self.threshold
    }

    /// Admit one new request, or return `None` when the predicted usage has
    /// reached the threshold.
    pub fn try_admit(&self) -> Option<Admission<'_>> {
        if !self.shed {
            return Some(Admission::untracked());
        }
        self.refresh_if_older_than(if self.eager {
            EAGER_MAX_AGE_MS
        } else {
            FALLBACK_STALE_MS
        });
        if self.predicted() >= self.threshold {
            return None;
        }
        self.pending.fetch_add(1, Ordering::Relaxed);
        Some(Admission { monitor: Some(self) })
    }

    /// How long to wait before the next background sample: shorter where
    /// counting lists entries and few are open.
    pub fn sample_interval(&self) -> Duration {
        if !self.eager && self.cached_open.load(Ordering::Relaxed) < CHEAP_LISTING_BELOW {
            LISTING_SAMPLE_INTERVAL
        } else {
            SAMPLE_INTERVAL
        }
    }

    /// The cached usage sample.
    pub fn usage(&self) -> FdUsage {
        FdUsage {
            limit: self.limit,
            open: self.cached_open.load(Ordering::Relaxed),
        }
    }

    /// The last sample, plus [`PENDING_COST`] for each admitted request
    /// still waiting on its upstream, plus [`CONNECT_COST`] for each upstream
    /// connection opened since the sample.
    fn predicted(&self) -> u64 {
        self.pending
            .load(Ordering::Relaxed)
            .saturating_mul(PENDING_COST)
            .saturating_add(self.connected.load(Ordering::Relaxed))
            .saturating_add(self.cached_open.load(Ordering::Relaxed))
    }

    /// Release one pending claim, counting its connection when it opened one.
    fn settle(&self, new_socket: bool) {
        self.pending.fetch_sub(1, Ordering::Relaxed);
        if new_socket {
            self.connected.fetch_add(CONNECT_COST, Ordering::Relaxed);
        }
    }

    /// Refresh the cached sample if it is at least `max_age_ms` old. Only one
    /// concurrent caller samples; the rest keep the cached value.
    fn refresh_if_older_than(&self, max_age_ms: u64) {
        let now = elapsed_ms();
        let last = self.last_check_ms.load(Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) < max_age_ms {
            return;
        }
        if self
            .last_check_ms
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.store_sample();
        }
    }

    /// Count open descriptors into the cache; connections opened before the
    /// count are now part of it.
    fn store_sample(&self) {
        if let Some(open) = count_open_fds() {
            self.connected.store(0, Ordering::Relaxed);
            self.cached_open.store(open, Ordering::Relaxed);
        }
    }
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Open descriptor count at which a process with `limit` sheds load.
fn shed_threshold(limit: u64) -> u64 {
    let reserve = (limit / RESERVE_DIVISOR).max(MIN_RESERVE);
    limit.saturating_sub(reserve)
}

/// Monotonic origin for sample ages, so a wall-clock step cannot freeze
/// sampling.
fn clock_base() -> Instant {
    static BASE: OnceLock<Instant> = OnceLock::new();
    *BASE.get_or_init(Instant::now)
}

/// Milliseconds since [`clock_base`], never zero so zero can mean "never
/// sampled".
fn elapsed_ms() -> u64 {
    u64::try_from(clock_base().elapsed().as_millis())
        .unwrap_or(u64::MAX)
        .max(1)
}

/// Number of descriptors this process holds open.
///
/// Linux 6.2 and later report the count as the size of `/proc/self/fd`, an
/// O(1) read even with hundreds of thousands open. Older kernels report zero,
/// so the entries are counted instead, less the one the listing itself holds
/// open.
#[cfg(target_os = "linux")]
fn count_open_fds() -> Option<u64> {
    count_from_size().or_else(count_from_listing)
}

/// Open descriptor count from the size of `/proc/self/fd`, or `None` on
/// kernels before 6.2, which report zero.
#[cfg(target_os = "linux")]
fn count_from_size() -> Option<u64> {
    std::fs::metadata("/proc/self/fd")
        .ok()
        .map(|meta| meta.len())
        .filter(|&size| size > 0)
}

/// Open descriptor count from listing `/proc/self/fd`, excluding the handle
/// the listing itself holds open.
#[cfg(target_os = "linux")]
fn count_from_listing() -> Option<u64> {
    let listed = std::fs::read_dir("/proc/self/fd").ok()?.count();
    u64::try_from(listed).ok().map(|count| count.saturating_sub(1))
}

/// Not tracked off Linux.
#[cfg(not(target_os = "linux"))]
fn count_open_fds() -> Option<u64> {
    None
}

/// Not tracked off Linux.
#[cfg(not(target_os = "linux"))]
fn count_from_size() -> Option<u64> {
    None
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn threshold_keeps_at_least_64_in_reserve() {
        assert_eq!(shed_threshold(1_024), 960, "5% of 1024 is below 64, so 64 are reserved");
        assert_eq!(shed_threshold(256), 192, "small limits reserve 64");
        assert_eq!(shed_threshold(128), 64, "the smallest allowed limit keeps half");
    }

    #[test]
    fn threshold_reserves_five_percent_of_large_limits() {
        assert_eq!(shed_threshold(1_048_576), 996_148, "5% of 1 Mi reserved");
        assert_eq!(shed_threshold(65_536), 62_260, "5% of 64 Ki reserved");
        assert_eq!(shed_threshold(1_280), 1_216, "5% and 64 meet at 1280");
    }

    #[test]
    fn threshold_saturates_below_the_reserve() {
        assert_eq!(shed_threshold(10), 0, "a limit below the reserve sheds from zero");
        assert_eq!(shed_threshold(0), 0, "a zero limit must not underflow");
    }

    #[test]
    fn new_monitor_starts_empty() {
        let pressure = FdPressure::new(1_024, true);
        assert_eq!(
            pressure.usage(),
            FdUsage { limit: 1_024, open: 0 },
            "nothing sampled yet"
        );
        assert_eq!(pressure.predicted(), 0, "nothing admitted yet");
    }

    #[test]
    fn admits_below_the_threshold_and_sheds_at_it() {
        let pressure = unsampled(1_024);
        pressure.cached_open.store(958, Ordering::Relaxed);
        let first = pressure.try_admit();
        assert!(
            first.is_some(),
            "958 open with nothing pending is below the 960 threshold"
        );
        assert!(
            pressure.try_admit().is_none(),
            "958 + 2 for the pending request reaches the threshold"
        );
        assert_eq!(pressure.predicted(), 960, "the shed request claims nothing");
    }

    #[test]
    fn a_burst_is_shed_before_the_next_sample() {
        let pressure = unsampled(256);
        pressure.cached_open.store(34, Ordering::Relaxed);
        let admitted: Vec<Admission<'_>> = std::iter::repeat_with(|| pressure.try_admit())
            .take(150)
            .flatten()
            .collect();
        assert_eq!(
            admitted.len(),
            79,
            "(192 threshold - 34 open) / 2 descriptors per pending request admits 79 of 150"
        );
    }

    #[test]
    fn pending_claims_survive_a_sample() {
        let pressure = unsampled(1_048_576);
        let held: Vec<Admission<'_>> = std::iter::repeat_with(|| pressure.try_admit())
            .take(5)
            .flatten()
            .collect();
        pressure.store_sample();
        assert_eq!(
            pressure.predicted(),
            pressure.usage().open + 10,
            "requests still connecting are not yet in the sample, so their claims stay"
        );
        drop(held);
        assert_eq!(
            pressure.predicted(),
            pressure.usage().open,
            "dropping releases every claim"
        );
    }

    #[test]
    fn a_new_connection_counts_until_the_next_sample() {
        let pressure = unsampled(1_048_576);
        pressure.cached_open.store(100, Ordering::Relaxed);
        let mut admission = pressure.try_admit().expect("admitted");
        assert_eq!(pressure.predicted(), 102, "pending: the connection and one callout");
        admission.connected(true);
        assert_eq!(
            pressure.predicted(),
            102,
            "the new connection and its client are real but not yet sampled"
        );
        admission.connected(true);
        drop(admission);
        assert_eq!(pressure.predicted(), 102, "an admission settles only once");
        pressure.store_sample();
        assert_eq!(
            pressure.connected.load(Ordering::Relaxed),
            0,
            "a sample absorbs the connections opened before it"
        );
    }

    #[test]
    fn a_reused_connection_releases_the_claim() {
        let pressure = unsampled(1_048_576);
        pressure.cached_open.store(100, Ordering::Relaxed);
        let mut admission = pressure.try_admit().expect("admitted");
        admission.connected(false);
        assert_eq!(pressure.predicted(), 100, "a pooled connection opens no descriptor");
    }

    #[test]
    fn disabled_shedding_always_admits() {
        let pressure = FdPressure::new(128, false);
        pressure.cached_open.store(128, Ordering::Relaxed);
        let admission = pressure.try_admit();
        assert!(admission.is_some(), "shed_on_fd_pressure: false must never shed");
        assert_eq!(pressure.usage().open, 128, "usage is still tracked for metrics");
        assert_eq!(
            pressure.pending.load(Ordering::Relaxed),
            0,
            "nothing to account when not shedding"
        );
    }

    #[test]
    fn listing_samples_faster_while_cheap() {
        let pressure = unsampled(65_536);
        pressure.cached_open.store(4_095, Ordering::Relaxed);
        assert_eq!(
            pressure.sample_interval(),
            LISTING_SAMPLE_INTERVAL,
            "listing fewer than 4096 entries is cheap enough for 50 ms sampling"
        );
        pressure.cached_open.store(4_096, Ordering::Relaxed);
        assert_eq!(
            pressure.sample_interval(),
            SAMPLE_INTERVAL,
            "large listings fall back to 250 ms sampling"
        );
    }

    #[test]
    fn constant_time_counting_samples_at_the_base_interval() {
        let pressure = FdPressure {
            eager: true,
            ..unsampled(1_024)
        };
        assert_eq!(
            pressure.sample_interval(),
            SAMPLE_INTERVAL,
            "admissions re-sample near the threshold, so the background can stay slow"
        );
    }

    #[test]
    fn try_admit_without_init_admits() {
        assert!(
            try_admit().is_some(),
            "the global monitor must admit everything when uninitialized"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn size_and_listing_counts_agree() {
        let agreed = std::iter::repeat_with(|| {
            let before = count_from_size();
            let listed = count_from_listing();
            let after = count_from_size();
            before.is_none() || (before == after && listed == before)
        })
        .take(200)
        .any(|agree| agree);
        assert!(
            agreed,
            "with no concurrent opens, the size and the listing (less its own handle) must match"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn listing_count_is_positive() {
        assert!(
            count_from_listing().is_some_and(|open| open >= 3),
            "stdin, stdout, and stderr are always open under the test harness"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn opening_files_raises_the_sample() {
        let pressure = FdPressure::new(u64::MAX, true);
        let exact = std::iter::repeat_with(|| {
            pressure.refresh();
            let before = pressure.usage().open;
            let files: Vec<std::fs::File> = std::iter::repeat_with(|| tempfile::tempfile().unwrap())
                .take(32)
                .collect();
            pressure.refresh();
            let during = pressure.usage().open;
            drop(files);
            pressure.refresh();
            before == pressure.usage().open && during == before.saturating_add(32)
        })
        .take(1_000)
        .any(|exact| exact);
        assert!(
            exact,
            "in a window where no other test opens or closes a descriptor, 32 new files must add exactly 32"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_admission_re_samples_a_count_older_than_a_millisecond() {
        let pressure = FdPressure::new(1_024, true);
        if !pressure.eager {
            return;
        }
        pressure.cached_open.store(1_000, Ordering::Relaxed);
        let sampled_at = elapsed_ms();
        pressure.last_check_ms.store(sampled_at, Ordering::Relaxed);
        while elapsed_ms() <= sampled_at.saturating_add(EAGER_MAX_AGE_MS) {
            std::hint::spin_loop();
        }
        let admission = pressure.try_admit();
        assert!(
            admission.is_some(),
            "a stale 1000 must be re-read, finding this process far below the 960 threshold"
        );
        assert!(pressure.usage().open < 960, "the admission re-sampled the real count");
    }

    #[test]
    fn a_fresh_count_is_trusted_by_admissions() {
        let pressure = FdPressure::new(1_024, true);
        pressure.cached_open.store(960, Ordering::Relaxed);
        pressure.last_check_ms.store(u64::MAX, Ordering::Relaxed);
        assert!(
            pressure.try_admit().is_none(),
            "a count sampled within the millisecond is used as is"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_never_sampled_monitor_samples_on_admission() {
        let pressure = FdPressure::new(1, true);
        assert!(
            pressure.try_admit().is_none() || count_from_size().is_none(),
            "any running process holds more than a 1 descriptor limit allows"
        );
    }

    #[test]
    fn a_fresh_sample_is_not_resampled() {
        let pressure = FdPressure::new(1, true);
        pressure.last_check_ms.store(elapsed_ms(), Ordering::Relaxed);
        pressure.refresh_if_older_than(FALLBACK_STALE_MS);
        assert_eq!(
            pressure.usage().open,
            0,
            "a sample younger than the max age must be reused, not re-read"
        );
    }

    #[test]
    fn elapsed_ms_is_never_zero() {
        assert!(elapsed_ms() >= 1, "zero is reserved for never sampled");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A shedding monitor that never samples, so tests drive the cached count.
    fn unsampled(limit: u64) -> FdPressure {
        FdPressure {
            eager: false,
            last_check_ms: AtomicU64::new(elapsed_ms()),
            ..FdPressure::new(limit, true)
        }
    }
}
