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
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

mod accounting;

use accounting::Accounting;

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
    /// Descriptors open at the most recent sample. Admissions must load
    /// `connected` with Acquire before reading this Relaxed value: the sampler
    /// publishes a new count through its Release update to `connected`.
    cached_open: AtomicU64,

    /// New upstream connections opened since the most recent sample. Runtime
    /// updates must remain read-modify-write operations so they extend the
    /// sampler's release sequence for `cached_open`.
    connected: AtomicU64,

    /// Whether counting is cheap enough for admissions to re-sample.
    eager: bool,

    /// Milliseconds since [`clock_base`] at the most recent sample.
    last_check_ms: AtomicU64,

    /// Soft `RLIMIT_NOFILE`.
    limit: u64,

    /// Admitted requests still waiting on their upstream connection. Mutated
    /// only through read-modify-write ops at runtime (never a plain `store`) so
    /// its release sequence stays unbroken and the acquire reads in
    /// [`Accounting::predicted_with`] keep pairing with the release in
    /// [`Accounting::settle`].
    pending: AtomicU64,

    /// Whether a sample is being taken, so samples never overlap.
    sampling: AtomicBool,

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
            sampling: AtomicBool::new(false),
            shed,
            threshold,
        }
    }

    /// Sample descriptor usage now, regardless of the cached sample's age,
    /// unless a sample is already being taken.
    pub fn refresh(&self) {
        self.last_check_ms.store(elapsed_ms(), Ordering::Relaxed);
        self.store_sample();
    }

    /// Open descriptor count at which requests are shed: the limit less a
    /// reserve of 5% or 64 descriptors, whichever is larger.
    pub const fn threshold(&self) -> u64 {
        self.threshold
    }

    /// Admit one new request, or return `None` when admitting it would push
    /// the predicted usage past the threshold.
    pub fn try_admit(&self) -> Option<Admission<'_>> {
        if !self.shed {
            return Some(Admission::untracked());
        }
        self.refresh_if_older_than(if self.eager {
            EAGER_MAX_AGE_MS
        } else {
            FALLBACK_STALE_MS
        });
        if !self.accounting().try_admit(self.threshold) {
            return None;
        }
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

    /// Borrow the atomic counters used for admission and settlement.
    fn accounting(&self) -> Accounting<'_, AtomicU64> {
        Accounting::new(&self.cached_open, &self.connected, &self.pending)
    }

    /// Release one pending claim, counting its connection when it opened one.
    fn settle(&self, new_socket: bool) {
        self.accounting().settle(new_socket);
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

    /// Count open descriptors into the cache.
    fn store_sample(&self) {
        self.store_sample_with(count_open_fds);
    }

    /// Publish the result of `count` as the new sample and drop only the
    /// connection charges recorded before it began. A connection that opens
    /// while `count` runs may be missing from it, so its charge stays until
    /// the next sample. Skipped while another sample is being taken.
    fn store_sample_with<C: FnOnce() -> Option<u64>>(&self, count: C) {
        if self.sampling.swap(true, Ordering::Acquire) {
            return;
        }
        self.accounting().sample_with(count);
        self.sampling.store(false, Ordering::Release);
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
        pressure.store_sample_with(|| Some(100));
        assert_eq!(
            pressure.connected.load(Ordering::Relaxed),
            0,
            "a sample absorbs the connections opened before it"
        );
    }

    #[test]
    fn a_connection_opened_mid_count_keeps_its_charge() {
        let pressure = unsampled(1_048_576);
        pressure.connected.store(4, Ordering::Relaxed);
        pressure.store_sample_with(|| {
            pressure.connected.fetch_add(CONNECT_COST, Ordering::Relaxed);
            Some(100)
        });
        assert_eq!(pressure.usage().open, 100, "the new count is published");
        assert_eq!(
            pressure.predicted(),
            102,
            "a connection that opens during the count may be missing from it, so its charge must survive"
        );
    }

    #[test]
    fn samples_never_overlap() {
        let pressure = unsampled(1_048_576);
        pressure.connected.store(4, Ordering::Relaxed);
        let nested_counted = AtomicBool::new(false);
        pressure.store_sample_with(|| {
            pressure.store_sample_with(|| {
                nested_counted.store(true, Ordering::Relaxed);
                Some(1)
            });
            Some(100)
        });
        assert!(
            !nested_counted.load(Ordering::Relaxed),
            "a sample must not start while another is counting"
        );
        assert_eq!(
            pressure.predicted(),
            100,
            "the one sample drops exactly the charges it absorbed"
        );
        assert!(
            !pressure.sampling.load(Ordering::Relaxed),
            "the sampling flag is released afterwards"
        );
    }

    #[test]
    fn dropping_charges_saturates_instead_of_wrapping() {
        let pressure = unsampled(1_048_576);
        pressure.connected.store(4, Ordering::Relaxed);
        pressure.store_sample_with(|| {
            pressure.connected.store(1, Ordering::Relaxed);
            Some(100)
        });
        assert_eq!(
            pressure.connected.load(Ordering::Relaxed),
            0,
            "charges must bottom out at zero; a wrap would shed every request"
        );
    }

    #[test]
    fn concurrent_samples_and_connections_never_wrap_the_charges() {
        let pressure = FdPressure::new(u64::MAX, true);
        let start = std::sync::Barrier::new(8);
        let peak = AtomicU64::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    start.wait();
                    for _ in 0..5_000 {
                        pressure.store_sample_with(|| {
                            std::thread::yield_now();
                            Some(100)
                        });
                        pressure.settle_new_connection();
                        peak.fetch_max(pressure.connected.load(Ordering::Relaxed), Ordering::Relaxed);
                    }
                });
            }
        });
        let peak = peak.load(Ordering::Relaxed);
        assert!(
            peak <= 8 * 5_000 * CONNECT_COST,
            "overlapping samples must never drive the charges below zero, even briefly: peaked at {peak}"
        );
        assert!(
            !pressure.sampling.load(Ordering::Relaxed),
            "the sampling flag is released once every sampler is done"
        );
    }

    #[test]
    fn concurrent_admissions_cannot_overrun_a_single_slot() {
        // Room for exactly one claim: 190 open plus the 2 a pending request
        // costs reaches the 192 threshold, so a second admission would push
        // past it.
        let pressure = unsampled(256);
        pressure.last_check_ms.store(u64::MAX, Ordering::Relaxed);
        pressure.cached_open.store(190, Ordering::Relaxed);
        let start = std::sync::Barrier::new(16);
        let held: std::sync::Mutex<Vec<Admission<'_>>> = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..16 {
                scope.spawn(|| {
                    start.wait();
                    if let Some(admission) = pressure.try_admit() {
                        held.lock().unwrap().push(admission);
                    }
                });
            }
        });
        let held = held.into_inner().unwrap();
        assert_eq!(
            held.len(),
            1,
            "only one of 16 racing admissions may claim the single free slot"
        );
        assert_eq!(
            pressure.predicted(),
            192,
            "the one admitted claim reaches the threshold exactly, with none over-admitted"
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the concurrent settle and admission loops share one budget and assertions"
    )]
    fn a_new_connection_never_frees_budget_during_the_transfer() {
        // A new-socket settle adds the connection charge before releasing the
        // pending claim. Concurrent readers must neither see freed budget nor
        // admit another request while the monitor is exactly at its threshold.
        const TRANSFERS: u64 = 200_000;
        let pressure = unsampled(u64::MAX);
        pressure.last_check_ms.store(u64::MAX, Ordering::Relaxed);
        let floor = pressure.threshold();
        pressure
            .cached_open
            .store(floor - TRANSFERS * PENDING_COST, Ordering::Relaxed);
        pressure.pending.store(TRANSFERS, Ordering::Relaxed);
        assert_eq!(pressure.predicted(), floor, "the pre-loaded claims fill the budget");
        let min_seen = AtomicU64::new(u64::MAX);
        let checks = AtomicU64::new(0);
        let unexpected_admissions = AtomicU64::new(0);
        let done = AtomicBool::new(false);
        let start = std::sync::Barrier::new(4);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                start.wait();
                for transfer in 0..TRANSFERS {
                    pressure.settle(true);
                    if transfer == TRANSFERS / 2 {
                        // Require a reader check before the remaining transfers.
                        let checked = checks.load(Ordering::Acquire);
                        while checks.load(Ordering::Acquire) == checked {
                            std::thread::yield_now();
                        }
                    }
                }
                done.store(true, Ordering::Relaxed);
            });
            for _ in 0..3 {
                scope.spawn(|| {
                    start.wait();
                    loop {
                        if let Some(admission) = pressure.try_admit() {
                            unexpected_admissions.fetch_add(1, Ordering::Relaxed);
                            drop(admission);
                        }
                        min_seen.fetch_min(pressure.predicted(), Ordering::Relaxed);
                        checks.fetch_add(1, Ordering::Release);
                        if done.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                });
            }
        });
        assert!(
            min_seen.load(Ordering::Relaxed) >= floor,
            "a claim transfer must never dip predicted usage below the threshold"
        );
        assert_eq!(
            unexpected_admissions.load(Ordering::Relaxed),
            0,
            "no racing admission may use a transiently freed claim"
        );
    }

    #[test]
    fn a_failed_count_keeps_every_charge() {
        let pressure = unsampled(1_048_576);
        pressure.cached_open.store(50, Ordering::Relaxed);
        pressure.connected.store(6, Ordering::Relaxed);
        pressure.store_sample_with(|| None);
        assert_eq!(pressure.predicted(), 56, "nothing is absorbed when the count fails");
        assert!(
            !pressure.sampling.load(Ordering::Relaxed),
            "the sampling flag is released after a failed count"
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
        let _counting = exclusive_descriptor_counting();
        let agreed = retry_until_quiet(|| {
            let before = count_from_size();
            let listed = count_from_listing();
            let after = count_from_size();
            before.is_none() || (before == after && listed == before)
        });
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
        let _counting = exclusive_descriptor_counting();
        let pressure = FdPressure::new(u64::MAX, true);
        let exact = retry_until_quiet(|| {
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
        });
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

    impl FdPressure {
        /// Predicted usage against the currently reserved claim count.
        ///
        /// Acquire on `pending` pairs with the release in [`FdPressure::settle`]:
        /// observing a settle's decremented claim also observes its connection
        /// charge, so the predicted usage never dips during the transfer.
        fn predicted(&self) -> u64 {
            self.accounting().predicted_with(self.pending.load(Ordering::Acquire))
        }

        /// Record one new upstream connection as an admission settling would.
        fn settle_new_connection(&self) {
            self.pending.fetch_add(1, Ordering::Relaxed);
            self.settle(true);
        }
    }

    /// Held by the tests that need an exact descriptor count, so they never
    /// overlap: each opens and closes descriptors while the other counts.
    static EXACT_COUNTING: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// How long an exact count keeps retrying for a moment when no other test
    /// in this binary opens or closes a descriptor.
    const QUIET_RETRY_BUDGET: Duration = Duration::from_secs(5);

    /// Take [`EXACT_COUNTING`] for as long as the guard lives.
    fn exclusive_descriptor_counting() -> std::sync::MutexGuard<'static, ()> {
        EXACT_COUNTING.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Run `attempt` until it succeeds or [`QUIET_RETRY_BUDGET`] passes.
    ///
    /// Other tests in this binary open and close descriptors in bursts that
    /// can outlast thousands of attempts, so the budget is time rather than a
    /// count: back-to-back retries would all land inside one burst.
    fn retry_until_quiet<F: FnMut() -> bool>(mut attempt: F) -> bool {
        let started = Instant::now();
        loop {
            if attempt() {
                return true;
            }
            if started.elapsed() >= QUIET_RETRY_BUDGET {
                return false;
            }
            std::thread::yield_now();
        }
    }

    /// A shedding monitor that never samples, so tests drive the cached count.
    fn unsampled(limit: u64) -> FdPressure {
        FdPressure {
            eager: false,
            last_check_ms: AtomicU64::new(elapsed_ms()),
            ..FdPressure::new(limit, true)
        }
    }
}
