// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Byte schedules with refundable, bounded write permits.
//!
//! Body hooks prepare charges without spending capacity. Writers reserve a
//! bounded prefix, wait for its absolute release time, then commit only bytes
//! accepted by the writer. Strongly shrinking transformations drain processed
//! input charges before their final output byte; cancellation refunds the
//! unadmitted remainder. Untouched plans never debit a budget.

use std::{
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use tokio::sync::watch;

/// One direction's shared byte budget.
pub(crate) struct Schedule {
    /// Monotonic origin used by release timestamps.
    epoch: Instant,
    /// Positive byte rate.
    rate: u64,
    /// Initial and refilling burst in nanoseconds.
    burst_ns: i128,
    /// Maximum bytes released in one write.
    quantum: u64,
    /// Short-held state lock, never retained while waiting or writing.
    inner: Mutex<ScheduleInner>,
    /// Wakes writers when in-flight allowance is settled.
    changed: watch::Sender<()>,
}

/// Planned debt and the independent record of bytes actually written.
struct ScheduleInner {
    /// Planned arrival time, including outstanding prefix reservations.
    tat: i128,
    /// Whether planned arrival time has been initialized.
    initialized: bool,
    /// Reservations that still have to be committed or refunded.
    outstanding: u64,
    /// Generation changes when idle refill supersedes the planned debt.
    generation: u64,
    /// Arrival time derived only from accepted writes.
    committed_tat: Option<i128>,
    /// Allowance pinned by admitted writes until their accepted bytes are known.
    claimed_ns: i128,
}

/// Prepared charge or owned reservation for one bounded prefix.
pub(crate) struct BandwidthGrant {
    /// Shared owner of this charge.
    pub(super) schedule: Arc<Schedule>,
    /// Bytes still represented by this charge.
    pub(super) bytes: u64,
    /// Nanoseconds charged by this reservation.
    cost_ns: i128,
    /// Absolute planned release timestamp relative to the schedule origin.
    tat_after: i128,
    /// Time the body hook prepared these bytes.
    created_at: i128,
    /// Generation against which the prefix was reserved.
    generation: u64,
    /// Whether this grant contributes to the planned-arrival ledger.
    reserved: bool,
    /// Original admitted cost, including any tail a partial write must release.
    claimed_ns: i128,
    /// Deterministic clock for model tests using `reserve_at`.
    synthetic_now: Option<i128>,
}

/// Why an owned prefix cannot be handed to its writer yet.
pub(super) enum Admission {
    /// Every applicable budget is ready.
    Ready,
    /// An absolute monotonic release time has not arrived.
    At(Instant, watch::Receiver<()>),
    /// All burst allowance is held by writes whose accepted bytes are unknown.
    Busy(watch::Receiver<()>),
    /// Another writer changed the largest prefix that can currently fit.
    Resize,
    /// The requested release timestamp cannot be represented.
    Overflow,
}

impl Schedule {
    /// Create an independent upload or download budget.
    pub(crate) fn new(rate: u64, burst_bytes: u64) -> Arc<Self> {
        let (changed, _receiver) = watch::channel(());
        // Amortize timer ticks with up to 10 ms of zero-burst traffic, while
        // bounding each pending write to one MiB and charging its full cost.
        let quantum = if burst_bytes == 0 {
            rate.div_ceil(100).clamp(1, 1_048_576)
        } else {
            burst_bytes.min(16_384)
        };
        Arc::new(Self {
            epoch: Instant::now(),
            rate,
            burst_ns: bytes_to_ns(burst_bytes, rate),
            quantum,
            inner: Mutex::new(ScheduleInner {
                tat: 0,
                initialized: false,
                outstanding: 0,
                generation: 0,
                committed_tat: None,
                claimed_ns: 0,
            }),
            changed,
        })
    }

    /// Prepare bytes without occupying capacity before a transport exists.
    pub(crate) fn prepare(self: &Arc<Self>, bytes: u64) -> BandwidthGrant {
        self.grant(bytes, self.now_ns(), None)
    }

    /// Reserve bytes immediately; production writers call this only for prefixes.
    #[cfg(test)]
    pub(crate) fn reserve(self: &Arc<Self>, bytes: u64) -> BandwidthGrant {
        let mut grant = self.prepare(bytes);
        grant.reserve();
        grant
    }

    /// Reserve with an explicit clock for deterministic accounting models.
    #[cfg(test)]
    pub(crate) fn reserve_at(self: &Arc<Self>, bytes: u64, now: i128) -> BandwidthGrant {
        let mut grant = self.grant(bytes, now, Some(now));
        grant.reserve();
        grant
    }

    /// Construct a non-debiting charge that retains its preparation timestamp.
    fn grant(self: &Arc<Self>, bytes: u64, now: i128, synthetic_now: Option<i128>) -> BandwidthGrant {
        BandwidthGrant {
            schedule: Arc::clone(self),
            bytes,
            cost_ns: bytes_to_ns(bytes, self.rate),
            tat_after: 0,
            created_at: now,
            generation: 0,
            reserved: false,
            claimed_ns: 0,
            synthetic_now,
        }
    }

    /// Whether a new full budget is equivalent to the remaining allowance.
    pub(crate) fn is_fresh(&self) -> bool {
        self.is_fresh_at(self.now_ns())
    }

    /// Check freshness using the supplied monotonic clock.
    pub(crate) fn is_fresh_at(&self, now: i128) -> bool {
        let inner = self.lock();
        inner.claimed_ns == 0
            && inner.outstanding == 0
            && (!inner.initialized || inner.tat <= now.saturating_sub(self.burst_ns))
    }

    /// Nanoseconds since this budget was created.
    fn now_ns(&self) -> i128 {
        i128::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(i128::MAX)
    }

    /// Lock accounting without retaining the guard across external operations.
    fn lock(&self) -> MutexGuard<'_, ScheduleInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl BandwidthGrant {
    /// Remaining wait computed at use time, including time spent resolving DNS.
    pub(crate) fn delay(&self) -> Duration {
        let now = self.now_ns();
        delay_between(now, self.release_ns(now))
    }

    /// Release available burst immediately, then use short refill-sized prefixes.
    pub(super) fn quantum(&self) -> u64 {
        let now = self.now_ns();
        let inner = self.schedule.lock();
        let planned = normalized_base(inner.tat, inner.initialized, now, self.schedule.burst_ns);
        let held = inner.claimed_ns.saturating_sub(self.claimed_ns);
        let committed = normalized_base(
            inner.committed_tat.unwrap_or(0),
            inner.committed_tat.is_some(),
            now,
            self.schedule.burst_ns,
        );
        let credit =
            u128::try_from(now.saturating_sub(planned.max(committed.saturating_add(held)))).unwrap_or_default();
        let capacity = self.capacity_quantum(&inner);
        drop(inner);
        let available = credit
            .saturating_mul(u128::from(self.schedule.rate))
            .saturating_div(1_000_000_000);
        let refill = self.schedule.rate.div_ceil(100).max(1);
        u64::try_from(available).unwrap_or(u64::MAX).max(refill).min(capacity)
    }

    /// Largest progress quantum not pinned by another in-flight write.
    pub(super) fn max_prefix(&self) -> u64 {
        self.capacity_quantum(&self.schedule.lock())
    }

    /// Bound a prefix by the unused burst, with one byte to wait on a full budget.
    fn capacity_quantum(&self, inner: &ScheduleInner) -> u64 {
        if self.schedule.burst_ns == 0 {
            return self.schedule.quantum;
        }
        let held = inner.claimed_ns.saturating_sub(self.claimed_ns);
        let free = u128::try_from(self.schedule.burst_ns.saturating_sub(held)).unwrap_or_default();
        let bytes = free
            .saturating_mul(u128::from(self.schedule.rate))
            .saturating_div(1_000_000_000);
        u64::try_from(bytes)
            .unwrap_or(u64::MAX)
            .min(self.schedule.quantum)
            .max(1)
    }

    /// Coalesce matching charges, returning an unrelated charge unchanged.
    pub(super) fn merge(&mut self, mut other: Self) -> Option<Self> {
        if !Arc::ptr_eq(&self.schedule, &other.schedule) {
            return Some(other);
        }
        self.refund();
        other.refund();
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.cost_ns = bytes_to_ns(self.bytes, self.schedule.rate);
        self.created_at = self.created_at.min(other.created_at);
        None
    }

    /// Split a prepared charge without adding any debt to the shared schedule.
    pub(super) fn split_plan(&mut self, bytes: u64) -> Self {
        self.refund();
        let taken = self.bytes.min(bytes);
        self.bytes = self.bytes.saturating_sub(taken);
        self.cost_ns = bytes_to_ns(self.bytes, self.schedule.rate);
        self.schedule.grant(taken, self.created_at, self.synthetic_now)
    }

    /// Atomically claim this prefix while leaving other writers the unused burst.
    pub(super) fn try_acquire(&mut self) -> Admission {
        if self.claimed_ns != 0 || self.cost_ns == 0 {
            return Admission::Ready;
        }
        let now = self.now_ns();
        let mut inner = self.schedule.lock();
        if let Some(wait) = self.capacity_wait(&inner) {
            return wait;
        }
        let release = self.release_with(&inner, now);
        if release > now {
            return self
                .schedule
                .epoch
                .checked_add(delay_between(0, release))
                .map_or(Admission::Overflow, |release| {
                    Admission::At(release, self.schedule.changed.subscribe())
                });
        }
        inner.claimed_ns = inner.claimed_ns.saturating_add(self.cost_ns);
        drop(inner);
        self.claimed_ns = self.cost_ns;
        Admission::Ready
    }

    /// Full held allowance needs settlement; a partially held burst needs resizing.
    fn capacity_wait(&self, inner: &ScheduleInner) -> Option<Admission> {
        if inner.claimed_ns == 0 {
            return None;
        }
        if inner.claimed_ns >= self.schedule.burst_ns {
            return Some(Admission::Busy(self.schedule.changed.subscribe()));
        }
        (inner.claimed_ns.saturating_add(self.cost_ns) > self.schedule.burst_ns).then_some(Admission::Resize)
    }

    /// Release just this writer's claim before a wait on another budget.
    pub(super) fn unclaim(&mut self) {
        if self.claimed_ns != 0 {
            let mut inner = self.schedule.lock();
            inner.claimed_ns = inner.claimed_ns.saturating_sub(self.claimed_ns);
            drop(inner);
            self.claimed_ns = 0;
            self.schedule.changed.send_replace(());
        }
    }

    /// Commit bytes accepted by the writer; dropping the rest refunds it.
    pub(crate) fn commit(mut self) {
        if self.cost_ns == 0 {
            self.unclaim();
            return;
        }
        self.reserve();
        let now = self.now_ns();
        let mut inner = self.schedule.lock();
        inner.committed_tat = Some(self.accepted_release(&inner, now));
        inner.outstanding = inner.outstanding.saturating_sub(1);
        finish_planning(&mut inner);
        inner.claimed_ns = inner.claimed_ns.saturating_sub(self.claimed_ns);
        self.reserved = false;
        self.claimed_ns = 0;
        drop(inner);
        self.schedule.changed.send_replace(());
    }

    /// Rebuild non-refundable debt from accepted writes using the actual clock.
    fn accepted_release(&self, inner: &ScheduleInner, now: i128) -> i128 {
        if self.schedule.burst_ns == 0 {
            return inner
                .committed_tat
                .unwrap_or(0)
                .max(self.created_at)
                .saturating_add(self.cost_ns)
                .max(now);
        }
        normalized_base(
            inner.committed_tat.unwrap_or(0),
            inner.committed_tat.is_some(),
            now,
            self.schedule.burst_ns,
        )
        .saturating_add(self.cost_ns)
    }

    /// Keep only the accepted portion of a prefix; dropping an empty write refunds it.
    pub(super) fn commit_partial(mut self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.bytes = self.bytes.min(bytes);
        self.cost_ns = bytes_to_ns(self.bytes, self.schedule.rate);
        self.commit();
    }

    /// Record this prefix in planned debt exactly once.
    fn reserve(&mut self) {
        if self.reserved || self.cost_ns == 0 {
            return;
        }
        let mut inner = self.schedule.lock();
        let floor = self.created_at.saturating_sub(self.schedule.burst_ns);
        if inner.initialized && floor > inner.tat {
            inner.generation = inner.generation.wrapping_add(1);
        }
        let base = normalized_base(inner.tat, inner.initialized, self.created_at, self.schedule.burst_ns);
        inner.tat = base.saturating_add(self.cost_ns);
        inner.initialized = true;
        inner.outstanding = inner.outstanding.saturating_add(1);
        self.tat_after = inner.tat;
        self.generation = inner.generation;
        drop(inner);
        self.reserved = true;
    }

    /// Release only debt belonging to this reservation's still-current generation.
    fn refund(&mut self) {
        if !self.reserved {
            self.unclaim();
            return;
        }
        let mut inner = self.schedule.lock();
        inner.outstanding = inner.outstanding.saturating_sub(1);
        if self.generation == inner.generation && inner.tat == self.tat_after {
            inner.tat = inner.tat.saturating_sub(self.cost_ns);
            if let Some(committed) = inner.committed_tat {
                inner.tat = inner.tat.max(committed);
            }
        }
        finish_planning(&mut inner);
        inner.claimed_ns = inner.claimed_ns.saturating_sub(self.claimed_ns);
        self.reserved = false;
        self.claimed_ns = 0;
        drop(inner);
        self.schedule.changed.send_replace(());
    }

    /// Planned release, bounded below by the non-refundable accepted-write ledger.
    fn release_ns(&self, now: i128) -> i128 {
        self.release_with(&self.schedule.lock(), now)
    }

    /// Calculate release while the caller already holds the accounting lock.
    fn release_with(&self, inner: &ScheduleInner, now: i128) -> i128 {
        let planned = if self.reserved {
            self.tat_after
        } else {
            normalized_base(inner.tat, inner.initialized, self.created_at, self.schedule.burst_ns)
                .saturating_add(self.cost_ns)
        };
        let committed = if self.schedule.burst_ns == 0 {
            inner
                .committed_tat
                .unwrap_or(0)
                .max(self.created_at)
                .saturating_add(self.cost_ns)
        } else {
            normalized_base(
                inner.committed_tat.unwrap_or(0),
                inner.committed_tat.is_some(),
                now,
                self.schedule.burst_ns,
            )
            .saturating_add(self.cost_ns)
        };
        planned.max(committed.saturating_add(inner.claimed_ns.saturating_sub(self.claimed_ns)))
    }

    /// Clock selected by production or a deterministic model test.
    fn now_ns(&self) -> i128 {
        self.synthetic_now.unwrap_or_else(|| self.schedule.now_ns())
    }
}

impl Drop for BandwidthGrant {
    fn drop(&mut self) {
        self.refund();
    }
}

/// Once all reservations settle, retain only bytes that really reached the writer.
fn finish_planning(inner: &mut ScheduleInner) {
    if inner.outstanding == 0 {
        inner.tat = inner.committed_tat.unwrap_or(0);
        inner.initialized = inner.committed_tat.is_some();
    }
}

/// Apply burst refill without manufacturing an allowance in no-burst mode.
fn normalized_base(tat: i128, initialized: bool, now: i128, burst_ns: i128) -> i128 {
    let floor = now.saturating_sub(burst_ns);
    if initialized { tat.max(floor) } else { floor }
}

/// Positive difference between monotonic timestamps.
fn delay_between(now: i128, release: i128) -> Duration {
    let delta = release.saturating_sub(now);
    if delta <= 0 {
        return Duration::ZERO;
    }
    u64::try_from(delta).map_or(Duration::MAX, Duration::from_nanos)
}

/// Round a nonempty charge upward so high rates cannot make bytes free.
fn bytes_to_ns(bytes: u64, rate: u64) -> i128 {
    if bytes == 0 || rate == 0 {
        return 0;
    }
    let numerator = u128::from(bytes).saturating_mul(1_000_000_000);
    i128::try_from(numerator.div_ceil(u128::from(rate))).unwrap_or(i128::MAX)
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one deterministic model checks every accepted-byte interval across four outstanding writers"
    )]
    fn concurrent_admission_preserves_the_budget_across_late_partial_writes() {
        let schedule = Schedule::new(10, 10);
        let mut held: Vec<BandwidthGrant> = Vec::new();
        let mut random = 17_u64;
        let mut total = 0_u64;
        let mut accepted = vec![(0_i128, 0_u64)];
        for step in 0_i128..1000 {
            let now = step.saturating_mul(50_000_000);
            random = random.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            if random.rotate_left(7).is_multiple_of(3) && held.len() < 4 {
                let mut grant = schedule.grant(random.rem_euclid(10).saturating_add(1), now, Some(now));
                if matches!(grant.try_acquire(), Admission::Ready) {
                    held.push(grant);
                }
            } else if !held.is_empty() {
                let index = usize::try_from(random.rem_euclid(u64::try_from(held.len()).unwrap())).unwrap();
                let mut grant = held.swap_remove(index);
                grant.synthetic_now = Some(now);
                let bytes = random.rotate_right(11).rem_euclid(grant.bytes.saturating_add(1));
                let before = total;
                total = total.saturating_add(bytes);
                grant.commit_partial(bytes);
                for (at, prior) in &accepted {
                    let refill =
                        u64::try_from(now.saturating_sub(*at).saturating_mul(10).saturating_div(1_000_000_000))
                            .unwrap();
                    assert!(
                        total.saturating_sub(*prior) <= 10_u64.saturating_add(refill),
                        "accepted writes exceeded a burst-plus-refill interval"
                    );
                }
                if bytes != 0 {
                    accepted.push((now, before));
                }
            }
        }
        assert!(accepted.len() > 20, "the trace must exercise repeated accepted writes");
        drop(held);
        assert_eq!(
            schedule.lock().claimed_ns,
            0,
            "all unfinished writes refund their held allowance"
        );
    }

    #[test]
    fn pending_allowance_is_pinned_across_refill_until_the_late_write_commits() {
        let schedule = Schedule::new(1000, 1000);
        let mut late = schedule.grant(1, 0, Some(0));
        assert!(matches!(late.try_acquire(), Admission::Ready));
        let mut first = schedule.grant(999, 0, Some(0));
        assert!(matches!(first.try_acquire(), Admission::Ready));
        first.commit();
        let mut too_large = schedule.grant(1000, 2_000_000_000, Some(2_000_000_000));
        assert!(matches!(too_large.try_acquire(), Admission::Resize));
        drop(too_large);
        let mut later = schedule.grant(999, 2_000_000_000, Some(2_000_000_000));
        assert!(matches!(later.try_acquire(), Admission::Ready));
        later.commit();
        late.synthetic_now = Some(2_000_000_000);
        late.commit();
        let mut next = schedule.grant(1, 2_000_000_000, Some(2_000_000_000));
        assert!(
            matches!(next.try_acquire(), Admission::At(..)),
            "late and current writes share one burst"
        );
    }

    #[test]
    fn a_partial_commit_releases_the_entire_original_claim() {
        let schedule = Schedule::new(1, 1000);
        let mut first = schedule.grant(1000, 0, Some(0));
        assert!(matches!(first.try_acquire(), Admission::Ready));
        first.commit_partial(1);
        let mut next = schedule.grant(999, 0, Some(0));
        assert!(matches!(next.try_acquire(), Admission::Ready));
        drop(next);
        assert_eq!(schedule.lock().claimed_ns, 0);
        assert_eq!(schedule.reserve_at(1000, 0).delay(), Duration::from_secs(1));
    }

    #[test]
    fn cancelling_a_pre_refill_grant_does_not_create_a_second_burst() {
        let schedule = Schedule::new(100, 100);
        let old = schedule.reserve_at(100, 0);
        let current = schedule.reserve_at(100, 2_000_000_000);
        drop(old);
        current.commit();
        assert_eq!(schedule.reserve_at(100, 2_000_000_000).delay(), Duration::from_secs(1));
    }

    #[test]
    fn a_wait_uses_only_the_time_left_until_its_absolute_release() {
        let schedule = Schedule::new(1000, 0);
        let mut grant = schedule.reserve_at(1000, 0);
        grant.synthetic_now = Some(600_000_000);
        assert_eq!(
            grant.delay(),
            Duration::from_millis(400),
            "DNS time is not charged twice"
        );
        grant.synthetic_now = Some(1_100_000_000);
        assert!(grant.delay().is_zero(), "a past release time does not sleep again");
    }

    #[test]
    fn no_burst_paces_the_first_byte() {
        let schedule = Schedule::new(1_000, 0);
        let grant = schedule.reserve_at(1_000, 0);
        assert_eq!(grant.delay(), Duration::from_secs(1), "the first byte waits its cost");
    }

    #[test]
    fn zero_burst_prefixes_amortize_timer_ticks_without_free_allowance() {
        let rate = 104_857_600;
        let schedule = Schedule::new(rate, 0);
        assert_eq!(schedule.quantum, 1_048_576);
        let prefix = schedule.reserve_at(schedule.quantum, 0);
        assert_eq!(prefix.delay(), Duration::from_millis(10));
        assert!(!Schedule::new(rate, 0).reserve_at(1, 0).delay().is_zero());
        assert_eq!(Schedule::new(u64::MAX, 0).quantum, 1_048_576);
        assert_eq!(Schedule::new(1, 0).quantum, 1);
        assert_eq!(Schedule::new(rate, u64::MAX).quantum, 16_384);
    }

    #[test]
    fn burst_covers_an_initial_prefix() {
        let schedule = Schedule::new(1_000, 1_000);
        let grant = schedule.reserve_at(1_000, 0);
        assert_eq!(grant.delay(), Duration::ZERO, "a full burst sends immediately");
    }

    #[test]
    fn a_second_reservation_does_not_receive_a_new_burst() {
        let schedule = Schedule::new(1_000, 1_000);
        let first = schedule.reserve_at(1_000, 0);
        assert_eq!(first.delay(), Duration::ZERO, "the burst covers the first chunk");
        first.commit();
        let second = schedule.reserve_at(1, 0);
        assert_eq!(
            second.delay(),
            Duration::from_millis(1),
            "the next byte waits on the shared schedule"
        );
    }

    #[test]
    fn an_oversized_chunk_waits_only_for_the_excess() {
        let schedule = Schedule::new(100, 100);
        let grant = schedule.reserve_at(1_000, 0);
        assert_eq!(
            grant.delay(),
            Duration::from_secs(9),
            "the chunk finishes without waiting to fit inside the burst"
        );
    }

    #[test]
    fn chunk_boundaries_share_one_schedule() {
        let one = Schedule::new(1_000, 0);
        let split = Schedule::new(1_000, 0);
        let whole = one.reserve_at(1_000, 0);
        let _first = split.reserve_at(250, 0);
        let _second = split.reserve_at(250, 0);
        let _third = split.reserve_at(250, 0);
        let last = split.reserve_at(250, 0);
        assert_eq!(
            last.delay(),
            whole.delay(),
            "four chunks and one chunk finish at the same schedule time"
        );
    }

    #[test]
    fn idle_time_does_not_create_a_burst_when_none_was_configured() {
        let schedule = Schedule::new(1_000, 0);
        let first = schedule.reserve_at(1_000, 0);
        first.commit();
        let second = schedule.reserve_at(1_000, 5_000_000_000);
        assert_eq!(
            second.delay(),
            Duration::from_secs(1),
            "idle time snaps a no-burst schedule back to now"
        );
    }

    #[test]
    fn idle_time_refills_only_the_configured_burst() {
        let schedule = Schedule::new(1_000, 1_000);
        schedule.reserve_at(1_000, 0).commit();
        let refilled = schedule.reserve_at(1_000, 1_000_000_000);
        assert_eq!(
            refilled.delay(),
            Duration::ZERO,
            "a full idle interval restores the burst"
        );
    }

    #[test]
    fn a_depleted_schedule_is_not_fresh_until_it_would_refill() {
        let schedule = Schedule::new(1_000, 1_000);
        schedule.reserve_at(1_000, 0).commit();
        assert!(!schedule.is_fresh_at(0), "a spent burst is not a new full bucket");
        assert!(
            schedule.is_fresh_at(1_000_000_000),
            "after a full refill a new bucket would be equivalent"
        );
    }

    #[test]
    fn dropping_the_tail_reservation_refunds_it() {
        let schedule = Schedule::new(1_000, 0);
        let first = schedule.reserve_at(500, 0);
        let second = schedule.reserve_at(500, 0);
        drop(second);
        let again = schedule.reserve_at(500, 0);
        assert_eq!(again.delay(), first.delay() + Duration::from_millis(500));
        assert_eq!(
            again.delay(),
            Duration::from_secs(1),
            "the tail rollback frees the second half"
        );
    }

    #[test]
    fn dropping_an_earlier_reservation_still_refunds_it() {
        let schedule = Schedule::new(1_000, 0);
        let earlier = schedule.reserve_at(500, 0);
        let later = schedule.reserve_at(500, 0);
        drop(earlier);
        drop(later);

        let next = schedule.reserve_at(1, 0);
        assert_eq!(
            next.delay(),
            Duration::from_millis(1),
            "cancelling the earlier grant first still returns both"
        );
    }

    #[test]
    fn an_earlier_cancel_stays_covered_until_the_later_grant_settles() {
        let schedule = Schedule::new(1_000, 0);
        let earlier = schedule.reserve_at(500, 0);
        let later = schedule.reserve_at(500, 0);
        drop(earlier);

        let next = schedule.reserve_at(1, 0);
        assert_eq!(
            next.delay(),
            Duration::from_millis(1_001),
            "a later outstanding grant still occupies the schedule"
        );
        drop(later);
        drop(next);
    }

    #[test]
    fn an_earlier_cancel_is_reclaimed_when_the_later_grant_is_sent() {
        let schedule = Schedule::new(1_000, 0);
        let earlier = schedule.reserve_at(500, 0);
        let later = schedule.reserve_at(500, 0);
        drop(earlier);
        later.commit();

        let next = schedule.reserve_at(1, 0);
        assert_eq!(
            next.delay(),
            Duration::from_millis(501),
            "only the sent grant remains after the earlier cancel"
        );
    }

    #[test]
    fn repeated_resets_do_not_bank_delay_for_the_next_connection() {
        let schedule = Schedule::new(1_000, 0);
        for _stream_pair in 0..4 {
            let earlier = schedule.reserve_at(500, 0);
            let later = schedule.reserve_at(500, 0);
            drop(earlier);
            drop(later);
        }

        assert!(schedule.is_fresh_at(0), "a fully cancelled schedule is fresh again");
        let next = schedule.reserve_at(1, 0);
        assert_eq!(
            next.delay(),
            Duration::from_millis(1),
            "http/2 resets do not leave per-ip delay behind"
        );
    }

    #[test]
    fn a_canceled_burst_is_offered_again() {
        let schedule = Schedule::new(1_000, 1_000);
        drop(schedule.reserve_at(1_000, 0));

        assert!(schedule.is_fresh_at(0), "nothing was sent");
        assert_eq!(
            schedule.reserve_at(1_000, 0).delay(),
            Duration::ZERO,
            "the burst is restored"
        );
    }

    #[test]
    fn commit_keeps_the_bytes_on_the_schedule() {
        let schedule = Schedule::new(1_000, 0);
        schedule.reserve_at(1_000, 0).commit();
        let next = schedule.reserve_at(1, 0);
        assert!(
            next.delay() >= Duration::from_secs(1),
            "committed bytes are not refunded"
        );
    }

    #[test]
    fn a_tiny_chunk_at_a_huge_rate_is_not_free() {
        let schedule = Schedule::new(u64::MAX, 0);
        let grant = schedule.reserve_at(1, 0);
        assert_eq!(
            grant.delay(),
            Duration::from_nanos(1),
            "rounding cannot make a byte free"
        );
    }
}
