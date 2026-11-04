// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Virtual-time byte schedule.
//!
//! Each direction keeps a theoretical arrival time. A reservation
//! moves that time forward by the byte cost immediately, then the
//! caller waits until the new time. Idle time refills at most
//! `burst_bytes`. A zero burst paces from the first byte and does
//! not accumulate credit.

use std::{
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

/// One direction's byte schedule.
pub(crate) struct Schedule {
    /// Monotonic origin for this schedule.
    epoch: Instant,

    /// Bytes per second. Always greater than zero.
    rate: u64,

    /// Burst capacity in nanoseconds. Zero means no burst.
    burst_ns: i128,

    /// Theoretical arrival time, guarded so streams can share it.
    inner: Mutex<ScheduleInner>,
}

/// Mutable schedule state.
struct ScheduleInner {
    /// Theoretical arrival time in nanoseconds since [`Schedule::epoch`].
    tat: i128,

    /// Whether [`ScheduleInner::tat`] has been initialized.
    initialized: bool,

    /// Grants not yet committed or dropped.
    outstanding: u64,

    /// Cost of cancelled grants still covered by a later outstanding grant.
    pending_refund_ns: i128,

    /// Cost of grants marked sent. Zero means a full cancel restores a fresh schedule.
    committed_ns: i128,
}

/// A reserved slice of a [`Schedule`].
///
/// Drop returns the reservation unless [`Self::commit`] was called.
/// A later outstanding grant keeps the hole covered until it commits
/// or drops, so cancelled bytes are reclaimed whatever the drop order.
/// Bytes already sent must be committed so a later failure does not
/// return them.
pub(crate) struct BandwidthGrant {
    /// Schedule that owns the reservation.
    schedule: Arc<Schedule>,

    /// Nanoseconds added to the theoretical arrival time.
    cost_ns: i128,

    /// Theoretical arrival time after this reservation.
    tat_after: i128,

    /// How long the caller should wait before sending the bytes.
    delay: Duration,

    /// Set once the bytes have been sent.
    committed: bool,
}

impl Schedule {
    /// Create a schedule that refills `rate` bytes per second.
    ///
    /// `burst_bytes == 0` is the no-burst mode: the first byte waits,
    /// and idle time does not create a free allowance.
    pub(crate) fn new(rate: u64, burst_bytes: u64) -> Arc<Self> {
        Arc::new(Self {
            epoch: Instant::now(),
            rate,
            burst_ns: bytes_to_ns(burst_bytes, rate),
            inner: Mutex::new(ScheduleInner {
                tat: 0,
                initialized: false,
                outstanding: 0,
                pending_refund_ns: 0,
                committed_ns: 0,
            }),
        })
    }

    /// Reserve `bytes` against the current time.
    pub(crate) fn reserve(self: &Arc<Self>, bytes: u64) -> BandwidthGrant {
        self.reserve_at(bytes, self.now_ns())
    }

    /// Reserve `bytes` as if the current time were `now` nanoseconds.
    pub(crate) fn reserve_at(self: &Arc<Self>, bytes: u64, now: i128) -> BandwidthGrant {
        if bytes == 0 || self.rate == 0 {
            return empty_grant(self);
        }
        let cost_ns = bytes_to_ns(bytes, self.rate);
        let mut inner = self.lock();
        let base = normalized_base(inner.tat, inner.initialized, now, self.burst_ns);
        inner.initialized = true;
        let tat_after = base.saturating_add(cost_ns);
        inner.tat = tat_after;
        inner.outstanding = inner.outstanding.saturating_add(1);
        drop(inner);
        BandwidthGrant {
            schedule: Arc::clone(self),
            cost_ns,
            tat_after,
            delay: delay_between(now, tat_after),
            committed: false,
        }
    }

    /// Whether a brand-new full burst would match this schedule.
    pub(crate) fn is_fresh(&self) -> bool {
        self.is_fresh_at(self.now_ns())
    }

    /// [`Self::is_fresh`] at a caller-supplied time.
    pub(crate) fn is_fresh_at(&self, now: i128) -> bool {
        let inner = self.lock();
        if !inner.initialized {
            return true;
        }
        inner.tat <= now.saturating_sub(self.burst_ns)
    }

    /// Account for a grant that was sent or cancelled.
    fn settle_grant(&self, cost_ns: i128, tat_after: i128, committed: bool) {
        let mut inner = self.lock();
        inner.outstanding = inner.outstanding.saturating_sub(1);
        if committed {
            note_commit(&mut inner, cost_ns);
            return;
        }
        note_cancel(&mut inner, cost_ns, tat_after);
    }

    /// Nanoseconds since this schedule was created.
    fn now_ns(&self) -> i128 {
        i128::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(i128::MAX)
    }

    /// Lock the theoretical arrival time, recovering from a poisoned mutex.
    fn lock(&self) -> MutexGuard<'_, ScheduleInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl BandwidthGrant {
    /// How long to wait before the reserved bytes may be sent.
    pub(crate) fn delay(&self) -> Duration {
        self.delay
    }

    /// Mark the bytes as sent so drop does not refund them.
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for BandwidthGrant {
    fn drop(&mut self) {
        if self.cost_ns == 0 {
            return;
        }
        self.schedule.settle_grant(self.cost_ns, self.tat_after, self.committed);
    }
}

/// Record a sent grant and release cancelled bytes once nothing is in flight.
fn note_commit(inner: &mut ScheduleInner, cost_ns: i128) {
    inner.committed_ns = inner.committed_ns.saturating_add(cost_ns);
    if inner.outstanding == 0 {
        reclaim_finished(inner, 0);
    }
}

/// Return a cancelled grant. A non-tail grant stays pending while a later one is outstanding.
fn note_cancel(inner: &mut ScheduleInner, cost_ns: i128, tat_after: i128) {
    if inner.outstanding == 0 {
        reclaim_finished(inner, cost_ns);
        return;
    }
    if inner.tat == tat_after {
        inner.tat = inner.tat.saturating_sub(cost_ns);
        return;
    }
    inner.pending_refund_ns = inner.pending_refund_ns.saturating_add(cost_ns);
}

/// Remove cancelled cost. A schedule with nothing sent becomes fresh again.
fn reclaim_finished(inner: &mut ScheduleInner, extra: i128) {
    if inner.committed_ns == 0 {
        inner.tat = 0;
        inner.pending_refund_ns = 0;
        inner.initialized = false;
        return;
    }
    let reclaim = extra.saturating_add(inner.pending_refund_ns);
    inner.tat = inner.tat.saturating_sub(reclaim);
    inner.pending_refund_ns = 0;
}

/// A grant that does not change the schedule.
fn empty_grant(schedule: &Arc<Schedule>) -> BandwidthGrant {
    BandwidthGrant {
        schedule: Arc::clone(schedule),
        cost_ns: 0,
        tat_after: 0,
        delay: Duration::ZERO,
        committed: true,
    }
}

/// Arrival time after applying the burst floor.
///
/// An uninitialized schedule starts a full burst behind `now`.
/// Idle time never moves the time further back than that floor,
/// so a no-burst schedule snaps to `now` and a burst schedule
/// refills only up to `burst_bytes`.
fn normalized_base(tat: i128, initialized: bool, now: i128, burst_ns: i128) -> i128 {
    let floor = now.saturating_sub(burst_ns);
    if initialized { tat.max(floor) } else { floor }
}

/// Wait from `now` until `tat_after`.
fn delay_between(now: i128, tat_after: i128) -> Duration {
    let Some(delta) = tat_after.checked_sub(now) else {
        return Duration::MAX;
    };
    if delta <= 0 {
        return Duration::ZERO;
    }
    u64::try_from(delta).map_or(Duration::MAX, Duration::from_nanos)
}

/// Convert bytes at `rate` bytes per second into nanoseconds.
///
/// A positive byte count that rounds to zero becomes one nanosecond
/// so a tiny chunk is not free. A zero byte count stays zero.
fn bytes_to_ns(bytes: u64, rate: u64) -> i128 {
    if bytes == 0 || rate == 0 {
        return 0;
    }
    let nanos = u128::from(bytes).saturating_mul(1_000_000_000) / u128::from(rate);
    let nanos = if nanos == 0 { 1 } else { nanos };
    i128::try_from(nanos).unwrap_or(i128::MAX)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

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
    fn no_burst_paces_the_first_byte() {
        let schedule = Schedule::new(1_000, 0);
        let grant = schedule.reserve_at(1_000, 0);
        assert_eq!(grant.delay(), Duration::from_secs(1), "the first byte waits its cost");
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
