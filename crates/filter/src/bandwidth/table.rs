// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Per-filter map of shared upload and download budgets.
//!
//! A per-IP slot stays while its schedule is not equivalent to a brand-new
//! full burst, including while nobody is connected. A per-connection slot
//! stays across keep-alive requests only while its [`ConnectionAlive`] watch
//! is live, and is removed when that connection closes. Fresh idle slots
//! may be removed because recreating them is the same allowance.
//! An in-use slot is never removed, so a key is never given a second budget.
//!
//! Eviction runs only when a new key is inserted and the map is already at
//! its soft cap. Each pass inspects a bounded window and leaves a cursor,
//! so later passes continue through the map instead of repeating its prefix.

use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

use super::schedule::Schedule;

/// Soft cap that starts eviction of fresh idle slots.
const MAX_TRACKED: usize = 100_000;

/// Hard cap after which a new key is refused.
const HARD_CAP: usize = 200_000;

/// Keys inspected in one eviction pass below the aggressive threshold.
const EVICTION_SCAN_LIMIT: usize = 2_048;

/// Map key for one budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum BudgetKey {
    /// Downstream connection identity.
    Connection(u64),

    /// Normalized source address.
    Ip(IpAddr),
}

/// Failure from [`BandwidthTable::acquire`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcquireError {
    /// The table is at its hard cap and no fresh idle slot could be removed.
    Full,
}

/// Watches a downstream connection so its budget ends when the connection does.
///
/// Hold one watch for the connection's socket identity. The table keeps a
/// per-connection budget across keep-alive requests while the watch is alive.
/// After the last owner of that identity drops, a later connection that
/// reuses the same address gets a new budget.
#[derive(Clone)]
#[must_use = "hold the watch for the life of the connection"]
pub struct ConnectionAlive {
    /// Weak handle for the connection allocation.
    alive: Weak<dyn Send + Sync>,
}

impl ConnectionAlive {
    /// Watch `resource` until its other owners drop it.
    pub fn watch<T: Send + Sync + 'static>(resource: &Arc<T>) -> Self {
        let owned = Arc::clone(resource);
        let erased: Arc<dyn Send + Sync> = owned;
        Self {
            alive: Arc::downgrade(&erased),
        }
    }

    /// Whether the watched connection is still open.
    pub(crate) fn is_alive(&self) -> bool {
        self.alive.upgrade().is_some()
    }
}

/// Budgets owned by one filter instance.
pub(crate) struct BandwidthTable {
    /// Upload rate in bytes per second. `None` is unlimited.
    upload_rate: Option<u64>,

    /// Download rate in bytes per second. `None` is unlimited.
    download_rate: Option<u64>,

    /// Burst shared by both directions. Zero selects the no-burst mode.
    burst_bytes: u64,

    /// Soft size that triggers eviction.
    max_entries: usize,

    /// Absolute size that refuses a new key.
    hard_cap: usize,

    /// Keys inspected by one pressure pass.
    scan_limit: usize,

    /// Slots and the cursor of the next pressure pass.
    slots: Mutex<TableState>,
}

/// The slot map and the key the next bounded scan starts at.
struct TableState {
    /// Budgets keyed by connection or address.
    slots: BTreeMap<BudgetKey, Slot>,

    /// First key the next pressure scan inspects. `None` starts at the lowest key.
    cursor: Option<BudgetKey>,
}

/// One tracked key.
struct Slot {
    /// Upload schedule. `None` when that direction is unlimited.
    upload: Option<Arc<Schedule>>,

    /// Download schedule. `None` when that direction is unlimited.
    download: Option<Arc<Schedule>>,

    /// Live attachments. Eviction requires this to be zero.
    in_flight: Arc<AtomicU64>,

    /// Set for an HTTP per-connection budget. `None` for per-IP and TCP.
    lease: Option<ConnectionAlive>,
}

/// Removes a per-connection slot once its last attachment drops.
struct IdleRelease {
    /// Table that owns the slot.
    table: Arc<BandwidthTable>,

    /// Key to remove when the connection has ended.
    key: BudgetKey,
}

/// A live claim on a slot.
pub(crate) struct Acquired {
    /// Shared upload schedule.
    pub(crate) upload: Option<Arc<Schedule>>,

    /// Shared download schedule.
    pub(crate) download: Option<Arc<Schedule>>,

    /// Decrements the slot's in-flight count on drop.
    pub(crate) guard: InFlightGuard,
}

/// Keeps a slot ineligible for eviction until dropped.
pub(crate) struct InFlightGuard {
    /// Shared counter incremented by [`attach`].
    counter: Arc<AtomicU64>,

    /// Present for per-connection attachments.
    release: Option<IdleRelease>,
}

impl BandwidthTable {
    /// Create a table with the production size caps.
    pub(crate) fn new(upload_rate: Option<u64>, download_rate: Option<u64>, burst_bytes: u64) -> Self {
        Self::with_limits(upload_rate, download_rate, burst_bytes, MAX_TRACKED, HARD_CAP)
    }

    /// Create a table with explicit caps. Tests use small caps.
    pub(crate) fn with_limits(
        upload_rate: Option<u64>,
        download_rate: Option<u64>,
        burst_bytes: u64,
        max_entries: usize,
        hard_cap: usize,
    ) -> Self {
        Self {
            upload_rate,
            download_rate,
            burst_bytes,
            max_entries,
            hard_cap,
            scan_limit: EVICTION_SCAN_LIMIT,
            slots: Mutex::new(TableState {
                slots: BTreeMap::new(),
                cursor: None,
            }),
        }
    }

    /// Inspect at most `limit` keys on each pressure pass. Tests use a small limit.
    #[cfg(test)]
    fn with_scan_limit(mut self, limit: usize) -> Self {
        self.scan_limit = limit;
        self
    }

    /// Whether this table paces uploads.
    pub(crate) fn has_upload(&self) -> bool {
        self.upload_rate.is_some()
    }

    /// Whether this table paces downloads.
    pub(crate) fn has_download(&self) -> bool {
        self.download_rate.is_some()
    }

    /// Return the existing budget or insert one.
    ///
    /// `lease` keeps an HTTP per-connection budget across keep-alive
    /// requests. A dead lease is replaced so a recycled address does not
    /// inherit the closed connection's allowance.
    ///
    /// # Errors
    ///
    /// Returns [`AcquireError::Full`] when the key is new and the table
    /// is at its hard cap after one bounded eviction pass.
    pub(crate) fn acquire(
        self: &Arc<Self>,
        key: BudgetKey,
        lease: Option<ConnectionAlive>,
    ) -> Result<Acquired, AcquireError> {
        let mut state = self.lock();
        let before = state.slots.len();
        let evicted = self.evict_for_new_key(&mut state, key);
        let result = self.insert_or_reuse(&mut state.slots, key, lease);
        let after = state.slots.len();
        drop(state);
        record_metrics(before, after, evicted);
        result
    }

    /// Evict only to make room for a key the map does not already hold.
    fn evict_for_new_key(&self, state: &mut TableState, key: BudgetKey) -> u64 {
        if state.slots.contains_key(&key) || state.slots.len() < self.max_entries {
            return 0;
        }
        self.evict_window(state)
    }

    /// Reuse `key`, replace a closed connection, or insert when the cap allows.
    fn insert_or_reuse(
        self: &Arc<Self>,
        slots: &mut BTreeMap<BudgetKey, Slot>,
        key: BudgetKey,
        lease: Option<ConnectionAlive>,
    ) -> Result<Acquired, AcquireError> {
        if slot_connection_ended(slots, key) {
            let _previous = slots.remove(&key);
        }
        if let Some(slot) = slots.get(&key) {
            return Ok(attach(self, key, slot));
        }
        self.insert_new(slots, key, lease)
    }

    /// Insert `key` when the hard cap allows.
    fn insert_new(
        self: &Arc<Self>,
        slots: &mut BTreeMap<BudgetKey, Slot>,
        key: BudgetKey,
        lease: Option<ConnectionAlive>,
    ) -> Result<Acquired, AcquireError> {
        if slots.len() >= self.hard_cap {
            return Err(AcquireError::Full);
        }
        let slot = Slot::new(
            self.upload_rate,
            self.download_rate,
            self.burst_bytes,
            stored_lease(key, lease),
        );
        let acquired = attach(self, key, &slot);
        slots.insert(key, slot);
        Ok(acquired)
    }

    /// Remove closed connections and fresh idle slots from one window.
    fn evict_window(&self, state: &mut TableState) -> u64 {
        let (keys, next) = scan_window(&state.slots, state.cursor, self.scan_limit);
        state.cursor = next;
        let mut removed: usize = 0;
        for key in keys {
            if self.drop_slot(&mut state.slots, key) {
                removed = removed.saturating_add(1);
            }
        }
        u64::try_from(removed).unwrap_or(u64::MAX)
    }

    /// Remove `key` when it is closed or a fresh idle slot above the soft cap.
    ///
    /// `slots.len()` is the count still present. Earlier removals in this pass
    /// have already left the map, so they must not be subtracted again.
    fn drop_slot(&self, slots: &mut BTreeMap<BudgetKey, Slot>, key: BudgetKey) -> bool {
        let remaining = slots.len();
        let removable = slots
            .get(&key)
            .is_some_and(|slot| can_drop(slot, remaining, self.max_entries));
        removable && slots.remove(&key).is_some()
    }

    /// Drop a per-connection slot whose connection has ended.
    fn release_idle_connection(&self, key: BudgetKey) {
        let removed = {
            let mut state = self.lock();
            let before = state.slots.len();
            let ended = state.slots.get(&key).is_some_and(Slot::idle_connection_ended);
            if ended {
                let _slot = state.slots.remove(&key);
            }
            ended.then_some((before, state.slots.len()))
        };
        if let Some((before, after)) = removed {
            record_metrics(before, after, 1);
        }
    }

    /// Lock the slot map, recovering from a poisoned mutex.
    fn lock(&self) -> MutexGuard<'_, TableState> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for BandwidthTable {
    /// Subtract this table's remaining entries from the shared gauge.
    fn drop(&mut self) {
        let len = self.slots.get_mut().unwrap_or_else(PoisonError::into_inner).slots.len();
        adjust_map_entries(len, 0);
    }
}

impl InFlightGuard {
    /// A guard that is not attached to a table slot.
    pub(crate) fn detached() -> Self {
        Self {
            counter: Arc::new(AtomicU64::new(1)),
            release: None,
        }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let previous = self.counter.fetch_sub(1, Ordering::AcqRel);
        if previous == 1
            && let Some(release) = self.release.take()
        {
            release.table.release_idle_connection(release.key);
        }
    }
}

impl Slot {
    /// Create schedules for the configured directions.
    fn new(
        upload_rate: Option<u64>,
        download_rate: Option<u64>,
        burst_bytes: u64,
        lease: Option<ConnectionAlive>,
    ) -> Self {
        Self {
            upload: upload_rate.map(|rate| Schedule::new(rate, burst_bytes)),
            download: download_rate.map(|rate| Schedule::new(rate, burst_bytes)),
            in_flight: Arc::new(AtomicU64::new(0)),
            lease,
        }
    }

    /// The per-connection watch has died and nobody is attached.
    fn lease_expired(&self) -> bool {
        self.in_flight.load(Ordering::Acquire) == 0 && self.lease.as_ref().is_some_and(|lease| !lease.is_alive())
    }

    /// An idle per-connection slot that should not outlive its connection.
    ///
    /// A live watch means HTTP keep-alive still owns the budget. No watch
    /// means the TCP connection, whose guard just dropped, has ended.
    fn idle_connection_ended(&self) -> bool {
        self.in_flight.load(Ordering::Acquire) == 0 && !self.lease.as_ref().is_some_and(ConnectionAlive::is_alive)
    }
}

/// Claim `slot` for one connection or request.
fn attach(table: &Arc<BandwidthTable>, key: BudgetKey, slot: &Slot) -> Acquired {
    slot.in_flight.fetch_add(1, Ordering::AcqRel);
    let release = matches!(key, BudgetKey::Connection(_)).then(|| IdleRelease {
        table: Arc::clone(table),
        key,
    });
    Acquired {
        upload: slot.upload.as_ref().map(Arc::clone),
        download: slot.download.as_ref().map(Arc::clone),
        guard: InFlightGuard {
            counter: Arc::clone(&slot.in_flight),
            release,
        },
    }
}

/// Whether `key` is a per-connection slot whose watch has died.
fn slot_connection_ended(slots: &BTreeMap<BudgetKey, Slot>, key: BudgetKey) -> bool {
    slots.get(&key).is_some_and(Slot::lease_expired)
}

/// Keep a lease only on per-connection keys.
fn stored_lease(key: BudgetKey, lease: Option<ConnectionAlive>) -> Option<ConnectionAlive> {
    match key {
        BudgetKey::Connection(_) => lease,
        BudgetKey::Ip(_) => None,
    }
}

/// Whether a pressure pass may remove `slot`.
///
/// A closed connection can leave at the soft cap. A fresh idle slot leaves
/// only while the map is still above that cap. `remaining` counts slots that
/// this pass has not removed yet.
fn can_drop(slot: &Slot, remaining: usize, max_entries: usize) -> bool {
    if slot.in_flight.load(Ordering::Acquire) != 0 {
        return false;
    }
    if slot.lease_expired() {
        return true;
    }
    remaining > max_entries && direction_fresh(slot.upload.as_ref()) && direction_fresh(slot.download.as_ref())
}

/// Keys in one pass, and the key the next pass should start at.
fn scan_window(
    slots: &BTreeMap<BudgetKey, Slot>,
    cursor: Option<BudgetKey>,
    limit: usize,
) -> (Vec<BudgetKey>, Option<BudgetKey>) {
    let mut keys = Vec::new();
    if limit == 0 || slots.is_empty() {
        return (keys, None);
    }
    if let Some(start) = cursor {
        push_limited(&mut keys, slots.range(start..), limit);
    }
    if keys.len() < limit {
        let tail = slots
            .iter()
            .take_while(|(key, _slot)| cursor.is_none_or(|start| **key < start));
        push_limited(&mut keys, tail, limit);
    }
    let next = keys.last().copied().and_then(|key| following_key(slots, key));
    (keys, next)
}

/// Append keys from `iter` until `keys` reaches `limit`.
fn push_limited<'a, I>(keys: &mut Vec<BudgetKey>, iter: I, limit: usize)
where
    I: Iterator<Item = (&'a BudgetKey, &'a Slot)>,
{
    for (key, _slot) in iter {
        if keys.len() == limit {
            return;
        }
        keys.push(*key);
    }
}

/// The key after `key`, wrapping to the lowest key after the last one.
fn following_key(slots: &BTreeMap<BudgetKey, Slot>, key: BudgetKey) -> Option<BudgetKey> {
    let mut rest = slots.range(key..);
    let _current = rest.next()?;
    rest.next()
        .map(|(key, _slot)| *key)
        .or_else(|| slots.keys().next().copied())
}

/// `None` is fresh. A present schedule must itself be fresh.
fn direction_fresh(schedule: Option<&Arc<Schedule>>) -> bool {
    schedule.is_none_or(|item| item.is_fresh())
}

/// Publish evictions and this table's change in tracked keys.
///
/// The gauge moves by the difference between `before` and `after`. Every
/// filter instance adds to the same total instead of replacing it.
fn record_metrics(before: usize, after: usize, evicted: u64) {
    if evicted > 0 {
        metrics::counter!("praxis_bandwidth_limit_evictions_total").increment(evicted);
    }
    adjust_map_entries(before, after);
}

/// Add or remove this table's size change from the shared map gauge.
fn adjust_map_entries(before: usize, after: usize) {
    if before == after {
        return;
    }
    let gauge = metrics::gauge!("praxis_bandwidth_limit_map_entries");
    if after > before {
        gauge.increment(gauge_units(after.saturating_sub(before)));
        return;
    }
    gauge.decrement(gauge_units(before.saturating_sub(after)));
}

/// `count` as a gauge sample. Values above `u32::MAX` clamp.
fn gauge_units(count: usize) -> f64 {
    f64::from(u32::try_from(count).unwrap_or(u32::MAX))
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
    use std::time::Duration;

    use super::*;

    fn ip(last: u8) -> BudgetKey {
        BudgetKey::Ip(IpAddr::from([10, 0, 0, last]))
    }

    fn connection(id: u64) -> BudgetKey {
        BudgetKey::Connection(id)
    }

    fn shared_table(burst: u64, max_entries: usize, hard_cap: usize) -> Arc<BandwidthTable> {
        Arc::new(BandwidthTable::with_limits(
            Some(1_000),
            None,
            burst,
            max_entries,
            hard_cap,
        ))
    }

    #[test]
    fn the_same_key_shares_one_burst() {
        let table = shared_table(1_000, 10, 10);
        let first = table.acquire(ip(1), None).unwrap();
        let burst = first.upload.as_ref().unwrap().reserve(1_000);
        assert_eq!(
            burst.delay(),
            Duration::ZERO,
            "the first connection spends the shared burst"
        );
        burst.commit();
        drop(first);

        let second = table.acquire(ip(1), None).unwrap();
        let next = second.upload.as_ref().unwrap().reserve(1);
        assert!(
            next.delay() > Duration::ZERO,
            "a second connection must not receive a new burst"
        );
    }

    #[test]
    fn different_keys_have_independent_bursts() {
        let table = shared_table(1_000, 10, 10);
        let first = table.acquire(ip(1), None).unwrap();
        first.upload.as_ref().unwrap().reserve(1_000).commit();
        let second = table.acquire(ip(2), None).unwrap();
        let grant = second.upload.as_ref().unwrap().reserve(1_000);
        assert_eq!(grant.delay(), Duration::ZERO, "another address keeps its own burst");
    }

    #[test]
    fn a_full_table_rejects_a_new_key() {
        let table = shared_table(0, 1, 1);
        let held = table.acquire(ip(1), None).unwrap();
        let Err(err) = table.acquire(ip(2), None) else {
            panic!("a new address should be refused when the table is full");
        };
        assert_eq!(
            err,
            AcquireError::Full,
            "a new address is refused when the table is full"
        );
        drop(held);
    }

    #[test]
    fn an_in_flight_slot_is_not_replaced() {
        let table = shared_table(0, 1, 1);
        let held = table.acquire(ip(1), None).unwrap();
        held.upload.as_ref().unwrap().reserve(1_000).commit();
        assert!(
            table.acquire(ip(2), None).is_err(),
            "the live key occupies the only slot"
        );
        let again = table.acquire(ip(1), None).unwrap();
        let grant = again.upload.as_ref().unwrap().reserve(1);
        assert!(
            grant.delay() > Duration::from_millis(500),
            "the live key keeps its depleted allowance"
        );
    }

    #[test]
    fn eviction_preserves_a_depleted_allowance() {
        let table = shared_table(0, 1, 3);
        let depleted = table.acquire(ip(1), None).unwrap();
        depleted.upload.as_ref().unwrap().reserve(1_000).commit();
        drop(depleted);
        let fresh = table.acquire(ip(2), None).unwrap();
        drop(fresh);

        let _inserted = table.acquire(ip(3), None).unwrap();
        let again = table.acquire(ip(1), None).unwrap();
        let grant = again.upload.as_ref().unwrap().reserve(1);
        assert!(
            grant.delay() > Duration::from_millis(500),
            "a depleted address keeps its allowance across reconnects"
        );
    }

    #[test]
    fn a_live_connection_keeps_a_spent_burst() {
        let table = shared_table(1_000, 10, 10);
        let socket = Arc::new(());
        let first = table
            .acquire(connection(7), Some(ConnectionAlive::watch(&socket)))
            .unwrap();
        first.upload.as_ref().unwrap().reserve(1_000).commit();
        drop(first);

        let second = table
            .acquire(connection(7), Some(ConnectionAlive::watch(&socket)))
            .unwrap();
        let next = second.upload.as_ref().unwrap().reserve(1);
        assert!(
            next.delay() > Duration::ZERO,
            "keep-alive requests share the connection budget"
        );
    }

    #[test]
    fn a_closed_connection_does_not_keep_its_budget() {
        let table = shared_table(1_000, 1, 1);
        let socket = Arc::new(());
        let first = table
            .acquire(connection(7), Some(ConnectionAlive::watch(&socket)))
            .unwrap();
        first.upload.as_ref().unwrap().reserve(1_000).commit();
        drop(first);
        let Err(blocked) = table.acquire(connection(8), Some(ConnectionAlive::watch(&Arc::new(())))) else {
            panic!("an open connection should still occupy the only slot");
        };
        assert_eq!(
            blocked,
            AcquireError::Full,
            "the open connection still occupies the table"
        );
        drop(socket);

        let replacement = Arc::new(());
        let again = table
            .acquire(connection(7), Some(ConnectionAlive::watch(&replacement)))
            .unwrap();
        let grant = again.upload.as_ref().unwrap().reserve(1_000);
        assert_eq!(
            grant.delay(),
            Duration::ZERO,
            "a recycled connection address starts a new budget"
        );
    }

    #[test]
    fn a_tcp_connection_budget_ends_when_its_guard_drops() {
        let table = shared_table(1_000, 10, 10);
        let first = table.acquire(connection(4), None).unwrap();
        first.upload.as_ref().unwrap().reserve(1_000).commit();
        drop(first);

        let again = table.acquire(connection(4), None).unwrap();
        let grant = again.upload.as_ref().unwrap().reserve(1_000);
        assert_eq!(
            grant.delay(),
            Duration::ZERO,
            "dropping the connection releases its budget"
        );
    }

    #[test]
    fn a_new_key_reclaims_a_closed_connection_at_the_cap() {
        let table = shared_table(1_000, 1, 1);
        let socket = Arc::new(());
        let first = table
            .acquire(connection(1), Some(ConnectionAlive::watch(&socket)))
            .unwrap();
        drop(first);
        drop(socket);

        let next = table
            .acquire(connection(2), Some(ConnectionAlive::watch(&Arc::new(()))))
            .unwrap();
        let grant = next.upload.as_ref().unwrap().reserve(1_000);
        assert_eq!(grant.delay(), Duration::ZERO, "a closed connection yields its slot");
    }

    fn occupy(table: &Arc<BandwidthTable>, id: u64, socket: &Arc<()>) {
        let acquired = table
            .acquire(connection(id), Some(ConnectionAlive::watch(socket)))
            .unwrap();
        acquired.upload.as_ref().unwrap().reserve(1_000).commit();
    }

    #[test]
    fn a_later_pass_reclaims_a_closed_connection_the_first_pass_missed() {
        let table = Arc::new(BandwidthTable::with_limits(Some(1_000), None, 1_000, 2, 2).with_scan_limit(1));
        let live = Arc::new(());
        let closed = Arc::new(());
        occupy(&table, 1, &live);
        occupy(&table, 2, &closed);
        drop(closed);
        drop(
            table
                .acquire(connection(1), Some(ConnectionAlive::watch(&live)))
                .unwrap(),
        );

        let newcomer = Arc::new(());
        let Err(_missed) = table.acquire(connection(3), Some(ConnectionAlive::watch(&newcomer))) else {
            panic!("the first window still holds the live connection");
        };
        assert!(
            table
                .acquire(connection(3), Some(ConnectionAlive::watch(&newcomer)))
                .is_ok(),
            "the next window reclaims the closed connection"
        );
    }

    #[test]
    fn a_bounded_scan_continues_where_the_last_pass_stopped() {
        let mut slots = BTreeMap::new();
        for id in 1..=3 {
            slots.insert(connection(id), Slot::new(None, None, 0, None));
        }
        let (first, cursor) = scan_window(&slots, None, 1);
        assert_eq!(first, vec![connection(1)], "the first pass starts at the lowest key");
        let (second, cursor) = scan_window(&slots, cursor, 1);
        assert_eq!(second, vec![connection(2)], "the next pass takes the following key");
        let (third, cursor) = scan_window(&slots, cursor, 1);
        assert_eq!(third, vec![connection(3)], "the pass walks forward");
        let (wrapped, _) = scan_window(&slots, cursor, 1);
        assert_eq!(wrapped, vec![connection(1)], "the pass wraps after the last key");
    }

    #[test]
    fn closed_connections_do_not_hide_fresh_idle_slots() {
        let table = Arc::new(BandwidthTable::with_limits(Some(1_000), None, 1_000, 2, 8).with_scan_limit(8));
        {
            let mut state = table.lock();
            for id in 1..=2 {
                let socket = Arc::new(());
                let lease = ConnectionAlive::watch(&socket);
                drop(socket);
                state
                    .slots
                    .insert(connection(id), Slot::new(Some(1_000), None, 1_000, Some(lease)));
            }
            for last in 1..=3 {
                state.slots.insert(ip(last), Slot::new(Some(1_000), None, 1_000, None));
            }
            adjust_map_entries(0, state.slots.len());
        }

        let _added = table.acquire(ip(9), None).unwrap();
        assert_eq!(
            table.lock().slots.len(),
            3,
            "one fresh idle slot leaves after the closed connections, then the new key is inserted"
        );
    }
}
