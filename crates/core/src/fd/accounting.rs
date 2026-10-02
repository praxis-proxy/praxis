// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Atomic descriptor accounting shared by the runtime and Loom tests.

use std::sync::atomic::{AtomicU64, Ordering};

use super::{CONNECT_COST, PENDING_COST};

/// Operations needed from a descriptor counter, supplied by `std` at runtime
/// and Loom in the model tests.
pub(super) trait FdAtomic {
    /// Read the current count.
    fn load(&self, order: Ordering) -> u64;

    /// Replace the current count.
    fn store(&self, value: u64, order: Ordering);

    /// Add to the count and return its previous value.
    fn fetch_add(&self, value: u64, order: Ordering) -> u64;

    /// Subtract from the count and return its previous value.
    fn fetch_sub(&self, value: u64, order: Ordering) -> u64;

    /// Apply an atomic update, retrying its closure on contention.
    fn fetch_update<F>(&self, set_order: Ordering, fetch_order: Ordering, update: F) -> Result<u64, u64>
    where
        F: FnMut(u64) -> Option<u64>;
}

impl FdAtomic for AtomicU64 {
    fn load(&self, order: Ordering) -> u64 {
        AtomicU64::load(self, order)
    }

    fn store(&self, value: u64, order: Ordering) {
        AtomicU64::store(self, value, order);
    }

    fn fetch_add(&self, value: u64, order: Ordering) -> u64 {
        AtomicU64::fetch_add(self, value, order)
    }

    fn fetch_sub(&self, value: u64, order: Ordering) -> u64 {
        AtomicU64::fetch_sub(self, value, order)
    }

    fn fetch_update<F>(&self, set_order: Ordering, fetch_order: Ordering, update: F) -> Result<u64, u64>
    where
        F: FnMut(u64) -> Option<u64>,
    {
        AtomicU64::fetch_update(self, set_order, fetch_order, update)
    }
}

/// The three counters that determine whether an admission fits the budget.
pub(super) struct Accounting<'counter, A: FdAtomic> {
    /// Descriptors in the most recent sample.
    cached_open: &'counter A,
    /// New connection charges not yet absorbed by a sample.
    connected: &'counter A,
    /// In-flight claims waiting for an upstream connection.
    pending: &'counter A,
}

impl<'counter, A: FdAtomic> Accounting<'counter, A> {
    /// Borrow the counters owned by an FD pressure monitor.
    pub(super) fn new(cached_open: &'counter A, connected: &'counter A, pending: &'counter A) -> Self {
        Self {
            cached_open,
            connected,
            pending,
        }
    }

    /// Reserve a claim and reject it if the resulting usage exceeds `threshold`.
    #[inline]
    pub(super) fn try_admit(&self, threshold: u64) -> bool {
        let claimed = self.pending.fetch_add(1, Ordering::AcqRel).saturating_add(1);
        if self.predicted_with(claimed) > threshold {
            self.pending.fetch_sub(1, Ordering::Release);
            return false;
        }
        true
    }

    /// The last sample plus claims and new connection charges.
    #[inline]
    pub(super) fn predicted_with(&self, pending: u64) -> u64 {
        let (connected, cached_open) = self.usage_components();
        pending
            .saturating_mul(PENDING_COST)
            .saturating_add(connected)
            .saturating_add(cached_open)
    }

    /// Read charges before the cached sample to pair with sample publication.
    fn usage_components(&self) -> (u64, u64) {
        // Load order is part of the publication protocol: observing a charge
        // dropped by the sampler must also expose the new cached sample.
        let connected = self.connected.load(Ordering::Acquire);
        let cached_open = self.cached_open.load(Ordering::Relaxed);
        (connected, cached_open)
    }

    /// Transfer a claim to a connected charge, or release it on reuse/drop.
    #[inline]
    pub(super) fn settle(&self, new_socket: bool) {
        if new_socket {
            self.connected.fetch_add(CONNECT_COST, Ordering::Release);
        }
        self.pending.fetch_sub(1, Ordering::Release);
    }

    /// Publish one sample and preserve charges added while `count` runs.
    pub(super) fn sample_with<C: FnOnce() -> Option<u64>>(&self, count: C) {
        let absorbed = self.connected.load(Ordering::Relaxed);
        if let Some(open) = count() {
            self.cached_open.store(open, Ordering::Relaxed);
            _ = self
                .connected
                .fetch_update(Ordering::Release, Ordering::Relaxed, |charged| {
                    Some(charged.saturating_sub(absorbed))
                });
        }
    }
}

#[cfg(test)]
impl FdAtomic for loom::sync::atomic::AtomicU64 {
    fn load(&self, order: Ordering) -> u64 {
        loom::sync::atomic::AtomicU64::load(self, order)
    }

    fn store(&self, value: u64, order: Ordering) {
        loom::sync::atomic::AtomicU64::store(self, value, order);
    }

    fn fetch_add(&self, value: u64, order: Ordering) -> u64 {
        loom::sync::atomic::AtomicU64::fetch_add(self, value, order)
    }

    fn fetch_sub(&self, value: u64, order: Ordering) -> u64 {
        loom::sync::atomic::AtomicU64::fetch_sub(self, value, order)
    }

    fn fetch_update<F>(&self, set_order: Ordering, fetch_order: Ordering, update: F) -> Result<u64, u64>
    where
        F: FnMut(u64) -> Option<u64>,
    {
        loom::sync::atomic::AtomicU64::fetch_update(self, set_order, fetch_order, update)
    }
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "test assertion policy")]
#[allow(clippy::expect_used, reason = "a failed model thread must fail the test")]
mod loom_tests {
    use loom::{
        sync::{Arc, atomic::AtomicU64},
        thread,
    };

    use super::*;

    /// Loom-owned counters shared between the modeled threads.
    #[derive(Clone)]
    struct Counts {
        /// Cached open descriptors.
        cached_open: Arc<AtomicU64>,
        /// Unabsorbed connection charges.
        connected: Arc<AtomicU64>,
        /// Pending admission claims.
        pending: Arc<AtomicU64>,
    }

    impl Counts {
        /// Start one model execution with known counter values.
        fn new(cached_open: u64, connected: u64, pending: u64) -> Self {
            Self {
                cached_open: Arc::new(AtomicU64::new(cached_open)),
                connected: Arc::new(AtomicU64::new(connected)),
                pending: Arc::new(AtomicU64::new(pending)),
            }
        }

        /// Run the production accounting methods on Loom atomics.
        fn accounting(&self) -> Accounting<'_, AtomicU64> {
            Accounting::new(&self.cached_open, &self.connected, &self.pending)
        }
    }

    #[test]
    fn concurrent_admissions_fit_one_slot() {
        loom::model(|| {
            let counts = Counts::new(190, 0, 0);
            let other = counts.clone();
            let second = thread::spawn(move || other.accounting().try_admit(192));
            let first = counts.accounting().try_admit(192);
            let second = second.join().expect("second admission thread completes");
            assert_eq!(u8::from(first) + u8::from(second), 1, "only one claim fits");
        });
    }

    #[test]
    fn settling_a_new_socket_never_frees_a_slot() {
        loom::model(|| {
            let counts = Counts::new(190, 0, 1);
            let other = counts.clone();
            let settlement = thread::spawn(move || other.accounting().settle(true));
            assert!(
                !counts.accounting().try_admit(192),
                "a pending claim becoming a connection charge does not free a slot"
            );
            settlement.join().expect("settlement thread completes");
        });
    }

    #[test]
    fn sample_publication_never_combines_old_open_with_dropped_charges() {
        loom::model(|| {
            let counts = Counts::new(100, 2, 0);
            let other = counts.clone();
            let sampler = thread::spawn(move || other.accounting().sample_with(|| Some(102)));
            let predicted = counts.accounting().predicted_with(0);
            assert!(predicted >= 102, "sample publication undercounted: {predicted}");
            sampler.join().expect("sampler thread completes");
        });
    }

    #[test]
    fn connection_update_preserves_sample_release_sequence() {
        loom::model(|| {
            let counts = Counts::new(100, 1, 1);
            let sampler_counts = counts.clone();
            let settler_counts = counts.clone();
            let sampler = thread::spawn(move || sampler_counts.accounting().sample_with(|| Some(120)));
            let settler = thread::spawn(move || settler_counts.accounting().settle(true));
            let (connected, cached_open) = counts.accounting().usage_components();
            if connected == 2 {
                assert_eq!(
                    cached_open, 120,
                    "a charge extending the sampler's release sequence publishes the new sample"
                );
            }
            sampler.join().expect("sample thread completes");
            settler.join().expect("settlement thread completes");
        });
    }
}
