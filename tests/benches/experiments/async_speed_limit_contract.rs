// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Standalone evaluation; see docs/developing/bandwidth-scheduler.md.
//! Tests assert observed behavior, including explicitly named counterexamples.
//! A green run means observations reproduced, not that the crate meets every contract.

#![allow(
    dead_code,
    reason = "the production module is imported unchanged for its contract tests"
)]

#[path = "../../../crates/filter/src/bandwidth/schedule.rs"]
mod praxis_schedule;

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Waker},
    time::Duration,
};

use async_speed_limit::{
    Limiter,
    clock::{ManualClock, Nanoseconds},
    limiter::Consume,
};

/// Only configuration, deferred activation, and accepted-byte accounting.
#[derive(Clone)]
struct Adapter(Limiter<ManualClock>);

impl Adapter {
    fn burst() -> Self {
        Self(
            Limiter::builder(16_384.0)
                .refill(Duration::from_secs(1))
                .min_wait(Duration::ZERO)
                .build(),
        )
    }

    /// Give the crate its smallest positive refill and matching min_wait.
    /// At ordinary rates this cancels its fractional-byte burst when waiting.
    fn zero(rate: f64) -> Self {
        Self(
            Limiter::builder(rate)
                .refill(Duration::from_nanos(1))
                .min_wait(Duration::from_nanos(1))
                .build(),
        )
    }

    fn prepare(&self, bytes: usize) -> Plan {
        Plan {
            owner: self.clone(),
            bytes,
        }
    }

    fn at(&self, nanos: u64) {
        self.0.clock().set_time(Nanoseconds(nanos));
    }
}

/// No debit until activate, just as with Schedule::prepare.
struct Plan {
    owner: Adapter,
    bytes: usize,
}

impl Plan {
    fn activate(self) -> Grant {
        let wait = self.owner.0.consume(self.bytes);
        Grant {
            owner: self.owner,
            bytes: self.bytes,
            wait,
        }
    }
}

/// RAII owns the crate reservation and its original absolute sleep future.
struct Grant {
    owner: Adapter,
    bytes: usize,
    wait: Consume<ManualClock, ()>,
}

impl Grant {
    fn ready(&mut self) -> bool {
        Pin::new(&mut self.wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    }

    fn settle(mut self, accepted: usize) {
        assert!(accepted <= self.bytes);
        self.owner.0.unconsume(self.bytes - accepted);
        self.bytes = 0;
    }
}

impl Drop for Grant {
    fn drop(&mut self) {
        self.owner.0.unconsume(self.bytes);
    }
}

#[test]
fn partial_write_new_sibling_reuses_twelve_kib_immediately() {
    let owner = Adapter::burst();
    let mut first = owner.prepare(16_384).activate();
    assert!(first.ready());
    first.settle(4_096);
    let mut second = owner.prepare(12_288).activate();
    assert!(second.ready());
    second.settle(12_288);
    assert_eq!(owner.0.total_bytes_consumed(), 16_384);
}

#[test]
fn partial_write_existing_sibling_keeps_obsolete_sleep() {
    let owner = Adapter::burst();
    let mut first = owner.prepare(16_384).activate();
    assert!(first.ready());
    let mut second = owner.prepare(12_288).activate();
    assert!(!second.ready());
    first.settle(4_096);
    assert!(!second.ready(), "refund does not re-evaluate the existing future");
    owner.at(749_999_999);
    assert!(!second.ready());
    owner.at(750_000_000);
    assert!(second.ready());
}

#[test]
fn configured_positive_burst_and_refill_work() {
    let owner = Adapter::burst();
    let mut first = owner.prepare(16_384).activate();
    assert!(first.ready());
    first.settle(16_384);
    owner.at(1_000_000_000);
    let mut next = owner.prepare(16_384).activate();
    assert!(next.ready());
    next.settle(16_384);
    assert!(!owner.prepare(1).activate().ready());
}

#[test]
fn cancelling_pre_refill_reservation_produces_second_burst() {
    let owner = Adapter::burst();
    let mut old = owner.prepare(16_384).activate();
    assert!(old.ready());
    owner.at(2_000_000_000);
    let mut current = owner.prepare(16_384).activate();
    assert!(current.ready());
    drop(old);
    current.settle(16_384);
    assert!(
        owner.prepare(16_384).activate().ready(),
        "an extra burst is admitted at the same instant"
    );
}

#[test]
fn delayed_partial_settlement_can_accept_twenty_four_kib_at_once() {
    let owner = Adapter::burst();
    let mut first = owner.prepare(16_384).activate();
    assert!(first.ready());
    owner.at(1_000_000_000);
    let mut sibling = owner.prepare(4_096).activate();
    assert!(sibling.ready());
    sibling.settle(4_096);
    first.settle(4_096);
    let mut extra = owner.prepare(16_384).activate();
    assert!(extra.ready());
    extra.settle(16_384);
    assert_eq!(owner.0.total_bytes_consumed(), 24_576);
}

#[test]
#[should_panic(expected = "refill duration must not be zero")]
fn literal_zero_refill_is_rejected() {
    Limiter::<ManualClock>::builder(1_000.0).refill(Duration::ZERO);
}

#[test]
fn tiny_refill_zero_burst_workaround_paces_ordinary_rates_after_idle() {
    let owner = Adapter::zero(1_000.0);
    let mut first = owner.prepare(1).activate();
    assert!(!first.ready());
    owner.at(1_000_000);
    assert!(first.ready());
    first.settle(1);
    owner.at(5_000_000_000);
    let mut later = owner.prepare(1).activate();
    assert!(!later.ready());
    owner.at(5_001_000_000);
    assert!(later.ready());
}

#[test]
fn tiny_refill_zero_burst_workaround_gives_free_byte_at_high_rate() {
    let owner = Adapter::zero(2_000_000_000.0);
    let mut first = owner.prepare(1).activate();
    assert!(first.ready(), "one nanosecond now holds two bytes of initial credit");
}

#[test]
fn repeated_resets_leave_neither_banked_credit_nor_debt_at_ordinary_rate() {
    let owner = Adapter::zero(1_000.0);
    for attempt in 0..4 {
        let first = owner.prepare(500).activate();
        let later = owner.prepare(500).activate();
        owner.at((attempt + 1) * 2_000_000_000);
        drop(first);
        drop(later);
        assert_eq!(owner.0.total_bytes_consumed(), 0);
    }
    let mut next = owner.prepare(1).activate();
    assert!(!next.ready());
    owner.at(8_001_000_000);
    assert!(next.ready());
}

#[test]
fn repeated_burst_resets_leave_only_one_fresh_burst() {
    let owner = Adapter::burst();
    for attempt in 0..4 {
        let first = owner.prepare(16_384).activate();
        let later = owner.prepare(16_384).activate();
        owner.at((attempt + 1) * 2_000_000_000);
        drop(first);
        drop(later);
        assert_eq!(owner.0.total_bytes_consumed(), 0);
    }
    let mut next = owner.prepare(16_384).activate();
    assert!(next.ready());
    next.settle(16_384);
    assert!(!owner.prepare(1).activate().ready());
}

#[test]
fn earlier_cancellation_preserves_later_captured_deadline() {
    let owner = Adapter::zero(1_000.0);
    let first = owner.prepare(500).activate();
    let mut later = owner.prepare(500).activate();
    assert!(!later.ready());
    drop(first);
    owner.at(500_000_000);
    assert!(!later.ready(), "the cancelled 500 ms is still in the captured future");
    owner.at(1_000_000_000);
    assert!(later.ready());
    // Like Schedule's conservative outstanding-reservation model, the older
    // cancellation does not move this captured deadline. Cancelling both must
    // nevertheless leave no debt for the next reservation.
    drop(later);
    let mut next = owner.prepare(1).activate();
    assert!(!next.ready());
    owner.at(1_001_000_000);
    assert!(next.ready());
}

#[test]
fn unactivated_plans_do_not_debit_budget() {
    let owner = Adapter::burst();
    let first = owner.prepare(16_384);
    let second = owner.prepare(16_384);
    assert_eq!(owner.0.total_bytes_consumed(), 0);
    assert!(owner.prepare(16_384).activate().ready(), "live plans hold no budget");
    drop(first);
    drop(second);
    assert!(owner.prepare(16_384).activate().ready());
}

#[test]
fn owned_future_accounts_for_elapsed_dns_time() {
    let owner = Adapter::zero(1_000.0);
    let mut first = owner.prepare(1_000).activate();
    owner.at(600_000_000);
    assert!(!first.ready());
    owner.at(1_000_000_000);
    assert!(first.ready(), "only 400 ms remained after the DNS interval");
}

#[test]
fn deferring_activation_until_after_dns_starts_a_new_full_delay() {
    let owner = Adapter::zero(1_000.0);
    let plan = owner.prepare(1_000);
    assert_eq!(owner.0.total_bytes_consumed(), 0);
    owner.at(600_000_000);
    let mut first = plan.activate();
    owner.at(1_000_000_000);
    assert!(
        !first.ready(),
        "the no-debit plan's original timestamp is not retained by the crate"
    );
    owner.at(1_600_000_000);
    assert!(first.ready());
}
