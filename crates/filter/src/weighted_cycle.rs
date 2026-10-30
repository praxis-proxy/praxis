// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Weighted round-robin cursor and bucket selection.
//!
//! This is a crate-level primitive shared by two layers: endpoint strategies
//! (`load_balancing`) and route-target selection (`router`). A monotonically
//! increasing slot modulo the candidate weight total is resolved against
//! cumulative weight buckets. Keeping it outside `load_balancing` makes the
//! layering explicit: the router selects a cluster, the load balancer selects
//! an endpoint, and neither owns the other's module.

use std::sync::atomic::{AtomicU64, Ordering};

// -----------------------------------------------------------------------------
// WeightedCycle
// -----------------------------------------------------------------------------

/// A monotonic cursor for weighted round-robin selection.
///
/// The cursor is cache-line aligned so adjacent tiers do not share its line.
/// A single atomic still serializes its own tier's writers; sharding the cursor
/// per worker remains a benchmark-driven follow-up rather than a speculative
/// change to the distribution.
#[derive(Debug, Default)]
#[repr(align(64))]
pub(crate) struct WeightedCycle {
    /// Number of selection turns taken so far.
    counter: AtomicU64,
}

impl WeightedCycle {
    /// Create a cycle starting at slot zero.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Advance the cycle and return the raw turn number.
    ///
    /// Callers reduce it modulo their current candidate weight total, which can
    /// change with health. Reducing here instead would bias redistribution when
    /// the configured total is not a multiple of the healthy total.
    pub(crate) fn next(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }
}

// -----------------------------------------------------------------------------
// Bucket Selection
// -----------------------------------------------------------------------------

/// Return the candidate whose cumulative weight bucket contains `slot`.
///
/// `candidates` yields `(candidate, weight)` in configuration order. `slot`
/// must be less than the sum of the yielded weights; a slot outside that range
/// returns `None`. Returning the candidate itself rather than an index lets
/// callers keep their own row representation without a second lookup.
pub(crate) fn pick_weighted<T, I>(slot: u64, candidates: I) -> Option<T>
where
    I: IntoIterator<Item = (T, u64)>,
{
    let mut remaining = slot;
    for (candidate, weight) in candidates {
        if remaining < weight {
            return Some(candidate);
        }
        remaining = remaining.saturating_sub(weight);
    }
    None
}

/// Total weight of the candidates `eligible` accepts.
fn eligible_weight<T, I, F>(candidates: I, eligible: F) -> u64
where
    T: Copy,
    I: IntoIterator<Item = (T, u64)>,
    F: Fn(T) -> bool,
{
    candidates
        .into_iter()
        .filter(|(candidate, _)| eligible(*candidate))
        .fold(0_u64, |total, (_, weight)| total.saturating_add(weight))
}

/// Pick a candidate from `candidates`, considering only entries `eligible`
/// accepts.
///
/// `tick` is the raw round-robin turn, reduced modulo the eligible weight total
/// here so a health change redistributes without biasing the cycle. `candidates`
/// is iterated twice, so pass a cheaply cloneable iterator (a slice iterator or
/// `iter().copied()`).
pub(crate) fn pick_weighted_matching<T, I, F>(tick: u64, candidates: I, eligible: F) -> Option<T>
where
    T: Copy,
    I: IntoIterator<Item = (T, u64)> + Clone,
    F: Fn(T) -> bool,
{
    let total = eligible_weight(candidates.clone(), &eligible);
    if total == 0 {
        return None;
    }
    let slot = tick.checked_rem(total)?;
    pick_weighted(
        slot,
        candidates.into_iter().filter(|(candidate, _)| eligible(*candidate)),
    )
}

/// Advance `cycle` and pick an eligible candidate.
///
/// Unlike [`pick_weighted_matching`], this does not consume a turn when no
/// candidate is eligible, so a health-gated caller can probe a tier before
/// falling back to panic mode without shifting that tier's rotation.
pub(crate) fn pick_weighted_cycle<T, I, F>(cycle: &WeightedCycle, candidates: I, eligible: F) -> Option<T>
where
    T: Copy,
    I: IntoIterator<Item = (T, u64)> + Clone,
    F: Fn(T) -> bool,
{
    let total = eligible_weight(candidates.clone(), &eligible);
    if total == 0 {
        return None;
    }
    let slot = cycle.next().checked_rem(total)?;
    pick_weighted(
        slot,
        candidates.into_iter().filter(|(candidate, _)| eligible(*candidate)),
    )
}

/// Advance `cycle` over a pre-computed weight total, with no eligibility pass.
///
/// Use this when every candidate is known to be eligible (no health gating, or
/// panic mode). It avoids the two candidate scans [`pick_weighted_cycle`]
/// needs to recompute the eligible total.
pub(crate) fn pick_weighted_cycle_unfiltered<T, I>(cycle: &WeightedCycle, total: u64, candidates: I) -> Option<T>
where
    I: IntoIterator<Item = (T, u64)>,
{
    if total == 0 {
        return None;
    }
    let slot = cycle.next().checked_rem(total)?;
    pick_weighted(slot, candidates)
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
    fn cycle_advances_one_turn_at_a_time() {
        let cycle = WeightedCycle::new();
        let turns: Vec<u64> = std::iter::repeat_with(|| cycle.next()).take(4).collect();
        assert_eq!(turns, vec![0, 1, 2, 3], "the cursor is monotonic");
    }

    #[test]
    fn bucket_picks_the_configured_share() {
        let candidates = [(0, 9_u64), (1, 1_u64)];
        let stable = (0..10)
            .filter(|slot| pick_weighted(*slot, candidates) == Some(0))
            .count();
        assert_eq!(stable, 9, "the first candidate owns 9 of 10 slots");
    }

    #[test]
    fn slot_past_the_total_selects_nothing() {
        assert_eq!(
            pick_weighted(9, [(0, 1_u64), (1, 1_u64)]),
            None,
            "a slot outside the cumulative total is invalid"
        );
    }

    #[test]
    fn matching_skips_ineligible_candidates() {
        let candidates = [(0, 5_u64), (1, 1_u64), (2, 1_u64)];
        let picks: Vec<usize> = (0..7)
            .filter_map(|tick| pick_weighted_matching(tick, candidates, |index| index != 0))
            .collect();
        assert_eq!(
            picks,
            vec![1, 2, 1, 2, 1, 2, 1],
            "only the eligible candidates share the cycle"
        );
    }

    #[test]
    fn matching_without_eligible_candidates_selects_nothing() {
        assert_eq!(
            pick_weighted_matching(3, [(0, 1_u64), (1, 1_u64)], |_| false),
            None,
            "an empty eligible set cannot select"
        );
    }

    #[test]
    fn failed_cycle_attempt_does_not_consume_a_turn() {
        let cycle = WeightedCycle::new();
        assert_eq!(
            pick_weighted_cycle(&cycle, [(0, 1_u64), (1, 1_u64)], |_| false),
            None,
            "no eligible candidate means no selection"
        );
        assert_eq!(
            pick_weighted_cycle(&cycle, [(0, 1_u64), (1, 1_u64)], |_| true),
            Some(0),
            "the failed attempt must not shift the rotation"
        );
    }
}
