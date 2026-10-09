// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Hedge budget for speculative upstream attempts.
//!
//! A hedge is an extra copy of a request, sent while an earlier attempt
//! may still be running. This budget caps those copies as a fraction of
//! the requests observed on the route so a slow cluster cannot be amplified
//! without bound. The first attempt is never charged; only copies are.

use std::sync::atomic::{AtomicU64, Ordering};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Parts-per-10_000 scale. `10%` is `1_000`; `100%` is `10_000`.
const BPS_SCALE: u64 = 10_000;

/// One basis point, in percent. This is the finest budget the counter can store.
const PERCENT_STEP: f64 = 0.01;

/// How far a percent may sit from a basis-point boundary and still be that boundary.
///
/// Half a step is `0.005`. Anything looser would accept a percent the counter
/// cannot store, which is the rounding this check exists to reject.
const PERCENT_STEP_EPSILON: f64 = 1e-4;

// -----------------------------------------------------------------------------
// HedgeBudget
// -----------------------------------------------------------------------------

/// Shared admission counter for one route's hedge policy.
///
/// `try_admit` allows another hedge while
/// `hedges / requests < budget_percent / 100`. The check uses integer
/// basis points so concurrent callers cannot drift the ratio with float
/// rounding. Counters are monotonic for the life of the policy (a config
/// reload builds a new budget).
#[derive(Debug)]
pub struct HedgeBudget {
    /// Client requests counted against this policy.
    requests: AtomicU64,
    /// Hedge copies admitted (not the primary attempt).
    hedges: AtomicU64,
    /// Budget in basis points, `0..=10_000`.
    bps: u64,
}

impl HedgeBudget {
    /// Build a budget for `percent` in `0.0..=100.0`.
    ///
    /// `percent` must be a multiple of `0.01` (one basis point).
    /// A finer value, and a non-finite value, is rejected. The stored budget
    /// is then the percent that was requested.
    ///
    /// # Errors
    ///
    /// Returns an error when `percent` is non-finite, outside `0.0..=100.0`,
    /// or not a multiple of `0.01`.
    pub fn try_new(percent: f64) -> Result<Self, String> {
        Ok(Self {
            requests: AtomicU64::new(0),
            hedges: AtomicU64::new(0),
            bps: percent_to_bps(percent)?,
        })
    }

    /// Count one client request toward the denominator.
    pub fn note_request(&self) {
        self.requests.fetch_add(1, Ordering::Release);
    }

    /// Undo one [`try_admit`](Self::try_admit) that did not start an attempt.
    ///
    /// Selection can fail after admission (no distinct healthy endpoint).
    /// The copy was never sent, so it must not consume the budget.
    pub fn revert_admission(&self) {
        let mut hedges = self.hedges.load(Ordering::Relaxed);
        while hedges > 0 {
            match self.hedges.compare_exchange_weak(
                hedges,
                hedges.saturating_sub(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => hedges = observed,
            }
        }
    }

    /// Try to admit one hedge copy.
    ///
    /// Returns `false` when the configured fraction is already used, including
    /// when the percent is zero.
    pub fn try_admit(&self) -> bool {
        if self.bps == 0 {
            return false;
        }
        let mut hedges = self.hedges.load(Ordering::Relaxed);
        loop {
            let requests = self.requests.load(Ordering::Acquire);
            let used = hedges.saturating_mul(BPS_SCALE);
            let allowed = requests.saturating_mul(self.bps);
            if used >= allowed {
                return false;
            }
            match self.hedges.compare_exchange_weak(
                hedges,
                hedges.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => hedges = observed,
            }
        }
    }

    /// Admitted hedge copies. For tests.
    #[cfg(test)]
    fn hedges(&self) -> u64 {
        self.hedges.load(Ordering::Relaxed)
    }

    /// Stored basis points. For tests.
    #[cfg(test)]
    pub(crate) fn bps(&self) -> u64 {
        self.bps
    }
}

// -----------------------------------------------------------------------------
// Response status
// -----------------------------------------------------------------------------

/// A final HTTP status the proxy can return to the client.
///
/// `2xx`, `3xx`, and `4xx` are success: the attempt produced an application
/// response. `5xx` is not, so a peer that is still running may still win.
#[must_use]
pub fn status_is_success(status: u16) -> bool {
    (200..500).contains(&status)
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Map a percent to basis points.
///
/// The percent must already be an integer number of [`PERCENT_STEP`]s.
/// Rounding is not applied: `0.005` is an error, not `0.01`.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the percent is finite and on a 0.01 boundary before the cast"
)]
fn percent_to_bps(percent: f64) -> Result<u64, String> {
    if !percent.is_finite() {
        return Err(format!("hedge_policy: budget_percent must be finite, got {percent}"));
    }
    if !(0.0..=100.0).contains(&percent) {
        return Err(format!(
            "hedge_policy: budget_percent must be in 0.0..=100.0, got {percent}"
        ));
    }
    let steps = percent / PERCENT_STEP;
    let rounded = steps.round();
    if !rounded.is_finite() || (steps - rounded).abs() > PERCENT_STEP_EPSILON {
        return Err(format!(
            "hedge_policy: budget_percent must be a multiple of 0.01, got {percent}"
        ));
    }
    if rounded >= 10_000.0 {
        return Ok(BPS_SCALE);
    }
    if rounded <= 0.0 {
        return Ok(0);
    }
    Ok(rounded as u64)
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
    fn zero_percent_admits_nothing() {
        let budget = HedgeBudget::try_new(0.0).unwrap();
        budget.note_request();
        assert!(!budget.try_admit(), "0% must not admit a hedge");
        assert_eq!(budget.hedges(), 0);
    }

    #[test]
    fn first_request_can_hedge_when_percent_is_positive() {
        let budget = HedgeBudget::try_new(10.0).unwrap();
        budget.note_request();
        assert!(budget.try_admit(), "the first request starts under the ratio");
        assert!(!budget.try_admit(), "a second copy on the same request exceeds 10%");
    }

    #[test]
    fn ten_percent_sustains_one_hedge_per_ten_requests() {
        let budget = HedgeBudget::try_new(10.0).unwrap();
        let mut admitted = 0_u32;
        for _ in 0..20 {
            budget.note_request();
            if budget.try_admit() {
                admitted = admitted.saturating_add(1);
            }
        }
        assert_eq!(admitted, 2, "20 requests at 10% admit 2 hedges, got {admitted}");
    }

    #[test]
    fn one_hundred_percent_allows_one_hedge_per_request() {
        let budget = HedgeBudget::try_new(100.0).unwrap();
        for _ in 0..5 {
            budget.note_request();
            assert!(budget.try_admit(), "100% allows one hedge per counted request");
            assert!(!budget.try_admit(), "100% does not allow two hedges on one request");
        }
        assert_eq!(budget.hedges(), 5);
    }

    #[test]
    fn reverted_admission_can_be_used_again() {
        let budget = HedgeBudget::try_new(10.0).unwrap();
        budget.note_request();
        assert!(budget.try_admit(), "the first copy is under 10%");
        budget.revert_admission();
        assert_eq!(budget.hedges(), 0, "a copy that was not sent is not charged");
        assert!(budget.try_admit(), "the reverted slot is available");
        assert!(!budget.try_admit(), "only one copy is under 10% for one request");
    }

    #[test]
    fn rejects_non_finite_and_finer_than_one_basis_point() {
        let non_finite = HedgeBudget::try_new(f64::NAN).unwrap_err();
        assert!(non_finite.contains("finite"), "{non_finite}");

        let half = HedgeBudget::try_new(0.005).unwrap_err();
        assert!(half.contains("multiple of 0.01"), "{half}");

        let tenth = HedgeBudget::try_new(0.001).unwrap_err();
        assert!(tenth.contains("multiple of 0.01"), "{tenth}");

        let one = HedgeBudget::try_new(0.01).unwrap();
        assert_eq!(one.bps(), 1, "0.01% is one basis point");
    }

    #[test]
    fn success_statuses_are_non_5xx_final_responses() {
        assert!(status_is_success(200));
        assert!(status_is_success(204));
        assert!(status_is_success(302));
        assert!(status_is_success(404));
        assert!(status_is_success(429));
        assert!(!status_is_success(500));
        assert!(!status_is_success(503));
        assert!(!status_is_success(101), "a 1xx is not a final response");
        assert!(!status_is_success(100));
    }
}
