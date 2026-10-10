// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Per-route hedged-request policy.
//!
//! Hedging races one client request against more than one healthy endpoint
//! in the same cluster and returns the first successful response. The
//! primary attempt is always sent. Further attempts are either part of the
//! initial fan-out or are started after [`HedgePolicy::per_try_timeout_ms`]
//! while no attempt has succeeded.

use std::{sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};

use crate::hedge::{HedgeBudget, HedgeRace};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Hard cap on attempts for one client request, including the primary.
///
/// Each attempt is a live upstream exchange. The cap keeps a configuration
/// typo from opening an unbounded number of connections.
pub const MAX_HEDGE_ATTEMPTS: u32 = 8;

// -----------------------------------------------------------------------------
// HedgePolicy
// -----------------------------------------------------------------------------

/// How a route races upstream attempts.
///
/// ```
/// use praxis_core::config::HedgePolicy;
///
/// let policy: HedgePolicy = serde_yaml::from_str(
///     r#"
/// initial_requests: 1
/// max_attempts: 2
/// per_try_timeout_ms: 50
/// budget_percent: 10
/// "#,
/// )
/// .unwrap();
/// assert_eq!(policy.initial_requests(), 1);
/// assert_eq!(policy.max_attempts(), 2);
/// assert_eq!(policy.per_try_timeout_ms(), Some(50));
/// ```
///
/// Fan-out omits the timeout because every attempt starts immediately:
///
/// ```
/// use praxis_core::config::HedgePolicy;
///
/// let policy: HedgePolicy = serde_yaml::from_str(
///     r#"
/// initial_requests: 2
/// max_attempts: 2
/// budget_percent: 100
/// "#,
/// )
/// .unwrap();
/// assert!(policy.per_try_timeout_ms().is_none());
/// ```
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "HedgePolicyRaw")]
pub struct HedgePolicy {
    /// Attempts started immediately, including the primary. At least 1.
    initial_requests: u32,

    /// Total attempts for one client request, including the primary.
    max_attempts: u32,

    /// Delay before each attempt beyond `initial_requests`, in milliseconds.
    ///
    /// Required when `max_attempts` is greater than `initial_requests`.
    /// Absent when every attempt is part of the initial fan-out.
    #[serde(skip_serializing_if = "Option::is_none")]
    per_try_timeout_ms: Option<u64>,

    /// Maximum hedge copies as a percent of requests on this route.
    budget_percent: f64,

    /// Admission state shared by every request that uses this policy.
    #[serde(skip)]
    budget: Arc<HedgeBudget>,
}

/// YAML shape for [`HedgePolicy`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HedgePolicyRaw {
    /// Attempts started immediately, including the primary.
    ///
    /// `1` sends the primary and waits for `per_try_timeout_ms` before any
    /// copy. Values greater than 1 fan out that many attempts at once.
    initial_requests: u32,

    /// Total attempts for one client request, including the primary.
    ///
    /// Must be at least `initial_requests` and at most 8.
    max_attempts: u32,

    /// Milliseconds to wait, with no successful response, before starting
    /// the next attempt.
    ///
    /// Required when `max_attempts` is greater than `initial_requests`.
    /// Must be omitted when they are equal.
    #[serde(default)]
    per_try_timeout_ms: Option<u64>,

    /// Cap on hedge copies as a percent of requests on this route (`0.0..=100.0`).
    ///
    /// The percent must be a multiple of `0.01` (one basis point). A finer
    /// value is rejected so the loaded percent is the percent that is enforced.
    /// The primary attempt is not counted. `0` disables copies. While no copy
    /// is in flight, any positive budget admits one, so a single active
    /// request can still hedge. Further copies stay under the percent: `10`
    /// keeps about one extra attempt per ten active requests.
    budget_percent: f64,
}

impl HedgePolicy {
    /// Attempts started immediately, including the primary.
    #[must_use]
    pub fn initial_requests(&self) -> u32 {
        self.initial_requests
    }

    /// Total attempts for one client request, including the primary.
    #[must_use]
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Delay before each attempt beyond the initial fan-out, in milliseconds.
    #[must_use]
    pub fn per_try_timeout_ms(&self) -> Option<u64> {
        self.per_try_timeout_ms
    }

    /// [`per_try_timeout_ms`](Self::per_try_timeout_ms) as a [`Duration`].
    #[must_use]
    pub fn per_try_timeout(&self) -> Option<Duration> {
        self.per_try_timeout_ms.map(Duration::from_millis)
    }

    /// Shared budget for copies started by this policy.
    #[must_use]
    pub fn budget(&self) -> &HedgeBudget {
        &self.budget
    }

    /// Race for one client request on this route.
    ///
    /// The race shares this policy's budget, so every request on the route
    /// counts against the same cap.
    #[must_use]
    pub fn start_race(&self) -> HedgeRace {
        HedgeRace::new(
            self.initial_requests,
            self.max_attempts,
            self.per_try_timeout(),
            Arc::clone(&self.budget),
        )
    }
}

impl TryFrom<HedgePolicyRaw> for HedgePolicy {
    type Error = String;

    fn try_from(raw: HedgePolicyRaw) -> Result<Self, Self::Error> {
        validate_counts(raw.initial_requests, raw.max_attempts, "hedge_policy")?;
        validate_timeout(
            raw.initial_requests,
            raw.max_attempts,
            raw.per_try_timeout_ms,
            "hedge_policy",
        )?;
        let budget = HedgeBudget::try_new(raw.budget_percent)?;
        Ok(Self {
            initial_requests: raw.initial_requests,
            max_attempts: raw.max_attempts,
            per_try_timeout_ms: raw.per_try_timeout_ms,
            budget_percent: raw.budget_percent,
            budget: Arc::new(budget),
        })
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Check attempt counts.
fn validate_counts(initial_requests: u32, max_attempts: u32, context: &str) -> Result<(), String> {
    if initial_requests == 0 {
        return Err(format!(
            "{context}: initial_requests is 0 (must be >= 1; the primary attempt is included)"
        ));
    }
    if max_attempts > MAX_HEDGE_ATTEMPTS {
        return Err(format!(
            "{context}: max_attempts is {max_attempts} (must be <= {MAX_HEDGE_ATTEMPTS})"
        ));
    }
    if initial_requests > max_attempts {
        return Err(format!(
            "{context}: initial_requests ({initial_requests}) is greater than max_attempts ({max_attempts})"
        ));
    }
    Ok(())
}

/// Check the timeout against the fan-out shape.
fn validate_timeout(
    initial_requests: u32,
    max_attempts: u32,
    per_try_timeout_ms: Option<u64>,
    context: &str,
) -> Result<(), String> {
    if max_attempts > initial_requests {
        return validate_trigger_timeout(initial_requests, max_attempts, per_try_timeout_ms, context);
    }
    if per_try_timeout_ms.is_some() {
        return Err(format!(
            "{context}: per_try_timeout_ms is set but max_attempts equals initial_requests \
             ({max_attempts}); omit it for an immediate fan-out, or raise max_attempts to start \
             further attempts after the timeout"
        ));
    }
    Ok(())
}

/// A timeout is required, and must sit inside the cluster timeout ceiling.
fn validate_trigger_timeout(
    initial_requests: u32,
    max_attempts: u32,
    per_try_timeout_ms: Option<u64>,
    context: &str,
) -> Result<(), String> {
    let Some(timeout_ms) = per_try_timeout_ms else {
        return Err(format!(
            "{context}: per_try_timeout_ms is required when max_attempts ({max_attempts}) \
             is greater than initial_requests ({initial_requests})"
        ));
    };
    if timeout_ms == 0 {
        return Err(format!("{context}: per_try_timeout_ms is 0 (must be > 0)"));
    }
    if timeout_ms > super::validate::cluster::MAX_TIMEOUT_MS {
        return Err(format!(
            "{context}: per_try_timeout_ms ({timeout_ms} ms) exceeds maximum ({} ms / 1 hour)",
            super::validate::cluster::MAX_TIMEOUT_MS
        ));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_assert_message,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn parses_timeout_trigger() {
        let policy: HedgePolicy = serde_yaml::from_str(
            r#"
initial_requests: 1
max_attempts: 3
per_try_timeout_ms: 40
budget_percent: 5.5
"#,
        )
        .unwrap();
        assert_eq!(policy.initial_requests(), 1);
        assert_eq!(policy.max_attempts(), 3);
        assert_eq!(policy.per_try_timeout(), Some(Duration::from_millis(40)));
    }

    #[test]
    fn rejects_zero_initial_requests() {
        let err = serde_yaml::from_str::<HedgePolicy>(
            r#"
initial_requests: 0
max_attempts: 1
budget_percent: 10
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("initial_requests is 0"), "{err}");
    }

    #[test]
    fn rejects_initial_above_max() {
        let err = serde_yaml::from_str::<HedgePolicy>(
            r#"
initial_requests: 3
max_attempts: 2
per_try_timeout_ms: 10
budget_percent: 10
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("greater than max_attempts"), "{err}");
    }

    #[test]
    fn rejects_attempt_cap() {
        let err = serde_yaml::from_str::<HedgePolicy>(
            r#"
initial_requests: 1
max_attempts: 9
per_try_timeout_ms: 10
budget_percent: 10
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("max_attempts is 9"), "{err}");
    }

    #[test]
    fn rejects_missing_timeout_when_more_attempts_remain() {
        let err = serde_yaml::from_str::<HedgePolicy>(
            r#"
initial_requests: 1
max_attempts: 2
budget_percent: 10
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("per_try_timeout_ms is required"), "{err}");
    }

    #[test]
    fn rejects_timeout_on_pure_fan_out() {
        let err = serde_yaml::from_str::<HedgePolicy>(
            r#"
initial_requests: 2
max_attempts: 2
per_try_timeout_ms: 10
budget_percent: 10
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("omit it"), "{err}");
    }

    #[test]
    fn rejects_zero_timeout_and_over_ceiling() {
        let zero = serde_yaml::from_str::<HedgePolicy>(
            r#"
initial_requests: 1
max_attempts: 2
per_try_timeout_ms: 0
budget_percent: 10
"#,
        )
        .unwrap_err();
        assert!(zero.to_string().contains("per_try_timeout_ms is 0"), "{zero}");

        let huge = serde_yaml::from_str::<HedgePolicy>(
            r#"
initial_requests: 1
max_attempts: 2
per_try_timeout_ms: 3600001
budget_percent: 10
"#,
        )
        .unwrap_err();
        assert!(huge.to_string().contains("exceeds maximum"), "{huge}");
    }

    #[test]
    fn rejects_budget_out_of_range_and_unknown_fields() {
        let range = serde_yaml::from_str::<HedgePolicy>(
            r#"
initial_requests: 1
max_attempts: 1
budget_percent: 101
"#,
        )
        .unwrap_err();
        assert!(range.to_string().contains("hedge_policy: budget_percent"), "{range}");
        assert!(!range.to_string().contains("retry_budget"), "{range}");

        let unknown = serde_yaml::from_str::<HedgePolicy>(
            r#"
initial_requests: 1
max_attempts: 1
budget_percent: 10
extra: true
"#,
        )
        .unwrap_err();
        assert!(unknown.to_string().contains("extra"), "{unknown}");
    }

    #[test]
    fn rejects_budget_finer_than_one_basis_point() {
        for percent in ["0.005", "0.001"] {
            let yaml = format!("initial_requests: 1\nmax_attempts: 1\nbudget_percent: {percent}\n");
            let err = serde_yaml::from_str::<HedgePolicy>(&yaml).unwrap_err();
            assert!(err.to_string().contains("multiple of 0.01"), "{err}");
        }

        let policy: HedgePolicy = serde_yaml::from_str(
            r#"
initial_requests: 1
max_attempts: 1
budget_percent: 0.01
"#,
        )
        .unwrap();
        assert_eq!(policy.budget().bps(), 1, "0.01% is stored as one basis point");
    }

    #[test]
    fn clones_share_one_budget() {
        let policy: HedgePolicy = serde_yaml::from_str(
            r#"
initial_requests: 1
max_attempts: 2
per_try_timeout_ms: 10
budget_percent: 100
"#,
        )
        .unwrap();
        let cloned = policy.clone();
        policy.budget().note_request();
        assert!(
            cloned.budget().try_admit(),
            "clones of one policy share the admission counter"
        );
    }

    #[test]
    fn start_race_shares_the_route_budget() {
        let policy: HedgePolicy = serde_yaml::from_str(
            r#"
initial_requests: 2
max_attempts: 2
budget_percent: 10
"#,
        )
        .unwrap();
        let mut first = policy.start_race();
        let mut second = policy.start_race();
        assert_eq!(
            launch_count(first.open(two_upstreams)),
            2,
            "the first request is under the 10% cap"
        );
        assert_eq!(
            launch_count(second.open(two_upstreams)),
            1,
            "the shared budget denies the second copy"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    fn launch_count(outcome: crate::hedge::HedgeOutcome) -> usize {
        match outcome {
            crate::hedge::HedgeOutcome::Launch { attempts, .. } => attempts.len(),
            crate::hedge::HedgeOutcome::Won { .. }
            | crate::hedge::HedgeOutcome::Lost { .. }
            | crate::hedge::HedgeOutcome::Pending => 0,
        }
    }

    fn two_upstreams(exclude: &[Arc<str>]) -> Option<Arc<str>> {
        ["10.0.0.1:80", "10.0.0.2:80"]
            .into_iter()
            .map(Arc::<str>::from)
            .find(|address| exclude.iter().all(|existing| existing != address))
    }
}
