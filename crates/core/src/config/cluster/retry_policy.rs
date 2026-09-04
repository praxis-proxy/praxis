// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Retry policy configuration for upstream clusters.

use serde::{Deserialize, Serialize};

/// Serde default for [`RetryPolicy::configured`]: any deserialized policy is
/// operator-configured.
fn configured_true() -> bool {
    true
}

/// Default max retries matching the legacy hardcoded behavior.
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// Ceiling on effective retries.
///
/// Pingora's proxy loop caps total attempts per request at 16
/// (`ServerConf::max_retries`), so configured values above 15 retries
/// cannot take effect and are clamped.
pub const MAX_EFFECTIVE_RETRIES: u32 = 15;

/// Default body replay limit matching Pingora's fixed retry buffer (64 `KiB`).
pub const DEFAULT_RETRY_BODY_LIMIT_BYTES: u64 = 65_536;

/// Hard upper bound for the retry body buffer.
///
/// Matches Pingora's fixed downstream retry buffer: bodies beyond 64 `KiB`
/// are truncated in the replay buffer, and a truncated buffer disables
/// retries entirely, so allowing a larger configured limit would only
/// promise replays that can never happen.
pub const MAX_RETRY_BODY_LIMIT_BYTES: u64 = 65_536; // 64 KiB

// -----------------------------------------------------------------------------
// HttpStatusCode
// -----------------------------------------------------------------------------

/// Validated HTTP status code in the range 100..=599.
///
/// ```
/// use praxis_core::config::HttpStatusCode;
///
/// let code = HttpStatusCode::try_from(503_u16).unwrap();
/// assert_eq!(code.get(), 503);
/// assert!(HttpStatusCode::try_from(99_u16).is_err());
/// assert!(HttpStatusCode::try_from(600_u16).is_err());
/// ```
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "u16")]
pub struct HttpStatusCode(u16);

impl HttpStatusCode {
    /// Return the underlying status code value.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for HttpStatusCode {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if (100..=599).contains(&value) {
            Ok(Self(value))
        } else {
            Err(format!("http status code must be in 100..=599, got {value}"))
        }
    }
}

// -----------------------------------------------------------------------------
// RetryBodyLimit
// -----------------------------------------------------------------------------

/// Constrained retry body buffer size in bytes (0..=64 KiB).
///
/// ```
/// use praxis_core::config::RetryBodyLimit;
///
/// let limit = RetryBodyLimit::try_from(65_536_u64).unwrap();
/// assert_eq!(limit.get(), 65_536);
/// assert!(RetryBodyLimit::try_from(17 * 1024 * 1024_u64).is_err());
/// ```
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "u64")]
pub struct RetryBodyLimit(u64);

impl RetryBodyLimit {
    /// Return the underlying byte limit.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Default 64 `KiB` limit matching legacy Pingora retry buffering.
    #[must_use]
    pub const fn default_limit() -> Self {
        Self(DEFAULT_RETRY_BODY_LIMIT_BYTES)
    }
}

impl Default for RetryBodyLimit {
    fn default() -> Self {
        Self::default_limit()
    }
}

impl TryFrom<u64> for RetryBodyLimit {
    type Error = String;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value > MAX_RETRY_BODY_LIMIT_BYTES {
            Err(format!(
                "retry_body_limit_bytes must be <= {MAX_RETRY_BODY_LIMIT_BYTES} (64 KiB, the replay buffer cap), got {value}"
            ))
        } else {
            Ok(Self(value))
        }
    }
}

// -----------------------------------------------------------------------------
// BudgetPercent
// -----------------------------------------------------------------------------

/// Validated retry-budget percentage in the range 0.0..=100.0.
///
/// ```
/// use praxis_core::config::BudgetPercent;
///
/// let pct = BudgetPercent::try_from(20.0_f64).unwrap();
/// assert!((pct.get() - 20.0).abs() < f64::EPSILON);
/// assert!(BudgetPercent::try_from(-1.0_f64).is_err());
/// assert!(BudgetPercent::try_from(101.0_f64).is_err());
/// assert!(BudgetPercent::try_from(f64::NAN).is_err());
/// ```
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(try_from = "f64")]
pub struct BudgetPercent(f64);

impl BudgetPercent {
    /// Return the underlying percentage value.
    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for BudgetPercent {
    type Error = String;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        if !value.is_finite() {
            return Err(format!("retry_budget.percent must be finite, got {value}"));
        }
        if !(0.0..=100.0).contains(&value) {
            return Err(format!("retry_budget.percent must be in 0.0..=100.0, got {value}"));
        }
        Ok(Self(value))
    }
}

// -----------------------------------------------------------------------------
// RetriableCondition
// -----------------------------------------------------------------------------

/// Conditions that make an upstream outcome eligible for retry.
///
/// ```
/// use praxis_core::config::RetriableCondition;
///
/// let cond: RetriableCondition = serde_yaml::from_str("connect_failure").unwrap();
/// assert!(matches!(cond, RetriableCondition::ConnectFailure));
/// ```
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetriableCondition {
    /// TCP/TLS connect failure before an HTTP response.
    ConnectFailure,
    /// Connection reset by peer.
    Reset,
    /// HTTP/2 stream refused by upstream.
    RefusedStream,
    /// Any HTTP 5xx response status.
    #[serde(alias = "status_5xx")]
    Status5xx,
}

// -----------------------------------------------------------------------------
// BackoffConfig
// -----------------------------------------------------------------------------

/// Exponential backoff settings with full jitter.
///
/// Validation: `base_interval_ms > 0` and
/// `max_interval_ms >= base_interval_ms`.
///
/// ```
/// use praxis_core::config::BackoffConfig;
///
/// let yaml = r#"
/// base_interval_ms: 25
/// max_interval_ms: 250
/// "#;
/// let cfg: BackoffConfig = serde_yaml::from_str(yaml).unwrap();
/// assert_eq!(cfg.base_interval_ms, 25);
/// assert_eq!(cfg.max_interval_ms, 250);
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, try_from = "RawBackoffConfig")]
pub struct BackoffConfig {
    /// Base delay in milliseconds for the first retry.
    pub base_interval_ms: u64,
    /// Cap on the exponential delay in milliseconds.
    pub max_interval_ms: u64,
}

/// Intermediate deserialization type with validated conversion.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBackoffConfig {
    /// Exponential base interval in milliseconds.
    base_interval_ms: u64,
    /// Maximum capped interval in milliseconds.
    max_interval_ms: u64,
}

impl TryFrom<RawBackoffConfig> for BackoffConfig {
    type Error = String;

    fn try_from(raw: RawBackoffConfig) -> Result<Self, Self::Error> {
        if raw.base_interval_ms == 0 {
            return Err("backoff.base_interval_ms must be > 0".into());
        }
        if raw.max_interval_ms < raw.base_interval_ms {
            return Err(format!(
                "backoff.max_interval_ms ({}) must be >= base_interval_ms ({})",
                raw.max_interval_ms, raw.base_interval_ms
            ));
        }
        Ok(Self {
            base_interval_ms: raw.base_interval_ms,
            max_interval_ms: raw.max_interval_ms,
        })
    }
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            base_interval_ms: 25,
            max_interval_ms: 250,
        }
    }
}

// -----------------------------------------------------------------------------
// RetryBudgetConfig
// -----------------------------------------------------------------------------

/// Token-bucket retry budget configuration.
///
/// ```
/// use praxis_core::config::RetryBudgetConfig;
///
/// let yaml = r#"
/// percent: 20
/// min_retries_per_second: 10
/// "#;
/// let cfg: RetryBudgetConfig = serde_yaml::from_str(yaml).unwrap();
/// assert!((cfg.percent.get() - 20.0).abs() < f64::EPSILON);
/// assert_eq!(cfg.min_retries_per_second, 10);
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetryBudgetConfig {
    /// Maximum retries as a percentage of active requests (0.0..=100.0).
    pub percent: BudgetPercent,
    /// Floor on tokens per second even at low traffic.
    #[serde(default = "default_min_retries_per_second")]
    pub min_retries_per_second: u32,
}

/// Serde default for `min_retries_per_second`.
fn default_min_retries_per_second() -> u32 {
    10
}

impl Default for RetryBudgetConfig {
    fn default() -> Self {
        Self {
            percent: BudgetPercent(20.0),
            min_retries_per_second: default_min_retries_per_second(),
        }
    }
}

// -----------------------------------------------------------------------------
// RetryPolicy
// -----------------------------------------------------------------------------

/// Cluster-level (or route-level) retry policy.
///
/// ```
/// use praxis_core::config::RetryPolicy;
///
/// let yaml = r#"
/// max_retries: 3
/// retriable_status_codes: [502, 503, 504]
/// retriable_conditions:
///   - connect_failure
///   - reset
/// per_try_timeout_ms: 2000
/// backoff:
///   base_interval_ms: 25
///   max_interval_ms: 250
/// retry_budget:
///   percent: 20
///   min_retries_per_second: 10
/// retry_body_limit_bytes: 65536
/// "#;
/// let policy: RetryPolicy = serde_yaml::from_str(yaml).unwrap();
/// assert_eq!(policy.effective_max_retries(), 3);
/// assert_eq!(policy.retriable_status_codes.len(), 3);
/// assert!(!policy.allow_non_idempotent());
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts after the initial try.
    ///
    /// `None` means inherit from the merge parent / use the legacy default.
    #[serde(default)]
    pub max_retries: Option<u32>,

    /// Explicit HTTP status codes that are retriable.
    #[serde(default)]
    pub retriable_status_codes: Vec<HttpStatusCode>,

    /// Named retriable conditions (connect failure, reset, 5xx, ...).
    #[serde(default)]
    pub retriable_conditions: Vec<RetriableCondition>,

    /// Independent timeout for a single upstream attempt, in milliseconds.
    #[serde(default)]
    pub per_try_timeout_ms: Option<u64>,

    /// Overall request deadline across all attempts, in milliseconds.
    ///
    /// When unset, the overall-timeout guard is skipped.
    #[serde(default)]
    pub request_timeout_ms: Option<u64>,

    /// Exponential backoff between attempts.
    #[serde(default)]
    pub backoff: Option<BackoffConfig>,

    /// Whether this policy came from operator configuration rather than the
    /// built-in legacy default.
    ///
    /// Endpoint reselection on retry is enabled only for configured
    /// policies; the legacy default preserves the historical
    /// retry-same-endpoint semantics.
    #[serde(skip_deserializing, skip_serializing, default = "configured_true")]
    pub configured: bool,

    /// Token-bucket retry budget.
    #[serde(default)]
    pub retry_budget: Option<RetryBudgetConfig>,

    /// Max request body size eligible for replay (bytes). Defaults to 64 `KiB`.
    #[serde(default)]
    pub retry_body_limit_bytes: Option<RetryBodyLimit>,

    /// Allow retries for non-idempotent methods (POST/PATCH) when true.
    #[serde(default)]
    pub allow_non_idempotent: Option<bool>,
}

impl RetryPolicy {
    /// Legacy default matching pre-policy behavior: 3 connect-failure
    /// retries, 64 `KiB` body limit, idempotent methods only, same endpoint.
    #[must_use]
    pub fn legacy_default() -> Self {
        Self {
            max_retries: Some(DEFAULT_MAX_RETRIES),
            retriable_status_codes: Vec::new(),
            retriable_conditions: vec![RetriableCondition::ConnectFailure],
            per_try_timeout_ms: None,
            request_timeout_ms: None,
            backoff: None,
            configured: false,
            retry_budget: None,
            retry_body_limit_bytes: Some(RetryBodyLimit::default_limit()),
            allow_non_idempotent: None,
        }
    }

    /// Effective max retries (falls back to the legacy default of 3).
    ///
    /// Clamped to [`MAX_EFFECTIVE_RETRIES`]: Pingora's proxy loop stops
    /// re-attempting past its own per-request cap regardless of policy.
    #[must_use]
    pub fn effective_max_retries(&self) -> u32 {
        self.max_retries
            .unwrap_or(DEFAULT_MAX_RETRIES)
            .min(MAX_EFFECTIVE_RETRIES)
    }

    /// Effective body replay limit in bytes.
    #[must_use]
    pub fn body_limit_bytes(&self) -> u64 {
        self.retry_body_limit_bytes
            .unwrap_or_else(RetryBodyLimit::default_limit)
            .get()
    }

    /// Whether non-idempotent methods are allowed to retry (defaults to `false`).
    #[must_use]
    pub fn allow_non_idempotent(&self) -> bool {
        self.allow_non_idempotent.unwrap_or(false)
    }

    /// Validate the per-attempt and overall timeout bounds.
    ///
    /// `per_try_timeout_ms: 0` would set zero-duration connect/read/write
    /// timeouts on every upstream attempt (failing effectively all
    /// requests on non-loopback upstreams), and `request_timeout_ms: 0`
    /// makes the overall deadline elapse before the first attempt,
    /// silently disabling retries. Both are rejected here with the same
    /// zero/ceiling bounds every other timeout field gets.
    ///
    /// `context` names the owning config object for the error message
    /// (e.g. `cluster 'backend'`).
    ///
    /// # Errors
    ///
    /// Returns a message naming the offending field when either timeout
    /// is `0` or exceeds the 1-hour ceiling.
    pub fn validate_timeout_bounds(&self, context: &str) -> Result<(), String> {
        for (field, value) in [
            ("retry_policy.per_try_timeout_ms", self.per_try_timeout_ms),
            ("retry_policy.request_timeout_ms", self.request_timeout_ms),
        ] {
            if let Some(0) = value {
                return Err(format!("{context}: {field} is 0 (must be > 0)"));
            }
            if let Some(v) = value
                && v > super::super::validate::cluster::MAX_TIMEOUT_MS
            {
                return Err(format!(
                    "{context}: {field} ({v} ms) exceeds maximum ({} ms / 1 hour)",
                    super::super::validate::cluster::MAX_TIMEOUT_MS
                ));
            }
        }

        // The retry budget refills at `min_retries_per_second` tokens/second;
        // a rate of 0 means the token bucket never refills, so every retry is
        // denied cluster-wide with no error or log — the configured retry
        // policy is silently inert. Reject it like the other zero-disables-the-
        // feature cases above.
        if let Some(budget) = &self.retry_budget
            && budget.min_retries_per_second == 0
        {
            return Err(format!(
                "{context}: retry_budget.min_retries_per_second is 0 (must be > 0; \
                 0 stops the budget refilling and denies every retry)"
            ));
        }
        Ok(())
    }

    /// Merge a route-level override onto this cluster policy.
    ///
    /// Route fields override cluster fields where present. List-typed
    /// fields (`retriable_status_codes`, `retriable_conditions`) are
    /// replaced entirely when the route provides a non-empty list.
    #[must_use]
    pub fn merge_override(&self, route: &Self) -> Self {
        Self {
            configured: self.configured || route.configured,
            max_retries: route.max_retries.or(self.max_retries),
            retriable_status_codes: if route.retriable_status_codes.is_empty() {
                self.retriable_status_codes.clone()
            } else {
                route.retriable_status_codes.clone()
            },
            retriable_conditions: if route.retriable_conditions.is_empty() {
                self.retriable_conditions.clone()
            } else {
                route.retriable_conditions.clone()
            },
            per_try_timeout_ms: route.per_try_timeout_ms.or(self.per_try_timeout_ms),
            request_timeout_ms: route.request_timeout_ms.or(self.request_timeout_ms),
            backoff: route.backoff.clone().or_else(|| self.backoff.clone()),
            retry_budget: route.retry_budget.clone().or_else(|| self.retry_budget.clone()),
            retry_body_limit_bytes: route.retry_body_limit_bytes.or(self.retry_body_limit_bytes),
            allow_non_idempotent: route.allow_non_idempotent.or(self.allow_non_idempotent),
        }
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::legacy_default()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn parse_full_policy() {
        let yaml = "
max_retries: 3
retriable_status_codes: [502, 503, 504]
retriable_conditions:
  - connect_failure
  - reset
  - refused_stream
  - status5xx
per_try_timeout_ms: 2000
request_timeout_ms: 10000
backoff:
  base_interval_ms: 25
  max_interval_ms: 250
retry_budget:
  percent: 20
  min_retries_per_second: 10
retry_body_limit_bytes: 65536
allow_non_idempotent: true
";
        let policy: RetryPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.effective_max_retries(), 3);
        assert_eq!(policy.retriable_status_codes.len(), 3);
        assert_eq!(policy.retriable_status_codes.get(1).map(|c| c.get()), Some(503));
        assert_eq!(policy.retriable_conditions.len(), 4);
        assert_eq!(policy.per_try_timeout_ms, Some(2000));
        assert_eq!(policy.request_timeout_ms, Some(10_000));
        assert!(policy.allow_non_idempotent());
        assert_eq!(policy.body_limit_bytes(), 65_536);
    }

    #[test]
    fn reject_invalid_status_code() {
        let yaml = "retriable_status_codes: [99]";
        let err = serde_yaml::from_str::<RetryPolicy>(yaml).unwrap_err();
        assert!(err.to_string().contains("100..=599"), "got: {err}");
    }

    #[test]
    fn reject_body_limit_above_cap() {
        let yaml = "retry_body_limit_bytes: 20000000";
        let err = serde_yaml::from_str::<RetryPolicy>(yaml).unwrap_err();
        assert!(err.to_string().contains("64 KiB"), "got: {err}");
    }

    #[test]
    fn reject_invalid_budget_percent() {
        let yaml = "
retry_budget:
  percent: 150
  min_retries_per_second: 1
";
        let err = serde_yaml::from_str::<RetryPolicy>(yaml).unwrap_err();
        assert!(err.to_string().contains("0.0..=100.0"), "got: {err}");
    }

    #[test]
    fn reject_zero_backoff_base() {
        let yaml = "
backoff:
  base_interval_ms: 0
  max_interval_ms: 100
";
        let err = serde_yaml::from_str::<RetryPolicy>(yaml).unwrap_err();
        assert!(err.to_string().contains("base_interval_ms"), "got: {err}");
    }

    #[test]
    fn reject_backoff_max_less_than_base() {
        let yaml = "
backoff:
  base_interval_ms: 100
  max_interval_ms: 50
";
        let err = serde_yaml::from_str::<RetryPolicy>(yaml).unwrap_err();
        assert!(err.to_string().contains("max_interval_ms"), "got: {err}");
    }

    #[test]
    fn merge_override_replaces_lists() {
        let cluster = RetryPolicy {
            retriable_status_codes: vec![HttpStatusCode(502)],
            retriable_conditions: vec![RetriableCondition::ConnectFailure],
            max_retries: Some(3),
            ..RetryPolicy::legacy_default()
        };
        let route = RetryPolicy {
            retriable_status_codes: vec![HttpStatusCode(503)],
            retriable_conditions: vec![RetriableCondition::Status5xx],
            max_retries: Some(2),
            allow_non_idempotent: Some(true),
            ..RetryPolicy {
                configured: true,
                max_retries: None,
                retriable_status_codes: Vec::new(),
                retriable_conditions: Vec::new(),
                per_try_timeout_ms: None,
                request_timeout_ms: None,
                backoff: None,
                retry_budget: None,
                retry_body_limit_bytes: None,
                allow_non_idempotent: None,
            }
        };
        let merged = cluster.merge_override(&route);
        assert_eq!(merged.effective_max_retries(), 2);
        assert_eq!(merged.retriable_status_codes, vec![HttpStatusCode(503)]);
        assert_eq!(merged.retriable_conditions, vec![RetriableCondition::Status5xx]);
        assert!(merged.allow_non_idempotent());
    }

    #[test]
    fn merge_partial_route_preserves_cluster_max_retries() {
        let cluster = RetryPolicy {
            max_retries: Some(5),
            ..RetryPolicy::legacy_default()
        };
        let route = RetryPolicy {
            configured: true,
            allow_non_idempotent: Some(true),
            max_retries: None,
            retriable_status_codes: Vec::new(),
            retriable_conditions: Vec::new(),
            per_try_timeout_ms: None,
            request_timeout_ms: None,
            backoff: None,
            retry_budget: None,
            retry_body_limit_bytes: None,
        };
        let merged = cluster.merge_override(&route);
        assert_eq!(merged.effective_max_retries(), 5);
        assert!(merged.allow_non_idempotent());
    }

    #[test]
    fn legacy_default_is_connect_failure_only() {
        let policy = RetryPolicy::legacy_default();
        assert_eq!(policy.effective_max_retries(), 3);
        assert_eq!(policy.retriable_conditions, vec![RetriableCondition::ConnectFailure]);
        assert!(policy.retriable_status_codes.is_empty());
        assert!(!policy.allow_non_idempotent());
        assert_eq!(policy.body_limit_bytes(), 65_536);
    }
    #[test]
    fn effective_max_retries_clamps_to_pingora_cap() {
        let policy = RetryPolicy {
            max_retries: Some(100),
            ..RetryPolicy::legacy_default()
        };
        assert_eq!(
            policy.effective_max_retries(),
            MAX_EFFECTIVE_RETRIES,
            "values beyond Pingora's per-request attempt cap are clamped"
        );
    }

    #[test]
    fn validate_rejects_zero_min_retries_per_second() {
        let budget: RetryBudgetConfig = serde_yaml::from_str("percent: 20\nmin_retries_per_second: 0").unwrap();
        let policy = RetryPolicy {
            retry_budget: Some(budget),
            ..RetryPolicy::legacy_default()
        };
        let err = policy
            .validate_timeout_bounds("cluster 'backend'")
            .expect_err("min_retries_per_second of 0 permanently empties the budget and must be rejected");
        assert!(
            err.contains("min_retries_per_second"),
            "error should name the offending field: {err}"
        );
    }

    #[test]
    fn validate_accepts_nonzero_min_retries_per_second() {
        let budget: RetryBudgetConfig = serde_yaml::from_str("percent: 20\nmin_retries_per_second: 5").unwrap();
        let policy = RetryPolicy {
            retry_budget: Some(budget),
            ..RetryPolicy::legacy_default()
        };
        assert!(
            policy.validate_timeout_bounds("cluster 'backend'").is_ok(),
            "a positive min_retries_per_second should pass validation"
        );
    }

    #[test]
    fn configured_flag_distinguishes_operator_policies() {
        assert!(
            !RetryPolicy::legacy_default().configured,
            "the built-in default is not operator-configured"
        );
        let parsed: RetryPolicy = serde_yaml::from_str("max_retries: 2").unwrap();
        assert!(parsed.configured, "any deserialized policy is operator-configured");
        let merged = RetryPolicy::legacy_default().merge_override(&parsed);
        assert!(merged.configured, "merging in a configured override keeps the flag");
    }
}
