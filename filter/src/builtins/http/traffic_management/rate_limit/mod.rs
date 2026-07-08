// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Token bucket rate limiter.

mod config;
mod limiter;

pub use self::config::RateLimitMode;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "tests"
)]
mod tests;

use std::{net::IpAddr, time::Instant};

use async_trait::async_trait;
use dashmap::DashMap;

use self::config::RateLimitConfig;
use super::token_bucket::TokenBucket;
use crate::{
    FilterAction, FilterError, Rejection,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Rate-Limiter Constants
// -----------------------------------------------------------------------------

/// Maximum number of per-IP entries before eviction is triggered.
const MAX_PER_IP_ENTRIES: usize = 100_000;

/// Hard cap on per-IP entries; new IPs are rejected with 429 above this.
///
/// Acts as a safety net above the soft eviction threshold. Prevents
/// unbounded memory growth when attackers rotate source addresses
/// faster than the eviction scan can reclaim entries.
const HARD_CAP_PER_IP_ENTRIES: usize = 200_000; // 2 * MAX_PER_IP_ENTRIES

/// Maximum entries to scan during a single eviction pass.
///
/// When the map exceeds the aggressive eviction threshold
/// ([`AGGRESSIVE_EVICTION_THRESHOLD`]), the scan limit is
/// lifted entirely (see [`RateLimitFilter::maybe_evict`]).
const EVICTION_SCAN_LIMIT: usize = 2_048;

/// Entry count above which eviction scans the entire map.
const AGGRESSIVE_EVICTION_THRESHOLD: usize = MAX_PER_IP_ENTRIES + MAX_PER_IP_ENTRIES / 2; // 150_000

/// Rate limit header: maximum bucket capacity.
const HEADER_RATELIMIT_LIMIT: &str = "X-RateLimit-Limit";

/// Rate limit header: remaining tokens.
const HEADER_RATELIMIT_REMAINING: &str = "X-RateLimit-Remaining";

/// Rate limit header: Unix timestamp when the bucket fully refills.
const HEADER_RATELIMIT_RESET: &str = "X-RateLimit-Reset";

// -----------------------------------------------------------------------------
// RateLimitState
// -----------------------------------------------------------------------------

/// Per-filter state: either a single global bucket or per-IP buckets.
enum RateLimitState {
    /// One shared bucket for all clients.
    Global(TokenBucket),

    /// Independent bucket per source IP address.
    PerIp(DashMap<IpAddr, TokenBucket>),
}

// -----------------------------------------------------------------------------
// RateLimitFilter
// -----------------------------------------------------------------------------

/// Token bucket rate limiter that rejects excess traffic with 429.
///
/// Supports `global` (one shared bucket) and `per_ip` (one bucket per
/// source IP) modes. Rate limit headers (`X-RateLimit-Limit`,
/// `X-RateLimit-Remaining`, `X-RateLimit-Reset`) are injected into
/// both 429 rejections and successful responses.
///
/// State is all managed locally.
///
/// # YAML configuration
///
/// ```yaml
/// filter: rate_limit
/// mode: per_ip        # "per_ip" or "global"
/// rate: 100           # tokens per second
/// burst: 200          # max bucket capacity
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::RateLimitFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// mode: global
/// rate: 50
/// burst: 100
/// "#,
/// )
/// .unwrap();
/// let filter = RateLimitFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "rate_limit");
/// ```
///
/// [`DashMap`]: dashmap::DashMap
pub struct RateLimitFilter {
    /// Bucket state (global or per-IP).
    pub(self) state: RateLimitState,

    /// Tokens replenished per second.
    pub(self) rate: f64,

    /// Maximum bucket capacity.
    pub(self) burst: f64,

    /// Pre-formatted burst value for the `X-RateLimit-Limit` header.
    pub(self) burst_string: String,

    /// Monotonic clock reference; all timestamps are offsets from this.
    pub(self) epoch: Instant,
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "limiter logic is split into a dedicated module"
)]
impl RateLimitFilter {
    /// Create a rate limit filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns an error if any field is missing, `rate` is not
    /// positive, `burst` is zero, or `burst < rate`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use praxis_filter::RateLimitFilter;
    ///
    /// let yaml: serde_yaml::Value = serde_yaml::from_str(
    ///     r#"
    /// mode: per_ip
    /// rate: 100
    /// burst: 200
    /// "#,
    /// )
    /// .unwrap();
    /// let filter = RateLimitFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "rate_limit");
    ///
    /// // Invalid: rate is zero.
    /// let bad: serde_yaml::Value = serde_yaml::from_str("mode: global\nrate: 0\nburst: 10").unwrap();
    /// assert!(RateLimitFilter::from_config(&bad).is_err());
    /// ```
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: RateLimitConfig = parse_filter_config("rate_limit", config)?;

        if !cfg.rate.is_finite() || cfg.rate <= 0.0 {
            return Err("rate_limit: rate must be a finite number greater than 0".into());
        }
        if cfg.burst == 0 {
            return Err("rate_limit: burst must be at least 1".into());
        }
        if f64::from(cfg.burst) < cfg.rate {
            return Err("rate_limit: burst must be >= rate".into());
        }

        let burst = f64::from(cfg.burst);
        let state = match cfg.mode {
            RateLimitMode::Global => RateLimitState::Global(TokenBucket::new(burst)),
            RateLimitMode::PerIp => RateLimitState::PerIp(DashMap::new()),
        };

        #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "burst fits u64")]
        let burst_string = (burst as u64).to_string();
        Ok(Box::new(Self {
            state,
            rate: cfg.rate,
            burst,
            burst_string,
            epoch: Instant::now(),
        }))
    }
}

#[async_trait]
impl HttpFilter for RateLimitFilter {
    fn name(&self) -> &'static str {
        "rate_limit"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        match self.try_acquire_for(ctx.client_addr) {
            Ok(_remaining) => Ok(FilterAction::Continue),
            Err(remaining) => {
                tracing::info!(
                    client = ?ctx.client_addr,
                    "rate_limit: rejecting request (429)"
                );
                let (headers, retry_secs) = self.rate_limit_headers(remaining, ctx.time_source);

                let mut rejection = Rejection::status(429).with_header("Retry-After", format!("{retry_secs}"));
                for (name, value) in headers {
                    rejection = rejection.with_header(name, value);
                }
                Ok(FilterAction::Reject(rejection))
            },
        }
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let remaining = self.current_remaining(ctx.client_addr);
        let (headers, _retry_secs) = self.rate_limit_headers(remaining, ctx.time_source);

        if let Some(ref mut resp) = ctx.response_header {
            for (name, value) in &headers {
                if let Ok(hv) = value.parse()
                    && let Ok(hn) = http::header::HeaderName::from_bytes(name.as_bytes())
                {
                    resp.headers.insert(hn, hv);
                    ctx.response_headers_modified = true;
                }
            }
        }

        Ok(FilterAction::Continue)
    }
}
