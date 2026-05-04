// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Rate limiting logic: token acquisition, eviction, and header generation.

use std::net::IpAddr;

use dashmap::DashMap;
use praxis_core::connectivity::normalize_mapped_ipv4;

use super::{
    EVICTION_SCAN_LIMIT, HEADER_RATELIMIT_LIMIT, HEADER_RATELIMIT_REMAINING, HEADER_RATELIMIT_RESET,
    MAX_PER_IP_ENTRIES, RateLimitFilter, RateLimitState,
};
use crate::builtins::http::traffic_management::token_bucket::TokenBucket;

// -----------------------------------------------------------------------------
// Token Acquisition
// -----------------------------------------------------------------------------

impl RateLimitFilter {
    /// Nanoseconds elapsed since this filter's epoch.
    #[allow(clippy::cast_possible_truncation, reason = "nanos fit u64")]
    pub(super) fn now_nanos(&self) -> u64 {
        self.epoch.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
    }

    /// Build rate limit headers and compute the retry-after value.
    ///
    /// Returns the header list and the `Retry-After` seconds (floored
    /// at 1 when the client is rate-limited).
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "token count truncation"
    )]
    pub(super) fn rate_limit_headers(&self, remaining: f64) -> (Vec<(&'static str, String)>, u64) {
        let retry_secs = if remaining < 1.0 {
            ((1.0 - remaining) / self.rate).ceil().max(1.0) as u64
        } else {
            0
        };
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let reset_unix = now_unix + retry_secs;
        let remaining_int = remaining.max(0.0) as u64;

        let headers = vec![
            (HEADER_RATELIMIT_LIMIT, (self.burst as u64).to_string()),
            (HEADER_RATELIMIT_REMAINING, format!("{remaining_int}")),
            (HEADER_RATELIMIT_RESET, format!("{reset_unix}")),
        ];
        (headers, retry_secs)
    }

    /// Evict stale entries from a per-IP map when it exceeds [`MAX_PER_IP_ENTRIES`].
    ///
    /// Scans up to [`EVICTION_SCAN_LIMIT`] entries and removes any whose
    /// `last_refill` is older than `2 * burst / rate` seconds, meaning
    /// the bucket would be fully refilled and idle.
    #[allow(clippy::too_many_lines, reason = "atomic CAS loop")]
    pub(super) fn maybe_evict(&self, map: &DashMap<IpAddr, TokenBucket>, now_nanos: u64) {
        if map.len() <= MAX_PER_IP_ENTRIES {
            return;
        }

        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "rate/burst nanos"
        )]
        let idle_threshold_nanos = (2.0 * self.burst / self.rate * 1_000_000_000.0) as u64;
        let mut scanned = 0usize;
        let mut evicted = 0usize;

        map.retain(|_ip, bucket| {
            if scanned >= EVICTION_SCAN_LIMIT {
                return true;
            }
            scanned += 1;
            let last = bucket.last_refill_nanos();
            if now_nanos.saturating_sub(last) > idle_threshold_nanos {
                evicted += 1;
                return false;
            }
            true
        });

        if evicted > 0 {
            tracing::debug!(
                evicted,
                scanned,
                remaining = map.len(),
                "rate_limit: evicted stale per-IP entries"
            );
        }
    }

    /// Try to acquire a token for the given request context.
    ///
    /// IPv4-mapped IPv6 addresses are normalized to plain IPv4 before
    /// keying the per-IP map (defense in depth; the Pingora boundary
    /// normalizes too).
    pub(super) fn try_acquire_for(&self, client_addr: Option<IpAddr>) -> Result<f64, f64> {
        let now = self.now_nanos();
        match &self.state {
            RateLimitState::Global(bucket) => match bucket.try_acquire(self.rate, self.burst, now) {
                Some(remaining) => Ok(remaining),
                None => Err(bucket.current_tokens(self.rate, self.burst, now)),
            },
            RateLimitState::PerIp(map) => {
                let Some(ip) = client_addr.map(normalize_mapped_ipv4) else {
                    tracing::info!("rate_limit: rejecting request with no client address");
                    return Err(0.0);
                };
                self.maybe_evict(map, now);
                let bucket = map.entry(ip).or_insert_with(|| TokenBucket::new(self.burst));
                match bucket.try_acquire(self.rate, self.burst, now) {
                    Some(remaining) => Ok(remaining),
                    None => Err(bucket.current_tokens(self.rate, self.burst, now)),
                }
            },
        }
    }

    /// Read current tokens for response header injection.
    ///
    /// Normalizes IPv4-mapped IPv6 addresses before lookup (defense in
    /// depth).
    pub(super) fn current_remaining(&self, client_addr: Option<IpAddr>) -> f64 {
        let now = self.now_nanos();
        match &self.state {
            RateLimitState::Global(bucket) => bucket.current_tokens(self.rate, self.burst, now),
            RateLimitState::PerIp(map) => {
                let Some(ip) = client_addr.map(normalize_mapped_ipv4) else {
                    return 0.0;
                };
                map.get(&ip)
                    .map_or(self.burst, |b| b.current_tokens(self.rate, self.burst, now))
            },
        }
    }
}
