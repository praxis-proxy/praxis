// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Rate limiting logic: token acquisition, eviction, and header generation.

use std::{net::IpAddr, sync::atomic::Ordering};

use dashmap::mapref::entry::Entry;
use praxis_core::connectivity::normalize_mapped_ipv4;

use super::{
    HARD_CAP_PER_IP_ENTRIES, HEADER_RATELIMIT_LIMIT, HEADER_RATELIMIT_REMAINING, HEADER_RATELIMIT_RESET,
    MAX_PER_IP_ENTRIES, PerIpState, RateLimitFilter, RateLimitState,
};
use crate::builtins::http::traffic_management::token_bucket::TokenBucket;

// -----------------------------------------------------------------------------
// Token Acquisition
// -----------------------------------------------------------------------------

impl RateLimitFilter {
    /// Nanoseconds elapsed since this filter's epoch.
    #[expect(clippy::cast_possible_truncation, reason = "nanos fit u64")]
    pub(super) fn now_nanos(&self) -> u64 {
        self.epoch.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
    }

    /// Build rate limit headers and compute the retry-after value.
    ///
    /// Returns the header list and the `Retry-After` seconds (floored
    /// at 1 when the client is rate-limited).
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "token count truncation"
    )]
    pub(super) fn rate_limit_headers(
        &self,
        remaining: f64,
        time_source: &dyn praxis_core::time::TimeSource,
    ) -> (Vec<(&'static str, String)>, u64) {
        let retry_secs = if remaining < 1.0 {
            ((1.0 - remaining) / self.rate).ceil().max(1.0) as u64
        } else {
            0
        };
        let now_unix = time_source.now().as_secs();
        let reset_unix = now_unix.saturating_add(retry_secs);
        let remaining_int = remaining.max(0.0) as u64;

        let headers = vec![
            (HEADER_RATELIMIT_LIMIT, self.burst_string.clone()),
            (HEADER_RATELIMIT_REMAINING, format!("{remaining_int}")),
            (HEADER_RATELIMIT_RESET, format!("{reset_unix}")),
        ];
        (headers, retry_secs)
    }

    /// Evict stale entries from a per-IP map when it exceeds [`MAX_PER_IP_ENTRIES`].
    ///
    /// Removes buckets whose `last_refill` is older than
    /// `2 * burst / rate` seconds, meaning the bucket would be fully
    /// refilled and idle.
    ///
    /// Passes are claimed through [`PerIpState::claim_eviction_pass`],
    /// so at most one caller per [`EVICTION_INTERVAL_NANOS`] performs
    /// the scan and everyone else returns without touching the map.
    /// This ordering matters: the interval is checked *before* the
    /// entry count, because reading the count from the map itself
    /// would already cost a read lock on every shard.
    ///
    /// A pass evicts every eligible entry rather than stopping after a
    /// fixed number. [`DashMap::retain`] visits all entries regardless
    /// of what the callback returns, so a partial scan reclaims less
    /// for exactly the same cost.
    ///
    /// [`DashMap::retain`]: dashmap::DashMap::retain
    /// [`EVICTION_INTERVAL_NANOS`]: super::EVICTION_INTERVAL_NANOS
    pub(super) fn maybe_evict(&self, state: &PerIpState, now_nanos: u64) {
        if !state.claim_eviction_pass(now_nanos) {
            return;
        }
        if state.entries() <= MAX_PER_IP_ENTRIES {
            return;
        }

        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "rate/burst nanos"
        )]
        let idle_threshold_nanos = (2.0 * self.burst / self.rate * 1_000_000_000.0) as u64;

        let mut evicted = 0_usize;
        state.buckets.retain(|_ip, bucket| {
            let last = bucket.last_refill_nanos();
            if now_nanos.saturating_sub(last) > idle_threshold_nanos {
                evicted += 1;
                return false;
            }
            true
        });

        if evicted > 0 {
            let remaining = state.entries.fetch_sub(evicted, Ordering::Relaxed) - evicted;
            tracing::debug!(evicted, remaining, "rate_limit: evicted stale per-IP entries");
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
            RateLimitState::Global(bucket) => Self::acquire_from_bucket(bucket, self.rate, self.burst, now),
            RateLimitState::PerIp(state) => self.acquire_per_ip(state, client_addr, now),
        }
    }

    /// Per-IP token acquisition with hard cap enforcement.
    ///
    /// Rejects unknown IPs when the map exceeds [`HARD_CAP_PER_IP_ENTRIES`]
    /// to prevent unbounded memory growth via address rotation.
    fn acquire_per_ip(&self, state: &PerIpState, client_addr: Option<IpAddr>, now: u64) -> Result<f64, f64> {
        let Some(ip) = client_addr.map(normalize_mapped_ipv4) else {
            tracing::info!("rate_limit: rejecting request with no client address");
            return Err(0.0);
        };
        self.maybe_evict(state, now);

        if let Some(bucket) = state.buckets.get(&ip) {
            return Self::acquire_from_bucket(&bucket, self.rate, self.burst, now);
        }

        // Reject unknown IPs when the map exceeds the hard cap to
        // prevent unbounded memory growth via address rotation.
        if state.entries() >= HARD_CAP_PER_IP_ENTRIES {
            tracing::warn!(
                entries = state.entries(),
                hard_cap = HARD_CAP_PER_IP_ENTRIES,
                "rate_limit: per-IP map hard cap reached, rejecting new IP"
            );
            return Err(0.0);
        }

        // Insert through the entry API so a genuinely new address can be
        // distinguished from one another thread inserted concurrently;
        // only the former advances the entry count.
        match state.buckets.entry(ip) {
            Entry::Occupied(occupied) => Self::acquire_from_bucket(occupied.get(), self.rate, self.burst, now),
            Entry::Vacant(vacant) => {
                let bucket = vacant.insert(TokenBucket::new(self.burst));
                state.entries.fetch_add(1, Ordering::Relaxed);
                Self::acquire_from_bucket(&bucket, self.rate, self.burst, now)
            },
        }
    }

    /// Try to acquire one token from a single bucket.
    fn acquire_from_bucket(bucket: &TokenBucket, rate: f64, burst: f64, now: u64) -> Result<f64, f64> {
        match bucket.try_acquire(rate, burst, now) {
            Some(remaining) => Ok(remaining),
            None => Err(bucket.current_tokens(rate, burst, now)),
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
            RateLimitState::PerIp(state) => {
                let Some(ip) = client_addr.map(normalize_mapped_ipv4) else {
                    return 0.0;
                };
                state
                    .buckets
                    .get(&ip)
                    .map_or(self.burst, |b| b.current_tokens(self.rate, self.burst, now))
            },
        }
    }
}
