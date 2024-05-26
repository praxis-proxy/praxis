//! Token bucket rate limiter.

use std::{net::IpAddr, time::Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use serde::Deserialize;

use super::token_bucket::TokenBucket;
use crate::{
    FilterAction, FilterError, Rejection,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum number of per-IP entries before eviction is triggered.
const MAX_PER_IP_ENTRIES: usize = 100_000;

/// Maximum entries to scan during a single eviction pass.
const EVICTION_SCAN_LIMIT: usize = 128;

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the rate limit filter.
#[derive(Debug, Deserialize)]
struct RateLimitConfig {
    /// `"per_ip"` or `"global"`.
    mode: String,

    /// Tokens replenished per second.
    rate: f64,

    /// Maximum bucket capacity.
    burst: u32,
}

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
/// ```
/// use praxis_filter::RateLimitFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(r#"
/// mode: global
/// rate: 50
/// burst: 100
/// "#).unwrap();
/// let filter = RateLimitFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "rate_limit");
/// ```
///
/// [`DashMap`]: dashmap::DashMap
pub struct RateLimitFilter {
    /// Bucket state (global or per-IP).
    state: RateLimitState,

    /// Tokens replenished per second.
    rate: f64,

    /// Maximum bucket capacity.
    burst: f64,

    /// Monotonic clock reference; all timestamps are offsets from this.
    epoch: Instant,
}

impl RateLimitFilter {
    /// Create a rate limit filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns an error if any field is missing, `rate` is not
    /// positive, `burst` is zero, `burst < rate`, or `mode` is
    /// unrecognised.
    ///
    /// # Example
    ///
    /// ```
    /// use praxis_filter::RateLimitFilter;
    ///
    /// let yaml: serde_yaml::Value = serde_yaml::from_str(r#"
    /// mode: per_ip
    /// rate: 100
    /// burst: 200
    /// "#).unwrap();
    /// let filter = RateLimitFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "rate_limit");
    ///
    /// // Invalid: rate is zero.
    /// let bad: serde_yaml::Value = serde_yaml::from_str("mode: global\nrate: 0\nburst: 10").unwrap();
    /// assert!(RateLimitFilter::from_config(&bad).is_err());
    /// ```
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: RateLimitConfig = parse_filter_config("rate_limit", config)?;

        if cfg.rate <= 0.0 {
            return Err("rate_limit: rate must be greater than 0".into());
        }
        if cfg.burst == 0 {
            return Err("rate_limit: burst must be at least 1".into());
        }
        if (cfg.burst as f64) < cfg.rate {
            return Err("rate_limit: burst must be >= rate".into());
        }

        let burst = f64::from(cfg.burst);
        let state = match cfg.mode.as_str() {
            "global" => RateLimitState::Global(TokenBucket::new(burst)),
            "per_ip" => RateLimitState::PerIp(DashMap::new()),
            other => return Err(format!("rate_limit: unknown mode '{other}'").into()),
        };

        Ok(Box::new(Self {
            state,
            rate: cfg.rate,
            burst,
            epoch: Instant::now(),
        }))
    }

    /// Nanoseconds elapsed since this filter's epoch.
    fn now_nanos(&self) -> u64 {
        self.epoch.elapsed().as_nanos() as u64
    }

    /// Build rate limit headers and compute the retry-after value.
    ///
    /// Returns the header list and the `Retry-After` seconds (floored
    /// at 1 when the client is rate-limited).
    fn rate_limit_headers(&self, remaining: f64) -> (Vec<(String, String)>, u64) {
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
            ("X-RateLimit-Limit".to_owned(), format!("{}", self.burst as u64)),
            ("X-RateLimit-Remaining".to_owned(), format!("{remaining_int}")),
            ("X-RateLimit-Reset".to_owned(), format!("{reset_unix}")),
        ];
        (headers, retry_secs)
    }

    /// Evict stale entries from a per-IP map when it exceeds [`MAX_PER_IP_ENTRIES`].
    ///
    /// Scans up to [`EVICTION_SCAN_LIMIT`] entries and removes any whose
    /// `last_refill` is older than `2 * burst / rate` seconds, meaning
    /// the bucket would be fully refilled and idle.
    fn maybe_evict(&self, map: &DashMap<IpAddr, TokenBucket>, now_nanos: u64) {
        if map.len() <= MAX_PER_IP_ENTRIES {
            return;
        }

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
    fn try_acquire_for(&self, client_addr: Option<IpAddr>) -> Result<f64, f64> {
        let now = self.now_nanos();
        match &self.state {
            RateLimitState::Global(bucket) => match bucket.try_acquire(self.rate, self.burst, now) {
                Some(remaining) => Ok(remaining),
                None => Err(bucket.current_tokens(self.rate, self.burst, now)),
            },
            RateLimitState::PerIp(map) => {
                let Some(ip) = client_addr else {
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
    fn current_remaining(&self, client_addr: Option<IpAddr>) -> f64 {
        let now = self.now_nanos();
        match &self.state {
            RateLimitState::Global(bucket) => bucket.current_tokens(self.rate, self.burst, now),
            RateLimitState::PerIp(map) => {
                let Some(ip) = client_addr else {
                    return 0.0;
                };
                map.get(&ip)
                    .map_or(self.burst, |b| b.current_tokens(self.rate, self.burst, now))
            },
        }
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
                let (headers, retry_secs) = self.rate_limit_headers(remaining);

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
        let (headers, _retry_secs) = self.rate_limit_headers(remaining);

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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_parses_per_ip() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("mode: per_ip\nrate: 100\nburst: 200").unwrap();
        let filter = RateLimitFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "rate_limit", "filter name should be rate_limit");
    }

    #[test]
    fn from_config_parses_global() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("mode: global\nrate: 50\nburst: 100").unwrap();
        let filter = RateLimitFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "rate_limit", "filter name should be rate_limit");
    }

    #[test]
    fn from_config_rejects_zero_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("mode: global\nrate: 0\nburst: 10").unwrap();
        let err = RateLimitFilter::from_config(&yaml).err().expect("should error");
        assert!(
            err.to_string().contains("rate must be greater than 0"),
            "should reject zero rate, got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_negative_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("mode: global\nrate: -5\nburst: 10").unwrap();
        let err = RateLimitFilter::from_config(&yaml).err().expect("should error");
        assert!(
            err.to_string().contains("rate must be greater than 0"),
            "should reject negative rate, got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_zero_burst() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("mode: global\nrate: 10\nburst: 0").unwrap();
        let err = RateLimitFilter::from_config(&yaml).err().expect("should error");
        assert!(
            err.to_string().contains("burst must be at least 1"),
            "should reject zero burst, got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_burst_below_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("mode: global\nrate: 100\nburst: 50").unwrap();
        let err = RateLimitFilter::from_config(&yaml).err().expect("should error");
        assert!(
            err.to_string().contains("burst must be >= rate"),
            "should reject burst < rate, got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_unknown_mode() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("mode: sliding_window\nrate: 10\nburst: 20").unwrap();
        let err = RateLimitFilter::from_config(&yaml).err().expect("should error");
        assert!(
            err.to_string().contains("unknown mode"),
            "should reject unknown mode, got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_missing_fields() {
        let yaml = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        assert!(
            RateLimitFilter::from_config(&yaml).is_err(),
            "missing fields should error"
        );
    }

    #[tokio::test]
    async fn global_mode_rejects_when_depleted() {
        let filter = make_filter("global", 10.0, 2);
        let req = crate::test_utils::make_request(http::Method::GET, "/");

        for i in 0..2 {
            let mut ctx = crate::test_utils::make_filter_context(&req);
            ctx.client_addr = Some("10.0.0.1".parse().unwrap());
            let action = filter.on_request(&mut ctx).await.unwrap();
            assert!(
                matches!(action, FilterAction::Continue),
                "request {i} within burst should continue"
            );
        }

        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.0.0.1".parse().unwrap());
        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(ref r) if r.status == 429),
            "request past burst should be rejected with 429"
        );
    }

    #[tokio::test]
    async fn per_ip_mode_isolates_clients() {
        let filter = make_filter("per_ip", 10.0, 1);
        let req = crate::test_utils::make_request(http::Method::GET, "/");

        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.0.0.1".parse().unwrap());
        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "first request from IP A should continue"
        );

        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.0.0.1".parse().unwrap());
        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(ref r) if r.status == 429),
            "second request from IP A should be rejected"
        );

        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.0.0.2".parse().unwrap());
        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "first request from IP B should still succeed (isolated bucket)"
        );
    }

    #[tokio::test]
    async fn per_ip_mode_no_client_addr_rejects() {
        let filter = make_filter("per_ip", 10.0, 10);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(ref r) if r.status == 429),
            "missing client addr should be rejected with 429"
        );
    }

    #[tokio::test]
    async fn rejection_includes_retry_after() {
        let filter = make_filter("global", 10.0, 1);
        let req = crate::test_utils::make_request(http::Method::GET, "/");

        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.0.0.1".parse().unwrap());
        filter.on_request(&mut ctx).await.unwrap();

        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.0.0.1".parse().unwrap());
        let action = filter.on_request(&mut ctx).await.unwrap();

        match action {
            FilterAction::Reject(r) => {
                let retry = r.headers.iter().find(|(n, _)| n == "Retry-After");
                assert!(retry.is_some(), "rejection should include Retry-After header");
                let val: u64 = retry.unwrap().1.parse().expect("Retry-After should be numeric");
                assert!(val >= 1, "Retry-After should be at least 1 second, got {val}");
            },
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejection_includes_rate_limit_headers() {
        let filter = make_filter("global", 10.0, 1);
        let req = crate::test_utils::make_request(http::Method::GET, "/");

        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.0.0.1".parse().unwrap());
        filter.on_request(&mut ctx).await.unwrap();

        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.0.0.1".parse().unwrap());
        let action = filter.on_request(&mut ctx).await.unwrap();

        match action {
            FilterAction::Reject(r) => {
                let has_limit = r.headers.iter().any(|(n, _)| n == "X-RateLimit-Limit");
                let has_remaining = r.headers.iter().any(|(n, _)| n == "X-RateLimit-Remaining");
                let has_reset = r.headers.iter().any(|(n, _)| n == "X-RateLimit-Reset");
                assert!(has_limit, "rejection should include X-RateLimit-Limit");
                assert!(has_remaining, "rejection should include X-RateLimit-Remaining");
                assert!(has_reset, "rejection should include X-RateLimit-Reset");

                let limit_val = &r.headers.iter().find(|(n, _)| n == "X-RateLimit-Limit").unwrap().1;
                assert_eq!(limit_val, "1", "X-RateLimit-Limit should equal burst");

                let remaining_val = &r.headers.iter().find(|(n, _)| n == "X-RateLimit-Remaining").unwrap().1;
                assert_eq!(remaining_val, "0", "X-RateLimit-Remaining should be 0 on rejection");
            },
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn on_response_injects_headers() {
        let filter = make_filter("global", 10.0, 5);
        let req = crate::test_utils::make_request(http::Method::GET, "/");

        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.0.0.1".parse().unwrap());
        filter.on_request(&mut ctx).await.unwrap();

        let mut resp = crate::test_utils::make_response();
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.0.0.1".parse().unwrap());
        ctx.response_header = Some(&mut resp);

        let action = filter.on_response(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "on_response should always continue"
        );

        assert!(
            resp.headers.contains_key("x-ratelimit-limit"),
            "response should contain X-RateLimit-Limit"
        );
        assert!(
            resp.headers.contains_key("x-ratelimit-remaining"),
            "response should contain X-RateLimit-Remaining"
        );
        assert!(
            resp.headers.contains_key("x-ratelimit-reset"),
            "response should contain X-RateLimit-Reset"
        );
    }

    #[test]
    fn per_ip_eviction_removes_stale_entries() {
        let map: DashMap<IpAddr, TokenBucket> = DashMap::new();
        let rate = 10.0;
        let burst = 20.0;
        let idle_threshold_nanos = (2.0 * burst / rate * 1_000_000_000.0) as u64;

        for i in 0..(MAX_PER_IP_ENTRIES + 50) {
            let ip: IpAddr = format!("10.{}.{}.{}", (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF)
                .parse()
                .unwrap();
            let bucket = TokenBucket::new(burst);
            bucket.try_acquire(rate, burst, 0);
            map.insert(ip, bucket);
        }

        assert!(
            map.len() > MAX_PER_IP_ENTRIES,
            "map should exceed high-water mark before eviction"
        );

        let now_nanos = idle_threshold_nanos + 1;
        let filter = RateLimitFilter {
            state: RateLimitState::PerIp(DashMap::new()),
            rate,
            burst,
            epoch: Instant::now(),
        };
        filter.maybe_evict(&map, now_nanos);

        assert!(
            map.len() < MAX_PER_IP_ENTRIES + 50,
            "eviction should have removed stale entries, got {}",
            map.len()
        );
    }

    #[test]
    fn per_ip_eviction_skips_when_below_threshold() {
        let map: DashMap<IpAddr, TokenBucket> = DashMap::new();
        let rate = 10.0;
        let burst = 20.0;

        for i in 0..10 {
            let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
            let bucket = TokenBucket::new(burst);
            bucket.try_acquire(rate, burst, 0);
            map.insert(ip, bucket);
        }

        let filter = RateLimitFilter {
            state: RateLimitState::PerIp(DashMap::new()),
            rate,
            burst,
            epoch: Instant::now(),
        };
        filter.maybe_evict(&map, 999_999_999_999);

        assert_eq!(map.len(), 10, "eviction should not run when below threshold");
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    /// Build a [`RateLimitFilter`] directly (bypassing YAML parsing).
    fn make_filter(mode: &str, rate: f64, burst: u32) -> RateLimitFilter {
        let burst_f = f64::from(burst);
        let state = match mode {
            "global" => RateLimitState::Global(TokenBucket::new(burst_f)),
            "per_ip" => RateLimitState::PerIp(DashMap::new()),
            _ => panic!("invalid mode in test utility"),
        };
        RateLimitFilter {
            state,
            rate,
            burst: burst_f,
            epoch: Instant::now(),
        }
    }
}
