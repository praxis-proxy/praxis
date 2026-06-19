// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the rate limit filter.

use std::{net::IpAddr, time::Instant};

use dashmap::DashMap;
use praxis_core::connectivity::normalize_mapped_ipv4;

use super::{HARD_CAP_PER_IP_ENTRIES, MAX_PER_IP_ENTRIES, RateLimitFilter, RateLimitState};
use crate::{FilterAction, builtins::http::traffic_management::token_bucket::TokenBucket, filter::HttpFilter as _};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

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
        err.to_string().contains("rate must be a finite number greater than 0"),
        "should reject zero rate: {err}"
    );
}

#[test]
fn from_config_rejects_nan_rate() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("mode: global\nrate: .nan\nburst: 10").unwrap();
    let err = RateLimitFilter::from_config(&yaml).err().expect("should error");
    assert!(err.to_string().contains("finite"), "should reject NaN rate, got: {err}");
}

#[test]
fn from_config_rejects_infinity_rate() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("mode: global\nrate: .inf\nburst: 10").unwrap();
    let err = RateLimitFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("finite"),
        "should reject infinity rate, got: {err}"
    );
}

#[test]
fn from_config_rejects_negative_rate() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("mode: global\nrate: -5\nburst: 10").unwrap();
    let err = RateLimitFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("rate must be a finite number greater than 0"),
        "should reject negative rate: {err}"
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
        err.to_string().contains("rate_limit"),
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
        matches!(&action, FilterAction::Reject(r) if r.status == 429),
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
        matches!(&action, FilterAction::Reject(r) if r.status == 429),
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
        matches!(&action, FilterAction::Reject(r) if r.status == 429),
        "missing client addr should be rejected with 429"
    );
}

#[tokio::test]
async fn rejection_includes_retry_after() {
    let filter = make_filter("global", 10.0, 1);
    let req = crate::test_utils::make_request(http::Method::GET, "/");

    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.client_addr = Some("10.0.0.1".parse().unwrap());
    drop(filter.on_request(&mut ctx).await.unwrap());

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
    drop(filter.on_request(&mut ctx).await.unwrap());

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
    drop(filter.on_request(&mut ctx).await.unwrap());

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
    let rate = 10.0;
    let burst = 20.0;
    let count = MAX_PER_IP_ENTRIES + 50;
    let idle_nanos = (2.0 * burst / rate * 1_000_000_000.0) as u64 + 1;
    let map = populate_stale_map(count, rate, burst);

    assert!(
        map.len() > MAX_PER_IP_ENTRIES,
        "map should exceed soft cap before eviction"
    );

    let filter = make_eviction_filter(rate, burst);
    filter.maybe_evict(&map, idle_nanos);

    assert!(
        map.len() < count,
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

#[tokio::test]
async fn per_ip_treats_mapped_ipv6_same_as_ipv4() {
    let filter = make_filter("per_ip", 10.0, 1);
    let req = crate::test_utils::make_request(http::Method::GET, "/");

    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.client_addr = Some("10.0.0.1".parse().unwrap());
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "first request from V4 10.0.0.1 should continue"
    );

    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.client_addr = Some("::ffff:10.0.0.1".parse().unwrap());
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(&action, FilterAction::Reject(r) if r.status == 429),
        "request from ::ffff:10.0.0.1 should share bucket with V4 10.0.0.1"
    );
}

#[tokio::test]
async fn per_ip_mapped_ipv6_first_then_v4() {
    let filter = make_filter("per_ip", 10.0, 1);
    let req = crate::test_utils::make_request(http::Method::GET, "/");

    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.client_addr = Some("::ffff:192.168.1.1".parse().unwrap());
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "first request from ::ffff:192.168.1.1 should continue"
    );

    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.client_addr = Some("192.168.1.1".parse().unwrap());
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(&action, FilterAction::Reject(r) if r.status == 429),
        "request from V4 192.168.1.1 should share bucket with ::ffff:192.168.1.1"
    );
}

#[test]
fn normalize_mapped_ipv4_unit() {
    let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
    let native: IpAddr = "10.0.0.1".parse().unwrap();
    assert_eq!(
        normalize_mapped_ipv4(mapped),
        native,
        "mapped IPv6 should normalize to plain IPv4"
    );

    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    assert_eq!(normalize_mapped_ipv4(v6), v6, "native IPv6 should be unchanged");

    assert_eq!(normalize_mapped_ipv4(native), native, "native IPv4 should be unchanged");
}

#[test]
fn hard_cap_rejects_new_ips() {
    let map: DashMap<IpAddr, TokenBucket> = DashMap::new();
    let rate = 10.0;
    let burst = 20.0;

    for i in 0..HARD_CAP_PER_IP_ENTRIES {
        let a = (i >> 16) & 0xFF;
        let b = (i >> 8) & 0xFF;
        let c = i & 0xFF;
        let ip: IpAddr = format!("10.{a}.{b}.{c}").parse().unwrap();
        map.insert(ip, TokenBucket::new(burst));
    }

    assert_eq!(map.len(), HARD_CAP_PER_IP_ENTRIES, "map should be exactly at hard cap");

    let filter = RateLimitFilter {
        state: RateLimitState::PerIp(map),
        rate,
        burst,
        epoch: Instant::now(),
    };

    let novel_ip: IpAddr = "192.168.1.1".parse().unwrap();
    let result = filter.try_acquire_for(Some(novel_ip));
    assert!(result.is_err(), "new IP should be rejected when map is at hard cap");
}

#[test]
fn hard_cap_allows_known_ips() {
    let map: DashMap<IpAddr, TokenBucket> = DashMap::new();
    let rate = 10.0;
    let burst = 20.0;
    let known_ip: IpAddr = "192.168.1.1".parse().unwrap();

    map.insert(known_ip, TokenBucket::new(burst));
    for i in 1..HARD_CAP_PER_IP_ENTRIES {
        let a = (i >> 16) & 0xFF;
        let b = (i >> 8) & 0xFF;
        let c = i & 0xFF;
        let ip: IpAddr = format!("10.{a}.{b}.{c}").parse().unwrap();
        map.insert(ip, TokenBucket::new(burst));
    }

    assert_eq!(map.len(), HARD_CAP_PER_IP_ENTRIES, "map should be exactly at hard cap");

    let filter = RateLimitFilter {
        state: RateLimitState::PerIp(map),
        rate,
        burst,
        epoch: Instant::now(),
    };

    let result = filter.try_acquire_for(Some(known_ip));
    assert!(result.is_ok(), "already-tracked IP should still be allowed at hard cap");
}

#[test]
fn eviction_reclaims_below_soft_cap() {
    let rate = 10.0;
    let burst = 20.0;
    let count = MAX_PER_IP_ENTRIES + 100;
    let idle_nanos = (2.0 * burst / rate * 1_000_000_000.0) as u64 + 1;
    let map = populate_stale_map(count, rate, burst);
    let filter = make_eviction_filter(rate, burst);

    filter.maybe_evict(&map, idle_nanos);
    let after_first = map.len();
    assert!(
        after_first < count,
        "first eviction pass should remove stale entries, got {after_first}"
    );

    while map.len() > MAX_PER_IP_ENTRIES {
        filter.maybe_evict(&map, idle_nanos);
    }
    assert!(
        map.len() <= MAX_PER_IP_ENTRIES,
        "repeated eviction should bring map to or below soft cap, got {}",
        map.len()
    );
}

#[test]
fn rate_limit_headers_saturate_near_u64_max() {
    let ts = praxis_core::time::FixedTimeSource::new(std::time::Duration::from_secs(u64::MAX - 1));
    let filter = make_filter("global", 10.0, 10);
    let (headers, _retry_secs) = filter.rate_limit_headers(0.0, &ts);
    let reset_val = &headers.iter().find(|(n, _)| *n == "X-RateLimit-Reset").unwrap().1;
    let reset_unix: u64 = reset_val.parse().expect("X-RateLimit-Reset should be numeric");
    assert_eq!(
        reset_unix,
        u64::MAX,
        "reset should saturate to u64::MAX instead of wrapping"
    );
}

#[test]
fn from_config_rejects_burst_equal_to_rate_minus_one() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("mode: global\nrate: 10\nburst: 9").unwrap();
    let err = RateLimitFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("burst must be >= rate"),
        "burst of 9 with rate of 10 should be rejected: {err}"
    );
}

#[test]
fn from_config_accepts_burst_equal_to_rate() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("mode: global\nrate: 10\nburst: 10").unwrap();
    let filter = RateLimitFilter::from_config(&yaml).expect("burst equal to rate should be accepted");
    assert_eq!(filter.name(), "rate_limit", "filter name should be rate_limit");
}

#[test]
fn from_config_rejects_unknown_fields() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("mode: global\nrate: 10\nburst: 20\nextra: true").unwrap();
    let err = RateLimitFilter::from_config(&yaml)
        .err()
        .expect("should error on unknown field");
    assert!(
        err.to_string().contains("rate_limit"),
        "unknown field error should reference the filter name: {err}"
    );
}

#[test]
fn from_config_accepts_fractional_rate() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("mode: global\nrate: 0.5\nburst: 1").unwrap();
    let filter = RateLimitFilter::from_config(&yaml).expect("fractional rate of 0.5 should be accepted");
    assert_eq!(filter.name(), "rate_limit", "filter name should be rate_limit");
}

#[test]
fn from_config_rejects_negative_infinity_rate() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("mode: global\nrate: -.inf\nburst: 10").unwrap();
    let err = RateLimitFilter::from_config(&yaml).err().expect("should error");
    assert!(
        err.to_string().contains("rate must be a finite number greater than 0"),
        "should reject negative infinity rate: {err}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Populate a [`DashMap`] with `count` stale entries (last activity at t=0).
fn populate_stale_map(count: usize, rate: f64, burst: f64) -> DashMap<IpAddr, TokenBucket> {
    let map = DashMap::new();
    for i in 0..count {
        let a = (i >> 16) & 0xFF;
        let b = (i >> 8) & 0xFF;
        let c = i & 0xFF;
        let ip: IpAddr = format!("10.{a}.{b}.{c}").parse().unwrap();
        let bucket = TokenBucket::new(burst);
        bucket.try_acquire(rate, burst, 0);
        map.insert(ip, bucket);
    }
    map
}

/// Build a [`RateLimitFilter`] with a throwaway per-IP map for eviction tests.
fn make_eviction_filter(rate: f64, burst: f64) -> RateLimitFilter {
    RateLimitFilter {
        state: RateLimitState::PerIp(DashMap::new()),
        rate,
        burst,
        epoch: Instant::now(),
    }
}

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
