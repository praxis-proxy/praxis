// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the rate limit filter.

use std::{net::IpAddr, time::Instant};

use dashmap::DashMap;
use praxis_core::connectivity::normalize_mapped_ipv4;

use super::{
    EVICTION_INTERVAL_NANOS, HARD_CAP_PER_IP_ENTRIES, Ipv6PrefixLen, MAX_PER_IP_ENTRIES, PerIpState, RateLimitFilter,
    RateLimitState, config::RateLimitConfig,
};
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
    let state = populate_stale_state(count, rate, burst);

    assert!(
        state.buckets.len() > MAX_PER_IP_ENTRIES,
        "map should exceed soft cap before eviction"
    );

    let filter = make_eviction_filter(rate, burst);
    filter.maybe_evict(&state, idle_nanos);

    assert!(
        state.buckets.len() < count,
        "eviction should have removed stale entries, got {}",
        state.buckets.len()
    );
    assert_eq!(
        state.entries(),
        state.buckets.len(),
        "entry counter should track the map after eviction"
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

    let state = PerIpState::from_buckets(map, Ipv6PrefixLen::default());
    let filter = RateLimitFilter {
        state: RateLimitState::PerIp(PerIpState::new(Ipv6PrefixLen::default())),
        rate,
        burst,
        burst_string: (burst as u64).to_string(),
        burst_value: http::header::HeaderValue::from(burst as u64),
        header_limit: http::header::HeaderName::from_static("x-ratelimit-limit"),
        header_remaining: http::header::HeaderName::from_static("x-ratelimit-remaining"),
        header_reset: http::header::HeaderName::from_static("x-ratelimit-reset"),
        epoch: Instant::now(),
    };
    filter.maybe_evict(&state, 999_999_999_999);

    assert_eq!(state.buckets.len(), 10, "eviction should not run when below threshold");
}

#[test]
fn eviction_pass_is_claimed_at_most_once_per_interval() {
    let state = PerIpState::new(Ipv6PrefixLen::default());
    let first = EVICTION_INTERVAL_NANOS;

    assert!(
        state.claim_eviction_pass(first),
        "first eligible pass should be claimed"
    );
    assert!(
        !state.claim_eviction_pass(first),
        "a second claim at the same instant must be refused"
    );
    assert!(
        !state.claim_eviction_pass(first + EVICTION_INTERVAL_NANOS - 1),
        "a claim inside the interval must be refused"
    );
    assert!(
        state.claim_eviction_pass(first + EVICTION_INTERVAL_NANOS),
        "a claim after the interval should be granted"
    );
}

#[test]
fn eviction_does_not_rescan_within_the_interval() {
    let rate = 10.0;
    let burst = 20.0;
    let count = MAX_PER_IP_ENTRIES + 50;
    let idle_nanos = (2.0 * burst / rate * 1_000_000_000.0) as u64 + 1;
    let state = populate_stale_state(count, rate, burst);
    let filter = make_eviction_filter(rate, burst);

    filter.maybe_evict(&state, idle_nanos);
    let after_first = state.buckets.len();
    assert!(after_first < count, "first pass should reclaim");

    for i in 0..100 {
        let ip: IpAddr = format!("172.16.{}.{}", i / 256, i % 256).parse().unwrap();
        state.buckets.insert(ip, TokenBucket::new(burst));
    }
    let before_second = state.buckets.len();
    filter.maybe_evict(&state, idle_nanos);

    assert_eq!(
        state.buckets.len(),
        before_second,
        "a second pass inside the interval must not touch the map"
    );
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
        state: RateLimitState::PerIp(PerIpState::from_buckets(map, Ipv6PrefixLen::default())),
        rate,
        burst,
        burst_string: (burst as u64).to_string(),
        burst_value: http::header::HeaderValue::from(burst as u64),
        header_limit: http::header::HeaderName::from_static("x-ratelimit-limit"),
        header_remaining: http::header::HeaderName::from_static("x-ratelimit-remaining"),
        header_reset: http::header::HeaderName::from_static("x-ratelimit-reset"),
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
        state: RateLimitState::PerIp(PerIpState::from_buckets(map, Ipv6PrefixLen::default())),
        rate,
        burst,
        burst_string: (burst as u64).to_string(),
        burst_value: http::header::HeaderValue::from(burst as u64),
        header_limit: http::header::HeaderName::from_static("x-ratelimit-limit"),
        header_remaining: http::header::HeaderName::from_static("x-ratelimit-remaining"),
        header_reset: http::header::HeaderName::from_static("x-ratelimit-reset"),
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
    let state = populate_stale_state(count, rate, burst);
    let filter = make_eviction_filter(rate, burst);

    filter.maybe_evict(&state, idle_nanos);

    assert!(
        state.buckets.len() <= MAX_PER_IP_ENTRIES,
        "a single eviction pass should bring the map to or below the soft cap, got {}",
        state.buckets.len()
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

#[test]
fn ipv6_prefix_len_defaults_to_128() {
    let cfg: RateLimitConfig = serde_yaml::from_str("mode: per_ip\nrate: 1\nburst: 1").unwrap();
    assert_eq!(
        cfg.ipv6_prefix_len,
        Ipv6PrefixLen::try_from(128_u8).unwrap(),
        "omitted ipv6_prefix_len should key IPv6 clients by full address"
    );
}

#[test]
fn ipv6_prefix_len_accepts_bounds() {
    for len in [1_u8, 60, 64, 127, 128] {
        let yaml: serde_yaml::Value =
            serde_yaml::from_str(&format!("mode: per_ip\nrate: 1\nburst: 1\nipv6_prefix_len: {len}")).unwrap();
        assert!(
            RateLimitFilter::from_config(&yaml).is_ok(),
            "ipv6_prefix_len {len} should be accepted"
        );
    }
}

#[test]
fn ipv6_prefix_len_rejects_out_of_range() {
    for len in ["0", "129"] {
        let yaml: serde_yaml::Value =
            serde_yaml::from_str(&format!("mode: per_ip\nrate: 1\nburst: 1\nipv6_prefix_len: {len}")).unwrap();
        let err = RateLimitFilter::from_config(&yaml).err().expect("should error");
        assert!(
            err.to_string().contains("ipv6_prefix_len must be in 1..=128"),
            "ipv6_prefix_len {len} should be rejected: {err}"
        );
    }
}

#[test]
fn ipv6_prefix_len_rejects_non_integer() {
    for len in ["256", "-1", "64.5", "\"64\"", "abc", "null"] {
        let yaml: serde_yaml::Value =
            serde_yaml::from_str(&format!("mode: per_ip\nrate: 1\nburst: 1\nipv6_prefix_len: {len}")).unwrap();
        assert!(
            RateLimitFilter::from_config(&yaml).is_err(),
            "ipv6_prefix_len {len} should be rejected"
        );
    }
}

#[test]
fn ipv6_prefix_len_mask_values() {
    let cases = [
        (1_u8, 0x8000_0000_0000_0000_0000_0000_0000_0000_u128),
        (60, 0xFFFF_FFFF_FFFF_FFF0_0000_0000_0000_0000),
        (64, 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000),
        (127, u128::MAX - 1),
        (128, u128::MAX),
    ];
    for (len, expected) in cases {
        assert_eq!(
            Ipv6PrefixLen::try_from(len).unwrap().mask(),
            expected,
            "mask for /{len} should have the top {len} bits set"
        );
    }
}

#[test]
fn bucket_key_masks_ipv6_to_prefix() {
    let cases = [
        (64_u8, "2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::"),
        (
            128,
            "2001:db8:1:2:aaaa:bbbb:cccc:dddd",
            "2001:db8:1:2:aaaa:bbbb:cccc:dddd",
        ),
        (1, "ffff:db8::1", "8000::"),
        (1, "2001:db8::1", "::"),
        (127, "2001:db8::3", "2001:db8::2"),
        (60, "2001:db8:1:234f:ffff::1", "2001:db8:1:2340::"),
    ];
    for (len, addr, expected) in cases {
        let state = PerIpState::new(Ipv6PrefixLen::try_from(len).unwrap());
        assert_eq!(
            state.bucket_key(addr.parse().unwrap()),
            expected.parse::<IpAddr>().unwrap(),
            "{addr} at /{len} should key as {expected}"
        );
    }
}

#[test]
fn bucket_key_leaves_ipv4_and_mapped_ipv4_unmasked() {
    let state = PerIpState::new(Ipv6PrefixLen::try_from(1_u8).unwrap());
    let native: IpAddr = "10.0.0.255".parse().unwrap();
    assert_eq!(state.bucket_key(native), native, "IPv4 should be keyed by full address");
    assert_eq!(
        state.bucket_key("::ffff:10.0.0.255".parse().unwrap()),
        native,
        "mapped IPv4 should normalize to full IPv4 before any IPv6 masking"
    );
}

#[test]
fn per_ip_same_ipv6_64_shares_bucket() {
    let filter = make_ipv6_filter(64, 1);
    let first: IpAddr = "2001:db8:1:2::1".parse().unwrap();
    let rotated: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();

    assert!(filter.try_acquire_for(Some(first)).is_ok(), "first request should pass");
    assert!(
        filter.try_acquire_for(Some(rotated)).is_err(),
        "rotating within the same /64 should hit the same exhausted bucket"
    );
    assert!(
        filter.current_remaining(Some(rotated)) < 1.0,
        "response headers should report the shared /64 bucket"
    );
}

#[test]
fn per_ip_different_ipv6_64s_are_isolated() {
    let filter = make_ipv6_filter(64, 1);
    assert!(
        filter.try_acquire_for(Some("2001:db8:1:2::1".parse().unwrap())).is_ok(),
        "first /64 should pass"
    );
    assert!(
        filter.try_acquire_for(Some("2001:db8:1:3::1".parse().unwrap())).is_ok(),
        "adjacent /64 should get its own bucket"
    );
}

#[test]
fn per_ip_ipv6_128_keys_full_address() {
    let filter = make_ipv6_filter(128, 1);
    assert!(
        filter.try_acquire_for(Some("2001:db8::1".parse().unwrap())).is_ok(),
        "first address should pass"
    );
    assert!(
        filter.try_acquire_for(Some("2001:db8::2".parse().unwrap())).is_ok(),
        "/128 should give each address its own bucket"
    );
}

#[test]
fn per_ip_ipv6_rotation_does_not_grow_map() {
    let filter = RateLimitFilter {
        state: RateLimitState::PerIp(PerIpState::new(Ipv6PrefixLen::try_from(64_u8).unwrap())),
        ..make_filter("per_ip", 0.001, 1)
    };
    let passed = (0..1_000_u128)
        .map(|host| std::net::Ipv6Addr::from_bits(0x2001_0DB8_0001_0002_0000_0000_0000_0000 | host))
        .filter(|addr| filter.try_acquire_for(Some(IpAddr::V6(*addr))).is_ok())
        .count();
    assert_eq!(
        passed, 1,
        "rotating source addresses within a /64 should not refresh the burst"
    );
    let RateLimitState::PerIp(state) = &filter.state else {
        panic!("expected per-IP state");
    };
    assert_eq!(state.entries(), 1, "one /64 should occupy a single map entry");
    assert_eq!(state.buckets.len(), 1, "one /64 should occupy a single map entry");
}

#[test]
fn per_ip_ipv4_unaffected_by_ipv6_prefix_len() {
    let filter = make_ipv6_filter(1, 1);
    assert!(
        filter.try_acquire_for(Some("10.0.0.1".parse().unwrap())).is_ok(),
        "first IPv4 client should pass"
    );
    assert!(
        filter.try_acquire_for(Some("::ffff:10.0.0.2".parse().unwrap())).is_ok(),
        "a different mapped IPv4 client should get its own bucket"
    );
    assert!(
        filter
            .try_acquire_for(Some("::ffff:10.0.0.1".parse().unwrap()))
            .is_err(),
        "mapped IPv4 should still share the plain IPv4 bucket"
    );
}

#[test]
fn global_mode_ignores_ipv6_prefix_len() {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str("mode: global\nrate: 1\nburst: 1\nipv6_prefix_len: 128").unwrap();
    assert!(
        RateLimitFilter::from_config(&yaml).is_ok(),
        "ipv6_prefix_len should parse in global mode"
    );

    let filter = make_filter("global", 10.0, 1);
    assert!(
        filter.try_acquire_for(Some("2001:db8:1::1".parse().unwrap())).is_ok(),
        "first request should pass"
    );
    assert!(
        filter.try_acquire_for(Some("2001:db8:2::1".parse().unwrap())).is_err(),
        "global mode should share one bucket across all prefixes"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Populate a [`DashMap`] with `count` stale entries (last activity at t=0).
fn populate_stale_state(count: usize, rate: f64, burst: f64) -> PerIpState {
    PerIpState::from_buckets(populate_stale_map(count, rate, burst), Ipv6PrefixLen::default())
}

/// Build a per-IP map of `count` fully idle buckets.
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
        state: RateLimitState::PerIp(PerIpState::new(Ipv6PrefixLen::default())),
        rate,
        burst,
        burst_string: (burst as u64).to_string(),
        burst_value: http::header::HeaderValue::from(burst as u64),
        header_limit: http::header::HeaderName::from_static("x-ratelimit-limit"),
        header_remaining: http::header::HeaderName::from_static("x-ratelimit-remaining"),
        header_reset: http::header::HeaderName::from_static("x-ratelimit-reset"),
        epoch: Instant::now(),
    }
}

/// Build a per-IP [`RateLimitFilter`] grouping IPv6 clients by `prefix_len`.
fn make_ipv6_filter(prefix_len: u8, burst: u32) -> RateLimitFilter {
    RateLimitFilter {
        state: RateLimitState::PerIp(PerIpState::new(Ipv6PrefixLen::try_from(prefix_len).unwrap())),
        ..make_filter("per_ip", 10.0, burst)
    }
}

/// Build a [`RateLimitFilter`] directly (bypassing YAML parsing).
fn make_filter(mode: &str, rate: f64, burst: u32) -> RateLimitFilter {
    let burst_f = f64::from(burst);
    let state = match mode {
        "global" => RateLimitState::Global(TokenBucket::new(burst_f)),
        "per_ip" => RateLimitState::PerIp(PerIpState::new(Ipv6PrefixLen::default())),
        _ => panic!("invalid mode in test utility"),
    };
    RateLimitFilter {
        state,
        rate,
        burst: burst_f,
        burst_string: u64::from(burst).to_string(),
        burst_value: http::header::HeaderValue::from(u64::from(burst)),
        header_limit: http::header::HeaderName::from_static("x-ratelimit-limit"),
        header_remaining: http::header::HeaderName::from_static("x-ratelimit-remaining"),
        header_reset: http::header::HeaderName::from_static("x-ratelimit-reset"),
        epoch: Instant::now(),
    }
}
