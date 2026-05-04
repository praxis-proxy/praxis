// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Tests for the circuit breaker filter.

use std::sync::Arc;

use super::{
    CircuitBreakerFilter,
    state::{CircuitBreaker, CircuitState},
};
use crate::{FilterAction, filter::HttpFilter};

// ---------------------------------------------------------------------------
// State Machine Tests
// ---------------------------------------------------------------------------

#[test]
fn starts_in_closed_state() {
    let cb = CircuitBreaker::new(3, 30);
    assert_eq!(cb.state(), CircuitState::Closed, "new breaker should start closed");
}

#[test]
fn stays_closed_below_threshold() {
    let cb = CircuitBreaker::new(3, 30);
    cb.record_failure();
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Closed, "should stay closed below threshold");
}

#[test]
fn trips_to_open_at_threshold() {
    let cb = CircuitBreaker::new(3, 30);
    cb.record_failure();
    cb.record_failure();
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Open, "should trip to open at threshold");
}

#[test]
fn success_resets_failure_count() {
    let cb = CircuitBreaker::new(3, 30);
    cb.record_failure();
    cb.record_failure();
    cb.record_success();
    cb.record_failure();
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Closed, "success should reset failure count");
}

#[test]
fn open_rejects_via_check() {
    let cb = CircuitBreaker::new(1, 9999);
    cb.record_failure();
    assert_eq!(
        cb.check(),
        CircuitState::Open,
        "open circuit should report Open on check"
    );
}

#[test]
fn half_open_after_recovery_window() {
    let cb = CircuitBreaker::new(1, 0);
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Open, "should be open after failure");
    let state = cb.check();
    assert_eq!(
        state,
        CircuitState::HalfOpen,
        "should transition to half-open after 0s window"
    );
}

#[test]
fn half_open_success_transitions_to_closed() {
    let cb = CircuitBreaker::new(1, 0);
    cb.record_failure();
    let _ = cb.check();
    assert_eq!(cb.state(), CircuitState::HalfOpen, "should be half-open");
    cb.record_success();
    assert_eq!(cb.state(), CircuitState::Closed, "success in half-open should close");
}

#[test]
fn half_open_failure_transitions_to_open() {
    let cb = CircuitBreaker::new(1, 0);
    cb.record_failure();
    let _ = cb.check();
    assert_eq!(cb.state(), CircuitState::HalfOpen, "should be half-open");
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Open, "failure in half-open should reopen");
}

#[test]
fn multiple_successes_in_closed_keep_closed() {
    let cb = CircuitBreaker::new(3, 30);
    for _ in 0..10 {
        cb.record_success();
    }
    assert_eq!(
        cb.state(),
        CircuitState::Closed,
        "repeated successes should stay closed"
    );
}

#[test]
fn open_record_failure_is_noop() {
    let cb = CircuitBreaker::new(1, 9999);
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Open, "should be open");
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Open, "extra failure in open should be no-op");
}

#[test]
fn open_record_success_is_noop() {
    let cb = CircuitBreaker::new(1, 9999);
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Open, "should be open");
    cb.record_success();
    assert_eq!(
        cb.state(),
        CircuitState::Open,
        "success in open should be no-op (only check transitions to half-open)"
    );
}

// ---------------------------------------------------------------------------
// Filter Tests
// ---------------------------------------------------------------------------

#[test]
fn from_config_valid() {
    let yaml = serde_yaml::from_str::<serde_yaml::Value>(
        "
clusters:
  - name: backend
    consecutive_failures: 5
    recovery_window_secs: 30
",
    )
    .unwrap();
    let filter = CircuitBreakerFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "circuit_breaker",
        "filter name should be circuit_breaker"
    );
}

#[test]
fn from_config_rejects_zero_threshold() {
    let yaml = serde_yaml::from_str::<serde_yaml::Value>(
        "
clusters:
  - name: backend
    consecutive_failures: 0
    recovery_window_secs: 30
",
    )
    .unwrap();
    let result = CircuitBreakerFilter::from_config(&yaml);
    let err = result.err().expect("should reject zero threshold");
    assert!(
        err.to_string().contains("consecutive_failures must be > 0"),
        "should reject zero threshold: {err}"
    );
}

#[test]
fn from_config_rejects_zero_recovery() {
    let yaml = serde_yaml::from_str::<serde_yaml::Value>(
        "
clusters:
  - name: backend
    consecutive_failures: 5
    recovery_window_secs: 0
",
    )
    .unwrap();
    let result = CircuitBreakerFilter::from_config(&yaml);
    let err = result.err().expect("should reject zero recovery");
    assert!(
        err.to_string().contains("recovery_window_secs must be > 0"),
        "should reject zero recovery: {err}"
    );
}

#[tokio::test]
async fn on_request_passes_when_closed() {
    let filter = make_filter(5, 30);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "closed circuit should continue"
    );
}

#[tokio::test]
async fn on_request_rejects_when_open() {
    let filter = make_filter(1, 9999);
    let req = crate::test_utils::make_request(http::Method::GET, "/");

    let mut resp = crate::test_utils::make_response();
    resp.status = http::StatusCode::INTERNAL_SERVER_ERROR;
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());

    let mut ctx2 = crate::test_utils::make_filter_context(&req);
    ctx2.cluster = Some(Arc::from("backend"));
    let action = filter.on_request(&mut ctx2).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 503),
        "open circuit should reject with 503"
    );
}

#[tokio::test]
async fn on_request_passes_for_unconfigured_cluster() {
    let filter = make_filter(1, 30);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("other"));
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "unconfigured cluster should pass through"
    );
}

#[tokio::test]
async fn on_request_passes_when_no_cluster() {
    let filter = make_filter(1, 30);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "no cluster should pass through"
    );
}

#[tokio::test]
async fn on_response_records_server_error_as_failure() {
    let filter = make_filter(2, 30);
    let req = crate::test_utils::make_request(http::Method::GET, "/");

    for _ in 0..2 {
        let mut resp = crate::test_utils::make_response();
        resp.status = http::StatusCode::INTERNAL_SERVER_ERROR;
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some(Arc::from("backend"));
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());
    }

    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(_)),
        "two 500s should trip the circuit"
    );
}

#[tokio::test]
async fn on_response_success_resets_failures() {
    let filter = make_filter(2, 30);
    let req = crate::test_utils::make_request(http::Method::GET, "/");

    let mut resp = crate::test_utils::make_response();
    resp.status = http::StatusCode::INTERNAL_SERVER_ERROR;
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());

    let mut resp2 = crate::test_utils::make_response();
    resp2.status = http::StatusCode::OK;
    let mut ctx2 = crate::test_utils::make_filter_context(&req);
    ctx2.cluster = Some(Arc::from("backend"));
    ctx2.response_header = Some(&mut resp2);
    drop(filter.on_response(&mut ctx2).await.unwrap());

    let mut resp3 = crate::test_utils::make_response();
    resp3.status = http::StatusCode::INTERNAL_SERVER_ERROR;
    let mut ctx3 = crate::test_utils::make_filter_context(&req);
    ctx3.cluster = Some(Arc::from("backend"));
    ctx3.response_header = Some(&mut resp3);
    drop(filter.on_response(&mut ctx3).await.unwrap());

    let mut ctx4 = crate::test_utils::make_filter_context(&req);
    ctx4.cluster = Some(Arc::from("backend"));
    let action = filter.on_request(&mut ctx4).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "intervening success should have reset failures"
    );
}

#[tokio::test]
async fn on_response_records_502_as_failure() {
    let filter = make_filter(1, 9999);
    let req = crate::test_utils::make_request(http::Method::GET, "/");

    let mut resp = crate::test_utils::make_response();
    resp.status = http::StatusCode::BAD_GATEWAY;
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());

    let mut ctx2 = crate::test_utils::make_filter_context(&req);
    ctx2.cluster = Some(Arc::from("backend"));
    let action = filter.on_request(&mut ctx2).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 503),
        "502 should be recorded as failure and trip the circuit"
    );
}

#[tokio::test]
async fn on_response_records_503_as_failure() {
    let filter = make_filter(1, 9999);
    let req = crate::test_utils::make_request(http::Method::GET, "/");

    let mut resp = crate::test_utils::make_response();
    resp.status = http::StatusCode::SERVICE_UNAVAILABLE;
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());

    let mut ctx2 = crate::test_utils::make_filter_context(&req);
    ctx2.cluster = Some(Arc::from("backend"));
    let action = filter.on_request(&mut ctx2).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 503),
        "503 should be recorded as failure and trip the circuit"
    );
}

#[tokio::test]
async fn on_response_records_504_as_failure() {
    let filter = make_filter(1, 9999);
    let req = crate::test_utils::make_request(http::Method::GET, "/");

    let mut resp = crate::test_utils::make_response();
    resp.status = http::StatusCode::GATEWAY_TIMEOUT;
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());

    let mut ctx2 = crate::test_utils::make_filter_context(&req);
    ctx2.cluster = Some(Arc::from("backend"));
    let action = filter.on_request(&mut ctx2).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 503),
        "504 should be recorded as failure and trip the circuit"
    );
}

#[tokio::test]
async fn on_response_records_499_as_success() {
    let filter = make_filter(2, 30);
    let req = crate::test_utils::make_request(http::Method::GET, "/");

    let mut resp = crate::test_utils::make_response();
    resp.status = http::StatusCode::from_u16(499).unwrap();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());

    let mut ctx2 = crate::test_utils::make_filter_context(&req);
    ctx2.cluster = Some(Arc::from("backend"));
    let action = filter.on_request(&mut ctx2).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "499 should be recorded as success, circuit should stay closed"
    );
}

#[tokio::test]
async fn clusters_are_isolated() {
    let filter = make_two_cluster_filter(1, 9999);
    let req = crate::test_utils::make_request(http::Method::GET, "/");

    let mut resp = crate::test_utils::make_response();
    resp.status = http::StatusCode::INTERNAL_SERVER_ERROR;
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("cluster-a"));
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());

    let mut ctx_a = crate::test_utils::make_filter_context(&req);
    ctx_a.cluster = Some(Arc::from("cluster-a"));
    let action_a = filter.on_request(&mut ctx_a).await.unwrap();
    assert!(
        matches!(action_a, FilterAction::Reject(_)),
        "cluster-a should be open after failure"
    );

    let mut ctx_b = crate::test_utils::make_filter_context(&req);
    ctx_b.cluster = Some(Arc::from("cluster-b"));
    let action_b = filter.on_request(&mut ctx_b).await.unwrap();
    assert!(
        matches!(action_b, FilterAction::Continue),
        "cluster-b should remain closed when cluster-a is open"
    );
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

/// Build a [`CircuitBreakerFilter`] for testing with a single cluster named "backend".
fn make_filter(threshold: u32, recovery_secs: u64) -> CircuitBreakerFilter {
    let mut breakers = std::collections::HashMap::new();
    breakers.insert(Arc::from("backend"), CircuitBreaker::new(threshold, recovery_secs));
    CircuitBreakerFilter { breakers }
}

/// Build a [`CircuitBreakerFilter`] with two clusters for isolation testing.
fn make_two_cluster_filter(threshold: u32, recovery_secs: u64) -> CircuitBreakerFilter {
    let mut breakers = std::collections::HashMap::new();
    breakers.insert(Arc::from("cluster-a"), CircuitBreaker::new(threshold, recovery_secs));
    breakers.insert(Arc::from("cluster-b"), CircuitBreaker::new(threshold, recovery_secs));
    CircuitBreakerFilter { breakers }
}
