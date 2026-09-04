// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the circuit breaker filter.

use std::sync::Arc;

use praxis_core::circuit::CircuitBreakerConfig as CoreCircuitBreakerConfig;

use super::CircuitBreakerFilter;
use crate::{FilterAction, filter::HttpFilter as _};

// -----------------------------------------------------------------------------
// Filter Config Tests
// -----------------------------------------------------------------------------

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

#[test]
fn from_config_half_open_timeout_defaults() {
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
        "filter should accept config without half_open_timeout_secs"
    );
}

#[test]
fn from_config_half_open_timeout_explicit() {
    let yaml = serde_yaml::from_str::<serde_yaml::Value>(
        "
clusters:
  - name: backend
    consecutive_failures: 5
    recovery_window_secs: 30
    half_open_timeout_secs: 60
",
    )
    .unwrap();
    let filter = CircuitBreakerFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "circuit_breaker",
        "filter should accept config with explicit half_open_timeout_secs"
    );
}

// -----------------------------------------------------------------------------
// Filter Behavioral Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn on_request_passes_when_closed() {
    let filter = make_filter(5, 30);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.current_filter_id = Some(0);
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

    // Record a failure to trip the circuit.
    let mut resp = crate::test_utils::make_response();
    resp.status = http::StatusCode::INTERNAL_SERVER_ERROR;
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.current_filter_id = Some(0);
    drop(filter.on_request(&mut ctx).await.unwrap());
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());

    // Next request should be rejected.
    let mut ctx2 = crate::test_utils::make_filter_context(&req);
    ctx2.cluster = Some(Arc::from("backend"));
    ctx2.current_filter_id = Some(0);
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
    ctx.current_filter_id = Some(0);
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
    ctx.current_filter_id = Some(0);
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
        ctx.current_filter_id = Some(0);
        drop(filter.on_request(&mut ctx).await.unwrap());
        ctx.response_header = Some(&mut resp);
        drop(filter.on_response(&mut ctx).await.unwrap());
    }

    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.current_filter_id = Some(0);
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

    // One failure.
    let mut resp = crate::test_utils::make_response();
    resp.status = http::StatusCode::INTERNAL_SERVER_ERROR;
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.current_filter_id = Some(0);
    drop(filter.on_request(&mut ctx).await.unwrap());
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());

    // One success (resets counter).
    let mut resp2 = crate::test_utils::make_response();
    resp2.status = http::StatusCode::OK;
    let mut ctx2 = crate::test_utils::make_filter_context(&req);
    ctx2.cluster = Some(Arc::from("backend"));
    ctx2.current_filter_id = Some(0);
    drop(filter.on_request(&mut ctx2).await.unwrap());
    ctx2.response_header = Some(&mut resp2);
    drop(filter.on_response(&mut ctx2).await.unwrap());

    // Another failure (counter is 1, not 2).
    let mut resp3 = crate::test_utils::make_response();
    resp3.status = http::StatusCode::INTERNAL_SERVER_ERROR;
    let mut ctx3 = crate::test_utils::make_filter_context(&req);
    ctx3.cluster = Some(Arc::from("backend"));
    ctx3.current_filter_id = Some(0);
    drop(filter.on_request(&mut ctx3).await.unwrap());
    ctx3.response_header = Some(&mut resp3);
    drop(filter.on_response(&mut ctx3).await.unwrap());

    let mut ctx4 = crate::test_utils::make_filter_context(&req);
    ctx4.cluster = Some(Arc::from("backend"));
    ctx4.current_filter_id = Some(0);
    let action = filter.on_request(&mut ctx4).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "intervening success should have reset failures"
    );
}

#[tokio::test]
async fn clusters_are_isolated() {
    let filter = make_two_cluster_filter(1, 9999);
    let req = crate::test_utils::make_request(http::Method::GET, "/");

    // Trip cluster-a.
    let mut resp = crate::test_utils::make_response();
    resp.status = http::StatusCode::INTERNAL_SERVER_ERROR;
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("cluster-a"));
    ctx.current_filter_id = Some(0);
    drop(filter.on_request(&mut ctx).await.unwrap());
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());

    let mut ctx_a = crate::test_utils::make_filter_context(&req);
    ctx_a.cluster = Some(Arc::from("cluster-a"));
    ctx_a.current_filter_id = Some(0);
    let action_a = filter.on_request(&mut ctx_a).await.unwrap();
    assert!(
        matches!(action_a, FilterAction::Reject(_)),
        "cluster-a should be open after failure"
    );

    let mut ctx_b = crate::test_utils::make_filter_context(&req);
    ctx_b.cluster = Some(Arc::from("cluster-b"));
    ctx_b.current_filter_id = Some(0);
    let action_b = filter.on_request(&mut ctx_b).await.unwrap();
    assert!(
        matches!(action_b, FilterAction::Continue),
        "cluster-b should remain closed when cluster-a is open"
    );
}

#[tokio::test]
async fn on_response_no_header_records_failure() {
    let filter = make_filter(1, 9999);
    let req = crate::test_utils::make_request(http::Method::GET, "/");

    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.current_filter_id = Some(0);
    drop(filter.on_request(&mut ctx).await.unwrap());
    drop(filter.on_response(&mut ctx).await.unwrap());

    let mut ctx2 = crate::test_utils::make_filter_context(&req);
    ctx2.cluster = Some(Arc::from("backend"));
    ctx2.current_filter_id = Some(0);
    let action = filter.on_request(&mut ctx2).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 503),
        "missing response header (connection failure) should trip the circuit"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a [`CircuitBreakerFilter`] for testing with a single cluster named "backend".
fn make_filter(threshold: u32, recovery_secs: u64) -> CircuitBreakerFilter {
    let mut breakers = std::collections::HashMap::new();
    breakers.insert(
        Arc::from("backend"),
        super::InstrumentedCircuitBreaker::new(
            "backend",
            CoreCircuitBreakerConfig {
                threshold,
                recovery_window: std::time::Duration::from_secs(recovery_secs),
                half_open_timeout: std::time::Duration::from_secs(9999),
            },
        ),
    );
    CircuitBreakerFilter { breakers }
}

/// Build a [`CircuitBreakerFilter`] with two clusters for isolation testing.
fn make_two_cluster_filter(threshold: u32, recovery_secs: u64) -> CircuitBreakerFilter {
    let config = CoreCircuitBreakerConfig {
        threshold,
        recovery_window: std::time::Duration::from_secs(recovery_secs),
        half_open_timeout: std::time::Duration::from_secs(9999),
    };
    let mut breakers = std::collections::HashMap::new();
    breakers.insert(
        Arc::from("cluster-a"),
        super::InstrumentedCircuitBreaker::new("cluster-a", config.clone()),
    );
    breakers.insert(
        Arc::from("cluster-b"),
        super::InstrumentedCircuitBreaker::new("cluster-b", config),
    );
    CircuitBreakerFilter { breakers }
}
