// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the circuit breaker filter.

use std::sync::Arc;

use praxis_core::circuit::CircuitBreakerConfig as CoreCircuitBreakerConfig;

use super::{CircuitBreakerFilter, InstrumentedCircuitBreaker, lock_gauge_owners};
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
fn from_config_rejects_duplicate_cluster() -> Result<(), serde_yaml::Error> {
    let yaml = serde_yaml::from_str::<serde_yaml::Value>(
        "
clusters:
  - name: backend
    consecutive_failures: 3
    recovery_window_secs: 30
  - name: backend
    consecutive_failures: 5
    recovery_window_secs: 30
",
    )?;
    let result = CircuitBreakerFilter::from_config(&yaml);
    assert!(
        result
            .err()
            .is_some_and(|e| e.to_string().contains("duplicate cluster 'backend'")),
        "duplicate cluster names should be rejected"
    );
    Ok(())
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
fn from_config_rejects_zero_half_open_timeout() {
    let yaml = serde_yaml::from_str::<serde_yaml::Value>(
        "
clusters:
  - name: backend
    consecutive_failures: 5
    recovery_window_secs: 30
    half_open_timeout_secs: 0
",
    )
    .unwrap();
    let err = CircuitBreakerFilter::from_config(&yaml)
        .err()
        .expect("should reject zero half-open timeout");
    assert!(
        err.to_string().contains("half_open_timeout_secs must be > 0"),
        "should reject zero half-open timeout: {err}"
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

    let mut resp = crate::test_utils::make_response();
    resp.status = http::StatusCode::INTERNAL_SERVER_ERROR;
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.current_filter_id = Some(0);
    drop(filter.on_request(&mut ctx).await.unwrap());
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());

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

    let mut resp = crate::test_utils::make_response();
    resp.status = http::StatusCode::INTERNAL_SERVER_ERROR;
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.current_filter_id = Some(0);
    drop(filter.on_request(&mut ctx).await.unwrap());
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());

    let mut resp2 = crate::test_utils::make_response();
    resp2.status = http::StatusCode::OK;
    let mut ctx2 = crate::test_utils::make_filter_context(&req);
    ctx2.cluster = Some(Arc::from("backend"));
    ctx2.current_filter_id = Some(0);
    drop(filter.on_request(&mut ctx2).await.unwrap());
    ctx2.response_header = Some(&mut resp2);
    drop(filter.on_response(&mut ctx2).await.unwrap());

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
async fn on_response_no_header_with_upstream_reached_records_failure() {
    let filter = make_filter(1, 9999);
    let req = crate::test_utils::make_request(http::Method::GET, "/");

    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.current_filter_id = Some(0);
    drop(filter.on_request(&mut ctx).await.unwrap());
    ctx.upstream_reached = true;
    drop(filter.on_response(&mut ctx).await.unwrap());

    let mut ctx2 = crate::test_utils::make_filter_context(&req);
    ctx2.cluster = Some(Arc::from("backend"));
    ctx2.current_filter_id = Some(0);
    let action = filter.on_request(&mut ctx2).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 503),
        "missing response header after reaching the upstream should trip the circuit"
    );
}

#[tokio::test]
async fn on_response_no_header_without_upstream_does_not_trip() {
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
        matches!(action, FilterAction::Continue),
        "a request that never reached the upstream must not trip the circuit"
    );
}

#[tokio::test]
async fn request_not_reaching_the_cluster_passes_an_open_circuit_without_a_token() {
    // A forward-proxy CONNECT never reaches the cluster its route names, so
    // that cluster's health is no reason to refuse it.
    let filter = make_filter(1, 9999);
    let req = crate::test_utils::make_request(http::Method::CONNECT, "/");
    exchange(&filter, &req, http::StatusCode::INTERNAL_SERVER_ERROR, false).await;

    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.current_filter_id = Some(0);
    ctx.extensions.insert(crate::ClusterNotContacted);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "the open circuit must not refuse a request it does not guard"
    );
    assert!(
        ctx.remove_filter_state::<super::ActiveCircuitToken>().is_none(),
        "no circuit token may be taken for it"
    );
}

#[tokio::test]
async fn outcome_of_a_request_not_reaching_the_cluster_is_not_recorded() {
    // A tunnel's 200 must not reset the failure count of a cluster the
    // tunnel never reached.
    let filter = make_filter(2, 9999);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    exchange(&filter, &req, http::StatusCode::INTERNAL_SERVER_ERROR, false).await;
    exchange(&filter, &req, http::StatusCode::OK, true).await;
    exchange(&filter, &req, http::StatusCode::INTERNAL_SERVER_ERROR, false).await;

    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.current_filter_id = Some(0);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 503),
        "two failures with only an uncounted success between them must open the circuit"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Run one request to the "backend" cluster through `filter`, answered with
/// `status`, optionally marked as never reaching the cluster.
async fn exchange(filter: &CircuitBreakerFilter, req: &crate::Request, status: http::StatusCode, bypass: bool) {
    let mut resp = crate::test_utils::make_response();
    resp.status = status;
    let mut ctx = crate::test_utils::make_filter_context(req);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.current_filter_id = Some(0);
    if bypass {
        ctx.extensions.insert(crate::ClusterNotContacted);
    }
    drop(filter.on_request(&mut ctx).await.unwrap());
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());
}

/// Build a [`CircuitBreakerFilter`] for testing with a single cluster named "backend".
fn make_filter(threshold: u32, recovery_secs: u64) -> CircuitBreakerFilter {
    let mut breakers = std::collections::HashMap::new();
    breakers.insert(
        Arc::from("backend"),
        Arc::new(InstrumentedCircuitBreaker::new(
            "backend",
            CoreCircuitBreakerConfig {
                threshold,
                recovery_window: std::time::Duration::from_secs(recovery_secs),
                half_open_timeout: std::time::Duration::from_secs(9999),
            },
        )),
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
        Arc::new(InstrumentedCircuitBreaker::new("cluster-a", config.clone())),
    );
    breakers.insert(
        Arc::from("cluster-b"),
        Arc::new(InstrumentedCircuitBreaker::new("cluster-b", config)),
    );
    CircuitBreakerFilter { breakers }
}

#[tokio::test]
async fn cancelled_transport_guard_records_failure() {
    let filter = make_filter(1, 30);
    let request = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&request);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.current_filter_id = Some(0);
    let outcome = crate::filtered_subrequest::NestedTransportOutcome::new();
    ctx.extensions.insert(outcome.clone());
    assert!(matches!(
        filter.on_request(&mut ctx).await.unwrap(),
        FilterAction::Continue
    ));

    outcome.start();
    drop(ctx);

    let mut next = crate::test_utils::make_filter_context(&request);
    next.cluster = Some(Arc::from("backend"));
    next.current_filter_id = Some(0);
    assert!(
        matches!(filter.on_request(&mut next).await.unwrap(), FilterAction::Reject(_)),
        "a cancelled transport attempt must record the failure exactly once"
    );
}

/// Delegate to a real shared breaker so executor tests can inspect token counts.
struct SharedCircuitFilter(Arc<CircuitBreakerFilter>);

#[async_trait::async_trait]
impl crate::HttpFilter for SharedCircuitFilter {
    fn name(&self) -> &'static str {
        "shared_circuit"
    }

    async fn on_request(&self, ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, crate::FilterError> {
        self.0.on_request(ctx).await
    }

    async fn on_response(&self, ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, crate::FilterError> {
        self.0.on_response(ctx).await
    }
}

/// Suspend after the preceding breaker entered, before any upstream work.
struct PendingLocalFilter(Arc<tokio::sync::Notify>);

#[async_trait::async_trait]
impl crate::HttpFilter for PendingLocalFilter {
    fn name(&self) -> &'static str {
        "pending_local"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, crate::FilterError> {
        self.0.notify_one();
        std::future::pending().await
    }
}

#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "drives a real nested executor through half-open cancellation"
)]
async fn outer_deadline_releases_local_probe() {
    use std::time::{Duration, Instant};
    for abort in [false, true] {
        let filter = Arc::new(make_filter(1, 0));
        let breaker = Arc::clone(filter.breakers.get("backend").unwrap());
        let praxis_core::circuit::CircuitCheck::Allowed(token) = breaker.try_acquire() else {
            panic!("closed breaker must admit");
        };
        breaker.record_failure(token);
        assert_eq!(breaker.inner.state(), praxis_core::circuit::CircuitState::Open);
        assert_eq!(breaker.inner.in_flight(), 0);
        let entered = Arc::new(tokio::sync::Notify::new());
        let mut registry = crate::FilterRegistry::with_builtins();
        registry
            .register(
                "shared_circuit",
                crate::FilterFactory::Http(Arc::new(move |_| {
                    Ok(Box::new(SharedCircuitFilter(Arc::clone(&filter))))
                })),
            )
            .unwrap();
        let signal = Arc::clone(&entered);
        registry
            .register(
                "pending_local",
                crate::FilterFactory::Http(Arc::new(move |_| Ok(Box::new(PendingLocalFilter(Arc::clone(&signal)))))),
            )
            .unwrap();
        let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str("- filter: router\n  routes:\n    - path_prefix: /\n      cluster: backend\n- filter: shared_circuit\n- filter: pending_local\n").unwrap();
        let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());
        let worker = tokio::spawn(async move {
            let client = praxis_core::subrequest::SubRequestClient::new(crate::test_support::connector(4, None));
            let executor = crate::FilteredSubrequestExecutor::for_callout(
                client,
                crate::SubrequestRuntime::new(None, false, None, Instant::now()),
                0,
                1024,
                Duration::from_secs(5),
            );
            let request = crate::SubRequest {
                method: http::Method::GET,
                uri: http::Uri::from_static("/"),
                headers: http::HeaderMap::new(),
                body: bytes::Bytes::new(),
            };
            executor
                .run(
                    &pipeline,
                    &request,
                    crate::RequestExtensions::default(),
                    Instant::now()
                        + if abort {
                            Duration::from_secs(5)
                        } else {
                            Duration::from_millis(100)
                        },
                )
                .await
                .unwrap()
        });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        assert_eq!(
            breaker.inner.state(),
            praxis_core::circuit::CircuitState::HalfOpen,
            "test must own a real half-open probe"
        );
        assert_eq!(
            breaker.inner.in_flight(),
            1,
            "pending hook must retain the acquired token"
        );
        if abort {
            worker.abort();
            assert!(matches!(worker.await, Err(error) if error.is_cancelled()));
        } else {
            match worker.await.unwrap() {
                crate::CalloutResponse::Buffered(response) => assert_eq!(response.status, 504),
                crate::CalloutResponse::Streaming { .. } => panic!("local timeout cannot stream"),
            }
        }
        assert_eq!(
            breaker.inner.in_flight(),
            0,
            "local cancellation must settle the slot before returning"
        );
        assert_eq!(
            breaker.inner.state(),
            praxis_core::circuit::CircuitState::HalfOpen,
            "neutral settlement preserves timeout-based recovery"
        );
        assert!(
            matches!(breaker.try_acquire(), praxis_core::circuit::CircuitCheck::Rejected),
            "neutral settlement must not admit an early replacement probe"
        );
    }
}

#[tokio::test]
async fn cancelled_response_hook_uses_observed_upstream_result() {
    let filter = make_filter(2, 30);
    let request = crate::test_utils::make_request(http::Method::GET, "/");
    let mut prior = crate::test_utils::make_filter_context(&request);
    prior.cluster = Some(Arc::from("backend"));
    prior.current_filter_id = Some(0);
    assert!(matches!(
        filter.on_request(&mut prior).await.unwrap(),
        FilterAction::Continue
    ));
    let mut failure = crate::test_utils::make_response();
    failure.status = http::StatusCode::BAD_GATEWAY;
    prior.response_header = Some(&mut failure);
    drop(filter.on_response(&mut prior).await.unwrap());

    let mut ctx = crate::test_utils::make_filter_context(&request);
    ctx.cluster = Some(Arc::from("backend"));
    ctx.current_filter_id = Some(0);
    let outcome = crate::filtered_subrequest::NestedTransportOutcome::new();
    ctx.extensions.insert(outcome.clone());
    assert!(matches!(
        filter.on_request(&mut ctx).await.unwrap(),
        FilterAction::Continue
    ));

    outcome.start();
    outcome.response(200);
    drop(ctx);

    let mut later_failure = crate::test_utils::make_filter_context(&request);
    later_failure.cluster = Some(Arc::from("backend"));
    later_failure.current_filter_id = Some(0);
    assert!(matches!(
        filter.on_request(&mut later_failure).await.unwrap(),
        FilterAction::Continue
    ));
    let mut failure = crate::test_utils::make_response();
    failure.status = http::StatusCode::BAD_GATEWAY;
    later_failure.response_header = Some(&mut failure);
    drop(filter.on_response(&mut later_failure).await.unwrap());

    let mut next = crate::test_utils::make_filter_context(&request);
    next.cluster = Some(Arc::from("backend"));
    next.current_filter_id = Some(0);
    assert!(
        matches!(filter.on_request(&mut next).await.unwrap(), FilterAction::Continue),
        "observed success during cancelled hooks must reset the previous failure streak"
    );
}

#[test]
fn stale_breaker_drop_keeps_newer_gauge_owner() {
    let config = CoreCircuitBreakerConfig {
        threshold: 1,
        recovery_window: std::time::Duration::from_secs(30),
        half_open_timeout: std::time::Duration::from_secs(30),
    };
    let old = InstrumentedCircuitBreaker::new("gauge-owner-reload", config.clone());
    let new = InstrumentedCircuitBreaker::new("gauge-owner-reload", config);
    drop(old);
    assert_eq!(
        lock_gauge_owners().get("gauge-owner-reload"),
        Some(&new.owner_id),
        "dropping the stale breaker must not release the newer breaker's gauge"
    );
    drop(new);
    assert!(
        !lock_gauge_owners().contains_key("gauge-owner-reload"),
        "dropping the current owner should release the gauge"
    );
}

/// Suspend a response hook before the real breaker can consume its token.
struct PendingCircuitResponse {
    entered: Arc<tokio::sync::Notify>,
    streaming: bool,
}

#[async_trait::async_trait]
impl crate::HttpFilter for PendingCircuitResponse {
    fn name(&self) -> &'static str {
        "pending_circuit_response"
    }

    fn may_select_streaming_subrequest_response(&self) -> bool {
        self.streaming
    }

    async fn on_request(&self, ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, crate::FilterError> {
        if self.streaming {
            ctx.set_subrequest_response_mode(crate::SubRequestResponseMode::Streaming);
        }
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, crate::FilterError> {
        self.entered.notify_one();
        std::future::pending().await
    }
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives real nested responses through cancellation")]
async fn outer_deadline_cancels_response_hook_and_settles_observed_outcome() {
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    for (streaming, upstream_status) in [(false, 200), (true, 200), (false, 503), (true, 503)] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let backend = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(socket.read_u8().await.unwrap());
            }
            let response = if upstream_status == 200 {
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice()
            } else {
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".as_slice()
            };
            socket.write_all(response).await.unwrap();
            head
        });
        let filter = Arc::new(make_filter(1, 0));
        let breaker = Arc::clone(filter.breakers.get("backend").unwrap());
        let praxis_core::circuit::CircuitCheck::Allowed(token) = breaker.try_acquire() else {
            panic!("closed breaker must admit");
        };
        breaker.record_failure(token);
        let entered = Arc::new(tokio::sync::Notify::new());
        let signal = Arc::clone(&entered);
        let mut registry = crate::FilterRegistry::with_builtins();
        registry
            .register(
                "shared_circuit",
                crate::FilterFactory::Http(Arc::new(move |_| {
                    Ok(Box::new(SharedCircuitFilter(Arc::clone(&filter))))
                })),
            )
            .unwrap();
        registry
            .register(
                "pending_circuit_response",
                crate::FilterFactory::Http(Arc::new(move |_| {
                    Ok(Box::new(PendingCircuitResponse {
                        entered: Arc::clone(&signal),
                        streaming,
                    }))
                })),
            )
            .unwrap();
        let yaml = format!(
            "- filter: router\n  routes:\n    - path_prefix: /\n      cluster: backend\n- filter: shared_circuit\n- filter: load_balancer\n  clusters:\n    - name: backend\n      endpoints: ['{address}']\n- filter: pending_circuit_response\n"
        );
        let mut entries = serde_yaml::from_str::<Vec<crate::FilterEntry>>(&yaml).unwrap();
        let pipeline = Arc::new(crate::FilterPipeline::build(&mut entries, &registry).unwrap());
        let worker = tokio::spawn(async move {
            let client = praxis_core::subrequest::SubRequestClient::new(crate::test_support::connector(4, None));
            let executor = crate::FilteredSubrequestExecutor::for_callout(
                client,
                crate::SubrequestRuntime::new(None, false, None, Instant::now()),
                0,
                1024,
                Duration::from_secs(5),
            );
            let request = crate::SubRequest {
                method: http::Method::GET,
                uri: http::Uri::from_static("/"),
                headers: http::HeaderMap::new(),
                body: bytes::Bytes::new(),
            };
            executor
                .run(
                    &pipeline,
                    &request,
                    crate::RequestExtensions::default(),
                    Instant::now() + Duration::from_millis(200),
                )
                .await
                .unwrap()
        });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        assert!(
            backend.await.unwrap().starts_with(b"GET /"),
            "backend must actually receive the request"
        );
        assert_eq!(
            breaker.inner.in_flight(),
            1,
            "pending response hook must still own the half-open token"
        );
        assert_eq!(breaker.inner.state(), praxis_core::circuit::CircuitState::HalfOpen);
        match tokio::time::timeout(Duration::from_secs(2), worker)
            .await
            .unwrap()
            .unwrap()
        {
            crate::CalloutResponse::Buffered(response) => assert_eq!(response.status, 504),
            crate::CalloutResponse::Streaming { .. } => panic!("stalled header hook cannot return a live body"),
        }
        assert_eq!(
            breaker.inner.in_flight(),
            0,
            "deadline must synchronously settle the cancelled hook's token"
        );
        assert_eq!(
            breaker.inner.state(),
            if upstream_status == 200 {
                praxis_core::circuit::CircuitState::Closed
            } else {
                praxis_core::circuit::CircuitState::Open
            },
            "observed upstream {upstream_status} must settle the cancelled probe"
        );
    }
}
