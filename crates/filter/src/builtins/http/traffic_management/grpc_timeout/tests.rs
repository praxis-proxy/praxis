// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the gRPC deadline filter.

use praxis_core::grpc::GrpcDeadline;

use super::GrpcTimeoutFilter;
use crate::{
    FilterAction, Rejection,
    filter::HttpFilter,
    test_utils::{make_filter_context, make_request},
};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Build a filter from YAML, panicking on a config error.
fn filter(yaml: &str) -> Box<dyn HttpFilter> {
    let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
    GrpcTimeoutFilter::from_config(&value).unwrap()
}

/// Build a gRPC request, optionally carrying a `grpc-timeout`.
fn grpc_request(timeout: Option<&str>) -> crate::Request {
    let mut req = make_request(http::Method::POST, "/pkg.Svc/Method");
    let _prev = req
        .headers
        .insert(http::header::CONTENT_TYPE, "application/grpc".parse().unwrap());
    if let Some(timeout) = timeout {
        let _prev = req.headers.insert("grpc-timeout", timeout.parse().unwrap());
    }
    req
}

/// The `grpc-status` a rejection carries, if any.
fn rejection_status(rejection: &Rejection) -> Option<String> {
    rejection
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("grpc-status"))
        .map(|(_, value)| value.clone())
}

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

#[test]
fn from_config_requires_max_timeout() {
    let value: serde_yaml::Value = serde_yaml::from_str("propagate: true").unwrap();
    assert!(
        GrpcTimeoutFilter::from_config(&value).is_err(),
        "max_timeout_ms is required"
    );
}

#[test]
fn from_config_rejects_unknown_fields() {
    let value: serde_yaml::Value = serde_yaml::from_str("max_timeout_ms: 1000\nbogus: true").unwrap();
    assert!(
        GrpcTimeoutFilter::from_config(&value).is_err(),
        "unknown fields should be rejected"
    );
}

#[test]
fn from_config_rejects_nonsense_budgets() {
    for (yaml, why) in [
        ("max_timeout_ms: 0", "a zero ceiling would reject every call"),
        (
            "max_timeout_ms: 3600001",
            "a ceiling past one hour exceeds the timeout limit",
        ),
        (
            "max_timeout_ms: 1000\ndefault_timeout_ms: 0",
            "a zero default is useless",
        ),
        (
            "max_timeout_ms: 1000\ndefault_timeout_ms: 5000",
            "a default past the ceiling would be silently clamped",
        ),
        (
            "max_timeout_ms: 1000\nheadroom_ms: 1000",
            "headroom equal to the ceiling leaves no budget",
        ),
        (
            "max_timeout_ms: 30000\nheadroom_ms: 200\ndefault_timeout_ms: 100",
            "a default at or below the headroom is born expired",
        ),
    ] {
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        assert!(GrpcTimeoutFilter::from_config(&value).is_err(), "{why}: {yaml}");
    }
}

// -----------------------------------------------------------------------------
// Request phase
// -----------------------------------------------------------------------------

#[tokio::test]
async fn non_grpc_requests_are_untouched() {
    let req = make_request(http::Method::GET, "/health");
    let mut ctx = make_filter_context(&req);
    let action = filter("max_timeout_ms: 30000\ndefault_timeout_ms: 1000")
        .on_request(&mut ctx)
        .await
        .unwrap();

    assert!(matches!(action, FilterAction::Continue), "should continue");
    assert!(
        ctx.extensions.get::<GrpcDeadline>().is_none(),
        "a non-gRPC request should get no deadline"
    );
}

#[tokio::test]
async fn client_timeout_is_honoured_and_propagated() {
    let req = grpc_request(Some("5S"));
    let mut ctx = make_filter_context(&req);
    let action = filter("max_timeout_ms: 30000").on_request(&mut ctx).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "should continue");
    let deadline = ctx
        .extensions
        .get::<GrpcDeadline>()
        .copied()
        .expect("deadline installed");
    assert!(!deadline.was_clamped(), "5s is within the 30s ceiling");
    let remaining = deadline.remaining().expect("time left");
    assert!(
        remaining <= std::time::Duration::from_secs(5),
        "the deadline should not exceed what the client asked for"
    );

    assert!(
        deadline.propagate(),
        "a client deadline should be marked to propagate upstream"
    );
}

#[tokio::test]
async fn oversized_timeout_is_clamped_to_the_ceiling() {
    let req = grpc_request(Some("1H"));
    let mut ctx = make_filter_context(&req);
    let _action = filter("max_timeout_ms: 1000").on_request(&mut ctx).await.unwrap();

    let deadline = ctx
        .extensions
        .get::<GrpcDeadline>()
        .copied()
        .expect("deadline installed");
    assert!(deadline.was_clamped(), "an hour exceeds the 1s ceiling");
    assert!(
        deadline.remaining().expect("time left") <= std::time::Duration::from_secs(1),
        "the deadline must be the proxy's ceiling, not the client's ask"
    );
}

#[tokio::test]
async fn headroom_is_withheld_from_the_upstream() {
    let req = grpc_request(Some("1S"));
    let mut ctx = make_filter_context(&req);
    let _action = filter("max_timeout_ms: 30000\nheadroom_ms: 200")
        .on_request(&mut ctx)
        .await
        .unwrap();

    let deadline = ctx
        .extensions
        .get::<GrpcDeadline>()
        .copied()
        .expect("deadline installed");
    assert!(
        deadline.remaining().expect("time left") <= std::time::Duration::from_millis(800),
        "200ms of headroom should be kept back for the proxy's own response"
    );
}

#[tokio::test]
async fn default_timeout_applies_when_the_header_is_absent() {
    let req = grpc_request(None);
    let mut ctx = make_filter_context(&req);
    let _action = filter("max_timeout_ms: 30000\ndefault_timeout_ms: 2000")
        .on_request(&mut ctx)
        .await
        .unwrap();

    let deadline = ctx
        .extensions
        .get::<GrpcDeadline>()
        .copied()
        .expect("deadline installed");
    assert!(
        deadline.remaining().expect("time left") <= std::time::Duration::from_secs(2),
        "the default should bound a header-less call"
    );
    assert!(
        deadline.propagate(),
        "the default deadline should be marked to propagate upstream"
    );
}

#[tokio::test]
async fn header_less_calls_stay_unbounded_without_a_default() {
    let req = grpc_request(None);
    let mut ctx = make_filter_context(&req);
    let action = filter("max_timeout_ms: 30000").on_request(&mut ctx).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "should continue");
    assert!(
        ctx.extensions.get::<GrpcDeadline>().is_none(),
        "with no default configured, a header-less call keeps today's behaviour"
    );
}

#[tokio::test]
async fn malformed_timeout_is_rejected_as_internal() {
    let req = grpc_request(Some("ten seconds"));
    let mut ctx = make_filter_context(&req);
    let action = filter("max_timeout_ms: 30000").on_request(&mut ctx).await.unwrap();

    let FilterAction::Reject(rejection) = action else {
        panic!("a malformed grpc-timeout should be rejected, got {action:?}");
    };
    assert_eq!(rejection.status, 200, "gRPC failures are HTTP 200");
    assert_eq!(
        rejection_status(&rejection).as_deref(),
        Some("13"),
        "a malformed deadline is INTERNAL, as gRPC implementations report it"
    );
}

#[tokio::test]
async fn malformed_timeout_can_be_ignored() {
    let req = grpc_request(Some("ten seconds"));
    let mut ctx = make_filter_context(&req);
    let action = filter("max_timeout_ms: 30000\ndefault_timeout_ms: 1000\non_invalid: ignore")
        .on_request(&mut ctx)
        .await
        .unwrap();

    assert!(matches!(action, FilterAction::Continue), "should fall back, not reject");
    assert!(
        ctx.extensions.get::<GrpcDeadline>().is_some(),
        "the configured default should apply instead"
    );
}

#[tokio::test]
async fn propagation_can_be_disabled() {
    let req = grpc_request(Some("5S"));
    let mut ctx = make_filter_context(&req);
    let _action = filter("max_timeout_ms: 30000\npropagate: false")
        .on_request(&mut ctx)
        .await
        .unwrap();

    let deadline = ctx
        .extensions
        .get::<GrpcDeadline>()
        .copied()
        .expect("the proxy should still enforce the deadline it did not propagate");
    assert!(
        !deadline.propagate(),
        "propagate: false should mark the deadline not to rewrite the upstream header"
    );
}

// -----------------------------------------------------------------------------
// Response phase
// -----------------------------------------------------------------------------

#[tokio::test]
async fn expired_deadline_is_rejected_in_the_response_phase() {
    let req = grpc_request(Some("5S"));
    let mut ctx = make_filter_context(&req);
    ctx.extensions.insert(GrpcDeadline::new(
        std::time::Instant::now() - std::time::Duration::from_secs(1),
        false,
        true,
    ));

    let action = filter("max_timeout_ms: 30000").on_response(&mut ctx).await.unwrap();

    let FilterAction::Reject(rejection) = action else {
        panic!("an expired deadline should be rejected, got {action:?}");
    };
    assert_eq!(
        rejection_status(&rejection).as_deref(),
        Some("4"),
        "an expired deadline is DEADLINE_EXCEEDED"
    );
}

#[tokio::test]
async fn live_deadline_passes_the_response_through() {
    let req = grpc_request(Some("5S"));
    let mut ctx = make_filter_context(&req);
    ctx.extensions.insert(GrpcDeadline::new(
        std::time::Instant::now() + std::time::Duration::from_secs(60),
        false,
        true,
    ));

    let action = filter("max_timeout_ms: 30000").on_response(&mut ctx).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "a live deadline should pass");
}

#[tokio::test]
async fn responses_without_a_deadline_pass_through() {
    let req = make_request(http::Method::GET, "/health");
    let mut ctx = make_filter_context(&req);

    let action = filter("max_timeout_ms: 30000").on_response(&mut ctx).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "no deadline, no rejection");
}
