// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Local matching and runtime defense against invalid internal construction.

#![expect(clippy::unwrap_used, reason = "local contract test assertions")]

use super::*;
use crate::{AnyFilter, FilterAction, FilterPipeline, HttpFilter, pipeline::filter::PipelineFilter};

/// Malformed owner bypasses the public, fallible builders in this test only.
struct InvalidOwner(Vec<LocalRoute>);
#[async_trait]
impl HttpFilter for InvalidOwner {
    fn name(&self) -> &'static str {
        "invalid_owner"
    }

    fn local_http_routes(&self) -> &[LocalRoute] {
        &self.0
    }

    fn local_http_compatibility(&self) -> LocalCompatibility {
        LocalCompatibility::Policy
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Err("invalid owners must never execute".into())
    }
}

#[tokio::test]
async fn runtime_conflict_guard_keeps_invalid_programmatic_claims_local() {
    let route = test_route();
    let pipeline = Arc::new(FilterPipeline::from_filters(vec![PipelineFilter::new(
        0,
        AnyFilter::Http(Box::new(InvalidOwner(vec![route.clone(), route]))),
        vec![],
        vec![],
    )]));
    let request = crate::test_utils::make_request(http::Method::POST, "/files");
    let mut ctx = crate::test_utils::make_filter_context(&request);
    assert!(
        matches!(pipeline.execute_http_request_head(&mut ctx).await.unwrap(), FilterAction::Reject(rejection) if rejection.status == 500)
    );
    assert!(
        matches!(pipeline.execute_http_request(&mut ctx).await.unwrap(), FilterAction::Reject(rejection) if rejection.status == 500)
    );
    let claim = pipeline.claim_local_http(&mut ctx).unwrap();
    assert!(matches!(claim.approve(&mut ctx).await, Some(LocalResponse::Buffered(response)) if response.status == 500));
    assert!(ctx.executed_filter_indices.iter().all(|executed| !executed));
}

#[test]
fn prefix_overlap_is_symmetric_and_retains_repeated_slash_semantics() {
    for (left, right) in [("/files//", "/files///"), ("/files/", "/files"), ("/", "/files/")] {
        let left = LocalPath::SegmentPrefix(left.into());
        let right = LocalPath::SegmentPrefix(right.into());
        assert!(left.overlaps(&right));
        assert!(right.overlaps(&left));
    }
    assert!(!LocalPath::SegmentPrefix("/files".into()).matches("/filestore"));
    assert!(!LocalMethods::Explicit(vec![http::Method::GET]).matches(&http::Method::HEAD));
}

#[test]
fn response_replacement_retains_policy_edits_without_leaking_source_headers() {
    let mut original = http::HeaderMap::new();
    original.insert("x-service-secret", http::HeaderValue::from_static("private"));
    original.append("set-cookie", http::HeaderValue::from_static("source=value"));
    let mut filtered = original.clone();
    filtered.remove("set-cookie");
    filtered.append("x-security", http::HeaderValue::from_static("one"));
    filtered.append("x-security", http::HeaderValue::from_static("two"));
    let mut edits = headers::HeaderEdits::default();
    edits.record(&original, &filtered, &[]);
    let mut replacement = http::HeaderMap::new();
    replacement.insert("set-cookie", http::HeaderValue::from_static("denial=value"));
    edits.apply(&mut replacement);
    assert!(!replacement.contains_key("x-service-secret"));
    assert!(!replacement.contains_key("set-cookie"));
    assert_eq!(replacement.get_all("x-security").iter().count(), 2);
}

#[test]
fn response_replacement_retains_explicit_unchanged_writes_and_absent_removals() {
    let mut original = http::HeaderMap::new();
    original.insert("x-frame-options", http::HeaderValue::from_static("DENY"));
    original.insert("x-service-secret", http::HeaderValue::from_static("private"));
    let touched = [
        http::header::HeaderName::from_static("x-frame-options"),
        http::header::SET_COOKIE,
    ];
    let mut edits = headers::HeaderEdits::default();
    edits.record(&original, &original, &touched);
    let mut replacement = http::HeaderMap::new();
    replacement.insert("x-frame-options", http::HeaderValue::from_static("SAMEORIGIN"));
    replacement.insert("set-cookie", http::HeaderValue::from_static("denial=value"));
    edits.apply(&mut replacement);
    assert_eq!(replacement.get("x-frame-options").unwrap(), "DENY");
    assert!(!replacement.contains_key("set-cookie"));
    assert!(!replacement.contains_key("x-service-secret"));
}

/// Even upstream-bound readers must leave exclusive request streams untouched.
#[cfg(feature = "bound-upstream-request-body")]
struct BoundConsumer;
#[cfg(feature = "bound-upstream-request-body")]
#[async_trait]
impl HttpFilter for BoundConsumer {
    fn name(&self) -> &'static str {
        "bound_consumer"
    }

    fn local_http_compatibility(&self) -> LocalCompatibility {
        LocalCompatibility::UpstreamRoutingOnly
    }

    fn bound_upstream_request_body_access(&self) -> crate::BodyAccess {
        crate::BodyAccess::ReadOnly
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

#[cfg(feature = "bound-upstream-request-body")]
#[test]
fn mandatory_validation_rejects_bound_upstream_consumers() {
    let mut registry = crate::FilterRegistry::with_builtins();
    registry
        .register(
            "owner",
            crate::FilterFactory::Http(Arc::new(|_| Ok(Box::new(InvalidOwner(vec![test_route()]))))),
        )
        .unwrap();
    registry
        .register(
            "bound_consumer",
            crate::FilterFactory::Http(Arc::new(|_| Ok(Box::new(BoundConsumer)))),
        )
        .unwrap();
    let mut entries =
        serde_yaml::from_str::<Vec<crate::FilterEntry>>("- filter: owner\n- filter: bound_consumer").unwrap();
    let error = FilterPipeline::build(&mut entries, &registry)
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("bound-upstream body consumers are incompatible"),
        "{error}"
    );
}

/// Minimal valid declaration shared by runtime and construction guards.
fn test_route() -> LocalRoute {
    LocalRoute {
        id: "files".into(),
        methods: LocalMethods::All,
        path: LocalPath::Exact("/files".into()),
        body: LocalBodyOwnership::Exclusive,
        request_limit: 1,
        response_limit: 1,
    }
}
