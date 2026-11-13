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
fn local_route_builders_reject_empty_branch_declarations() {
    let mut registry = crate::FilterRegistry::with_builtins();
    registry
        .register(
            "owner",
            crate::FilterFactory::Http(Arc::new(|_| Ok(Box::new(InvalidOwner(vec![test_route()]))))),
        )
        .unwrap();
    for config in [
        "- filter: owner\n  branch_chains: []",
        "- filter: owner\n- filter: headers\n  branch_chains: []",
    ] {
        let mut entries = serde_yaml::from_str::<Vec<crate::FilterEntry>>(config).unwrap();
        let error = FilterPipeline::build(&mut entries, &registry).err().unwrap();
        assert!(error.to_string().contains("cannot contain branch chains"), "{error}");

        let mut entries = serde_yaml::from_str::<Vec<crate::FilterEntry>>(config).unwrap();
        let error = FilterPipeline::build_with_chains(
            &mut entries,
            &registry,
            &std::collections::HashMap::new(),
            &praxis_core::config::InsecureOptions::default(),
            &[],
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("cannot contain branch chains"), "{error}");
    }
}

#[test]
fn nonlocal_builders_accept_empty_branch_declarations() {
    let registry = crate::FilterRegistry::with_builtins();
    let mut entries =
        serde_yaml::from_str::<Vec<crate::FilterEntry>>("- filter: headers\n  branch_chains: []").unwrap();
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    assert_eq!(pipeline.len(), 1, "ordinary pipelines still accept empty branches");

    let mut entries =
        serde_yaml::from_str::<Vec<crate::FilterEntry>>("- filter: headers\n  branch_chains: []").unwrap();
    let pipeline = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &std::collections::HashMap::new(),
        &praxis_core::config::InsecureOptions::default(),
        &[],
    )
    .unwrap();
    assert_eq!(pipeline.len(), 1, "ordinary pipelines still accept empty branches");
}

#[cfg(feature = "iterative-request-router")]
#[test]
fn local_route_builders_reject_iterative_step_owners() {
    let mut registry = crate::FilterRegistry::with_builtins();
    registry
        .register(
            "owner",
            crate::FilterFactory::Http(Arc::new(|_| Ok(Box::new(InvalidOwner(vec![test_route()]))))),
        )
        .unwrap();
    for owner in ["{filter: owner},", ""] {
        let config = format!(
            "- filter: iterative_request_router\n  initial_step: serve\n  steps:\n    - name: serve\n      filters: [{owner} {{filter: static_response, status: 200}}]\n      on_result: [{{default: true, done: true}}]"
        );
        for with_chains in [false, true] {
            let mut entries = serde_yaml::from_str::<Vec<crate::FilterEntry>>(&config).unwrap();
            let result = if with_chains {
                FilterPipeline::build_with_chains(
                    &mut entries,
                    &registry,
                    &std::collections::HashMap::new(),
                    &praxis_core::config::InsecureOptions::default(),
                    &[],
                )
            } else {
                FilterPipeline::build(&mut entries, &registry)
            };
            if owner.is_empty() {
                let pipeline = result.unwrap();
                assert!(
                    !pipeline.has_local_http_routes(),
                    "ordinary nested steps stay supported"
                );
            } else {
                let error = result.err().unwrap();
                assert!(
                    error.to_string().contains("nested local HTTP routes are unsupported"),
                    "both builders must reject local ownership in iterative steps: {error}"
                );
            }
        }
    }
}

#[test]
fn nested_route_ownership_remains_visible_to_adapter_guards() {
    for routes in [vec![], vec![test_route()]] {
        let owns_routes = !routes.is_empty();
        let mut pipeline = FilterPipeline::from_filters(vec![PipelineFilter::new(
            0,
            AnyFilter::Http(Box::new(InvalidOwner(routes))),
            vec![],
            vec![],
        )]);
        for _depth in 0..2 {
            pipeline = FilterPipeline::from_filters(vec![PipelineFilter::new(
                0,
                AnyFilter::Http(Box::new(NestedPipeline(pipeline))),
                vec![],
                vec![],
            )]);
            assert_eq!(pipeline.has_local_http_routes(), owns_routes);
            match pipeline.validate_local_http() {
                Err(error) => {
                    assert!(owns_routes, "non-local nested pipelines remain valid: {error}");
                    assert!(error.to_string().contains("nested local HTTP routes are unsupported"));
                },
                Ok(()) => assert!(!owns_routes, "nested local routes must fail validation"),
            }
        }
    }
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
fn response_replacement_replays_appends_without_adopting_existing_values() {
    let name = http::header::SET_COOKIE;
    let mut original = http::HeaderMap::new();
    original.append(name.clone(), http::HeaderValue::from_static("session=handler"));
    original.append(name.clone(), http::HeaderValue::from_static("policy=value"));
    let mut filtered = original.clone();
    filtered.append(name.clone(), http::HeaderValue::from_static("policy=value"));
    let mut edits = headers::HeaderEdits::default();
    edits.record(&original, &filtered, &[]);
    let mut next = filtered.clone();
    next.append(name.clone(), http::HeaderValue::from_static("policy=value"));
    edits.record(&filtered, &next, &[]);
    for value in ["first=denial", "second=denial"] {
        let mut replacement = http::HeaderMap::new();
        replacement.insert(name.clone(), http::HeaderValue::from_static(value));
        edits.apply(&mut replacement);
        assert_eq!(
            replacement.get_all(&name).iter().collect::<Vec<_>>(),
            [value, "policy=value", "policy=value"],
            "appends preserve replacement values and duplicate policy values in order"
        );
    }
}

#[test]
fn response_replacement_preserves_append_set_remove_order() {
    let name = http::header::SET_COOKIE;
    let mut current = http::HeaderMap::new();
    current.insert(name.clone(), http::HeaderValue::from_static("session=handler"));
    let mut edits = headers::HeaderEdits::default();
    for (value, authoritative, expected) in [
        (Some("first=policy"), false, vec!["denial=value", "first=policy"]),
        (Some("session=handler"), true, vec!["session=handler"]),
        (Some("second=policy"), false, vec!["session=handler", "second=policy"]),
        (None, true, vec![]),
        (Some("last=policy"), false, vec!["last=policy"]),
    ] {
        let before = current.clone();
        if authoritative {
            current.remove(&name);
        }
        if let Some(value) = value {
            current.append(name.clone(), http::HeaderValue::from_static(value));
        }
        let touched = if authoritative { vec![name.clone()] } else { vec![] };
        edits.record(&before, &current, &touched);
        let mut replacement = http::HeaderMap::new();
        replacement.insert(name.clone(), http::HeaderValue::from_static("denial=value"));
        edits.apply(&mut replacement);
        assert_eq!(replacement.get_all(&name).iter().collect::<Vec<_>>(), expected);
    }
}

#[test]
fn response_replacement_retains_explicit_sets_that_resemble_appends() {
    let name = http::header::SET_COOKIE;
    let mut original = http::HeaderMap::new();
    original.insert(name.clone(), http::HeaderValue::from_static("first=policy"));
    let mut filtered = original.clone();
    filtered.append(name.clone(), http::HeaderValue::from_static("second=policy"));
    let mut edits = headers::HeaderEdits::default();
    edits.record(&original, &filtered, std::slice::from_ref(&name));
    let mut replacement = http::HeaderMap::new();
    replacement.insert(name.clone(), http::HeaderValue::from_static("denial=value"));
    edits.apply(&mut replacement);
    assert_eq!(
        replacement.get_all(&name).iter().collect::<Vec<_>>(),
        ["first=policy", "second=policy"],
        "an explicit set replaces the entire field even when the previous values match its prefix"
    );
}

#[test]
fn response_replacement_retains_explicit_unchanged_writes_and_absent_removals() {
    let mut original = http::HeaderMap::new();
    original.insert("x-frame-options", http::HeaderValue::from_static("DENY"));
    original.insert("x-service-secret", http::HeaderValue::from_static("private"));
    let mut extensions = crate::RequestExtensions::new();
    extensions.insert(headers::PolicyHeaders::default());
    record_response_header_effects(&mut extensions, [http::header::X_FRAME_OPTIONS]);
    record_response_header_effects(&mut extensions, [http::header::SET_COOKIE]);
    let explicit = extensions.remove::<headers::PolicyHeaders>().unwrap();
    let mut edits = headers::HeaderEdits::default();
    edits.record(&original, &original, &explicit.touched);
    let mut replacement = http::HeaderMap::new();
    replacement.insert("x-frame-options", http::HeaderValue::from_static("SAMEORIGIN"));
    replacement.insert("set-cookie", http::HeaderValue::from_static("denial=value"));
    edits.apply(&mut replacement);
    assert_eq!(replacement.get("x-frame-options").unwrap(), "DENY");
    assert!(!replacement.contains_key("set-cookie"));
    assert!(!replacement.contains_key("x-service-secret"));
}

#[test]
fn recording_header_effects_outside_local_response_hooks_does_not_create_state() {
    let mut extensions = crate::RequestExtensions::new();
    record_response_header_effects(&mut extensions, [http::header::SET_COOKIE]);
    assert!(extensions.get::<headers::PolicyHeaders>().is_none());
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

/// An ordinary framework filter that exposes its owned pipeline for configuration.
struct NestedPipeline(FilterPipeline);

#[async_trait]
impl HttpFilter for NestedPipeline {
    fn name(&self) -> &'static str {
        "nested_pipeline"
    }

    fn visit_nested_pipelines(&mut self, visitor: &mut dyn FnMut(&mut FilterPipeline)) {
        visitor(&mut self.0);
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
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
