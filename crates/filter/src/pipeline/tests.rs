// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for pipeline construction, body capabilities, execution, and ordering warnings.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use ::http::{HeaderMap, Method, StatusCode};
use async_trait::async_trait;
use bytes::Bytes;
use praxis_core::config::{BranchChainConfig, ChainRef, FailureMode, SkipPipelineChecks};

use super::{
    FilterPipeline,
    body::compute_body_capabilities,
    branch::{RejoinTarget, ResolvedBranch, ResolvedBranchCondition},
    filter::PipelineFilter,
};
use crate::{
    FilterAction, FilterEntry, FilterError, FilterFactory, FilterRegistry, SecurityClass, StreamingResponseBody,
    StreamingTerminalResponse,
    any_filter::AnyFilter,
    body::{BodyAccess, BodyCapabilities, BodyMode},
    filter::HttpFilter,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn build_empty_pipeline() {
    let registry = FilterRegistry::with_builtins();
    let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
    assert!(pipeline.is_empty(), "empty pipeline should report is_empty");
    assert_eq!(pipeline.len(), 0, "empty pipeline should have zero length");
}

#[test]
fn build_unknown_filter_errors() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![],
        filter_type: "nonexistent".into(),
        config: serde_yaml::Value::Null,
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }];
    match FilterPipeline::build(&mut entries, &registry) {
        Err(e) => assert!(
            e.to_string().contains("unknown filter type"),
            "error should mention unknown filter type"
        ),
        Ok(_) => panic!("expected error for unknown filter"),
    }
}

#[test]
fn build_with_valid_filters() {
    let registry = FilterRegistry::with_builtins();
    let router_config: serde_yaml::Value =
        serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap();
    let serde_yaml::Value::Mapping(router_config) = router_config else {
        panic!("router config should be a mapping");
    };
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![],
        filter_type: "router".into(),
        config: serde_yaml::Value::Mapping(router_config),
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    assert_eq!(pipeline.len(), 1, "pipeline should contain one filter");
    assert!(!pipeline.is_empty(), "non-empty pipeline should not report is_empty");
}

#[test]
fn ordinary_router_in_terminal_branch_does_not_enable_binding() {
    let registry = FilterRegistry::with_builtins();
    let mut entries: Vec<FilterEntry> = serde_yaml::from_str(
        r#"
- filter: headers
  branch_chains:
    - name: route
      rejoin: terminal
      chains:
        - name: inline
          filters:
            - filter: router
              routes:
                - path_prefix: "/"
                  cluster: backend
            - filter: load_balancer
              clusters:
                - name: backend
                  endpoints: ["127.0.0.1:9"]
"#,
    )
    .unwrap();
    let chains = HashMap::new();
    let pipeline = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &chains,
        &praxis_core::config::InsecureOptions::default(),
    )
    .unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());

    assert!(
        errors.iter().all(|error| !error.contains("logical upstream binding")),
        "ordinary branch routing must retain its historical shape: {errors:?}"
    );
}

#[cfg(feature = "upstream-binding")]
#[test]
fn ordinary_routing_does_not_require_global_cluster_metadata_agreement() {
    let registry = FilterRegistry::with_builtins();
    let mut entries: Vec<FilterEntry> = serde_yaml::from_str(
        r#"
- filter: router
  routes:
    - path_prefix: "/"
      cluster: backend
- filter: load_balancer
  clusters:
    - name: backend
      endpoints: ["127.0.0.1:9"]
- filter: load_balancer
  clusters:
    - name: backend
      http:
        application_provider: openai
      endpoints: ["127.0.0.1:10"]
"#,
    )
    .unwrap();
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());

    assert!(
        !pipeline
            .filters
            .iter()
            .any(|pf| matches!(&pf.filter, AnyFilter::Http(f) if f.binds_upstream())),
        "ordinary routing must not enable binding or build a pipeline-wide catalog"
    );
    assert!(
        errors
            .iter()
            .all(|error| !error.contains("conflicting application metadata")),
        "independent ordinary dispatch paths own their metadata locally: {errors:?}"
    );
}

#[cfg(feature = "upstream-binding")]
#[test]
fn binding_enabled_routing_requires_global_cluster_metadata_agreement() {
    let registry = FilterRegistry::with_builtins();
    let mut entries: Vec<FilterEntry> = serde_yaml::from_str(
        r#"
- filter: router
  routes:
    - path_prefix: "/"
      cluster: backend
- filter: load_balancer
  clusters:
    - name: backend
      endpoints: ["127.0.0.1:9"]
- filter: load_balancer
  clusters:
    - name: backend
      http:
        application_provider: openai
      endpoints: ["127.0.0.1:10"]
- filter: headers
  conditions:
    - when:
        bound_upstream:
          application_provider: openai
  request_set: [{name: x-bound, value: "true"}]
"#,
    )
    .unwrap();
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());

    assert!(
        pipeline
            .filters
            .iter()
            .any(|pf| matches!(&pf.filter, AnyFilter::Http(f) if f.binds_upstream())),
        "binding-aware routing must enable binding on the router"
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("conflicting application metadata")),
        "binding metadata must remain unambiguous: {errors:?}"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn built_binding_router_resolves_metadata_from_pipeline_catalog() {
    let registry = FilterRegistry::with_builtins();
    let mut entries: Vec<FilterEntry> = serde_yaml::from_str(
        r#"
- filter: router
  routes:
    - path_prefix: "/"
      cluster: inference
- filter: headers
  conditions:
    - when:
        bound_upstream:
          application_provider: openai
  request_set: [{name: x-bound, value: "true"}]
- filter: load_balancer
  clusters:
    - name: inference
      http:
        application_protocol: openai_responses
        application_provider: openai
      endpoints: ["127.0.0.1:9"]
"#,
    )
    .unwrap();
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "the pipeline should continue");
    assert_eq!(
        ctx.bound_application_protocol(),
        Some("openai_responses"),
        "the built router must resolve the protocol from the pipeline catalog"
    );
    assert_eq!(
        ctx.bound_application_provider(),
        Some("openai"),
        "the built router must resolve the provider from the pipeline catalog"
    );
    assert!(
        ctx.request_headers_to_set.iter().any(|(name, _)| name == "x-bound"),
        "the bound_upstream condition must match the catalog-resolved provider"
    );
}

#[cfg(feature = "upstream-binding")]
#[test]
fn deny_branch_before_bound_dispatch_is_accepted_from_yaml() {
    let registry = FilterRegistry::with_builtins();
    let mut entries: Vec<FilterEntry> = serde_yaml::from_str(
        r#"
- filter: guardrails
  action: flag
  rules:
    - target: header
      name: "X-Danger"
      contains: "true"
  branch_chains:
    - name: block_banned
      on_result:
        filter: guardrails
        result: blocked
      rejoin: terminal
      chains:
        - name: blocked_response
          filters:
            - filter: static_response
              status: 403
- filter: router
  routes:
    - path_prefix: "/"
      cluster: backend
- filter: load_balancer
  cluster_source: bound_upstream
  clusters:
    - name: backend
      endpoints: ["127.0.0.1:9"]
"#,
    )
    .unwrap();
    let pipeline = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &HashMap::new(),
        &praxis_core::config::InsecureOptions::default(),
    )
    .unwrap();
    assert_eq!(
        pipeline.filters.first().map(|pf| pf.branches.len()),
        Some(1),
        "the deny branch must be resolved onto the guardrails host"
    );
    assert!(
        pipeline
            .filters
            .get(1)
            .is_some_and(|pf| matches!(&pf.filter, AnyFilter::Http(f) if f.binds_upstream())),
        "the bound load balancer must turn the router into the binding router"
    );

    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());

    assert!(
        errors.is_empty(),
        "a deny branch ahead of the binding router never carries the binding, so it cannot leave the bound cluster unserved: {errors:?}"
    );
}

#[cfg(feature = "upstream-binding")]
#[test]
fn branch_trace_context_is_checked_by_where_its_branch_runs() {
    let registry = FilterRegistry::with_builtins();
    for (router_first, expect_error) in [(true, false), (false, true)] {
        let trace_host = "
- filter: headers
  branch_chains:
    - name: trace
      chains:
        - name: inline
          filters:
            - filter: trace_context
              conditions: [{when: {bound_upstream: {application_provider: openai}}}]
";
        let router = r#"
- filter: router
  routes:
    - path_prefix: "/"
      cluster: backend
"#;
        let lb = r#"
- filter: load_balancer
  clusters:
    - name: backend
      http: {application_provider: openai}
      endpoints: ["127.0.0.1:9"]
"#;
        let yaml = if router_first {
            format!("{router}{trace_host}{lb}")
        } else {
            format!("{trace_host}{router}{lb}")
        };
        let mut entries: Vec<FilterEntry> = serde_yaml::from_str(&yaml).unwrap();
        let pipeline = FilterPipeline::build_with_chains(
            &mut entries,
            &registry,
            &HashMap::new(),
            &praxis_core::config::InsecureOptions::default(),
        )
        .unwrap();

        let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());

        assert_eq!(
            errors
                .iter()
                .any(|error| error.contains("requires a bound logical upstream")),
            expect_error,
            "a branch trace_context before the router must be rejected, one after it accepted \
             (router_first = {router_first}): {errors:?}"
        );
        assert!(
            errors.iter().all(|error| !error.contains("before routing")),
            "the top-level trace_context rule must not fire for a branch one: {errors:?}"
        );
    }
}

#[cfg(feature = "upstream-binding")]
#[test]
fn binding_enabled_router_in_branch_is_rejected_from_yaml() {
    let registry = FilterRegistry::with_builtins();
    let mut entries: Vec<FilterEntry> = serde_yaml::from_str(
        r#"
- filter: router
  routes:
    - path_prefix: "/"
      cluster: backend
- filter: headers
  conditions:
    - when:
        bound_upstream:
          application_provider: openai
  branch_chains:
    - name: reroute
      rejoin: terminal
      chains:
        - name: inline
          filters:
            - filter: router
              routes:
                - path_prefix: "/"
                  cluster: backend
            - filter: load_balancer
              clusters:
                - name: backend
                  http:
                    application_provider: openai
                  endpoints: ["127.0.0.1:9"]
"#,
    )
    .unwrap();
    let chains = HashMap::new();
    let pipeline = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &chains,
        &praxis_core::config::InsecureOptions::default(),
    )
    .unwrap();
    assert!(
        pipeline
            .filters
            .iter()
            .flat_map(|filter| &filter.branches)
            .any(|branch| {
                branch
                    .filters
                    .iter()
                    .any(|filter| matches!(&filter.filter, AnyFilter::Http(filter) if filter.binds_upstream()))
            }),
        "binding opt-in must recurse into branch routers"
    );
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());

    assert!(
        errors
            .iter()
            .any(|error| { error.contains("publishes a logical upstream binding inside a branch") }),
        "binding-aware routers must stay top-level: {errors:?}"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn unmatched_conditional_router_publishes_no_binding_or_route_metrics() {
    let registry = FilterRegistry::with_builtins();
    let mut entries: Vec<FilterEntry> = serde_yaml::from_str(
        r#"
- filter: router
  conditions:
    - when: {path_prefix: "/routed"}
  routes:
    - path_prefix: "/"
      cluster: backend
- filter: headers
  conditions:
    - when:
        bound_upstream: {application_provider: openai}
  request_set: [{name: x-routed, value: "true"}]
- filter: load_balancer
  conditions:
    - when: {path_prefix: "/routed"}
  clusters:
    - name: backend
      http: {application_provider: openai}
      endpoints: ["127.0.0.1:9"]
"#,
    )
    .unwrap();
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let routed = crate::test_utils::make_request(Method::GET, "/routed");
    let mut routed_ctx = crate::test_utils::make_filter_context(&routed);
    let skipped = crate::test_utils::make_request(Method::GET, "/skipped");
    let mut ctx = crate::test_utils::make_filter_context(&skipped);

    drop(pipeline.execute_http_request(&mut routed_ctx).await.unwrap());
    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();

    assert!(
        routed_ctx
            .request_headers_to_set
            .iter()
            .any(|(name, _)| name == "x-routed"),
        "a routed request binds the openai cluster and runs the bound-gated filter"
    );
    assert!(
        matches!(action, FilterAction::Continue),
        "a skipped router lets the request continue rather than rejecting it: {action:?}"
    );
    assert!(
        ctx.bound_cluster().is_none(),
        "a skipped binding router must not publish a binding"
    );
    assert!(ctx.cluster.is_none(), "a skipped router must not select a cluster");
    assert!(
        ctx.metrics_route.is_none(),
        "a skipped router must not label the request with a route"
    );
    assert!(
        ctx.request_headers_to_set.is_empty(),
        "the bound-gated filter must not run for an unbound request"
    );
}

#[test]
fn build_stops_on_first_error() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "bad_filter".into(),
            config: serde_yaml::Value::Null,
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    match FilterPipeline::build(&mut entries, &registry) {
        Err(e) => assert!(
            e.to_string().contains("unknown filter type"),
            "build should stop with unknown filter type error"
        ),
        Ok(_) => panic!("expected error for unknown filter"),
    }
}

#[tokio::test]
async fn terminal_branch_without_response_fails_closed() {
    let after_ran = Arc::new(AtomicUsize::new(0));
    let mut branching = PipelineFilter::new(
        0,
        AnyFilter::Http(Box::new(CountingFilter {
            counter: Arc::new(AtomicUsize::new(0)),
        })),
        vec![],
        vec![],
    );
    branching.branches = vec![ResolvedBranch {
        name: Arc::from("term"),
        condition: None,
        filters: vec![],
        max_iterations: None,
        rejoin: RejoinTarget::Terminal,
    }];
    let after = PipelineFilter::new(
        1,
        AnyFilter::Http(Box::new(CountingFilter {
            counter: Arc::clone(&after_ran),
        })),
        vec![],
        vec![],
    );

    let pipeline = test_pipeline(BodyCapabilities::default(), vec![branching, after]);

    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 500),
        "terminal branch with no response should fail closed with 500"
    );
    assert_eq!(
        after_ran.load(Ordering::SeqCst),
        0,
        "filters after a terminal branch point must not run"
    );
}

#[tokio::test]
async fn terminal_branch_with_cluster_selection_forwards_upstream() {
    use super::branch::{RejoinTarget, ResolvedBranch};

    let after_ran = Arc::new(AtomicUsize::new(0));
    let mut branching = PipelineFilter::new(
        0,
        AnyFilter::Http(Box::new(CountingFilter {
            counter: Arc::new(AtomicUsize::new(0)),
        })),
        vec![],
        vec![],
    );
    branching.branches = vec![ResolvedBranch {
        name: Arc::from("routing_branch"),
        condition: None,
        filters: vec![PipelineFilter::new(
            10,
            AnyFilter::Http(Box::new(ClusterSelectFilter("backend"))),
            vec![],
            vec![],
        )],
        max_iterations: None,
        rejoin: RejoinTarget::Terminal,
    }];
    let after = PipelineFilter::new(
        1,
        AnyFilter::Http(Box::new(CountingFilter {
            counter: Arc::clone(&after_ran),
        })),
        vec![],
        vec![],
    );

    let pipeline = test_pipeline(BodyCapabilities::default(), vec![branching, after]);

    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "terminal branch that selected a cluster should continue to upstream forwarding"
    );
    assert!(ctx.cluster.is_some(), "cluster should be set by the branch filter");
    assert_eq!(
        after_ran.load(Ordering::SeqCst),
        0,
        "filters after a terminal branch point must not run"
    );
}

#[tokio::test]
async fn execute_request_stops_on_first_reject() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline(vec![
        Box::new(RejectFilter),
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "first filter should reject with 403"
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "second filter must not have been called after reject"
    );
}

#[tokio::test]
async fn execute_response_runs_in_reverse_order() {
    let log: Arc<std::sync::Mutex<Vec<&'static str>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(LoggingFilter {
            label: "first",
            log: Arc::clone(&log),
        }),
        Box::new(LoggingFilter {
            label: "second",
            log: Arc::clone(&log),
        }),
        Box::new(LoggingFilter {
            label: "third",
            log: Arc::clone(&log),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let _result = pipeline.execute_http_response(&mut ctx).await.unwrap();
    let recorded = log.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["third", "second", "first"],
        "response filters should execute in reverse order"
    );
}

#[tokio::test]
async fn execute_request_propagates_errors() {
    let pipeline = make_pipeline(vec![Box::new(ErrorFilter)]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let result = pipeline.execute_http_request(&mut ctx).await;
    assert!(result.is_err(), "error filter should propagate error");
    assert!(
        result.unwrap_err().to_string().contains("injected error"),
        "error message should contain injected error text"
    );
}

#[tokio::test]
async fn condition_when_matches_executes_filter() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        vec![when_path("/api")],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/api/users");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let _result = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "filter should execute when path matches"
    );
}

#[tokio::test]
async fn condition_when_no_match_skips_filter() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        vec![when_path("/api")],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/health");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let _result = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "filter should be skipped when path does not match"
    );
}

#[tokio::test]
async fn condition_unless_match_skips_filter() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        vec![unless_path("/healthz")],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/healthz");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let _result = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "unless-matched path should skip filter"
    );
}

#[tokio::test]
async fn condition_unless_no_match_executes_filter() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        vec![unless_path("/healthz")],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/api/users");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let _result = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "unless-unmatched path should execute filter"
    );
}

#[tokio::test]
async fn request_conditions_do_not_gate_response_phase() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        vec![when_path("/api")],
    )]);

    let req = crate::test_utils::make_request(Method::GET, "/health");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let _result = pipeline.execute_http_response(&mut ctx).await.unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "request conditions should not gate response phase"
    );
}

#[tokio::test]
async fn response_condition_when_matches_executes_filter() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline_with_response_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        vec![when_status(&[200])],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut resp = crate::context::Response {
        status: StatusCode::OK,
        headers: HeaderMap::new(),
    };
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);
    let _result = pipeline.execute_http_response(&mut ctx).await.unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "filter should execute when response status matches"
    );
}

#[tokio::test]
async fn response_condition_when_no_match_skips_filter() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline_with_response_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        vec![when_status(&[200])],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut resp = crate::context::Response {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        headers: HeaderMap::new(),
    };
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);
    let _result = pipeline.execute_http_response(&mut ctx).await.unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "filter should be skipped when response status does not match"
    );
}

#[test]
fn response_body_condition_when_no_match_skips_filter_with_ctx_header() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline_with_response_conditions(vec![(
        Box::new(ResponseBodyInspectorFilter {
            chunks: Arc::clone(&chunks),
        }),
        vec![when_status(&[200])],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut resp = crate::context::Response {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        headers: HeaderMap::new(),
    };
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);

    let mut body = Some(Bytes::from_static(b"response data"));
    let _result = pipeline.execute_http_response_body(&mut ctx, &mut body, true).unwrap();

    assert_eq!(
        chunks.lock().unwrap().len(),
        0,
        "response body filter should be skipped when ctx response status does not match"
    );
}

#[test]
fn response_body_condition_when_match_executes_filter_with_ctx_header() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline_with_response_conditions(vec![(
        Box::new(ResponseBodyInspectorFilter {
            chunks: Arc::clone(&chunks),
        }),
        vec![when_status(&[200])],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut resp = crate::context::Response {
        status: StatusCode::OK,
        headers: HeaderMap::new(),
    };
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);

    let mut body = Some(Bytes::from_static(b"response data"));
    let _result = pipeline.execute_http_response_body(&mut ctx, &mut body, true).unwrap();

    assert_eq!(
        chunks.lock().unwrap().len(),
        1,
        "response body filter should execute when ctx response status matches"
    );
}

#[tokio::test]
async fn no_conditions_always_executes() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        vec![],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/anything");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let _result = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "unconditional filter should always execute"
    );
}

#[tokio::test]
async fn rejecting_filter_is_marked_executed() {
    let pipeline = make_pipeline(vec![Box::new(PassthroughFilter), Box::new(RejectFilter)]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();

    assert!(matches!(action, FilterAction::Reject(_)), "pipeline should reject");
    assert!(
        ctx.executed_filter_indices[1],
        "the rejecting filter ran and must participate in response-phase cleanup"
    );
}

#[test]
fn body_capabilities_none_when_no_body_filters() {
    let pipeline = make_pipeline(vec![Box::new(RejectFilter)]);
    let caps = pipeline.body_capabilities();

    assert!(!caps.needs_request_body, "non-body filter should not need request body");
    assert!(
        !caps.needs_response_body,
        "non-body filter should not need response body"
    );
}

#[test]
fn body_capabilities_detects_request_body_reader() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(BodyInspectorFilter { chunks })]);
    let caps = pipeline.body_capabilities();

    assert!(
        caps.needs_request_body,
        "read-only body filter should need request body"
    );
    assert!(
        !caps.any_request_body_writer,
        "read-only filter should not be a body writer"
    );
    assert!(
        !caps.needs_response_body,
        "request body filter should not need response body"
    );
}

#[test]
fn body_capabilities_detects_request_body_writer() {
    let pipeline = make_pipeline(vec![Box::new(BodyUppercaseFilter)]);
    let caps = pipeline.body_capabilities();

    assert!(
        caps.needs_request_body,
        "read-write body filter should need request body"
    );
    assert!(
        caps.any_request_body_writer,
        "read-write filter should be a body writer"
    );
}

#[test]
fn request_body_reset_preserves_other_completion_flags() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(PassthroughFilter),
        Box::new(BodyUppercaseFilter),
        Box::new(ResponseBodyInspectorFilter { chunks }),
    ]);
    let mut body_done = [true; 3];

    pipeline.clear_request_body_done(&mut body_done);

    assert_eq!(
        body_done,
        [true, false, true],
        "only request-body completion flags should reset"
    );
}

#[test]
fn body_capabilities_detects_response_body() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(ResponseBodyInspectorFilter { chunks })]);
    let caps = pipeline.body_capabilities();

    assert!(
        !caps.needs_request_body,
        "response body filter should not need request body"
    );
    assert!(
        caps.needs_response_body,
        "response body filter should need response body"
    );
}

#[tokio::test]
async fn execute_request_body_read_only() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(BodyInspectorFilter {
        chunks: Arc::clone(&chunks),
    })]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"chunk1"));
    let action = pipeline
        .execute_http_request_body(&mut ctx, &mut body, false)
        .await
        .unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "read-only body filter should continue"
    );
    assert_eq!(chunks.lock().unwrap().len(), 1, "inspector should record one chunk");
    assert_eq!(
        chunks.lock().unwrap()[0],
        Bytes::from_static(b"chunk1"),
        "recorded chunk should match input"
    );
}

#[tokio::test]
async fn execute_request_body_mutation() {
    let pipeline = make_pipeline(vec![Box::new(BodyUppercaseFilter)]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"hello"));
    let _result = pipeline
        .execute_http_request_body(&mut ctx, &mut body, true)
        .await
        .unwrap();

    assert_eq!(
        body.unwrap(),
        Bytes::from_static(b"HELLO"),
        "body should be uppercased by filter"
    );
}

#[tokio::test]
async fn execute_request_body_reject() {
    let pipeline = make_pipeline(vec![Box::new(BodyRejectFilter)]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"REJECT_ME"));
    let action = pipeline
        .execute_http_request_body(&mut ctx, &mut body, false)
        .await
        .unwrap();

    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 400),
        "body containing REJECT should trigger 400 rejection"
    );
}

#[tokio::test]
async fn execute_request_body_skips_none_access_filters() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline(vec![Box::new(CountingFilter {
        counter: Arc::clone(&counter),
    })]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"data"));
    let _result = pipeline
        .execute_http_request_body(&mut ctx, &mut body, true)
        .await
        .unwrap();

    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "filter with no body access should not be called for body"
    );
}

// -----------------------------------------------------------------------------
// Selected-Upstream Request-Body Execution Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn execute_selected_upstream_request_body_discards_a_read_only_edit() {
    let pipeline = make_pipeline(vec![Box::new(SelectedUpstreamTamperFilter {
        access: BodyAccess::ReadOnly,
        error: false,
    })]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"payload"));

    let action = pipeline
        .execute_http_selected_upstream_request_body(&mut ctx, &mut body)
        .await
        .unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "the filter continued: {action:?}"
    );
    assert_eq!(
        body.as_deref(),
        Some(&b"payload"[..]),
        "a read-only filter works on a copy, so its edit never reaches the forwarded body"
    );
}

#[tokio::test]
async fn execute_selected_upstream_request_body_undoes_a_fail_open_writer_that_errors() {
    let mut pipeline = make_pipeline(vec![Box::new(SelectedUpstreamTamperFilter {
        access: BodyAccess::ReadWrite,
        error: true,
    })]);
    pipeline.filters[0].failure_mode = FailureMode::Open;
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"payload"));

    let action = pipeline
        .execute_http_selected_upstream_request_body(&mut ctx, &mut body)
        .await
        .unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "fail-open swallows the error: {action:?}"
    );
    assert_eq!(
        body.as_deref(),
        Some(&b"payload"[..]),
        "the writer's partial edit is undone before the error is swallowed"
    );
}

#[tokio::test]
async fn execute_selected_upstream_request_body_read_only() {
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(SelectedUpstreamRecorderFilter {
        label: "sel_a",
        log: Arc::clone(&log),
        bodies: Arc::clone(&bodies),
    })]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"payload"));
    let action = pipeline
        .execute_http_selected_upstream_request_body(&mut ctx, &mut body)
        .await
        .unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "read-only selected-upstream body filter should continue"
    );
    assert_eq!(log.lock().unwrap().as_slice(), ["sel_a"], "filter should run once");
    assert_eq!(
        bodies.lock().unwrap()[0],
        Some(Bytes::from_static(b"payload")),
        "recorded body should match input"
    );
    assert_eq!(
        body,
        Some(Bytes::from_static(b"payload")),
        "read-only filter should leave the body unchanged"
    );
}

#[tokio::test]
async fn execute_selected_upstream_request_body_mutation() {
    let pipeline = make_pipeline(vec![Box::new(SelectedUpstreamRewriteFilter)]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"hello"));
    let action = pipeline
        .execute_http_selected_upstream_request_body(&mut ctx, &mut body)
        .await
        .unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "rewrite filter should continue"
    );
    assert_eq!(
        body,
        Some(Bytes::from_static(b"HELLO")),
        "read-write filter should rewrite the selected-upstream body"
    );
}

#[tokio::test]
async fn execute_selected_upstream_request_body_reject_short_circuits() {
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(SelectedUpstreamRejectFilter),
        Box::new(SelectedUpstreamRecorderFilter {
            label: "after_reject",
            log: Arc::clone(&log),
            bodies: Arc::clone(&bodies),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"payload"));
    let action = pipeline
        .execute_http_selected_upstream_request_body(&mut ctx, &mut body)
        .await
        .unwrap();

    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 413),
        "rejecting filter should short-circuit with its status"
    );
    assert!(log.lock().unwrap().is_empty(), "filter after a reject should not run");
}

#[tokio::test]
async fn execute_selected_upstream_request_body_runs_in_pipeline_order() {
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(SelectedUpstreamRecorderFilter {
            label: "sel_a",
            log: Arc::clone(&log),
            bodies: Arc::clone(&bodies),
        }),
        Box::new(SelectedUpstreamRecorderFilter {
            label: "sel_b",
            log: Arc::clone(&log),
            bodies: Arc::clone(&bodies),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"payload"));
    let _action = pipeline
        .execute_http_selected_upstream_request_body(&mut ctx, &mut body)
        .await
        .unwrap();

    assert_eq!(
        log.lock().unwrap().as_slice(),
        ["sel_a", "sel_b"],
        "selected-upstream filters should run in pipeline order"
    );
}

#[tokio::test]
async fn execute_selected_upstream_request_body_skips_non_participants() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(BodyInspectorFilter {
        chunks: Arc::clone(&chunks),
    })]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"payload"));
    let action = pipeline
        .execute_http_selected_upstream_request_body(&mut ctx, &mut body)
        .await
        .unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "no participants should continue"
    );
    assert!(
        chunks.lock().unwrap().is_empty(),
        "a request-body-only filter must not run in the selected-upstream phase"
    );
}

#[tokio::test]
async fn execute_selected_upstream_request_body_preserves_canonical_body() {
    let pipeline = make_pipeline(vec![Box::new(SelectedUpstreamRewriteFilter)]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"hello"));
    let _action = pipeline
        .execute_http_selected_upstream_request_body(&mut ctx, &mut body)
        .await
        .unwrap();

    assert_eq!(
        body,
        Some(Bytes::from_static(b"HELLO")),
        "the working body should be rewritten"
    );
    assert_eq!(
        ctx.request_body_bytes, 0,
        "selected-upstream phase must not re-accumulate the canonical request body counter"
    );
}

#[tokio::test]
async fn execute_selected_upstream_request_body_skips_filters_not_executed_in_request_phase() {
    let counter = Arc::new(AtomicUsize::new(0));
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        Box::new(SelectedUpstreamRecorderFilter {
            label: "sel_a",
            log: Arc::clone(&log),
            bodies: Arc::clone(&bodies),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.executed_filter_indices = vec![true, false];

    let mut body = Some(Bytes::from_static(b"payload"));
    let action = pipeline
        .execute_http_selected_upstream_request_body(&mut ctx, &mut body)
        .await
        .unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "skipped filter should continue"
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "a filter not executed in the request phase must be skipped here too"
    );
}

#[test]
fn execute_response_body_read_only() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(ResponseBodyInspectorFilter {
        chunks: Arc::clone(&chunks),
    })]);
    let req = crate::test_utils::make_request(Method::GET, "/data");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"response data"));
    let _result = pipeline.execute_http_response_body(&mut ctx, &mut body, true).unwrap();

    assert_eq!(
        chunks.lock().unwrap().len(),
        1,
        "response inspector should record one chunk"
    );
    assert_eq!(
        chunks.lock().unwrap()[0],
        Bytes::from_static(b"response data"),
        "recorded response chunk should match input"
    );
}

#[test]
fn body_capabilities_detects_stream_buffer_mode() {
    let pipeline = make_pipeline(vec![Box::new(StreamBufferReleaseFilter { marker: b"OK" })]);
    let caps = pipeline.body_capabilities();

    assert!(caps.needs_request_body, "stream buffer filter should need request body");
    assert_eq!(
        caps.request_body_mode,
        BodyMode::StreamBuffer { max_bytes: None },
        "mode should be StreamBuffer with no limit"
    );
}

#[test]
fn body_capabilities_buffer_overrides_stream_buffer() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(StreamBufferReleaseFilter { marker: b"OK" }),
        Box::new(BodyInspectorFilter { chunks }),
    ]);
    let caps = pipeline.body_capabilities();

    assert_eq!(
        caps.request_body_mode,
        BodyMode::StreamBuffer { max_bytes: None },
        "StreamBuffer should win over Stream mode"
    );
}

#[test]
fn body_capabilities_multiple_stream_buffer_merges() {
    let pipeline = make_pipeline(vec![
        Box::new(StreamBufferReleaseFilter { marker: b"A" }),
        Box::new(StreamBufferReleaseFilter { marker: b"B" }),
    ]);
    let caps = pipeline.body_capabilities();

    assert_eq!(
        caps.request_body_mode,
        BodyMode::StreamBuffer { max_bytes: None },
        "multiple StreamBuffer filters should still yield StreamBuffer"
    );
}

#[test]
fn body_capabilities_multiple_stream_buffer_largest_wins() {
    let pipeline = make_pipeline(vec![
        Box::new(BoundedStreamBufferFilter { max_bytes: 1024 }),
        Box::new(BoundedStreamBufferFilter { max_bytes: 65_536 }),
    ]);
    let caps = pipeline.body_capabilities();

    assert_eq!(
        caps.request_body_mode,
        BodyMode::StreamBuffer {
            max_bytes: Some(65_536)
        },
        "largest StreamBuffer limit should win when merging finite limits"
    );
}

#[tokio::test]
async fn execute_request_body_release_propagates() {
    let pipeline = make_pipeline(vec![Box::new(StreamBufferReleaseFilter { marker: b"GO" })]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"GO"));
    let action = pipeline
        .execute_http_request_body(&mut ctx, &mut body, false)
        .await
        .unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "marker match should trigger Release"
    );
}

#[tokio::test]
async fn execute_request_body_release_does_not_short_circuit() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(StreamBufferReleaseFilter { marker: b"GO" }),
        Box::new(BodyInspectorFilter {
            chunks: Arc::clone(&chunks),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"GO"));
    let action = pipeline
        .execute_http_request_body(&mut ctx, &mut body, false)
        .await
        .unwrap();

    assert!(matches!(action, FilterAction::Release), "Release should propagate");
    assert_eq!(
        chunks.lock().unwrap().len(),
        1,
        "second filter should still see the chunk"
    );
}

#[tokio::test]
async fn execute_request_body_continue_without_marker() {
    let pipeline = make_pipeline(vec![Box::new(StreamBufferReleaseFilter { marker: b"GO" })]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"not yet"));
    let action = pipeline
        .execute_http_request_body(&mut ctx, &mut body, false)
        .await
        .unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "no marker should yield Continue"
    );
}

#[test]
fn apply_body_limits_no_limits_leaves_stream_mode() {
    let caps = BodyCapabilities::default();
    let mut pipeline = test_pipeline(caps, vec![]);
    pipeline.apply_body_limits(None, None, false).unwrap();

    assert!(
        !pipeline.body_capabilities().needs_request_body,
        "no limits should not need request body"
    );
    assert!(
        !pipeline.body_capabilities().needs_response_body,
        "no limits should not need response body"
    );
    assert_eq!(
        pipeline.body_capabilities().request_body_mode,
        BodyMode::Stream,
        "default request body mode should be Stream"
    );
    assert_eq!(
        pipeline.body_capabilities().response_body_mode,
        BodyMode::Stream,
        "default response body mode should be Stream"
    );
}

#[test]
fn apply_body_limits_converts_default_stream_to_size_limit() {
    let caps = BodyCapabilities::default();
    let mut pipeline = test_pipeline(caps, vec![]);
    pipeline
        .apply_body_limits(Some(1_048_576), Some(524_288), false)
        .unwrap();
    let caps = pipeline.body_capabilities();

    assert!(
        caps.needs_request_body,
        "limits should enable body access for enforcement"
    );
    assert!(
        caps.needs_response_body,
        "limits should enable body access for enforcement"
    );
    assert_eq!(
        caps.request_body_mode,
        BodyMode::SizeLimit { max_bytes: 1_048_576 },
        "default Stream should become SizeLimit for enforcement"
    );
    assert_eq!(
        caps.response_body_mode,
        BodyMode::SizeLimit { max_bytes: 524_288 },
        "default Stream should become SizeLimit for enforcement"
    );
}

#[test]
fn apply_body_limits_preserves_filter_declared_stream() {
    let caps = BodyCapabilities {
        needs_request_body: true,
        request_body_mode: BodyMode::Stream,
        needs_response_body: true,
        response_body_mode: BodyMode::Stream,
        ..BodyCapabilities::default()
    };
    let mut pipeline = test_pipeline(caps, vec![]);
    pipeline
        .apply_body_limits(Some(1_048_576), Some(524_288), false)
        .unwrap();
    let caps = pipeline.body_capabilities();

    assert_eq!(
        caps.request_body_mode,
        BodyMode::Stream,
        "filter-declared Stream should be preserved"
    );
    assert_eq!(
        caps.response_body_mode,
        BodyMode::Stream,
        "filter-declared Stream should be preserved"
    );
}

#[tokio::test]
async fn execute_request_body_condition_gating() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(BodyInspectorFilter {
            chunks: Arc::clone(&chunks),
        }),
        vec![when_path("/api")],
    )]);

    let req = crate::test_utils::make_request(Method::POST, "/other");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"data"));

    let _result = pipeline
        .execute_http_request_body(&mut ctx, &mut body, true)
        .await
        .unwrap();

    assert!(
        chunks.lock().unwrap().is_empty(),
        "condition-gated filter should not see body for non-matching path"
    );
}

#[test]
fn errors_load_balancer_without_router() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![],
        filter_type: "load_balancer".into(),
        config: serde_yaml::from_str("clusters:\n  - name: web\n    endpoints: [\"10.0.0.1:80\"]").unwrap(),
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors
            .iter()
            .any(|e| e.contains("load_balancer without a preceding router")),
        "should error on missing router: {errors:?}"
    );
}

#[test]
fn no_error_when_router_precedes_load_balancer() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "load_balancer".into(),
            config: serde_yaml::from_str("clusters:\n  - name: web\n    endpoints: [\"10.0.0.1:80\"]").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors.is_empty(),
        "router before load_balancer should produce no errors: {errors:?}"
    );
}

#[test]
fn errors_unconditional_static_response_followed_by_filters() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "static_response".into(),
            config: serde_yaml::from_str("status: 200").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors.iter().any(|e| e.contains("unreachable")),
        "should error on unreachable filters: {errors:?}"
    );
}

#[test]
fn no_error_for_conditional_static_response() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![when_path("/health")],
            filter_type: "static_response".into(),
            config: serde_yaml::from_str("status: 200").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "load_balancer".into(),
            config: serde_yaml::from_str("clusters:\n  - name: web\n    endpoints: [\"10.0.0.1:80\"]").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors.is_empty(),
        "conditional static_response should not error: {errors:?}"
    );
}

#[test]
fn errors_duplicate_router() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "load_balancer".into(),
            config: serde_yaml::from_str("clusters:\n  - name: web\n    endpoints: [\"10.0.0.1:80\"]").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors.iter().any(|e| e.contains("multiple router")),
        "should error on duplicate router filters: {errors:?}"
    );
}

#[test]
fn errors_duplicate_load_balancer() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "load_balancer".into(),
            config: serde_yaml::from_str("clusters:\n  - name: web\n    endpoints: [\"10.0.0.1:80\"]").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "load_balancer".into(),
            config: serde_yaml::from_str("clusters:\n  - name: web\n    endpoints: [\"10.0.0.1:80\"]").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors.iter().any(|e| e.contains("multiple load_balancer")),
        "should error on duplicate load_balancer filters: {errors:?}"
    );
}

#[test]
fn errors_conditional_security_filter() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![when_path("/api")],
        filter_type: "ip_acl".into(),
        config: serde_yaml::from_str("allow: [\"10.0.0.0/8\"]").unwrap(),
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors
            .iter()
            .any(|e| e.contains("security filter") && e.contains("ip_acl")),
        "should error on conditional security filter: {errors:?}"
    );
}

#[test]
fn no_error_for_unconditional_security_filter() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![],
        filter_type: "ip_acl".into(),
        config: serde_yaml::from_str("allow: [\"10.0.0.0/8\"]").unwrap(),
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        !errors.iter().any(|e| e.contains("security filter")),
        "unconditional security filter should not error: {errors:?}"
    );
}

#[test]
fn errors_open_security_filter() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![],
        filter_type: "ip_acl".into(),
        config: serde_yaml::from_str("allow: [\"10.0.0.0/8\"]").unwrap(),
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::Open,
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors
            .iter()
            .any(|e| e.contains("failure_mode: open") && e.contains("ip_acl")),
        "should error on open security filter: {errors:?}"
    );
}

#[test]
fn allow_open_security_filter_with_insecure_flag() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![],
        filter_type: "ip_acl".into(),
        config: serde_yaml::from_str("allow: [\"10.0.0.0/8\"]").unwrap(),
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::Open,
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, true, &SkipPipelineChecks::default());
    assert!(
        !errors.iter().any(|e| e.contains("failure_mode: open")),
        "insecure flag should demote open security filter error to warning: {errors:?}"
    );
}

#[test]
fn errors_open_forwarded_headers_filter() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![],
        filter_type: "forwarded_headers".into(),
        config: serde_yaml::from_str("trusted_proxies: [\"10.0.0.0/8\"]").unwrap(),
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::Open,
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors
            .iter()
            .any(|e| e.contains("failure_mode: open") && e.contains("forwarded_headers")),
        "should error on open forwarded_headers filter: {errors:?}"
    );
}

#[test]
fn allow_open_forwarded_headers_with_insecure_flag() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![],
        filter_type: "forwarded_headers".into(),
        config: serde_yaml::from_str("trusted_proxies: [\"10.0.0.0/8\"]").unwrap(),
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::Open,
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, true, &SkipPipelineChecks::default());
    assert!(
        !errors
            .iter()
            .any(|e| e.contains("failure_mode: open") && e.contains("forwarded_headers")),
        "insecure flag should demote open forwarded_headers error to warning: {errors:?}"
    );
}

#[test]
fn build_rejects_conditions_on_a_tcp_filter() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![tcp_access_log_entry()];
    entries[0].conditions = vec![when_path("/never")];
    let err = FilterPipeline::build(&mut entries, &registry)
        .err()
        .expect("a TCP filter ignores conditions, so a config that sets them must not build");
    assert!(
        err.to_string().contains("conditions are not supported on TCP filters"),
        "the error should say why the config is rejected: {err}"
    );
}

#[test]
fn build_with_chains_rejects_conditions_on_a_tcp_filter() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![tcp_access_log_entry()];
    entries[0].conditions = vec![when_path("/never")];
    let err = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &HashMap::new(),
        &praxis_core::config::InsecureOptions::default(),
    )
    .err()
    .expect("the production build path must reject conditions on a TCP filter too");
    assert!(
        err.to_string().contains("conditions are not supported on TCP filters"),
        "the error should say why the config is rejected: {err}"
    );
}

#[test]
fn build_with_chains_rejects_response_conditions_on_a_tcp_filter() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![tcp_access_log_entry()];
    entries[0].response_conditions = vec![when_status(&[500])];
    let err = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &HashMap::new(),
        &praxis_core::config::InsecureOptions::default(),
    )
    .err()
    .expect("a TCP filter has no response phase, so response_conditions alone must not build");
    assert!(
        err.to_string().contains("conditions are not supported on TCP filters"),
        "the error should say why the config is rejected: {err}"
    );
}

#[test]
fn build_with_chains_rejects_branch_chains_on_a_tcp_filter() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![tcp_access_log_entry()];
    entries[0].branch_chains = Some(Vec::new());
    let err = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &HashMap::new(),
        &praxis_core::config::InsecureOptions::default(),
    )
    .err()
    .expect("a TCP filter never branches, so a config that sets branch_chains must not build");
    assert!(
        err.to_string()
            .contains("branch_chains are not supported on TCP filters"),
        "the error should say why the config is rejected: {err}"
    );
}

#[test]
fn errors_conditional_security_filter_in_branch_chain() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![host_entry_with_branch(
        "sec",
        None,
        vec![ip_acl_entry(vec![when_path("/admin")], FailureMode::default())],
    )];
    let pipeline = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &HashMap::new(),
        &praxis_core::config::InsecureOptions::default(),
    )
    .unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors
            .iter()
            .any(|e| e.contains("ip_acl") && e.contains("branch 'sec'") && e.contains("request conditions")),
        "conditional security filter in a branch chain should error: {errors:?}"
    );
}

#[test]
fn errors_open_security_filter_in_branch_chain() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![host_entry_with_branch(
        "sec",
        None,
        vec![ip_acl_entry(vec![], FailureMode::Open)],
    )];
    let pipeline = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &HashMap::new(),
        &praxis_core::config::InsecureOptions::default(),
    )
    .unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors
            .iter()
            .any(|e| e.contains("ip_acl") && e.contains("branch 'sec'") && e.contains("failure_mode: open")),
        "fail-open security filter in a branch chain should error: {errors:?}"
    );
}

#[test]
fn errors_open_security_filter_in_nested_branch_chain() {
    let registry = FilterRegistry::with_builtins();
    let inner = host_entry_with_branch("inner", None, vec![ip_acl_entry(vec![], FailureMode::Open)]);
    let mut entries = vec![host_entry_with_branch("outer", None, vec![inner])];
    let pipeline = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &HashMap::new(),
        &praxis_core::config::InsecureOptions::default(),
    )
    .unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors
            .iter()
            .any(|e| e.contains("ip_acl") && e.contains("branch 'inner'") && e.contains("failure_mode: open")),
        "nested branch chains should be walked: {errors:?}"
    );
}

#[test]
fn allow_open_security_filter_in_branch_chain_with_insecure_flag() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![host_entry_with_branch(
        "sec",
        None,
        vec![ip_acl_entry(vec![], FailureMode::Open)],
    )];
    let pipeline = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &HashMap::new(),
        &praxis_core::config::InsecureOptions::default(),
    )
    .unwrap();
    let errors = pipeline.ordering_errors(&entries, true, &SkipPipelineChecks::default());
    assert!(
        !errors.iter().any(|e| e.contains("failure_mode: open")),
        "insecure flag should demote the branch-level open error to a warning: {errors:?}"
    );
}

#[test]
fn skip_conditional_security_suppresses_branch_chain_error() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![host_entry_with_branch(
        "sec",
        None,
        vec![ip_acl_entry(vec![when_path("/admin")], FailureMode::default())],
    )];
    let pipeline = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &HashMap::new(),
        &praxis_core::config::InsecureOptions::default(),
    )
    .unwrap();
    let skip = SkipPipelineChecks {
        conditional_security: true,
        ..SkipPipelineChecks::default()
    };
    let errors = pipeline.ordering_errors(&entries, false, &skip);
    assert!(
        !errors.iter().any(|e| e.contains("request conditions")),
        "conditional_security skip should also cover branch chains: {errors:?}"
    );
}

#[test]
fn warns_but_does_not_error_on_security_filter_in_conditional_branch_chain() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![host_entry_with_branch(
        "gated",
        Some("suspect"),
        vec![ip_acl_entry(vec![], FailureMode::default())],
    )];
    let pipeline = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &HashMap::new(),
        &praxis_core::config::InsecureOptions::default(),
    )
    .unwrap();

    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        !errors.iter().any(|e| e.contains("ip_acl")),
        "a branch-level gate alone must not fail the build: {errors:?}"
    );

    let warnings = pipeline.ordering_warnings();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("ip_acl") && w.contains("conditional branch 'gated'")),
        "gated security filter should be reported as an advisory: {warnings:?}"
    );
}

#[test]
fn no_conditional_branch_advisory_for_unconditional_branch_chain() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![host_entry_with_branch(
        "always",
        None,
        vec![ip_acl_entry(vec![], FailureMode::default())],
    )];
    let pipeline = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &HashMap::new(),
        &praxis_core::config::InsecureOptions::default(),
    )
    .unwrap();
    let warnings = pipeline.ordering_warnings();
    assert!(
        !warnings.iter().any(|w| w.contains("ip_acl")),
        "an unconditional branch always runs, so no advisory is due: {warnings:?}"
    );
}

#[test]
fn build_stamps_is_security_from_registry_class() {
    let mut registry = FilterRegistry::with_builtins();
    register_named_filter(&mut registry, "my_auth", SecurityClass::Security);
    register_named_filter(&mut registry, "my_logger", SecurityClass::Standard);
    let mut entries = vec![
        named_noop_entry("my_auth", FailureMode::default()),
        named_noop_entry("my_logger", FailureMode::default()),
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    assert!(
        pipeline.filters[0].is_security,
        "Security-class registration must stamp is_security at build"
    );
    assert!(
        !pipeline.filters[1].is_security,
        "Standard-class registration must not stamp is_security"
    );
}

#[test]
fn build_with_chains_stamps_is_security_on_branch_filter() {
    let mut registry = FilterRegistry::with_builtins();
    register_named_filter(&mut registry, "my_auth", SecurityClass::Security);
    let mut entries = vec![FilterEntry {
        branch_chains: Some(vec![BranchChainConfig {
            chains: vec![ChainRef::Inline {
                name: "auth_chain".to_owned(),
                filters: vec![named_noop_entry("my_auth", FailureMode::default())],
            }],
            max_iterations: None,
            name: "auth_branch".to_owned(),
            on_result: None,
            rejoin: "next".to_owned(),
        }]),
        ..named_noop_entry("request_id", FailureMode::default())
    }];
    let chains: HashMap<&str, &[FilterEntry]> = HashMap::new();
    let pipeline = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &chains,
        &praxis_core::config::InsecureOptions::default(),
    )
    .unwrap();
    assert_eq!(
        pipeline.filters.len(),
        1,
        "top-level host should be the only parent filter"
    );
    assert!(
        !pipeline.filters[0].is_security,
        "host request_id is Standard and must not be stamped Security"
    );
    assert_eq!(pipeline.filters[0].branches.len(), 1, "host should carry one branch");
    assert_eq!(
        pipeline.filters[0].branches[0].filters.len(),
        1,
        "branch sub-chain should contain the custom Security filter"
    );
    assert!(
        pipeline.filters[0].branches[0].filters[0].is_security,
        "Security-class filter inside a branch must be stamped by build_with_chains"
    );
}

#[test]
fn errors_open_custom_security_filter() {
    let mut registry = FilterRegistry::with_builtins();
    register_named_filter(&mut registry, "my_auth", SecurityClass::Security);
    let mut entries = vec![named_noop_entry("my_auth", FailureMode::Open)];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors
            .iter()
            .any(|e| e.contains("failure_mode: open") && e.contains("my_auth")),
        "custom Security-class filter with failure_mode: open must error: {errors:?}"
    );
}

#[test]
fn allow_open_custom_security_filter_with_insecure_flag() {
    let mut registry = FilterRegistry::with_builtins();
    register_named_filter(&mut registry, "my_auth", SecurityClass::Security);
    let mut entries = vec![named_noop_entry("my_auth", FailureMode::Open)];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, true, &SkipPipelineChecks::default());
    assert!(
        !errors.iter().any(|e| e.contains("failure_mode: open")),
        "insecure flag should demote open custom security filter error to warning: {errors:?}"
    );
}

#[test]
fn no_error_open_custom_standard_filter() {
    let mut registry = FilterRegistry::with_builtins();
    register_named_filter(&mut registry, "my_logger", SecurityClass::Standard);
    let mut entries = vec![named_noop_entry("my_logger", FailureMode::Open)];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        !errors.iter().any(|e| e.contains("failure_mode: open")),
        "Standard-class custom filter with failure_mode: open must not error: {errors:?}"
    );
}

#[test]
fn errors_conditional_custom_security_filter() {
    let mut registry = FilterRegistry::with_builtins();
    register_named_filter(&mut registry, "my_auth", SecurityClass::Security);
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![when_path("/api")],
        filter_type: "my_auth".into(),
        config: serde_yaml::Value::Null,
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors
            .iter()
            .any(|e| e.contains("security filter") && e.contains("my_auth")),
        "custom Security-class filter with request conditions must error: {errors:?}"
    );
}

#[test]
fn empty_pipeline_no_errors() {
    let registry = FilterRegistry::with_builtins();
    let mut entries: Vec<FilterEntry> = vec![];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(errors.is_empty(), "empty pipeline should produce no errors");
}

#[test]
fn empty_pipeline_no_warnings() {
    let registry = FilterRegistry::with_builtins();
    let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
    let warnings = pipeline.ordering_warnings();
    assert!(warnings.is_empty(), "empty pipeline should produce no warnings");
}

#[test]
fn skip_lb_without_router_suppresses_error() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![],
        filter_type: "load_balancer".into(),
        config: serde_yaml::from_str("clusters:\n  - name: web\n    endpoints: [\"10.0.0.1:80\"]").unwrap(),
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let skip = SkipPipelineChecks {
        lb_without_router: true,
        ..Default::default()
    };
    let errors = pipeline.ordering_errors(&entries, false, &skip);
    assert!(
        !errors.iter().any(|e| e.contains("without a preceding router")),
        "lb_without_router skip should suppress the error: {errors:?}"
    );
}

#[test]
fn skip_duplicate_routers_suppresses_error() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "load_balancer".into(),
            config: serde_yaml::from_str("clusters:\n  - name: web\n    endpoints: [\"10.0.0.1:80\"]").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let skip = SkipPipelineChecks {
        duplicate_routers: true,
        ..Default::default()
    };
    let errors = pipeline.ordering_errors(&entries, false, &skip);
    assert!(
        !errors.iter().any(|e| e.contains("multiple router")),
        "duplicate_routers skip should suppress the error: {errors:?}"
    );
}

#[test]
fn skip_conditional_security_suppresses_error() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![when_path("/api")],
        filter_type: "ip_acl".into(),
        config: serde_yaml::from_str("allow: [\"10.0.0.0/8\"]").unwrap(),
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let skip = SkipPipelineChecks {
        conditional_security: true,
        ..Default::default()
    };
    let errors = pipeline.ordering_errors(&entries, false, &skip);
    assert!(
        !errors.iter().any(|e| e.contains("security filter")),
        "conditional_security skip should suppress the error: {errors:?}"
    );
}

#[test]
fn skip_all_suppresses_all_errors() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![when_path("/api")],
            filter_type: "ip_acl".into(),
            config: serde_yaml::from_str("allow: [\"10.0.0.0/8\"]").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::all());
    assert!(errors.is_empty(), "skip-all should suppress every check: {errors:?}");
}

#[test]
fn granular_skip_only_affects_targeted_check() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "load_balancer".into(),
            config: serde_yaml::from_str("clusters:\n  - name: web\n    endpoints: [\"10.0.0.1:80\"]").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let skip = SkipPipelineChecks {
        conditional_security: true,
        ..Default::default()
    };
    let errors = pipeline.ordering_errors(&entries, false, &skip);
    assert!(
        errors.iter().any(|e| e.contains("multiple router")),
        "skipping conditional_security should not suppress duplicate router error: {errors:?}"
    );
}

#[test]
fn warns_router_without_lb() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![],
        filter_type: "router".into(),
        config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let warnings = pipeline.ordering_warnings();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("router filter without a load_balancer")),
        "should warn when router has no following LB: {warnings:?}"
    );
}

#[test]
fn errors_misaligned_clusters() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: missing_cluster").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "load_balancer".into(),
            config: serde_yaml::from_str("clusters:\n  - name: other_cluster\n    endpoints: [\"10.0.0.1:80\"]")
                .unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors
            .iter()
            .any(|e| e.contains("missing_cluster") && e.contains("not defined")),
        "should error on cluster mismatch: {errors:?}"
    );
}

#[test]
fn no_error_for_aligned_clusters() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: backend").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "load_balancer".into(),
            config: serde_yaml::from_str("clusters:\n  - name: backend\n    endpoints: [\"10.0.0.1:80\"]").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors.is_empty(),
        "aligned clusters should produce no errors: {errors:?}"
    );
}

#[test]
fn warns_all_routers_conditional() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![when_path("/api")],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "load_balancer".into(),
            config: serde_yaml::from_str("clusters:\n  - name: web\n    endpoints: [\"10.0.0.1:80\"]").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let warnings = pipeline.ordering_warnings();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("all router filters are conditional")),
        "should warn when all routers are conditional: {warnings:?}"
    );
}

#[test]
fn no_warning_when_unconditional_router_exists() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![when_path("/api")],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let warnings = pipeline.ordering_warnings();
    assert!(
        !warnings
            .iter()
            .any(|w| w.contains("all router filters are conditional")),
        "should not warn when at least one router is unconditional: {warnings:?}"
    );
}

#[tokio::test]
async fn response_header_swap_same_count_is_applied_to_the_map() {
    let pipeline = make_pipeline(vec![Box::new(SwapHeaderFilter)]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut resp = crate::context::Response {
        status: StatusCode::OK,
        headers: HeaderMap::new(),
    };
    resp.headers.insert("x-old", "original".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);
    let _result = pipeline.execute_http_response(&mut ctx).await.unwrap();
    assert!(
        !ctx.response_headers_modified,
        "the pipeline no longer infers modification; the flag is an explicit filter hint only"
    );
    assert!(resp.headers.get("x-old").is_none(), "swapped-out header should be gone");
    assert!(
        resp.headers.get("x-new").is_some(),
        "swapped-in header should be present"
    );
}

#[test]
fn apply_body_limits_default_stream_becomes_size_limit() {
    let caps = BodyCapabilities::default();
    let mut pipeline = test_pipeline(caps, vec![]);
    pipeline.apply_body_limits(Some(4096), Some(8192), false).unwrap();
    assert_eq!(
        pipeline.body_capabilities().request_body_mode,
        BodyMode::SizeLimit { max_bytes: 4096 },
        "default Stream should become SizeLimit for enforcement"
    );
    assert_eq!(
        pipeline.body_capabilities().response_body_mode,
        BodyMode::SizeLimit { max_bytes: 8192 },
        "default Stream should become SizeLimit for enforcement"
    );
}

#[test]
fn apply_body_limits_filter_stricter_than_config() {
    let mut caps = BodyCapabilities::default();
    caps.request_body_mode = BodyMode::StreamBuffer { max_bytes: Some(500) };
    caps.needs_request_body = true;
    let mut pipeline = test_pipeline(caps, vec![]);
    pipeline.apply_body_limits(Some(1000), None, false).unwrap();
    assert_eq!(
        pipeline.body_capabilities().request_body_mode,
        BodyMode::StreamBuffer { max_bytes: Some(500) },
        "filter's stricter limit should be preserved"
    );
}

#[test]
fn apply_body_limits_config_stricter_than_filter() {
    let caps = BodyCapabilities {
        request_body_mode: BodyMode::StreamBuffer { max_bytes: Some(2000) },
        needs_request_body: true,
        ..BodyCapabilities::default()
    };
    let mut pipeline = test_pipeline(caps, vec![]);
    pipeline.apply_body_limits(Some(1000), None, false).unwrap();
    assert_eq!(
        pipeline.body_capabilities().request_body_mode,
        BodyMode::StreamBuffer { max_bytes: Some(1000) },
        "config's stricter limit should override filter's limit"
    );
}

#[test]
fn apply_body_limits_rejects_unbounded_stream_buffer() {
    let caps = BodyCapabilities {
        request_body_mode: BodyMode::StreamBuffer { max_bytes: None },
        needs_request_body: true,
        ..BodyCapabilities::default()
    };
    let mut pipeline = test_pipeline(caps, vec![]);
    let err = pipeline.apply_body_limits(None, None, false).unwrap_err();
    assert!(
        err.to_string().contains("no size limit"),
        "should reject unbounded StreamBuffer: {err}"
    );
}

#[test]
fn apply_body_limits_clamps_unbounded_stream_buffer_with_override() {
    let caps = BodyCapabilities {
        request_body_mode: BodyMode::StreamBuffer { max_bytes: None },
        needs_request_body: true,
        ..BodyCapabilities::default()
    };
    let mut pipeline = test_pipeline(caps, vec![]);
    pipeline
        .apply_body_limits(None, None, true)
        .expect("allow_unbounded_body should demote error to warning");
    assert_eq!(
        pipeline.body_capabilities().request_body_mode,
        BodyMode::StreamBuffer {
            max_bytes: Some(praxis_core::config::ABSOLUTE_MAX_BODY_BYTES)
        },
        "unbounded StreamBuffer should be clamped to absolute ceiling"
    );
}

#[test]
fn errors_duplicate_path_rewrite_filters() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "path_rewrite".into(),
            config: serde_yaml::from_str("strip_prefix: \"/api\"").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "path_rewrite".into(),
            config: serde_yaml::from_str("add_prefix: \"/v2\"").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors
            .iter()
            .any(|e| e.contains("multiple path rewriting filters") && e.contains("rewritten_path")),
        "should error on duplicate path_rewrite: {errors:?}"
    );
}

#[test]
fn errors_mixed_path_and_url_rewrite_filters() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "path_rewrite".into(),
            config: serde_yaml::from_str("strip_prefix: \"/api\"").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "url_rewrite".into(),
            config: serde_yaml::from_str(
                "operations:\n  - regex_replace:\n      pattern: \"^/a\"\n      replacement: \"/b\"",
            )
            .unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors
            .iter()
            .any(|e| e.contains("path_rewrite") && e.contains("url_rewrite")),
        "should error on mixed rewrite filters: {errors:?}"
    );
}

#[test]
fn no_error_single_path_rewrite_filter() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![],
        filter_type: "path_rewrite".into(),
        config: serde_yaml::from_str("strip_prefix: \"/api\"").unwrap(),
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        !errors.iter().any(|e| e.contains("rewriting filters")),
        "single rewrite filter should not error: {errors:?}"
    );
}

#[test]
fn no_error_duplicate_rewrite_with_allow_override() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "path_rewrite".into(),
            config: serde_yaml::from_str("strip_prefix: \"/api\"").unwrap(),
            name: None,
            response_conditions: vec![],
        failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "url_rewrite".into(),
            config: serde_yaml::from_str(
                "operations:\n  - regex_replace:\n      pattern: \"^/a\"\n      replacement: \"/b\"\nallow_rewrite_override: true",
            )
            .unwrap(),
            name: None,
            response_conditions: vec![],
        failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        !errors.iter().any(|e| e.contains("rewriting filters")),
        "allow_rewrite_override should suppress error: {errors:?}"
    );
}

#[test]
fn error_when_allow_override_on_first_not_last() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "path_rewrite".into(),
            config: serde_yaml::from_str("strip_prefix: \"/api\"\nallow_rewrite_override: true").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "url_rewrite".into(),
            config: serde_yaml::from_str(
                "operations:\n  - regex_replace:\n      pattern: \"^/a\"\n      replacement: \"/b\"",
            )
            .unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors.iter().any(|e| e.contains("rewriting filters")),
        "override on first filter should not suppress error: {errors:?}"
    );
}

#[tokio::test]
async fn skip_to_excludes_skipped_filters_from_response() {
    let log: Arc<std::sync::Mutex<Vec<&'static str>>> = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut filter_a = PipelineFilter::new(
        0,
        AnyFilter::Http(Box::new(LoggingFilter {
            label: "A",
            log: Arc::clone(&log),
        })),
        vec![],
        vec![],
    );
    filter_a.branches = vec![ResolvedBranch {
        condition: None,
        filters: vec![],
        max_iterations: None,
        name: Arc::from("skip_branch"),
        rejoin: RejoinTarget::SkipTo(2),
    }];

    let filter_b = PipelineFilter::new(
        1,
        AnyFilter::Http(Box::new(LoggingFilter {
            label: "B",
            log: Arc::clone(&log),
        })),
        vec![],
        vec![],
    );

    let filter_c = PipelineFilter::new(
        2,
        AnyFilter::Http(Box::new(LoggingFilter {
            label: "C",
            log: Arc::clone(&log),
        })),
        vec![],
        vec![],
    );

    let pipeline = with_body_indices(FilterPipeline {
        body_capabilities: BodyCapabilities::default(),
        compression: None,
        filters: vec![filter_a, filter_b, filter_c],
        record_filter_duration_metrics: false,
        route_templates: Arc::default(),
        health_registry: None,
        id_generator: Arc::new(praxis_core::id::IdGenerator::with_seed(0)),
        kv_stores: None,
        session_stores: None,
        subrequest_client: None,
        may_select_streaming_subrequest_response: false,
        trace_context_filter_indices: Vec::new(),
        pipeline_extensions: Vec::new(),
        time_source: Arc::new(praxis_core::time::SystemTimeSource),
        request_body_ceiling: None,
        response_body_ceiling: None,
        request_body_filter_indices: Vec::new(),
        response_body_filter_indices: Vec::new(),
        selected_upstream_request_body_filter_indices: Vec::new(),
        #[cfg(feature = "bound-upstream-request-body")]
        bound_upstream_request_body_filter_indices: Vec::new(),
        allow_private_upstreams: false,
        response_trailer_filter_indices: Vec::new(),
    });

    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());
    log.lock().unwrap().clear();

    drop(pipeline.execute_http_response(&mut ctx).await.unwrap());
    let recorded = log.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["C", "A"],
        "response should skip B (skipped by SkipTo) and run C then A in reverse"
    );
}

#[tokio::test]
async fn skip_to_excludes_skipped_filters_from_body_hooks() {
    let log: Arc<std::sync::Mutex<Vec<&'static str>>> = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut filter_a = PipelineFilter::new(
        0,
        AnyFilter::Http(Box::new(BodyLoggingFilter {
            label: "A",
            log: Arc::clone(&log),
        })),
        vec![],
        vec![],
    );
    filter_a.branches = vec![ResolvedBranch {
        condition: None,
        filters: vec![],
        max_iterations: None,
        name: Arc::from("skip_branch"),
        rejoin: RejoinTarget::SkipTo(2),
    }];

    let filter_b = PipelineFilter::new(
        1,
        AnyFilter::Http(Box::new(BodyLoggingFilter {
            label: "B",
            log: Arc::clone(&log),
        })),
        vec![],
        vec![],
    );
    let filter_c = PipelineFilter::new(
        2,
        AnyFilter::Http(Box::new(BodyLoggingFilter {
            label: "C",
            log: Arc::clone(&log),
        })),
        vec![],
        vec![],
    );

    let pipeline = with_body_indices(FilterPipeline {
        body_capabilities: BodyCapabilities::default(),
        compression: None,
        filters: vec![filter_a, filter_b, filter_c],
        record_filter_duration_metrics: false,
        route_templates: Arc::default(),
        health_registry: None,
        id_generator: Arc::new(praxis_core::id::IdGenerator::with_seed(0)),
        kv_stores: None,
        session_stores: None,
        may_select_streaming_subrequest_response: false,
        trace_context_filter_indices: Vec::new(),
        subrequest_client: None,
        pipeline_extensions: Vec::new(),
        time_source: Arc::new(praxis_core::time::SystemTimeSource),
        request_body_ceiling: None,
        response_body_ceiling: None,
        request_body_filter_indices: Vec::new(),
        response_body_filter_indices: Vec::new(),
        selected_upstream_request_body_filter_indices: Vec::new(),
        #[cfg(feature = "bound-upstream-request-body")]
        bound_upstream_request_body_filter_indices: Vec::new(),
        allow_private_upstreams: false,
        response_trailer_filter_indices: Vec::new(),
    });

    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());
    log.lock().unwrap().clear();

    let mut body = Some(Bytes::from_static(b"payload"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body, true)
            .await
            .unwrap(),
    );
    assert_eq!(
        log.lock().unwrap().clone(),
        vec!["A", "C"],
        "request body should skip B, which SkipTo bypassed in the request phase"
    );

    log.lock().unwrap().clear();
    let mut body = Some(Bytes::from_static(b"payload"));
    drop(pipeline.execute_http_response_body(&mut ctx, &mut body, true).unwrap());
    assert_eq!(
        log.lock().unwrap().clone(),
        vec!["C", "A"],
        "response body should skip B and run in reverse order"
    );
}

#[tokio::test]
async fn body_hooks_run_for_every_filter_before_the_request_phase() {
    let log: Arc<std::sync::Mutex<Vec<&'static str>>> = Arc::new(std::sync::Mutex::new(Vec::new()));

    let pipeline = with_body_indices(FilterPipeline {
        body_capabilities: BodyCapabilities::default(),
        compression: None,
        filters: vec![
            PipelineFilter::new(
                0,
                AnyFilter::Http(Box::new(BodyLoggingFilter {
                    label: "A",
                    log: Arc::clone(&log),
                })),
                vec![],
                vec![],
            ),
            PipelineFilter::new(
                1,
                AnyFilter::Http(Box::new(BodyLoggingFilter {
                    label: "B",
                    log: Arc::clone(&log),
                })),
                vec![],
                vec![],
            ),
        ],
        record_filter_duration_metrics: false,
        route_templates: Arc::default(),
        health_registry: None,
        id_generator: Arc::new(praxis_core::id::IdGenerator::with_seed(0)),
        kv_stores: None,
        session_stores: None,
        may_select_streaming_subrequest_response: false,
        trace_context_filter_indices: Vec::new(),
        subrequest_client: None,
        pipeline_extensions: Vec::new(),
        time_source: Arc::new(praxis_core::time::SystemTimeSource),
        request_body_ceiling: None,
        response_body_ceiling: None,
        request_body_filter_indices: Vec::new(),
        response_body_filter_indices: Vec::new(),
        selected_upstream_request_body_filter_indices: Vec::new(),
        #[cfg(feature = "bound-upstream-request-body")]
        bound_upstream_request_body_filter_indices: Vec::new(),
        allow_private_upstreams: false,
        response_trailer_filter_indices: Vec::new(),
    });

    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    assert!(
        ctx.executed_filter_indices.is_empty(),
        "precondition: request phase has not run"
    );

    let mut body = Some(Bytes::from_static(b"payload"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body, true)
            .await
            .unwrap(),
    );

    assert_eq!(
        log.lock().unwrap().clone(),
        vec!["A", "B"],
        "pre-read must not gate on request-phase tracking that has not happened yet"
    );
}

#[tokio::test]
async fn all_executed_filters_run_on_response() {
    let log: Arc<std::sync::Mutex<Vec<&'static str>>> = Arc::new(std::sync::Mutex::new(Vec::new()));

    let pipeline = with_body_indices(FilterPipeline {
        body_capabilities: BodyCapabilities::default(),
        compression: None,
        filters: vec![
            PipelineFilter::new(
                0,
                AnyFilter::Http(Box::new(LoggingFilter {
                    label: "first",
                    log: Arc::clone(&log),
                })),
                vec![],
                vec![],
            ),
            PipelineFilter::new(
                1,
                AnyFilter::Http(Box::new(LoggingFilter {
                    label: "second",
                    log: Arc::clone(&log),
                })),
                vec![],
                vec![],
            ),
        ],
        record_filter_duration_metrics: false,
        route_templates: Arc::default(),
        health_registry: None,
        id_generator: Arc::new(praxis_core::id::IdGenerator::with_seed(0)),
        kv_stores: None,
        session_stores: None,
        subrequest_client: None,
        may_select_streaming_subrequest_response: false,
        trace_context_filter_indices: Vec::new(),
        pipeline_extensions: Vec::new(),
        time_source: Arc::new(praxis_core::time::SystemTimeSource),
        request_body_ceiling: None,
        response_body_ceiling: None,
        request_body_filter_indices: Vec::new(),
        response_body_filter_indices: Vec::new(),
        selected_upstream_request_body_filter_indices: Vec::new(),
        #[cfg(feature = "bound-upstream-request-body")]
        bound_upstream_request_body_filter_indices: Vec::new(),
        allow_private_upstreams: false,
        response_trailer_filter_indices: Vec::new(),
    });

    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());
    log.lock().unwrap().clear();

    drop(pipeline.execute_http_response(&mut ctx).await.unwrap());
    let recorded = log.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["second", "first"],
        "all request-executed filters should run on_response in reverse"
    );
}

#[tokio::test]
async fn branch_filter_conditions_skip_it_for_non_matching_requests() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = pipeline_with_branch(vec![PipelineFilter::new(
        100,
        AnyFilter::Http(Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        })),
        vec![when_path("/api")],
        vec![],
    )]);

    let req = crate::test_utils::make_request(Method::GET, "/other");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "a branch filter whose conditions do not match must be skipped"
    );

    let req = crate::test_utils::make_request(Method::GET, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "a branch filter whose conditions match must run"
    );
}

#[tokio::test]
async fn branch_filter_failure_mode_open_swallows_its_error() {
    let after = Arc::new(AtomicUsize::new(0));
    let mut failing = PipelineFilter::new(100, AnyFilter::Http(Box::new(ErrorFilter)), vec![], vec![]);
    failing.failure_mode = FailureMode::Open;
    let pipeline = pipeline_with_branch(vec![
        failing,
        PipelineFilter::new(
            101,
            AnyFilter::Http(Box::new(CountingFilter {
                counter: Arc::clone(&after),
            })),
            vec![],
            vec![],
        ),
    ]);

    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let result = pipeline.execute_http_request(&mut ctx).await;
    assert!(result.is_ok(), "failure_mode: open must swallow a branch filter error");
    assert_eq!(
        after.load(Ordering::SeqCst),
        1,
        "the branch must continue past a swallowed error"
    );
}

#[tokio::test]
async fn branch_filter_failure_mode_closed_propagates_its_error() {
    let after = Arc::new(AtomicUsize::new(0));
    let mut failing = PipelineFilter::new(100, AnyFilter::Http(Box::new(ErrorFilter)), vec![], vec![]);
    failing.failure_mode = FailureMode::Closed;
    let pipeline = pipeline_with_branch(vec![
        failing,
        PipelineFilter::new(
            101,
            AnyFilter::Http(Box::new(CountingFilter {
                counter: Arc::clone(&after),
            })),
            vec![],
            vec![],
        ),
    ]);

    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let result = pipeline.execute_http_request(&mut ctx).await;
    assert!(
        result.is_err(),
        "the default closed failure mode must propagate a branch filter error"
    );
    assert_eq!(
        after.load(Ordering::SeqCst),
        0,
        "the branch must stop at a propagated error"
    );
}

#[tokio::test]
async fn reenter_short_circuit_still_runs_on_response() {
    let log: Arc<std::sync::Mutex<Vec<&'static str>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let calls = Arc::new(AtomicUsize::new(0));

    let reject_on_second = PipelineFilter::new(
        0,
        AnyFilter::Http(Box::new(RejectOnSecondCallFilter {
            calls: Arc::clone(&calls),
        })),
        vec![],
        vec![],
    );
    let mut reenter = PipelineFilter::new(
        1,
        AnyFilter::Http(Box::new(LoggingFilter {
            label: "reenter",
            log: Arc::clone(&log),
        })),
        vec![],
        vec![],
    );
    reenter.branches = vec![ResolvedBranch {
        name: Arc::from("loop-back"),
        condition: None,
        filters: vec![],
        max_iterations: Some(3),
        rejoin: RejoinTarget::ReEnter(0),
    }];

    let pipeline = test_pipeline(BodyCapabilities::default(), vec![reject_on_second, reenter]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(_)),
        "the second pass should short-circuit with a reject"
    );

    drop(pipeline.execute_http_response(&mut ctx).await.unwrap());
    assert_eq!(
        log.lock().unwrap().clone(),
        vec!["reenter"],
        "a first-pass filter short-circuited on re-entry must still run on_response"
    );
}

#[tokio::test]
async fn skipped_filter_skips_its_branches() {
    let counter = Arc::new(AtomicUsize::new(0));

    let branch_filter = PipelineFilter::new(
        100,
        AnyFilter::Http(Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        })),
        vec![],
        vec![],
    );
    let branch = ResolvedBranch {
        condition: None,
        filters: vec![branch_filter],
        max_iterations: None,
        name: Arc::from("should_not_fire"),
        rejoin: RejoinTarget::Next,
    };

    let mut parent = PipelineFilter::new(
        0,
        AnyFilter::Http(Box::new(CountingFilter {
            counter: Arc::new(AtomicUsize::new(0)),
        })),
        vec![when_path("/api")],
        vec![],
    );
    parent.branches = vec![branch];

    let pipeline = with_body_indices(FilterPipeline {
        body_capabilities: BodyCapabilities::default(),
        compression: None,
        filters: vec![parent],
        record_filter_duration_metrics: false,
        route_templates: Arc::default(),
        health_registry: None,
        id_generator: Arc::new(praxis_core::id::IdGenerator::with_seed(0)),
        kv_stores: None,
        session_stores: None,
        subrequest_client: None,
        may_select_streaming_subrequest_response: false,
        trace_context_filter_indices: Vec::new(),
        pipeline_extensions: Vec::new(),
        time_source: Arc::new(praxis_core::time::SystemTimeSource),
        request_body_ceiling: None,
        response_body_ceiling: None,
        request_body_filter_indices: Vec::new(),
        response_body_filter_indices: Vec::new(),
        selected_upstream_request_body_filter_indices: Vec::new(),
        #[cfg(feature = "bound-upstream-request-body")]
        bound_upstream_request_body_filter_indices: Vec::new(),
        allow_private_upstreams: false,
        response_trailer_filter_indices: Vec::new(),
    });

    let req = crate::test_utils::make_request(Method::GET, "/other");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "branch filter should not execute when parent filter is skipped by conditions"
    );
}

#[tokio::test]
async fn stream_buffer_eos_delivers_frozen_body() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(BodyInspectorFilter {
        chunks: Arc::clone(&chunks),
    })]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body1 = Some(Bytes::from_static(b"hello "));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body1, false)
            .await
            .unwrap(),
    );

    let mut body2 = Some(Bytes::from_static(b"world"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body2, true)
            .await
            .unwrap(),
    );

    let seen = chunks.lock().unwrap();
    assert_eq!(seen.len(), 2, "inspector should have been called twice");
    assert_eq!(
        seen[0],
        Bytes::from_static(b"hello "),
        "first call should see raw chunk"
    );
    assert_eq!(
        seen[1],
        Bytes::from_static(b"world"),
        "second call should see chunk delivered at EOS"
    );
}

#[tokio::test]
async fn stream_buffer_non_eos_delivers_raw_chunk() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(BodyInspectorFilter {
        chunks: Arc::clone(&chunks),
    })]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"hello "));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body, false)
            .await
            .unwrap(),
    );

    let seen = chunks.lock().unwrap();
    assert_eq!(seen.len(), 1, "inspector should have been called once");
    assert_eq!(
        seen[0],
        Bytes::from_static(b"hello "),
        "non-EOS call should see raw chunk"
    );
}

#[tokio::test]
async fn three_filters_all_see_each_chunk() {
    let chunks_a = Arc::new(std::sync::Mutex::new(Vec::new()));
    let chunks_b = Arc::new(std::sync::Mutex::new(Vec::new()));
    let chunks_c = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(BodyInspectorFilter {
            chunks: Arc::clone(&chunks_a),
        }),
        Box::new(BodyInspectorFilter {
            chunks: Arc::clone(&chunks_b),
        }),
        Box::new(BodyInspectorFilter {
            chunks: Arc::clone(&chunks_c),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"payload"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body, false)
            .await
            .unwrap(),
    );

    let a = chunks_a.lock().unwrap();
    let b = chunks_b.lock().unwrap();
    let c = chunks_c.lock().unwrap();
    assert_eq!(a.len(), 1, "filter A should see one chunk");
    assert_eq!(b.len(), 1, "filter B should see one chunk");
    assert_eq!(c.len(), 1, "filter C should see one chunk");
    assert_eq!(
        a[0],
        Bytes::from_static(b"payload"),
        "filter A should see correct content"
    );
    assert_eq!(
        b[0],
        Bytes::from_static(b"payload"),
        "filter B should see correct content"
    );
    assert_eq!(
        c[0],
        Bytes::from_static(b"payload"),
        "filter C should see correct content"
    );
}

#[tokio::test]
async fn three_filters_see_frozen_body_at_eos() {
    let chunks_a = Arc::new(std::sync::Mutex::new(Vec::new()));
    let chunks_b = Arc::new(std::sync::Mutex::new(Vec::new()));
    let chunks_c = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(BodyInspectorFilter {
            chunks: Arc::clone(&chunks_a),
        }),
        Box::new(BodyInspectorFilter {
            chunks: Arc::clone(&chunks_b),
        }),
        Box::new(BodyInspectorFilter {
            chunks: Arc::clone(&chunks_c),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body1 = Some(Bytes::from_static(b"first "));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body1, false)
            .await
            .unwrap(),
    );

    let mut body2 = Some(Bytes::from_static(b"second"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body2, true)
            .await
            .unwrap(),
    );

    for (label, chunks) in [("A", &chunks_a), ("B", &chunks_b), ("C", &chunks_c)] {
        let seen = chunks.lock().unwrap();
        assert_eq!(seen.len(), 2, "filter {label} should see two calls");
        assert_eq!(
            seen[0],
            Bytes::from_static(b"first "),
            "filter {label} should see raw first chunk"
        );
        assert_eq!(
            seen[1],
            Bytes::from_static(b"second"),
            "filter {label} should see chunk at EOS"
        );
    }
}

#[tokio::test]
async fn mutation_visible_to_subsequent_filters() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(BodyUppercaseFilter),
        Box::new(BodyInspectorFilter {
            chunks: Arc::clone(&chunks),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"hello"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body, true)
            .await
            .unwrap(),
    );

    let seen = chunks.lock().unwrap();
    assert_eq!(seen.len(), 1, "inspector should see one chunk");
    assert_eq!(
        seen[0],
        Bytes::from_static(b"HELLO"),
        "inspector should see uppercased body from preceding filter"
    );
}

#[tokio::test]
async fn release_from_first_filter_still_delivers_to_all() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(StreamBufferReleaseFilter { marker: b"GO" }),
        Box::new(BodyInspectorFilter {
            chunks: Arc::clone(&chunks),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"GO"));
    let action = pipeline
        .execute_http_request_body(&mut ctx, &mut body, false)
        .await
        .unwrap();

    assert!(matches!(action, FilterAction::Release), "should propagate Release");
    let seen = chunks.lock().unwrap();
    assert_eq!(seen.len(), 1, "inspector should still see the chunk after Release");
    assert_eq!(
        seen[0],
        Bytes::from_static(b"GO"),
        "inspector should see correct content"
    );
}

#[tokio::test]
async fn filter_takes_body_next_sees_none() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::<Option<Bytes>>::new()));
    let pipeline = make_pipeline(vec![
        Box::new(BodyTakeFilter),
        Box::new(NullableBodyInspectorFilter {
            chunks: Arc::clone(&chunks),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"disappear"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body, false)
            .await
            .unwrap(),
    );

    let seen = chunks.lock().unwrap();
    assert_eq!(seen.len(), 1, "nullable inspector should be called once");
    assert!(seen[0].is_none(), "inspector should see None after take()");
}

#[tokio::test]
async fn single_chunk_eos() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(BodyInspectorFilter {
        chunks: Arc::clone(&chunks),
    })]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"only"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body, true)
            .await
            .unwrap(),
    );

    let seen = chunks.lock().unwrap();
    assert_eq!(seen.len(), 1, "inspector should record exactly one call");
    assert_eq!(
        seen[0],
        Bytes::from_static(b"only"),
        "single EOS chunk should contain full body"
    );
}

#[tokio::test]
async fn empty_body_eos() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::<Option<Bytes>>::new()));
    let pipeline = make_pipeline(vec![Box::new(NullableBodyInspectorFilter {
        chunks: Arc::clone(&chunks),
    })]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body: Option<Bytes> = None;
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body, true)
            .await
            .unwrap(),
    );

    let seen = chunks.lock().unwrap();
    assert_eq!(seen.len(), 1, "nullable inspector should be called even with None body");
    assert!(seen[0].is_none(), "recorded body should be None");
}

#[tokio::test]
async fn body_done_skips_filter_on_subsequent_chunks() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(BodyDoneAfterFirstFilter {
            chunks: Arc::clone(&chunks),
        }),
        Box::new(BodyInspectorFilter {
            chunks: Arc::new(std::sync::Mutex::new(Vec::new())),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body1 = Some(Bytes::from_static(b"first"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body1, false)
            .await
            .unwrap(),
    );

    let mut body2 = Some(Bytes::from_static(b"second"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body2, false)
            .await
            .unwrap(),
    );

    let mut body3 = Some(Bytes::from_static(b"third"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body3, true)
            .await
            .unwrap(),
    );

    let seen = chunks.lock().unwrap();
    assert_eq!(seen.len(), 1, "BodyDone filter should only see the first chunk");
    assert_eq!(
        seen[0],
        Bytes::from_static(b"first"),
        "BodyDone filter should have recorded the first chunk"
    );
}

#[tokio::test]
async fn body_done_other_filters_continue() {
    let done_chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let inspector_chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(BodyDoneAfterFirstFilter {
            chunks: Arc::clone(&done_chunks),
        }),
        Box::new(BodyInspectorFilter {
            chunks: Arc::clone(&inspector_chunks),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body1 = Some(Bytes::from_static(b"chunk1"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body1, false)
            .await
            .unwrap(),
    );
    let mut body2 = Some(Bytes::from_static(b"chunk2"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body2, true)
            .await
            .unwrap(),
    );

    assert_eq!(
        done_chunks.lock().unwrap().len(),
        1,
        "BodyDone filter should see only the first chunk"
    );
    assert_eq!(
        inspector_chunks.lock().unwrap().len(),
        2,
        "inspector filter should see all chunks despite first filter's BodyDone"
    );
}

#[tokio::test]
async fn body_done_does_not_trigger_release() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(BodyDoneAfterFirstFilter {
        chunks: Arc::clone(&chunks),
    })]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"data"));
    let action = pipeline
        .execute_http_request_body(&mut ctx, &mut body, false)
        .await
        .unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "BodyDone should not cause the pipeline to return Release"
    );
}

#[tokio::test]
async fn multiple_filters_independently_signal_body_done() {
    let chunks_a = Arc::new(std::sync::Mutex::new(Vec::new()));
    let chunks_b = Arc::new(std::sync::Mutex::new(Vec::new()));
    let inspector_chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(BodyDoneAfterFirstFilter {
            chunks: Arc::clone(&chunks_a),
        }),
        Box::new(BodyInspectorFilter {
            chunks: Arc::clone(&inspector_chunks),
        }),
        Box::new(BodyDoneAfterFirstFilter {
            chunks: Arc::clone(&chunks_b),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body1 = Some(Bytes::from_static(b"one"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body1, false)
            .await
            .unwrap(),
    );
    let mut body2 = Some(Bytes::from_static(b"two"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body2, false)
            .await
            .unwrap(),
    );
    let mut body3 = Some(Bytes::from_static(b"three"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body3, true)
            .await
            .unwrap(),
    );

    assert_eq!(
        chunks_a.lock().unwrap().len(),
        1,
        "first BodyDone filter should see only one chunk"
    );
    assert_eq!(
        chunks_b.lock().unwrap().len(),
        1,
        "third BodyDone filter should see only one chunk"
    );
    assert_eq!(
        inspector_chunks.lock().unwrap().len(),
        3,
        "middle inspector should see all three chunks"
    );
}

#[test]
fn body_done_response_body_skips_filter_on_subsequent_chunks() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(ResponseBodyDoneAfterFirstFilter {
        chunks: Arc::clone(&chunks),
    })]);
    let req = crate::test_utils::make_request(Method::GET, "/data");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body1 = Some(Bytes::from_static(b"resp1"));
    drop(
        pipeline
            .execute_http_response_body(&mut ctx, &mut body1, false)
            .unwrap(),
    );

    let mut body2 = Some(Bytes::from_static(b"resp2"));
    drop(pipeline.execute_http_response_body(&mut ctx, &mut body2, true).unwrap());

    let seen = chunks.lock().unwrap();
    assert_eq!(
        seen.len(),
        1,
        "response BodyDone filter should only see the first chunk"
    );
}

#[tokio::test]
async fn request_body_done_does_not_suppress_response_body() {
    let responses = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(RequestBodyDoneWithResponseFilter {
        responses: Arc::clone(&responses),
    })]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());
    let mut req_body = Some(Bytes::from_static(b"req"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut req_body, true)
            .await
            .unwrap(),
    );

    drop(pipeline.execute_http_response(&mut ctx).await.unwrap());

    let mut resp_body = Some(Bytes::from_static(b"resp"));
    drop(
        pipeline
            .execute_http_response_body(&mut ctx, &mut resp_body, true)
            .unwrap(),
    );

    assert_eq!(
        responses.lock().unwrap().clone(),
        vec!["dual_body"],
        "a request-body BodyDone must not suppress the response-body hook"
    );
}

#[tokio::test]
async fn body_done_with_stream_buffer_mode() {
    let done_chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let inspector_chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(StreamBufferBodyDoneFilter {
            chunks: Arc::clone(&done_chunks),
        }),
        Box::new(BodyInspectorFilter {
            chunks: Arc::clone(&inspector_chunks),
        }),
    ]);

    assert_eq!(
        pipeline.body_capabilities().request_body_mode,
        BodyMode::StreamBuffer { max_bytes: None },
        "pipeline should use StreamBuffer mode from first filter"
    );

    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body1 = Some(Bytes::from_static(b"chunk1"));
    let action1 = pipeline
        .execute_http_request_body(&mut ctx, &mut body1, false)
        .await
        .unwrap();
    assert!(
        matches!(action1, FilterAction::Continue),
        "BodyDone from StreamBuffer filter should not cause Release"
    );

    let mut body2 = Some(Bytes::from_static(b"chunk2"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body2, false)
            .await
            .unwrap(),
    );

    let mut body3 = Some(Bytes::from_static(b"chunk3"));
    drop(
        pipeline
            .execute_http_request_body(&mut ctx, &mut body3, true)
            .await
            .unwrap(),
    );

    let done_seen = done_chunks.lock().unwrap();
    assert_eq!(
        done_seen.len(),
        1,
        "StreamBuffer+BodyDone filter should only see the first chunk"
    );
    assert_eq!(
        done_seen[0],
        Bytes::from_static(b"chunk1"),
        "StreamBuffer+BodyDone filter should have recorded the first chunk"
    );

    let inspector_seen = inspector_chunks.lock().unwrap();
    assert_eq!(
        inspector_seen.len(),
        3,
        "inspector should see all three chunks despite first filter's BodyDone"
    );
}

// -----------------------------------------------------------------------------
// Referenced files
// -----------------------------------------------------------------------------

#[test]
fn referenced_files_empty_for_pipeline_with_no_filters() {
    let pipeline = make_pipeline(vec![]);
    assert!(
        pipeline.referenced_files().is_empty(),
        "a pipeline with no filters declares nothing"
    );
}

#[test]
fn referenced_files_collects_from_every_declaring_filter() {
    let pipeline = make_pipeline(vec![
        Box::new(ReferencingFilter::new(&["/etc/praxis/a.yaml"])),
        Box::new(ReferencingFilter::new(&["/etc/praxis/b.yaml"])),
    ]);
    assert_eq!(
        pipeline.referenced_files(),
        vec![
            std::path::PathBuf::from("/etc/praxis/a.yaml"),
            std::path::PathBuf::from("/etc/praxis/b.yaml"),
        ],
        "both filters' documents must be collected"
    );
}

#[test]
fn referenced_files_skips_filters_that_declare_nothing() {
    let pipeline = make_pipeline(vec![
        Box::new(PassthroughFilter),
        Box::new(ReferencingFilter::new(&["/etc/praxis/only.yaml"])),
        Box::new(PassthroughFilter),
    ]);
    assert_eq!(
        pipeline.referenced_files(),
        vec![std::path::PathBuf::from("/etc/praxis/only.yaml")],
        "only the declaring filter contributes"
    );
}

#[test]
fn referenced_files_keeps_duplicates_for_the_caller_to_dedupe() {
    let shared = "/etc/praxis/shared.yaml";
    let pipeline = make_pipeline(vec![
        Box::new(ReferencingFilter::new(&[shared])),
        Box::new(ReferencingFilter::new(&[shared])),
    ]);
    assert_eq!(
        pipeline.referenced_files().len(),
        2,
        "the pipeline reports what its filters declared, without deduping"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a [`FilterEntry`] carrying one branch chain named `branch_name`
/// whose inline sub-chain holds `inner`.
///
/// Goes through the same `branch_chains` -> [`ResolvedBranch`] resolution the
/// server uses, so the branch filter's `conditions` and `failure_mode` are
/// carried by [`build_filters`], not injected by the test.
///
/// [`build_filters`]: super::build_branch
fn host_entry_with_branch(branch_name: &str, on_result: Option<&str>, inner: Vec<FilterEntry>) -> FilterEntry {
    FilterEntry {
        branch_chains: Some(vec![BranchChainConfig {
            name: branch_name.to_owned(),
            chains: vec![ChainRef::Inline {
                name: format!("{branch_name}_chain"),
                filters: inner,
            }],
            max_iterations: None,
            on_result: on_result.map(|value| praxis_core::config::BranchCondition {
                filter: "headers".to_owned(),
                key: "status".to_owned(),
                value: value.to_owned(),
            }),
            rejoin: "next".to_owned(),
        }]),
        conditions: vec![],
        filter_type: "headers".into(),
        config: serde_yaml::from_str("request_add:\n  - name: X-Host\n    value: \"1\"").unwrap(),
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }
}

/// Build an `ip_acl` [`FilterEntry`] with the given conditions and failure mode.
fn ip_acl_entry(conditions: Vec<praxis_core::config::Condition>, failure_mode: FailureMode) -> FilterEntry {
    FilterEntry {
        branch_chains: None,
        conditions,
        filter_type: "ip_acl".into(),
        config: serde_yaml::from_str("allow: [\"10.0.0.0/8\"]").unwrap(),
        name: None,
        response_conditions: vec![],
        failure_mode,
    }
}

/// Build a pipeline whose single unconditional host filter carries one
/// unconditional Next-rejoin branch holding `branch_filters`.
fn pipeline_with_branch(branch_filters: Vec<PipelineFilter>) -> FilterPipeline {
    let mut parent = PipelineFilter::new(
        0,
        AnyFilter::Http(Box::new(CountingFilter {
            counter: Arc::new(AtomicUsize::new(0)),
        })),
        vec![],
        vec![],
    );
    parent.branches = vec![ResolvedBranch {
        condition: None,
        filters: branch_filters,
        max_iterations: None,
        name: Arc::from("br"),
        rejoin: RejoinTarget::Next,
    }];
    test_pipeline(BodyCapabilities::default(), vec![parent])
}

/// A filter that reads config from external documents.
struct ReferencingFilter {
    referenced_files: Vec<std::path::PathBuf>,
}

impl ReferencingFilter {
    fn new(paths: &[&str]) -> Self {
        Self {
            referenced_files: paths.iter().map(std::path::PathBuf::from).collect(),
        }
    }
}

#[async_trait]
impl HttpFilter for ReferencingFilter {
    fn name(&self) -> &'static str {
        "referencing"
    }

    fn referenced_files(&self) -> Vec<std::path::PathBuf> {
        self.referenced_files.clone()
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

/// A filter that does nothing and declares no external config.
struct PassthroughFilter;

#[async_trait]
impl HttpFilter for PassthroughFilter {
    fn name(&self) -> &'static str {
        "passthrough"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

/// Noop whose [`HttpFilter::name`] matches the registered type name.
struct NamedNoopFilter(&'static str);

#[async_trait]
impl HttpFilter for NamedNoopFilter {
    fn name(&self) -> &'static str {
        self.0
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

/// A filter that immediately rejects all requests.
struct RejectFilter;

#[async_trait]
impl HttpFilter for RejectFilter {
    fn name(&self) -> &'static str {
        "reject"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Reject(crate::Rejection::status(403)))
    }
}

/// A filter that sets `ctx.cluster` to a fixed name.
struct ClusterSelectFilter(&'static str);

#[async_trait]
impl HttpFilter for ClusterSelectFilter {
    fn name(&self) -> &'static str {
        "cluster_select"
    }

    async fn on_request(&self, ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        ctx.cluster = Some(Arc::from(self.0));
        Ok(FilterAction::Continue)
    }
}

/// A filter that increments a shared counter on each hook call.
struct CountingFilter {
    counter: Arc<AtomicUsize>,
}

#[async_trait]
impl HttpFilter for CountingFilter {
    fn name(&self) -> &'static str {
        "counting"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(FilterAction::Continue)
    }
}

/// A filter that appends its name to a shared log during `on_response`.
struct LoggingFilter {
    label: &'static str,
    log: Arc<std::sync::Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl HttpFilter for LoggingFilter {
    fn name(&self) -> &'static str {
        self.label
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.log.lock().unwrap().push(self.label);
        Ok(FilterAction::Continue)
    }
}

/// A filter that records which body hooks it was handed.
struct BodyLoggingFilter {
    label: &'static str,
    log: Arc<std::sync::Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl HttpFilter for BodyLoggingFilter {
    fn name(&self) -> &'static str {
        self.label
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        self.log.lock().unwrap().push(self.label);
        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        self.log.lock().unwrap().push(self.label);
        Ok(FilterAction::Continue)
    }
}

/// Continues on the first `on_request`, rejects on every later call.
struct RejectOnSecondCallFilter {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl HttpFilter for RejectOnSecondCallFilter {
    fn name(&self) -> &'static str {
        "reject_on_second"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) >= 1 {
            Ok(FilterAction::Reject(crate::Rejection::status(403)))
        } else {
            Ok(FilterAction::Continue)
        }
    }
}

/// Finishes the request body (`BodyDone`) but records each response-body call.
struct RequestBodyDoneWithResponseFilter {
    responses: Arc<std::sync::Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl HttpFilter for RequestBodyDoneWithResponseFilter {
    fn name(&self) -> &'static str {
        "dual_body"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::BodyDone)
    }

    fn on_response_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        self.responses.lock().unwrap().push("dual_body");
        Ok(FilterAction::Continue)
    }
}

/// A filter that always returns an error.
struct ErrorFilter;

#[async_trait]
impl HttpFilter for ErrorFilter {
    fn name(&self) -> &'static str {
        "error"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Err("injected error".into())
    }
}

/// A filter that records body chunks it sees (read-only).
struct BodyInspectorFilter {
    chunks: Arc<std::sync::Mutex<Vec<Bytes>>>,
}

#[async_trait]
impl HttpFilter for BodyInspectorFilter {
    fn name(&self) -> &'static str {
        "body_inspector"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body {
            self.chunks.lock().unwrap().push(b.clone());
        }

        Ok(FilterAction::Continue)
    }
}

/// A filter that uppercases request body chunks (read-write).
struct BodyUppercaseFilter;

#[async_trait]
impl HttpFilter for BodyUppercaseFilter {
    fn name(&self) -> &'static str {
        "body_uppercase"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body {
            let upper: Vec<u8> = b.iter().map(|c| c.to_ascii_uppercase()).collect();
            *b = Bytes::from(upper);
        }

        Ok(FilterAction::Continue)
    }
}

/// A filter that rejects if the body contains a forbidden byte sequence.
struct BodyRejectFilter;

#[async_trait]
impl HttpFilter for BodyRejectFilter {
    fn name(&self) -> &'static str {
        "body_reject"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body
            && b.windows(6).any(|w| w == b"REJECT")
        {
            return Ok(FilterAction::Reject(crate::Rejection::status(400)));
        }

        Ok(FilterAction::Continue)
    }
}

/// A selected-upstream request-body filter that records the buffered body
/// and its label (read-only), for order and canonical-body assertions.
struct SelectedUpstreamRecorderFilter {
    label: &'static str,
    log: Arc<std::sync::Mutex<Vec<&'static str>>>,
    bodies: Arc<std::sync::Mutex<Vec<Option<Bytes>>>>,
}

#[async_trait]
impl HttpFilter for SelectedUpstreamRecorderFilter {
    fn name(&self) -> &'static str {
        self.label
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<crate::SelectedUpstreamBodyOutcome, FilterError> {
        self.log.lock().unwrap().push(self.label);
        self.bodies.lock().unwrap().push(body.clone());
        Ok(crate::SelectedUpstreamBodyOutcome::Continue)
    }
}

/// A selected-upstream request-body filter that uppercases the buffered
/// body in place (read-write).
struct SelectedUpstreamRewriteFilter;

#[async_trait]
impl HttpFilter for SelectedUpstreamRewriteFilter {
    fn name(&self) -> &'static str {
        "selected_upstream_rewrite"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<crate::SelectedUpstreamBodyOutcome, FilterError> {
        if let Some(b) = body {
            let upper: Vec<u8> = b.iter().map(|c| c.to_ascii_uppercase()).collect();
            *b = Bytes::from(upper);
        }
        Ok(crate::SelectedUpstreamBodyOutcome::Continue)
    }
}

/// A selected-upstream body filter that appends `|tamper` whatever access it
/// declared, then continues or errors.
struct SelectedUpstreamTamperFilter {
    access: BodyAccess,
    error: bool,
}

#[async_trait]
impl HttpFilter for SelectedUpstreamTamperFilter {
    fn name(&self) -> &'static str {
        "selected_upstream_tamper"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        self.access
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<crate::SelectedUpstreamBodyOutcome, FilterError> {
        let mut output = body.as_ref().map_or_else(Vec::new, |bytes| bytes.to_vec());
        output.extend_from_slice(b"|tamper");
        *body = Some(Bytes::from(output));
        if self.error {
            return Err(FilterError::from("tamper boom"));
        }
        Ok(crate::SelectedUpstreamBodyOutcome::Continue)
    }
}

/// A selected-upstream request-body filter that always rejects with 413.
struct SelectedUpstreamRejectFilter;

#[async_trait]
impl HttpFilter for SelectedUpstreamRejectFilter {
    fn name(&self) -> &'static str {
        "selected_upstream_reject"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
    ) -> Result<crate::SelectedUpstreamBodyOutcome, FilterError> {
        Ok(crate::SelectedUpstreamBodyOutcome::Reject(crate::Rejection::status(
            413,
        )))
    }
}

/// A filter that records response body chunks (read-only).
struct ResponseBodyInspectorFilter {
    chunks: Arc<std::sync::Mutex<Vec<Bytes>>>,
}

#[async_trait]
impl HttpFilter for ResponseBodyInspectorFilter {
    fn name(&self) -> &'static str {
        "resp_body_inspector"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn on_response_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body {
            self.chunks.lock().unwrap().push(b.clone());
        }

        Ok(FilterAction::Continue)
    }
}

/// A filter that declares StreamBuffer mode and returns Release
/// after seeing a marker in the body.
struct StreamBufferReleaseFilter {
    marker: &'static [u8],
}

#[async_trait]
impl HttpFilter for StreamBufferReleaseFilter {
    fn name(&self) -> &'static str {
        "stream_buffer_release"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: None }
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body
            && b.windows(self.marker.len()).any(|w| w == self.marker)
        {
            return Ok(FilterAction::Release);
        }
        Ok(FilterAction::Continue)
    }
}

/// A filter that declares StreamBuffer mode with a finite byte limit.
struct BoundedStreamBufferFilter {
    max_bytes: usize,
}

#[async_trait]
impl HttpFilter for BoundedStreamBufferFilter {
    fn name(&self) -> &'static str {
        "bounded_stream_buffer"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.max_bytes),
        }
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

/// A filter that removes one header and adds another (net count stays the same).
struct SwapHeaderFilter;

#[async_trait]
impl HttpFilter for SwapHeaderFilter {
    fn name(&self) -> &'static str {
        "swap_header"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if let Some(resp) = ctx.response_header.as_mut() {
            resp.headers.remove("x-old");
            resp.headers.insert("x-new", "value".parse().unwrap());
        }
        Ok(FilterAction::Continue)
    }
}

/// A filter that calls `body.take()`, consuming the body.
struct BodyTakeFilter;

#[async_trait]
impl HttpFilter for BodyTakeFilter {
    fn name(&self) -> &'static str {
        "body_take"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        body.take();
        Ok(FilterAction::Continue)
    }
}

/// A filter that records body presence (including None) for each call.
struct NullableBodyInspectorFilter {
    /// Each entry is the body snapshot: `Some(bytes)` or `None`.
    chunks: Arc<std::sync::Mutex<Vec<Option<Bytes>>>>,
}

#[async_trait]
impl HttpFilter for NullableBodyInspectorFilter {
    fn name(&self) -> &'static str {
        "nullable_body_inspector"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        self.chunks.lock().unwrap().push(body.clone());
        Ok(FilterAction::Continue)
    }
}

/// A filter that returns `BodyDone` after recording the first chunk.
struct BodyDoneAfterFirstFilter {
    chunks: Arc<std::sync::Mutex<Vec<Bytes>>>,
}

#[async_trait]
impl HttpFilter for BodyDoneAfterFirstFilter {
    fn name(&self) -> &'static str {
        "body_done_after_first"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body {
            self.chunks.lock().unwrap().push(b.clone());
        }
        Ok(FilterAction::BodyDone)
    }
}

/// A response body filter that returns `BodyDone` after recording the first chunk.
struct ResponseBodyDoneAfterFirstFilter {
    chunks: Arc<std::sync::Mutex<Vec<Bytes>>>,
}

#[async_trait]
impl HttpFilter for ResponseBodyDoneAfterFirstFilter {
    fn name(&self) -> &'static str {
        "resp_body_done_after_first"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn on_response_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body {
            self.chunks.lock().unwrap().push(b.clone());
        }
        Ok(FilterAction::BodyDone)
    }
}

/// A filter that uses StreamBuffer mode and returns BodyDone after the first chunk.
struct StreamBufferBodyDoneFilter {
    chunks: Arc<std::sync::Mutex<Vec<Bytes>>>,
}

#[async_trait]
impl HttpFilter for StreamBufferBodyDoneFilter {
    fn name(&self) -> &'static str {
        "stream_buffer_body_done"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: None }
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body {
            self.chunks.lock().unwrap().push(b.clone());
        }
        Ok(FilterAction::BodyDone)
    }
}

/// Recompute the precomputed body-filter index lists for a hand-built
/// pipeline literal, mirroring what [`FilterPipeline::build`] does.
fn with_body_indices(mut pipeline: FilterPipeline) -> FilterPipeline {
    let (request, response) = super::body::body_filter_indices(&pipeline.filters);
    pipeline.request_body_filter_indices = request;
    pipeline.response_body_filter_indices = response;
    pipeline.selected_upstream_request_body_filter_indices =
        super::body::selected_upstream_request_body_indices(&pipeline.filters);
    #[cfg(feature = "bound-upstream-request-body")]
    {
        pipeline.bound_upstream_request_body_filter_indices =
            super::body::bound_upstream_request_body_indices(&pipeline.filters);
    }
    pipeline
}

/// Build a [`FilterPipeline`] from pre-built [`PipelineFilter`]s and
/// explicit body capabilities (defaults everywhere else).
fn test_pipeline(body_capabilities: BodyCapabilities, filters: Vec<PipelineFilter>) -> FilterPipeline {
    with_body_indices(FilterPipeline {
        body_capabilities,
        compression: None,
        filters,
        record_filter_duration_metrics: false,
        route_templates: Arc::default(),
        health_registry: None,
        id_generator: Arc::new(praxis_core::id::IdGenerator::with_seed(0)),
        kv_stores: None,
        session_stores: None,
        subrequest_client: None,
        may_select_streaming_subrequest_response: false,
        trace_context_filter_indices: Vec::new(),
        pipeline_extensions: Vec::new(),
        time_source: Arc::new(praxis_core::time::SystemTimeSource),
        request_body_ceiling: None,
        response_body_ceiling: None,
        request_body_filter_indices: Vec::new(),
        response_body_filter_indices: Vec::new(),
        selected_upstream_request_body_filter_indices: Vec::new(),
        #[cfg(feature = "bound-upstream-request-body")]
        bound_upstream_request_body_filter_indices: Vec::new(),
        allow_private_upstreams: false,
        response_trailer_filter_indices: Vec::new(),
    })
}

// -----------------------------------------------------------------------------
// Body-Phase Condition Tests
// -----------------------------------------------------------------------------

/// A StreamBuffer body filter that promotes a header from its body hook,
/// mirroring `json_body_field` (grouped queue) promotion during pre-read.
struct PromoterBodyFilter {
    name: &'static str,
    header: &'static str,
    value: &'static str,
    /// `true` promotes via `request_headers_to_set` (Set); `false` via
    /// `extra_request_headers` (Add).
    via_set: bool,
}

#[async_trait]
impl HttpFilter for PromoterBodyFilter {
    fn name(&self) -> &'static str {
        self.name
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(65_536),
        }
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if self.via_set {
            ctx.request_headers_to_set.push((
                ::http::header::HeaderName::from_bytes(self.header.as_bytes()).unwrap(),
                ::http::header::HeaderValue::from_str(self.value).unwrap(),
            ));
        } else {
            ctx.extra_request_headers
                .push((std::borrow::Cow::Borrowed(self.header), self.value.to_owned()));
        }
        Ok(FilterAction::BodyDone)
    }
}

/// A StreamBuffer body filter that records whether its body hook ran.
struct GatedRecordingBodyFilter {
    ran: Arc<AtomicBool>,
}

#[async_trait]
impl HttpFilter for GatedRecordingBodyFilter {
    fn name(&self) -> &'static str {
        "gated_recorder"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(65_536),
        }
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        self.ran.store(true, Ordering::SeqCst);
        Ok(FilterAction::Continue)
    }
}

/// Build a single `when: headers: {header: value}` request condition.
fn gate_condition(header: &str, value: &str) -> Vec<praxis_core::config::Condition> {
    let mut headers = HashMap::new();
    headers.insert(header.to_owned(), value.to_owned());
    vec![praxis_core::config::Condition::When(
        praxis_core::config::ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: None,
            methods: None,
            headers: Some(headers),
            bound_upstream: None,
            selected_upstream: None,
        },
    )]
}

#[tokio::test]
async fn body_condition_single_pass_sees_promoted_header() {
    let ran = Arc::new(AtomicBool::new(false));
    let pipeline = make_pipeline_with_conditions(vec![
        (
            Box::new(PromoterBodyFilter {
                name: "promoter",
                header: "x-gate",
                value: "on",
                via_set: false,
            }),
            vec![],
        ),
        (
            Box::new(GatedRecordingBodyFilter { ran: Arc::clone(&ran) }),
            gate_condition("x-gate", "on"),
        ),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"{}"));
    let _outcome = pipeline
        .execute_http_request_body(&mut ctx, &mut body, true)
        .await
        .unwrap();
    assert!(
        ran.load(Ordering::SeqCst),
        "gated body filter should run when a promoter set the gate header this pass"
    );
}

#[tokio::test]
async fn body_condition_set_queue_promoter_gates() {
    let ran = Arc::new(AtomicBool::new(false));
    let pipeline = make_pipeline_with_conditions(vec![
        (
            Box::new(PromoterBodyFilter {
                name: "promoter",
                header: "x-gate",
                value: "on",
                via_set: true,
            }),
            vec![],
        ),
        (
            Box::new(GatedRecordingBodyFilter { ran: Arc::clone(&ran) }),
            gate_condition("x-gate", "on"),
        ),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"{}"));
    let _outcome = pipeline
        .execute_http_request_body(&mut ctx, &mut body, true)
        .await
        .unwrap();
    assert!(
        ran.load(Ordering::SeqCst),
        "gated body filter should run when a promoter Set the gate header this pass"
    );
}

#[tokio::test]
async fn body_condition_prior_pass_promotion_visible() {
    let ran = Arc::new(AtomicBool::new(false));
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(GatedRecordingBodyFilter { ran: Arc::clone(&ran) }),
        gate_condition("x-gate", "on"),
    )]);
    let req = crate::test_utils::make_request(Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.prior_pre_read_mutations.push(crate::TrustedHeaderMutation::Add(
        "x-gate".parse().unwrap(),
        "on".to_owned(),
    ));
    let mut body = Some(Bytes::from_static(b"{}"));
    let _outcome = pipeline
        .execute_http_request_body(&mut ctx, &mut body, true)
        .await
        .unwrap();
    assert!(
        ran.load(Ordering::SeqCst),
        "gated body filter should run when the gate header was promoted on a prior pass"
    );
}

#[tokio::test]
async fn body_condition_without_promotion_skips_gated() {
    let ran = Arc::new(AtomicBool::new(false));
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(GatedRecordingBodyFilter { ran: Arc::clone(&ran) }),
        gate_condition("x-gate", "on"),
    )]);
    let req = crate::test_utils::make_request(Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"{}"));
    let _outcome = pipeline
        .execute_http_request_body(&mut ctx, &mut body, true)
        .await
        .unwrap();
    assert!(
        !ran.load(Ordering::SeqCst),
        "gated body filter should be skipped when nothing promoted the gate header"
    );
}

#[tokio::test]
async fn body_condition_promoter_after_gated_skips() {
    let ran = Arc::new(AtomicBool::new(false));
    let pipeline = make_pipeline_with_conditions(vec![
        (
            Box::new(GatedRecordingBodyFilter { ran: Arc::clone(&ran) }),
            gate_condition("x-gate", "on"),
        ),
        (
            Box::new(PromoterBodyFilter {
                name: "promoter",
                header: "x-gate",
                value: "on",
                via_set: false,
            }),
            vec![],
        ),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"{}"));
    let _outcome = pipeline
        .execute_http_request_body(&mut ctx, &mut body, true)
        .await
        .unwrap();
    assert!(
        !ran.load(Ordering::SeqCst),
        "gated body filter should be skipped when the promoter is ordered after it"
    );
}

#[tokio::test]
async fn body_condition_conflicting_promoters_error() {
    let ran = Arc::new(AtomicBool::new(false));
    let pipeline = make_pipeline_with_conditions(vec![
        (
            Box::new(PromoterBodyFilter {
                name: "promoter_a",
                header: "x-gate",
                value: "on",
                via_set: false,
            }),
            vec![],
        ),
        (
            Box::new(PromoterBodyFilter {
                name: "promoter_b",
                header: "x-gate",
                value: "off",
                via_set: false,
            }),
            vec![],
        ),
        (
            Box::new(GatedRecordingBodyFilter { ran: Arc::clone(&ran) }),
            gate_condition("x-gate", "on"),
        ),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"{}"));
    let result = pipeline.execute_http_request_body(&mut ctx, &mut body, true).await;
    assert!(
        result.is_err(),
        "two promoters writing different values to the gate header should fail closed"
    );
}

/// Build a [`FilterPipeline`] from the given HTTP filters (no conditions).
fn make_pipeline(filters: Vec<Box<dyn HttpFilter>>) -> FilterPipeline {
    let filters: Vec<_> = filters
        .into_iter()
        .enumerate()
        .map(|(i, f)| PipelineFilter::new(i, AnyFilter::Http(f), vec![], vec![]))
        .collect();
    let body_capabilities = compute_body_capabilities(&filters);

    with_body_indices(FilterPipeline {
        body_capabilities,
        compression: None,
        filters,
        record_filter_duration_metrics: false,
        route_templates: Arc::default(),
        health_registry: None,
        id_generator: Arc::new(praxis_core::id::IdGenerator::with_seed(0)),
        kv_stores: None,
        session_stores: None,
        subrequest_client: None,
        may_select_streaming_subrequest_response: false,
        trace_context_filter_indices: Vec::new(),
        pipeline_extensions: Vec::new(),
        time_source: Arc::new(praxis_core::time::SystemTimeSource),
        request_body_ceiling: None,
        response_body_ceiling: None,
        request_body_filter_indices: Vec::new(),
        response_body_filter_indices: Vec::new(),
        selected_upstream_request_body_filter_indices: Vec::new(),
        #[cfg(feature = "bound-upstream-request-body")]
        bound_upstream_request_body_filter_indices: Vec::new(),
        allow_private_upstreams: false,
        response_trailer_filter_indices: Vec::new(),
    })
}

/// Build a [`FilterPipeline`] with per-filter request conditions.
fn make_pipeline_with_conditions(
    filters: Vec<(Box<dyn HttpFilter>, Vec<praxis_core::config::Condition>)>,
) -> FilterPipeline {
    let filters: Vec<_> = filters
        .into_iter()
        .enumerate()
        .map(|(i, (f, c))| PipelineFilter::new(i, AnyFilter::Http(f), c, vec![]))
        .collect();
    let body_capabilities = compute_body_capabilities(&filters);

    with_body_indices(FilterPipeline {
        body_capabilities,
        compression: None,
        filters,
        record_filter_duration_metrics: false,
        route_templates: Arc::default(),
        health_registry: None,
        id_generator: Arc::new(praxis_core::id::IdGenerator::with_seed(0)),
        kv_stores: None,
        session_stores: None,
        subrequest_client: None,
        may_select_streaming_subrequest_response: false,
        trace_context_filter_indices: Vec::new(),
        pipeline_extensions: Vec::new(),
        time_source: Arc::new(praxis_core::time::SystemTimeSource),
        request_body_ceiling: None,
        response_body_ceiling: None,
        request_body_filter_indices: Vec::new(),
        response_body_filter_indices: Vec::new(),
        selected_upstream_request_body_filter_indices: Vec::new(),
        #[cfg(feature = "bound-upstream-request-body")]
        bound_upstream_request_body_filter_indices: Vec::new(),
        allow_private_upstreams: false,
        response_trailer_filter_indices: Vec::new(),
    })
}

/// Build a [`FilterPipeline`] with per-filter response conditions.
fn make_pipeline_with_response_conditions(
    filters: Vec<(Box<dyn HttpFilter>, Vec<praxis_core::config::ResponseCondition>)>,
) -> FilterPipeline {
    let filters: Vec<_> = filters
        .into_iter()
        .enumerate()
        .map(|(i, (f, rc))| PipelineFilter::new(i, AnyFilter::Http(f), vec![], rc))
        .collect();
    let body_capabilities = compute_body_capabilities(&filters);

    with_body_indices(FilterPipeline {
        body_capabilities,
        compression: None,
        filters,
        record_filter_duration_metrics: false,
        route_templates: Arc::default(),
        health_registry: None,
        id_generator: Arc::new(praxis_core::id::IdGenerator::with_seed(0)),
        kv_stores: None,
        session_stores: None,
        subrequest_client: None,
        may_select_streaming_subrequest_response: false,
        trace_context_filter_indices: Vec::new(),
        pipeline_extensions: Vec::new(),
        time_source: Arc::new(praxis_core::time::SystemTimeSource),
        request_body_ceiling: None,
        response_body_ceiling: None,
        request_body_filter_indices: Vec::new(),
        response_body_filter_indices: Vec::new(),
        selected_upstream_request_body_filter_indices: Vec::new(),
        #[cfg(feature = "bound-upstream-request-body")]
        bound_upstream_request_body_filter_indices: Vec::new(),
        allow_private_upstreams: false,
        response_trailer_filter_indices: Vec::new(),
    })
}

/// Build a `When` condition that matches on a path prefix.
fn when_path(prefix: &str) -> praxis_core::config::Condition {
    praxis_core::config::Condition::When(praxis_core::config::ConditionMatch {
        grpc: None,
        path: None,
        path_prefix: Some(prefix.to_owned()),
        methods: None,
        headers: None,
        bound_upstream: None,
        selected_upstream: None,
    })
}

/// A `tcp_access_log` filter entry with no conditions or branches.
fn tcp_access_log_entry() -> FilterEntry {
    FilterEntry {
        branch_chains: None,
        filter_type: "tcp_access_log".into(),
        config: serde_yaml::Value::Null,
        conditions: vec![],
        response_conditions: vec![],
        name: None,
        failure_mode: FailureMode::default(),
    }
}

/// Register a noop HTTP filter whose type name is `name`.
fn register_named_filter(registry: &mut FilterRegistry, name: &'static str, class: SecurityClass) {
    let factory = FilterFactory::Http(Arc::new(move |_| Ok(Box::new(NamedNoopFilter(name)))));
    registry
        .register_with_class(name, factory, class)
        .expect("test filter name must not collide with builtins");
}

/// Build a [`FilterEntry`] for a config-less custom filter.
fn named_noop_entry(filter_type: &str, failure_mode: FailureMode) -> FilterEntry {
    FilterEntry {
        branch_chains: None,
        conditions: vec![],
        filter_type: filter_type.into(),
        config: serde_yaml::Value::Null,
        name: None,
        response_conditions: vec![],
        failure_mode,
    }
}

/// Build an `Unless` condition that matches on a path prefix.
fn unless_path(prefix: &str) -> praxis_core::config::Condition {
    praxis_core::config::Condition::Unless(praxis_core::config::ConditionMatch {
        grpc: None,
        path: None,
        path_prefix: Some(prefix.to_owned()),
        methods: None,
        headers: None,
        bound_upstream: None,
        selected_upstream: None,
    })
}

/// Build a `When` response condition that matches on status codes.
fn when_status(codes: &[u16]) -> praxis_core::config::ResponseCondition {
    praxis_core::config::ResponseCondition::When(praxis_core::config::ResponseConditionMatch {
        status: Some(codes.to_vec()),
        headers: None,
    })
}

// -----------------------------------------------------------------------------
// Filter State Lifecycle Tests
// -----------------------------------------------------------------------------

/// Tracked state that records observations and drop events.
struct TrackedState {
    id: u64,
    observations: Arc<std::sync::Mutex<Vec<(u64, &'static str)>>>,
}

impl Drop for TrackedState {
    fn drop(&mut self) {
        if let Ok(mut obs) = self.observations.lock() {
            obs.push((self.id, "drop"));
        }
    }
}

/// Test filter that stores per-request typed state and reads it in
/// every phase, recording observations for lifecycle verification.
struct StatefulFilter {
    id: u64,
    observations: Arc<std::sync::Mutex<Vec<(u64, &'static str)>>>,
}

#[async_trait]
impl HttpFilter for StatefulFilter {
    fn name(&self) -> &'static str {
        "stateful"
    }

    async fn on_request(&self, ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        ctx.insert_filter_state(TrackedState {
            id: self.id,
            observations: Arc::clone(&self.observations),
        });
        self.observations.lock().unwrap().push((self.id, "on_request"));
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let state = ctx.get_filter_state::<TrackedState>();
        assert!(state.is_some(), "state should survive into response phase");
        assert_eq!(state.unwrap().id, self.id, "state id should match filter id");
        self.observations.lock().unwrap().push((self.id, "on_response"));
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request_body(
        &self,
        ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        let state = ctx.get_filter_state::<TrackedState>();
        assert!(state.is_some(), "state should survive into request body phase");
        assert_eq!(state.unwrap().id, self.id, "state id should match filter id");
        self.observations.lock().unwrap().push((self.id, "on_request_body"));
        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        let state = ctx.get_filter_state::<TrackedState>();
        assert!(state.is_some(), "state should survive into response body phase");
        assert_eq!(state.unwrap().id, self.id, "state id should match filter id");
        self.observations.lock().unwrap().push((self.id, "on_response_body"));
        Ok(FilterAction::Continue)
    }
}

#[tokio::test]
async fn filter_state_persists_from_request_to_request_body() {
    let obs: Arc<std::sync::Mutex<Vec<(u64, &'static str)>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(StatefulFilter {
        id: 1,
        observations: Arc::clone(&obs),
    })]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let _action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    let mut body = Some(Bytes::from_static(b"hello"));
    let _action = pipeline
        .execute_http_request_body(&mut ctx, &mut body, true)
        .await
        .unwrap();
    let recorded = obs.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec![(1, "on_request"), (1, "on_request_body")],
        "state should persist from request to request body"
    );
}

#[tokio::test]
async fn filter_state_persists_from_request_to_response() {
    let obs: Arc<std::sync::Mutex<Vec<(u64, &'static str)>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(StatefulFilter {
        id: 2,
        observations: Arc::clone(&obs),
    })]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let _action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    let _action = pipeline.execute_http_response(&mut ctx).await.unwrap();
    let recorded = obs.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec![(2, "on_request"), (2, "on_response")],
        "state should persist from request to response"
    );
}

#[tokio::test]
async fn two_same_type_filters_get_independent_state() {
    let obs: Arc<std::sync::Mutex<Vec<(u64, &'static str)>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(StatefulFilter {
            id: 10,
            observations: Arc::clone(&obs),
        }),
        Box::new(StatefulFilter {
            id: 20,
            observations: Arc::clone(&obs),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let _action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    let _action = pipeline.execute_http_response(&mut ctx).await.unwrap();
    let recorded = obs.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec![
            (10, "on_request"),
            (20, "on_request"),
            (20, "on_response"),
            (10, "on_response"),
        ],
        "two instances should have independent state and both should see their own id"
    );
}

#[tokio::test]
async fn filter_state_dropped_on_request_reject() {
    let obs: Arc<std::sync::Mutex<Vec<(u64, &'static str)>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(StatefulFilter {
            id: 30,
            observations: Arc::clone(&obs),
        }),
        Box::new(RejectFilter),
    ]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Reject(_)), "pipeline should reject");
    drop(ctx);
    let recorded = obs.lock().unwrap().clone();
    assert!(
        recorded.contains(&(30, "on_request")),
        "state should have been inserted"
    );
    assert!(
        recorded.contains(&(30, "drop")),
        "state should be dropped when context is dropped"
    );
}

#[tokio::test]
async fn filter_state_dropped_on_body_reject() {
    let obs: Arc<std::sync::Mutex<Vec<(u64, &'static str)>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(StatefulFilter {
            id: 40,
            observations: Arc::clone(&obs),
        }),
        Box::new(BodyRejectFilter),
    ]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let _action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    let mut body = Some(Bytes::from_static(b"REJECT"));
    let action = pipeline
        .execute_http_request_body(&mut ctx, &mut body, true)
        .await
        .unwrap();
    assert!(matches!(action, FilterAction::Reject(_)), "body filter should reject");
    drop(ctx);
    let recorded = obs.lock().unwrap().clone();
    assert!(
        recorded.contains(&(40, "on_request")),
        "state should have been inserted"
    );
    assert!(
        recorded.contains(&(40, "on_request_body")),
        "body phase should have read state"
    );
    assert!(
        recorded.contains(&(40, "drop")),
        "state should be dropped when context is dropped"
    );
}

#[tokio::test]
async fn concurrent_requests_do_not_share_state() {
    let obs: Arc<std::sync::Mutex<Vec<(u64, &'static str)>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = Arc::new(make_pipeline(vec![Box::new(StatefulFilter {
        id: 50,
        observations: Arc::clone(&obs),
    })]));

    let pipeline1 = Arc::clone(&pipeline);
    let pipeline2 = Arc::clone(&pipeline);

    let h1 = tokio::spawn(async move {
        let req = crate::test_utils::make_request(Method::GET, "/a");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        drop(pipeline1.execute_http_request(&mut ctx).await.unwrap());
        let state = ctx
            .filter_state
            .get(&0)
            .unwrap()
            .downcast_ref::<TrackedState>()
            .unwrap();
        assert_eq!(state.id, 50, "request 1 should see filter id 50");
    });

    let h2 = tokio::spawn(async move {
        let req = crate::test_utils::make_request(Method::GET, "/b");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        drop(pipeline2.execute_http_request(&mut ctx).await.unwrap());
        let state = ctx
            .filter_state
            .get(&0)
            .unwrap()
            .downcast_ref::<TrackedState>()
            .unwrap();
        assert_eq!(state.id, 50, "request 2 should see filter id 50");
    });

    h1.await.unwrap();
    h2.await.unwrap();
}

// -----------------------------------------------------------------------------
// Identity Leak-Path Tests
// -----------------------------------------------------------------------------

/// Filter that errors on every phase.
struct AllPhaseErrorFilter;

#[async_trait]
impl HttpFilter for AllPhaseErrorFilter {
    fn name(&self) -> &'static str {
        "all_phase_error"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Err("request error".into())
    }

    async fn on_response(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Err("response error".into())
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        Err("request body error".into())
    }

    fn on_response_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        Err("response body error".into())
    }
}

#[tokio::test]
async fn identity_none_after_request_filter_skipped_by_conditions() {
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::new(AtomicUsize::new(0)),
        }),
        vec![when_path("/api")],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/other");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let _action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert!(
        ctx.current_filter_id.is_none(),
        "identity should be None after filter skipped by conditions"
    );
}

#[tokio::test]
async fn identity_none_after_request_rejection() {
    let pipeline = make_pipeline(vec![Box::new(RejectFilter)]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Reject(_)), "should reject");
    assert!(
        ctx.current_filter_id.is_none(),
        "identity should be None after rejection"
    );
}

#[tokio::test]
async fn identity_none_after_request_error_closed() {
    let pipeline = make_pipeline(vec![Box::new(AllPhaseErrorFilter)]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let result = pipeline.execute_http_request(&mut ctx).await;
    assert!(result.is_err(), "should propagate error");
    assert!(
        ctx.current_filter_id.is_none(),
        "identity should be None after request error"
    );
}

#[tokio::test]
async fn identity_none_after_response_error_closed() {
    let pipeline = make_pipeline(vec![Box::new(AllPhaseErrorFilter)]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.executed_filter_indices = vec![true];
    let result = pipeline.execute_http_response(&mut ctx).await;
    assert!(result.is_err(), "should propagate error");
    assert!(
        ctx.current_filter_id.is_none(),
        "identity should be None after response error"
    );
}

#[tokio::test]
async fn identity_none_after_request_body_error_closed() {
    let pipeline = make_pipeline(vec![Box::new(AllPhaseErrorFilter)]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"data"));
    let result = pipeline.execute_http_request_body(&mut ctx, &mut body, true).await;
    assert!(result.is_err(), "should propagate error");
    assert!(
        ctx.current_filter_id.is_none(),
        "identity should be None after request body error"
    );
}

#[test]
fn identity_none_after_response_body_error_closed() {
    let pipeline = make_pipeline(vec![Box::new(AllPhaseErrorFilter)]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.executed_filter_indices = vec![true];
    let mut body = Some(Bytes::from_static(b"data"));
    let result = pipeline.execute_http_response_body(&mut ctx, &mut body, true);
    assert!(result.is_err(), "should propagate error");
    assert!(
        ctx.current_filter_id.is_none(),
        "identity should be None after response body error"
    );
}

#[test]
fn pipeline_extension_is_injected_into_request_extensions() {
    use crate::{PipelineExtension, RequestExtensions};

    #[derive(Clone)]
    struct TestExtension(u32);

    impl PipelineExtension for TestExtension {
        fn prepare(&self, extensions: &mut RequestExtensions) {
            extensions.insert(self.clone());
        }
    }

    let mut pipeline = FilterPipeline::build(&mut [], &FilterRegistry::with_builtins()).unwrap();
    pipeline.add_pipeline_extension(Box::new(TestExtension(42)));

    let mut ext = RequestExtensions::new();
    pipeline.prepare_extensions(&mut ext);

    let val = ext.get::<TestExtension>();
    assert!(val.is_some(), "extension should be present after prepare");
    assert_eq!(val.unwrap().0, 42, "extension value should match");
}

#[test]
fn multiple_pipeline_extensions_are_all_injected() {
    use crate::{PipelineExtension, RequestExtensions};

    #[derive(Clone)]
    struct ExtA(u32);
    #[derive(Clone)]
    struct ExtB(String);

    impl PipelineExtension for ExtA {
        fn prepare(&self, extensions: &mut RequestExtensions) {
            extensions.insert(self.clone());
        }
    }

    impl PipelineExtension for ExtB {
        fn prepare(&self, extensions: &mut RequestExtensions) {
            extensions.insert(self.clone());
        }
    }

    let mut pipeline = FilterPipeline::build(&mut [], &FilterRegistry::with_builtins()).unwrap();
    pipeline.add_pipeline_extension(Box::new(ExtA(1)));
    pipeline.add_pipeline_extension(Box::new(ExtB("hello".to_owned())));

    let mut ext = RequestExtensions::new();
    pipeline.prepare_extensions(&mut ext);

    assert_eq!(ext.get::<ExtA>().unwrap().0, 1, "ExtA should be injected");
    assert_eq!(ext.get::<ExtB>().unwrap().0, "hello", "ExtB should be injected");
}

// -----------------------------------------------------------------------------
// Streaming Terminal Response Pipeline Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn streaming_terminal_response_returned_from_request_pipeline() {
    struct StreamingTerminalResponseFilter;

    #[async_trait::async_trait]
    impl HttpFilter for StreamingTerminalResponseFilter {
        fn name(&self) -> &'static str {
            "streaming_terminal_response"
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            struct NullBody;
            #[async_trait::async_trait]
            impl StreamingResponseBody for NullBody {
                async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
                    Ok(None)
                }

                async fn suppress(&mut self) -> Result<(), FilterError> {
                    Ok(())
                }

                async fn cancel(&mut self) {}
            }
            Ok(FilterAction::StreamingTerminalResponse(Box::new(
                StreamingTerminalResponse::new(200, Box::new(NullBody)),
            )))
        }
    }

    let pipeline = make_pipeline(vec![Box::new(StreamingTerminalResponseFilter)]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let result = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert!(
        matches!(result, FilterAction::StreamingTerminalResponse(_)),
        "pipeline should return StreamingTerminalResponse"
    );
}

#[tokio::test]
async fn streaming_terminal_response_marks_executed_index() {
    struct StreamingFilter;

    #[async_trait::async_trait]
    impl HttpFilter for StreamingFilter {
        fn name(&self) -> &'static str {
            "streaming_marker"
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            struct NullBody;
            #[async_trait::async_trait]
            impl StreamingResponseBody for NullBody {
                async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
                    Ok(None)
                }

                async fn suppress(&mut self) -> Result<(), FilterError> {
                    Ok(())
                }

                async fn cancel(&mut self) {}
            }
            Ok(FilterAction::StreamingTerminalResponse(Box::new(
                StreamingTerminalResponse::new(200, Box::new(NullBody)),
            )))
        }
    }

    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline(vec![
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        Box::new(StreamingFilter),
    ]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

    assert!(ctx.executed_filter_indices[0], "first filter should be marked executed");
    assert!(
        ctx.executed_filter_indices[1],
        "streaming filter should be marked executed"
    );
}

#[tokio::test]
async fn streaming_terminal_response_ignored_in_response_phase() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline(vec![Box::new(CountingFilter { counter })]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());
    let result = pipeline.execute_http_response(&mut ctx).await.unwrap();

    assert!(
        matches!(result, FilterAction::Continue),
        "response phase should continue normally"
    );
}

#[test]
fn streaming_capability_not_detected_for_normal_filter() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline(vec![Box::new(CountingFilter { counter })]);
    assert!(
        !pipeline.may_select_streaming_subrequest_response(),
        "normal filter should not declare streaming capability"
    );
}

#[test]
fn streaming_capability_detected_when_filter_declares_it() {
    let streaming_pf = super::test_filters::streaming_capable_filter();
    let pipeline = with_body_indices(FilterPipeline {
        body_capabilities: BodyCapabilities::default(),
        compression: None,
        filters: vec![streaming_pf],
        health_registry: None,
        id_generator: Arc::new(praxis_core::id::IdGenerator::new()),
        kv_stores: None,
        session_stores: None,
        pipeline_extensions: Vec::new(),
        record_filter_duration_metrics: false,
        route_templates: Arc::default(),
        subrequest_client: None,
        may_select_streaming_subrequest_response: true,
        trace_context_filter_indices: Vec::new(),
        time_source: Arc::new(praxis_core::time::SystemTimeSource),
        request_body_ceiling: None,
        response_body_ceiling: None,
        request_body_filter_indices: Vec::new(),
        response_body_filter_indices: Vec::new(),
        selected_upstream_request_body_filter_indices: Vec::new(),
        #[cfg(feature = "bound-upstream-request-body")]
        bound_upstream_request_body_filter_indices: Vec::new(),
        allow_private_upstreams: false,
        response_trailer_filter_indices: Vec::new(),
    });
    assert!(
        pipeline.may_select_streaming_subrequest_response(),
        "pipeline with streaming-capable filter should detect capability"
    );
}

#[test]
fn streaming_with_stream_buffer_is_ordering_error() {
    use praxis_core::config::SkipPipelineChecks;

    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        filter_type: "static_response".into(),
        config: serde_yaml::from_str("status: 200").unwrap(),
        conditions: vec![],
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }];
    let mut pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    pipeline.body_capabilities.response_body_mode = BodyMode::StreamBuffer { max_bytes: Some(1024) };
    pipeline.may_select_streaming_subrequest_response = true;

    let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());
    assert!(
        errors
            .iter()
            .any(|e| e.contains("streaming sub-request response") && e.contains("StreamBuffer")),
        "should detect streaming + StreamBuffer incompatibility: {errors:?}"
    );
}

// -----------------------------------------------------------------------------
// trace_context request matching
// -----------------------------------------------------------------------------

#[test]
fn trace_propagation_enabled_for_unconditional_trace_context() {
    let pipeline = FilterPipeline::from_filters(vec![super::test_filters::noop_filter("trace_context")]);
    let request = crate::test_utils::make_request(Method::GET, "/");
    assert!(pipeline.enables_trace_propagation(&request));
}

#[test]
fn trace_propagation_honors_trace_context_conditions() {
    let cond = praxis_core::config::Condition::When(praxis_core::config::ConditionMatch {
        grpc: None,
        path: None,
        path_prefix: Some("/api".to_owned()),
        methods: None,
        headers: None,
        bound_upstream: None,
        selected_upstream: None,
    });
    let pipeline = FilterPipeline::from_filters(vec![super::test_filters::noop_filter_with_conditions(
        "trace_context",
        vec![cond],
    )]);
    let matching = crate::test_utils::make_request(Method::GET, "/api/models");
    let skipped = crate::test_utils::make_request(Method::GET, "/healthz");
    assert!(pipeline.enables_trace_propagation(&matching));
    assert!(!pipeline.enables_trace_propagation(&skipped));
}

#[tokio::test]
async fn request_body_after_request_phase_does_not_start_trace_context() {
    let cond = praxis_core::config::Condition::When(praxis_core::config::ConditionMatch {
        grpc: None,
        path: None,
        path_prefix: Some("/api".to_owned()),
        methods: None,
        headers: None,
        bound_upstream: None,
        selected_upstream: None,
    });
    let pipeline = FilterPipeline::from_filters(vec![
        super::test_filters::noop_filter_with_conditions("trace_context", vec![cond]),
        PipelineFilter::new(
            1,
            AnyFilter::Http(Box::new(BodyInspectorFilter { chunks: Arc::default() })),
            vec![],
            vec![],
        ),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/api/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.executed_filter_indices = vec![false, true];

    let mut body = Some(Bytes::from_static(b"chunk"));
    let action = pipeline
        .execute_http_request_body(&mut ctx, &mut body, true)
        .await
        .unwrap();

    assert!(matches!(action, FilterAction::Continue), "the body filter continues");
    assert!(
        ctx.extensions.get::<crate::trace_context::TraceContext>().is_none(),
        "the request phase skipped trace_context, so the body phase must not start the context"
    );
}

#[tokio::test]
async fn ambiguous_pre_read_header_does_not_fail_the_request() {
    let cond = praxis_core::config::Condition::When(praxis_core::config::ConditionMatch {
        grpc: None,
        path: None,
        path_prefix: None,
        methods: None,
        headers: Some(HashMap::from([("x-tenant".to_owned(), "a".to_owned())])),
        bound_upstream: None,
        selected_upstream: None,
    });
    let pipeline = FilterPipeline::from_filters(vec![
        super::test_filters::noop_filter_with_conditions("trace_context", vec![cond]),
        PipelineFilter::new(
            1,
            AnyFilter::Http(Box::new(BodyInspectorFilter { chunks: Arc::default() })),
            vec![],
            vec![],
        ),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.extra_request_headers
        .push((std::borrow::Cow::Borrowed("x-tenant"), "a".to_owned()));
    ctx.extra_request_headers
        .push((std::borrow::Cow::Borrowed("x-tenant"), "b".to_owned()));

    let mut body = Some(Bytes::from_static(b"chunk"));
    let action = pipeline.execute_http_request_body(&mut ctx, &mut body, true).await;

    assert!(
        matches!(action, Ok(FilterAction::Continue)),
        "an ambiguous header must not fail a request over best-effort correlation"
    );
    assert!(
        ctx.extensions.get::<crate::trace_context::TraceContext>().is_none(),
        "an ambiguous header counts as no match"
    );
}

#[test]
fn trace_propagation_disabled_when_absent() {
    let pipeline = FilterPipeline::from_filters(vec![super::test_filters::noop_filter("rate_limit")]);
    let request = crate::test_utils::make_request(Method::GET, "/");
    assert!(!pipeline.enables_trace_propagation(&request));
}

// -----------------------------------------------------------------------------
// Filter Metrics Tests
// -----------------------------------------------------------------------------

mod filter_duration_metrics_tests {
    use super::*;

    fn assert_filter_metric(metrics: &str, filter: &str, phase: &str, stream: &str) {
        let filter_label = format!("filter=\"{filter}\"");
        let phase_label = format!("phase=\"{phase}\"");
        let stream_label = format!("stream=\"{stream}\"");
        assert!(
            metrics.lines().any(|line| {
                line.contains(&filter_label) && line.contains(&phase_label) && line.contains(&stream_label)
            }),
            "expected filter={filter} phase={phase} stream={stream} on one metric line: {metrics}"
        );
    }

    fn make_filter_duration_pipeline(filters: Vec<Box<dyn HttpFilter>>) -> FilterPipeline {
        let mut pipeline = make_pipeline(filters);
        pipeline.set_record_filter_duration_metrics(true);
        pipeline
    }

    fn make_filter_duration_pipeline_with_conditions(
        filters: Vec<(Box<dyn HttpFilter>, Vec<praxis_core::config::Condition>)>,
    ) -> FilterPipeline {
        let mut pipeline = make_pipeline_with_conditions(filters);
        pipeline.set_record_filter_duration_metrics(true);
        pipeline
    }

    struct GatedFilter;

    #[async_trait]
    impl HttpFilter for GatedFilter {
        fn name(&self) -> &'static str {
            "gated_filter"
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }

    /// Exercises all four HTTP filter hooks for metrics coverage.
    struct AllStreamsFilter;

    #[async_trait]
    impl HttpFilter for AllStreamsFilter {
        fn name(&self) -> &'static str {
            "all_streams"
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        async fn on_response(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        fn request_body_access(&self) -> BodyAccess {
            BodyAccess::ReadOnly
        }

        fn response_body_access(&self) -> BodyAccess {
            BodyAccess::ReadOnly
        }

        async fn on_request_body(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
            _body: &mut Option<Bytes>,
            _end_of_stream: bool,
        ) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        fn on_response_body(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
            _body: &mut Option<Bytes>,
            _end_of_stream: bool,
        ) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }

    struct DisabledOnlyFilter;

    #[async_trait]
    impl HttpFilter for DisabledOnlyFilter {
        fn name(&self) -> &'static str {
            "disabled_only"
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }

    #[tokio::test]
    async fn filter_duration_metric_emitted_on_request_headers() {
        crate::test_utils::install_metrics_recorder();

        let pipeline = make_filter_duration_pipeline(vec![Box::new(AllStreamsFilter)]);
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

        assert_filter_metric(
            &crate::test_utils::render_metrics(),
            "all_streams",
            "request",
            "headers",
        );
    }

    #[tokio::test]
    async fn filter_duration_metric_emitted_on_request_body() {
        crate::test_utils::install_metrics_recorder();

        let pipeline = make_filter_duration_pipeline(vec![Box::new(AllStreamsFilter)]);
        let req = crate::test_utils::make_request(Method::POST, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

        let mut body = Some(Bytes::from_static(b"data"));
        drop(
            pipeline
                .execute_http_request_body(&mut ctx, &mut body, true)
                .await
                .unwrap(),
        );

        assert_filter_metric(&crate::test_utils::render_metrics(), "all_streams", "request", "body");
    }

    #[tokio::test]
    async fn filter_duration_metric_emitted_on_response_headers() {
        crate::test_utils::install_metrics_recorder();

        let pipeline = make_filter_duration_pipeline(vec![Box::new(AllStreamsFilter)]);
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

        let mut resp = crate::test_utils::make_response();
        ctx.response_header = Some(&mut resp);
        drop(pipeline.execute_http_response(&mut ctx).await.unwrap());

        assert_filter_metric(
            &crate::test_utils::render_metrics(),
            "all_streams",
            "response",
            "headers",
        );
    }

    #[tokio::test]
    async fn filter_duration_metric_emitted_on_response_body() {
        crate::test_utils::install_metrics_recorder();

        let pipeline = make_filter_duration_pipeline(vec![Box::new(AllStreamsFilter)]);
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

        let mut resp = crate::test_utils::make_response();
        ctx.response_header = Some(&mut resp);

        let mut body = Some(Bytes::from_static(b"resp"));
        drop(pipeline.execute_http_response_body(&mut ctx, &mut body, true).unwrap());

        assert_filter_metric(&crate::test_utils::render_metrics(), "all_streams", "response", "body");
    }

    #[tokio::test]
    async fn filter_duration_metric_skipped_when_condition_not_met() {
        crate::test_utils::install_metrics_recorder();

        let pipeline =
            make_filter_duration_pipeline_with_conditions(vec![(Box::new(GatedFilter), vec![when_path("/api")])]);
        let req = crate::test_utils::make_request(Method::GET, "/health");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

        let metrics = crate::test_utils::render_metrics();
        assert!(
            !metrics.contains("filter=\"gated_filter\""),
            "condition-gated skip should not emit filter metric: {metrics}"
        );
    }

    #[tokio::test]
    async fn filter_duration_not_recorded_when_disabled() {
        crate::test_utils::install_metrics_recorder();

        let pipeline = make_pipeline(vec![Box::new(DisabledOnlyFilter)]);
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

        let metrics = crate::test_utils::render_metrics();
        assert!(
            !metrics.contains("filter=\"disabled_only\""),
            "disabled filter metrics should not record this filter: {metrics}"
        );
    }

    #[test]
    fn empty_pipeline_accessors_reflect_defaults() {
        let registry = FilterRegistry::with_builtins();
        let mut pipeline = FilterPipeline::build(&mut [], &registry).unwrap();

        assert!(!pipeline.needs_body_filters(), "an empty pipeline needs no body hooks");
        assert_eq!(pipeline.len(), 0, "an empty pipeline has no filters");
        assert!(
            pipeline.referenced_files().is_empty(),
            "an empty pipeline references no external files"
        );

        let generator = Arc::new(praxis_core::id::IdGenerator::with_seed(9));
        pipeline.set_id_generator(Arc::clone(&generator));
        let _id_generator = pipeline.id_generator();

        let source: Arc<dyn praxis_core::time::TimeSource> = Arc::new(praxis_core::time::SystemTimeSource);
        pipeline.set_time_source(source);
        let _time_source = pipeline.time_source();
    }
}

// -----------------------------------------------------------------------------
// Runtime Resource Propagation
// -----------------------------------------------------------------------------

// A filter that owns a nested pipeline and exposes it through
// `visit_nested_pipelines`, so recursion of runtime-resource setters can be
// observed without depending on the outbound-callout filter.
struct NestedPipelineFilter {
    nested: FilterPipeline,
}

#[async_trait]
impl HttpFilter for NestedPipelineFilter {
    fn name(&self) -> &'static str {
        "nested_pipeline_filter"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn visit_nested_pipelines(&mut self, visitor: &mut dyn FnMut(&mut FilterPipeline)) {
        visitor(&mut self.nested);
    }
}

#[test]
fn set_session_stores_propagates_into_nested_pipelines() {
    let parent_filter = NestedPipelineFilter {
        nested: make_pipeline(vec![]),
    };
    let mut parent = make_pipeline(vec![Box::new(parent_filter)]);

    parent.set_session_stores(Arc::new(crate::SessionStoreRegistry::new()));

    let mut nested_has_stores = false;
    parent.visit_nested_pipelines(&mut |pipeline| {
        nested_has_stores = pipeline.session_stores().is_some();
    });
    assert!(
        nested_has_stores,
        "set_session_stores must reach nested outbound pipelines like set_kv_stores does"
    );
}

// A terminal-filter stand-in that declares the terminal-response capability yet
// no body access. It models a terminal filter the branch body-access check would
// NOT reject (unlike the real IRR, which always declares body access), so
// terminal detection must recurse into branch sub-chains on its own to catch it.
struct TerminalDouble;

#[async_trait]
impl HttpFilter for TerminalDouble {
    fn name(&self) -> &'static str {
        "iterative_request_router"
    }

    fn produces_terminal_response(&self) -> bool {
        true
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

#[test]
fn terminal_filters_detects_filter_nested_in_branch() {
    let mut parent = make_pipeline(vec![Box::new(CountingFilter {
        counter: Arc::new(AtomicUsize::new(0)),
    })]);
    parent.filters[0].branches = vec![ResolvedBranch {
        condition: None,
        filters: vec![PipelineFilter::new(
            10,
            AnyFilter::Http(Box::new(TerminalDouble)),
            vec![],
            vec![],
        )],
        max_iterations: None,
        name: Arc::from("br"),
        rejoin: RejoinTarget::Next,
    }];

    assert!(
        parent.terminal_filters().contains(&"iterative_request_router"),
        "terminal_filters must find a terminal filter nested inside a branch sub-chain"
    );
}

#[test]
fn set_session_stores_propagates_into_branch_nested_pipelines() {
    let branch_filter = NestedPipelineFilter {
        nested: make_pipeline(vec![]),
    };
    let mut parent = make_pipeline(vec![Box::new(CountingFilter {
        counter: Arc::new(AtomicUsize::new(0)),
    })]);
    parent.filters[0].branches = vec![ResolvedBranch {
        condition: None,
        filters: vec![PipelineFilter::new(
            10,
            AnyFilter::Http(Box::new(branch_filter)),
            vec![],
            vec![],
        )],
        max_iterations: None,
        name: Arc::from("br"),
        rejoin: RejoinTarget::Next,
    }];

    parent.set_session_stores(Arc::new(crate::SessionStoreRegistry::new()));

    let mut nested_has_stores = false;
    if let AnyFilter::Http(filter) = &mut parent.filters[0].branches[0].filters[0].filter {
        filter.visit_nested_pipelines(&mut |pipeline| {
            nested_has_stores = pipeline.session_stores().is_some();
        });
    }
    assert!(
        nested_has_stores,
        "set_session_stores must reach pipelines embedded by filters inside branch sub-chains"
    );
}

// -----------------------------------------------------------------------------
// Bound-Upstream Condition
// -----------------------------------------------------------------------------

/// A filter that publishes a logical upstream binding during `on_request`,
/// mirroring what the trusted `router` does after it resolves a route.
#[cfg(feature = "upstream-binding")]
struct BindingRouterFilter {
    cluster: &'static str,
    protocol: Option<&'static str>,
    provider: Option<&'static str>,
}

#[cfg(feature = "upstream-binding")]
#[async_trait]
impl HttpFilter for BindingRouterFilter {
    fn name(&self) -> &'static str {
        "binding_router"
    }

    fn binds_upstream(&self) -> bool {
        true
    }

    async fn on_request(&self, ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if ctx
            .publish_bound_upstream(
                Arc::from(self.cluster),
                self.protocol.map(Arc::from),
                self.provider.map(Arc::from),
            )
            .is_err()
        {
            return Ok(FilterAction::Reject(crate::Rejection::status(500)));
        }
        Ok(FilterAction::Continue)
    }
}

#[cfg(feature = "upstream-binding")]
/// An unconditional `Next` branch over `filters`.
fn always_branch(filters: Vec<PipelineFilter>) -> ResolvedBranch {
    ResolvedBranch {
        condition: None,
        filters,
        max_iterations: None,
        name: Arc::from("always"),
        rejoin: RejoinTarget::Next,
    }
}

#[cfg(feature = "upstream-binding")]
/// A pipeline filter that counts its request-phase runs into `counter`.
fn counting_filter(
    filter_id: usize,
    counter: &Arc<AtomicUsize>,
    conditions: Vec<praxis_core::config::Condition>,
) -> PipelineFilter {
    PipelineFilter::new(
        filter_id,
        AnyFilter::Http(Box::new(CountingFilter {
            counter: Arc::clone(counter),
        })),
        conditions,
        vec![],
    )
}

#[cfg(feature = "upstream-binding")]
/// A request condition that matches a binding tagged with the openai provider.
fn openai_gate() -> Vec<praxis_core::config::Condition> {
    serde_yaml::from_str("- when:\n    bound_upstream:\n      application_provider: openai\n").unwrap()
}

/// Run the request phase of a pipeline that binds a cluster tagged with
/// `provider` and then runs `host`.
#[cfg(feature = "upstream-binding")]
async fn run_bound_to(provider: &'static str, host: PipelineFilter) {
    let router = PipelineFilter::new(
        0,
        AnyFilter::Http(Box::new(BindingRouterFilter {
            cluster: "inference",
            protocol: None,
            provider: Some(provider),
        })),
        vec![],
        vec![],
    );
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![router, host]);
    let req = crate::test_utils::make_request(Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_upstream_condition_runs_filter_on_match() {
    let counter = Arc::new(AtomicUsize::new(0));
    let match_cond: Vec<praxis_core::config::Condition> =
        serde_yaml::from_str("- when:\n    bound_upstream:\n      application_protocol: p1\n").unwrap();
    let pipeline = make_pipeline_with_conditions(vec![
        (
            Box::new(BindingRouterFilter {
                cluster: "inference",
                protocol: Some("p1"),
                provider: None,
            }),
            vec![],
        ),
        (
            Box::new(CountingFilter {
                counter: Arc::clone(&counter),
            }),
            match_cond,
        ),
    ]);

    let req = crate::test_utils::make_request(Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "pipeline should continue");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "a filter gated on a matching bound_upstream condition must run after the binding router"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_upstream_condition_skips_filter_on_mismatch() {
    let counter = Arc::new(AtomicUsize::new(0));
    let mismatch_cond: Vec<praxis_core::config::Condition> =
        serde_yaml::from_str("- when:\n    bound_upstream:\n      application_protocol: other\n").unwrap();
    let pipeline = make_pipeline_with_conditions(vec![
        (
            Box::new(BindingRouterFilter {
                cluster: "inference",
                protocol: Some("p1"),
                provider: None,
            }),
            vec![],
        ),
        (
            Box::new(CountingFilter {
                counter: Arc::clone(&counter),
            }),
            mismatch_cond,
        ),
    ]);

    let req = crate::test_utils::make_request(Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "pipeline should continue");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "a filter gated on a non-matching bound_upstream condition must be skipped"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_upstream_condition_inside_branch_subchain_follows_the_binding() {
    for (provider, expected) in [("openai", 1), ("anthropic", 0)] {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut host = counting_filter(1, &Arc::new(AtomicUsize::new(0)), vec![]);
        host.branches = vec![always_branch(vec![counting_filter(2, &counter, openai_gate())])];

        run_bound_to(provider, host).await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            expected,
            "an openai-gated filter inside a branch sub-chain, with the request bound to {provider}"
        );
    }
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_gated_branch_host_fires_its_branch_only_when_the_binding_matches() {
    for (provider, expected) in [("openai", 1), ("anthropic", 0)] {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut host = counting_filter(1, &Arc::new(AtomicUsize::new(0)), openai_gate());
        host.branches = vec![always_branch(vec![counting_filter(2, &counter, vec![])])];

        run_bound_to(provider, host).await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            expected,
            "the branch of an openai-gated host, with the request bound to {provider}"
        );
    }
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn bound_upstream_request_gate_controls_response_hook() {
    for (protocol, expected) in [("p1", vec!["gated"]), ("other", vec![])] {
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let condition: Vec<praxis_core::config::Condition> =
            serde_yaml::from_str("- when:\n    bound_upstream:\n      application_protocol: p1\n").unwrap();
        let pipeline = make_pipeline_with_conditions(vec![
            (
                Box::new(BindingRouterFilter {
                    cluster: "inference",
                    protocol: Some(protocol),
                    provider: None,
                }),
                vec![],
            ),
            (
                Box::new(LoggingFilter {
                    label: "gated",
                    log: Arc::clone(&log),
                }),
                condition,
            ),
        ]);
        let req = crate::test_utils::make_request(Method::POST, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        drop(pipeline.execute_http_request(&mut ctx).await.unwrap());
        drop(pipeline.execute_http_response(&mut ctx).await.unwrap());

        assert_eq!(
            *log.lock().unwrap(),
            expected,
            "the bound_upstream request gate should decide whether the response hook runs for protocol {protocol}"
        );
    }
}

// -----------------------------------------------------------------------------
// Bound-Upstream Freeze
// -----------------------------------------------------------------------------

#[cfg(feature = "upstream-binding")]
fn binding_router(cluster: &'static str) -> Box<dyn HttpFilter> {
    Box::new(BindingRouterFilter {
        cluster,
        protocol: Some("p1"),
        provider: None,
    })
}

/// A filter that claims to bind an upstream but publishes nothing, modelling a
/// router that ran without resolving a route.
#[cfg(feature = "upstream-binding")]
struct NonPublishingBindingFilter;

#[cfg(feature = "upstream-binding")]
#[async_trait]
impl HttpFilter for NonPublishingBindingFilter {
    fn name(&self) -> &'static str {
        "non_publishing_binding"
    }

    fn binds_upstream(&self) -> bool {
        true
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn binding_freeze_waits_for_a_binder_that_publishes() {
    let pipeline = make_pipeline(vec![Box::new(NonPublishingBindingFilter), binding_router("inference")]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "a binder that published nothing must not freeze, so the next router can bind"
    );
    assert_eq!(
        ctx.bound_cluster(),
        Some("inference"),
        "the first binder that actually publishes owns the binding"
    );
    assert!(ctx.bound_upstream_frozen(), "the published binding is frozen");
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn binding_freezes_without_bound_body_participants() {
    let pipeline = make_pipeline(vec![binding_router("first"), binding_router("second")]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();

    assert!(
        matches!(action, FilterAction::Reject(rejection) if rejection.status == 500),
        "a rebind after the first binding freezes must be rejected with 500"
    );
    assert_eq!(
        ctx.bound_cluster(),
        Some("first"),
        "the first binding must stay frozen after the rejected rebind"
    );
}

#[cfg(feature = "upstream-binding")]
#[tokio::test]
async fn reenter_over_the_real_router_republishes_or_fails_closed() {
    for (prefix, rebinds) in [("/c", false), ("/b", true)] {
        let mut entries: Vec<FilterEntry> = serde_yaml::from_str(&format!(
            r#"
- filter: router
  name: route
  routes:
    - {{path_prefix: "/b", cluster: b}}
    - {{path_prefix: "/", cluster: a}}
- filter: path_rewrite
  add_prefix: "{prefix}"
  branch_chains:
    - name: again
      rejoin: route
      max_iterations: 1
      chains: [{{name: again-chain, filters: [{{filter: headers, request_set: [{{name: x-pass, value: "2"}}]}}]}}]
- filter: load_balancer
  cluster_source: bound_upstream
  clusters:
    - {{name: a, http: {{application_provider: openai}}, endpoints: ["127.0.0.1:9"]}}
    - {{name: b, endpoints: ["127.0.0.1:10"]}}
"#
        ))
        .unwrap();
        let pipeline = FilterPipeline::build_with_chains(
            &mut entries,
            &FilterRegistry::with_builtins(),
            &HashMap::new(),
            &praxis_core::config::InsecureOptions::default(),
        )
        .unwrap();
        let req = crate::test_utils::make_request(Method::GET, "/x");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();

        assert_eq!(
            matches!(&action, FilterAction::Reject(rejection) if rejection.status == 500),
            rebinds,
            "the second pass routes {prefix}/x, so the router {} its frozen binding: {action:?}",
            if rebinds {
                "fails closed instead of replacing"
            } else {
                "republishes"
            }
        );
        assert_eq!(
            ctx.bound_cluster(),
            Some("a"),
            "the first pass's binding survives the loop"
        );
        assert_eq!(
            ctx.bound_application_provider(),
            Some("openai"),
            "the frozen binding keeps its catalog metadata through the loop"
        );
    }
}

// -----------------------------------------------------------------------------
// Bound-Upstream Request-Body Barrier
// -----------------------------------------------------------------------------

#[cfg(feature = "bound-upstream-request-body")]
mod bound_upstream_body_barrier {
    use super::*;

    /// Configurable outcome for [`BoundBodyRecordingFilter`]'s barrier hook.
    enum BoundBodyBehavior {
        Continue,
        Reject(u16),
        Error,
    }

    /// A bound-upstream request-body participant. Declaring
    /// `bound_upstream_request_body_access` is what arms the barrier: `build` (and
    /// the `with_body_indices` test helper) collect such filters into
    /// `bound_upstream_request_body_filter_indices`. The hook records how many
    /// times it ran and the body it observed, then returns a configurable outcome.
    struct BoundBodyRecordingFilter {
        name: &'static str,
        ran: Arc<AtomicUsize>,
        seen_body: Arc<std::sync::Mutex<Option<Bytes>>>,
        behavior: BoundBodyBehavior,
    }

    impl BoundBodyRecordingFilter {
        fn new(
            name: &'static str,
            behavior: BoundBodyBehavior,
        ) -> (Self, Arc<AtomicUsize>, Arc<std::sync::Mutex<Option<Bytes>>>) {
            let ran = Arc::new(AtomicUsize::new(0));
            let seen_body = Arc::new(std::sync::Mutex::new(None));
            let filter = Self {
                name,
                ran: Arc::clone(&ran),
                seen_body: Arc::clone(&seen_body),
                behavior,
            };
            (filter, ran, seen_body)
        }
    }

    #[async_trait]
    impl HttpFilter for BoundBodyRecordingFilter {
        fn name(&self) -> &'static str {
            self.name
        }

        fn bound_upstream_request_body_access(&self) -> BodyAccess {
            BodyAccess::ReadOnly
        }

        fn request_body_mode(&self) -> BodyMode {
            BodyMode::StreamBuffer {
                max_bytes: Some(65_536),
            }
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        async fn on_bound_upstream_request_body(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
        ) -> Result<crate::BoundUpstreamBodyOutcome, FilterError> {
            self.ran.fetch_add(1, Ordering::SeqCst);
            *self.seen_body.lock().unwrap() = body.clone();
            match self.behavior {
                BoundBodyBehavior::Continue => Ok(crate::BoundUpstreamBodyOutcome::Continue),
                BoundBodyBehavior::Reject(status) => Ok(crate::BoundUpstreamBodyOutcome::Reject(
                    crate::Rejection::status(status),
                )),
                BoundBodyBehavior::Error => Err(FilterError::from("bound body boom")),
            }
        }
    }

    #[tokio::test]
    async fn bound_upstream_barrier_runs_participant_and_commits_body() {
        let (participant, ran, seen) = BoundBodyRecordingFilter::new("bound_body", BoundBodyBehavior::Continue);
        let pipeline = make_pipeline(vec![binding_router("inference"), Box::new(participant)]);
        assert_eq!(
            pipeline.bound_upstream_request_body_filter_indices,
            vec![1],
            "the body participant must be collected into the barrier index"
        );

        let req = crate::test_utils::make_request(Method::POST, "/v1/responses");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue), "pipeline should continue");
        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "barrier must run the participant exactly once"
        );
        assert_eq!(
            seen.lock().unwrap().as_deref(),
            Some(&b"payload"[..]),
            "the participant must observe the buffered body"
        );
        assert_eq!(
            ctx.buffered_request_body.as_deref(),
            Some(&b"payload"[..]),
            "the barrier must commit the body back into the context"
        );
        assert!(
            ctx.take_bound_request_body_rewrite().is_none(),
            "a read-only participant must not replace the forwarded body"
        );
    }

    /// Read-write participant that appends `|<name>` at the barrier, or rejects
    /// there, and counts its own request and response hooks.
    struct MarkingParticipant {
        name: &'static str,
        reject: Option<u16>,
        requests: Arc<AtomicUsize>,
        responses: Arc<AtomicUsize>,
    }

    impl MarkingParticipant {
        fn new(name: &'static str, reject: Option<u16>) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
            let requests = Arc::new(AtomicUsize::new(0));
            let responses = Arc::new(AtomicUsize::new(0));
            let filter = Self {
                name,
                reject,
                requests: Arc::clone(&requests),
                responses: Arc::clone(&responses),
            };
            (filter, requests, responses)
        }
    }

    #[async_trait]
    impl HttpFilter for MarkingParticipant {
        fn name(&self) -> &'static str {
            self.name
        }

        fn bound_upstream_request_body_access(&self) -> BodyAccess {
            BodyAccess::ReadWrite
        }

        fn request_body_mode(&self) -> BodyMode {
            BodyMode::StreamBuffer {
                max_bytes: Some(65_536),
            }
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            Ok(FilterAction::Continue)
        }

        async fn on_response(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            self.responses.fetch_add(1, Ordering::SeqCst);
            Ok(FilterAction::Continue)
        }

        async fn on_bound_upstream_request_body(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
        ) -> Result<crate::BoundUpstreamBodyOutcome, FilterError> {
            if let Some(status) = self.reject {
                return Ok(crate::BoundUpstreamBodyOutcome::Reject(crate::Rejection::status(
                    status,
                )));
            }
            let mut output = body.as_ref().map_or_else(Vec::new, |bytes| bytes.to_vec());
            output.push(b'|');
            output.extend_from_slice(self.name.as_bytes());
            *body = Some(Bytes::from(output));
            Ok(crate::BoundUpstreamBodyOutcome::Continue)
        }
    }

    #[tokio::test]
    async fn barrier_runs_a_participant_the_request_never_reaches() {
        let skip_past = |target| ResolvedBranch {
            condition: None,
            filters: vec![],
            max_iterations: None,
            name: Arc::from("past"),
            rejoin: target,
        };
        let cases: [(&str, Box<dyn HttpFilter>, Vec<ResolvedBranch>); 3] = [
            ("a rejecting filter", Box::new(RejectFilter), vec![]),
            (
                "a SkipTo branch",
                Box::new(PassthroughFilter),
                vec![skip_past(RejoinTarget::SkipTo(3))],
            ),
            (
                "a terminal branch",
                Box::new(PassthroughFilter),
                vec![skip_past(RejoinTarget::Terminal)],
            ),
        ];
        for (case, interposer, router_branches) in cases {
            let (participant, requests, _) = MarkingParticipant::new("late", None);
            let mut pipeline = make_pipeline(vec![
                binding_router("inference"),
                interposer,
                Box::new(participant),
                Box::new(PassthroughFilter),
            ]);
            pipeline.filters[0].branches = router_branches;
            let req = crate::test_utils::make_request(Method::POST, "/");
            let mut ctx = crate::test_utils::make_filter_context(&req);
            ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

            drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

            assert_eq!(
                ctx.take_bound_request_body_rewrite().as_deref(),
                Some(&b"payload|late"[..]),
                "with {case} between the router and the participant, the barrier still ran its body hook"
            );
            assert_eq!(
                requests.load(Ordering::SeqCst),
                0,
                "with {case} between the router and the participant, its request hook never ran"
            );
        }
    }

    #[tokio::test]
    async fn barrier_runs_participants_in_order_and_honors_their_conditions() {
        let gate = |protocol: &str| -> Vec<praxis_core::config::Condition> {
            serde_yaml::from_str(&format!(
                "- when:\n    bound_upstream:\n      application_protocol: {protocol}\n"
            ))
            .unwrap()
        };
        let (first, ..) = MarkingParticipant::new("first", None);
        let (matching, ..) = MarkingParticipant::new("matching", None);
        let (other, ..) = MarkingParticipant::new("other", None);
        let pipeline = make_pipeline_with_conditions(vec![
            (binding_router("inference"), vec![]),
            (Box::new(first), vec![]),
            (Box::new(matching), gate("p1")),
            (Box::new(other), gate("p2")),
        ]);
        let req = crate::test_utils::make_request(Method::POST, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.take_bound_request_body_rewrite().as_deref(),
            Some(&b"payload|first|matching"[..]),
            "participants rewrite in pipeline order, and one gated on another protocol is skipped"
        );
    }

    #[tokio::test]
    async fn barrier_records_bound_upstream_duration_metrics() {
        crate::test_utils::install_metrics_recorder();
        let (participant, ..) = MarkingParticipant::new("bound_metric_participant", None);
        let mut pipeline = make_pipeline(vec![binding_router("inference"), Box::new(participant)]);
        pipeline.set_record_filter_duration_metrics(true);
        let req = crate::test_utils::make_request(Method::POST, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

        let rendered = crate::test_utils::render_metrics();
        assert!(
            rendered.lines().any(|line| {
                line.contains("filter=\"bound_metric_participant\"")
                    && line.contains("phase=\"bound_upstream\"")
                    && line.contains("stream=\"body\"")
            }),
            "the executor times the participant's body hook under the bound_upstream phase: {rendered}"
        );
    }

    #[tokio::test]
    async fn barrier_rejection_runs_responses_only_for_filters_that_ran() {
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (rejecting, _, rejecting_responses) = MarkingParticipant::new("rejecting", Some(403));
        let pipeline = make_pipeline(vec![
            Box::new(LoggingFilter {
                label: "before",
                log: Arc::clone(&log),
            }),
            binding_router("inference"),
            Box::new(rejecting),
        ]);
        let req = crate::test_utils::make_request(Method::POST, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
        drop(pipeline.execute_http_response(&mut ctx).await.unwrap());

        assert!(
            matches!(&action, FilterAction::Reject(rejection) if rejection.status == 403),
            "the barrier's rejection is returned unchanged: {action:?}"
        );
        assert_eq!(
            *log.lock().unwrap(),
            vec!["before"],
            "a filter that ran before the router still gets its response hook"
        );
        assert_eq!(
            rejecting_responses.load(Ordering::SeqCst),
            0,
            "the rejecting participant never reached its own request hook, so it gets no response hook"
        );
    }

    #[test]
    fn branch_router_never_binds_for_a_top_level_participant() {
        let mut registry = FilterRegistry::with_builtins();
        registry
            .register(
                "marking",
                FilterFactory::Http(Arc::new(|_| Ok(Box::new(MarkingParticipant::new("marking", None).0)))),
            )
            .unwrap();
        let mut entries: Vec<FilterEntry> = serde_yaml::from_str(
            r#"
- filter: headers
  branch_chains:
    - name: route
      chains:
        - name: route-chain
          filters:
            - filter: router
              routes: [{path_prefix: "/", cluster: backend}]
- filter: marking
- filter: load_balancer
  cluster_source: bound_upstream
  clusters: [{name: backend, endpoints: ["127.0.0.1:9"]}]
"#,
        )
        .unwrap();
        let pipeline = FilterPipeline::build_with_chains(
            &mut entries,
            &registry,
            &HashMap::new(),
            &praxis_core::config::InsecureOptions::default(),
        )
        .unwrap();

        let errors = pipeline.ordering_errors(&entries, false, &SkipPipelineChecks::default());

        assert_eq!(
            pipeline.filters[0].branches.len(),
            1,
            "the router's branch must actually be resolved for this to mean anything"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("filter 'router' publishes a logical upstream binding inside a branch")),
            "a router in a branch cannot be the binding router: {errors:?}"
        );
        assert!(
            errors.iter().any(|error| error
                .contains("filter 'marking' requires a bound logical upstream (a bound-upstream request-body hook)")),
            "the barrier only fires after a top-level router, so the participant has no binding: {errors:?}"
        );
    }

    /// Participant that appends `|tamper` whatever access it declared, then
    /// continues or errors.
    struct TamperingParticipant {
        access: BodyAccess,
        error: bool,
    }

    #[async_trait]
    impl HttpFilter for TamperingParticipant {
        fn name(&self) -> &'static str {
            "tampering"
        }

        fn bound_upstream_request_body_access(&self) -> BodyAccess {
            self.access
        }

        fn request_body_mode(&self) -> BodyMode {
            BodyMode::StreamBuffer {
                max_bytes: Some(65_536),
            }
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        async fn on_bound_upstream_request_body(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
        ) -> Result<crate::BoundUpstreamBodyOutcome, FilterError> {
            let mut output = body.as_ref().map_or_else(Vec::new, |bytes| bytes.to_vec());
            output.extend_from_slice(b"|tamper");
            *body = Some(Bytes::from(output));
            if self.error {
                return Err(FilterError::from("tamper boom"));
            }
            Ok(crate::BoundUpstreamBodyOutcome::Continue)
        }
    }

    #[tokio::test]
    async fn read_only_participant_edits_never_reach_the_committed_body() {
        let pipeline = make_pipeline(vec![
            binding_router("inference"),
            Box::new(TamperingParticipant {
                access: BodyAccess::ReadOnly,
                error: false,
            }),
        ]);
        let req = crate::test_utils::make_request(Method::POST, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.buffered_request_body.as_deref(),
            Some(&b"payload"[..]),
            "a read-only participant works on a copy, so later filters see the original body"
        );
        assert!(
            ctx.take_bound_request_body_rewrite().is_none(),
            "nothing is recorded as a rewrite, so the transport forwards the original too"
        );
    }

    #[tokio::test]
    async fn fail_open_writer_that_errors_leaves_the_body_for_the_next_participant() {
        let (after, ..) = MarkingParticipant::new("after", None);
        let mut pipeline = make_pipeline(vec![
            binding_router("inference"),
            Box::new(TamperingParticipant {
                access: BodyAccess::ReadWrite,
                error: true,
            }),
            Box::new(after),
        ]);
        pipeline.filters[1].failure_mode = FailureMode::Open;
        let req = crate::test_utils::make_request(Method::POST, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "fail-open swallows the error: {action:?}"
        );
        assert_eq!(
            ctx.take_bound_request_body_rewrite().as_deref(),
            Some(&b"payload|after"[..]),
            "the failed writer's partial edit is undone, so the next writer builds on the original"
        );
    }

    /// Read-write participant that appends `|bound` at the barrier and later, at
    /// its own header-phase position, takes the buffered body the way a
    /// body-consuming request filter does.
    struct AppendThenTakeFilter;

    #[async_trait]
    impl HttpFilter for AppendThenTakeFilter {
        fn name(&self) -> &'static str {
            "append_then_take"
        }

        fn bound_upstream_request_body_access(&self) -> BodyAccess {
            BodyAccess::ReadWrite
        }

        fn request_body_mode(&self) -> BodyMode {
            BodyMode::StreamBuffer {
                max_bytes: Some(65_536),
            }
        }

        async fn on_request(&self, ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            drop(ctx.buffered_request_body.take());
            Ok(FilterAction::Continue)
        }

        async fn on_bound_upstream_request_body(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
        ) -> Result<crate::BoundUpstreamBodyOutcome, FilterError> {
            let mut output = body.as_ref().map_or_else(Vec::new, |bytes| bytes.to_vec());
            output.extend_from_slice(b"|bound");
            *body = Some(Bytes::from(output));
            Ok(crate::BoundUpstreamBodyOutcome::Continue)
        }
    }

    #[tokio::test]
    async fn bound_upstream_barrier_rewrite_survives_a_later_take() {
        let pipeline = make_pipeline(vec![binding_router("inference"), Box::new(AppendThenTakeFilter)]);
        let req = crate::test_utils::make_request(Method::POST, "/v1/responses");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue), "pipeline should continue");
        assert!(
            ctx.buffered_request_body.is_none(),
            "the participant's own on_request took the buffered body"
        );
        assert_eq!(
            ctx.take_bound_request_body_rewrite().as_deref(),
            Some(&b"payload|bound"[..]),
            "the barrier must record the writer's output where later filters cannot reach it"
        );
        assert!(
            ctx.take_bound_request_body_rewrite().is_none(),
            "the rewrite is handed to the transport once"
        );
    }

    #[tokio::test]
    async fn bound_upstream_barrier_skipped_writer_records_no_rewrite() {
        let mismatch: Vec<praxis_core::config::Condition> =
            serde_yaml::from_str("- when:\n    bound_upstream:\n      application_protocol: other\n").unwrap();
        let pipeline = make_pipeline_with_conditions(vec![
            (binding_router("inference"), vec![]),
            (Box::new(AppendThenTakeFilter), mismatch),
        ]);
        let req = crate::test_utils::make_request(Method::POST, "/v1/responses");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue), "pipeline should continue");
        assert!(
            ctx.take_bound_request_body_rewrite().is_none(),
            "a writer skipped by its conditions must not replace the forwarded body"
        );
        assert_eq!(
            ctx.buffered_request_body.as_deref(),
            Some(&b"payload"[..]),
            "a skipped writer leaves the buffered body untouched"
        );
    }

    #[tokio::test]
    async fn bound_upstream_barrier_reject_short_circuits_remaining_participants() {
        let (rejecting, first_ran, _) = BoundBodyRecordingFilter::new("reject_body", BoundBodyBehavior::Reject(403));
        let (trailing, second_ran, _) = BoundBodyRecordingFilter::new("trailing_body", BoundBodyBehavior::Continue);
        let pipeline = make_pipeline(vec![
            binding_router("inference"),
            Box::new(rejecting),
            Box::new(trailing),
        ]);

        let req = crate::test_utils::make_request(Method::POST, "/v1/responses");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
        match action {
            FilterAction::Reject(rejection) => assert_eq!(rejection.status, 403, "reject status must propagate"),
            other => panic!("expected reject, got {other:?}"),
        }
        assert_eq!(
            first_ran.load(Ordering::SeqCst),
            1,
            "the rejecting participant must run"
        );
        assert_eq!(
            second_ran.load(Ordering::SeqCst),
            0,
            "a participant after a reject must not run"
        );
    }

    #[tokio::test]
    async fn bound_upstream_barrier_closed_failure_aborts_request() {
        let (failing, ran, _) = BoundBodyRecordingFilter::new("failing_body", BoundBodyBehavior::Error);
        let pipeline = make_pipeline(vec![binding_router("inference"), Box::new(failing)]);

        let req = crate::test_utils::make_request(Method::POST, "/v1/responses");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        let result = pipeline.execute_http_request(&mut ctx).await;
        assert!(
            result.is_err(),
            "the default failure_mode is Closed, so the participant's error must abort the request"
        );
        assert_eq!(ran.load(Ordering::SeqCst), 1, "the failing participant must have run");
    }

    #[tokio::test]
    async fn bound_upstream_barrier_open_failure_continues_to_next_participant() {
        let (failing, first_ran, _) = BoundBodyRecordingFilter::new("failing_body", BoundBodyBehavior::Error);
        let (trailing, second_ran, _) = BoundBodyRecordingFilter::new("trailing_body", BoundBodyBehavior::Continue);
        let mut pipeline = make_pipeline(vec![binding_router("inference"), Box::new(failing), Box::new(trailing)]);
        pipeline.filters[1].failure_mode = FailureMode::Open;

        let req = crate::test_utils::make_request(Method::POST, "/v1/responses");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "open failure mode on the failing participant must swallow its error, not abort"
        );
        assert_eq!(
            first_ran.load(Ordering::SeqCst),
            1,
            "the failing participant must have run"
        );
        assert_eq!(
            second_ran.load(Ordering::SeqCst),
            1,
            "a participant after an open failure must still run"
        );
        assert_eq!(
            ctx.buffered_request_body.as_deref(),
            Some(&b"payload"[..]),
            "the barrier must commit the body back after an open failure"
        );
    }

    #[tokio::test]
    async fn bound_upstream_barrier_gates_participant_on_condition() {
        let mismatch: Vec<praxis_core::config::Condition> =
            serde_yaml::from_str("- when:\n    bound_upstream:\n      application_protocol: other\n").unwrap();
        let (skipped, skipped_ran, _) = BoundBodyRecordingFilter::new("skipped_body", BoundBodyBehavior::Continue);
        let pipeline = make_pipeline_with_conditions(vec![
            (binding_router("inference"), vec![]),
            (Box::new(skipped), mismatch),
        ]);

        let req = crate::test_utils::make_request(Method::POST, "/v1/responses");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue), "pipeline should continue");
        assert_eq!(
            skipped_ran.load(Ordering::SeqCst),
            0,
            "a participant whose bound_upstream condition does not match must be skipped"
        );

        let matches: Vec<praxis_core::config::Condition> =
            serde_yaml::from_str("- when:\n    bound_upstream:\n      application_protocol: p1\n").unwrap();
        let (matched, matched_ran, _) = BoundBodyRecordingFilter::new("matched_body", BoundBodyBehavior::Continue);
        let pipeline = make_pipeline_with_conditions(vec![
            (binding_router("inference"), vec![]),
            (Box::new(matched), matches),
        ]);
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));
        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue), "pipeline should continue");
        assert_eq!(
            matched_ran.load(Ordering::SeqCst),
            1,
            "the matching counterpart: a participant whose bound_upstream condition matches must run"
        );
    }

    #[tokio::test]
    async fn bound_upstream_barrier_runs_once_per_request() {
        let (participant, ran, _) = BoundBodyRecordingFilter::new("bound_body", BoundBodyBehavior::Continue);
        let pipeline = make_pipeline(vec![
            binding_router("inference"),
            binding_router("inference"),
            Box::new(participant),
        ]);

        let req = crate::test_utils::make_request(Method::POST, "/v1/responses");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue), "pipeline should continue");
        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "the barrier drains only on the first binding, so participants run once with two binding filters"
        );
    }

    #[tokio::test]
    async fn bound_upstream_barrier_runs_once_through_a_reenter_loop() {
        let (participant, ran, _) = BoundBodyRecordingFilter::new("bound_body", BoundBodyBehavior::Continue);
        let mut looping = PipelineFilter::new(1, AnyFilter::Http(Box::new(participant)), vec![], vec![]);
        looping.branches = vec![ResolvedBranch {
            condition: None,
            filters: vec![],
            max_iterations: Some(2),
            name: Arc::from("again"),
            rejoin: RejoinTarget::ReEnter(0),
        }];
        let filters = vec![
            PipelineFilter::new(0, AnyFilter::Http(binding_router("inference")), vec![], vec![]),
            looping,
        ];
        let pipeline = test_pipeline(compute_body_capabilities(&filters), filters);
        let req = crate::test_utils::make_request(Method::POST, "/v1/responses");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "republishing the same cluster on each pass continues: {action:?}"
        );
        assert_eq!(
            ctx.branch_iterations.get("again").copied(),
            Some(3),
            "the loop re-entered the router twice and then fell through"
        );
        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "the frozen binding keeps the barrier from replaying the body hooks on a re-entered pass"
        );
    }

    #[tokio::test]
    async fn bound_upstream_barrier_noop_without_bound_cluster() {
        let (participant, ran, _) = BoundBodyRecordingFilter::new("bound_body", BoundBodyBehavior::Continue);
        let pipeline = make_pipeline(vec![Box::new(NonPublishingBindingFilter), Box::new(participant)]);
        assert_eq!(
            pipeline.bound_upstream_request_body_filter_indices,
            vec![1],
            "the participant is still collected; only the runtime guard skips it"
        );

        let req = crate::test_utils::make_request(Method::POST, "/v1/responses");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue), "pipeline should continue");
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "a binder that never publishes binds no cluster, so the barrier must not drain participants"
        );
    }

    #[tokio::test]
    async fn bound_upstream_barrier_runs_for_request_without_body() {
        let (participant, ran, seen) = BoundBodyRecordingFilter::new("bound_body", BoundBodyBehavior::Continue);
        let pipeline = make_pipeline(vec![binding_router("inference"), Box::new(participant)]);
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::new());

        drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "the barrier runs even when the request has no body"
        );
        assert!(
            seen.lock().unwrap().is_none(),
            "an empty pre-read buffer must reach the hook as None"
        );
        assert_eq!(
            ctx.buffered_request_body.as_deref(),
            Some(&b""[..]),
            "the empty buffer stays in place for later request filters"
        );
    }

    /// Read-write participant that removes the request body at the barrier,
    /// leaving `None` or an empty buffer depending on `leave_empty_buffer`.
    struct RemoveBoundBodyFilter {
        leave_empty_buffer: bool,
    }

    #[async_trait]
    impl HttpFilter for RemoveBoundBodyFilter {
        fn name(&self) -> &'static str {
            "remove_bound_body"
        }

        fn bound_upstream_request_body_access(&self) -> BodyAccess {
            BodyAccess::ReadWrite
        }

        fn request_body_mode(&self) -> BodyMode {
            BodyMode::StreamBuffer {
                max_bytes: Some(65_536),
            }
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        async fn on_bound_upstream_request_body(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
        ) -> Result<crate::BoundUpstreamBodyOutcome, FilterError> {
            *body = self.leave_empty_buffer.then(Bytes::new);
            Ok(crate::BoundUpstreamBodyOutcome::Continue)
        }
    }

    #[tokio::test]
    async fn bound_upstream_barrier_keeps_a_buffer_when_a_writer_removes_the_body() {
        let pipeline = make_pipeline(vec![
            binding_router("inference"),
            Box::new(RemoveBoundBodyFilter {
                leave_empty_buffer: false,
            }),
        ]);
        let req = crate::test_utils::make_request(Method::POST, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

        assert_eq!(
            ctx.buffered_request_body.as_deref(),
            Some(&b""[..]),
            "a removed body leaves an empty buffer, not None, for the IRR and other body readers"
        );
        assert_eq!(
            ctx.take_bound_request_body_rewrite().as_deref(),
            Some(&b""[..]),
            "the transport forwards the removal as an empty body"
        );
    }

    #[tokio::test]
    async fn bound_upstream_barrier_hands_later_participants_none_for_an_emptied_body() {
        let (recorder, ran, seen) = BoundBodyRecordingFilter::new("bound_body", BoundBodyBehavior::Continue);
        let pipeline = make_pipeline(vec![
            binding_router("inference"),
            Box::new(RemoveBoundBodyFilter {
                leave_empty_buffer: true,
            }),
            Box::new(recorder),
        ]);
        let req = crate::test_utils::make_request(Method::POST, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

        assert_eq!(ran.load(Ordering::SeqCst), 1, "the later participant still runs");
        assert!(
            seen.lock().unwrap().is_none(),
            "a body an earlier writer emptied must reach the next participant as None"
        );
    }

    #[tokio::test]
    async fn bound_upstream_barrier_runs_before_skip_to_rejoin() {
        let (participant, ran, _) = BoundBodyRecordingFilter::new("bound_body", BoundBodyBehavior::Continue);
        let mut pipeline = make_pipeline(vec![
            binding_router("inference"),
            Box::new(participant),
            Box::new(CountingFilter {
                counter: Arc::new(AtomicUsize::new(0)),
            }),
        ]);
        pipeline.filters[0].branches = vec![ResolvedBranch {
            condition: None,
            filters: vec![],
            max_iterations: None,
            name: Arc::from("skip_participant_request_position"),
            rejoin: RejoinTarget::SkipTo(2),
        }];
        let req = crate::test_utils::make_request(Method::POST, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "the binding barrier runs before branches can skip the participant's request position"
        );
    }

    #[tokio::test]
    async fn a_rewrite_exactly_at_the_limit_is_forwarded() {
        let (limit, action, rewrite) = rewrite_with_output_near_the_limit(false).await;

        assert!(
            matches!(action, FilterAction::Continue),
            "a rewrite of exactly {limit} bytes is not over the limit: {action:?}"
        );
        assert_eq!(
            rewrite.map(|bytes| bytes.len()),
            Some(limit),
            "a rewrite of exactly {limit} bytes is recorded for the transport"
        );
    }

    #[tokio::test]
    async fn a_rewrite_one_byte_over_the_limit_is_rejected() {
        let (limit, action, rewrite) = rewrite_with_output_near_the_limit(true).await;

        assert!(
            matches!(&action, FilterAction::Reject(rejection) if rejection.status == 413),
            "a rewrite one byte over the {limit}-byte limit is rejected: {action:?}"
        );
        assert!(
            rewrite.is_none(),
            "an oversized rewrite is never recorded for the transport"
        );
    }

    #[tokio::test]
    async fn barrier_records_no_metric_when_recording_is_off() {
        crate::test_utils::install_metrics_recorder();
        let (participant, ..) = MarkingParticipant::new("bound_silent_participant", None);
        let mut pipeline = make_pipeline(vec![binding_router("inference"), Box::new(participant)]);
        pipeline.set_record_filter_duration_metrics(false);
        let req = crate::test_utils::make_request(Method::POST, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

        let rendered = crate::test_utils::render_metrics();
        assert_eq!(
            ctx.take_bound_request_body_rewrite().as_deref(),
            Some(&b"payload|bound_silent_participant"[..]),
            "the participant ran, so a missing metric means recording was off rather than the hook being skipped"
        );
        assert!(
            !rendered.lines().any(|line| {
                line.contains("filter=\"bound_silent_participant\"") && line.contains("phase=\"bound_upstream\"")
            }),
            "with recording off (the default) the barrier times nothing: {rendered}"
        );
    }

    #[tokio::test]
    async fn a_writer_can_add_a_body_where_the_pre_read_had_none() {
        let (participant, ..) = MarkingParticipant::new("after", None);
        let pipeline = make_pipeline(vec![binding_router("inference"), Box::new(participant)]);
        let req = crate::test_utils::make_request(Method::POST, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = None;

        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "pipeline should continue: {action:?}"
        );
        assert_eq!(
            ctx.buffered_request_body.as_deref(),
            Some(&b"|after"[..]),
            "a body the writer added is committed for later request filters even without a pre-read buffer"
        );
        assert_eq!(
            ctx.take_bound_request_body_rewrite().as_deref(),
            Some(&b"|after"[..]),
            "the added body is recorded as the rewrite the transport forwards"
        );
    }

    #[tokio::test]
    async fn a_barrier_rejection_returns_before_the_routers_branches_run() {
        let branch_runs = Arc::new(AtomicUsize::new(0));
        let (rejecting, ..) = MarkingParticipant::new("rejecting", Some(403));
        let mut pipeline = make_pipeline(vec![binding_router("inference"), Box::new(rejecting)]);
        pipeline.filters[0].branches = vec![counting_branch(&branch_runs)];
        let req = crate::test_utils::make_request(Method::POST, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from_static(b"payload"));

        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();

        assert!(
            matches!(&action, FilterAction::Reject(rejection) if rejection.status == 403),
            "the barrier's rejection is returned unchanged: {action:?}"
        );
        assert_eq!(
            branch_runs.load(Ordering::SeqCst),
            0,
            "the binding router's branches never run once the barrier rejects"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Run a `|limit` writer over a pre-read sized so its output lands exactly
    /// at the pipeline's rewrite limit, or one byte past it. Returns the limit,
    /// the pipeline's action, and the recorded rewrite.
    async fn rewrite_with_output_near_the_limit(over_by_one: bool) -> (usize, FilterAction, Option<Bytes>) {
        let (participant, ..) = MarkingParticipant::new("limit", None);
        let pipeline = make_pipeline(vec![binding_router("inference"), Box::new(participant)]);
        let limit = pipeline.selected_upstream_request_body_limit();
        let at_limit = limit.checked_sub("|limit".len()).expect("the limit covers the marker");
        let mut pre_read = vec![b'x'; at_limit];
        if over_by_one {
            pre_read.push(b'x');
        }
        let req = crate::test_utils::make_request(Method::POST, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.buffered_request_body = Some(Bytes::from(pre_read));
        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
        (limit, action, ctx.take_bound_request_body_rewrite())
    }

    /// An unconditional branch holding one [`CountingFilter`] over `counter`.
    fn counting_branch(counter: &Arc<AtomicUsize>) -> ResolvedBranch {
        ResolvedBranch {
            condition: None,
            filters: vec![PipelineFilter::new(
                10,
                AnyFilter::Http(Box::new(CountingFilter {
                    counter: Arc::clone(counter),
                })),
                vec![],
                vec![],
            )],
            max_iterations: None,
            name: Arc::from("after_binding"),
            rejoin: RejoinTarget::Next,
        }
    }
}

// -----------------------------------------------------------------------------
// filter_request_conditions_match (selection axis)
// -----------------------------------------------------------------------------

/// Build a single-`access_log`-filter pipeline scoped to `provider` via a
/// `selected_upstream` `when` condition. `build` does not enforce ordering, so
/// no load balancer is needed to construct it for these condition-match tests.
fn access_log_scoped_to_provider(provider: &str) -> FilterPipeline {
    let registry = FilterRegistry::with_builtins();
    let condition = serde_yaml::from_str(&format!(
        "when:\n  selected_upstream:\n    application_provider: {provider}\n"
    ))
    .expect("valid selected_upstream condition");
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![condition],
        filter_type: "access_log".into(),
        config: serde_yaml::Value::Null,
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }];
    FilterPipeline::build(&mut entries, &registry).expect("access_log pipeline builds")
}

#[test]
fn conditions_match_selected_honors_published_selection() {
    let pipeline = access_log_scoped_to_provider("vllm");
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.publish_selected_application(None, Some(Arc::from("vllm")));
    assert!(
        pipeline.filter_request_conditions_match("access_log", &ctx),
        "a selected_upstream-scoped filter must match when the published selection (as the fallback path restores it) satisfies its predicate"
    );
}

#[test]
fn conditions_match_selected_fails_closed_without_selection() {
    let pipeline = access_log_scoped_to_provider("vllm");
    let req = crate::test_utils::make_request(Method::GET, "/");
    let ctx = crate::test_utils::make_filter_context(&req);
    assert!(
        !pipeline.filter_request_conditions_match("access_log", &ctx),
        "with no published selection the predicate must fail closed, like the selection-unaware helper"
    );
}

#[test]
fn conditions_match_selected_rejects_mismatched_selection() {
    let pipeline = access_log_scoped_to_provider("vllm");
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.publish_selected_application(None, Some(Arc::from("openai")));
    assert!(
        !pipeline.filter_request_conditions_match("access_log", &ctx),
        "a mismatched published provider must not match, so the fallback record is withheld"
    );
}

#[cfg(feature = "upstream-binding")]
#[test]
fn filter_request_conditions_match_honors_bound_upstream_view() {
    let cond: Vec<praxis_core::config::Condition> =
        serde_yaml::from_str("- when:\n    bound_upstream:\n      application_protocol: p1\n").unwrap();
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(LoggingFilter {
            label: "access_log",
            log: Arc::new(std::sync::Mutex::new(Vec::new())),
        }),
        cond,
    )]);

    let req = crate::test_utils::make_request(Method::POST, "/v1/responses");

    let ctx_unbound = crate::test_utils::make_filter_context(&req);
    assert!(
        !pipeline.filter_request_conditions_match("access_log", &ctx_unbound),
        "an unbound request must not match a bound_upstream-gated access_log filter (no fallback record)"
    );

    let mut ctx_bound = crate::test_utils::make_filter_context(&req);
    ctx_bound
        .publish_bound_upstream(Arc::from("inference"), Some(Arc::from("p1")), None)
        .expect("publish before freeze succeeds");
    assert!(
        pipeline.filter_request_conditions_match("access_log", &ctx_bound),
        "the fallback must evaluate the real bound view (not an empty one), so a matching protocol must match"
    );
}

#[cfg(feature = "upstream-binding")]
#[test]
fn filter_request_conditions_match_fails_closed_for_untagged_binding() {
    let condition: Vec<praxis_core::config::Condition> =
        serde_yaml::from_str("- when:\n    bound_upstream:\n      application_provider: openai\n").unwrap();
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(LoggingFilter {
            label: "access_log",
            log: Arc::new(std::sync::Mutex::new(Vec::new())),
        }),
        condition,
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.publish_bound_upstream(Arc::from("generic"), None, None).unwrap();

    assert!(
        !pipeline.filter_request_conditions_match("access_log", &ctx),
        "an untagged binding must not satisfy a provider-scoped fallback"
    );
}

#[test]
fn conditions_match_selected_unconditional_filter_always_matches() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![],
        filter_type: "access_log".into(),
        config: serde_yaml::Value::Null,
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).expect("access_log pipeline builds");
    let req = crate::test_utils::make_request(Method::GET, "/");
    let ctx = crate::test_utils::make_filter_context(&req);
    assert!(
        pipeline.filter_request_conditions_match("access_log", &ctx),
        "an unconditional filter matches even with no selection, like the selection-unaware helper"
    );
}

// -----------------------------------------------------------------------------
// Branch Response Unwinding Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn branch_filters_unwind_in_reverse_before_their_host() {
    let log = HookLog::default();
    let mut host = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![unwind_branch(
        "br",
        RejoinTarget::Next,
        vec![
            scripted_pf(100, "B1", &log, Scripted::Continue, Scripted::Continue),
            scripted_pf(101, "B2", &log, Scripted::Continue, Scripted::Continue),
        ],
    )];
    let tail = scripted_pf(1, "C", &log, Scripted::Continue, Scripted::Continue);
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host, tail]);

    let recorded = run_request_then_response(&pipeline, &log, "/").await;

    assert_eq!(
        recorded,
        vec!["C", "B2", "B1", "A"],
        "branch filters must unwind in reverse, right before their host"
    );
}

#[tokio::test]
async fn sibling_branches_unwind_in_reverse_branch_order() {
    let log = HookLog::default();
    let mut host = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![
        unwind_branch(
            "first",
            RejoinTarget::Next,
            vec![scripted_pf(100, "X", &log, Scripted::Continue, Scripted::Continue)],
        ),
        unwind_branch(
            "second",
            RejoinTarget::Next,
            vec![scripted_pf(101, "Y", &log, Scripted::Continue, Scripted::Continue)],
        ),
    ];
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host]);

    let recorded = run_request_then_response(&pipeline, &log, "/").await;

    assert_eq!(
        recorded,
        vec!["Y", "X", "A"],
        "the later sibling branch ran last, so it must unwind first"
    );
}

#[tokio::test]
async fn nested_branch_filters_unwind_before_the_filter_hosting_them() {
    let log = HookLog::default();
    let mut outer = scripted_pf(100, "B1", &log, Scripted::Continue, Scripted::Continue);
    outer.branches = vec![unwind_branch(
        "inner",
        RejoinTarget::Next,
        vec![
            scripted_pf(200, "N1", &log, Scripted::Continue, Scripted::Continue),
            scripted_pf(201, "N2", &log, Scripted::Continue, Scripted::Continue),
        ],
    )];
    let mut host = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![unwind_branch(
        "outer",
        RejoinTarget::Next,
        vec![
            outer,
            scripted_pf(101, "B2", &log, Scripted::Continue, Scripted::Continue),
        ],
    )];
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host]);

    let recorded = run_request_then_response(&pipeline, &log, "/").await;

    assert_eq!(
        recorded,
        vec!["B2", "N2", "N1", "B1", "A"],
        "a nested branch must unwind right before the branch filter hosting it"
    );
}

#[tokio::test]
async fn nested_rejection_unwinds_only_the_filters_that_ran() {
    let log = HookLog::default();
    let mut outer = scripted_pf(100, "B1", &log, Scripted::Continue, Scripted::Continue);
    outer.branches = vec![unwind_branch(
        "inner",
        RejoinTarget::Terminal,
        vec![scripted_pf(200, "N1", &log, Scripted::Reject, Scripted::Continue)],
    )];
    let mut host = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![unwind_branch(
        "outer",
        RejoinTarget::Next,
        vec![
            outer,
            scripted_pf(101, "B2", &log, Scripted::Continue, Scripted::Continue),
        ],
    )];
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host]);

    assert_eq!(
        run_request_then_response(&pipeline, &log, "/").await,
        vec!["N1", "B1", "A"],
        "a nested rejection stops the outer branch, so B2 never ran"
    );
}

#[tokio::test]
async fn branch_filter_skipped_by_conditions_does_not_run_on_response() {
    let log = HookLog::default();
    let mut gated = scripted_pf(100, "B1", &log, Scripted::Continue, Scripted::Continue);
    gated.conditions = vec![when_path("/api")];
    let mut host = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![unwind_branch(
        "br",
        RejoinTarget::Next,
        vec![
            gated,
            scripted_pf(101, "B2", &log, Scripted::Continue, Scripted::Continue),
        ],
    )];
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host]);

    assert_eq!(
        run_request_then_response(&pipeline, &log, "/other").await,
        vec!["B2", "A"],
        "a branch filter skipped by its conditions must not run on_response"
    );
    assert_eq!(
        run_request_then_response(&pipeline, &log, "/api").await,
        vec!["B2", "B1", "A"],
        "a branch filter whose conditions match must run on_response"
    );
}

#[tokio::test]
async fn unfired_conditional_branch_does_not_run_on_response() {
    let log = HookLog::default();
    let mut branch = unwind_branch(
        "gated",
        RejoinTarget::Next,
        vec![scripted_pf(100, "B1", &log, Scripted::Continue, Scripted::Continue)],
    );
    branch.condition = Some(ResolvedBranchCondition {
        filter_name: Arc::from("A"),
        key: Arc::from("status"),
        value: Arc::from("hit"),
    });
    let mut host = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![branch];
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host]);

    assert_eq!(
        run_request_then_response(&pipeline, &log, "/").await,
        vec!["A"],
        "filters of a branch that never fired must not run on_response"
    );
}

#[tokio::test]
async fn branch_filter_response_conditions_gate_its_on_response() {
    let log = HookLog::default();
    let mut gated = scripted_pf(100, "B1", &log, Scripted::Continue, Scripted::Continue);
    gated.response_conditions = vec![when_status(&[500])];
    let mut host = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![unwind_branch("br", RejoinTarget::Next, vec![gated])];
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut resp = crate::context::Response {
        status: StatusCode::OK,
        headers: HeaderMap::new(),
    };
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());
    ctx.response_header = Some(&mut resp);

    drop(pipeline.execute_http_response(&mut ctx).await.unwrap());

    assert_eq!(
        log.take(),
        vec!["A"],
        "a branch filter whose response conditions do not match must be skipped"
    );
}

#[tokio::test]
async fn branch_filter_on_response_error_is_swallowed_when_fail_open() {
    let log = HookLog::default();
    let mut failing = scripted_pf(101, "B2", &log, Scripted::Continue, Scripted::Error);
    failing.failure_mode = FailureMode::Open;
    let mut host = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![unwind_branch(
        "br",
        RejoinTarget::Next,
        vec![
            scripted_pf(100, "B1", &log, Scripted::Continue, Scripted::Continue),
            failing,
        ],
    )];
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

    let action = pipeline.execute_http_response(&mut ctx).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "failure_mode: open must swallow a branch filter's on_response error"
    );
    assert_eq!(
        log.take(),
        vec!["B2", "B1", "A"],
        "the unwind must continue past a swallowed error"
    );
}

#[tokio::test]
async fn branch_filter_on_response_error_propagates_when_fail_closed() {
    let log = HookLog::default();
    let mut host = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![unwind_branch(
        "br",
        RejoinTarget::Next,
        vec![
            scripted_pf(100, "B1", &log, Scripted::Continue, Scripted::Continue),
            scripted_pf(101, "B2", &log, Scripted::Continue, Scripted::Error),
        ],
    )];
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

    let result = pipeline.execute_http_response(&mut ctx).await;

    assert!(
        matches!(&result, Err(e) if e.to_string().contains("scripted error")),
        "the default closed failure mode must propagate a branch filter's on_response error"
    );
    assert_eq!(log.take(), vec!["B2"], "the unwind must stop at a propagated error");
}

#[tokio::test]
async fn branch_filter_on_response_rejection_stops_the_response_phase() {
    let log = HookLog::default();
    let mut host = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![unwind_branch(
        "br",
        RejoinTarget::Next,
        vec![
            scripted_pf(100, "B1", &log, Scripted::Continue, Scripted::Continue),
            scripted_pf(101, "B2", &log, Scripted::Continue, Scripted::Reject),
        ],
    )];
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

    let action = pipeline.execute_http_response(&mut ctx).await.unwrap();

    assert!(
        matches!(&action, FilterAction::Reject(r) if r.status == 418),
        "a branch filter's on_response rejection must reach the caller"
    );
    assert_eq!(log.take(), vec!["B2"], "no hook may run after the rejection");
}

#[tokio::test]
async fn rejecting_branch_filter_runs_on_response_but_unreached_ones_do_not() {
    let log = HookLog::default();
    let mut host = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![unwind_branch(
        "br",
        RejoinTarget::Next,
        vec![
            scripted_pf(100, "B1", &log, Scripted::Reject, Scripted::Continue),
            scripted_pf(101, "B2", &log, Scripted::Continue, Scripted::Continue),
        ],
    )];
    let tail = scripted_pf(1, "C", &log, Scripted::Continue, Scripted::Continue);
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host, tail]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(_)),
        "the branch filter should reject"
    );

    drop(pipeline.execute_http_response(&mut ctx).await.unwrap());
    assert_eq!(
        log.take(),
        vec!["B1", "A"],
        "the rejecting branch filter runs on_response; B2 and C never ran"
    );
}

#[tokio::test]
async fn branch_filter_request_error_pairs_on_response_only_when_fail_open() {
    let log = HookLog::default();
    let mut open = scripted_pf(100, "open", &log, Scripted::Error, Scripted::Continue);
    open.failure_mode = FailureMode::Open;
    let mut host = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![unwind_branch(
        "br",
        RejoinTarget::Next,
        vec![
            open,
            scripted_pf(101, "closed", &log, Scripted::Error, Scripted::Continue),
        ],
    )];
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let result = pipeline.execute_http_request(&mut ctx).await;
    assert!(
        matches!(&result, Err(e) if e.to_string().contains("scripted error")),
        "the closed branch filter's error must propagate"
    );

    drop(pipeline.execute_http_response(&mut ctx).await.unwrap());
    assert_eq!(
        log.take(),
        vec!["open", "A"],
        "a swallowed error counts as executed; a propagated one does not"
    );
}

#[tokio::test]
async fn terminal_branch_unwinds_its_filters_but_not_unreached_ones() {
    let log = HookLog::default();
    let mut host = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![unwind_branch(
        "stop",
        RejoinTarget::Terminal,
        vec![scripted_pf(100, "B1", &log, Scripted::Continue, Scripted::Continue)],
    )];
    let tail = scripted_pf(1, "C", &log, Scripted::Continue, Scripted::Continue);
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host, tail]);

    assert_eq!(
        run_request_then_response(&pipeline, &log, "/").await,
        vec!["B1", "A"],
        "a terminal branch unwinds its own filters; C was never reached"
    );
}

#[tokio::test]
async fn skip_to_branch_unwinds_its_filters_and_skips_bypassed_ones() {
    let log = HookLog::default();
    let mut host = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![unwind_branch(
        "skip",
        RejoinTarget::SkipTo(2),
        vec![scripted_pf(100, "B1", &log, Scripted::Continue, Scripted::Continue)],
    )];
    let bypassed = scripted_pf(1, "skipped", &log, Scripted::Continue, Scripted::Continue);
    let tail = scripted_pf(2, "C", &log, Scripted::Continue, Scripted::Continue);
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host, bypassed, tail]);

    assert_eq!(
        run_request_then_response(&pipeline, &log, "/").await,
        vec!["C", "B1", "A"],
        "SkipTo keeps the branch filters paired and drops the bypassed filter"
    );
}

#[tokio::test]
async fn reentered_branch_filter_runs_on_response_once() {
    let log = HookLog::default();
    let mut branch = unwind_branch(
        "loop",
        RejoinTarget::ReEnter(0),
        vec![scripted_pf(100, "B1", &log, Scripted::Continue, Scripted::Continue)],
    );
    branch.max_iterations = Some(2);
    let mut host = scripted_pf(1, "H", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![branch];
    let head = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![head, host]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());
    assert_eq!(
        ctx.branch_iterations.get("loop"),
        Some(&3),
        "the branch should fire twice and fall through on the third pass"
    );

    drop(pipeline.execute_http_response(&mut ctx).await.unwrap());

    assert_eq!(
        log.take(),
        vec!["B1", "H", "A"],
        "a branch filter re-entered twice must still run on_response once"
    );
}

#[tokio::test]
async fn request_phase_rerun_forgets_earlier_branch_filters() {
    let log = HookLog::default();
    let mut gated = scripted_pf(100, "B1", &log, Scripted::Continue, Scripted::Continue);
    gated.conditions = vec![when_path("/api")];
    let mut host = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![unwind_branch("br", RejoinTarget::Next, vec![gated])];
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host]);
    let api = crate::test_utils::make_request(Method::GET, "/api");
    let other = crate::test_utils::make_request(Method::GET, "/other");
    let mut ctx = crate::test_utils::make_filter_context(&api);
    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());
    ctx.request = &other;
    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

    drop(pipeline.execute_http_response(&mut ctx).await.unwrap());

    assert_eq!(
        log.take(),
        vec!["A"],
        "a rerun request phase must not pair filters only an earlier run executed"
    );
}

#[tokio::test]
async fn branch_filters_skip_on_response_without_a_request_phase() {
    let log = HookLog::default();
    let mut host = scripted_pf(0, "A", &log, Scripted::Continue, Scripted::Continue);
    host.branches = vec![unwind_branch(
        "br",
        RejoinTarget::Next,
        vec![scripted_pf(100, "B1", &log, Scripted::Continue, Scripted::Continue)],
    )];
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(pipeline.execute_http_response(&mut ctx).await.unwrap());

    assert_eq!(
        log.take(),
        vec!["A"],
        "a branch filter whose on_request never ran must not run on_response"
    );
}

#[tokio::test]
async fn branch_filter_state_reaches_its_on_response() {
    let obs: Arc<std::sync::Mutex<Vec<(u64, &'static str)>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut host = PipelineFilter::new(
        0,
        AnyFilter::Http(Box::new(StatefulFilter {
            id: 1,
            observations: Arc::clone(&obs),
        })),
        vec![],
        vec![],
    );
    host.branches = vec![unwind_branch(
        "br",
        RejoinTarget::Next,
        vec![PipelineFilter::new(
            100,
            AnyFilter::Http(Box::new(StatefulFilter {
                id: 2,
                observations: Arc::clone(&obs),
            })),
            vec![],
            vec![],
        )],
    )];
    let pipeline = test_pipeline(BodyCapabilities::default(), vec![host]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(pipeline.execute_http_request(&mut ctx).await.unwrap());

    drop(pipeline.execute_http_response(&mut ctx).await.unwrap());

    assert_eq!(
        obs.lock().unwrap().clone(),
        vec![
            (1, "on_request"),
            (2, "on_request"),
            (2, "on_response"),
            (1, "on_response")
        ],
        "the branch filter's on_response must see its own per-request state"
    );
}

/// Shared log of `on_response` calls, in call order.
#[derive(Clone, Default)]
struct HookLog(Arc<std::sync::Mutex<Vec<&'static str>>>);

impl HookLog {
    /// Drain the recorded labels.
    fn take(&self) -> Vec<&'static str> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

/// How a [`ScriptedFilter`] hook returns.
#[derive(Clone, Copy)]
enum Scripted {
    /// Return `Continue`.
    Continue,

    /// Return an error.
    Error,

    /// Reject with a 418.
    Reject,
}

impl Scripted {
    /// The hook result this script produces.
    fn action(self) -> Result<FilterAction, FilterError> {
        match self {
            Self::Continue => Ok(FilterAction::Continue),
            Self::Error => Err("scripted error".into()),
            Self::Reject => Ok(FilterAction::Reject(crate::Rejection::status(418))),
        }
    }
}

/// Logs its label from `on_response` and returns each hook's scripted outcome.
struct ScriptedFilter {
    label: &'static str,
    log: HookLog,
    request: Scripted,
    response: Scripted,
}

#[async_trait]
impl HttpFilter for ScriptedFilter {
    fn name(&self) -> &'static str {
        self.label
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.request.action()
    }

    async fn on_response(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.log.0.lock().unwrap().push(self.label);
        self.response.action()
    }
}

/// A [`ScriptedFilter`] pipeline entry with the given `filter_id`.
fn scripted_pf(
    filter_id: usize,
    label: &'static str,
    log: &HookLog,
    request: Scripted,
    response: Scripted,
) -> PipelineFilter {
    PipelineFilter::new(
        filter_id,
        AnyFilter::Http(Box::new(ScriptedFilter {
            label,
            log: log.clone(),
            request,
            response,
        })),
        vec![],
        vec![],
    )
}

/// An unconditional branch over `filters` rejoining at `rejoin`.
fn unwind_branch(name: &str, rejoin: RejoinTarget, filters: Vec<PipelineFilter>) -> ResolvedBranch {
    ResolvedBranch {
        condition: None,
        filters,
        max_iterations: None,
        name: Arc::from(name),
        rejoin,
    }
}

/// Run the request phase for `path`, then the response phase, returning
/// the `on_response` log.
async fn run_request_then_response(pipeline: &FilterPipeline, log: &HookLog, path: &str) -> Vec<&'static str> {
    let req = crate::test_utils::make_request(Method::GET, path);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(pipeline.execute_http_request(&mut ctx).await);
    drop(log.take());
    drop(pipeline.execute_http_response(&mut ctx).await.unwrap());
    log.take()
}
