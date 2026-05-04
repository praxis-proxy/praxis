// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Tests for pipeline construction, body capabilities, execution, and ordering warnings.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use ::http::{HeaderMap, Method, StatusCode};
use async_trait::async_trait;
use bytes::Bytes;
use praxis_core::config::FailureMode;

use super::{FilterPipeline, body::compute_body_capabilities, filter::PipelineFilter};
use crate::{
    FilterAction, FilterEntry, FilterError, FilterRegistry,
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
    let mut router_config = serde_yaml::Mapping::new();
    router_config.insert(
        serde_yaml::Value::String("routes".into()),
        serde_yaml::Value::Sequence(vec![]),
    );
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
fn build_stops_on_first_error() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
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
fn body_capabilities_multiple_stream_buffer_takes_min() {
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
    let mut pipeline = FilterPipeline {
        body_capabilities: caps,
        compression: None,
        filters: vec![],
        health_registry: None,
    };
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
fn apply_body_limits_request_limit_uses_size_limit_mode() {
    let caps = BodyCapabilities::default();
    let mut pipeline = FilterPipeline {
        body_capabilities: caps,
        compression: None,
        filters: vec![],
        health_registry: None,
    };
    pipeline.apply_body_limits(Some(1_048_576), None, false).unwrap();
    let caps = pipeline.body_capabilities();

    assert!(caps.needs_request_body, "request limit should enable request body");
    assert_eq!(
        caps.request_body_mode,
        BodyMode::SizeLimit { max_bytes: 1_048_576 },
        "request limit without body filters should use SizeLimit mode"
    );

    assert!(!caps.needs_response_body, "response side should be untouched");
    assert_eq!(
        caps.response_body_mode,
        BodyMode::Stream,
        "response mode should remain Stream"
    );
}

#[test]
fn apply_body_limits_response_limit_uses_size_limit_mode() {
    let caps = BodyCapabilities::default();
    let mut pipeline = FilterPipeline {
        body_capabilities: caps,
        compression: None,
        filters: vec![],
        health_registry: None,
    };
    pipeline.apply_body_limits(None, Some(524_288), false).unwrap();
    let caps = pipeline.body_capabilities();

    assert!(caps.needs_response_body, "response limit should enable response body");
    assert_eq!(
        caps.response_body_mode,
        BodyMode::SizeLimit { max_bytes: 524_288 },
        "response limit without body filters should use SizeLimit mode"
    );

    assert!(!caps.needs_request_body, "request side should be untouched");
    assert_eq!(
        caps.request_body_mode,
        BodyMode::Stream,
        "request mode should remain Stream"
    );
}

#[test]
fn apply_body_limits_both_applied_independently() {
    let caps = BodyCapabilities::default();
    let mut pipeline = FilterPipeline {
        body_capabilities: caps,
        compression: None,
        filters: vec![],
        health_registry: None,
    };
    pipeline.apply_body_limits(Some(1_024), Some(2_048), false).unwrap();
    let caps = pipeline.body_capabilities();

    assert_eq!(
        caps.request_body_mode,
        BodyMode::SizeLimit { max_bytes: 1_024 },
        "request body limit should use SizeLimit when no body filters"
    );
    assert_eq!(
        caps.response_body_mode,
        BodyMode::SizeLimit { max_bytes: 2_048 },
        "response body limit should use SizeLimit when no body filters"
    );
    assert!(caps.needs_request_body, "request limit should enable request body");
    assert!(caps.needs_response_body, "response limit should enable response body");
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
        config: serde_yaml::from_str("clusters: []").unwrap(),
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries);
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
    let errors = pipeline.ordering_errors(&entries);
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
            config: serde_yaml::from_str("routes: []").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries);
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
    let errors = pipeline.ordering_errors(&entries);
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
            config: serde_yaml::from_str("routes: []").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes: []").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "load_balancer".into(),
            config: serde_yaml::from_str("clusters: []").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries);
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
    let errors = pipeline.ordering_errors(&entries);
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
    let errors = pipeline.ordering_errors(&entries);
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
    let errors = pipeline.ordering_errors(&entries);
    assert!(
        !errors.iter().any(|e| e.contains("security filter")),
        "unconditional security filter should not error: {errors:?}"
    );
}

#[test]
fn empty_pipeline_no_errors() {
    let registry = FilterRegistry::with_builtins();
    let mut entries: Vec<FilterEntry> = vec![];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries);
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
fn warns_router_without_lb() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        conditions: vec![],
        filter_type: "router".into(),
        config: serde_yaml::from_str("routes: []").unwrap(),
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
    let errors = pipeline.ordering_errors(&entries);
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
    let errors = pipeline.ordering_errors(&entries);
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
            config: serde_yaml::from_str("routes: []").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "load_balancer".into(),
            config: serde_yaml::from_str("clusters: []").unwrap(),
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
            config: serde_yaml::from_str("routes: []").unwrap(),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        },
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes: []").unwrap(),
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
async fn response_header_swap_same_count_detected() {
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
        "count-based detection does not catch same-count header swaps"
    );
}

#[test]
fn apply_body_limits_stream_uses_size_limit() {
    let caps = BodyCapabilities::default();
    let mut pipeline = FilterPipeline {
        body_capabilities: caps,
        compression: None,
        filters: vec![],
        health_registry: None,
    };
    pipeline.apply_body_limits(Some(4096), Some(8192), false).unwrap();
    assert_eq!(
        pipeline.body_capabilities().request_body_mode,
        BodyMode::SizeLimit { max_bytes: 4096 },
        "Stream mode should become SizeLimit"
    );
    assert_eq!(
        pipeline.body_capabilities().response_body_mode,
        BodyMode::SizeLimit { max_bytes: 8192 },
        "Stream mode should become SizeLimit"
    );
}

#[test]
fn apply_body_limits_filter_stricter_than_config() {
    let mut caps = BodyCapabilities::default();
    caps.request_body_mode = BodyMode::StreamBuffer { max_bytes: Some(500) };
    caps.needs_request_body = true;
    let mut pipeline = FilterPipeline {
        body_capabilities: caps,
        compression: None,
        filters: vec![],
        health_registry: None,
    };
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
    let mut pipeline = FilterPipeline {
        body_capabilities: caps,
        compression: None,
        filters: vec![],
        health_registry: None,
    };
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
    let mut pipeline = FilterPipeline {
        body_capabilities: caps,
        compression: None,
        filters: vec![],
        health_registry: None,
    };
    let err = pipeline.apply_body_limits(None, None, false).unwrap_err();
    assert!(
        err.to_string().contains("no size limit"),
        "should reject unbounded StreamBuffer: {err}"
    );
}

#[test]
fn apply_body_limits_allows_unbounded_stream_buffer_with_override() {
    let caps = BodyCapabilities {
        request_body_mode: BodyMode::StreamBuffer { max_bytes: None },
        needs_request_body: true,
        ..BodyCapabilities::default()
    };
    let mut pipeline = FilterPipeline {
        body_capabilities: caps,
        compression: None,
        filters: vec![],
        health_registry: None,
    };
    pipeline
        .apply_body_limits(None, None, true)
        .expect("allow_unbounded_body should demote error to warning");
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
    let errors = pipeline.ordering_errors(&entries);
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
    let errors = pipeline.ordering_errors(&entries);
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
    let errors = pipeline.ordering_errors(&entries);
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
    let errors = pipeline.ordering_errors(&entries);
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
    let errors = pipeline.ordering_errors(&entries);
    assert!(
        errors.iter().any(|e| e.contains("rewriting filters")),
        "override on first filter should not suppress error: {errors:?}"
    );
}

#[tokio::test]
async fn skip_to_excludes_skipped_filters_from_response() {
    let log: Arc<std::sync::Mutex<Vec<&'static str>>> = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut filter_a = PipelineFilter::new(
        AnyFilter::Http(Box::new(LoggingFilter {
            label: "A",
            log: Arc::clone(&log),
        })),
        vec![],
        vec![],
    );
    filter_a.branches = vec![super::branch::ResolvedBranch {
        condition: None,
        filters: vec![],
        max_iterations: None,
        name: Arc::from("skip_branch"),
        rejoin: super::branch::RejoinTarget::SkipTo(2),
    }];

    let filter_b = PipelineFilter::new(
        AnyFilter::Http(Box::new(LoggingFilter {
            label: "B",
            log: Arc::clone(&log),
        })),
        vec![],
        vec![],
    );

    let filter_c = PipelineFilter::new(
        AnyFilter::Http(Box::new(LoggingFilter {
            label: "C",
            log: Arc::clone(&log),
        })),
        vec![],
        vec![],
    );

    let pipeline = FilterPipeline {
        body_capabilities: BodyCapabilities::default(),
        compression: None,
        filters: vec![filter_a, filter_b, filter_c],
        health_registry: None,
    };

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
async fn all_executed_filters_run_on_response() {
    let log: Arc<std::sync::Mutex<Vec<&'static str>>> = Arc::new(std::sync::Mutex::new(Vec::new()));

    let pipeline = FilterPipeline {
        body_capabilities: BodyCapabilities::default(),
        compression: None,
        filters: vec![
            PipelineFilter::new(
                AnyFilter::Http(Box::new(LoggingFilter {
                    label: "first",
                    log: Arc::clone(&log),
                })),
                vec![],
                vec![],
            ),
            PipelineFilter::new(
                AnyFilter::Http(Box::new(LoggingFilter {
                    label: "second",
                    log: Arc::clone(&log),
                })),
                vec![],
                vec![],
            ),
        ],
        health_registry: None,
    };

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
async fn skipped_filter_skips_its_branches() {
    let counter = Arc::new(AtomicUsize::new(0));

    let branch_filter = PipelineFilter::new(
        AnyFilter::Http(Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        })),
        vec![],
        vec![],
    );
    let branch = super::branch::ResolvedBranch {
        condition: None,
        filters: vec![branch_filter],
        max_iterations: None,
        name: Arc::from("should_not_fire"),
        rejoin: super::branch::RejoinTarget::Next,
    };

    let mut parent = PipelineFilter::new(
        AnyFilter::Http(Box::new(CountingFilter {
            counter: Arc::new(AtomicUsize::new(0)),
        })),
        vec![when_path("/api")],
        vec![],
    );
    parent.branches = vec![branch];

    let pipeline = FilterPipeline {
        body_capabilities: BodyCapabilities::default(),
        compression: None,
        filters: vec![parent],
        health_registry: None,
    };

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
// Test Utilities
// -----------------------------------------------------------------------------

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

/// Build a [`FilterPipeline`] from the given HTTP filters (no conditions).
fn make_pipeline(filters: Vec<Box<dyn HttpFilter>>) -> FilterPipeline {
    let filters: Vec<_> = filters
        .into_iter()
        .map(|f| PipelineFilter::new(AnyFilter::Http(f), vec![], vec![]))
        .collect();
    let body_capabilities = compute_body_capabilities(&filters);

    FilterPipeline {
        body_capabilities,
        compression: None,
        filters,
        health_registry: None,
    }
}

/// Build a [`FilterPipeline`] with per-filter request conditions.
fn make_pipeline_with_conditions(
    filters: Vec<(Box<dyn HttpFilter>, Vec<praxis_core::config::Condition>)>,
) -> FilterPipeline {
    let filters: Vec<_> = filters
        .into_iter()
        .map(|(f, c)| PipelineFilter::new(AnyFilter::Http(f), c, vec![]))
        .collect();
    let body_capabilities = compute_body_capabilities(&filters);

    FilterPipeline {
        body_capabilities,
        compression: None,
        filters,
        health_registry: None,
    }
}

/// Build a [`FilterPipeline`] with per-filter response conditions.
fn make_pipeline_with_response_conditions(
    filters: Vec<(Box<dyn HttpFilter>, Vec<praxis_core::config::ResponseCondition>)>,
) -> FilterPipeline {
    let filters: Vec<_> = filters
        .into_iter()
        .map(|(f, rc)| PipelineFilter::new(AnyFilter::Http(f), vec![], rc))
        .collect();
    let body_capabilities = compute_body_capabilities(&filters);

    FilterPipeline {
        body_capabilities,
        compression: None,
        filters,
        health_registry: None,
    }
}

/// Build a `When` condition that matches on a path prefix.
fn when_path(prefix: &str) -> praxis_core::config::Condition {
    praxis_core::config::Condition::When(praxis_core::config::ConditionMatch {
        path: None,
        path_prefix: Some(prefix.to_owned()),
        methods: None,
        headers: None,
    })
}

/// Build an `Unless` condition that matches on a path prefix.
fn unless_path(prefix: &str) -> praxis_core::config::Condition {
    praxis_core::config::Condition::Unless(praxis_core::config::ConditionMatch {
        path: None,
        path_prefix: Some(prefix.to_owned()),
        methods: None,
        headers: None,
    })
}

/// Build a `When` response condition that matches on status codes.
fn when_status(codes: &[u16]) -> praxis_core::config::ResponseCondition {
    praxis_core::config::ResponseCondition::When(praxis_core::config::ResponseConditionMatch {
        status: Some(codes.to_vec()),
        headers: None,
    })
}
