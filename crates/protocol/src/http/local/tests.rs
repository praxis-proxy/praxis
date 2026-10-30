// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Instrumented contract tests use the production coordinator and real hooks.

#![expect(
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::significant_drop_tightening,
    reason = "contract test setup and assertions"
)]

#[path = "../../../examples/local_http/context.rs"]
mod context;
#[path = "../../../examples/local_http/handler.rs"]
mod example_handler;
mod support;

use praxis_filter::local_http::*;
use support::*;

use super::*;

#[tokio::test]
async fn unmatched_requests_use_ordinary_proxy_processing() {
    for (method, path) in [
        (http::Method::POST, "/other?path=/files"),
        (http::Method::POST, "/filestore"),
        (http::Method::GET, "/files"),
        (http::Method::HEAD, "/files/child"),
    ] {
        let state = State::default();
        let mut owner = Fixture::owner(state.clone());
        owner.routes.first_mut().unwrap().methods = LocalMethods::Explicit(vec![http::Method::POST]);
        let pipeline = pipeline(vec![owner, Fixture::routing(state.clone())]);
        let request = praxis_filter::Request {
            method,
            uri: path.parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        let mut ctx = context::context(&request, &pipeline);
        assert!(LocalExchange::claim(&pipeline, &mut ctx).is_none());
        ctx.rewritten_path = Some("/files".into());
        assert!(matches!(
            pipeline.execute_http_request_head(&mut ctx).await.unwrap(),
            praxis_filter::FilterAction::Continue
        ));
        assert!(matches!(
            pipeline.execute_http_request(&mut ctx).await.unwrap(),
            praxis_filter::FilterAction::Continue
        ));
        assert!(matches!(
            pipeline.execute_http_response(&mut ctx).await.unwrap(),
            praxis_filter::FilterAction::Continue
        ));
        assert_eq!(
            state.events(),
            [
                "head:owner",
                "head:routing",
                "request:owner",
                "request:routing",
                "response:routing",
                "response:owner",
            ]
        );
        let observed = state.inner.lock().unwrap();
        assert_eq!(observed.upstream_connections, 1);
        assert_eq!(observed.forwarded_bytes, 4);
    }
}

#[tokio::test]
async fn matching_or_claimed_requests_cannot_enter_ordinary_proxy_processing() {
    let state = State::default();
    let local = pipeline(vec![Fixture::owner(state.clone()), Fixture::routing(state.clone())]);
    let proxy = pipeline(vec![Fixture::routing(state.clone())]);
    let request = praxis_filter::Request {
        method: http::Method::POST,
        uri: "/files/child?ignored=1".parse().unwrap(),
        headers: http::HeaderMap::new(),
    };
    for claimed in [false, true] {
        let mut ctx = context::context(&request, &local);
        let pipeline = if claimed {
            drop(LocalExchange::claim(&local, &mut ctx).unwrap());
            &proxy
        } else {
            &local
        };
        ctx.rewritten_path = Some("/other".into());
        assert!(matches!(pipeline.execute_http_request_head(&mut ctx).await.unwrap(),
                praxis_filter::FilterAction::Reject(rejection) if rejection.status == 500));
        assert!(matches!(pipeline.execute_http_request(&mut ctx).await.unwrap(),
                praxis_filter::FilterAction::Reject(rejection) if rejection.status == 500));
        assert!(
            state.events().is_empty(),
            "local ownership must prevent all proxy hooks"
        );
    }
}

#[tokio::test]
async fn claim_policies_and_response_chunks_have_ordered_pairing() {
    let state = State::default();
    let owner = Fixture::owner(state.clone());
    let pipeline = pipeline(vec![
        Fixture::policy("before", state.clone()),
        owner,
        Fixture::routing(state.clone()),
        Fixture::policy("after", state.clone()),
    ]);
    let result = run(
        &pipeline,
        &state,
        Input::bytes(8),
        "/files?ignored=1",
        http::Method::POST,
    )
    .await;
    assert_eq!(result.status, 200);
    assert_eq!(
        state.events(),
        vec![
            "head:before",
            "head:owner",
            "head:after",
            "request:before",
            "request:owner",
            "request:after",
            "factory",
            "handler",
            "accept",
            "read",
            "read",
            "response:after",
            "response:owner",
            "response:before",
            "source",
            "chunk:after",
            "chunk:owner",
            "chunk:before",
            "headers",
            "write",
            "source",
            "chunk:after",
            "chunk:owner",
            "chunk:before",
            "finish",
            "finalize",
            "complete"
        ]
    );
    assert_complete(&state, 1);
    assert_eq!(result.request_bytes, 8);
    assert_eq!(result.response_bytes, 4);
}

#[tokio::test]
async fn later_denial_never_constructs_handler_or_accepts_body() {
    for behavior in [
        Behavior::RejectRequest,
        Behavior::ErrorRequest,
        Behavior::TerminalRequest,
        Behavior::RejectHead,
    ] {
        let state = State::default();
        let mut later = Fixture::policy("later", state.clone());
        later.behavior = behavior;
        let pipeline = pipeline(vec![Fixture::owner(state.clone()), later]);
        let result = run(&pipeline, &state, Input::bytes(8), "/files", http::Method::POST).await;
        assert_eq!(
            result.status,
            if matches!(behavior, Behavior::RejectRequest | Behavior::RejectHead) {
                403
            } else {
                500
            }
        );
        assert!(
            !state
                .events()
                .iter()
                .any(|event| event == "factory" || event == "handler" || event == "accept" || event == "read")
        );
        assert_complete(&state, 0);
    }
}

#[tokio::test]
async fn handler_and_factory_errors_are_local_and_response_filtered() {
    for kind in [HandlerKind::Error, HandlerKind::FactoryError] {
        let state = State::default();
        let mut owner = Fixture::owner(state.clone());
        owner.handler = kind;
        let pipeline = pipeline(vec![
            Fixture::policy("before", state.clone()),
            owner,
            Fixture::policy("after", state.clone()),
        ]);
        let result = run(&pipeline, &state, Input::bytes(1), "/files", http::Method::POST).await;
        assert_eq!(result.status, 500);
        assert!(state.events().contains(&"response:after".into()));
        assert_complete(&state, usize::from(kind != HandlerKind::FactoryError));
    }
}

#[tokio::test]
async fn response_rejection_replaces_without_restarting_or_losing_earlier_headers() {
    let state = State::default();
    let mut later = Fixture::policy("later", state.clone());
    later.behavior = Behavior::RejectResponse;
    let pipeline = pipeline(vec![
        Fixture::policy("before", state.clone()),
        Fixture::owner(state.clone()),
        later,
    ]);
    let result = run(&pipeline, &state, Input::bytes(1), "/files", http::Method::POST).await;
    assert_eq!(result.status, 451);
    assert_eq!(
        state.events().iter().filter(|event| *event == "response:later").count(),
        1
    );
    assert_eq!(state.inner.lock().unwrap().source_cancels, 1);
    assert_complete(&state, 1);
}

#[tokio::test]
async fn generated_512_mib_stream_is_bounded_and_ignores_global_buffer_ceilings() {
    let state = State::default();
    let mut owner = Fixture::owner(state.clone());
    owner.response_bytes = 536_870_912;
    let mut pipeline = build(vec![owner]);
    pipeline
        .apply_body_limits(Some(10_485_760), Some(10_485_760), false)
        .unwrap();
    assert_eq!(pipeline.request_body_ceiling(), Some(10_485_760));
    assert_eq!(praxis_core::config::ABSOLUTE_MAX_BODY_BYTES, 67_108_864);
    let pipeline = Arc::new(pipeline);
    let result = run(
        &pipeline,
        &state,
        Input::generated(536_870_912),
        "/files",
        http::Method::POST,
    )
    .await;
    assert_eq!(result.outcome, LocalOutcome::Completed);
    assert_eq!(result.request_bytes, 536_870_912);
    assert_eq!(result.response_bytes, 536_870_912);
    let inner = state.inner.lock().unwrap();
    assert_eq!(inner.max_chunk, 65_536);
    assert_eq!(inner.completions, 1);
}

#[tokio::test]
async fn exact_limit_and_plus_one_are_enforced_before_handoff_and_after_filtering() {
    for input in [8, 9] {
        let state = State::default();
        let mut owner = Fixture::owner(state.clone());
        owner.routes.get_mut(0).unwrap().request_limit = 8;
        let pipeline = pipeline(vec![owner]);
        let result = run(&pipeline, &state, Input::bytes(input), "/files", http::Method::POST).await;
        assert_eq!(result.status, if input == 8 { 200 } else { 413 });
        assert_complete(&state, 1);
    }
    let state = State::default();
    let mut owner = Fixture::owner(state.clone());
    owner.routes.get_mut(0).unwrap().response_limit = 4;
    let mut expand = Fixture::policy("expand", state.clone());
    expand.behavior = Behavior::ExpandBody;
    let pipeline = pipeline(vec![owner, expand]);
    let result = run(&pipeline, &state, Input::bytes(1), "/files", http::Method::POST).await;
    assert_eq!(result.status, 500);
    assert_eq!(result.outcome, LocalOutcome::LimitExceeded);
    assert_eq!(result.response_bytes, 0);
}

#[test]
fn counter_overflow_is_a_sticky_limit_violation() {
    let mut counter = LocalByteCounter::new(u64::MAX);
    counter.add(u64::MAX).unwrap();
    assert!(counter.add(1).is_err());
    assert_eq!(counter.total(), u64::MAX);
}

#[tokio::test]
async fn source_failure_before_and_after_commit_has_no_second_head() {
    for kind in [HandlerKind::SourceErrorBefore, HandlerKind::SourceErrorAfter] {
        let state = State::default();
        let mut owner = Fixture::owner(state.clone());
        owner.handler = kind;
        let pipeline = pipeline(vec![owner]);
        let result = run(&pipeline, &state, Input::bytes(1), "/files", http::Method::POST).await;
        assert_eq!(result.outcome, LocalOutcome::Failed);
        assert_eq!(
            result.status,
            if kind == HandlerKind::SourceErrorBefore {
                500
            } else {
                200
            }
        );
        assert_eq!(state.events().iter().filter(|event| *event == "headers").count(), 1);
        assert_eq!(state.inner.lock().unwrap().source_cancels, 1);
        assert_complete(&state, 1);
    }
}

#[tokio::test]
async fn precommit_failure_retains_only_applied_policy_headers() {
    for kind in [HandlerKind::SourceErrorBefore, HandlerKind::Consume] {
        let state = State::default();
        let mut owner = Fixture::owner(state.clone());
        owner.handler = kind;
        owner.routes.first_mut().unwrap().response_limit = 1;
        for (name, value) in [
            ("content-encoding", "gzip"),
            ("content-type", "application/gzip"),
            ("content-length", "4"),
            ("transfer-encoding", "chunked"),
            ("etag", "source"),
            ("set-cookie", "source=value"),
            ("x-frame-options", "DENY"),
            ("access-control-allow-origin", "https://client.example"),
        ] {
            owner.response_headers.insert(
                http::header::HeaderName::from_static(name),
                http::HeaderValue::from_static(value),
            );
        }
        let registry = registry(vec![owner]);
        let mut entries: Vec<praxis_filter::FilterEntry> = serde_yaml::from_str(
            r#"
- filter: owner
- filter: cors
  allow_origins: ["https://client.example"]
- filter: headers
  response_set:
    - name: X-Frame-Options
      value: DENY
  response_remove: [Set-Cookie]
"#,
        )
        .unwrap();
        let pipeline = Arc::new(FilterPipeline::build(&mut entries, &registry).unwrap());
        let mut request = praxis_filter::Request {
            method: http::Method::POST,
            uri: "/files".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        request
            .headers
            .insert("origin", http::HeaderValue::from_static("https://client.example"));
        let mut head = Response {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
        };
        let mut ctx = context::context(&request, &pipeline);
        ctx.response_header = Some(&mut head);
        let result = LocalExchange::claim(&pipeline, &mut ctx)
            .unwrap()
            .run(
                &mut ctx,
                &mut Transport {
                    state: state.clone(),
                    input: Input::bytes(1),
                },
            )
            .await;
        assert_eq!(result.status, 500);
        assert_eq!(result.response_bytes, 0);
        assert_eq!(
            result.outcome,
            if kind == HandlerKind::Consume {
                LocalOutcome::LimitExceeded
            } else {
                LocalOutcome::Failed
            }
        );
        let inner = state.inner.lock().unwrap();
        let (status, headers) = inner.head.as_ref().unwrap();
        assert_eq!(*status, 500);
        assert_eq!(
            headers.get("x-frame-options").unwrap(),
            "DENY",
            "explicit unchanged policy writes survive"
        );
        assert_eq!(
            headers.get("access-control-allow-origin").unwrap(),
            "https://client.example"
        );
        for name in [
            "content-encoding",
            "content-type",
            "content-length",
            "transfer-encoding",
            "etag",
            "set-cookie",
        ] {
            assert!(!headers.contains_key(name), "discarded response header: {name}");
        }
        assert_eq!(inner.source_cancels, 1);
        assert_eq!(ctx.response_header.as_deref().unwrap().headers, *headers);
        drop(inner);
        assert_eq!(
            state.events().iter().filter(|event| *event == "response:owner").count(),
            1,
            "error replacement must not rerun response hooks"
        );
        assert!(!state.events().contains(&"write".into()));
        assert_complete(&state, 1);
    }
}

#[tokio::test]
async fn early_response_requires_http1_close_or_http2_stream_termination() {
    let state = State::default();
    let mut owner = Fixture::owner(state.clone());
    owner.handler = HandlerKind::Early;
    let pipeline = pipeline(vec![owner]);
    let result = run(&pipeline, &state, Input::bytes(1), "/files", http::Method::POST).await;
    assert!(!result.request_eof);
    assert!(!state.events().contains(&"accept".into()));
    assert_eq!(state.inner.lock().unwrap().reusable, Some(false));
    assert_complete(&state, 1);
}

#[tokio::test]
async fn suppression_does_not_pull_a_response_source() {
    let state = State::default();
    let pipeline = pipeline(vec![Fixture::owner(state.clone())]);
    let result = run(&pipeline, &state, Input::bytes(1), "/files", http::Method::HEAD).await;
    assert_eq!(result.outcome, LocalOutcome::Suppressed);
    assert!(!state.events().contains(&"source".into()));
    assert_eq!(state.inner.lock().unwrap().suppressed, 1);
    assert_complete(&state, 1);
}

#[tokio::test]
async fn cancellation_interrupts_blocked_response_suppression() {
    for (method, status) in [
        (http::Method::HEAD, 200),
        (http::Method::GET, 204),
        (http::Method::GET, 304),
    ] {
        let state = State::default();
        let mut owner = Fixture::owner(state.clone());
        owner.handler = HandlerKind::SuppressWait;
        owner.response_status = status;
        let pipeline = pipeline(vec![owner]);
        let request = praxis_filter::Request {
            method,
            uri: "/files".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        let mut head = Response {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
        };
        let mut ctx = context::context(&request, &pipeline);
        ctx.response_header = Some(&mut head);
        let exchange = LocalExchange::claim(&pipeline, &mut ctx).unwrap();
        let cancellation = exchange.cancellation();
        let cancel = async {
            while state.inner.lock().unwrap().suppressed == 0 {
                tokio::task::yield_now().await;
            }
            cancellation.cancel();
        };
        let mut transport = Transport {
            state: state.clone(),
            input: Input::bytes(1),
        };
        let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::join!(exchange.run(&mut ctx, &mut transport), cancel)
        })
        .await
        .unwrap();
        assert_eq!(result.outcome, LocalOutcome::Cancelled);
        assert!(!result.committed);
        assert_eq!(result.response_bytes, 0);
        assert!(!state.events().contains(&"source".into()));
        assert!(state.events().contains(&"abort".into()));
        assert!(praxis_filter::access_record_already_emitted(&ctx));
        let inner = state.inner.lock().unwrap();
        assert_eq!(inner.suppressed, 1);
        assert_eq!(inner.source_cancels, 1);
        assert_eq!(inner.finalizations, [LocalOutcome::Cancelled]);
        drop(inner);
        assert_complete(&state, 1);
    }
}

#[test]
fn mandatory_build_validation_rejects_all_unsafe_compositions() {
    let state = State::default();
    let owner = Fixture::owner(state.clone());
    let mut variants = Vec::new();
    let mut fail = owner.clone();
    fail.routes.get_mut(0).unwrap().body = LocalBodyOwnership::Unspecified;
    variants.push(fail);
    let mut fail = owner.clone();
    fail.routes.get_mut(0).unwrap().request_limit = 0;
    variants.push(fail);
    let mut fail = owner.clone();
    fail.routes.get_mut(0).unwrap().response_limit = 0;
    variants.push(fail);
    let mut fail = owner.clone();
    fail.routes.get_mut(0).unwrap().methods = LocalMethods::Explicit(vec![]);
    variants.push(fail);
    let mut fail = owner.clone();
    fail.routes.get_mut(0).unwrap().path = LocalPath::Exact("/files?query".into());
    variants.push(fail);
    let mut fail = owner.clone();
    fail.compatibility = LocalCompatibility::Unsupported;
    variants.push(fail);
    let mut fail = owner.clone();
    fail.request_access = praxis_filter::BodyAccess::ReadOnly;
    variants.push(fail);
    let mut fail = owner.clone();
    fail.selected_access = praxis_filter::BodyAccess::ReadWrite;
    variants.push(fail);
    let mut fail = owner.clone();
    fail.response_mode = praxis_filter::BodyMode::StreamBuffer { max_bytes: Some(1024) };
    variants.push(fail);
    for fixture in variants {
        let mut entries = entries(&["owner"]);
        let registry = registry(vec![fixture]);
        assert!(FilterPipeline::build(&mut entries, &registry).is_err());
    }
    for yaml in [
        "filter: owner\nfailure_mode: open",
        "filter: owner\nconditions:\n- when:\n    selected_upstream:\n      application_protocol: test",
        "filter: owner\nconditions:\n- unless:\n    bound_upstream:\n      application_protocol: test",
    ] {
        let mut entries = vec![serde_yaml::from_str(yaml).unwrap()];
        assert!(
            FilterPipeline::build(&mut entries, &registry(vec![owner.clone()])).is_err(),
            "{yaml}"
        );
    }
    let mut conditional = Fixture::policy("conditional", state);
    conditional.request_access = praxis_filter::BodyAccess::ReadOnly;
    let mut entries: Vec<praxis_filter::FilterEntry> = serde_yaml::from_str(
        "- filter: owner\n- filter: conditional\n  conditions:\n  - when:\n      path: /unrelated",
    )
    .unwrap();
    assert!(
        FilterPipeline::build(&mut entries, &registry(vec![owner, conditional])).is_err(),
        "conditional consumers are potentially reachable"
    );
}

#[test]
fn exact_prefix_and_method_overlap_has_no_precedence() {
    for (left, right, overlaps) in [
        (
            LocalPath::Exact("/files".into()),
            LocalPath::Exact("/files".into()),
            true,
        ),
        (
            LocalPath::Exact("/files/id".into()),
            LocalPath::SegmentPrefix("/files".into()),
            true,
        ),
        (
            LocalPath::SegmentPrefix("/files/".into()),
            LocalPath::SegmentPrefix("/files/id".into()),
            true,
        ),
        (
            LocalPath::SegmentPrefix("/".into()),
            LocalPath::SegmentPrefix("/files".into()),
            true,
        ),
        (
            LocalPath::SegmentPrefix("/files".into()),
            LocalPath::Exact("/filestore".into()),
            false,
        ),
    ] {
        let state = State::default();
        let mut owner = Fixture::owner(state);
        owner.routes.get_mut(0).unwrap().path = left;
        let mut other = owner.routes.first().unwrap().clone();
        other.id = "other".into();
        other.path = right;
        owner.routes.push(other);
        let result = FilterPipeline::build(&mut entries(&["owner"]), &registry(vec![owner]));
        assert_eq!(result.is_err(), overlaps);
    }
    let mut owner = Fixture::owner(State::default());
    owner.routes.get_mut(0).unwrap().methods = LocalMethods::Explicit(vec![http::Method::POST]);
    let mut other = owner.routes.first().unwrap().clone();
    other.id = "get".into();
    other.methods = LocalMethods::Explicit(vec![http::Method::GET]);
    owner.routes.push(other);
    FilterPipeline::build(&mut entries(&["owner"]), &registry(vec![owner])).unwrap();
}

#[tokio::test]
async fn declared_length_rejection_sends_no_interim_or_service_work() {
    let state = State::default();
    let pipeline = pipeline(vec![Fixture::owner(state.clone())]);
    let mut request = praxis_filter::Request {
        method: http::Method::POST,
        uri: "/files".parse().unwrap(),
        headers: http::HeaderMap::new(),
    };
    request
        .headers
        .insert("content-length", http::HeaderValue::from_static("536870913"));
    request
        .headers
        .insert("expect", http::HeaderValue::from_static("100-continue"));
    let mut head = Response {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
    };
    let mut ctx = context::context(&request, &pipeline);
    ctx.response_header = Some(&mut head);
    let exchange = LocalExchange::claim(&pipeline, &mut ctx).unwrap();
    let result = exchange
        .run(
            &mut ctx,
            &mut Transport {
                state: state.clone(),
                input: Input::bytes(1),
            },
        )
        .await;
    assert_eq!(result.status, 413);
    assert!(!state.events().contains(&"factory".into()));
    assert!(!state.events().contains(&"accept".into()));
    assert_complete(&state, 0);
}

#[tokio::test]
async fn disconnect_and_external_cancellation_finalize_once() {
    for disconnect in [false, true] {
        let state = State::default();
        let pipeline = pipeline(vec![Fixture::owner(state.clone())]);
        let request = praxis_filter::Request {
            method: http::Method::POST,
            uri: "/files".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        let mut head = Response {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
        };
        let mut ctx = context::context(&request, &pipeline);
        ctx.response_header = Some(&mut head);
        let exchange = LocalExchange::claim(&pipeline, &mut ctx).unwrap();
        if disconnect {
            state.inner.lock().unwrap().write_mode = WriteMode::Disconnected;
        } else {
            state.inner.lock().unwrap().cancel_on_write = Some(exchange.cancellation());
        }
        let result = exchange
            .run(
                &mut ctx,
                &mut Transport {
                    state: state.clone(),
                    input: Input::bytes(1),
                },
            )
            .await;
        assert_eq!(
            result.outcome,
            if disconnect {
                LocalOutcome::Failed
            } else {
                LocalOutcome::Cancelled
            }
        );
        assert!(state.events().contains(&"abort".into()));
        assert_eq!(state.inner.lock().unwrap().source_cancels, 1);
        assert_complete(&state, 1);
    }
}

#[tokio::test]
async fn cancellation_interrupts_blocked_handler_and_drop_only_signals() {
    let state = State::default();
    let mut owner = Fixture::owner(state.clone());
    owner.handler = HandlerKind::Wait;
    let pipeline = pipeline(vec![owner]);
    let request = praxis_filter::Request {
        method: http::Method::POST,
        uri: "/files".parse().unwrap(),
        headers: http::HeaderMap::new(),
    };
    let mut head = Response {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
    };
    let mut ctx = context::context(&request, &pipeline);
    ctx.response_header = Some(&mut head);
    let exchange = LocalExchange::claim(&pipeline, &mut ctx).unwrap();
    let signal = exchange.cancellation();
    let cancel = async {
        tokio::task::yield_now().await;
        signal.cancel();
    };
    let mut transport = Transport {
        state: state.clone(),
        input: Input::bytes(1),
    };
    let (result, ()) = tokio::join!(exchange.run(&mut ctx, &mut transport), cancel);
    assert_eq!(result.outcome, LocalOutcome::Cancelled);
    assert_complete(&state, 1);
    let mut fresh = context::context(&request, &pipeline);
    let exchange = LocalExchange::claim(&pipeline, &mut fresh).unwrap();
    let signal = exchange.cancellation();
    drop(exchange);
    assert!(signal.is_cancelled());
    signal.cancel();
    signal.cancel();
    signal.cancelled().await;
    assert_eq!(
        state.inner.lock().unwrap().finalizations.len(),
        1,
        "Drop cannot await finalization"
    );
}

#[tokio::test]
async fn swallowed_request_fault_still_fails_closed_and_dropped_chunks_are_not_eof() {
    let state = State::default();
    let mut owner = Fixture::owner(state.clone());
    owner.handler = HandlerKind::SwallowRead;
    state.inner.lock().unwrap().fail_read = true;
    let pipeline = pipeline(vec![owner]);
    let result = run(&pipeline, &state, Input::bytes(1), "/files", http::Method::POST).await;
    assert_eq!(result.status, 500);
    assert_complete(&state, 1);
    let state = State::default();
    let mut dropper = Fixture::policy("dropper", state.clone());
    dropper.behavior = Behavior::DropBody;
    let mut owner = Fixture::owner(state.clone());
    owner.response_bytes = 131_072;
    let pipeline = support::pipeline(vec![owner, dropper]);
    let result = run(&pipeline, &state, Input::bytes(1), "/files", http::Method::POST).await;
    assert_eq!(result.response_bytes, 0);
    assert_eq!(
        state.events().iter().filter(|event| *event == "source").count(),
        3,
        "dropped chunks must not terminate delivery"
    );
}

#[tokio::test]
async fn claims_pin_generation_and_repeated_claims_poison_both_owners() {
    let old = State::default();
    let new = State::default();
    let original = pipeline(vec![Fixture::owner(old.clone())]);
    let swap = arc_swap::ArcSwap::from(Arc::clone(&original));
    let request = praxis_filter::Request {
        method: http::Method::POST,
        uri: "/files".parse().unwrap(),
        headers: http::HeaderMap::new(),
    };
    let mut head = Response {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
    };
    let mut ctx = context::context(&request, &original);
    ctx.response_header = Some(&mut head);
    let exchange = LocalExchange::claim(&swap.load_full(), &mut ctx).unwrap();
    swap.store(pipeline(vec![Fixture::owner(new.clone())]));
    ctx.rewritten_path = Some("/elsewhere".into());
    let result = exchange
        .run(
            &mut ctx,
            &mut Transport {
                state: old.clone(),
                input: Input::bytes(1),
            },
        )
        .await;
    assert_eq!(result.status, 200);
    assert!(new.events().is_empty());
    assert_complete(&old, 1);
    let mut ctx = context::context(&request, &original);
    ctx.response_header = Some(&mut head);
    let first = LocalExchange::claim(&original, &mut ctx).unwrap();
    let second = LocalExchange::claim(&swap.load_full(), &mut ctx).unwrap();
    drop(second);
    let result = first
        .run(
            &mut ctx,
            &mut Transport {
                state: old.clone(),
                input: Input::bytes(1),
            },
        )
        .await;
    assert_eq!(result.status, 500);
    assert_eq!(old.events().iter().filter(|event| *event == "handler").count(), 1);
}

#[tokio::test]
async fn compiled_minimal_example_runs_through_the_contract() {
    let mut registry = praxis_filter::FilterRegistry::with_builtins();
    registry
        .register(
            "upload_count",
            praxis_filter::FilterFactory::Http(Arc::new(|_| Ok(Box::new(example_handler::UploadCount::default())))),
        )
        .unwrap();
    let pipeline = Arc::new(FilterPipeline::build(&mut entries(&["upload_count"]), &registry).unwrap());
    let state = State::default();
    let result = run(&pipeline, &state, Input::bytes(9), "/count", http::Method::POST).await;
    assert_eq!(result.status, 200);
    assert_eq!(result.response_bytes, 1);
    assert_eq!(result.request_bytes, 9);
    assert_complete(&state, 0);
    assert!(
        require_supported_adapter(&pipeline).is_err(),
        "neither live adapter may install local routes"
    );
    require_supported_adapter(&FilterPipeline::build(&mut [], &registry).unwrap()).unwrap();
}

#[tokio::test]
async fn cors_and_configured_security_headers_cover_success_denial_and_handler_error() {
    for behavior in [Behavior::Pass, Behavior::RejectRequest, Behavior::ErrorRequest] {
        let state = State::default();
        let owner = Fixture::owner(state.clone());
        let mut later = Fixture::policy("later", state.clone());
        later.behavior = behavior;
        let registry = registry(vec![owner, later]);
        let mut entries: Vec<praxis_filter::FilterEntry> = serde_yaml::from_str(
            r#"
- filter: cors
  allow_origins: ["https://client.example"]
- filter: headers
  response_set:
    - name: X-Content-Type-Options
      value: nosniff
- filter: owner
- filter: later
"#,
        )
        .unwrap();
        let pipeline = Arc::new(FilterPipeline::build(&mut entries, &registry).unwrap());
        let mut request = praxis_filter::Request {
            method: http::Method::POST,
            uri: "/files".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        request
            .headers
            .insert("origin", http::HeaderValue::from_static("https://client.example"));
        let mut head = Response {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
        };
        let mut ctx = context::context(&request, &pipeline);
        ctx.response_header = Some(&mut head);
        let exchange = LocalExchange::claim(&pipeline, &mut ctx).unwrap();
        exchange
            .run(
                &mut ctx,
                &mut Transport {
                    state: state.clone(),
                    input: Input::bytes(1),
                },
            )
            .await;
        let inner = state.inner.lock().unwrap();
        let (_, headers) = inner.head.as_ref().unwrap();
        assert_eq!(
            headers.get("access-control-allow-origin").unwrap(),
            "https://client.example"
        );
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    }
}

#[tokio::test]
async fn allowed_options_preflight_keeps_permissions_through_local_exchange() {
    let state = State::default();
    let registry = registry(vec![Fixture::owner(state.clone())]);
    let mut entries: Vec<praxis_filter::FilterEntry> = serde_yaml::from_str(
        r#"
- filter: cors
  allow_origins: ["https://client.example"]
  allow_methods: [POST]
  allow_headers: [x-custom]
  allow_credentials: true
  max_age: 600
  allow_private_network: true
- filter: owner
"#,
    )
    .unwrap();
    let pipeline = Arc::new(FilterPipeline::build(&mut entries, &registry).unwrap());
    let mut request = praxis_filter::Request {
        method: http::Method::OPTIONS,
        uri: "/files".parse().unwrap(),
        headers: http::HeaderMap::new(),
    };
    request
        .headers
        .insert("origin", http::HeaderValue::from_static("https://client.example"));
    request
        .headers
        .insert("access-control-request-method", http::HeaderValue::from_static("POST"));
    request.headers.insert(
        "access-control-request-headers",
        http::HeaderValue::from_static("x-custom"),
    );
    request.headers.insert(
        "access-control-request-private-network",
        http::HeaderValue::from_static("true"),
    );
    let mut head = Response {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
    };
    let mut ctx = context::context(&request, &pipeline);
    ctx.response_header = Some(&mut head);
    let result = LocalExchange::claim(&pipeline, &mut ctx)
        .unwrap()
        .run(
            &mut ctx,
            &mut Transport {
                state: state.clone(),
                input: Input::bytes(0),
            },
        )
        .await;

    assert_eq!(result.status, 204);
    assert_eq!(result.outcome, LocalOutcome::PolicyDenied);
    let inner = state.inner.lock().unwrap();
    let (status, headers) = inner.head.as_ref().unwrap();
    assert_eq!(*status, 204);
    assert_eq!(
        headers.get("access-control-allow-origin").unwrap(),
        "https://client.example"
    );
    assert_eq!(headers.get("access-control-allow-methods").unwrap(), "POST");
    assert_eq!(headers.get("access-control-allow-headers").unwrap(), "x-custom");
    assert_eq!(headers.get("access-control-allow-credentials").unwrap(), "true");
    assert_eq!(headers.get("access-control-max-age").unwrap(), "600");
    assert_eq!(headers.get("access-control-allow-private-network").unwrap(), "true");
    drop(inner);
    assert_complete(&state, 0);
}

#[tokio::test]
async fn access_logging_is_once_and_honors_scope_and_emit_conditions() {
    for (scope, emit, expected) in [("/files", "[2xx]", 1), ("/files", "[4xx]", 0), ("/other", "[2xx]", 0)] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("access.jsonl");
        let state = State::default();
        let registry = registry(vec![Fixture::owner(state.clone())]);
        let yaml = format!(
            "- filter: access_log\n  conditions:\n    status_classes: {emit}\n  sink:\n    type: file\n    path: '{}'\n- filter: owner",
            path.display()
        );
        let mut entries: Vec<praxis_filter::FilterEntry> = serde_yaml::from_str(&yaml).unwrap();
        entries.first_mut().unwrap().conditions =
            serde_yaml::from_str(&format!("- when:\n    path_prefix: {scope}")).unwrap();
        let pipeline = Arc::new(FilterPipeline::build(&mut entries, &registry).unwrap());
        run(&pipeline, &state, Input::bytes(1), "/files", http::Method::POST).await;
        // The configured file sink flushes in its writer task.
        let mut lines = 0;
        for _attempt in 0..20 {
            lines = std::fs::read_to_string(&path).unwrap_or_default().lines().count();
            if lines == expected {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(
            lines, expected,
            "local completion must retain configured logging eligibility"
        );
        assert_complete(&state, 1);
    }
}

#[test]
fn branch_chains_are_rejected_even_with_every_validation_override() {
    let state = State::default();
    let registry = registry(vec![Fixture::owner(state), Fixture::policy("nested", State::default())]);
    let mut entries: Vec<praxis_filter::FilterEntry> = serde_yaml::from_str(
        "
- filter: owner
  branch_chains:
    - name: nested
      chains: [child]
",
    )
    .unwrap();
    let child = support::entries(&["nested"]);
    let chains = std::collections::HashMap::from([("child", child.as_slice())]);
    let insecure = praxis_core::config::InsecureOptions {
        skip_pipeline_validation: true,
        skip_pipeline_checks: praxis_core::config::SkipPipelineChecks::all(),
        ..Default::default()
    };
    assert!(FilterPipeline::build(&mut entries.clone(), &registry).is_err());
    assert!(FilterPipeline::build_with_chains(&mut entries, &registry, &chains, &insecure).is_err());
}

#[tokio::test]
async fn already_applied_cors_and_security_policies_survive_response_replacement() {
    let state = State::default();
    let mut owner = Fixture::owner(state.clone());
    owner.behavior = Behavior::RejectResponse;
    owner
        .response_headers
        .insert("x-frame-options", http::HeaderValue::from_static("DENY"));
    owner.response_headers.insert(
        "access-control-allow-origin",
        http::HeaderValue::from_static("https://client.example"),
    );
    owner
        .response_headers
        .insert("x-service-secret", http::HeaderValue::from_static("private"));
    let registry = registry(vec![owner]);
    let mut entries: Vec<praxis_filter::FilterEntry> = serde_yaml::from_str(
        r#"
- filter: owner
- filter: cors
  allow_origins: ["https://client.example"]
- filter: headers
  response_set:
    - name: X-Frame-Options
      value: DENY
"#,
    )
    .unwrap();
    let pipeline = Arc::new(FilterPipeline::build(&mut entries, &registry).unwrap());
    let mut request = praxis_filter::Request {
        method: http::Method::POST,
        uri: "/files".parse().unwrap(),
        headers: http::HeaderMap::new(),
    };
    request
        .headers
        .insert("origin", http::HeaderValue::from_static("https://client.example"));
    let mut head = Response {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
    };
    let mut ctx = context::context(&request, &pipeline);
    ctx.response_header = Some(&mut head);
    LocalExchange::claim(&pipeline, &mut ctx)
        .unwrap()
        .run(
            &mut ctx,
            &mut Transport {
                state: state.clone(),
                input: Input::bytes(1),
            },
        )
        .await;
    let inner = state.inner.lock().unwrap();
    let (status, headers) = inner.head.as_ref().unwrap();
    assert_eq!(*status, 451);
    assert_eq!(
        headers.get("access-control-allow-origin").unwrap(),
        "https://client.example"
    );
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert!(!headers.contains_key("x-service-secret"));
    drop(inner);
    assert_complete(&state, 1);
}

#[tokio::test]
async fn downstream_backpressure_prevents_a_second_source_pull() {
    let state = State::default();
    state.inner.lock().unwrap().write_mode = WriteMode::Blocked;
    let mut owner = Fixture::owner(state.clone());
    owner.response_bytes = 131_072;
    let pipeline = pipeline(vec![owner]);
    let request = praxis_filter::Request {
        method: http::Method::POST,
        uri: "/files".parse().unwrap(),
        headers: http::HeaderMap::new(),
    };
    let mut head = Response {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
    };
    let mut ctx = context::context(&request, &pipeline);
    ctx.response_header = Some(&mut head);
    let exchange = LocalExchange::claim(&pipeline, &mut ctx).unwrap();
    let cancellation = exchange.cancellation();
    let observe = async {
        while !state.events().contains(&"write".into()) {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            state.events().iter().filter(|event| *event == "source").count(),
            1,
            "no speculative response pull during a blocked write"
        );
        cancellation.cancel();
    };
    let mut transport = Transport {
        state: state.clone(),
        input: Input::bytes(1),
    };
    let (result, ()) = tokio::join!(exchange.run(&mut ctx, &mut transport), observe);
    assert_eq!(result.outcome, LocalOutcome::Cancelled);
    assert_complete(&state, 1);
}

#[tokio::test]
async fn unexpected_body_terminal_fails_after_commit_even_for_open_policies() {
    let state = State::default();
    let mut owner = Fixture::owner(state.clone());
    owner.response_bytes = 131_072;
    let mut policy = Fixture::policy("terminal_policy", state.clone());
    policy.behavior = Behavior::TerminalBody;
    let registry = registry(vec![owner, policy]);
    let mut entries = entries(&["owner", "terminal_policy"]);
    entries.get_mut(1).unwrap().failure_mode = praxis_filter::FailureMode::Open;
    let pipeline = Arc::new(FilterPipeline::build(&mut entries, &registry).unwrap());
    let result = run(&pipeline, &state, Input::bytes(1), "/files", http::Method::POST).await;
    assert_eq!(result.status, 200);
    assert_eq!(result.outcome, LocalOutcome::Failed);
    assert_eq!(result.response_bytes, 65_536);
    assert!(state.events().contains(&"abort".into()));
    assert_complete(&state, 1);
}

#[tokio::test]
async fn header_policies_see_facts_promoted_by_earlier_head_hooks() {
    let state = State::default();
    let mut promoter = Fixture::policy("promoter", state.clone());
    promoter.behavior = Behavior::PromoteHead;
    let mut deny = Fixture::policy("deny", state.clone());
    deny.behavior = Behavior::RejectRequest;
    let registry = registry(vec![promoter, Fixture::owner(state.clone()), deny]);
    let mut entries = entries(&["promoter", "owner", "deny"]);
    entries.get_mut(2).unwrap().conditions =
        serde_yaml::from_str("- when:\n    headers:\n      x-praxis-approved: yes").unwrap();
    let pipeline = Arc::new(FilterPipeline::build(&mut entries, &registry).unwrap());
    let result = run(&pipeline, &state, Input::bytes(1), "/files", http::Method::POST).await;
    assert_eq!(result.status, 403);
    assert!(!state.events().contains(&"handler".into()));
    assert_complete(&state, 0);
}

#[tokio::test]
async fn reentrant_claims_from_policies_and_handlers_fail_closed() {
    for behavior in [
        Behavior::ReclaimRequest,
        Behavior::ReclaimResponse,
        Behavior::ReclaimBody,
    ] {
        let state = State::default();
        let mut later = Fixture::policy("later", state.clone());
        later.behavior = behavior;
        let registry = registry(vec![Fixture::owner(state.clone()), later]);
        let mut entries = entries(&["owner", "later"]);
        entries.get_mut(1).unwrap().failure_mode = praxis_core::config::FailureMode::Open;
        let pipeline = Arc::new(FilterPipeline::build(&mut entries, &registry).unwrap());
        state.inner.lock().unwrap().pipeline = Some(Arc::downgrade(&pipeline));
        let result = run(&pipeline, &state, Input::bytes(1), "/files", http::Method::POST).await;
        assert_eq!(result.status, 500, "{behavior:?}");
        let handler_count = usize::from(!matches!(behavior, Behavior::ReclaimRequest));
        assert_complete(&state, handler_count);
        assert_eq!(
            state.events().iter().filter(|event| *event == "handler").count(),
            handler_count
        );
    }
    let state = State::default();
    let mut owner = Fixture::owner(state.clone());
    owner.handler = HandlerKind::Reclaim;
    let pipeline = pipeline(vec![owner]);
    state.inner.lock().unwrap().pipeline = Some(Arc::downgrade(&pipeline));
    let result = run(&pipeline, &state, Input::bytes(1), "/files", http::Method::POST).await;
    assert_eq!(result.status, 500);
    assert_complete(&state, 1);
}
