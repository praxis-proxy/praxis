// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Collector-backed tests for OpenTelemetry propagation across gateway hops.

#![forbid(unsafe_code)]
#![cfg(feature = "otel")]
#![expect(
    clippy::arithmetic_side_effects,
    reason = "collector tests use bounded wall-clock deadlines and duration arithmetic"
)]
#![expect(
    clippy::as_conversions,
    reason = "tests compare protobuf enum discriminants and fixture wire values"
)]
#![expect(
    clippy::cognitive_complexity,
    reason = "each end-to-end scenario asserts a multi-hop trace contract"
)]
#![expect(
    clippy::disallowed_methods,
    reason = "synchronous raw-socket fixtures coordinate delayed network events"
)]
#![expect(
    clippy::expect_used,
    reason = "test setup and assertions fail immediately with contextual diagnostics"
)]
#![expect(
    clippy::panic,
    reason = "trace assertion helpers panic with the captured trace when required spans are missing"
)]
#![expect(
    clippy::print_stdout,
    reason = "one diagnostic prints span IDs to aid local collector-test failures"
)]
#![expect(
    clippy::too_many_lines,
    reason = "collector-backed scenarios keep setup, requests, and exported-span assertions together"
)]
#![expect(
    clippy::used_underscore_binding,
    reason = "underscore-prefixed tracing guards are explicitly dropped to close spans"
)]
//! Collector-backed parentage proof across two in-process Praxis proxies.
//!
//! This file is its own test binary because `init_tracing` installs a global
//! subscriber. The local OTLP receiver stores decoded protobuf spans so tests
//! compare exported IDs and parent IDs instead of matching trace IDs alone.

use std::{
    io::Write as _,
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http::{HeaderMap, Method};
use opentelemetry::trace::TraceContextExt as _;
use opentelemetry_proto::tonic::{
    collector::trace::v1::{
        ExportTraceServiceRequest, ExportTraceServiceResponse,
        trace_service_server::{TraceService, TraceServiceServer},
    },
    common::v1::any_value::Value,
    trace::v1::{Span, span::SpanKind},
};
use praxis_core::{
    config::Config,
    subrequest::{StreamLimits, SubRequest, SubRequestClient, SubRequestConnector},
};
use praxis_test_utils::{
    Backend, free_port, http_send, parse_body, parse_status, read_http_request, spawn_raw_http_backend,
    start_full_proxy, start_header_echo_backend, start_proxy, start_slow_backend, wait_for_tcp,
};
use tracing::Instrument as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

#[derive(Clone, Default)]
struct CapturedSpans {
    requests: Arc<Mutex<Vec<ExportTraceServiceRequest>>>,
}

#[tonic::async_trait]
impl TraceService for CapturedSpans {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.into_inner());
        Ok(tonic::Response::new(ExportTraceServiceResponse {
            partial_success: None,
        }))
    }
}

#[test]
#[expect(
    clippy::tests_outside_test_module,
    reason = "this file is an isolated test binary for the process-global tracing subscriber"
)]
fn exported_parentage_links_edge_provider_and_backend() {
    let collector = CapturedSpans::default();
    let collector_port = free_port();
    let collector_addr: SocketAddr = ([127, 0, 0, 1], collector_port).into();
    let collector_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("collector runtime");
    let collector_service = collector.clone();
    collector_runtime.spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(collector_service))
            .serve(collector_addr)
            .await
            .expect("collector server");
    });
    wait_for_tcp(&format!("127.0.0.1:{collector_port}"));

    let backend = start_header_echo_backend();
    let subrequest_backend = start_header_echo_backend();
    let provider_port = free_port();
    let edge_port = free_port();
    let routing_edge_port = free_port();
    let retry_edge_port = free_port();
    let retry_dead_port = free_port();
    let mid_proxy_failure_port = start_slow_backend("late response", Duration::from_millis(500));
    let mid_proxy_edge_port = free_port();
    let not_found_backend = Backend::status(404, "not found").start_with_shutdown();
    let internal_error_backend = Backend::status(500, "internal error").start_with_shutdown();
    let not_found_edge_port = free_port();
    let internal_error_edge_port = free_port();
    let endpoint = format!("http://127.0.0.1:{collector_port}");
    let provider_config = proxy_config(provider_port, backend.port(), &endpoint, "provider");
    let edge_config = proxy_config(edge_port, provider_port, &endpoint, "edge");
    let routing_edge_config = routing_proxy_config(routing_edge_port, subrequest_backend.port(), &endpoint);
    let retry_edge_config = retry_proxy_config(
        retry_edge_port,
        retry_dead_port,
        backend.port(),
        &endpoint,
        "connect_failure",
    );
    let mid_proxy_edge_config = retry_proxy_config(
        mid_proxy_edge_port,
        mid_proxy_failure_port,
        backend.port(),
        &endpoint,
        "reset",
    );
    let not_found_edge_config = proxy_config(
        not_found_edge_port,
        not_found_backend.port(),
        &endpoint,
        "not-found-edge",
    );
    let internal_error_edge_config = proxy_config(
        internal_error_edge_port,
        internal_error_backend.port(),
        &endpoint,
        "internal-error-edge",
    );
    let tracing_guard = praxis_core::logging::init_tracing(&edge_config).expect("OTLP tracing setup");

    let provider = start_proxy(&provider_config);
    let edge = start_proxy(&edge_config);
    let routing_edge = start_full_proxy(&routing_edge_config);
    let retry_edge = start_proxy(&retry_edge_config);
    let mid_proxy_edge = start_proxy(&mid_proxy_edge_config);
    let not_found_edge = start_proxy(&not_found_edge_config);
    let internal_error_edge = start_proxy(&internal_error_edge_config);
    wait_for_tcp(routing_edge.addr());
    wait_for_tcp(retry_edge.addr());
    wait_for_tcp(mid_proxy_edge.addr());
    wait_for_tcp(not_found_edge.addr());
    wait_for_tcp(internal_error_edge.addr());

    let valid_trace_id = "11111111111111111111111111111111";
    let incoming_parent_id = "2222222222222222";
    let valid_response = send_request(
        edge.addr(),
        Some(&format!("00-{valid_trace_id}-{incoming_parent_id}-01")),
        Some("vendor=trusted"),
    );
    let absent_response = send_request(edge.addr(), None, None);
    let malformed_response = send_request(edge.addr(), Some("not-a-traceparent"), Some("vendor=untrusted"));

    let unsampled_trace_id = "33333333333333333333333333333333";
    let unsampled_response = send_request(
        edge.addr(),
        Some(&format!("00-{unsampled_trace_id}-4444444444444444-00")),
        Some("vendor=unsampled"),
    );
    let routed_trace_id = "55555555555555555555555555555555";
    let routed_response = send_request(
        routing_edge.addr(),
        Some(&format!("00-{routed_trace_id}-6666666666666666-01")),
        Some("vendor=routed"),
    );
    let retry_trace_id = "77777777777777777777777777777777";
    let retry_response = send_retry_request(retry_edge.addr(), &format!("00-{retry_trace_id}-8888888888888888-01"));
    let mid_proxy_trace_id = "99999999999999999999999999999999";
    let mid_proxy_response = send_retry_request(
        mid_proxy_edge.addr(),
        &format!("00-{mid_proxy_trace_id}-aaaaaaaaaaaaaaaa-01"),
    );
    let not_found_trace_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let not_found_status = send_status_request(
        not_found_edge.addr(),
        &format!("00-{not_found_trace_id}-cccccccccccccccc-01"),
    );
    let internal_error_trace_id = "dddddddddddddddddddddddddddddddd";
    let internal_error_status = send_status_request(
        internal_error_edge.addr(),
        &format!("00-{internal_error_trace_id}-eeeeeeeeeeeeeeee-01"),
    );
    assert_eq!(not_found_status, 404, "status backend should return 404");
    assert_eq!(internal_error_status, 500, "status backend should return 500");

    let subrequest_client = SubRequestClient::new(SubRequestConnector::new(2, None));
    let subrequest_peer = pingora_core::upstreams::peer::HttpPeer::new(
        format!("127.0.0.1:{}", subrequest_backend.port()),
        false,
        String::new(),
    );
    let subrequest = SubRequest {
        method: Method::GET,
        uri: "/callout".parse().expect("valid callout URI"),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let subrequest_parent = tracing::info_span!("subrequest_test_parent");
    let subrequest_parent_id = subrequest_parent.context().span().span_context().span_id().to_string();
    let _entered_parent = subrequest_parent.enter();
    let subrequest_response = collector_runtime
        .block_on(subrequest_client.execute(&subrequest_peer, &subrequest, 4096, Duration::from_secs(5), None))
        .expect("framework sub-request");
    drop(_entered_parent);
    let subrequest_headers = echoed_headers(std::str::from_utf8(&subrequest_response.body).expect("header response"));

    assert!(
        collector
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty(),
        "spans should remain buffered until the tracing guard flushes on shutdown"
    );
    drop(edge);
    drop(provider);
    drop(routing_edge);
    drop(retry_edge);
    drop(mid_proxy_edge);
    drop(not_found_edge);
    drop(internal_error_edge);
    drop(not_found_backend);
    drop(internal_error_backend);
    drop(tracing_guard);

    let spans = wait_for_spans(&collector, 41);
    let valid_backend_headers = echoed_headers(&valid_response);
    let absent_backend_headers = echoed_headers(&absent_response);
    let malformed_backend_headers = echoed_headers(&malformed_response);
    let unsampled_backend_headers = echoed_headers(&unsampled_response);
    let routed_backend_headers = echoed_headers(&routed_response);
    let retry_backend_headers = echoed_headers(&retry_response);
    let mid_proxy_backend_headers = echoed_headers(&mid_proxy_response);

    let valid = assert_linked_trace(&spans, valid_trace_id, Some(incoming_parent_id));
    assert_eq!(valid.edge.trace_state, "vendor=trusted");
    assert_eq!(valid.provider.trace_state, "vendor=trusted");
    assert_backend_parent(&valid_backend_headers, valid_trace_id, valid.provider_client);
    assert!(
        header(&valid_backend_headers, "x-api-key").is_none(),
        "collector credentials must not be forwarded to the application backend"
    );
    let (routed_edge, routed_step, routed_client) =
        assert_routed_subrequest_trace(&spans, &routed_backend_headers, routed_trace_id, "6666666666666666");
    assert!(header(&routed_backend_headers, "x-api-key").is_none());
    let retry_trace = spans
        .iter()
        .filter(|span| hex(&span.trace_id) == retry_trace_id)
        .collect::<Vec<_>>();
    let retry_server = retry_trace
        .iter()
        .copied()
        .find(|span| span.kind == SpanKind::Server as i32)
        .expect("retry edge SERVER span");
    let retry_clients = retry_trace
        .iter()
        .copied()
        .filter(|span| span.kind == SpanKind::Client as i32)
        .collect::<Vec<_>>();
    assert_eq!(retry_clients.len(), 2, "one CLIENT span per dial attempt");
    assert!(
        retry_clients
            .iter()
            .all(|span| span.parent_span_id == retry_server.span_id)
    );
    let failed_client = retry_clients
        .iter()
        .copied()
        .find(|span| span.status.as_ref().is_some_and(|status| status.code == 2))
        .expect("failed connection must export an errored CLIENT span");
    let successful_client = retry_clients
        .iter()
        .copied()
        .find(|span| span.span_id != failed_client.span_id)
        .expect("retry must create a fresh successful CLIENT span");
    assert_ne!(failed_client.span_id, successful_client.span_id);
    assert_eq!(
        string_attribute(failed_client, "error.type"),
        Some("connect_refused"),
        "failed connection has a bounded error classification"
    );
    assert_backend_parent(&retry_backend_headers, retry_trace_id, successful_client);

    let mid_proxy_trace = spans
        .iter()
        .filter(|span| hex(&span.trace_id) == mid_proxy_trace_id)
        .collect::<Vec<_>>();
    let mid_proxy_server = mid_proxy_trace
        .iter()
        .copied()
        .find(|span| span.kind == SpanKind::Server as i32)
        .expect("mid-proxy retry edge SERVER span");
    let mid_proxy_clients = mid_proxy_trace
        .iter()
        .copied()
        .filter(|span| span.kind == SpanKind::Client as i32)
        .collect::<Vec<_>>();
    assert_eq!(
        mid_proxy_clients.len(),
        2,
        "mid-proxy failure and retry each export a CLIENT span"
    );
    assert!(
        mid_proxy_clients
            .iter()
            .all(|span| span.parent_span_id == mid_proxy_server.span_id)
    );
    let failed_mid_proxy_client = mid_proxy_clients
        .iter()
        .copied()
        .find(|span| span.status.as_ref().is_some_and(|status| status.code == 2))
        .expect("mid-proxy failure must export an errored CLIENT span");
    let successful_mid_proxy_client = mid_proxy_clients
        .iter()
        .copied()
        .find(|span| span.span_id != failed_mid_proxy_client.span_id)
        .expect("mid-proxy retry must create a fresh CLIENT span");
    assert_eq!(
        string_attribute(failed_mid_proxy_client, "error.type"),
        Some("read_timeout"),
        "mid-proxy error uses a bounded connection error type"
    );
    assert_eq!(
        u16_attribute(failed_mid_proxy_client, "server.port"),
        Some(mid_proxy_failure_port),
        "the failed CLIENT span names the connected but unresponsive endpoint; attrs={:?}",
        failed_mid_proxy_client.attributes
    );
    assert_backend_parent(
        &mid_proxy_backend_headers,
        mid_proxy_trace_id,
        successful_mid_proxy_client,
    );
    assert_exported_http_status(&spans, not_found_trace_id, 404, None);
    assert_exported_http_status(&spans, internal_error_trace_id, 500, Some("500"));

    let absent_id = parent_trace_id(&absent_backend_headers);
    let absent = assert_linked_trace(&spans, &absent_id, None);
    assert_ne!(absent_id, valid_trace_id);
    assert_backend_parent(&absent_backend_headers, &absent_id, absent.provider_client);
    assert!(header(&absent_backend_headers, "tracestate").is_none());

    let malformed_id = parent_trace_id(&malformed_backend_headers);
    let malformed = assert_linked_trace(&spans, &malformed_id, None);
    assert_ne!(malformed_id, valid_trace_id);
    assert_ne!(malformed_id, absent_id);
    assert_backend_parent(&malformed_backend_headers, &malformed_id, malformed.provider_client);
    assert!(header(&malformed_backend_headers, "tracestate").is_none());

    let subrequest_traceparent = header(&subrequest_headers, "traceparent").expect("callout traceparent");
    let subrequest_trace_id = subrequest_traceparent.split('-').nth(1).expect("trace ID");
    let subrequest_span_id = subrequest_traceparent.split('-').nth(2).expect("span ID");
    let subrequest_client_span = spans
        .iter()
        .find(|span| span.kind == SpanKind::Client as i32 && hex(&span.span_id) == subrequest_span_id)
        .expect("exported framework sub-request client span");
    assert_eq!(hex(&subrequest_client_span.trace_id), subrequest_trace_id);
    assert_eq!(hex(&subrequest_client_span.parent_span_id), subrequest_parent_id);

    assert!(
        spans.iter().all(|span| hex(&span.trace_id) != unsampled_trace_id),
        "an unsampled remote parent must not export spans"
    );
    let unsampled_parent = header(&unsampled_backend_headers, "traceparent").expect("forwarded traceparent");
    assert!(unsampled_parent.starts_with(&format!("00-{unsampled_trace_id}-")));
    assert!(unsampled_parent.ends_with("-00"));
    assert_eq!(
        header(&unsampled_backend_headers, "tracestate"),
        Some("vendor=unsampled")
    );

    let collector_dump = format!("{spans:#?}");
    assert!(!collector_dump.contains("PROMPT_SENTINEL"));
    assert!(!collector_dump.contains("CREDENTIAL_SENTINEL"));
    println!(
        "collector parentage: valid trace={} edge_server={} parent={} edge_client={} parent={} provider_server={} parent={} provider_client={} parent={} backend_parent={}; routed edge_server={} parent={} step={} parent={} client={} parent={} backend_parent={}; connect_retry trace={} server={} failed_client={} parent={} successful_client={} parent={} backend_parent={}; mid_proxy_retry trace={} server={} failed_client={} parent={} error_type={} successful_client={} parent={} backend_parent={}; absent trace={} edge_server={} parent={} edge_client={} parent={} provider_server={} parent={} provider_client={} parent={}; malformed trace={} edge_server={} parent={} edge_client={} parent={} provider_server={} parent={} provider_client={} parent={}; unsampled trace omitted; credential/body sentinels absent",
        hex(&valid.edge.trace_id),
        hex(&valid.edge.span_id),
        hex(&valid.edge.parent_span_id),
        hex(&valid.edge_client.span_id),
        hex(&valid.edge_client.parent_span_id),
        hex(&valid.provider.span_id),
        hex(&valid.provider.parent_span_id),
        hex(&valid.provider_client.span_id),
        hex(&valid.provider_client.parent_span_id),
        header(&valid_backend_headers, "traceparent").expect("backend parent traceparent"),
        hex(&routed_edge.span_id),
        hex(&routed_edge.parent_span_id),
        hex(&routed_step.span_id),
        hex(&routed_step.parent_span_id),
        hex(&routed_client.span_id),
        hex(&routed_client.parent_span_id),
        header(&routed_backend_headers, "traceparent").expect("routing backend parent traceparent"),
        retry_trace_id,
        hex(&retry_server.span_id),
        hex(&failed_client.span_id),
        hex(&failed_client.parent_span_id),
        hex(&successful_client.span_id),
        hex(&successful_client.parent_span_id),
        header(&retry_backend_headers, "traceparent").expect("retry backend parent traceparent"),
        mid_proxy_trace_id,
        hex(&mid_proxy_server.span_id),
        hex(&failed_mid_proxy_client.span_id),
        hex(&failed_mid_proxy_client.parent_span_id),
        string_attribute(failed_mid_proxy_client, "error.type").expect("mid-proxy error type"),
        hex(&successful_mid_proxy_client.span_id),
        hex(&successful_mid_proxy_client.parent_span_id),
        header(&mid_proxy_backend_headers, "traceparent").expect("mid-proxy retry backend parent traceparent"),
        absent_id,
        hex(&absent.edge.span_id),
        hex(&absent.edge.parent_span_id),
        hex(&absent.edge_client.span_id),
        hex(&absent.edge_client.parent_span_id),
        hex(&absent.provider.span_id),
        hex(&absent.provider.parent_span_id),
        hex(&absent.provider_client.span_id),
        hex(&absent.provider_client.parent_span_id),
        malformed_id,
        hex(&malformed.edge.span_id),
        hex(&malformed.edge.parent_span_id),
        hex(&malformed.edge_client.span_id),
        hex(&malformed.edge_client.parent_span_id),
        hex(&malformed.provider.span_id),
        hex(&malformed.provider.parent_span_id),
        hex(&malformed.provider_client.span_id),
        hex(&malformed.provider_client.parent_span_id),
    );
}

#[test]
#[expect(
    clippy::tests_outside_test_module,
    reason = "this file is an isolated test binary for the process-global tracing subscriber"
)]
fn sampled_remote_parent_overrides_zero_root_rate() {
    if std::env::var_os("PRAXIS_OTEL_ZERO_RATE_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("sampled_remote_parent_overrides_zero_root_rate")
            .env("PRAXIS_OTEL_ZERO_RATE_CHILD", "1")
            .output()
            .expect("run zero-rate tracing test in a separate process");
        assert!(
            output.status.success(),
            "zero-rate tracing test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("test sampled_remote_parent_overrides_zero_root_rate ... ok"),
            "child test did not execute:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        return;
    }

    let collector = CapturedSpans::default();
    let collector_port = free_port();
    let collector_addr: SocketAddr = ([127, 0, 0, 1], collector_port).into();
    let collector_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("collector runtime");
    let collector_service = collector.clone();
    collector_runtime.spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(collector_service))
            .serve(collector_addr)
            .await
            .expect("collector server");
    });
    wait_for_tcp(&format!("127.0.0.1:{collector_port}"));

    let backend = start_header_echo_backend();
    let provider_port = free_port();
    let edge_port = free_port();
    let endpoint = format!("http://127.0.0.1:{collector_port}");
    let mut edge_config = proxy_config(edge_port, provider_port, &endpoint, "zero-rate-edge");
    edge_config.telemetry.sampling_rate = Some(0.0);
    let provider_config = proxy_config(provider_port, backend.port(), &endpoint, "zero-rate-provider");
    let tracing_guard = praxis_core::logging::init_tracing(&edge_config).expect("OTLP tracing setup");
    let provider = start_proxy(&provider_config);
    let edge = start_proxy(&edge_config);

    let trace_id = "abababababababababababababababab";
    let parent_id = "cdcdcdcdcdcdcdcd";
    let response = send_request(
        edge.addr(),
        Some(&format!("00-{trace_id}-{parent_id}-01")),
        Some("vendor=sampled"),
    );
    let backend_headers = echoed_headers(&response);
    let root_response = send_request(edge.addr(), None, None);
    let root_backend_headers = echoed_headers(&root_response);
    let root_traceparent = header(&root_backend_headers, "traceparent").expect("root context forwarded");
    assert!(
        root_traceparent.ends_with("-00"),
        "zero-rate root must remain unsampled"
    );
    let root_trace_id = parent_trace_id(&root_backend_headers);

    drop(edge);
    drop(provider);
    drop(tracing_guard);

    let spans = wait_for_spans(&collector, 4);
    assert!(
        spans.iter().all(|span| hex(&span.trace_id) != root_trace_id),
        "zero-rate root must not export spans"
    );
    let linked = assert_linked_trace(&spans, trace_id, Some(parent_id));
    assert_backend_parent(&backend_headers, trace_id, linked.provider_client);
    assert_eq!(header(&backend_headers, "tracestate"), Some("vendor=sampled"));
    assert_eq!(hex(&linked.edge.parent_span_id), parent_id);
}

#[test]
#[expect(
    clippy::tests_outside_test_module,
    reason = "this file is an isolated test binary for the process-global tracing subscriber"
)]
fn response_attempt_client_spans_record_final_status_and_actual_close() {
    const CHILD: &str = "PRAXIS_OTEL_SPAN_REGRESSION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("response_attempt_client_spans_record_final_status_and_actual_close")
            .env(CHILD, "1")
            .output()
            .expect("run span regression test in an isolated process");
        assert!(
            output.status.success(),
            "span regression child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("test response_attempt_client_spans_record_final_status_and_actual_close ... ok"),
            "child test did not execute:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        return;
    }

    let collector = CapturedSpans::default();
    let collector_port = free_port();
    let collector_addr: SocketAddr = ([127, 0, 0, 1], collector_port).into();
    let collector_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("collector runtime");
    let collector_service = collector.clone();
    collector_runtime.spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(collector_service))
            .serve(collector_addr)
            .await
            .expect("collector server");
    });
    wait_for_tcp(&format!("127.0.0.1:{collector_port}"));

    let (interim_port, interim_server) = spawn_raw_http_backend(|mut stream| {
        read_http_request(&mut stream);
        stream
            .write_all(
                b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n\
                  HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            )
            .expect("write interim and final response");
    });
    let (headers_sent, headers_received) = mpsc::sync_channel(1);
    let (release_body, body_released) = mpsc::sync_channel(1);
    let (disconnect_port, disconnect_server) = spawn_raw_http_backend(move |mut stream| {
        read_http_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n")
            .expect("write successful upstream response headers");
        stream.flush().expect("flush successful upstream response headers");
        headers_sent.send(()).expect("signal upstream headers sent");
        body_released.recv().expect("wait for downstream disconnect");
        let _write = stream.write_all(&vec![b'x'; 1_048_576]);
    });
    let (timeout_port, timeout_server) = spawn_raw_http_backend(|mut stream| {
        read_http_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n")
            .expect("write response headers before delayed body failure");
        stream.flush().expect("flush response headers");
        thread::sleep(Duration::from_secs(1));
        let _write = stream.write_all(b"late");
    });
    let (step_deadline_port, step_deadline_server) = spawn_raw_http_backend(|mut stream| {
        read_http_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nfirst")
            .expect("write streaming subrequest headers");
        stream.flush().expect("flush streaming subrequest headers");
        thread::sleep(Duration::from_millis(700));
        let _write = stream.write_all(b"late");
    });

    let endpoint = format!("http://127.0.0.1:{collector_port}");
    let config = response_attempt_config(free_port(), interim_port, disconnect_port, timeout_port, &endpoint);
    let tracing_guard = praxis_core::logging::init_tracing(&config).expect("OTLP tracing setup");
    let proxy = start_proxy(&config);
    wait_for_tcp(proxy.addr());

    let interim_trace_id = "10101010101010101010101010101010";
    let interim_response = http_send(
        proxy.addr(),
        &format!(
            "GET /interim HTTP/1.1\r\nHost: localhost\r\ntraceparent: 00-{interim_trace_id}-1111111111111111-01\r\nConnection: close\r\n\r\n"
        ),
    );
    let response_statuses = interim_response
        .lines()
        .filter_map(|line| line.strip_prefix("HTTP/1.1 "))
        .filter_map(|status| status.split_whitespace().next())
        .filter_map(|status| status.parse::<u16>().ok())
        .collect::<Vec<_>>();
    assert_eq!(
        response_statuses,
        [103, 200],
        "raw response must contain interim then final status: {interim_response:?}"
    );

    let disconnect_trace_id = "20202020202020202020202020202020";
    let mut downstream = TcpStream::connect(proxy.addr()).expect("connect downstream client");
    downstream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set downstream read timeout");
    downstream
        .write_all(format!(
            "GET /disconnect HTTP/1.1\r\nHost: localhost\r\ntraceparent: 00-{disconnect_trace_id}-2222222222222222-01\r\nConnection: close\r\n\r\n"
        ).as_bytes())
        .expect("send downstream request");
    headers_received
        .recv_timeout(Duration::from_secs(2))
        .expect("backend sends a successful upstream response");
    drop(downstream);
    release_body
        .send(())
        .expect("allow backend body write after upstream 200 and downstream disconnect");

    let timeout_trace_id = "30303030303030303030303030303030";
    let timeout_request_started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    let timeout_response = http_send(
        proxy.addr(),
        &format!(
            "GET /timeout HTTP/1.1\r\nHost: localhost\r\ntraceparent: 00-{timeout_trace_id}-3333333333333333-01\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(
        parse_status(&timeout_response),
        200,
        "headers precede delayed body timeout"
    );

    let subrequest_client = SubRequestClient::new(SubRequestConnector::new(1, None));
    let subrequest_peer =
        pingora_core::upstreams::peer::HttpPeer::new(format!("127.0.0.1:{step_deadline_port}"), false, String::new());
    let subrequest = SubRequest {
        method: Method::GET,
        uri: "/step-deadline".parse().expect("valid subrequest URI"),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let parent = tracing::info_span!("filtered_subrequest_step");
    let parent_otel_context = parent.context();
    let parent_otel_span = parent_otel_context.span();
    let parent_context = parent_otel_span.span_context();
    let subrequest_trace_id = parent_context.trace_id().to_string();
    let subrequest_parent_id = parent_context.span_id().to_string();
    let (stream_result, step_deadline_unix_nanos) = collector_runtime.block_on(
        async {
            let praxis_core::subrequest::StreamingSubResponse {
                body: mut response_body,
                ..
            } = Box::pin(subrequest_client.send_streaming(
                &subrequest_peer,
                &subrequest,
                Duration::from_secs(3),
                StreamLimits {
                    idle_timeout: Duration::from_secs(5),
                    max_stream_duration: None,
                    max_total_bytes: None,
                },
                None,
            ))
            .await
            .expect("streaming subrequest headers arrive before the filter deadline");
            let first_chunk = response_body
                .next_chunk()
                .await
                .expect("first streaming body chunk arrives")
                .expect("backend sends an initial body chunk");
            assert!(!first_chunk.is_empty(), "initial body chunk is non-empty");
            let deadline = tokio::time::Instant::now() + Duration::from_millis(350);
            let wall_deadline = SystemTime::now() + Duration::from_millis(350);
            let deadline_unix_nanos = u64::try_from(
                wall_deadline
                    .duration_since(UNIX_EPOCH)
                    .expect("deadline after epoch")
                    .as_nanos(),
            )
            .expect("timestamp fits u64 nanoseconds");
            response_body.cap_stream_deadline(deadline);
            (response_body.next_chunk().await, deadline_unix_nanos)
        }
        .instrument(parent),
    );
    assert!(
        matches!(
            stream_result,
            Err(praxis_core::subrequest::SubRequestError::DeadlineExceeded)
        ),
        "filtered step deadline should be reported before an outer cancellation"
    );

    drop(proxy);
    drop(tracing_guard);
    let spans = wait_for_spans(&collector, 8);
    interim_server.join().expect("interim backend exits");
    disconnect_server.join().expect("disconnect backend exits");
    timeout_server.join().expect("timeout backend exits");
    step_deadline_server.join().expect("step-deadline backend exits");

    let interim_client = client_span_for_trace(&spans, interim_trace_id);
    let status_attrs = interim_client
        .attributes
        .iter()
        .filter(|attribute| attribute.key == "http.response.status_code")
        .collect::<Vec<_>>();
    assert_eq!(status_attrs.len(), 1, "CLIENT status is exported once");
    assert_eq!(u16_attribute(interim_client, "http.response.status_code"), Some(200));

    let disconnect_client = client_span_for_trace(&spans, disconnect_trace_id);
    assert!(
        !span_has_error_status(disconnect_client),
        "downstream disconnect is not an upstream CLIENT error"
    );
    assert_eq!(string_attribute(disconnect_client, "error.type"), None);

    let timeout_client = client_span_for_trace(&spans, timeout_trace_id);
    assert!(
        span_has_error_status(timeout_client),
        "upstream body timeout remains a CLIENT error"
    );
    assert_eq!(string_attribute(timeout_client, "error.type"), Some("read_timeout"));
    let close_threshold = u64::try_from(timeout_request_started + 250_000_000).expect("time fits u64 nanoseconds");
    assert!(
        timeout_client.end_time_unix_nano >= close_threshold,
        "CLIENT span must end at delayed body failure, not response headers: start={}, end={}, threshold={close_threshold}",
        timeout_client.start_time_unix_nano,
        timeout_client.end_time_unix_nano
    );

    let step_deadline_client = spans
        .iter()
        .find(|span| {
            hex(&span.trace_id) == subrequest_trace_id
                && span.kind == SpanKind::Client as i32
                && u16_attribute(span, "server.port") == Some(step_deadline_port)
        })
        .expect("streaming subrequest exports its CLIENT span");
    assert_eq!(
        hex(&step_deadline_client.parent_span_id),
        subrequest_parent_id,
        "streaming CLIENT span retains the filtered-step parent"
    );
    assert!(span_has_error_status(step_deadline_client));
    assert_eq!(
        string_attribute(step_deadline_client, "error.type"),
        Some("subrequest_body")
    );
    assert!(
        step_deadline_client.end_time_unix_nano >= step_deadline_unix_nanos,
        "streaming CLIENT span must end after its step deadline: start={}, end={}, deadline={step_deadline_unix_nanos}",
        step_deadline_client.start_time_unix_nano,
        step_deadline_client.end_time_unix_nano
    );
}

fn response_attempt_config(
    listener_port: u16,
    interim_port: u16,
    disconnect_port: u16,
    timeout_port: u16,
    endpoint: &str,
) -> Config {
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{listener_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: trace_context
      - filter: router
        routes:
          - path_prefix: /interim
            cluster: interim
          - path_prefix: /disconnect
            cluster: disconnect
          - path_prefix: /timeout
            cluster: timeout
      - filter: load_balancer
        clusters:
          - name: interim
            endpoints: ["127.0.0.1:{interim_port}"]
          - name: disconnect
            endpoints: ["127.0.0.1:{disconnect_port}"]
          - name: timeout
            endpoints: ["127.0.0.1:{timeout_port}"]
            read_timeout_ms: 350
insecure_options:
  allow_private_endpoints: true
telemetry:
  otlp_endpoint: "{endpoint}"
  service_name: "response-attempt-regression"
  sampling_rate: 1.0
  batch_size: 512
  batch_interval_secs: 300
"#
    );
    Config::from_yaml(&yaml).expect("valid response-attempt regression config")
}

#[cfg(feature = "cloud-events-filter")]
#[test]
#[expect(
    clippy::tests_outside_test_module,
    reason = "this file is an isolated test binary for the process-global tracing subscriber"
)]
fn cloud_events_delivery_keeps_the_request_span_as_parent() {
    const CHILD: &str = "PRAXIS_OTEL_CLOUD_EVENTS_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("cloud_events_delivery_keeps_the_request_span_as_parent")
            .env(CHILD, "1")
            .output()
            .expect("run CloudEvents tracing test in an isolated process");
        assert!(
            output.status.success(),
            "CloudEvents tracing child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("test cloud_events_delivery_keeps_the_request_span_as_parent ... ok"),
            "child test did not execute:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        return;
    }

    let collector = CapturedSpans::default();
    let collector_port = free_port();
    let collector_addr: SocketAddr = ([127, 0, 0, 1], collector_port).into();
    let collector_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("collector runtime");
    let collector_service = collector.clone();
    collector_runtime.spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(collector_service))
            .serve(collector_addr)
            .await
            .expect("collector server");
    });
    wait_for_tcp(&format!("127.0.0.1:{collector_port}"));

    let backend = start_header_echo_backend();
    let (event_received, event_waiter) = mpsc::sync_channel(0);
    let (release_event, event_release) = mpsc::sync_channel(0);
    let (event_finished, event_finish_waiter) = mpsc::sync_channel(0);
    let (event_port, event_receiver) = spawn_raw_http_backend(move |mut stream| {
        read_http_request(&mut stream);
        event_received
            .send(SystemTime::now())
            .expect("signal CloudEvents delivery started");
        event_release.recv().expect("wait before completing delivery");
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .expect("write CloudEvents receiver response");
        event_finished
            .send(SystemTime::now())
            .expect("signal CloudEvents delivery finished");
    });
    let endpoint = format!("http://127.0.0.1:{collector_port}");
    let config = cloud_events_proxy_config(free_port(), backend.port(), event_port, &endpoint, false);
    let tracing_guard = praxis_core::logging::init_tracing(&config).expect("OTLP tracing setup");
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());

    let trace_id = "41414141414141414141414141414141";
    let parent_id = "5151515151515151";
    let response = http_send(
        proxy.addr(),
        &format!(
            "GET /cloud-events HTTP/1.1\r\nHost: localhost\r\ntraceparent: 00-{trace_id}-{parent_id}-01\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(parse_status(&response), 200, "application response is successful");
    let response_received_at = SystemTime::now();
    let event_started_at = event_waiter
        .recv_timeout(Duration::from_secs(3))
        .expect("CloudEvents request reaches the receiver");
    thread::sleep(Duration::from_millis(400));
    release_event.send(()).expect("release delayed CloudEvents response");
    let event_finished_at = event_finish_waiter
        .recv_timeout(Duration::from_secs(3))
        .expect("CloudEvents delivery finishes");

    drop(proxy);
    drop(tracing_guard);
    let spans = wait_for_spans(&collector, 4);
    event_receiver.join().expect("CloudEvents receiver exits");

    let trace_spans = spans
        .iter()
        .filter(|span| hex(&span.trace_id) == trace_id)
        .collect::<Vec<_>>();
    let server = trace_spans
        .iter()
        .copied()
        .find(|span| span.kind == SpanKind::Server as i32 && hex(&span.parent_span_id) == parent_id)
        .expect("request SERVER span with the supplied remote parent");
    let delivery_span = trace_spans
        .iter()
        .copied()
        .find(|span| span.name == "cloud_events.delivery")
        .expect("detached delivery has its own span");
    assert_eq!(
        delivery_span.parent_span_id, server.span_id,
        "detached delivery span is a child of the request SERVER span"
    );
    let delivery_client = trace_spans
        .iter()
        .copied()
        .find(|span| span.kind == SpanKind::Client as i32 && u16_attribute(span, "server.port") == Some(event_port))
        .expect("CloudEvents delivery CLIENT span in the request trace");
    assert_eq!(
        delivery_client.parent_span_id, delivery_span.span_id,
        "CloudEvents delivery CLIENT span is a child of the detached delivery span"
    );
    let response_received_at_nanos = u64::try_from(
        response_received_at
            .duration_since(UNIX_EPOCH)
            .expect("response timestamp after epoch")
            .as_nanos(),
    )
    .expect("timestamp fits u64 nanoseconds");
    let event_started_at_nanos = u64::try_from(
        event_started_at
            .duration_since(UNIX_EPOCH)
            .expect("event timestamp after epoch")
            .as_nanos(),
    )
    .expect("timestamp fits u64 nanoseconds");
    let event_finished_at_nanos = u64::try_from(
        event_finished_at
            .duration_since(UNIX_EPOCH)
            .expect("event timestamp after epoch")
            .as_nanos(),
    )
    .expect("timestamp fits u64 nanoseconds");
    assert!(
        event_finished_at_nanos.saturating_sub(server.end_time_unix_nano) >= 200_000_000,
        "request SERVER span must close independently of the delayed event delivery: response={response_received_at_nanos}, event_started={event_started_at_nanos}, server_end={}, event_end={event_finished_at_nanos}",
        server.end_time_unix_nano
    );
}

#[cfg(feature = "cloud-events-filter")]
#[test]
#[expect(
    clippy::tests_outside_test_module,
    reason = "this file is an isolated test binary for the process-global tracing subscriber"
)]
fn cloud_events_fallback_dispatch_keeps_the_request_span_as_parent() {
    const CHILD: &str = "PRAXIS_OTEL_CLOUD_EVENTS_FALLBACK_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("cloud_events_fallback_dispatch_keeps_the_request_span_as_parent")
            .env(CHILD, "1")
            .output()
            .expect("run fallback CloudEvents tracing test in an isolated process");
        assert!(
            output.status.success(),
            "fallback CloudEvents child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("test cloud_events_fallback_dispatch_keeps_the_request_span_as_parent ... ok"),
            "fallback CloudEvents child did not execute:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        return;
    }

    let collector = CapturedSpans::default();
    let collector_port = free_port();
    let collector_addr: SocketAddr = ([127, 0, 0, 1], collector_port).into();
    let collector_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("collector runtime");
    let collector_service = collector.clone();
    collector_runtime.spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(collector_service))
            .serve(collector_addr)
            .await
            .expect("collector server");
    });
    wait_for_tcp(&format!("127.0.0.1:{collector_port}"));

    let (event_sent, event_waiter) = mpsc::sync_channel(0);
    let (event_port, event_receiver) = spawn_raw_http_backend(move |mut stream| {
        read_http_request(&mut stream);
        event_sent.send(()).expect("signal fallback event delivery");
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .expect("complete fallback CloudEvents delivery");
    });
    let (truncated_port, truncated_receiver) = spawn_raw_http_backend(|mut stream| {
        read_http_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\npartial")
            .expect("write incomplete upstream response body");
    });
    let endpoint = format!("http://127.0.0.1:{collector_port}");
    let config = cloud_events_proxy_config(free_port(), truncated_port, event_port, &endpoint, true);
    let tracing_guard = praxis_core::logging::init_tracing(&config).expect("OTLP tracing setup");
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());

    let trace_id = "61616161616161616161616161616161";
    let parent_id = "7171717171717171";
    let response = http_send(
        proxy.addr(),
        &format!(
            "GET /cloud-events-fallback HTTP/1.1\r\nHost: localhost\r\ntraceparent: 00-{trace_id}-{parent_id}-01\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(parse_status(&response), 200, "upstream headers reached the client");
    truncated_receiver.join().expect("truncated backend exits");
    event_waiter
        .recv_timeout(Duration::from_secs(3))
        .expect("access-log fallback dispatches the deferred CloudEvent");
    event_receiver.join().expect("CloudEvents receiver exits");

    drop(proxy);
    drop(tracing_guard);
    let spans = wait_for_spans(&collector, 4);
    let trace_spans = spans
        .iter()
        .filter(|span| hex(&span.trace_id) == trace_id)
        .collect::<Vec<_>>();
    let server = trace_spans
        .iter()
        .copied()
        .find(|span| span.kind == SpanKind::Server as i32 && hex(&span.parent_span_id) == parent_id)
        .expect("request SERVER span with the supplied remote parent");
    let delivery = trace_spans
        .iter()
        .copied()
        .find(|span| span.name == "cloud_events.delivery")
        .expect("fallback delivery has its own span");
    assert_eq!(
        delivery.parent_span_id, server.span_id,
        "fallback cloud_events.delivery span is a child of the request SERVER span"
    );
    let delivery_client = trace_spans
        .iter()
        .copied()
        .find(|span| span.kind == SpanKind::Client as i32 && u16_attribute(span, "server.port") == Some(event_port))
        .expect("fallback CloudEvents delivery CLIENT span");
    assert_eq!(
        delivery_client.parent_span_id, delivery.span_id,
        "fallback delivery CLIENT span is a child of cloud_events.delivery"
    );
}

#[cfg(feature = "cloud-events-filter")]
fn cloud_events_proxy_config(
    listener_port: u16,
    backend_port: u16,
    event_port: u16,
    endpoint: &str,
    include_access_log: bool,
) -> Config {
    let access_log_filter = if include_access_log {
        "      - filter: access_log\n"
    } else {
        ""
    };
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{listener_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: trace_context
      - filter: cloud_events
        on: response_complete
        destination: "http://127.0.0.1:{event_port}/events"
        source: urn:praxis:test
        type: test.response.completed
{access_log_filter}      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:{backend_port}"]
insecure_options:
  allow_private_endpoints: true
telemetry:
  otlp_endpoint: "{endpoint}"
  service_name: "cloud-events-parentage"
  sampling_rate: 1.0
  batch_size: 512
  batch_interval_secs: 300
"#
    );
    Config::from_yaml(&yaml).expect("valid CloudEvents tracing config")
}

fn client_span_for_trace<'spans>(spans: &'spans [Span], trace_id: &str) -> &'spans Span {
    spans
        .iter()
        .find(|span| hex(&span.trace_id) == trace_id && span.kind == SpanKind::Client as i32)
        .unwrap_or_else(|| panic!("exported CLIENT span missing for trace {trace_id}"))
}

fn string_attribute<'attributes>(span: &'attributes Span, name: &str) -> Option<&'attributes str> {
    span.attributes
        .iter()
        .find(|attribute| attribute.key == name)
        .and_then(|attribute| attribute.value.as_ref())
        .and_then(|value| value.value.as_ref())
        .and_then(|value| match value {
            Value::StringValue(value) => Some(value.as_str()),
            Value::BoolValue(_)
            | Value::IntValue(_)
            | Value::DoubleValue(_)
            | Value::ArrayValue(_)
            | Value::KvlistValue(_)
            | Value::BytesValue(_)
            | Value::StringValueStrindex(_) => None,
        })
}

fn u16_attribute(span: &Span, name: &str) -> Option<u16> {
    span.attributes
        .iter()
        .find(|attribute| attribute.key == name)
        .and_then(|attribute| attribute.value.as_ref())
        .and_then(|value| value.value.as_ref())
        .and_then(|value| match value {
            Value::IntValue(value) => u16::try_from(*value).ok(),
            Value::StringValue(value) => value.parse::<u16>().ok(),
            Value::BoolValue(_)
            | Value::DoubleValue(_)
            | Value::ArrayValue(_)
            | Value::KvlistValue(_)
            | Value::BytesValue(_)
            | Value::StringValueStrindex(_) => None,
        })
}

fn assert_exported_http_status(spans: &[Span], trace_id: &str, status: u16, server_error: Option<&str>) {
    let trace_spans = spans
        .iter()
        .filter(|span| hex(&span.trace_id) == trace_id)
        .collect::<Vec<_>>();
    let server = trace_spans
        .iter()
        .copied()
        .find(|span| span.kind == SpanKind::Server as i32)
        .expect("exported HTTP SERVER span");
    let client = trace_spans
        .iter()
        .copied()
        .find(|span| span.kind == SpanKind::Client as i32)
        .expect("exported HTTP CLIENT span");
    assert_eq!(
        trace_spans
            .iter()
            .filter(|span| span.kind == SpanKind::Server as i32)
            .count(),
        1,
        "status request should produce one SERVER span"
    );
    assert_eq!(
        trace_spans
            .iter()
            .filter(|span| span.kind == SpanKind::Client as i32)
            .count(),
        1,
        "status request should produce one CLIENT span"
    );
    assert_eq!(
        client.parent_span_id, server.span_id,
        "CLIENT belongs to the SERVER request"
    );
    assert_eq!(
        u16_attribute(server, "http.response.status_code"),
        Some(status),
        "exported SERVER span records the response status"
    );
    assert_eq!(
        u16_attribute(client, "http.response.status_code"),
        Some(status),
        "exported CLIENT span records the upstream response status"
    );
    assert!(span_has_error_status(client), "HTTP CLIENT status is exported as Error");
    let client_error_type = status.to_string();
    assert_eq!(
        string_attribute(client, "error.type"),
        Some(client_error_type.as_str()),
        "exported CLIENT span uses the numeric HTTP status as error.type"
    );
    assert_eq!(
        span_has_error_status(server),
        server_error.is_some(),
        "HTTP SERVER status follows the 5xx-only error policy"
    );
    assert_eq!(
        string_attribute(server, "error.type"),
        server_error,
        "SERVER error.type is present for 5xx statuses only"
    );
}

fn span_has_error_status(span: &Span) -> bool {
    span.status.as_ref().is_some_and(|status| status.code == 2)
}

struct LinkedTrace<'spans> {
    edge: &'spans Span,
    edge_client: &'spans Span,
    provider: &'spans Span,
    provider_client: &'spans Span,
}

fn assert_linked_trace<'spans>(
    spans: &'spans [Span],
    trace_id: &str,
    root_parent: Option<&str>,
) -> LinkedTrace<'spans> {
    let trace_spans = spans
        .iter()
        .filter(|span| hex(&span.trace_id) == trace_id)
        .collect::<Vec<_>>();
    let servers = trace_spans
        .iter()
        .copied()
        .filter(|span| span.kind == SpanKind::Server as i32)
        .collect::<Vec<_>>();
    let clients = trace_spans
        .iter()
        .copied()
        .filter(|span| span.kind == SpanKind::Client as i32)
        .collect::<Vec<_>>();

    let edge = servers
        .iter()
        .copied()
        .find(|span| {
            root_parent.map_or(span.parent_span_id.is_empty(), |parent| {
                hex(&span.parent_span_id) == parent
            })
        })
        .expect("edge server span with expected remote/root parent");
    let edge_client = clients
        .iter()
        .copied()
        .find(|span| span.parent_span_id == edge.span_id)
        .expect("edge HTTP client span below edge server");
    let provider = servers
        .iter()
        .copied()
        .find(|span| span.parent_span_id == edge_client.span_id)
        .expect("provider server parent must equal edge client span ID");
    let provider_client = clients
        .iter()
        .copied()
        .find(|span| span.parent_span_id == provider.span_id)
        .expect("provider HTTP client span below provider server");

    for span in [edge, edge_client, provider, provider_client] {
        assert_eq!(span.trace_id, edge.trace_id, "one trace ID across both gateways");
    }
    LinkedTrace {
        edge,
        edge_client,
        provider,
        provider_client,
    }
}

fn assert_backend_parent(headers: &[(String, String)], trace_id: &str, provider_client: &Span) {
    let forwarded = header(headers, "traceparent").expect("backend receives traceparent");
    let expected_span_id = hex(&provider_client.span_id);
    assert_eq!(
        forwarded,
        format!("00-{trace_id}-{expected_span_id}-01"),
        "the backend's parent ID must be the exported provider client span"
    );
}

/// Assert the router step and its outbound client span.
fn assert_routed_subrequest_trace<'spans>(
    spans: &'spans [Span],
    backend_headers: &[(String, String)],
    trace_id: &str,
    remote_parent_id: &str,
) -> (&'spans Span, &'spans Span, &'spans Span) {
    let trace_spans = spans
        .iter()
        .filter(|span| hex(&span.trace_id) == trace_id)
        .collect::<Vec<_>>();
    let edge = trace_spans
        .iter()
        .copied()
        .find(|span| span.kind == SpanKind::Server as i32 && hex(&span.parent_span_id) == remote_parent_id)
        .expect("routed edge server span");
    let step = trace_spans
        .iter()
        .copied()
        .find(|span| span.name == "filtered_subrequest")
        .unwrap_or_else(|| {
            panic!(
                "iterative router step span missing for trace {trace_id}; exported spans: {:?}",
                trace_spans
                    .iter()
                    .map(|span| (
                        span.name.as_str(),
                        hex(&span.trace_id),
                        hex(&span.span_id),
                        hex(&span.parent_span_id)
                    ))
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(
        step.parent_span_id, edge.span_id,
        "routing step is below its HTTP server span"
    );
    let edge_client = trace_spans
        .iter()
        .copied()
        .find(|span| span.kind == SpanKind::Client as i32 && span.parent_span_id == step.span_id)
        .expect("router's outbound HTTP client span");
    let forwarded = header(backend_headers, "traceparent").expect("routing backend receives traceparent");
    assert_eq!(
        forwarded,
        format!("00-{trace_id}-{}-01", hex(&edge_client.span_id)),
        "routing sub-request parent ID is its exported HTTP client span"
    );
    (edge, step, edge_client)
}

fn parent_trace_id(headers: &[(String, String)]) -> String {
    header(headers, "traceparent")
        .and_then(|traceparent| traceparent.split('-').nth(1))
        .expect("traceparent trace ID")
        .to_owned()
}

fn send_request(proxy_addr: &str, traceparent: Option<&str>, tracestate: Option<&str>) -> String {
    let mut headers = String::new();
    if let Some(traceparent) = traceparent {
        headers.push_str("traceparent: ");
        headers.push_str(traceparent);
        headers.push_str("\r\n");
    }
    if let Some(tracestate) = tracestate {
        headers.push_str("tracestate: ");
        headers.push_str(tracestate);
        headers.push_str("\r\n");
    }
    let body = "PROMPT_SENTINEL";
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\n{headers}Authorization: Bearer CREDENTIAL_SENTINEL\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let response = http_send(proxy_addr, &request);
    assert_eq!(parse_status(&response), 200, "both gateways should forward the request");
    parse_body(&response)
}

fn send_retry_request(proxy_addr: &str, traceparent: &str) -> String {
    let request =
        format!("GET /retry HTTP/1.1\r\nHost: localhost\r\ntraceparent: {traceparent}\r\nConnection: close\r\n\r\n");
    let response = http_send(proxy_addr, &request);
    assert_eq!(
        parse_status(&response),
        200,
        "connect retry must reach the live backend"
    );
    parse_body(&response)
}

fn send_status_request(proxy_addr: &str, traceparent: &str) -> u16 {
    let request =
        format!("GET /status HTTP/1.1\r\nHost: localhost\r\ntraceparent: {traceparent}\r\nConnection: close\r\n\r\n");
    parse_status(&http_send(proxy_addr, &request))
}

fn echoed_headers(body: &str) -> Vec<(String, String)> {
    body.lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect()
}

fn header<'headers>(headers: &'headers [(String, String)], name: &str) -> Option<&'headers str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn wait_for_spans(collector: &CapturedSpans, expected: usize) -> Vec<Span> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let requests = collector
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let spans = requests
            .iter()
            .flat_map(|request| &request.resource_spans)
            .flat_map(|resource| &resource.scope_spans)
            .flat_map(|scope| &scope.spans)
            .cloned()
            .collect::<Vec<_>>();
        drop(requests);
        if spans.len() >= expected {
            return spans;
        }
        assert!(
            Instant::now() < deadline,
            "collector received {} spans, expected at least {expected}",
            spans.len()
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn proxy_config(listener_port: u16, backend_port: u16, endpoint: &str, service_name: &str) -> Config {
    let yaml = format!(
        "listeners:\n  - name: default\n    address: \"127.0.0.1:{listener_port}\"\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n      - filter: trace_context\n      - filter: router\n        routes:\n          - path_prefix: \"/\"\n            cluster: backend\n      - filter: load_balancer\n        clusters:\n          - name: backend\n            endpoints: [\"127.0.0.1:{backend_port}\"]\ninsecure_options:\n  allow_private_endpoints: true\ntelemetry:\n  otlp_endpoint: \"{endpoint}\"\n  service_name: \"{service_name}\"\n  sampling_rate: 1.0\n  batch_size: 512\n  batch_interval_secs: 300\n  otlp_headers:\n    x-api-key: CREDENTIAL_SENTINEL\n"
    );
    Config::from_yaml(&yaml).expect("valid two-proxy test config")
}

fn retry_proxy_config(
    listener_port: u16,
    dead_port: u16,
    live_port: u16,
    endpoint: &str,
    retriable_conditions: &str,
) -> Config {
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{listener_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: trace_context
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{dead_port}"
              - "127.0.0.1:{live_port}"
            load_balancer_strategy: round_robin
            read_timeout_ms: 100
            retry_policy:
              max_retries: 1
              retriable_conditions: [{retriable_conditions}]
              backoff:
                base_interval_ms: 1
                max_interval_ms: 5
insecure_options:
  allow_private_endpoints: true
telemetry:
  otlp_endpoint: "{endpoint}"
  service_name: "retry-edge"
  sampling_rate: 1.0
  batch_size: 512
  batch_interval_secs: 300
  otlp_headers:
    x-api-key: CREDENTIAL_SENTINEL
"#
    );
    Config::from_yaml(&yaml).expect("valid retry proxy test config")
}

/// Build an edge config whose iterative-router step calls the provider proxy.
fn routing_proxy_config(listener_port: u16, backend_port: u16, endpoint: &str) -> Config {
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{listener_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: trace_context
      - filter: iterative_request_router
        initial_step: provider
        steps:
          - name: provider
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: provider
              - filter: load_balancer
                clusters:
                  - name: provider
                    endpoints: ["127.0.0.1:{backend_port}"]
            on_result:
              - default: true
                done: true
insecure_options:
  allow_private_endpoints: true
telemetry:
  otlp_endpoint: "{endpoint}"
  service_name: "routing-edge"
  sampling_rate: 1.0
  batch_size: 512
  batch_interval_secs: 300
  otlp_headers:
    x-api-key: CREDENTIAL_SENTINEL
"#
    );
    Config::from_yaml(&yaml).expect("valid routing edge test config")
}
