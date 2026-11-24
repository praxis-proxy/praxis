// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Collector-backed proof that policy request metadata joins the exported trace.
//!
//! The proxy under test runs without a `trace_context` filter, so the only
//! source the policy filter can read a trace ID from is the exported root
//! request span: a rule pinned to the joined inbound trace proves the span's
//! trace ID reaches `request.trace_id`, and the collector proves the same ID
//! is the one a tracing backend would export.
//!
//! The scenario runs in a child copy of this test binary, mirroring
//! `otlp_exporter.rs`: the child installs the process-global tracing
//! subscriber, serves the requests, and exits; its orderly shutdown flushes
//! the spans to the parent's collector, so the parent asserts on spans only
//! after the child process has fully exited.

#![forbid(unsafe_code)]
#![cfg(all(feature = "otel", feature = "policy-engine"))]
#![expect(
    clippy::as_conversions,
    reason = "span-kind assertions compare protobuf enum discriminants"
)]
#![expect(
    clippy::expect_used,
    reason = "test setup and assertions fail immediately with contextual diagnostics"
)]

use std::{
    process::Command,
    sync::{Arc, Mutex},
};

use opentelemetry_proto::tonic::{
    collector::trace::v1::{
        ExportTraceServiceRequest, ExportTraceServiceResponse,
        trace_service_server::{TraceService, TraceServiceServer},
    },
    trace::v1::{Span, span::SpanKind},
};
use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_send, parse_status, start_header_echo_backend, start_proxy, wait_for_tcp};

/// Environment variable selecting child mode in the spawned test process.
const CHILD_MODE_ENV: &str = "PRAXIS_POLICY_METADATA_TEST_CHILD";
/// Environment variable carrying the collector endpoint to the child.
const CHILD_ENDPOINT_ENV: &str = "PRAXIS_POLICY_METADATA_TEST_ENDPOINT";

/// Trace ID the allowed request joins through its inbound `traceparent`.
const ALLOWED_TRACE: &str = "11111111111111111111111111111111";
/// Trace ID the denied request joins; the policy rule pins the allowed one.
const DENIED_TRACE: &str = "22222222222222222222222222222222";

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
fn policy_request_trace_id_joins_the_exported_span_trace() {
    if std::env::var(CHILD_MODE_ENV).is_ok() {
        run_child_scenario();
        return;
    }

    let (collector, collector_port, _collector_runtime) = start_collector();
    let output = run_child(&format!("http://127.0.0.1:{collector_port}"));
    assert!(
        output.status.success(),
        "isolated policy metadata scenario failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let spans = flattened_spans(&collector);
    let trace_ids = spans.iter().map(|span| hex(&span.trace_id)).collect::<Vec<_>>();
    assert!(
        spans
            .iter()
            .any(|span| hex(&span.trace_id) == ALLOWED_TRACE && span.kind == SpanKind::Server as i32),
        "the allowed request's SERVER span must export the joined trace: {trace_ids:?}"
    );
    assert!(
        spans
            .iter()
            .any(|span| hex(&span.trace_id) == DENIED_TRACE && span.kind == SpanKind::Server as i32),
        "the denied request's SERVER span must export its joined trace too: {trace_ids:?}"
    );
}

/// Serve both requests and assert both policy outcomes, in a clean process.
///
/// Dropping the tracing guard at the end of this function flushes the buffered
/// spans to the parent's collector before the child exits.
fn run_child_scenario() {
    let endpoint = std::env::var(CHILD_ENDPOINT_ENV).expect("collector endpoint");
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let (_policy_dir, config) = proxy_config(proxy_port, backend.port(), &endpoint);
    let tracing_guard = praxis_core::logging::init_tracing(&config).expect("OTLP tracing setup");
    let proxy = start_proxy(&config);
    wait_for_tcp(proxy.addr());

    let allowed = send(proxy.addr(), ALLOWED_TRACE, "3333333333333333");
    assert_eq!(
        parse_status(&allowed),
        200,
        "the policy rule must see the span's joined trace ID: {allowed}"
    );
    assert!(
        allowed.contains(ALLOWED_TRACE),
        "the forwarded traceparent must carry the joined trace: {allowed}"
    );

    let denied = send(proxy.addr(), DENIED_TRACE, "4444444444444444");
    assert_eq!(
        parse_status(&denied),
        403,
        "a request joining any other trace must fail the pinned rule: {denied}"
    );

    drop(proxy);
    drop(tracing_guard);
}

/// Run the scenario in a child copy of this test binary and wait for its exit.
fn run_child(endpoint: &str) -> std::process::Output {
    Command::new(std::env::current_exe().expect("test executable path"))
        .args([
            "--exact",
            "policy_request_trace_id_joins_the_exported_span_trace",
            "--nocapture",
        ])
        .env(CHILD_MODE_ENV, "1")
        .env(CHILD_ENDPOINT_ENV, endpoint)
        .output()
        .expect("run isolated policy metadata child test")
}

/// Serve the span-collecting OTLP receiver and return it with its port.
///
/// The returned runtime keeps the receiver alive; dropping it stops the
/// collector before the exported spans arrive.
fn start_collector() -> (CapturedSpans, u16, tokio::runtime::Runtime) {
    let collector = CapturedSpans::default();
    let collector_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("collector runtime");

    let (listener, port) = praxis_test_utils::bind_unique_port();
    listener.set_nonblocking(true).expect("nonblocking collector");
    let listener = {
        let _entered = collector_runtime.enter();
        tokio::net::TcpListener::from_std(listener).expect("collector listener")
    };

    let collector_service = collector.clone();
    collector_runtime.spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(collector_service))
            .serve_with_incoming(tonic::transport::server::TcpIncoming::from(listener))
            .await
            .expect("collector server");
    });
    wait_for_tcp(&format!("127.0.0.1:{port}"));
    (collector, port, collector_runtime)
}

/// Send one request joining the given trace through its inbound `traceparent`.
fn send(addr: &str, trace_id: &str, span_id: &str) -> String {
    http_send(
        addr,
        &format!(
            "GET / HTTP/1.1\r\nHost: localhost\r\nTraceparent: 00-{trace_id}-{span_id}-01\r\nConnection: close\r\n\r\n"
        ),
    )
}

/// Build a proxy with a policy chain but no `trace_context` filter.
///
/// Without `trace_context`, no filter-level `TraceContext` exists, so
/// `request.trace_id` can only come from the exported request span's ID.
fn proxy_config(listener_port: u16, backend_port: u16, endpoint: &str) -> (tempfile::TempDir, Config) {
    let dir = tempfile::TempDir::new().expect("policy directory");
    let policy_path = dir.path().join("policy.yaml");
    std::fs::write(
        &policy_path,
        format!(
            "engine_settings:\n  dispatch: policy\nglobal:\n  authorization:\n    pre_invocation:\n      - \"require(request.trace_id == '{ALLOWED_TRACE}')\"\n"
        ),
    )
    .expect("write policy");
    let yaml = format!(
        "listeners:\n  - name: default\n    address: \"127.0.0.1:{listener_port}\"\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n      - filter: policy\n        config_path: {}\n      - filter: router\n        routes:\n          - path_prefix: /\n            cluster: backend\n      - filter: load_balancer\n        clusters:\n          - name: backend\n            endpoints: [\"127.0.0.1:{backend_port}\"]\ninsecure_options:\n  allow_private_endpoints: true\ntelemetry:\n  otlp_endpoint: \"{endpoint}\"\n  service_name: \"policy-request-metadata\"\n  sampling_rate: 1.0\n  batch_size: 512\n  batch_interval_secs: 300\n",
        policy_path.to_str().expect("UTF-8 policy path")
    );
    (
        dir,
        Config::from_yaml(&yaml).expect("valid policy metadata test config"),
    )
}

/// Lowercase hex of an exported protobuf ID field.
fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Decode every span the collector received so far.
fn flattened_spans(collector: &CapturedSpans) -> Vec<Span> {
    collector
        .requests
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .flat_map(|request| &request.resource_spans)
        .flat_map(|resource| &resource.scope_spans)
        .flat_map(|scope| &scope.spans)
        .cloned()
        .collect()
}
