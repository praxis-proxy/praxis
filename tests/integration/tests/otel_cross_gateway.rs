// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]
#![cfg(feature = "otel")]
#![allow(
    clippy::allow_attributes_without_reason,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::clone_on_ref_ptr,
    clippy::cognitive_complexity,
    clippy::default_trait_access,
    clippy::disallowed_methods,
    clippy::doc_markdown,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::items_after_statements,
    clippy::iter_over_hash_type,
    clippy::len_zero,
    clippy::manual_let_else,
    clippy::min_ident_chars,
    clippy::needless_raw_strings,
    clippy::panic,
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::shadow_unrelated,
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::used_underscore_binding,
    reason = "collector-backed integration test"
)]

//! Collector-backed parentage proof across two in-process Praxis proxies.
//!
//! This file is its own test binary because `init_tracing` installs a global
//! subscriber. The local OTLP receiver stores decoded protobuf spans so tests
//! compare exported IDs and parent IDs instead of matching trace IDs alone.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{HeaderMap, Method};
use opentelemetry::trace::TraceContextExt as _;
use opentelemetry_proto::tonic::{
    collector::trace::v1::{
        ExportTraceServiceRequest, ExportTraceServiceResponse,
        trace_service_server::{TraceService, TraceServiceServer},
    },
    trace::v1::{Span, span::SpanKind},
};
use praxis_core::{
    config::Config,
    subrequest::{SubRequest, SubRequestClient, SubRequestConnector},
};
use praxis_test_utils::{
    free_port, http_send, parse_body, parse_status, start_full_proxy, start_header_echo_backend, start_proxy,
    wait_for_tcp,
};
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
    let endpoint = format!("http://127.0.0.1:{collector_port}");
    let provider_config = proxy_config(provider_port, backend.port(), &endpoint, "provider");
    let edge_config = proxy_config(edge_port, provider_port, &endpoint, "edge");
    let routing_edge_config = routing_proxy_config(routing_edge_port, subrequest_backend.port(), &endpoint);
    let tracing_guard = praxis_core::logging::init_tracing(&edge_config).expect("OTLP tracing setup");

    let provider = start_proxy(&provider_config);
    let edge = start_proxy(&edge_config);
    let routing_edge = start_full_proxy(&routing_edge_config);
    wait_for_tcp(routing_edge.addr());

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
    drop(tracing_guard);

    let spans = wait_for_spans(&collector, 27);
    let valid_backend_headers = echoed_headers(&valid_response);
    let absent_backend_headers = echoed_headers(&absent_response);
    let malformed_backend_headers = echoed_headers(&malformed_response);
    let unsampled_backend_headers = echoed_headers(&unsampled_response);
    let routed_backend_headers = echoed_headers(&routed_response);

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
        "collector parentage: valid trace={} edge_server={} parent={} edge_client={} parent={} provider_server={} parent={} provider_client={} parent={} backend_parent={}; routed edge_server={} parent={} step={} parent={} client={} parent={} backend_parent={}; absent trace={} edge_server={} parent={} edge_client={} parent={} provider_server={} parent={} provider_client={} parent={}; malformed trace={} edge_server={} parent={} edge_client={} parent={} provider_server={} parent={} provider_client={} parent={}; unsampled trace omitted; credential/body sentinels absent",
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
        .expect("iterative router step span");
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
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn proxy_config(listener_port: u16, backend_port: u16, endpoint: &str, service_name: &str) -> Config {
    let yaml = format!(
        "listeners:\n  - name: default\n    address: \"127.0.0.1:{listener_port}\"\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n      - filter: trace_context\n      - filter: router\n        routes:\n          - path_prefix: \"/\"\n            cluster: backend\n      - filter: load_balancer\n        clusters:\n          - name: backend\n            endpoints: [\"127.0.0.1:{backend_port}\"]\ninsecure_options:\n  allow_private_endpoints: true\ntelemetry:\n  otlp_endpoint: \"{endpoint}\"\n  service_name: \"{service_name}\"\n  sampling_rate: 1.0\n  batch_size: 512\n  batch_interval_secs: 300\n  otlp_headers:\n    x-api-key: CREDENTIAL_SENTINEL\n"
    );
    Config::from_yaml(&yaml).expect("valid two-proxy test config")
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
