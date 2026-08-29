// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! OTLP span-export integration test.
//!
//! This test installs a process-global tracing subscriber (via
//! `praxis_core::logging::init_tracing`) to drive the OTLP batch exporter, so
//! it runs as its own test binary instead of inside the shared `suite`
//! process. There, `init_tracing`'s `set_global_default` would redirect every
//! other suite test's spans into this collector (and could not coexist with a
//! second global subscriber), and the batch exporter would keep trying to reach
//! the dropped collector for the rest of the run.

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
    clippy::doc_nested_refdefs,
    clippy::expect_used,
    clippy::format_push_string,
    clippy::indexing_slicing,
    clippy::iter_over_hash_type,
    clippy::items_after_statements,
    clippy::len_zero,
    clippy::manual_is_multiple_of,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::map_with_unused_argument_over_ranges,
    clippy::min_ident_chars,
    clippy::needless_raw_string_hashes,
    clippy::needless_raw_strings,
    clippy::panic,
    clippy::print_stderr,
    clippy::redundant_closure_for_method_calls,
    clippy::shadow_unrelated,
    clippy::single_char_lifetime_names,
    clippy::string_add,
    clippy::struct_field_names,
    clippy::tests_outside_test_module,
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::used_underscore_binding,
    clippy::useless_format,
    clippy::wildcard_enum_match_arm,
    reason = "test code"
)]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
    trace_service_server::{TraceService, TraceServiceServer},
};
use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_proxy, wait_for_tcp};

struct FakeCollector {
    span_count: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl TraceService for FakeCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        let msg = request.into_inner();
        let count: usize = msg
            .resource_spans
            .iter()
            .flat_map(|rs| &rs.scope_spans)
            .map(|ss| ss.spans.len())
            .sum();
        self.span_count.fetch_add(count, Ordering::Relaxed);
        Ok(tonic::Response::new(ExportTraceServiceResponse {
            partial_success: None,
        }))
    }
}

#[test]
fn otlp_exporter_delivers_spans() {
    let collector_port = free_port();
    let span_count = Arc::new(AtomicUsize::new(0));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let collector = FakeCollector {
        span_count: Arc::clone(&span_count),
    };
    let addr: std::net::SocketAddr = ([127, 0, 0, 1], collector_port).into();
    rt.spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(collector))
            .serve(addr)
            .await
            .expect("collector server");
    });

    wait_for_tcp(&format!("127.0.0.1:{collector_port}"));

    let proxy_port = free_port();
    let yaml = format!(
        "\
listeners:
  - name: default
    address: \"127.0.0.1:{proxy_port}\"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: request_id
      - filter: static_response
        status: 200
telemetry:
  otlp_endpoint: \"http://127.0.0.1:{collector_port}\"
  sampling_rate: 1.0
  batch_size: 1
  batch_interval_secs: 1
"
    );
    let config = Config::from_yaml(&yaml).expect("parse inline OTLP config");

    let _tracing_guard = praxis_core::logging::init_tracing(&config).expect("init tracing with OTLP");

    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200);

    // Poll for the batch exporter's flush (interval=1s) instead of a
    // fixed sleep so the test passes as soon as spans land.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while span_count.load(Ordering::Relaxed) == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let received = span_count.load(Ordering::Relaxed);
    assert!(
        received > 0,
        "fake collector should have received spans within 10s, got {received}"
    );
}
