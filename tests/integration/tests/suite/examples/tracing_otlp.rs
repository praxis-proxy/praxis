// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the OTLP tracing example config.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, start_proxy};

#[test]
fn tracing_otlp() {
    let proxy_port = free_port();
    let config = super::load_example_config("observability/tracing-otlp.yaml", proxy_port, HashMap::new());
    let proxy = start_proxy(&config);

    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "proxy with OTLP tracing config should serve requests");
}

#[cfg(feature = "otel")]
mod collector_test {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use opentelemetry_proto::tonic::collector::trace::v1::{
        ExportTraceServiceRequest, ExportTraceServiceResponse,
        trace_service_server::{TraceService, TraceServiceServer},
    };
    use praxis_core::config::Config;
    use praxis_test_utils::{free_port, http_get, start_proxy};

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

        std::thread::sleep(std::time::Duration::from_millis(200));

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

        // Wait for the batch exporter to flush (interval=1s, add margin).
        std::thread::sleep(std::time::Duration::from_secs(3));

        let received = span_count.load(Ordering::Relaxed);
        assert!(
            received > 0,
            "fake collector should have received spans, got {received}"
        );
    }
}
