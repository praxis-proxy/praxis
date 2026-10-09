// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! OTLP span-export integration tests.
//!
//! These tests install a process-global tracing subscriber. The outer test
//! therefore launches each exporter scenario in a child copy of this test
//! binary, isolating both the subscriber and process-wide certificate-root
//! environment from other integration tests.

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

use std::{
    fs,
    net::SocketAddr,
    path::Path,
    process::{Command, Output},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
    trace_service_client::TraceServiceClient,
    trace_service_server::{TraceService, TraceServiceServer},
};
use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get,
    net::tls::{TestCertificates, ensure_crypto_provider},
    start_proxy, wait_for_tcp,
};
use tonic::transport::{Identity, ServerTlsConfig};

const CHILD_MODE_ENV: &str = "PRAXIS_OTLP_EXPORTER_TEST_CHILD";
const CHILD_ENDPOINT_ENV: &str = "PRAXIS_OTLP_EXPORTER_TEST_ENDPOINT";
const CHILD_TLS_ERROR_ENV: &str = "PRAXIS_OTLP_EXPORTER_TEST_TLS_ERROR";
const TEST_AUTHORIZATION: &str = "Bearer otlp-test-credential-do-not-log";

enum TrustSource<'a> {
    None,
    File(&'a Path),
    Directory(&'a Path),
}

struct ChildScenario<'a> {
    mode: &'a str,
    endpoint: Option<&'a str>,
    trust_source: TrustSource<'a>,
    generic_insecure: Option<&'a str>,
    traces_insecure: Option<&'a str>,
    expected_tls_error: Option<&'a str>,
}

#[derive(Default)]
struct CollectorState {
    span_count: AtomicUsize,
    request_count: AtomicUsize,
    saw_authorization: AtomicBool,
    saw_expected_authorization: AtomicBool,
}

struct FakeCollector {
    state: Arc<CollectorState>,
}

#[tonic::async_trait]
impl TraceService for FakeCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        self.state.request_count.fetch_add(1, Ordering::Relaxed);
        let authorization = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok());
        if authorization.is_some() {
            self.state.saw_authorization.store(true, Ordering::Relaxed);
        }
        if authorization == Some(TEST_AUTHORIZATION) {
            self.state.saw_expected_authorization.store(true, Ordering::Relaxed);
        }

        let message = request.into_inner();
        let count: usize = message
            .resource_spans
            .iter()
            .flat_map(|resource| &resource.scope_spans)
            .map(|scope| scope.spans.len())
            .sum();
        self.state.span_count.fetch_add(count, Ordering::Relaxed);
        Ok(tonic::Response::new(ExportTraceServiceResponse {
            partial_success: None,
        }))
    }
}

fn start_collector(
    runtime: &tokio::runtime::Runtime,
    certificates: Option<&TestCertificates>,
) -> (u16, Arc<CollectorState>) {
    let port = free_port();
    let state = Arc::new(CollectorState::default());
    let collector = FakeCollector {
        state: Arc::clone(&state),
    };
    let address: SocketAddr = ([127, 0, 0, 1], port).into();

    let server = tonic::transport::Server::builder();
    let mut server = if let Some(certificates) = certificates {
        let certificate = fs::read(&certificates.cert_path).expect("read test collector certificate");
        let private_key = fs::read(&certificates.key_path).expect("read test collector key");
        let identity = Identity::from_pem(certificate, private_key);
        server
            .tls_config(ServerTlsConfig::new().identity(identity))
            .expect("configure verified-TLS test collector")
    } else {
        server
    };

    runtime.spawn(async move {
        server
            .add_service(TraceServiceServer::new(collector))
            .serve(address)
            .await
            .expect("serve OTLP test collector");
    });
    wait_for_tcp(&format!("127.0.0.1:{port}"));
    (port, state)
}

/// Run one scenario in a clean test process and return its captured output.
fn run_child(scenario: &ChildScenario<'_>) -> String {
    let mut command = Command::new(std::env::current_exe().expect("test executable path"));
    command
        .args(["--exact", "otlp_exporter_tls_and_plaintext_contract", "--nocapture"])
        .env(CHILD_MODE_ENV, scenario.mode)
        .env_remove(CHILD_ENDPOINT_ENV)
        .env_remove(CHILD_TLS_ERROR_ENV)
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_CERT_DIR")
        .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT")
        .env_remove("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .env_remove("OTEL_EXPORTER_OTLP_PROTOCOL")
        .env_remove("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
        .env_remove("OTEL_EXPORTER_OTLP_HEADERS")
        .env_remove("OTEL_EXPORTER_OTLP_TRACES_HEADERS")
        .env_remove("OTEL_EXPORTER_OTLP_INSECURE")
        .env_remove("OTEL_EXPORTER_OTLP_TRACES_INSECURE");

    if let Some(endpoint) = scenario.endpoint {
        command.env(CHILD_ENDPOINT_ENV, endpoint);
    }
    match scenario.trust_source {
        TrustSource::None => {},
        TrustSource::File(file) => {
            command.env("SSL_CERT_FILE", file);
        },
        TrustSource::Directory(directory) => {
            command.env("SSL_CERT_DIR", directory);
        },
    }
    if let Some(value) = scenario.generic_insecure {
        command.env("OTEL_EXPORTER_OTLP_INSECURE", value);
    }
    if let Some(value) = scenario.traces_insecure {
        command.env("OTEL_EXPORTER_OTLP_TRACES_INSECURE", value);
    }
    if let Some(expected) = scenario.expected_tls_error {
        command.env(CHILD_TLS_ERROR_ENV, expected);
    }

    let output = command.output().expect("run isolated OTLP child test");
    let text = captured_output(&output);
    assert!(
        !text.contains(TEST_AUTHORIZATION),
        "test credential leaked into child output"
    );
    assert!(
        output.status.success(),
        "isolated OTLP scenario {} failed: {text}",
        scenario.mode
    );
    text
}

fn captured_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_no_export(state: &CollectorState, context: &str) {
    assert_eq!(
        state.request_count.load(Ordering::Relaxed),
        0,
        "{context}: collector must not receive an RPC"
    );
    assert_eq!(
        state.span_count.load(Ordering::Relaxed),
        0,
        "{context}: collector must not receive spans"
    );
}

#[test]
fn otlp_exporter_tls_and_plaintext_contract() {
    if let Ok(mode) = std::env::var(CHILD_MODE_ENV) {
        run_exporter_child(&mode);
        return;
    }

    ensure_crypto_provider();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("collector runtime");

    let trusted_certificates = TestCertificates::generate();
    let unrelated_certificates = TestCertificates::generate_for_san("localhost");
    let wrong_name_certificates = TestCertificates::generate_for_san("collector.invalid");

    let (trusted_file_port, trusted_file_state) = start_collector(&runtime, Some(&trusted_certificates));
    let (trusted_dir_port, trusted_dir_state) = start_collector(&runtime, Some(&trusted_certificates));
    let (untrusted_port, untrusted_state) = start_collector(&runtime, Some(&unrelated_certificates));
    let (wrong_name_port, wrong_name_state) = start_collector(&runtime, Some(&wrong_name_certificates));
    let (http_port, http_state) = start_collector(&runtime, None);

    let trusted_output = run_child(&ChildScenario {
        mode: "trusted-file",
        endpoint: Some(&format!("https://localhost:{trusted_file_port}")),
        trust_source: TrustSource::File(&trusted_certificates.ca_cert_path),
        generic_insecure: Some("false"),
        traces_insecure: Some("true"),
        expected_tls_error: None,
    });
    assert!(
        trusted_file_state.span_count.load(Ordering::Relaxed) > 0,
        "trusted HTTPS collector received no spans during orderly shutdown"
    );
    assert!(
        trusted_file_state.saw_expected_authorization.load(Ordering::Relaxed),
        "trusted HTTPS collector did not receive the configured authorization metadata"
    );
    assert!(trusted_file_state.saw_authorization.load(Ordering::Relaxed));
    assert!(!trusted_output.contains(TEST_AUTHORIZATION));

    let cert_directory = tempfile::tempdir().expect("certificate directory");
    fs::copy(
        &trusted_certificates.ca_cert_path,
        cert_directory.path().join("trusted-ca.pem"),
    )
    .expect("copy test CA into native-root directory");
    let directory_output = run_child(&ChildScenario {
        mode: "trusted-directory",
        endpoint: Some(&format!("localhost:{trusted_dir_port}")),
        trust_source: TrustSource::Directory(cert_directory.path()),
        generic_insecure: Some("true"),
        traces_insecure: Some("false"),
        expected_tls_error: None,
    });
    assert!(
        trusted_dir_state.span_count.load(Ordering::Relaxed) > 0,
        "collector trusted through SSL_CERT_DIR received no spans"
    );
    assert!(!directory_output.contains(TEST_AUTHORIZATION));

    let untrusted_output = run_child(&ChildScenario {
        mode: "untrusted-ca",
        endpoint: Some(&format!("https://localhost:{untrusted_port}")),
        trust_source: TrustSource::File(&trusted_certificates.ca_cert_path),
        generic_insecure: None,
        traces_insecure: None,
        expected_tls_error: Some("UnknownIssuer"),
    });
    assert_no_export(&untrusted_state, "untrusted CA");
    assert!(untrusted_output.contains("certificate_rejection=UnknownIssuer"));

    let wrong_name_output = run_child(&ChildScenario {
        mode: "wrong-hostname",
        endpoint: Some(&format!("https://localhost:{wrong_name_port}")),
        trust_source: TrustSource::File(&wrong_name_certificates.ca_cert_path),
        generic_insecure: None,
        traces_insecure: None,
        expected_tls_error: Some("certificate not valid for name"),
    });
    assert_no_export(&wrong_name_state, "wrong hostname");
    assert!(wrong_name_output.contains("certificate_rejection=certificate not valid for name"));

    let http_output = run_child(&ChildScenario {
        mode: "explicit-http",
        endpoint: Some(&format!("http://127.0.0.1:{http_port}")),
        trust_source: TrustSource::None,
        generic_insecure: Some("true"),
        traces_insecure: Some("true"),
        expected_tls_error: None,
    });
    assert!(
        http_state.span_count.load(Ordering::Relaxed) > 0,
        "explicit HTTP collector received no spans"
    );
    assert!(
        !http_state.saw_authorization.load(Ordering::Relaxed),
        "HTTP baseline unexpectedly sent authorization metadata"
    );
    assert!(!http_output.contains(TEST_AUTHORIZATION));

    let spans_before_schemeless = http_state.span_count.load(Ordering::Relaxed);
    let schemeless_http = run_child(&ChildScenario {
        mode: "schemeless-insecure",
        endpoint: Some(&format!("127.0.0.1:{http_port}")),
        trust_source: TrustSource::None,
        generic_insecure: Some("true"),
        traces_insecure: None,
        expected_tls_error: None,
    });
    assert!(
        http_state.span_count.load(Ordering::Relaxed) > spans_before_schemeless,
        "scheme-less endpoint with INSECURE=true did not use the existing HTTP path"
    );
    assert!(!schemeless_http.contains(TEST_AUTHORIZATION));

    let requests_before_disabled = http_state.request_count.load(Ordering::Relaxed)
        + trusted_file_state.request_count.load(Ordering::Relaxed)
        + trusted_dir_state.request_count.load(Ordering::Relaxed);
    let disabled_output = run_child(&ChildScenario {
        mode: "disabled",
        endpoint: None,
        trust_source: TrustSource::None,
        generic_insecure: None,
        traces_insecure: None,
        expected_tls_error: None,
    });
    let requests_after_disabled = http_state.request_count.load(Ordering::Relaxed)
        + trusted_file_state.request_count.load(Ordering::Relaxed)
        + trusted_dir_state.request_count.load(Ordering::Relaxed);
    assert_eq!(requests_after_disabled, requests_before_disabled);
    assert!(!disabled_output.contains(TEST_AUTHORIZATION));
}

fn run_exporter_child(mode: &str) {
    ensure_crypto_provider();
    let endpoint = std::env::var(CHILD_ENDPOINT_ENV).ok();
    let expected_tls_error = std::env::var(CHILD_TLS_ERROR_ENV).ok();

    if let (Some(endpoint), Some(expected)) = (endpoint.as_deref(), expected_tls_error.as_deref()) {
        let detail = probe_tls_rejection(endpoint);
        assert!(
            detail.contains(expected),
            "expected TLS verification result {expected}, got {detail}"
        );
        eprintln!("certificate_rejection={expected}");
    }

    let proxy_port = free_port();
    let endpoint_config = endpoint
        .as_deref()
        .map(|endpoint| format!("  otlp_endpoint: \"{endpoint}\"\n"))
        .unwrap_or_default();
    let headers = matches!(
        mode,
        "trusted-file" | "trusted-directory" | "untrusted-ca" | "wrong-hostname"
    )
    .then(|| format!("  otlp_headers:\n    authorization: \"{TEST_AUTHORIZATION}\"\n"))
    .unwrap_or_default();
    let batch = if matches!(mode, "explicit-http") {
        "  batch_size: 1\n  batch_interval_secs: 1\n"
    } else {
        // Keep queued spans below the batch limit and the interval far beyond
        // this child lifetime, so receipt proves shutdown flush.
        "  batch_size: 512\n  batch_interval_secs: 300\n"
    };
    let telemetry = if endpoint.is_some() {
        format!("telemetry:\n{endpoint_config}{headers}  sampling_rate: 1.0\n{batch}")
    } else {
        "telemetry:\n  sampling_rate: 1.0\n".to_owned()
    };
    let yaml = format!(
        "listeners:\n  - name: default\n    address: \"127.0.0.1:{proxy_port}\"\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n      - filter: request_id\n      - filter: static_response\n        status: 200\n{telemetry}"
    );
    let config = Config::from_yaml(&yaml).expect("parse child OTLP config");
    let tracing_guard = praxis_core::logging::init_tracing(&config).expect("initialize Praxis tracing");
    let proxy = start_proxy(&config);
    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "Praxis request should remain healthy in {mode}");

    drop(proxy);
    drop(tracing_guard);
}

fn probe_tls_rejection(endpoint: &str) -> String {
    ensure_crypto_provider();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("TLS probe runtime");
    let endpoint = tonic::transport::Endpoint::from_shared(endpoint.to_owned())
        .expect("valid TLS probe endpoint")
        .tls_config(tonic::transport::ClientTlsConfig::new().with_native_roots())
        .expect("configure native-root TLS probe");
    let result: Result<(), Box<dyn std::error::Error>> = runtime.block_on(async {
        let channel = endpoint.connect().await?;
        TraceServiceClient::new(channel)
            .export(ExportTraceServiceRequest::default())
            .await?;
        Ok(())
    });
    let error = result.expect_err("collector with invalid trust or name must be rejected");
    let mut chain = Vec::new();
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error.as_ref());
    while let Some(source) = current {
        chain.push(source.to_string());
        current = source.source();
    }
    chain.join(" | ")
}
