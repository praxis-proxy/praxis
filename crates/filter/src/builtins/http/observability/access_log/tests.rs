// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Behaviour tests for the access log filter.

use super::*;

fn test_filter(config: &serde_yaml::Value) -> AccessLogFilter {
    let cfg: AccessLogConfig = parse_filter_config("access_log", config).unwrap();
    AccessLogFilter::build(cfg).unwrap()
}

fn default_filter() -> AccessLogFilter {
    AccessLogFilter {
        sample_rate: 1.0,
        counter: AtomicU64::default(),
        emit_plan: EmitPlan {
            shape: EmitShape::DefaultFlat,
        },
        emit_conditions: None,
        needs_response_headers: false,
        sink: RuntimeSink::Tracing,
    }
}

#[test]
fn from_config_defaults_to_log_all() {
    let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    let filter = test_filter(&config);
    assert_eq!(
        filter.name(),
        "access_log",
        "default config should produce access_log filter"
    );
    assert!(matches!(filter.emit_plan.shape, EmitShape::DefaultFlat));
}

#[test]
fn from_config_parses_sample_rate() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.5").unwrap();
    let filter = test_filter(&yaml);
    assert_eq!(filter.name(), "access_log", "sample_rate config should parse correctly");
}

#[test]
fn from_config_rejects_zero_sample_rate() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.0").unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("sample_rate must be in (0.0, 1.0]"),
        "got: {err}"
    );
}

#[test]
fn from_config_rejects_negative_sample_rate() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: -0.5").unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("sample_rate must be in (0.0, 1.0]"),
        "got: {err}"
    );
}

#[test]
fn from_config_rejects_sample_rate_above_one() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 1.5").unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("sample_rate must be in (0.0, 1.0]"),
        "got: {err}"
    );
}

#[test]
fn from_config_rejects_nan_sample_rate() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: .nan").unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("sample_rate must be in (0.0, 1.0]"),
        "NaN passes a range check and then never samples; got: {err}"
    );
}

#[test]
fn from_config_rejects_non_numeric_sample_rate() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: abc").unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("invalid type"),
        "serde should reject non-numeric sample_rate: {err}"
    );
}

#[test]
fn from_config_rejects_unknown_field() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("sampl_rate: 0.5").unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("unknown field"),
        "typo should be rejected by deny_unknown_fields: {err}"
    );
}

#[test]
fn from_config_rejects_empty_fields() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("fields: []").unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(err.to_string().contains("fields must not be empty"), "got: {err}");
}

#[test]
fn from_config_rejects_unknown_field_token() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("fields: [method, not_a_field]").unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(err.to_string().contains("unknown field token"), "got: {err}");
}

#[test]
fn from_config_rejects_filter_results_token() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("fields: [filter_results]").unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(err.to_string().contains("filter_results"), "got: {err}");
}

#[test]
fn from_config_rejects_nested_fields_map() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
fields:
  request_headers: [user-agent]
",
    )
    .unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("scalar tokens") || err.to_string().contains("expected a sequence"),
        "got: {err}"
    );
}

#[test]
fn from_config_rejects_sensitive_request_header() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
request_headers: [authorization]
fields: [request_header.authorization]
",
    )
    .unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(err.to_string().contains("not allowed"), "got: {err}");
}

#[test]
fn from_config_rejects_header_token_without_list() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("fields: [request_header.user-agent]").unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(err.to_string().contains("request_headers"), "got: {err}");
}

#[test]
fn from_config_parses_custom_fields_and_headers() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
fields: [method, request_header.user-agent, trace_id]
request_headers: [user-agent]
",
    )
    .unwrap();
    let filter = test_filter(&yaml);
    assert!(matches!(filter.emit_plan.shape, EmitShape::JsonRecord(_)));
    if let EmitShape::JsonRecord(fields) = &filter.emit_plan.shape {
        assert_eq!(fields.len(), 3);
    }
}

#[test]
fn from_config_parses_emit_conditions() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
conditions:
  status_classes: [5xx]
",
    )
    .unwrap();
    let filter = test_filter(&yaml);
    assert!(filter.emit_conditions.is_some());
}

#[test]
fn from_config_rejects_invalid_status_class() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
conditions:
  status_classes: [6xx]
",
    )
    .unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(err.to_string().contains("unknown variant"), "got: {err}");
}

#[test]
fn from_config_rejects_glob_paths() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
conditions:
  paths: [/api/*]
",
    )
    .unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(err.to_string().contains("without globs"), "got: {err}");
}

// -------------------------------------------------------------------------
// Format / template config parsing
// -------------------------------------------------------------------------

#[test]
fn from_config_rejects_format_key() {
    // `format` was removed: output type is inferred from `template` presence,
    // so the key is now rejected by deny_unknown_fields.
    let yaml: serde_yaml::Value = serde_yaml::from_str("format: text\ntemplate: \"{method} {path}\"").unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(err.to_string().contains("unknown field"), "got: {err}");
}

#[test]
fn from_config_rejects_fields_with_template() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("fields: [method]\ntemplate: \"{method}\"").unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(err.to_string().contains("mutually exclusive"), "got: {err}");
}

#[test]
fn from_config_rejects_empty_template() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("template: \"   \"").unwrap();
    let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
    assert!(err.to_string().contains("template must not be empty"), "got: {err}");
}

#[test]
fn from_config_template_builds_text_shape() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("template: \"{method} {path} {status}\"").unwrap();
    let filter = test_filter(&yaml);
    assert!(
        matches!(filter.emit_plan.shape, EmitShape::Text(_)),
        "template config should build a Text emit shape"
    );
}

// -------------------------------------------------------------------------
// Template parsing
// -------------------------------------------------------------------------

#[test]
fn parse_template_extracts_literals_and_field_tokens() {
    let headers = HashSet::new();
    let parts = parse_template("{method} {path} [{status}]", &headers, &headers).unwrap();
    assert_eq!(parts.len(), 6); // Field, Literal, Field, Literal, Field, Literal
}

#[test]
fn parse_template_rejects_unclosed_brace() {
    let headers = HashSet::new();
    let err = parse_template("{method {path}", &headers, &headers).unwrap_err();
    assert!(err.to_string().contains("unclosed"), "got: {err}");
}

#[test]
fn parse_template_rejects_unknown_token() {
    let headers = HashSet::new();
    let err = parse_template("{not_a_field}", &headers, &headers).unwrap_err();
    assert!(err.to_string().contains("unknown field token"), "got: {err}");
}

#[test]
fn parse_template_rejects_request_header_without_allowlist() {
    let headers = HashSet::new();
    let err = parse_template("{request_header.user-agent}", &headers, &headers).unwrap_err();
    assert!(err.to_string().contains("request_headers"), "got: {err}");
}

#[test]
fn parse_template_accepts_allowed_header() {
    let mut req_headers = HashSet::new();
    req_headers.insert("user-agent".to_owned());
    let res_headers = HashSet::new();
    let parts = parse_template("{request_header.user-agent}", &req_headers, &res_headers).unwrap();
    assert_eq!(parts.len(), 1);
    assert!(matches!(&parts[0], TemplatePart::Field(FieldToken::RequestHeader(n)) if n == "user-agent"));
}

#[test]
fn parse_template_rejects_response_header_without_allowlist() {
    let headers = HashSet::new();
    let err = parse_template("{response_header.content-type}", &headers, &headers).unwrap_err();
    assert!(err.to_string().contains("response_headers"), "got: {err}");
}

#[test]
fn parse_template_rejects_unclosed_brace_at_end() {
    let headers = HashSet::new();
    let err = parse_template("{method", &headers, &headers).unwrap_err();
    assert!(err.to_string().contains("unclosed"), "got: {err}");
}

#[test]
fn parse_template_rejects_stray_closing_brace() {
    let headers = HashSet::new();
    let err = parse_template("{status}}", &headers, &headers).unwrap_err();
    assert!(err.to_string().contains("unexpected '}'"), "got: {err}");
}

// -------------------------------------------------------------------------
// Text rendering
// -------------------------------------------------------------------------

#[test]
fn render_text_template_interpolates_method_path_status() {
    let parts = vec![
        TemplatePart::Field(FieldToken::Method),
        TemplatePart::Literal(" ".to_owned()),
        TemplatePart::Field(FieldToken::Path),
        TemplatePart::Literal(" ".to_owned()),
        TemplatePart::Field(FieldToken::Status),
    ];
    let req = crate::test_utils::make_request(http::Method::GET, "/api");
    let ctx = crate::test_utils::make_filter_context(&req);
    let line = render_text_template(&parts, &ctx, 200, None, 42);
    assert_eq!(line, "GET /api 200");
}

#[test]
fn render_text_template_uses_dash_for_missing_values() {
    let parts = vec![TemplatePart::Field(FieldToken::Cluster)];
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let ctx = crate::test_utils::make_filter_context(&req);
    let line = render_text_template(&parts, &ctx, 200, None, 0);
    assert_eq!(line, "-", "missing cluster should render as dash");
}

#[test]
fn render_text_template_sanitizes_field_values() {
    let parts = vec![TemplatePart::Field(FieldToken::Metadata("llm.model".to_owned()))];
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("llm.model", "gpt\ninjected 200");
    let line = render_text_template(&parts, &ctx, 200, None, 0);
    assert!(
        !line.contains('\n'),
        "newlines in field values must not forge log lines"
    );
}

// -------------------------------------------------------------------------
// Sampling and emit conditions (unchanged)
// -------------------------------------------------------------------------

#[test]
fn should_log_every_request_by_default() {
    let filter = default_filter();
    for _ in 0..5 {
        assert!(filter.should_log(), "sample_rate=1.0 should log every request");
    }
}

#[test]
fn should_log_samples_at_rate() {
    let filter = AccessLogFilter {
        sample_rate: 0.25,
        counter: AtomicU64::default(),
        emit_plan: EmitPlan {
            shape: EmitShape::DefaultFlat,
        },
        emit_conditions: None,
        needs_response_headers: false,
        sink: RuntimeSink::Tracing,
    };
    let mut logged = 0;
    for _ in 0..8 {
        if filter.should_log() {
            logged += 1;
        }
    }
    assert_eq!(logged, 2, "1-in-4 over 8 calls = 2 logged");
}

#[test]
fn should_log_honors_non_reciprocal_rates() {
    for (rate, calls, expected) in [(0.7, 10, 7), (0.4, 10, 4), (0.000_000_51, 2_000_000, 1)] {
        let filter = AccessLogFilter {
            sample_rate: rate,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan {
                shape: EmitShape::DefaultFlat,
            },
            emit_conditions: None,
            needs_response_headers: false,
            sink: RuntimeSink::Tracing,
        };
        let logged = (0..calls).filter(|_| filter.should_log()).count();
        assert_eq!(
            logged, expected,
            "rate {rate} over {calls} calls must log exactly {expected}"
        );
    }
}

#[test]
fn status_class_or_matching() {
    assert!(StatusClass::ServerError.matches(500));
    assert!(StatusClass::ClientError.matches(404));
    assert!(!StatusClass::ServerError.matches(200));
}

#[test]
fn passes_emit_conditions_and_sampling_order() {
    let filter = AccessLogFilter {
        sample_rate: 1.0,
        counter: AtomicU64::default(),
        emit_plan: EmitPlan {
            shape: EmitShape::JsonRecord(vec![FieldToken::Method]),
        },
        emit_conditions: Some(AccessLogEmitConditions {
            min_duration_ms: None,
            status_classes: Some(vec![StatusClass::ServerError]),
            paths: None,
        }),
        needs_response_headers: false,
        sink: RuntimeSink::Tracing,
    };
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let ctx = crate::test_utils::make_filter_context(&req);
    assert!(
        !filter.passes_emit_conditions(&ctx, 200, 0),
        "200 should not pass 5xx-only condition"
    );
    assert!(
        filter.passes_emit_conditions(&ctx, 503, 0),
        "503 should pass 5xx condition"
    );
}

#[test]
fn build_record_includes_selected_fields_only() {
    let fields = [FieldToken::Method, FieldToken::Status];
    let req = crate::test_utils::make_request(http::Method::POST, "/api");
    let ctx = crate::test_utils::make_filter_context(&req);
    let record = build_record_from_fields(&fields, &ctx, 201, None, 0);
    assert_eq!(record.len(), 2);
    assert_eq!(record.get("method"), Some(&"POST".to_owned()));
    assert_eq!(record.get("status"), Some(&"201".to_owned()));
    assert!(!record.contains_key("path"));
}

#[test]
fn metadata_token_parses_its_key() {
    let token = parse_scalar_field_token("metadata.llm.model").unwrap();
    assert!(
        matches!(&token, FieldToken::Metadata(key) if key == "llm.model"),
        "the dotted key is taken whole; got {token:?}",
    );
}

#[test]
#[expect(clippy::too_many_lines, reason = "one assertion per rendered gRPC field")]
fn build_record_renders_grpc_completion() {
    let fields = [
        FieldToken::GrpcStatus,
        FieldToken::GrpcStatusName,
        FieldToken::GrpcMessage,
        FieldToken::GrpcStatusDetailsBin,
    ];
    let req = grpc_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut trailers = http::HeaderMap::new();
    let _prev = trailers.insert("grpc-status", http::HeaderValue::from_static("5"));
    let _prev = trailers.insert("grpc-message", http::HeaderValue::from_static("no%20such%20user"));
    let _prev = trailers.insert("grpc-status-details-bin", http::HeaderValue::from_static("CAUSBG9vcHM"));
    ctx.grpc_completion = praxis_core::grpc::GrpcCompletion::from_headers(&trailers);

    let record = build_record_from_fields(&fields, &ctx, 200, None, 0);

    assert_eq!(
        record.get("grpc_status"),
        Some(&"5".to_owned()),
        "the numeric status should be rendered"
    );
    assert_eq!(
        record.get("grpc_status_name"),
        Some(&"NOT_FOUND".to_owned()),
        "the canonical name should be rendered"
    );
    assert_eq!(
        record.get("grpc_message"),
        Some(&"no%20such%20user".to_owned()),
        "the message should be rendered as received"
    );
    assert_eq!(
        record.get("grpc_status_details_bin"),
        Some(&"CAUSBG9vcHM".to_owned()),
        "status details should be rendered as received"
    );
}

#[test]
fn metadata_token_rejects_an_empty_key() {
    let err = parse_scalar_field_token("metadata.").expect_err("should fail");
    assert!(err.to_string().contains("metadata token"), "got: {err}");
}

#[test]
fn metadata_keys_are_case_sensitive_unlike_header_names() {
    // Header tokens lowercase their name; a metadata key is an exact
    // lookup into the bag, so it must survive as written.
    let token = parse_scalar_field_token("metadata.LLM.Model").unwrap();
    assert!(matches!(&token, FieldToken::Metadata(key) if key == "LLM.Model"));
}

#[test]
fn build_record_emits_filter_metadata() {
    let fields = [FieldToken::Metadata("llm.model".to_owned())];
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat/completions");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("llm.model", "gpt-4o");

    let record = build_record_from_fields(&fields, &ctx, 200, None, 0);
    assert_eq!(record.get("metadata.llm.model"), Some(&"gpt-4o".to_owned()));
}

#[test]
fn build_record_dashes_absent_metadata() {
    let fields = [FieldToken::Metadata("llm.model".to_owned())];
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let ctx = crate::test_utils::make_filter_context(&req);

    let record = build_record_from_fields(&fields, &ctx, 200, None, 0);
    assert_eq!(
        record.get("metadata.llm.model"),
        Some(&"-".to_owned()),
        "an unset key reads as absent, matching the header tokens",
    );
}

#[test]
fn build_record_grpc_fields_are_dashes_for_non_grpc_responses() {
    let fields = [
        FieldToken::GrpcStatus,
        FieldToken::GrpcStatusName,
        FieldToken::GrpcMessage,
    ];
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let ctx = crate::test_utils::make_filter_context(&req);

    let record = build_record_from_fields(&fields, &ctx, 200, None, 0);

    assert_eq!(record.get("grpc_status"), Some(&"-".to_owned()), "no gRPC status");
    assert_eq!(record.get("grpc_status_name"), Some(&"-".to_owned()), "no gRPC name");
    assert_eq!(record.get("grpc_message"), Some(&"-".to_owned()), "no gRPC message");
}

#[test]
fn grpc_field_tokens_parse() {
    for token in [
        "grpc_status",
        "grpc_status_name",
        "grpc_message",
        "grpc_status_details_bin",
    ] {
        assert!(
            parse_scalar_field_token(token).is_ok(),
            "{token} should be a valid access_log field"
        );
    }
}

#[test]
fn build_record_trace_id_defaults_to_dash_without_span() {
    let fields = [FieldToken::TraceId, FieldToken::SpanId];
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let ctx = crate::test_utils::make_filter_context(&req);
    let record = build_record_from_fields(&fields, &ctx, 200, None, 0);
    assert_eq!(record.get("trace_id"), Some(&"-".to_owned()));
    assert_eq!(record.get("span_id"), Some(&"-".to_owned()));
}

#[cfg(feature = "otel")]
#[test]
fn extract_otel_ids_returns_ids_with_active_otel_span() {
    use opentelemetry::trace::TracerProvider as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
    let tracer = provider.tracer("test");
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let span = tracing::info_span!("test_span");
    let _entered = span.enter();

    let (trace_id, span_id) = extract_otel_ids().expect("ids should be present with an active OTel span");
    assert_eq!(trace_id.len(), 32, "trace_id must be 32 hex chars, got {trace_id}");
    assert_ne!(trace_id, "0".repeat(32), "trace_id must not be all-zero");
    assert_eq!(span_id.len(), 16, "span_id must be 16 hex chars, got {span_id}");
    assert_ne!(span_id, "0".repeat(16), "span_id must not be all-zero");
}

// -------------------------------------------------------------------------
// Sanitization (unchanged)
// -------------------------------------------------------------------------

#[test]
fn sanitize_strips_newlines() {
    assert_eq!(
        sanitize_for_log("/path\ninjected"),
        "/pathinjected",
        "newlines should be stripped"
    );
    assert_eq!(
        sanitize_for_log("/path\r\ninjected"),
        "/pathinjected",
        "CRLF should be stripped"
    );
}

#[test]
fn sanitize_strips_ansi_escapes() {
    assert_eq!(
        sanitize_for_log("/path\x1b[31mred\x1b[0m"),
        "/pathred",
        "ANSI escapes should be stripped"
    );
}

#[test]
fn sanitize_strips_tabs_and_null() {
    assert_eq!(
        sanitize_for_log("/path\0\there"),
        "/pathhere",
        "null and tab should be stripped"
    );
}

#[test]
fn sanitize_preserves_normal_paths() {
    assert_eq!(
        sanitize_for_log("/api/v1/users?q=foo"),
        "/api/v1/users?q=foo",
        "normal paths should be unchanged"
    );
}

#[test]
fn sanitize_returns_borrowed_for_clean_paths() {
    let result = sanitize_for_log("/clean/path");
    assert!(
        matches!(result, Cow::Borrowed(_)),
        "clean paths should return Cow::Borrowed"
    );
}

#[test]
fn sanitize_returns_owned_for_dirty_paths() {
    let result = sanitize_for_log("/path\ninjected");
    assert!(matches!(result, Cow::Owned(_)), "dirty paths should return Cow::Owned");
}

#[test]
fn sanitize_strips_del_character() {
    assert_eq!(
        sanitize_for_log("/path\x7Fhere"),
        "/pathhere",
        "DEL (0x7F) should be stripped"
    );
}

#[test]
fn sanitize_strips_c1_control_characters() {
    assert_eq!(
        sanitize_for_log("/path\u{0080}injected"),
        "/pathinjected",
        "C1 control U+0080 should be stripped"
    );
    assert_eq!(
        sanitize_for_log("/path\u{009F}injected"),
        "/pathinjected",
        "C1 control U+009F should be stripped"
    );
}

// -------------------------------------------------------------------------
// HttpFilter hooks (unchanged)
// -------------------------------------------------------------------------

#[tokio::test]
async fn on_response_continues_with_no_header() {
    let filter = default_filter();
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = filter.on_response(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "on_response with no header should continue"
    );
}

#[tokio::test]
async fn on_response_with_populated_context_continues() {
    use praxis_core::connectivity::{ConnectionOptions, Upstream};

    let filter = default_filter();
    let mut headers = http::HeaderMap::new();
    headers.insert("x-request-id", "req-123".parse().unwrap());
    let req = crate::context::Request {
        method: http::Method::GET,
        uri: "/api/users".parse().unwrap(),
        headers,
    };
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.client_addr = Some("10.0.0.1".parse().unwrap());
    ctx.cluster = Some(Arc::from("backend"));
    ctx.upstream = Some(Upstream {
        address: Arc::from("10.0.0.2:8080"),
        authority: None,
        base_path: None,
        connection: Arc::new(ConnectionOptions::default()),
        tls: None,
    });
    let mut resp = crate::context::Response {
        headers: http::HeaderMap::new(),
        status: http::StatusCode::OK,
    };
    ctx.response_header = Some(&mut resp);
    let action = filter.on_response(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "on_response with populated context should continue"
    );
}

#[tokio::test]
async fn on_response_stores_state_in_filter_state() {
    let filter = default_filter();
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.current_filter_id = Some(42);
    let mut resp = crate::context::Response {
        headers: http::HeaderMap::new(),
        status: http::StatusCode::NOT_FOUND,
    };
    ctx.response_header = Some(&mut resp);
    let _action = filter.on_response(&mut ctx).await.unwrap();
    assert_eq!(
        ctx.get_filter_state::<AccessLogState>().map(|state| state.status),
        Some(404),
        "on_response should store status in access log state"
    );
}

#[tokio::test]
async fn on_response_no_header_skips_filter_state() {
    let filter = default_filter();
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.current_filter_id = Some(42);
    let _action = filter.on_response(&mut ctx).await.unwrap();
    assert!(
        ctx.get_filter_state::<AccessLogState>().is_none(),
        "on_response without header should not store filter state"
    );
}

#[test]
fn is_bodyless_detects_1xx() {
    assert!(
        AccessLogFilter::is_bodyless(http::StatusCode::CONTINUE, &http::Method::GET),
        "100 Continue should be bodyless"
    );
}

#[test]
fn is_bodyless_detects_204() {
    assert!(
        AccessLogFilter::is_bodyless(http::StatusCode::NO_CONTENT, &http::Method::DELETE),
        "204 No Content should be bodyless"
    );
}

#[test]
fn is_bodyless_detects_304() {
    assert!(
        AccessLogFilter::is_bodyless(http::StatusCode::NOT_MODIFIED, &http::Method::GET),
        "304 Not Modified should be bodyless"
    );
}

#[test]
fn is_bodyless_detects_head() {
    assert!(
        AccessLogFilter::is_bodyless(http::StatusCode::OK, &http::Method::HEAD),
        "HEAD request should be bodyless regardless of status"
    );
}

#[test]
fn is_bodyless_returns_false_for_normal_response() {
    assert!(
        !AccessLogFilter::is_bodyless(http::StatusCode::OK, &http::Method::GET),
        "normal 200 GET should not be bodyless"
    );
}

#[tokio::test]
async fn on_response_stores_status_for_bodyless() {
    let filter = default_filter();
    let req = crate::test_utils::make_request(http::Method::DELETE, "/api/users/42");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.current_filter_id = Some(42);
    let mut resp = crate::context::Response {
        headers: http::HeaderMap::new(),
        status: http::StatusCode::NO_CONTENT,
    };
    ctx.response_header = Some(&mut resp);
    let _action = filter.on_response(&mut ctx).await.unwrap();
    assert_eq!(
        ctx.get_filter_state::<AccessLogState>().map(|state| state.status),
        Some(204),
        "on_response should store status for bodyless responses"
    );
}

#[test]
fn on_response_body_continues_before_end_of_stream() {
    let filter = default_filter();
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.current_filter_id = Some(42);
    let mut body = Some(Bytes::from_static(b"partial"));
    let action = filter.on_response_body(&mut ctx, &mut body, false).unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "on_response_body should continue before end_of_stream"
    );
}

#[tokio::test]
async fn on_response_body_uses_status_from_on_response() {
    let filter = default_filter();
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.current_filter_id = Some(42);

    let mut resp = crate::context::Response {
        headers: http::HeaderMap::new(),
        status: http::StatusCode::OK,
    };
    ctx.response_header = Some(&mut resp);
    let _action = filter.on_response(&mut ctx).await.unwrap();
    ctx.response_header = None;

    ctx.response_body_bytes = 1234;
    let mut body = None;
    let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "on_response_body should continue at end_of_stream"
    );
    assert_eq!(
        ctx.get_filter_state::<AccessLogState>().map(|state| state.status),
        Some(200),
        "status set by on_response should survive into on_response_body"
    );
}

#[test]
fn response_body_access_is_read_only() {
    let filter = default_filter();
    assert_eq!(
        filter.response_body_access(),
        BodyAccess::ReadOnly,
        "access_log should declare ReadOnly response body access"
    );
}

#[test]
fn normalized_ipv4_formats_without_mapped_prefix() {
    use std::net::IpAddr;

    let v4: IpAddr = "10.0.0.1".parse().unwrap();
    assert_eq!(
        v4.to_string(),
        "10.0.0.1",
        "normalized IPv4 should format without ::ffff: prefix"
    );

    let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
    assert_eq!(
        mapped.to_string(),
        "::ffff:10.0.0.1",
        "un-normalized mapped address keeps ::ffff: prefix in Display"
    );
}

// -------------------------------------------------------------------------
// Emission Shape (unchanged)
// -------------------------------------------------------------------------

/// Capture `tracing` output emitted synchronously by `f` on this thread.
fn capture_logs<F: FnOnce()>(f: F) -> String {
    use std::io::Write;

    #[derive(Clone)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("buffer lock").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let buffer = Buffer(Arc::new(Mutex::new(Vec::new())));
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    let bytes = buffer.0.lock().expect("buffer lock").clone();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn no_record_work_when_info_level_disabled() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("fields: [method, path, status]").unwrap();
    let filter = test_filter(&yaml);
    let req = crate::test_utils::make_request(http::Method::GET, "/api/thing");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).finish();
    tracing::subscriber::with_default(subscriber, || {
        filter.maybe_emit(&mut ctx, 200, None);
    });

    assert!(
        !access_record_already_emitted(&ctx),
        "when info is disabled, maybe_emit must skip all work (no marker set)"
    );
}

#[test]
#[expect(clippy::disallowed_methods, reason = "sync sink test polls with thread::sleep")]
fn file_sink_writes_even_when_info_level_disabled() {
    // A file sink bypasses tracing, so the INFO gate must not suppress it:
    // with RUST_LOG=warn a file sink would otherwise silently lose every
    // record, including rejections and upstream failures.
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("access.log");
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(&format!("sink:\n  type: file\n  path: {}", log_path.to_str().unwrap())).unwrap();
    let filter = test_filter(&yaml);

    let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).finish();
    tracing::subscriber::with_default(subscriber, || {
        for (path, status) in [("/ok", 200), ("/err", 500)] {
            let req = crate::test_utils::make_request(http::Method::GET, path);
            let mut ctx = crate::test_utils::make_filter_context(&req);
            filter.maybe_emit(&mut ctx, status, None);
        }
    });

    let mut lines = 0;
    for _ in 0..100 {
        lines = std::fs::read_to_string(&log_path).unwrap_or_default().lines().count();
        if lines == 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(lines, 2, "both records must reach the file sink despite the INFO gate");
}

#[test]
fn maybe_emit_gates_by_status_and_emits_stable_record() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
fields: [method, path, status, duration_ms, request_id]
conditions:
  status_classes: [5xx]
",
    )
    .unwrap();
    let filter = test_filter(&yaml);
    let req = crate::test_utils::make_request(http::Method::GET, "/api/thing");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let unmatched = capture_logs(|| filter.maybe_emit(&mut ctx, 200, None));
    assert!(
        !unmatched.contains("access"),
        "non-matching status must not emit: {unmatched:?}"
    );

    let matched = capture_logs(|| filter.maybe_emit(&mut ctx, 500, None));
    assert!(matched.contains("access"), "matching status must emit: {matched:?}");
    assert!(
        matched.contains("record="),
        "custom field sets emit one JSON record field: {matched:?}"
    );
    for key in ["method", "path", "status", "duration_ms", "request_id"] {
        assert!(matched.contains(key), "record should include {key}: {matched:?}");
    }
}

#[test]
fn small_custom_field_sets_also_emit_record_shape() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("fields: [method, path]").unwrap();
    let filter = test_filter(&yaml);
    let req = crate::test_utils::make_request(http::Method::GET, "/x");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let out = capture_logs(|| filter.maybe_emit(&mut ctx, 200, None));
    assert!(
        out.contains("record="),
        "small field sets must use the same record shape as large ones: {out:?}"
    );
}

#[test]
fn template_emit_renders_response_header_through_maybe_emit() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
template: \"{status} {response_header.content-type}\"
response_headers: [content-type]
",
    )
    .unwrap();
    let filter = test_filter(&yaml);
    let req = crate::test_utils::make_request(http::Method::GET, "/api/thing");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut response_headers = http::HeaderMap::new();
    response_headers.insert("content-type", "text/plain".parse().unwrap());

    let out = capture_logs(|| filter.maybe_emit(&mut ctx, 200, Some(&response_headers)));
    assert!(
        out.contains("line=200 text/plain"),
        "template emit should render the status and response header into the line field: {out:?}"
    );
}

#[test]
fn deferred_record_samples_complete_grpc_calls() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.5").unwrap();
    let filter = test_filter(&yaml);
    let req = grpc_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.grpc_completion = grpc_completion("0");

    let mut logged = 0;
    for _ in 0..8 {
        if capture_logs(|| {
            let _claimed = filter.emit_deferred_record(&ctx, 200);
        })
        .contains("access")
        {
            logged += 1;
        }
    }
    assert_eq!(logged, 4, "sample_rate 0.5 should log half of the complete gRPC calls");
}

#[test]
fn deferred_record_gates_complete_grpc_by_conditions() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("conditions:\n  paths: [\"/allowed\"]").unwrap();
    let filter = test_filter(&yaml);
    let req = grpc_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.grpc_completion = grpc_completion("0");

    let dropped = capture_logs(|| {
        let _claimed = filter.emit_deferred_record(&ctx, 200);
    });
    assert!(
        !dropped.contains("access"),
        "a complete gRPC call outside the configured paths must not log: {dropped:?}"
    );
}

#[test]
fn deferred_record_always_logs_incomplete_requests() {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str("sample_rate: 0.5\nconditions:\n  paths: [\"/allowed\"]").unwrap();
    let filter = test_filter(&yaml);
    let req = grpc_request();
    let ctx = crate::test_utils::make_filter_context(&req);

    for _ in 0..4 {
        let logged = capture_logs(|| {
            let _claimed = filter.emit_deferred_record(&ctx, 502);
        });
        assert!(
            logged.contains("access"),
            "an incomplete request must always log, bypassing sampling and conditions: {logged:?}"
        );
    }
}

#[test]
fn deferred_record_gates_grpc_by_mapped_status_class() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("conditions:\n  status_classes: [5xx]").unwrap();
    let filter = test_filter(&yaml);
    let req = grpc_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);

    ctx.grpc_completion = grpc_completion("13");
    let logged_error = capture_logs(|| {
        let _claimed = filter.emit_deferred_record(&ctx, 200);
    });
    assert!(
        logged_error.contains("access"),
        "a gRPC INTERNAL error maps to 5xx and must log despite the HTTP 200: {logged_error:?}"
    );

    ctx.grpc_completion = grpc_completion("0");
    let logged_ok = capture_logs(|| {
        let _claimed = filter.emit_deferred_record(&ctx, 200);
    });
    assert!(
        !logged_ok.contains("access"),
        "a successful gRPC call maps to 2xx and must be excluded by an errors-only filter: {logged_ok:?}"
    );
}

#[test]
fn deferred_record_logs_non_canonical_grpc_failures() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("conditions:\n  status_classes: [5xx]").unwrap();
    let filter = test_filter(&yaml);
    let req = grpc_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);

    ctx.grpc_completion = grpc_completion("20");
    let logged = capture_logs(|| {
        let _claimed = filter.emit_deferred_record(&ctx, 200);
    });
    assert!(
        logged.contains("access"),
        "a non-canonical grpc-status is still a failure and must map to 5xx, not the HTTP 200: {logged:?}"
    );
}

#[test]
fn deferred_record_ignores_stray_grpc_status_on_non_grpc_request() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.5").unwrap();
    let filter = test_filter(&yaml);
    let req = crate::test_utils::make_request(http::Method::GET, "/rest/thing");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.grpc_completion = grpc_completion("0");

    for _ in 0..4 {
        let logged = capture_logs(|| {
            let _claimed = filter.emit_deferred_record(&ctx, 200);
        });
        assert!(
            logged.contains("access"),
            "a non-gRPC request must always log; a stray grpc-status must not enable sampling: {logged:?}"
        );
    }
}

fn grpc_request() -> crate::context::Request {
    let mut req = crate::test_utils::make_request(http::Method::POST, "/pkg.Svc/Method");
    let _prev = req.headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/grpc"),
    );
    req
}

fn grpc_completion(status: &'static str) -> Option<praxis_core::grpc::GrpcCompletion> {
    let mut trailers = http::HeaderMap::new();
    let _prev = trailers.insert("grpc-status", http::HeaderValue::from_static(status));
    praxis_core::grpc::GrpcCompletion::from_headers(&trailers)
}

#[test]
fn render_text_template_substitutes_request_id_and_response_header() {
    let template = "{method} id={request_id} agent={response_header.user-agent}";
    let mut request_headers = HashSet::new();
    let mut response_headers = HashSet::new();

    request_headers.insert(String::from("user-agent"));
    response_headers.insert(String::from("user-agent"));
    let parts = parse_template(template, &request_headers, &response_headers).unwrap();
    assert_eq!(parts.len(), 5, "method, literal, request_id, literal, response_header");

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("x-request-id", "abdc".parse().unwrap());
    let ctx = crate::test_utils::make_filter_context(&req);
    let mut response_headers_map = http::HeaderMap::new();
    response_headers_map.insert("user-agent", "my-agent".parse().unwrap());
    let line = render_text_template(&parts, &ctx, 200, Some(&response_headers_map), 5);
    assert_eq!(
        line, "GET id=abdc agent=my-agent",
        "template should interpolate method, request id, and response header"
    );
}

// -------------------------------------------------------------------------
// Sinks
// -------------------------------------------------------------------------

#[test]
fn from_config_no_sink_defaults_to_tracing() {
    let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    let filter = test_filter(&config);
    assert!(matches!(filter.sink, RuntimeSink::Tracing));
}

/// Number of NDJSON records in `contents`, or `None` when any line is not
/// valid JSON yet. A flush can expose the start of the next line before
/// the rest of that line is written.
fn complete_ndjson_count(contents: &str) -> Option<usize> {
    let mut count = 0_usize;
    for line in contents.lines() {
        if serde_json::from_str::<BTreeMap<String, String>>(line).is_err() {
            return None;
        }
        count = count.saturating_add(1);
    }
    Some(count)
}

/// Read a file, retrying briefly so a background writer thread has time to
/// flush before the assertion runs.
#[expect(clippy::disallowed_methods, reason = "sync sink tests poll with thread::sleep")]
fn read_file_with_retry(path: &std::path::Path) -> String {
    for _ in 0..100 {
        if let Ok(contents) = std::fs::read_to_string(path)
            && !contents.is_empty()
        {
            return contents;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    std::fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn from_config_parses_stdout_sink() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("sink:\n  type: stdout").unwrap();
    let filter = test_filter(&yaml);
    let RuntimeSink::Direct(sink) = &filter.sink else {
        panic!("stdout sink should resolve to a direct sink");
    };
    assert_eq!(&*sink.dest, "stdout");
}

#[test]
fn from_config_rejects_sink_stdout_with_path() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("sink:\n  type: stdout\n  path: /tmp/x.log").unwrap();
    let err = AccessLogFilter::from_config(&yaml)
        .err()
        .expect("stdout sink with a path should fail");
    assert!(err.to_string().contains("does not accept a path"), "got: {err}");
}

#[test]
fn from_config_rejects_sink_file_without_path() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("sink:\n  type: file").unwrap();
    let err = AccessLogFilter::from_config(&yaml)
        .err()
        .expect("file sink without a path should fail");
    assert!(err.to_string().contains("requires a path"), "got: {err}");
}

#[cfg(feature = "access-log-syslog")]
#[test]
fn from_config_rejects_syslog_udp_without_address() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("sink:\n  type: syslog\n  transport: udp").unwrap();
    let err = AccessLogFilter::from_config(&yaml)
        .err()
        .expect("syslog udp without an address should fail");
    assert!(err.to_string().contains("requires an address"), "got: {err}");
}

#[cfg(feature = "access-log-syslog")]
#[test]
fn from_config_rejects_syslog_tcp_without_address() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("sink:\n  type: syslog\n  transport: tcp").unwrap();
    let err = AccessLogFilter::from_config(&yaml)
        .err()
        .expect("syslog tcp without an address should fail");
    assert!(err.to_string().contains("requires an address"), "got: {err}");
}

#[cfg(feature = "access-log-syslog")]
#[test]
fn from_config_rejects_syslog_unix_with_address() {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str("sink:\n  type: syslog\n  transport: unix\n  address: 127.0.0.1:514").unwrap();
    let err = AccessLogFilter::from_config(&yaml)
        .err()
        .expect("syslog unix with an address should fail");
    assert!(err.to_string().contains("does not accept an address"), "got: {err}");
}

#[cfg(feature = "access-log-syslog")]
#[test]
fn from_config_rejects_syslog_udp_with_path() {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str("sink:\n  type: syslog\n  transport: udp\n  address: 127.0.0.1:514\n  path: /dev/log")
            .unwrap();
    let err = AccessLogFilter::from_config(&yaml)
        .err()
        .expect("syslog udp with a path should fail");
    assert!(err.to_string().contains("does not accept a path"), "got: {err}");
}

#[cfg(feature = "access-log-syslog")]
#[test]
fn from_config_rejects_syslog_fields_on_stdout() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("sink:\n  type: stdout\n  facility: local0").unwrap();
    let err = AccessLogFilter::from_config(&yaml)
        .err()
        .expect("stdout sink with a syslog field should fail");
    assert!(err.to_string().contains("does not accept syslog fields"), "got: {err}");
}

#[cfg(feature = "access-log-syslog")]
#[test]
fn from_config_rejects_syslog_fields_on_file() {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str("sink:\n  type: file\n  path: /tmp/x.log\n  transport: tcp").unwrap();
    let err = AccessLogFilter::from_config(&yaml)
        .err()
        .expect("file sink with a syslog field should fail");
    assert!(err.to_string().contains("does not accept syslog fields"), "got: {err}");
}

#[cfg(feature = "access-log-syslog")]
#[test]
fn syslog_unix_sink_delivers_rendered_line() {
    // Bind a datagram receiver first so the writer thread's lazy connect
    // succeeds, then drive the emit path and confirm the framed line lands.
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("syslog.sock");
    let receiver = UnixDatagram::bind(&sock_path).unwrap();
    receiver.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
        "template: '{{method}} {{path}} {{status}}'\nsink:\n  type: syslog\n  transport: unix\n  path: {}\n  facility: local0",
        sock_path.to_str().unwrap()
    ))
    .unwrap();
    let filter = test_filter(&yaml);

    let req = crate::test_utils::make_request(http::Method::GET, "/health");
    let ctx = crate::test_utils::make_filter_context(&req);
    filter.emit_access_log(&ctx, 200, None, 7);

    let mut buf = [0_u8; 2048];
    let n = receiver.recv(&mut buf).unwrap();
    assert_rfc3164(&String::from_utf8_lossy(&buf[..n]), false);
}

#[cfg(feature = "access-log-syslog")]
fn assert_rfc3164(line: &str, expect_hostname: bool) {
    assert!(line.starts_with("<134>"), "PRI for local0.info must be <134>: {line:?}");
    let tag = format!("praxis[{}]: GET /health 200", std::process::id());
    assert!(line.ends_with(&tag), "line must end with TAG[PID]: MSG: {line:?}");
    let header = line.split(" praxis[").next().unwrap_or_default();
    let fields = header.split_whitespace().count();
    if expect_hostname {
        assert_eq!(fields, 4, "remote HEADER must carry PRI+timestamp+hostname: {header:?}");
    } else {
        assert_eq!(fields, 3, "unix HEADER must omit the hostname: {header:?}");
    }
}

#[cfg(feature = "access-log-syslog")]
#[test]
fn syslog_udp_sink_emits_rfc3164_with_hostname() {
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let address = receiver.local_addr().unwrap().to_string();

    let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
        "template: '{{method}} {{path}} {{status}}'\nsink:\n  type: syslog\n  transport: udp\n  address: {address}\n  facility: local0"
    )).unwrap();
    let filter = test_filter(&yaml);
    let req = crate::test_utils::make_request(http::Method::GET, "/health");
    let ctx = crate::test_utils::make_filter_context(&req);
    filter.emit_access_log(&ctx, 200, None, 7);

    let mut buf = [0_u8; 2048];
    let n = receiver.recv(&mut buf).unwrap();
    assert_rfc3164(&String::from_utf8_lossy(&buf[..n]), true);
}

#[cfg(feature = "access-log-syslog")]
#[test]
fn syslog_tcp_sink_emits_rfc3164_with_octet_framing() {
    use std::io::Read as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();

    let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
        "template: '{{method}} {{path}} {{status}}'\nsink:\n  type: syslog\n  transport: tcp\n  address: {address}\n  facility: local0"
    )).unwrap();
    let filter = test_filter(&yaml);
    let req = crate::test_utils::make_request(http::Method::GET, "/health");
    let ctx = crate::test_utils::make_filter_context(&req);
    // Two records back-to-back exercise RFC 6587 octet framing as the record
    // delimiter on the stream (the crate writes none).
    filter.emit_access_log(&ctx, 200, None, 7);
    filter.emit_access_log(&ctx, 200, None, 7);

    let (mut stream, _) = listener.accept().unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 2048];
    let records = loop {
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0, "collector closed before both frames arrived");
        buf.extend_from_slice(&chunk[..n]);
        let records = parse_octet_frames(&buf);
        if records.len() >= 2 {
            break records;
        }
    };
    assert_eq!(records.len(), 2, "two records must be framed separately");
    for record in &records {
        assert_rfc3164(record, true);
    }
}

/// Decode RFC 6587 octet-counted frames (`MSG-LEN SP MSG`) from a byte buffer,
/// returning the messages and ignoring any trailing partial frame.
#[cfg(feature = "access-log-syslog")]
fn parse_octet_frames(buf: &[u8]) -> Vec<String> {
    let mut records = Vec::new();
    let mut rest = buf;
    while let Some(sp) = rest.iter().position(|&byte| byte == b' ') {
        let (len_bytes, after) = rest.split_at(sp);
        let Ok(len) = std::str::from_utf8(len_bytes).unwrap_or_default().parse::<usize>() else {
            break;
        };
        match after.get(1..=len) {
            Some(msg) => {
                records.push(String::from_utf8_lossy(msg).into_owned());
                rest = after.get(len.saturating_add(1)..).unwrap_or_default();
            },
            None => break,
        }
    }
    records
}

#[cfg(feature = "access-log-syslog")]
#[test]
fn remote_address_rejects_malformed_host_port() {
    for bad in [
        "collector",
        "collector:",
        "collector:0",
        "collector:70000",
        "collector:abc",
        ":514",
        "collector:514:123",
    ] {
        assert!(
            remote_address(false, Some(bad.to_owned())).is_err(),
            "address {bad:?} must be rejected at config time"
        );
    }
    for good in ["collector:514", "127.0.0.1:514", "[::1]:514"] {
        assert!(
            remote_address(false, Some(good.to_owned())).is_ok(),
            "address {good:?} must be accepted"
        );
    }
}

/// A formatter standing in for a real sink in connection-level tests.
#[cfg(feature = "access-log-syslog")]
fn test_formatter() -> Rfc3164Formatter {
    Rfc3164Formatter {
        priority_base: SyslogFacility::Local0.priority_base(),
        hostname: None,
        process: "praxis".to_owned(),
        pid: std::process::id(),
        octet_framed: false,
    }
}

#[cfg(feature = "access-log-syslog")]
#[test]
fn rfc3164_timestamp_renders_wall_clock_in_its_own_offset() {
    // 12:00:00Z at UTC-04:00 is 08:00:00 local; the HEADER must carry local
    // wall-clock time, not UTC (the crate's formatter would emit 12:00:00).
    use chrono::{FixedOffset, TimeZone as _};
    let offset = FixedOffset::west_opt(4 * 3600).unwrap();
    let instant = offset.with_ymd_and_hms(2026, 1, 2, 8, 0, 0).unwrap();
    assert_eq!(rfc3164_timestamp(&instant), "Jan  2 08:00:00");
    // The same instant one zone east renders a different wall clock.
    let east = FixedOffset::east_opt(2 * 3600).unwrap();
    assert_eq!(rfc3164_timestamp(&instant.with_timezone(&east)), "Jan  2 14:00:00");
}

#[cfg(feature = "access-log-syslog")]
#[test]
fn syslog_unix_write_times_out_when_collector_stalls() {
    use std::time::Instant;
    // A Unix stream collector that never drains must not block the writer
    // forever: the bounded write timeout surfaces an error instead. The
    // listener is bound but never accepts, so the connected socket's send
    // buffer fills and the next write blocks until it times out.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stall.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();

    let mut logger =
        connect_unix(test_formatter(), path.to_str(), Duration::from_millis(200)).expect("connect to collector");
    let payload = "x".repeat(8192);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut timed_out = false;
    while Instant::now() < deadline {
        if logger.info(&payload).is_err() {
            timed_out = true;
            break;
        }
    }
    assert!(
        timed_out,
        "a stalled unix collector must not block the writer indefinitely"
    );
}

#[cfg(feature = "access-log-syslog")]
#[test]
fn rfc3164_message_is_capped_at_1024_bytes() {
    // RFC 3164 §4.1 limits a complete message to 1024 bytes; an overlong rendered
    // line must be truncated on the wire rather than sent in full.
    let formatter = test_formatter();
    let mut out = Vec::new();
    <Rfc3164Formatter as LogFormat<String>>::format(&formatter, &mut out, Severity::LOG_INFO, "a".repeat(4096))
        .unwrap();
    assert!(
        out.len() <= RFC3164_MAX_BYTES,
        "RFC 3164 §4.1 caps the message at {RFC3164_MAX_BYTES} bytes, got {}",
        out.len()
    );
    assert!(std::str::from_utf8(&out).is_ok(), "truncation must keep valid UTF-8");
}

#[cfg(feature = "access-log-syslog")]
#[test]
#[expect(clippy::disallowed_methods, reason = "test stalls an op with thread::sleep")]
fn with_timeout_bounds_a_stalled_operation() {
    // A completed op returns its value; an op that outlasts the timeout surfaces a
    // TimedOut error instead of blocking, which is how unix connect and DNS stay
    // bounded on the writer thread.
    let quick: std::io::Result<u8> = with_timeout(Duration::from_secs(5), || Ok(7));
    assert_eq!(quick.unwrap(), 7);
    let slow: std::io::Result<u8> = with_timeout(Duration::from_millis(50), || {
        std::thread::sleep(Duration::from_secs(5));
        Ok(0)
    });
    assert_eq!(slow.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
}

#[cfg(feature = "access-log-syslog")]
#[test]
fn syslog_writer_backs_off_after_a_failed_connect() {
    // A failed (re)connection must start a cooldown so the writer stops retrying
    // (and stops spawning helper threads) on every subsequent record until it
    // expires. A missing socket path fails the connect quickly.
    let target = SyslogTarget {
        destination: SyslogDestination::Unix {
            path: Some("/nonexistent/praxis-syslog-test.sock".to_owned()),
        },
        formatter: test_formatter(),
        dest: Arc::from("syslog:unix:/nonexistent/praxis-syslog-test.sock"),
    };
    let mut state = SyslogWriterState::default();
    assert!(!state.in_cooldown(), "no cooldown before the first attempt");
    state.emit(&target, "first");
    assert!(state.logger.is_none(), "a missing socket must not yield a logger");
    assert!(
        state.in_cooldown(),
        "a failed connect must start the reconnect cooldown"
    );
}

#[cfg(feature = "access-log-syslog")]
#[test]
fn stream_fallback_only_on_socket_type_mismatch() {
    use std::io::{Error, ErrorKind};
    // A missing socket or denied permission is a real datagram failure: surface it
    // rather than masking it with a stream-connect fallback.
    assert!(!is_wrong_socket_type(&Error::from(ErrorKind::NotFound)));
    assert!(!is_wrong_socket_type(&Error::from(ErrorKind::PermissionDenied)));
    // InvalidInput and raw EPROTOTYPE both mean the endpoint is a stream socket.
    assert!(is_wrong_socket_type(&Error::from(ErrorKind::InvalidInput)));
    assert!(is_wrong_socket_type(&Error::from_raw_os_error(EPROTOTYPE_ERRNO)));
}

#[test]
fn from_config_file_sink_opens_file() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("access.log");
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(&format!("sink:\n  type: file\n  path: {}", log_path.to_str().unwrap())).unwrap();
    let filter = test_filter(&yaml);
    assert!(
        matches!(filter.sink, RuntimeSink::Direct(_)),
        "file sink should be created"
    );
    assert!(log_path.exists(), "log file should be created on disk");
}

#[test]
fn file_sink_writes_ndjson_line() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("access.log");
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(&format!("sink:\n  type: file\n  path: {}", log_path.to_str().unwrap())).unwrap();
    let filter = test_filter(&yaml);

    let req = crate::test_utils::make_request(http::Method::GET, "/health");
    let ctx = crate::test_utils::make_filter_context(&req);
    filter.emit_access_log(&ctx, 200, None, 7);

    // The write happens on the background writer thread, so poll briefly
    // for the line to land before asserting.
    let contents = read_file_with_retry(&log_path);
    let line = contents.lines().next().expect("file sink should write one NDJSON line");
    let record: BTreeMap<String, String> = serde_json::from_str(line).unwrap();
    assert_eq!(record.get("method").map(String::as_str), Some("GET"));
    assert_eq!(record.get("path").map(String::as_str), Some("/health"));
    assert_eq!(record.get("status").map(String::as_str), Some("200"));
    let timestamp = record.get("timestamp").expect("sink record must carry a timestamp");
    assert!(
        timestamp.contains('T') && timestamp.ends_with('Z'),
        "timestamp should be RFC 3339 UTC: {timestamp:?}"
    );
}

#[test]
fn file_sink_writes_template_line() {
    // A text template routed to a direct sink renders its own line verbatim,
    // not an NDJSON record, matching what the tracing path would log.
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("template.log");
    let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
        "template: \"{{method}} {{path}} {{status}}\"\nsink:\n  type: file\n  path: {}",
        log_path.to_str().unwrap()
    ))
    .unwrap();
    let filter = test_filter(&yaml);

    let req = crate::test_utils::make_request(http::Method::GET, "/health");
    let ctx = crate::test_utils::make_filter_context(&req);
    filter.emit_access_log(&ctx, 200, None, 7);

    let contents = read_file_with_retry(&log_path);
    let line = contents
        .lines()
        .next()
        .expect("file sink should write one template line");
    assert_eq!(
        line, "GET /health 200",
        "template sink should write the rendered line, not JSON"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    clippy::disallowed_methods,
    reason = "concurrency test spawns threads and polls with thread::sleep"
)]
fn file_sink_shares_one_writer_per_path() {
    // Two filters pointed at the same path must share a single writer so
    // their NDJSON records never interleave, even under concurrency.
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("shared.log");
    let cfg_a = format!("sink:\n  type: file\n  path: {}", log_path.to_str().unwrap());
    // A different spelling of the same file (a `.` segment) must canonicalize
    // to the same registry key, so both filters resolve to one writer.
    let alt_path = dir.path().join(".").join("shared.log");
    let cfg_b = format!("sink:\n  type: file\n  path: {}", alt_path.to_str().unwrap());
    let filter_a = Arc::new(test_filter(&serde_yaml::from_str(&cfg_a).unwrap()));
    let filter_b = Arc::new(test_filter(&serde_yaml::from_str(&cfg_b).unwrap()));

    // Both filters must share one `DirectSink`, which the canonical-key
    // registry proves by handing back the same `Arc`.
    let sink = |filter: &AccessLogFilter| match &filter.sink {
        RuntimeSink::Direct(sink) => Arc::clone(sink),
        RuntimeSink::Tracing => panic!("file sink should resolve to a direct sink"),
    };
    assert!(
        Arc::ptr_eq(&sink(&filter_a), &sink(&filter_b)),
        "both path spellings should resolve to a single shared writer"
    );

    let per_thread = 200;
    let handles: Vec<_> = [(filter_a, "/a"), (filter_b, "/b")]
        .into_iter()
        .map(|(filter, path)| {
            std::thread::spawn(move || {
                let req = crate::test_utils::make_request(http::Method::GET, path);
                for _ in 0..per_thread {
                    let ctx = crate::test_utils::make_filter_context(&req);
                    filter.emit_access_log(&ctx, 200, None, 1);
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }

    // The writer thread flushes while this test reads the file, so a read can
    // catch the tail of a line before its newline lands. That partial tail is
    // not a torn record: keep polling until every line parses and the count
    // matches. A real interleave stays unparseable and fails the assert below.
    let expected = per_thread * 2;
    let mut lines = 0;
    for _ in 0..100 {
        let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
        if let Some(count) = complete_ndjson_count(&contents) {
            lines = count;
            if lines == expected {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if lines != expected {
        let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
        for line in contents.lines() {
            serde_json::from_str::<BTreeMap<String, String>>(line)
                .unwrap_or_else(|e| panic!("line should be valid NDJSON ({e}): {line}"));
        }
    }
    assert_eq!(lines, expected, "all records from both filters should be written");
}

#[test]
fn run_sink_writer_flushes_queue_then_exits_on_shutdown_flag() {
    // A writer whose sender never drops (like stdout) still exits once the
    // shutdown flag is set, after flushing everything already queued.
    let (tx, rx) = sync_channel::<String>(8);
    tx.send("alpha".to_owned()).unwrap();
    tx.send("beta".to_owned()).unwrap();
    let shutdown = AtomicBool::new(true);

    let mut buf: Vec<u8> = Vec::new();
    // Returns because the flag is set, not because the sender dropped: `tx`
    // is deliberately held live across the call.
    run_sink_writer(&mut buf, &rx, "test", &shutdown);
    drop(tx);

    assert_eq!(
        String::from_utf8(buf).unwrap(),
        "alpha\nbeta\n",
        "shutdown must flush records queued before the flag was set"
    );
}
