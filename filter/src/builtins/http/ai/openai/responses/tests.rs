// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Unit tests for the `openai_responses_format` filter.

use bytes::Bytes;

use super::*;

// -----------------------------------------------------------------------------
// Config Parsing
// -----------------------------------------------------------------------------

#[test]
fn default_config_parses() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let filter = ResponsesFormatFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "openai_responses_format",
        "filter name should be openai_responses_format"
    );
}

#[test]
fn full_config_parses() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
on_invalid: reject
max_body_bytes: 65536
headers:
  format: x-custom-format
  model: x-custom-model
  stream: x-custom-stream
"#,
    )
    .unwrap();

    let filter = ResponsesFormatFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "openai_responses_format",
        "filter name should be openai_responses_format"
    );
}

#[test]
fn on_invalid_continue_parses() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("on_invalid: continue").unwrap();
    let filter = ResponsesFormatFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "openai_responses_format", "continue mode should parse");
}

#[test]
fn on_invalid_reject_parses() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("on_invalid: reject").unwrap();
    let filter = ResponsesFormatFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "openai_responses_format", "reject mode should parse");
}

#[test]
fn deny_unknown_fields_rejects_typo() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("on_invlid: continue").unwrap();
    let result = ResponsesFormatFilter::from_config(&yaml);
    assert!(result.is_err(), "typo in config field should be rejected");
}

#[test]
fn zero_max_body_bytes_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("max_body_bytes: 0").unwrap();
    let result = ResponsesFormatFilter::from_config(&yaml);
    assert!(result.is_err(), "zero max_body_bytes should be rejected");
}

#[test]
fn rejects_max_body_bytes_above_ceiling() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("max_body_bytes: 67108865").unwrap();
    let result = ResponsesFormatFilter::from_config(&yaml);
    assert!(
        result.is_err(),
        "max_body_bytes above 64 MiB ceiling should be rejected"
    );
}

#[test]
fn invalid_header_name_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
headers:
  format: "invalid header name with spaces"
"#,
    )
    .unwrap();
    let result = ResponsesFormatFilter::from_config(&yaml);
    assert!(result.is_err(), "header name with spaces should be rejected");
}

#[test]
fn empty_header_name_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
headers:
  model: ""
"#,
    )
    .unwrap();
    let result = ResponsesFormatFilter::from_config(&yaml);
    assert!(result.is_err(), "empty header name should be rejected");
}

#[test]
fn null_header_disables_promotion() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
headers:
  format: null
  model: null
  stream: null
"#,
    )
    .unwrap();
    let filter = ResponsesFormatFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "openai_responses_format",
        "null headers should disable promotion"
    );
}

// -----------------------------------------------------------------------------
// Body Access
// -----------------------------------------------------------------------------

#[test]
fn body_access_is_read_only() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let filter = ResponsesFormatFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.request_body_access(),
        BodyAccess::ReadOnly,
        "classifier must not mutate the body"
    );
}

#[test]
fn body_mode_is_stream_buffer() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let filter = ResponsesFormatFilter::from_config(&yaml).unwrap();
    match filter.request_body_mode() {
        BodyMode::StreamBuffer { max_bytes } => {
            assert_eq!(
                max_bytes,
                Some(67_108_864),
                "StreamBuffer should default to a bounded 64 MiB limit"
            );
        },
        other => panic!("expected StreamBuffer, got {other:?}"),
    }
}

// -----------------------------------------------------------------------------
// Handle Invalid Format
// -----------------------------------------------------------------------------

#[test]
fn invalid_json_continue_returns_none() {
    let cfg: ResponsesFormatConfig = serde_yaml::from_str("on_invalid: continue").unwrap();
    let result = handle_invalid_format(AiRequestFormat::InvalidJson, &cfg);
    assert!(result.is_none(), "continue mode should return None for invalid JSON");
}

#[test]
fn invalid_json_reject_returns_reject() {
    let cfg: ResponsesFormatConfig = serde_yaml::from_str("on_invalid: reject").unwrap();
    let result = handle_invalid_format(AiRequestFormat::InvalidJson, &cfg);
    assert!(result.is_some(), "reject mode should return Reject for invalid JSON");
}

#[test]
fn non_json_continue_returns_none() {
    let cfg: ResponsesFormatConfig = serde_yaml::from_str("on_invalid: continue").unwrap();
    let result = handle_invalid_format(AiRequestFormat::NonJson, &cfg);
    assert!(result.is_none(), "continue mode should return None for non-JSON");
}

#[test]
fn non_json_reject_returns_reject() {
    let cfg: ResponsesFormatConfig = serde_yaml::from_str("on_invalid: reject").unwrap();
    let result = handle_invalid_format(AiRequestFormat::NonJson, &cfg);
    assert!(result.is_some(), "reject mode should return Reject for non-JSON");
}

#[test]
fn openai_responses_format_not_rejected() {
    let cfg: ResponsesFormatConfig = serde_yaml::from_str("on_invalid: reject").unwrap();
    let result = handle_invalid_format(AiRequestFormat::Responses, &cfg);
    assert!(result.is_none(), "responses format should not be rejected");
}

#[test]
fn chat_completions_not_rejected() {
    let cfg: ResponsesFormatConfig = serde_yaml::from_str("on_invalid: reject").unwrap();
    let result = handle_invalid_format(AiRequestFormat::ChatCompletions, &cfg);
    assert!(
        result.is_none(),
        "openai_chat_completions format should not be rejected"
    );
}

#[test]
fn unknown_json_rejected_in_reject_mode() {
    let cfg: ResponsesFormatConfig = serde_yaml::from_str("on_invalid: reject").unwrap();
    let result = handle_invalid_format(AiRequestFormat::UnknownJson, &cfg);
    assert!(result.is_some(), "unknown JSON should be rejected in reject mode");
}

#[test]
fn unknown_json_continues_in_continue_mode() {
    let cfg: ResponsesFormatConfig = serde_yaml::from_str("on_invalid: continue").unwrap();
    let result = handle_invalid_format(AiRequestFormat::UnknownJson, &cfg);
    assert!(result.is_none(), "unknown JSON should continue in continue mode");
}

// -----------------------------------------------------------------------------
// Full Reject-Path Tests (on_request_body)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn on_request_body_rejects_unknown_json() {
    let action = run_filter_raw("on_invalid: reject", r#"{"prompt":"hello"}"#).await;
    assert!(
        matches!(action, FilterAction::Reject(_)),
        "unknown JSON should be rejected"
    );
}

#[tokio::test]
async fn on_request_body_rejects_invalid_json() {
    let action = run_filter_raw("on_invalid: reject", "not json {{{").await;
    assert!(
        matches!(action, FilterAction::Reject(_)),
        "invalid JSON should be rejected"
    );
}

// -----------------------------------------------------------------------------
// Promotion Tests (on_request_body)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn promotes_headers_for_full_responses_request() {
    let ctx = run_filter("{}", FULL_RESPONSES_BODY).await;
    let headers = collect_headers(&ctx);

    assert_eq!(
        headers.get("x-praxis-ai-format"),
        Some(&"openai_responses"),
        "format header"
    );
    assert_eq!(headers.get("x-praxis-ai-model"), Some(&"gpt-4.1"), "model header");
    assert_eq!(headers.get("x-praxis-ai-stream"), Some(&"true"), "stream header");
    assert!(
        !headers.contains_key("x-praxis-ai-background"),
        "background should not have a default header"
    );
}

#[tokio::test]
async fn promotes_metadata_for_full_responses_request() {
    let ctx = run_filter("{}", FULL_RESPONSES_BODY).await;

    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.format")
            .map(String::as_str),
        Some("openai_responses")
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.model")
            .map(String::as_str),
        Some("gpt-4.1")
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.stream")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.store")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.background")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.has_previous_response_id")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.has_conversation")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn promotes_filter_results_for_full_responses_request() {
    let ctx = run_filter("{}", FULL_RESPONSES_BODY).await;
    let results = ctx.filter_results.get("openai_responses_format").unwrap();

    assert_eq!(results.get("format"), Some("openai_responses"));
    assert_eq!(results.get("model"), Some("gpt-4.1"));
    assert_eq!(results.get("stream"), Some("true"));
    assert_eq!(results.get("store"), Some("false"));
    assert_eq!(results.get("background"), Some("true"));
    assert_eq!(results.get("has_previous_response_id"), Some("true"));
    assert_eq!(results.get("has_conversation"), Some("true"));
}

#[tokio::test]
async fn missing_optional_facts_not_promoted() {
    let ctx = run_filter("{}", r#"{"input":"test"}"#).await;
    let headers = collect_headers(&ctx);

    assert_eq!(
        headers.get("x-praxis-ai-format"),
        Some(&"openai_responses"),
        "format still promoted"
    );
    assert!(!headers.contains_key("x-praxis-ai-model"), "model header absent");
    assert!(!headers.contains_key("x-praxis-ai-stream"), "stream header absent");
    assert!(
        !ctx.filter_metadata.contains_key("openai_responses_format.model"),
        "model metadata absent"
    );
    assert!(
        !ctx.filter_metadata.contains_key("openai_responses_format.stream"),
        "stream metadata absent"
    );
    assert!(
        !ctx.filter_metadata.contains_key("openai_responses_format.store"),
        "store metadata absent"
    );
    assert!(
        !ctx.filter_metadata.contains_key("openai_responses_format.background"),
        "background metadata absent"
    );
    assert!(
        !ctx.filter_metadata
            .contains_key("openai_responses_format.has_previous_response_id"),
        "prev_id metadata absent"
    );
    assert!(
        !ctx.filter_metadata
            .contains_key("openai_responses_format.has_conversation"),
        "conversation metadata absent"
    );
}

#[tokio::test]
async fn oversized_model_not_promoted_to_header_or_results() {
    let long_model = "x".repeat(300);
    let body_str = format!(r#"{{"model":"{long_model}","input":"test"}}"#);
    let ctx = run_filter("{}", &body_str).await;
    let headers = collect_headers(&ctx);

    assert!(
        !headers.contains_key("x-praxis-ai-model"),
        "oversized model not in header"
    );
    let results = ctx.filter_results.get("openai_responses_format").unwrap();
    assert!(results.get("model").is_none(), "oversized model not in results");
}

#[tokio::test]
async fn control_char_model_not_promoted() {
    let ctx = run_filter("{}", "{\"model\":\"bad\\nmodel\",\"input\":\"test\"}").await;
    let headers = collect_headers(&ctx);

    assert!(
        !headers.contains_key("x-praxis-ai-model"),
        "control-char model not in header"
    );
}

#[tokio::test]
async fn custom_headers_emitted_at_runtime() {
    let cfg = "headers:\n  format: x-custom-fmt\n  model: x-custom-mdl\n  stream: x-custom-strm";
    let ctx = run_filter(cfg, r#"{"model":"gpt-4.1","input":"test","stream":true}"#).await;
    let headers = collect_headers(&ctx);

    assert_eq!(headers.get("x-custom-fmt"), Some(&"openai_responses"), "custom format");
    assert_eq!(headers.get("x-custom-mdl"), Some(&"gpt-4.1"), "custom model");
    assert_eq!(headers.get("x-custom-strm"), Some(&"true"), "custom stream");
    assert!(
        !headers.contains_key("x-praxis-ai-format"),
        "default not emitted when overridden"
    );
}

#[tokio::test]
async fn null_headers_suppress_emission() {
    let cfg = "headers:\n  format: null\n  model: null\n  stream: null";
    let ctx = run_filter(cfg, r#"{"model":"gpt-4.1","input":"test","stream":true}"#).await;

    assert!(
        ctx.extra_request_headers.is_empty(),
        "null headers suppress all emission"
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.format")
            .map(String::as_str),
        Some("openai_responses"),
        "metadata still written with null headers"
    );
}

// -----------------------------------------------------------------------------
// Path-Based Classification (method + path in on_request_body)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn get_v1_responses_with_id_classifies_as_responses() {
    let ctx = run_filter_with_method("{}", "", http::Method::GET, "/v1/responses/resp_abc123").await;

    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.format")
            .map(String::as_str),
        Some("openai_responses"),
        "GET /v1/responses/{{id}} should classify as responses"
    );
}

#[tokio::test]
async fn get_v1_responses_input_items_classifies_as_responses() {
    let ctx = run_filter_with_method("{}", "", http::Method::GET, "/v1/responses/resp_abc123/input_items").await;

    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.format")
            .map(String::as_str),
        Some("openai_responses"),
        "GET /v1/responses/{{id}}/input_items should classify as responses"
    );
}

#[tokio::test]
async fn delete_v1_responses_with_id_classifies_as_responses() {
    let ctx = run_filter_with_method("{}", "", http::Method::DELETE, "/v1/responses/resp_abc123").await;

    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.format")
            .map(String::as_str),
        Some("openai_responses"),
        "DELETE /v1/responses/{{id}} should classify as responses"
    );
}

#[tokio::test]
async fn post_v1_responses_cancel_classifies_as_responses() {
    let ctx = run_filter_with_method("{}", "", http::Method::POST, "/v1/responses/resp_abc123/cancel").await;

    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.format")
            .map(String::as_str),
        Some("openai_responses"),
        "POST /v1/responses/{{id}}/cancel should classify as responses"
    );
    let results = ctx.filter_results.get("openai_responses_format").unwrap();
    assert_eq!(results.get("format"), Some("openai_responses"), "filter result format");
}

#[tokio::test]
async fn post_v1_responses_input_tokens_classifies_as_responses() {
    let ctx = run_filter_with_method("{}", "", http::Method::POST, "/v1/responses/input_tokens").await;

    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.format")
            .map(String::as_str),
        Some("openai_responses"),
        "POST /v1/responses/input_tokens should classify as responses"
    );
}

#[tokio::test]
async fn post_v1_responses_compact_classifies_as_responses() {
    let ctx = run_filter_with_method("{}", "", http::Method::POST, "/v1/responses/compact").await;

    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.format")
            .map(String::as_str),
        Some("openai_responses"),
        "POST /v1/responses/compact should classify as responses"
    );
}

#[tokio::test]
async fn get_path_match_promotes_filter_results() {
    let ctx = run_filter_with_method("{}", "", http::Method::GET, "/v1/responses/resp_abc123").await;
    let results = ctx.filter_results.get("openai_responses_format").unwrap();

    assert_eq!(results.get("format"), Some("openai_responses"), "filter result format");
    assert_eq!(results.get("model"), None, "no model from path-only classification");
    assert_eq!(results.get("stream"), None, "no stream from path-only classification");
}

#[tokio::test]
async fn delete_path_match_promotes_filter_results() {
    let ctx = run_filter_with_method("{}", "", http::Method::DELETE, "/v1/responses/resp_abc123").await;
    let results = ctx.filter_results.get("openai_responses_format").unwrap();

    assert_eq!(results.get("format"), Some("openai_responses"), "filter result format");
}

#[tokio::test]
async fn get_path_match_promotes_format_header() {
    let ctx = run_filter_with_method("{}", "", http::Method::GET, "/v1/responses/resp_abc").await;
    let headers = collect_headers(&ctx);

    assert_eq!(
        headers.get("x-praxis-ai-format"),
        Some(&"openai_responses"),
        "GET path match should promote format header"
    );
    assert!(
        !headers.contains_key("x-praxis-ai-model"),
        "no model for path-only classification"
    );
    assert!(
        !headers.contains_key("x-praxis-ai-stream"),
        "no stream for path-only classification"
    );
}

#[tokio::test]
async fn get_path_match_no_body_facts() {
    let ctx = run_filter_with_method("{}", "", http::Method::GET, "/v1/responses/resp_abc").await;

    assert!(
        !ctx.filter_metadata.contains_key("openai_responses_format.model"),
        "no model from path-only classification"
    );
    assert!(
        !ctx.filter_metadata.contains_key("openai_responses_format.stream"),
        "no stream from path-only classification"
    );
    assert!(
        !ctx.filter_metadata.contains_key("openai_responses_format.store"),
        "no store from path-only classification"
    );
    assert!(
        !ctx.filter_metadata.contains_key("openai_responses_format.background"),
        "no background from path-only classification"
    );
}

#[tokio::test]
async fn put_unrelated_path_classifies_body_normally() {
    let ctx = run_filter_with_method(
        "{}",
        r#"{"model":"gpt-4","messages":[]}"#,
        http::Method::PUT,
        "/v1/chat/completions",
    )
    .await;

    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.format")
            .map(String::as_str),
        Some("openai_chat_completions"),
        "non-path method should classify using request body"
    );
}

#[tokio::test]
async fn post_v1_responses_classifies_body_normally() {
    let ctx = run_filter_with_method(
        "{}",
        r#"{"model":"gpt-4.1","input":"test"}"#,
        http::Method::POST,
        "/v1/responses",
    )
    .await;

    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.format")
            .map(String::as_str),
        Some("openai_responses"),
        "POST should classify via body, not path"
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_format.model")
            .map(String::as_str),
        Some("gpt-4.1"),
        "POST should extract model from body"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Full Responses body with all optional fields for promotion tests.
const FULL_RESPONSES_BODY: &str = r#"{"model":"gpt-4.1","input":"test","stream":true,"store":false,"background":true,"previous_response_id":"resp_abc","conversation":{"id":"conv_1"}}"#;

/// Run the filter's `on_request_body` and return the resulting context.
async fn run_filter(config_yaml: &str, body_str: &str) -> HttpFilterContext<'static> {
    let filter = make_filter(config_yaml);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");

    let req: &'static crate::context::Request = Box::leak(Box::new(req));
    let mut ctx = crate::test_utils::make_filter_context(req);
    let mut body = Some(Bytes::from(body_str.to_owned()));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Release), "filter should release");
    ctx
}

/// Collect extra request headers into a map for assertion.
fn collect_headers<'a>(ctx: &'a HttpFilterContext<'_>) -> std::collections::HashMap<&'a str, &'a str> {
    ctx.extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect()
}

/// Run the filter's `on_request_body` and return the raw action.
async fn run_filter_raw(config_yaml: &str, body_str: &str) -> FilterAction {
    let filter = make_filter(config_yaml);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");

    let req: &'static crate::context::Request = Box::leak(Box::new(req));
    let mut ctx = crate::test_utils::make_filter_context(req);
    let mut body = Some(Bytes::from(body_str.to_owned()));

    filter.on_request_body(&mut ctx, &mut body, true).await.unwrap()
}

/// Run the filter's `on_request_body` with a custom method and path.
async fn run_filter_with_method(
    config_yaml: &str,
    body_str: &str,
    method: http::Method,
    path: &str,
) -> HttpFilterContext<'static> {
    let filter = make_filter(config_yaml);
    let req = crate::test_utils::make_request(method, path);

    let req: &'static crate::context::Request = Box::leak(Box::new(req));
    let mut ctx = crate::test_utils::make_filter_context(req);
    let mut body = Some(Bytes::from(body_str.to_owned()));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Release), "filter should release");
    ctx
}

/// Build a `ResponsesFormatFilter` from a YAML snippet.
fn make_filter(yaml_str: &str) -> Box<dyn HttpFilter> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(yaml_str).unwrap();
    ResponsesFormatFilter::from_config(&yaml).unwrap()
}
