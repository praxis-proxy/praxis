// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

use bytes::Bytes;

use super::*;

// -----------------------------------------------------------------------------
// Config Parsing — Valid
// -----------------------------------------------------------------------------

#[test]
fn from_config_minimal_alias_only() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
model_aliases:
  codex-mini-latest: "llama-3.3-70b"
"#,
    )
    .unwrap();
    let filter = ModelRewriteFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "openai_responses_model_rewrite",
        "filter name should match"
    );
}

#[test]
fn from_config_accepts_wildcard_alias() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
model_aliases:
  "codex-*": "llama-3.3-70b"
"#,
    )
    .unwrap();
    let filter = ModelRewriteFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "openai_responses_model_rewrite",
        "single-wildcard alias should parse"
    );
}

#[test]
fn from_config_minimal_default_only() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(r#"default_model: "llama-3.3-70b""#).unwrap();
    let filter = ModelRewriteFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "openai_responses_model_rewrite",
        "default-only config should parse"
    );
}

#[test]
fn from_config_full() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
default_model: "llama-3.3-70b"
model_aliases:
  codex-mini-latest: "llama-3.3-70b"
  gpt-4.1-mini: "qwen-2.5-72b"
max_body_bytes: 65536
on_invalid: reject
headers:
  effective_model: x-custom-effective
  original_model: x-custom-original
"#,
    )
    .unwrap();
    let filter = ModelRewriteFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "openai_responses_model_rewrite",
        "full config should parse"
    );
}

// -----------------------------------------------------------------------------
// Config Parsing — Rejection
// -----------------------------------------------------------------------------

#[test]
fn from_config_rejects_empty_default_model() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(r#"default_model: """#).unwrap();
    let result = ModelRewriteFilter::from_config(&yaml);
    assert!(result.is_err(), "empty default_model should be rejected");
}

#[test]
fn from_config_rejects_whitespace_default_model() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(r#"default_model: "   ""#).unwrap();
    let result = ModelRewriteFilter::from_config(&yaml);
    assert!(result.is_err(), "whitespace-only default_model should be rejected");
}

#[test]
fn from_config_rejects_no_default_and_no_aliases() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let result = ModelRewriteFilter::from_config(&yaml);
    assert!(
        result.is_err(),
        "config with neither default_model nor aliases should be rejected"
    );
}

#[test]
fn from_config_rejects_empty_alias_source() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
model_aliases:
  "": "llama-3.3-70b"
"#,
    )
    .unwrap();
    let result = ModelRewriteFilter::from_config(&yaml);
    assert!(result.is_err(), "empty alias source should be rejected");
}

#[test]
fn from_config_rejects_empty_alias_target() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
model_aliases:
  codex-mini-latest: ""
"#,
    )
    .unwrap();
    let result = ModelRewriteFilter::from_config(&yaml);
    assert!(result.is_err(), "empty alias target should be rejected");
}

#[test]
fn from_config_rejects_alias_source_with_multiple_wildcards() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
model_aliases:
  "gpt-*-mini-*": "qwen-2.5-72b"
"#,
    )
    .unwrap();
    let result = ModelRewriteFilter::from_config(&yaml);
    assert!(
        result.is_err(),
        "alias source with more than one wildcard should be rejected"
    );
}

#[test]
fn from_config_rejects_zero_max_body_bytes() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
default_model: "test"
max_body_bytes: 0
"#,
    )
    .unwrap();
    let result = ModelRewriteFilter::from_config(&yaml);
    assert!(result.is_err(), "zero max_body_bytes should be rejected");
}

#[test]
fn from_config_rejects_oversized_max_body_bytes() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
default_model: "test"
max_body_bytes: 67108865
"#,
    )
    .unwrap();
    let result = ModelRewriteFilter::from_config(&yaml);
    assert!(
        result.is_err(),
        "max_body_bytes above 64 MiB ceiling should be rejected"
    );
}

#[test]
fn from_config_rejects_unknown_fields() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
default_model: "test"
unknown_field: true
"#,
    )
    .unwrap();
    let result = ModelRewriteFilter::from_config(&yaml);
    assert!(result.is_err(), "unknown fields should be rejected");
}

#[test]
fn from_config_rejects_invalid_header_name() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
default_model: "test"
headers:
  effective_model: "invalid header with spaces"
"#,
    )
    .unwrap();
    let result = ModelRewriteFilter::from_config(&yaml);
    assert!(result.is_err(), "header name with spaces should be rejected");
}

#[test]
fn from_config_rejects_empty_header_name() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
default_model: "test"
headers:
  effective_model: ""
"#,
    )
    .unwrap();
    let result = ModelRewriteFilter::from_config(&yaml);
    assert!(result.is_err(), "empty header name should be rejected");
}

#[test]
fn from_config_null_headers_suppress_promotion() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
default_model: "test"
headers:
  effective_model: null
  original_model: null
"#,
    )
    .unwrap();
    let filter = ModelRewriteFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "openai_responses_model_rewrite",
        "null headers should be accepted"
    );
}

// -----------------------------------------------------------------------------
// Trait Properties
// -----------------------------------------------------------------------------

#[test]
fn body_access_is_read_write() {
    let filter = make_filter(ALIAS_CONFIG);
    assert_eq!(
        filter.request_body_access(),
        BodyAccess::ReadWrite,
        "model rewrite must use ReadWrite body access"
    );
}

#[test]
fn body_mode_is_stream_buffer() {
    let filter = make_filter(ALIAS_CONFIG);
    match filter.request_body_mode() {
        BodyMode::StreamBuffer { max_bytes } => {
            assert!(max_bytes.is_some(), "StreamBuffer should have a bounded limit");
        },
        other => panic!("expected StreamBuffer, got {other:?}"),
    }
}

// -----------------------------------------------------------------------------
// Body Processing — Skip Paths
// -----------------------------------------------------------------------------

#[tokio::test]
async fn not_end_of_stream_continues() {
    let filter = make_filter(ALIAS_CONFIG);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(r#"{"model":"gpt-4.1","input":"test"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "non-end-of-stream should continue"
    );
}

#[tokio::test]
async fn empty_body_continues() {
    let filter = make_filter(ALIAS_CONFIG);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body: Option<Bytes> = None;

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "empty body should continue");
}

#[tokio::test]
async fn chat_completions_path_skips() {
    let filter = make_filter(ALIAS_CONFIG);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat/completions");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(r#"{"model":"codex-mini-latest","messages":[]}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "chat completions path should skip"
    );
    assert!(
        !ctx.filter_metadata
            .contains_key("openai_responses_model_rewrite.effective_model"),
        "non-responses path should not set metadata"
    );
}

#[tokio::test]
async fn get_responses_id_skips() {
    let filter = make_filter(REJECT_CONFIG);
    let req = crate::test_utils::make_request(http::Method::GET, "/v1/responses/resp_abc123");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body: Option<Bytes> = None;

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "GET /v1/responses/{{id}} should skip even in reject mode"
    );
}

#[tokio::test]
async fn delete_responses_id_skips() {
    let filter = make_filter(REJECT_CONFIG);
    let req = crate::test_utils::make_request(http::Method::DELETE, "/v1/responses/resp_abc123");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body: Option<Bytes> = None;

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "DELETE /v1/responses/{{id}} should skip even in reject mode"
    );
}

#[tokio::test]
async fn post_cancel_subresource_skips() {
    let filter = make_filter(REJECT_CONFIG);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses/resp_abc/cancel");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body: Option<Bytes> = Some(Bytes::new());

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "POST /v1/responses/{{id}}/cancel should skip even in reject mode"
    );
}

#[tokio::test]
async fn post_input_tokens_subresource_skips() {
    let filter = make_filter(REJECT_CONFIG);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses/input_tokens");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body: Option<Bytes> = Some(Bytes::new());

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "POST /v1/responses/input_tokens should skip"
    );
}

#[tokio::test]
async fn post_compact_subresource_skips() {
    let filter = make_filter(REJECT_CONFIG);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses/compact");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body: Option<Bytes> = Some(Bytes::new());

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "POST /v1/responses/compact should skip"
    );
}

#[tokio::test]
async fn trailing_slash_treated_as_create() {
    let filter = make_filter(ALIAS_CONFIG);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(r#"{"model":"codex-mini-latest","input":"test"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "trailing slash should be treated as create"
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_model_rewrite.effective_model")
            .map(String::as_str),
        Some("llama-3.3-70b"),
        "model should be rewritten for trailing-slash create"
    );
}

#[tokio::test]
async fn reject_mode_rejects_malformed_create() {
    let filter = make_filter(REJECT_CONFIG);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from("not valid json {{{"));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(_)),
        "malformed POST /v1/responses should be rejected in reject mode"
    );
}

#[tokio::test]
async fn control_char_model_not_promoted_to_metadata() {
    let ctx = run_filter(ALIAS_CONFIG, "{\"model\":\"bad\\nmodel\",\"input\":\"test\"}").await;

    assert!(
        !ctx.filter_metadata
            .contains_key("openai_responses_model_rewrite.effective_model"),
        "control-char model should not be written to metadata"
    );
    assert!(
        !ctx.filter_metadata
            .contains_key("openai_responses_model_rewrite.original_model"),
        "control-char original model should not be written to metadata"
    );
}

// -----------------------------------------------------------------------------
// Body Processing — Invalid Input
// -----------------------------------------------------------------------------

#[tokio::test]
async fn invalid_json_continue_leaves_body_unchanged() {
    let original = b"not json {{{";
    let ctx = run_filter(ALIAS_CONFIG, std::str::from_utf8(original).unwrap()).await;

    assert!(
        !ctx.filter_metadata
            .contains_key("openai_responses_model_rewrite.effective_model"),
        "invalid JSON in continue mode should not set metadata"
    );
}

#[tokio::test]
async fn invalid_json_reject_returns_400() {
    let action = run_filter_raw(REJECT_CONFIG, "not json {{{").await;
    assert!(
        matches!(action, FilterAction::Reject(_)),
        "invalid JSON in reject mode should return 400"
    );
}

#[tokio::test]
async fn non_object_json_continue_leaves_body_unchanged() {
    let ctx = run_filter(ALIAS_CONFIG, "[1, 2, 3]").await;

    assert!(
        !ctx.filter_metadata
            .contains_key("openai_responses_model_rewrite.effective_model"),
        "non-object JSON in continue mode should not set metadata"
    );
}

#[tokio::test]
async fn non_object_json_reject_returns_400() {
    let action = run_filter_raw(REJECT_CONFIG, "[1, 2, 3]").await;
    assert!(
        matches!(action, FilterAction::Reject(_)),
        "non-object JSON in reject mode should return 400"
    );
}

// -----------------------------------------------------------------------------
// Body Processing — Mutation
// -----------------------------------------------------------------------------

#[tokio::test]
async fn known_alias_rewrites_model() {
    let (ctx, body) = run_filter_with_body(ALIAS_CONFIG, r#"{"model":"codex-mini-latest","input":"test"}"#).await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed["model"].as_str(),
        Some("llama-3.3-70b"),
        "model should be rewritten to alias target"
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_model_rewrite.effective_model")
            .map(String::as_str),
        Some("llama-3.3-70b"),
        "effective model metadata"
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_model_rewrite.original_model")
            .map(String::as_str),
        Some("codex-mini-latest"),
        "original model metadata"
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_model_rewrite.rewritten")
            .map(String::as_str),
        Some("true"),
        "rewritten flag"
    );
}

#[tokio::test]
async fn wildcard_alias_rewrites_model() {
    let (ctx, body) = run_filter_with_body(
        WILDCARD_ALIAS_CONFIG,
        r#"{"model":"codex-mini-2026-06-24","input":"test"}"#,
    )
    .await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed["model"].as_str(),
        Some("llama-3.3-70b"),
        "wildcard alias should rewrite matching model"
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_model_rewrite.original_model")
            .map(String::as_str),
        Some("codex-mini-2026-06-24"),
        "original model metadata should preserve wildcard-matched client model"
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_model_rewrite.rewritten")
            .map(String::as_str),
        Some("true"),
        "wildcard rewrite should set rewritten flag"
    );
}

#[tokio::test]
async fn exact_alias_beats_wildcard_alias() {
    let (ctx, body) =
        run_filter_with_body(WILDCARD_ALIAS_CONFIG, r#"{"model":"codex-mini-latest","input":"test"}"#).await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed["model"].as_str(),
        Some("llama-exact"),
        "exact alias should take precedence over wildcard alias"
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_model_rewrite.effective_model")
            .map(String::as_str),
        Some("llama-exact"),
        "effective model metadata should use exact alias target"
    );
}

#[tokio::test]
async fn more_specific_wildcard_alias_beats_less_specific_alias() {
    let (_ctx, body) = run_filter_with_body(
        WILDCARD_ALIAS_CONFIG,
        r#"{"model":"gpt-4.1-2026-06-24","input":"test"}"#,
    )
    .await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed["model"].as_str(),
        Some("qwen-2.5-72b"),
        "more specific wildcard should beat broader wildcard"
    );
}

#[tokio::test]
async fn wildcard_alias_tie_uses_lexical_pattern_order() {
    let (_ctx, body) = run_filter_with_body(WILDCARD_ALIAS_CONFIG, r#"{"model":"foo-bar","input":"test"}"#).await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed["model"].as_str(),
        Some("bar-family"),
        "equal-specificity wildcard ties should be deterministic"
    );
}

#[tokio::test]
async fn wildcard_alias_miss_passes_model_unchanged() {
    let (ctx, body) =
        run_filter_with_body(WILDCARD_ALIAS_CONFIG, r#"{"model":"anthropic-sonnet","input":"test"}"#).await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed["model"].as_str(),
        Some("anthropic-sonnet"),
        "non-matching wildcard aliases should pass through unchanged"
    );
    assert!(
        !ctx.filter_metadata
            .contains_key("openai_responses_model_rewrite.rewritten"),
        "wildcard miss should not set rewritten flag"
    );
}

#[tokio::test]
async fn missing_model_injects_default() {
    let (ctx, body) = run_filter_with_body(DEFAULT_CONFIG, r#"{"input":"test"}"#).await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed["model"].as_str(),
        Some("llama-3.3-70b"),
        "default model should be injected"
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_model_rewrite.default_injected")
            .map(String::as_str),
        Some("true"),
        "default_injected flag"
    );
    assert!(
        !ctx.filter_metadata
            .contains_key("openai_responses_model_rewrite.original_model"),
        "no original model when missing"
    );
}

#[tokio::test]
async fn null_model_injects_default() {
    let (ctx, body) = run_filter_with_body(DEFAULT_CONFIG, r#"{"model":null,"input":"test"}"#).await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed["model"].as_str(),
        Some("llama-3.3-70b"),
        "null model should be replaced with default"
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_model_rewrite.default_injected")
            .map(String::as_str),
        Some("true"),
        "default_injected flag"
    );
}

#[tokio::test]
async fn unknown_model_passes_unchanged() {
    let (ctx, body) = run_filter_with_body(ALIAS_CONFIG, r#"{"model":"unknown-model","input":"test"}"#).await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed["model"].as_str(),
        Some("unknown-model"),
        "unknown model should pass through unchanged"
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_model_rewrite.effective_model")
            .map(String::as_str),
        Some("unknown-model"),
        "effective model should equal original"
    );
    assert!(
        !ctx.filter_metadata
            .contains_key("openai_responses_model_rewrite.rewritten"),
        "rewritten flag should not be set"
    );
}

#[tokio::test]
async fn no_default_and_no_alias_match_is_noop() {
    let (ctx, body) = run_filter_with_body(ALIAS_CONFIG, r#"{"model":"unknown-model","input":"test"}"#).await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed["model"].as_str(),
        Some("unknown-model"),
        "body should not be mutated"
    );
    assert!(
        ctx.extra_request_headers
            .iter()
            .all(|(k, _)| k.as_ref() != "content-length"),
        "content-length should not be added when body is unmodified"
    );
}

#[tokio::test]
async fn non_string_model_is_noop() {
    let (ctx, body) = run_filter_with_body(DEFAULT_CONFIG, r#"{"model":123,"input":"test"}"#).await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed["model"].as_u64(),
        Some(123),
        "numeric model should pass through unchanged"
    );
    assert!(
        !ctx.filter_metadata
            .contains_key("openai_responses_model_rewrite.default_injected"),
        "default should not be injected for non-string model"
    );
    assert!(
        ctx.extra_request_headers
            .iter()
            .all(|(k, _)| k.as_ref() != "content-length"),
        "content-length should not be added when body is unmodified"
    );
}

#[tokio::test]
async fn object_model_is_noop() {
    let (ctx, body) = run_filter_with_body(DEFAULT_CONFIG, r#"{"model":{},"input":"test"}"#).await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        parsed["model"].is_object(),
        "object model should pass through unchanged"
    );
    assert!(
        !ctx.filter_metadata
            .contains_key("openai_responses_model_rewrite.default_injected"),
        "default should not be injected for object model"
    );
}

// -----------------------------------------------------------------------------
// Body Processing — Field Preservation
// -----------------------------------------------------------------------------

#[tokio::test]
async fn preserves_input_tools_instructions_and_unknown_fields() {
    let input_body = r#"{"model":"codex-mini-latest","input":[{"role":"user","content":"Hello"}],"instructions":"Be helpful","tools":[{"type":"function","name":"read_file"}],"custom_field":"preserved","stream":true}"#;

    let (_ctx, body) = run_filter_with_body(ALIAS_CONFIG, input_body).await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed["model"].as_str(),
        Some("llama-3.3-70b"),
        "model should be rewritten"
    );
    assert!(parsed["input"].is_array(), "input should be preserved");
    assert_eq!(
        parsed["instructions"].as_str(),
        Some("Be helpful"),
        "instructions should be preserved"
    );
    assert!(parsed["tools"].is_array(), "tools should be preserved");
    assert_eq!(
        parsed["tools"][0]["name"].as_str(),
        Some("read_file"),
        "tool name should be preserved"
    );
    assert_eq!(
        parsed["custom_field"].as_str(),
        Some("preserved"),
        "unknown fields should be preserved"
    );
    assert_eq!(parsed["stream"].as_bool(), Some(true), "stream should be preserved");
}

#[tokio::test]
async fn preserves_function_call_output_items() {
    let input_body = r#"{"model":"codex-mini-latest","input":[{"type":"function_call_output","call_id":"call_abc","output":"{\"result\":42}"},{"role":"user","content":"What happened?"}]}"#;

    let (_ctx, body) = run_filter_with_body(ALIAS_CONFIG, input_body).await;

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["model"].as_str(), Some("llama-3.3-70b"), "model rewritten");
    let items = parsed["input"].as_array().unwrap();
    assert_eq!(items.len(), 2, "input items preserved");
    assert_eq!(
        items[0]["type"].as_str(),
        Some("function_call_output"),
        "function_call_output type preserved"
    );
    assert_eq!(items[0]["call_id"].as_str(), Some("call_abc"), "call_id preserved");
}

// -----------------------------------------------------------------------------
// Content-Length Behavior
// -----------------------------------------------------------------------------

#[tokio::test]
async fn updates_content_length_when_mutated() {
    let (ctx, body) = run_filter_with_body(ALIAS_CONFIG, r#"{"model":"codex-mini-latest","input":"test"}"#).await;

    let cl_header = ctx
        .extra_request_headers
        .iter()
        .find(|(k, _)| k.as_ref() == "content-length")
        .map(|(_, v)| v.as_str());

    assert!(cl_header.is_some(), "content-length should be set after mutation");
    let cl_value: usize = cl_header.unwrap().parse().unwrap();
    assert_eq!(
        cl_value,
        body.len(),
        "content-length should match serialized body length"
    );
}

#[tokio::test]
async fn does_not_add_content_length_when_unmodified() {
    let ctx = run_filter(ALIAS_CONFIG, r#"{"model":"unknown-model","input":"test"}"#).await;

    assert!(
        ctx.extra_request_headers
            .iter()
            .all(|(k, _)| k.as_ref() != "content-length"),
        "content-length should not be added when body is unmodified"
    );
}

// -----------------------------------------------------------------------------
// Header and Metadata Promotion
// -----------------------------------------------------------------------------

#[tokio::test]
async fn sets_effective_model_header_and_metadata() {
    let ctx = run_filter(ALIAS_CONFIG, r#"{"model":"codex-mini-latest","input":"test"}"#).await;
    let headers = collect_headers(&ctx);

    assert_eq!(
        headers.get("x-praxis-ai-effective-model"),
        Some(&"llama-3.3-70b"),
        "effective model header"
    );
}

#[tokio::test]
async fn sets_original_model_header_when_present() {
    let ctx = run_filter(ALIAS_CONFIG, r#"{"model":"codex-mini-latest","input":"test"}"#).await;
    let headers = collect_headers(&ctx);

    assert_eq!(
        headers.get("x-praxis-ai-original-model"),
        Some(&"codex-mini-latest"),
        "original model header"
    );
}

#[tokio::test]
async fn no_original_model_header_when_model_absent() {
    let ctx = run_filter(DEFAULT_CONFIG, r#"{"input":"test"}"#).await;
    let headers = collect_headers(&ctx);

    assert!(
        !headers.contains_key("x-praxis-ai-original-model"),
        "no original model header when model was absent"
    );
    assert_eq!(
        headers.get("x-praxis-ai-effective-model"),
        Some(&"llama-3.3-70b"),
        "effective model header should be set for default injection"
    );
}

#[tokio::test]
async fn custom_headers_emitted() {
    let cfg = r#"
default_model: "test-model"
headers:
  effective_model: x-custom-eff
  original_model: x-custom-orig
"#;
    let ctx = run_filter(cfg, r#"{"model":"old","input":"test"}"#).await;
    let headers = collect_headers(&ctx);

    assert!(
        !headers.contains_key("x-praxis-ai-effective-model"),
        "default header should not be emitted when overridden"
    );
    assert_eq!(
        headers.get("x-custom-eff"),
        Some(&"old"),
        "custom effective model header"
    );
    assert_eq!(
        headers.get("x-custom-orig"),
        Some(&"old"),
        "custom original model header"
    );
}

#[tokio::test]
async fn null_headers_suppress_emission() {
    let cfg = r#"
default_model: "test-model"
headers:
  effective_model: null
  original_model: null
"#;
    let ctx = run_filter(cfg, r#"{"model":"old","input":"test"}"#).await;
    let headers = collect_headers(&ctx);

    assert!(
        !headers.contains_key("x-praxis-ai-effective-model"),
        "null effective header suppressed"
    );
    assert!(
        !headers.contains_key("x-praxis-ai-original-model"),
        "null original header suppressed"
    );
    assert_eq!(
        ctx.filter_metadata
            .get("openai_responses_model_rewrite.effective_model")
            .map(String::as_str),
        Some("old"),
        "metadata still written even with null headers"
    );
}

// -----------------------------------------------------------------------------
// Filter Results
// -----------------------------------------------------------------------------

#[tokio::test]
async fn filter_results_record_rewrite_decision() {
    let ctx = run_filter(ALIAS_CONFIG, r#"{"model":"codex-mini-latest","input":"test"}"#).await;
    let results = ctx.filter_results.get("openai_responses_model_rewrite").unwrap();

    assert_eq!(
        results.get("effective_model"),
        Some("llama-3.3-70b"),
        "effective_model filter result"
    );
    assert_eq!(results.get("rewritten"), Some("true"), "rewritten filter result");
    assert!(
        results.get("default_injected").is_none(),
        "default_injected should not be set for alias rewrite"
    );
}

#[tokio::test]
async fn filter_results_record_default_injection() {
    let ctx = run_filter(DEFAULT_CONFIG, r#"{"input":"test"}"#).await;
    let results = ctx.filter_results.get("openai_responses_model_rewrite").unwrap();

    assert_eq!(
        results.get("effective_model"),
        Some("llama-3.3-70b"),
        "effective_model filter result"
    );
    assert_eq!(
        results.get("default_injected"),
        Some("true"),
        "default_injected filter result"
    );
    assert!(
        results.get("rewritten").is_none(),
        "rewritten should not be set for default injection"
    );
}

#[tokio::test]
async fn on_request_repopulates_filter_results_from_metadata() {
    let filter = make_filter(ALIAS_CONFIG);
    let req: &'static crate::context::Request = Box::leak(Box::new(crate::test_utils::make_request(
        http::Method::POST,
        "/v1/responses",
    )));
    let mut ctx = crate::test_utils::make_filter_context(req);

    ctx.set_metadata("openai_responses_model_rewrite.effective_model", "llama-3.3-70b");
    ctx.set_metadata("openai_responses_model_rewrite.rewritten", "true");

    ctx.filter_results.clear();
    assert!(
        !ctx.filter_results.contains_key("openai_responses_model_rewrite"),
        "results should be cleared before on_request"
    );

    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "on_request should continue");

    let results = ctx.filter_results.get("openai_responses_model_rewrite").unwrap();
    assert_eq!(
        results.get("effective_model"),
        Some("llama-3.3-70b"),
        "on_request should repopulate effective_model from metadata"
    );
    assert_eq!(
        results.get("rewritten"),
        Some("true"),
        "on_request should repopulate rewritten from metadata"
    );
}

#[tokio::test]
async fn on_request_skips_repopulation_when_no_metadata() {
    let filter = make_filter(ALIAS_CONFIG);
    let req: &'static crate::context::Request = Box::leak(Box::new(crate::test_utils::make_request(
        http::Method::POST,
        "/v1/responses",
    )));
    let mut ctx = crate::test_utils::make_filter_context(req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "on_request should continue");

    assert!(
        !ctx.filter_results.contains_key("openai_responses_model_rewrite"),
        "on_request should not create results when no metadata exists"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Config with only alias mapping.
const ALIAS_CONFIG: &str = r#"
model_aliases:
  codex-mini-latest: "llama-3.3-70b"
  gpt-4.1-mini: "qwen-2.5-72b"
"#;

/// Config with exact and wildcard alias mappings.
const WILDCARD_ALIAS_CONFIG: &str = r#"
model_aliases:
  codex-mini-latest: "llama-exact"
  "codex-*": "llama-3.3-70b"
  "gpt-*": "generic-gpt"
  "gpt-4.1-*": "qwen-2.5-72b"
  "foo-*": "foo-family"
  "*-bar": "bar-family"
"#;

/// Config with only default model.
const DEFAULT_CONFIG: &str = r#"default_model: "llama-3.3-70b""#;

/// Config with reject behavior.
const REJECT_CONFIG: &str = r#"
model_aliases:
  codex-mini-latest: "llama-3.3-70b"
on_invalid: reject
"#;

/// Build a [`ModelRewriteFilter`] from a YAML snippet.
fn make_filter(yaml_str: &str) -> Box<dyn HttpFilter> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(yaml_str).unwrap();
    ModelRewriteFilter::from_config(&yaml).unwrap()
}

/// Run the filter and return the resulting context.
async fn run_filter(config_yaml: &str, body_str: &str) -> HttpFilterContext<'static> {
    let filter = make_filter(config_yaml);
    let req: &'static crate::context::Request = Box::leak(Box::new(crate::test_utils::make_request(
        http::Method::POST,
        "/v1/responses",
    )));
    let mut ctx = crate::test_utils::make_filter_context(req);
    let mut body = Some(Bytes::from(body_str.to_owned()));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "valid request should continue: got {action:?}"
    );
    ctx
}

/// Run the filter and return both context and final body bytes.
async fn run_filter_with_body(config_yaml: &str, body_str: &str) -> (HttpFilterContext<'static>, Bytes) {
    let filter = make_filter(config_yaml);
    let req: &'static crate::context::Request = Box::leak(Box::new(crate::test_utils::make_request(
        http::Method::POST,
        "/v1/responses",
    )));
    let mut ctx = crate::test_utils::make_filter_context(req);
    let mut body = Some(Bytes::from(body_str.to_owned()));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "valid request should continue: got {action:?}"
    );
    (ctx, body.unwrap())
}

/// Run the filter and return the raw action.
async fn run_filter_raw(config_yaml: &str, body_str: &str) -> FilterAction {
    let filter = make_filter(config_yaml);
    let req: &'static crate::context::Request = Box::leak(Box::new(crate::test_utils::make_request(
        http::Method::POST,
        "/v1/responses",
    )));
    let mut ctx = crate::test_utils::make_filter_context(req);
    let mut body = Some(Bytes::from(body_str.to_owned()));

    filter.on_request_body(&mut ctx, &mut body, true).await.unwrap()
}

/// Collect extra request headers into a map for assertions.
fn collect_headers<'a>(ctx: &'a HttpFilterContext<'_>) -> HashMap<&'a str, &'a str> {
    ctx.extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect()
}
