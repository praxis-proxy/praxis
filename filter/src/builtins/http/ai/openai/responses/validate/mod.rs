// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `openai_responses_validate` filter: validate and enrich incoming Responses
//! API requests.
//!
//! Expects the upstream `openai_responses_format` classifier to have already
//! identified this request as a Responses API request and promoted
//! routing facts (`model`, `stream`, `store`, `background`) to
//! `openai_responses_format.*` metadata.
//!
//! This filter reads classifier metadata for parameter-combination
//! validation, then does targeted JSON field extraction for
//! `conversation.id`. It does **not** deserialize the full body into a
//! typed struct.
//!
//! # YAML
//!
//! ```yaml
//! filter: openai_responses_validate
//! ```

mod rules;

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use tracing::{debug, trace};

use self::rules::validate_request;
use super::error::responses_error_rejection;
use crate::{
    FilterAction, FilterError,
    body::{BodyAccess, BodyMode, MAX_JSON_BODY_BYTES},
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// OpenaiResponsesValidateFilter
// -----------------------------------------------------------------------------

/// Validates and enriches Responses API requests.
///
/// Reads classifier metadata for parameter-combination checks, then
/// parses the body as [`serde_json::Value`] for targeted field
/// extraction. Does not deserialize the full body into a typed struct.
///
/// Must be placed after `openai_responses_format` in the filter chain.
/// Skips non-Responses API requests (those not classified as
/// `openai_responses`).
///
/// Validation rules: rejects `stream=true` combined with
/// `background=true` (400), rejects `background=true` combined with
/// `store=false` (400).
///
/// Generates metadata: `responses.response_id` (format: `resp_` + 32
/// hex chars, CSPRNG), `responses.conversation_id`, `responses.store`,
/// `responses.background`, `responses.stream`.
///
/// This filter has no configuration, body buffering is handled by
/// the upstream `openai_responses_format` classifier.
#[derive(Default)]
pub struct OpenaiResponsesValidateFilter;

impl OpenaiResponsesValidateFilter {
    /// Create a filter from YAML config.
    ///
    /// This filter has no configuration fields. The config parameter
    /// is accepted but ignored.
    ///
    /// # Errors
    ///
    /// This function does not return errors; the `Result` return type
    /// is required by the [`FilterFactory`] signature.
    ///
    /// [`FilterFactory`]: crate::FilterFactory
    #[expect(clippy::unnecessary_wraps, reason = "signature required by FilterFactory")]
    pub fn from_config(_config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        Ok(Box::new(Self))
    }
}

#[async_trait]
impl HttpFilter for OpenaiResponsesValidateFilter {
    fn name(&self) -> &'static str {
        "openai_responses_validate"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(MAX_JSON_BODY_BYTES),
        }
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        if ctx.get_metadata("openai_responses_format.format") != Some("openai_responses") {
            trace!("skipping non-responses request");
            return Ok(FilterAction::Release);
        }

        if is_bodyless_responses_request(&ctx.request.method, ctx.request.uri.path()) {
            trace!(
                method = %ctx.request.method,
                path = ctx.request.uri.path(),
                "skipping validation for bodyless endpoint"
            );
            return Ok(FilterAction::Release);
        }

        let parsed = match parse_and_validate(ctx, body) {
            Ok(v) => v,
            Err(action) => return Ok(action),
        };

        let response_id = format!("resp_{}", ctx.id_generator.generate(ctx.time_source));
        let conversation_id = resolve_conversation_id(ctx, &parsed);

        enrich_context(ctx, &response_id, &conversation_id);

        debug!(
            response_id = %response_id,
            conversation_id = %conversation_id,
            "request validated"
        );

        Ok(FilterAction::Release)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(detect_and_prepare_error_reformat(ctx))
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        Ok(reformat_error_body(ctx, body, end_of_stream))
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Check whether a backend response should be reformatted as a
/// Responses API error (non-2xx, not already SSE).
fn should_reformat_error(ctx: &HttpFilterContext<'_>) -> bool {
    ctx.response_header.as_ref().is_some_and(|resp| {
        let is_error = !resp.status.is_success();
        let already_sse = resp
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("text/event-stream"));
        is_error && !already_sse
    })
}

/// Apply error-reformatting headers to the response.
fn apply_error_response_headers(ctx: &mut HttpFilterContext<'_>, is_streaming: bool) {
    if let Some(resp) = &mut ctx.response_header {
        resp.headers.remove(http::header::CONTENT_LENGTH);
        resp.headers.remove(http::header::CONTENT_ENCODING);
        resp.headers.remove(http::header::CONTENT_RANGE);
        resp.headers.remove(http::header::ETAG);

        if is_streaming {
            resp.status = http::StatusCode::OK;
            resp.headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/event-stream"),
            );
        } else {
            resp.headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
        }

        ctx.response_headers_modified = true;
    }
}

/// Detect non-2xx backend responses for Responses API requests and prepare
/// for body reformatting by modifying headers and setting metadata.
fn detect_and_prepare_error_reformat(ctx: &mut HttpFilterContext<'_>) -> FilterAction {
    if ctx.get_metadata("openai_responses_format.format") != Some("openai_responses") {
        return FilterAction::Continue;
    }
    if !should_reformat_error(ctx) {
        return FilterAction::Continue;
    }

    let status = ctx.response_header.as_ref().map_or(500, |r| r.status.as_u16());
    let is_streaming = ctx.get_metadata("responses.stream").is_some_and(|v| v == "true");

    ctx.set_metadata("responses._reformat_error", status.to_string());
    ctx.set_response_body_mode(BodyMode::StreamBuffer {
        max_bytes: Some(MAX_JSON_BODY_BYTES),
    });
    apply_error_response_headers(ctx, is_streaming);

    debug!(
        original_status = status,
        is_streaming, "reformatting backend error response"
    );
    FilterAction::Continue
}

/// Replace the backend error body with Responses API format (SSE or JSON).
fn reformat_error_body(ctx: &HttpFilterContext<'_>, body: &mut Option<Bytes>, end_of_stream: bool) -> FilterAction {
    let Some(status_str) = ctx.get_metadata("responses._reformat_error") else {
        return FilterAction::Continue;
    };

    if !end_of_stream {
        return FilterAction::Continue;
    }

    let original_status: u16 = status_str.parse().unwrap_or(500);
    let is_streaming = ctx.get_metadata("responses.stream").is_some_and(|v| v == "true");

    let backend_body = body.as_deref().and_then(|b| std::str::from_utf8(b).ok()).unwrap_or("");

    let backend_error = extract_backend_error(backend_body, original_status);

    let replacement = if is_streaming {
        let response_id = ctx.get_metadata("responses.response_id").unwrap_or("resp_unknown");
        let model = ctx.get_metadata("openai_responses_format.model").unwrap_or("unknown");
        let store = ctx.get_metadata("responses.store").is_none_or(|v| v != "false");
        let background = ctx.get_metadata("responses.background").is_some_and(|v| v == "true");
        build_sse_error_body(response_id, model, store, background, &backend_error)
    } else {
        build_json_error_body(&backend_error)
    };

    *body = Some(replacement);

    FilterAction::Continue
}

/// Parse the request body and run validation checks.
fn parse_and_validate(ctx: &HttpFilterContext<'_>, body: &Option<Bytes>) -> Result<serde_json::Value, FilterAction> {
    let streaming = ctx
        .get_metadata("openai_responses_format.stream")
        .is_some_and(|v| v == "true");
    let Some(chunk) = body.as_deref() else {
        debug!("rejecting request with missing body");
        return Err(reject_invalid("request body is required", streaming));
    };

    let parsed: serde_json::Value = match serde_json::from_slice(chunk) {
        Ok(v) => v,
        Err(e) => {
            debug!(error = %e, "failed to parse request body");
            return Err(reject_invalid(&format!("invalid request body: {e}"), streaming));
        },
    };

    if let Err(e) = validate_request(ctx) {
        debug!(error = %e, "request validation failed");
        return Err(reject_invalid(&e.to_string(), streaming));
    }

    Ok(parsed)
}

/// Check whether a Responses endpoint has no JSON request body to validate.
///
/// Assumes the format classifier already confirmed this is a Responses API path.
fn is_bodyless_responses_request(method: &http::Method, path: &str) -> bool {
    match *method {
        http::Method::GET | http::Method::DELETE => true,
        http::Method::POST => matches!(
            path.split('/').collect::<Vec<_>>().as_slice(),
            ["", "v1", "responses", _, "cancel"]
        ),
        _ => false,
    }
}

/// Build a 400 rejection with a Responses API error body.
fn reject_invalid(message: &str, streaming: bool) -> FilterAction {
    FilterAction::Reject(responses_error_rejection(
        400,
        "invalid_request_error",
        message,
        streaming,
    ))
}

/// Extract conversation ID from the request body.
///
/// Handles both `"conversation": "conv_id"` and `"conversation": {"id": "conv_id"}`.
fn extract_conversation_id(body: &serde_json::Value) -> Option<String> {
    body.get("conversation").and_then(|c| {
        c.as_str()
            .or_else(|| c.get("id").and_then(serde_json::Value::as_str))
            .map(str::to_owned)
    })
}

/// Extract or generate a conversation ID for the request.
fn resolve_conversation_id(ctx: &HttpFilterContext<'_>, body: &serde_json::Value) -> String {
    if let Some(id) = extract_conversation_id(body) {
        trace!(conversation_id = %id, "conversation ID extracted from request");
        id
    } else {
        let id = format!("conv_{}", ctx.id_generator.generate(ctx.time_source));
        trace!(conversation_id = %id, "conversation ID generated");
        id
    }
}

/// Error details normalized from an upstream backend response.
#[derive(Clone, Debug, Eq, PartialEq)]
struct BackendError {
    /// Machine-readable error code.
    code: String,
    /// Error category.
    error_type: String,
    /// Human-readable error message.
    message: String,
}

/// Extract error details from the backend response body.
///
/// Tries common formats: OpenAI (`error.message` + `error.code`), simple
/// (`message`), `FastAPI` (`detail`). Falls back to the HTTP status code.
fn extract_backend_error(body: &str, status: u16) -> BackendError {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(error) = json.get("error") {
            return backend_error_from_error_object(error, status);
        }

        if let Some(msg) = json.get("message").and_then(serde_json::Value::as_str) {
            return backend_error_from_message(status, msg);
        }

        if let Some(detail) = json.get("detail").and_then(serde_json::Value::as_str) {
            return backend_error_from_message(status, detail);
        }
    }

    fallback_backend_error(status)
}

/// Normalize an OpenAI-style `error` object.
fn backend_error_from_error_object(error: &serde_json::Value, status: u16) -> BackendError {
    let message = error
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown error");
    let error_type = error
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| default_error_type(status));
    let code = error
        .get("code")
        .and_then(normalize_error_code)
        .unwrap_or_else(|| status.to_string());

    BackendError {
        code,
        error_type: error_type.to_owned(),
        message: message.to_owned(),
    }
}

/// Normalize an error code JSON value into a string.
fn normalize_error_code(value: &serde_json::Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_u64().map(|n| n.to_string()))
}

/// Build a backend error from a plain message field.
fn backend_error_from_message(status: u16, message: &str) -> BackendError {
    BackendError {
        code: status.to_string(),
        error_type: default_error_type(status).to_owned(),
        message: message.to_owned(),
    }
}

/// Build a backend error when the upstream body has no usable details.
fn fallback_backend_error(status: u16) -> BackendError {
    BackendError {
        code: status.to_string(),
        error_type: default_error_type(status).to_owned(),
        message: format!("upstream error (HTTP {status})"),
    }
}

/// Return an error type fallback for an upstream status code.
fn default_error_type(status: u16) -> &'static str {
    match status {
        404 => "not_found",
        429 => "too_many_requests",
        400..=499 => "invalid_request",
        _ => "server_error",
    }
}

/// Build a reusable error payload object.
fn error_payload(error: &BackendError) -> serde_json::Value {
    serde_json::json!({
        "type": error.error_type.as_str(),
        "code": error.code.as_str(),
        "message": error.message.as_str(),
        "param": null,
    })
}

/// Build a Responses API response snapshot for error SSE events.
#[expect(
    clippy::too_many_lines,
    reason = "Responses API snapshot intentionally includes the full stable field set"
)]
fn error_response_object(response_id: &str, model: &str, store: bool, background: bool) -> serde_json::Value {
    let created_at = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());

    serde_json::json!({
        "id": response_id,
        "object": "response",
        "created_at": created_at,
        "completed_at": null,
        "status": "in_progress",
        "incomplete_details": null,
        "model": model,
        "previous_response_id": null,
        "instructions": null,
        "output": [],
        "error": null,
        "tools": [],
        "tool_choice": "auto",
        "truncation": "disabled",
        "parallel_tool_calls": true,
        "text": {
            "format": {
                "type": "text"
            }
        },
        "top_p": 1.0,
        "presence_penalty": 0.0,
        "frequency_penalty": 0.0,
        "top_logprobs": 0,
        "temperature": 1.0,
        "reasoning": null,
        "usage": null,
        "max_output_tokens": null,
        "max_tool_calls": null,
        "store": store,
        "background": background,
        "service_tier": "default",
        "metadata": {},
        "safety_identifier": null,
        "prompt_cache_key": null,
    })
}

/// Build SSE-formatted error body for streaming Responses API requests.
///
/// Emits `response.created`, `response.in_progress`, and `error` events.
fn build_sse_error_body(
    response_id: &str,
    model: &str,
    store: bool,
    background: bool,
    backend_error: &BackendError,
) -> Bytes {
    let response_obj = error_response_object(response_id, model, store, background);

    let created = serde_json::json!({
        "type": "response.created",
        "response": response_obj.clone(),
        "sequence_number": 0,
    });
    let in_progress = serde_json::json!({
        "type": "response.in_progress",
        "response": response_obj,
        "sequence_number": 1,
    });
    // OpenResponses `ErrorStreamingEvent` nests error details under `error`.
    let error = serde_json::json!({
        "type": "error",
        "error": error_payload(backend_error),
        "sequence_number": 2,
    });

    Bytes::from(format!(
        "event: response.created\ndata: {created}\n\nevent: response.in_progress\ndata: {in_progress}\n\nevent: error\ndata: {error}\n\n"
    ))
}

/// Build JSON error body for non-streaming Responses API requests.
fn build_json_error_body(backend_error: &BackendError) -> Bytes {
    Bytes::from(
        serde_json::json!({
            "error": error_payload(backend_error),
        })
        .to_string(),
    )
}

/// Enrich filter context with validated metadata for downstream filters.
///
/// Reads `stream`, `store`, `background` from `openai_responses_format.*`
/// classifier metadata and applies spec defaults.
fn enrich_context(ctx: &mut HttpFilterContext<'_>, response_id: &str, conversation_id: &str) {
    ctx.set_metadata("responses.response_id", response_id);
    ctx.set_metadata("responses.conversation_id", conversation_id);

    let store = ctx
        .get_metadata("openai_responses_format.store")
        .is_none_or(|v| v != "false");
    ctx.set_metadata("responses.store", if store { "true" } else { "false" });

    let background = ctx
        .get_metadata("openai_responses_format.background")
        .is_some_and(|v| v == "true");
    ctx.set_metadata("responses.background", if background { "true" } else { "false" });

    let stream = ctx
        .get_metadata("openai_responses_format.stream")
        .is_some_and(|v| v == "true");
    ctx.set_metadata("responses.stream", if stream { "true" } else { "false" });

    trace!(store, background, stream, "classifier metadata applied");
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests"
)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn from_config_succeeds() {
        let filter = OpenaiResponsesValidateFilter::from_config(&serde_yaml::Value::Null).unwrap();
        assert_eq!(
            filter.name(),
            "openai_responses_validate",
            "filter name should be openai_responses_validate"
        );
    }

    #[test]
    fn body_access_is_read_only() {
        let filter = OpenaiResponsesValidateFilter;
        assert_eq!(
            filter.request_body_access(),
            BodyAccess::ReadOnly,
            "filter should use read-only body access"
        );
    }

    #[tokio::test]
    async fn valid_request_produces_metadata() {
        let ctx = run_filter(r#"{"model": "gpt-4.1", "input": "Hello"}"#, &[]).await;

        assert!(
            ctx.filter_metadata
                .get("responses.response_id")
                .is_some_and(|v| v.starts_with("resp_") && v.len() == 37),
            "response_id should be resp_ + 32 hex chars"
        );
        assert!(
            ctx.filter_metadata
                .get("responses.conversation_id")
                .is_some_and(|v| v.starts_with("conv_") && v.len() == 37),
            "conversation_id should be conv_ + 32 hex chars"
        );
        assert_eq!(
            ctx.filter_metadata.get("responses.store").map(String::as_str),
            Some("true"),
            "store should default to true when classifier has no value"
        );
        assert_eq!(
            ctx.filter_metadata.get("responses.background").map(String::as_str),
            Some("false"),
            "background should default to false"
        );
        assert_eq!(
            ctx.filter_metadata.get("responses.stream").map(String::as_str),
            Some("false"),
            "stream should default to false"
        );
    }

    #[tokio::test]
    async fn reads_stream_from_classifier_metadata() {
        let ctx = run_filter(r#"{"input": "Hi"}"#, &[("openai_responses_format.stream", "true")]).await;

        assert_eq!(
            ctx.filter_metadata.get("responses.stream").map(String::as_str),
            Some("true"),
            "stream should be read from classifier metadata"
        );
    }

    #[tokio::test]
    async fn reads_store_from_classifier_metadata() {
        let ctx = run_filter(r#"{"input": "Hi"}"#, &[("openai_responses_format.store", "false")]).await;

        assert_eq!(
            ctx.filter_metadata.get("responses.store").map(String::as_str),
            Some("false"),
            "store should be read from classifier metadata"
        );
    }

    #[tokio::test]
    async fn reads_background_from_classifier_metadata() {
        let ctx = run_filter(r#"{"input": "Hi"}"#, &[("openai_responses_format.background", "true")]).await;

        assert_eq!(
            ctx.filter_metadata.get("responses.background").map(String::as_str),
            Some("true"),
            "background should be read from classifier metadata"
        );
    }

    #[tokio::test]
    async fn valid_request_with_conversation_id() {
        let ctx = run_filter(r#"{"input": "Hi", "conversation": {"id": "conv_existing_123"}}"#, &[]).await;

        assert_eq!(
            ctx.filter_metadata.get("responses.conversation_id").map(String::as_str),
            Some("conv_existing_123"),
            "conversation_id should be extracted from request body"
        );
    }

    #[tokio::test]
    async fn valid_request_with_bare_string_conversation_id() {
        let ctx = run_filter(r#"{"input": "Hi", "conversation": "conv_existing_123"}"#, &[]).await;

        assert_eq!(
            ctx.filter_metadata.get("responses.conversation_id").map(String::as_str),
            Some("conv_existing_123"),
            "bare-string conversation ID should be extracted from request body"
        );
    }

    #[tokio::test]
    async fn valid_request_generates_conversation_id() {
        let ctx = run_filter(r#"{"input": "Hi"}"#, &[]).await;

        assert!(
            ctx.filter_metadata
                .get("responses.conversation_id")
                .is_some_and(|v| v.starts_with("conv_") && v.len() == 37),
            "conversation_id should be conv_ + 32 hex chars"
        );
    }

    #[tokio::test]
    async fn stream_and_background_rejected() {
        let action = run_filter_raw(
            r#"{"input": "test"}"#,
            &[
                ("openai_responses_format.stream", "true"),
                ("openai_responses_format.background", "true"),
            ],
        )
        .await;
        assert!(
            matches!(action, FilterAction::Reject(_)),
            "stream=true + background=true should be rejected"
        );
    }

    #[tokio::test]
    async fn background_without_store_rejected() {
        let action = run_filter_raw(
            r#"{"input": "test"}"#,
            &[
                ("openai_responses_format.background", "true"),
                ("openai_responses_format.store", "false"),
            ],
        )
        .await;
        assert!(
            matches!(action, FilterAction::Reject(_)),
            "background=true + store=false should be rejected"
        );
    }

    #[tokio::test]
    async fn streaming_rejection_has_sse_content_type() {
        let action = run_filter_raw(
            r#"{"input": "test"}"#,
            &[
                ("openai_responses_format.stream", "true"),
                ("openai_responses_format.background", "true"),
            ],
        )
        .await;
        if let FilterAction::Reject(rejection) = action {
            let has_content_type = rejection
                .headers
                .iter()
                .any(|(k, v)| k == "content-type" && v == "text/event-stream");
            assert!(
                has_content_type,
                "streaming rejection should have text/event-stream content-type"
            );
        } else {
            panic!("expected rejection");
        }
    }

    #[tokio::test]
    async fn non_streaming_rejection_has_json_content_type() {
        let action = run_filter_raw(
            r#"{"input": "test"}"#,
            &[
                ("openai_responses_format.background", "true"),
                ("openai_responses_format.store", "false"),
            ],
        )
        .await;
        if let FilterAction::Reject(rejection) = action {
            let has_content_type = rejection
                .headers
                .iter()
                .any(|(k, v)| k == "content-type" && v == "application/json");
            assert!(
                has_content_type,
                "non-streaming rejection should have application/json content-type"
            );
        } else {
            panic!("expected rejection");
        }
    }

    #[tokio::test]
    async fn rejection_body_uses_responses_error_format() {
        let action = run_filter_raw(
            r#"{"input": "test"}"#,
            &[
                ("openai_responses_format.background", "true"),
                ("openai_responses_format.store", "false"),
            ],
        )
        .await;
        if let FilterAction::Reject(rejection) = action {
            let body = rejection.body.unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                parsed["error"]["type"].as_str(),
                Some("invalid_request_error"),
                "rejection body should have error type=invalid_request_error"
            );
            assert!(
                parsed["error"]["message"].is_string(),
                "rejection body should contain error message"
            );
            assert!(
                parsed["error"]["param"].is_null(),
                "rejection body should have error param=null"
            );
        } else {
            panic!("expected rejection");
        }
    }

    #[test]
    fn reject_invalid_escapes_control_characters() {
        let action = reject_invalid("line1\nline2", false);
        if let FilterAction::Reject(rejection) = action {
            let body = rejection.body.unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                parsed["error"]["message"].as_str(),
                Some("line1\nline2"),
                "control characters in rejection body should remain valid JSON"
            );
        } else {
            panic!("expected rejection");
        }
    }

    #[tokio::test]
    async fn skips_chat_completions_request() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/chat/completions",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("openai_responses_format.format", "openai_chat_completions");
        let mut body = Some(Bytes::from(r#"{"messages":[]}"#));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(
            matches!(action, FilterAction::Release),
            "chat completions request should be released without validation"
        );
        assert!(
            !ctx.filter_metadata.contains_key("responses.response_id"),
            "responses metadata should not be set for non-responses requests"
        );
    }

    #[tokio::test]
    async fn skips_missing_format_metadata() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/responses",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        let mut body = Some(Bytes::from(r#"{"input":"test"}"#));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(
            matches!(action, FilterAction::Release),
            "request without classifier metadata should be released without validation"
        );
    }

    #[tokio::test]
    async fn not_end_of_stream_continues() {
        let filter = OpenaiResponsesValidateFilter;
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/responses");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut body = Some(Bytes::from(r#"{"input": "partial"}"#));

        let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "non-end-of-stream should continue"
        );
    }

    #[tokio::test]
    async fn minimal_request_without_model() {
        let ctx = run_filter(r#"{"input": "Hello"}"#, &[]).await;

        assert!(
            ctx.filter_metadata.contains_key("responses.response_id"),
            "response_id should still be generated"
        );
    }

    #[tokio::test]
    async fn skips_get_response_without_body() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::GET,
            "/v1/responses/resp_abc123",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("openai_responses_format.format", "openai_responses");
        let mut body = None;

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(
            matches!(action, FilterAction::Release),
            "GET request should be released without body validation"
        );
        assert!(
            !ctx.filter_metadata.contains_key("responses.response_id"),
            "responses metadata should not be set for bodyless requests"
        );
    }

    #[tokio::test]
    async fn skips_delete_response_without_body() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::DELETE,
            "/v1/responses/resp_abc123",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("openai_responses_format.format", "openai_responses");
        let mut body = None;

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(
            matches!(action, FilterAction::Release),
            "DELETE request should be released without body validation"
        );
    }

    #[tokio::test]
    async fn skips_get_input_items_without_body() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::GET,
            "/v1/responses/resp_abc123/input_items",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("openai_responses_format.format", "openai_responses");
        let mut body = None;

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(
            matches!(action, FilterAction::Release),
            "GET /input_items request should be released without body validation"
        );
    }

    #[tokio::test]
    async fn skips_post_cancel_without_body() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/responses/resp_abc123/cancel",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("openai_responses_format.format", "openai_responses");
        let mut body = None;

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(
            matches!(action, FilterAction::Release),
            "POST /cancel request should be released without body validation"
        );
        assert!(
            !ctx.filter_metadata.contains_key("responses.response_id"),
            "responses metadata should not be set for bodyless requests"
        );
    }

    #[tokio::test]
    async fn post_input_tokens_still_validates_body() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/responses/input_tokens",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("openai_responses_format.format", "openai_responses");
        let mut body = None;

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(_)),
            "POST /input_tokens without body should be rejected, not released"
        );
    }

    // -------------------------------------------------------------------------
    // Response Error Formatting — Helpers
    // -------------------------------------------------------------------------

    #[test]
    fn extract_backend_error_openai_format() {
        let body = r#"{"error":{"message":"The model does not exist.","type":"NotFoundError","code":404}}"#;
        let error = extract_backend_error(body, 404);
        assert_eq!(error.code, "404", "code should be extracted from error.code");
        assert_eq!(
            error.error_type, "NotFoundError",
            "type should be extracted from error.type"
        );
        assert_eq!(
            error.message, "The model does not exist.",
            "message should be extracted from error.message"
        );
    }

    #[test]
    fn extract_backend_error_string_code() {
        let body = r#"{"error":{"message":"Invalid API key","code":"invalid_api_key"}}"#;
        let error = extract_backend_error(body, 401);
        assert_eq!(error.code, "invalid_api_key", "string code should be preserved");
        assert_eq!(error.error_type, "invalid_request");
        assert_eq!(error.message, "Invalid API key");
    }

    #[test]
    fn extract_backend_error_simple_format() {
        let body = r#"{"message":"Something went wrong"}"#;
        let error = extract_backend_error(body, 500);
        assert_eq!(error.code, "500", "code should fall back to HTTP status");
        assert_eq!(error.error_type, "server_error");
        assert_eq!(error.message, "Something went wrong");
    }

    #[test]
    fn extract_backend_error_fastapi_format() {
        let body = r#"{"detail":"Not found"}"#;
        let error = extract_backend_error(body, 404);
        assert_eq!(error.code, "404");
        assert_eq!(error.error_type, "not_found");
        assert_eq!(error.message, "Not found");
    }

    #[test]
    fn extract_backend_error_non_json() {
        let error = extract_backend_error("not json", 502);
        assert_eq!(error.code, "502");
        assert_eq!(error.error_type, "server_error");
        assert_eq!(error.message, "upstream error (HTTP 502)");
    }

    #[test]
    fn extract_backend_error_empty_body() {
        let error = extract_backend_error("", 500);
        assert_eq!(error.code, "500");
        assert_eq!(error.error_type, "server_error");
        assert_eq!(error.message, "upstream error (HTTP 500)");
    }

    // -------------------------------------------------------------------------
    // Response Error Formatting — SSE/JSON Builders
    // -------------------------------------------------------------------------

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "single SSE shape regression asserts all emitted frames"
    )]
    fn build_sse_error_body_has_three_events() {
        let backend_error = BackendError {
            code: "404".to_owned(),
            error_type: "not_found".to_owned(),
            message: "Model not found".to_owned(),
        };
        let body = build_sse_error_body("resp_test123", "gpt-4.1", true, false, &backend_error);
        let text = std::str::from_utf8(&body).unwrap();

        let events: Vec<&str> = text.split("\n\n").filter(|s| !s.is_empty()).collect();
        assert_eq!(events.len(), 3, "SSE body should have 3 events");

        let (name0, e0) = parse_sse_event(events[0]);
        assert_eq!(name0, "response.created", "event 0 should use named SSE framing");
        assert_eq!(e0["type"], "response.created");
        assert_eq!(e0["sequence_number"], 0);
        assert_eq!(e0["response"]["id"], "resp_test123");
        assert_eq!(e0["response"]["model"], "gpt-4.1");
        assert_eq!(e0["response"]["status"], "in_progress");
        assert!(e0["response"]["completed_at"].is_null());
        assert!(e0["response"]["error"].is_null());
        assert_eq!(e0["response"]["store"], true);
        assert_eq!(e0["response"]["background"], false);

        let (name1, e1) = parse_sse_event(events[1]);
        assert_eq!(name1, "response.in_progress", "event 1 should use named SSE framing");
        assert_eq!(e1["type"], "response.in_progress");
        assert_eq!(e1["sequence_number"], 1);

        let (name2, e2) = parse_sse_event(events[2]);
        assert_eq!(name2, "error", "event 2 should use named SSE framing");
        assert_eq!(e2["type"], "error");
        assert_eq!(e2["error"]["type"], "not_found");
        assert_eq!(e2["error"]["code"], "404");
        assert_eq!(e2["error"]["message"], "Model not found");
        assert!(e2["error"]["param"].is_null());
        assert_eq!(e2["sequence_number"], 2);
    }

    #[test]
    fn build_json_error_body_has_correct_shape() {
        let backend_error = BackendError {
            code: "404".to_owned(),
            error_type: "not_found".to_owned(),
            message: "Model not found".to_owned(),
        };
        let body = build_json_error_body(&backend_error);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(parsed["error"]["type"], "not_found");
        assert_eq!(parsed["error"]["code"], "404");
        assert_eq!(parsed["error"]["message"], "Model not found");
        assert!(parsed["error"]["param"].is_null());
    }

    // -------------------------------------------------------------------------
    // Response Error Formatting — on_response Hook
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn on_response_sets_reformat_metadata_for_error() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/responses",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("openai_responses_format.format", "openai_responses");
        ctx.set_metadata("responses.stream", "false");

        let mut resp = crate::test_utils::make_response();
        resp.status = http::StatusCode::NOT_FOUND;
        resp.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        ctx.response_header = Some(&mut resp);

        let action = filter.on_response(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
        assert_eq!(
            ctx.filter_metadata.get("responses._reformat_error").map(String::as_str),
            Some("404"),
            "should set reformat error metadata with status code"
        );
        assert!(ctx.response_headers_modified, "headers should be marked as modified");
    }

    #[tokio::test]
    async fn on_response_skips_success() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/responses",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("openai_responses_format.format", "openai_responses");

        let mut resp = crate::test_utils::make_response();
        ctx.response_header = Some(&mut resp);

        drop(filter.on_response(&mut ctx).await.unwrap());
        assert!(
            !ctx.filter_metadata.contains_key("responses._reformat_error"),
            "should not set reformat metadata for 2xx"
        );
    }

    #[tokio::test]
    async fn on_response_skips_non_responses() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/chat/completions",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("openai_responses_format.format", "openai_chat_completions");

        let mut resp = crate::test_utils::make_response();
        resp.status = http::StatusCode::NOT_FOUND;
        ctx.response_header = Some(&mut resp);

        drop(filter.on_response(&mut ctx).await.unwrap());
        assert!(
            !ctx.filter_metadata.contains_key("responses._reformat_error"),
            "should not reformat non-responses API errors"
        );
    }

    #[tokio::test]
    async fn on_response_skips_already_sse() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/responses",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("openai_responses_format.format", "openai_responses");

        let mut resp = crate::test_utils::make_response();
        resp.status = http::StatusCode::INTERNAL_SERVER_ERROR;
        resp.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/event-stream"),
        );
        ctx.response_header = Some(&mut resp);

        drop(filter.on_response(&mut ctx).await.unwrap());
        assert!(
            !ctx.filter_metadata.contains_key("responses._reformat_error"),
            "should not reformat already-SSE responses"
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "single header rewrite regression covers stale representation headers"
    )]
    async fn on_response_sets_streaming_headers() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/responses",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("openai_responses_format.format", "openai_responses");
        ctx.set_metadata("responses.stream", "true");

        let mut resp = crate::test_utils::make_response();
        resp.status = http::StatusCode::NOT_FOUND;
        resp.headers
            .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("42"));
        resp.headers
            .insert(http::header::CONTENT_ENCODING, http::HeaderValue::from_static("gzip"));
        resp.headers.insert(
            http::header::CONTENT_RANGE,
            http::HeaderValue::from_static("bytes 0-41/42"),
        );
        resp.headers
            .insert(http::header::ETAG, http::HeaderValue::from_static("\"upstream\""));
        ctx.response_header = Some(&mut resp);

        drop(filter.on_response(&mut ctx).await.unwrap());

        assert_eq!(resp.status, http::StatusCode::OK, "streaming errors should return 200");
        assert_eq!(
            resp.headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/event-stream"),
            "streaming errors should have SSE content type"
        );
        assert!(
            resp.headers.get(http::header::CONTENT_LENGTH).is_none(),
            "content-length should be removed"
        );
        assert!(
            resp.headers.get(http::header::CONTENT_ENCODING).is_none(),
            "content-encoding should be removed"
        );
        assert!(
            resp.headers.get(http::header::CONTENT_RANGE).is_none(),
            "content-range should be removed"
        );
        assert!(resp.headers.get(http::header::ETAG).is_none(), "etag should be removed");
    }

    #[tokio::test]
    async fn on_response_keeps_status_for_non_streaming() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/responses",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("openai_responses_format.format", "openai_responses");
        ctx.set_metadata("responses.stream", "false");

        let mut resp = crate::test_utils::make_response();
        resp.status = http::StatusCode::NOT_FOUND;
        ctx.response_header = Some(&mut resp);

        drop(filter.on_response(&mut ctx).await.unwrap());

        assert_eq!(
            resp.status,
            http::StatusCode::NOT_FOUND,
            "non-streaming should keep original status"
        );
        assert_eq!(
            resp.headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "non-streaming errors should have JSON content type"
        );
    }

    // -------------------------------------------------------------------------
    // Response Error Formatting — on_response_body Hook
    // -------------------------------------------------------------------------

    #[test]
    fn on_response_body_replaces_streaming_error() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/responses",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("responses._reformat_error", "404");
        ctx.set_metadata("responses.stream", "true");
        ctx.set_metadata("responses.response_id", "resp_test123");
        ctx.set_metadata("openai_responses_format.model", "gpt-4.1");

        let backend_error = r#"{"error":{"message":"Model not found","code":404}}"#;
        let mut body = Some(Bytes::from(backend_error));

        let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
        assert!(matches!(action, FilterAction::Continue));

        let bytes = body.unwrap();
        let output = std::str::from_utf8(&bytes).unwrap();
        let events: Vec<&str> = output.split("\n\n").filter(|s| !s.is_empty()).collect();
        assert_eq!(events.len(), 3, "should produce 3 SSE events");

        let (event_name, error_event) = parse_sse_event(events[2]);
        assert_eq!(event_name, "error");
        assert_eq!(error_event["type"], "error");
        assert_eq!(error_event["error"]["message"], "Model not found");
    }

    #[test]
    fn on_response_body_replaces_non_streaming_error() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/responses",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("responses._reformat_error", "500");
        ctx.set_metadata("responses.stream", "false");

        let backend_error = r#"{"error":{"message":"Internal error","type":"server_error"}}"#;
        let mut body = Some(Bytes::from(backend_error));

        let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
        assert!(matches!(action, FilterAction::Continue));

        let parsed: serde_json::Value = serde_json::from_slice(&body.unwrap()).unwrap();
        assert_eq!(parsed["error"]["type"], "server_error");
        assert_eq!(parsed["error"]["message"], "Internal error");
        assert_eq!(parsed["error"]["code"], "500");
        assert!(parsed["error"]["param"].is_null());
    }

    #[test]
    fn on_response_body_skips_without_flag() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/responses",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);

        let original = r#"{"output":"success"}"#;
        let mut body = Some(Bytes::from(original));

        drop(filter.on_response_body(&mut ctx, &mut body, true).unwrap());
        assert_eq!(
            std::str::from_utf8(&body.unwrap()).unwrap(),
            original,
            "body should be unchanged when no reformat flag set"
        );
    }

    #[test]
    fn on_response_body_continues_before_eos() {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/responses",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("responses._reformat_error", "404");

        let mut body = Some(Bytes::from("partial"));
        let action = filter.on_response_body(&mut ctx, &mut body, false).unwrap();
        assert!(matches!(action, FilterAction::Continue));
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    fn make_filter() -> Box<dyn HttpFilter> {
        OpenaiResponsesValidateFilter::from_config(&serde_yaml::Value::Null).unwrap()
    }

    fn parse_sse_event(frame: &str) -> (&str, serde_json::Value) {
        let mut lines = frame.lines();
        let event_type = lines.next().and_then(|line| line.strip_prefix("event: ")).unwrap();
        let data = lines.next().and_then(|line| line.strip_prefix("data: ")).unwrap();
        (event_type, serde_json::from_str(data).unwrap())
    }

    async fn run_filter(body_str: &str, classifier_metadata: &[(&str, &str)]) -> HttpFilterContext<'static> {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/responses",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("openai_responses_format.format", "openai_responses");
        for (k, v) in classifier_metadata {
            ctx.set_metadata(*k, *v);
        }
        let mut body = Some(Bytes::from(body_str.to_owned()));

        let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
        assert!(
            matches!(action, FilterAction::Release),
            "valid request should release: got {action:?}"
        );

        ctx
    }

    async fn run_filter_raw(body_str: &str, classifier_metadata: &[(&str, &str)]) -> FilterAction {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/responses",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
        ctx.set_metadata("openai_responses_format.format", "openai_responses");
        for (k, v) in classifier_metadata {
            ctx.set_metadata(*k, *v);
        }
        let mut body = Some(Bytes::from(body_str.to_owned()));

        filter.on_request_body(&mut ctx, &mut body, true).await.unwrap()
    }
}
