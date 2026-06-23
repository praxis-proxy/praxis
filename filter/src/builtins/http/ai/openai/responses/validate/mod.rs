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

use async_trait::async_trait;
use bytes::Bytes;
use tracing::{debug, trace};

use self::rules::validate_request;
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum request body size for `StreamBuffer` mode (64 MiB).
const MAX_BODY_BYTES: usize = 67_108_864; // 64 MiB

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
            max_bytes: Some(MAX_BODY_BYTES),
        }
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

        let parsed = match parse_and_validate(ctx, body) {
            Ok(v) => v,
            Err(action) => return Ok(action),
        };

        let response_id = format!("resp_{}", ctx.id_generator.generate(ctx.time_source));
        let conversation_id = if let Some(id) = extract_conversation_id(&parsed) {
            trace!(conversation_id = %id, "conversation ID extracted from request");
            id
        } else {
            let id = format!("conv_{}", ctx.id_generator.generate(ctx.time_source));
            trace!(conversation_id = %id, "conversation ID generated");
            id
        };

        enrich_context(ctx, &response_id, &conversation_id);

        debug!(
            response_id = %response_id,
            conversation_id = %conversation_id,
            "request validated"
        );

        Ok(FilterAction::Release)
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Parse the request body and run validation checks.
fn parse_and_validate(ctx: &HttpFilterContext<'_>, body: &Option<Bytes>) -> Result<serde_json::Value, FilterAction> {
    let Some(chunk) = body.as_deref() else {
        debug!("rejecting request with missing body");
        return Err(reject_invalid("request body is required"));
    };

    let parsed: serde_json::Value = match serde_json::from_slice(chunk) {
        Ok(v) => v,
        Err(e) => {
            debug!(error = %e, "failed to parse request body");
            return Err(reject_invalid(&format!("invalid request body: {e}")));
        },
    };

    if let Err(e) = validate_request(ctx) {
        debug!(error = %e, "request validation failed");
        return Err(reject_invalid(&e.to_string()));
    }

    Ok(parsed)
}

/// Build a 400 rejection with a JSON error body.
fn reject_invalid(message: &str) -> FilterAction {
    let body = serde_json::json!({
        "error": {
            "message": message,
            "type": "invalid_request_error"
        }
    })
    .to_string();

    FilterAction::Reject(
        Rejection::status(400)
            .with_header("content-type", "application/json")
            .with_body(Bytes::from(body)),
    )
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
    async fn rejection_has_json_content_type() {
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
                .any(|(k, v)| k == "content-type" && v == "application/json");
            assert!(has_content_type, "rejection should have application/json content-type");
        } else {
            panic!("expected rejection");
        }
    }

    #[tokio::test]
    async fn rejection_body_is_valid_json() {
        let action = run_filter_raw(
            r#"{"input": "test"}"#,
            &[
                ("openai_responses_format.stream", "true"),
                ("openai_responses_format.background", "true"),
            ],
        )
        .await;
        if let FilterAction::Reject(rejection) = action {
            let body = rejection.body.unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(
                parsed["error"]["message"].is_string(),
                "rejection body should contain error.message"
            );
            assert_eq!(
                parsed["error"]["type"].as_str(),
                Some("invalid_request_error"),
                "rejection body should have invalid_request_error type"
            );
        } else {
            panic!("expected rejection");
        }
    }

    #[test]
    fn reject_invalid_escapes_control_characters() {
        let action = reject_invalid("line1\nline2");
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

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    fn make_filter() -> Box<dyn HttpFilter> {
        OpenaiResponsesValidateFilter::from_config(&serde_yaml::Value::Null).unwrap()
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
