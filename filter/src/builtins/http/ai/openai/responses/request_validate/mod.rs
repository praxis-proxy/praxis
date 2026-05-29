// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `request_validate` filter: validate and enrich incoming Responses
//! API requests.
//!
//! Expects the upstream `responses_format` classifier to have already
//! identified this request as a Responses API request and promoted
//! routing facts (`model`, `stream`, `store`, `background`) to
//! `responses_format.*` metadata.
//!
//! This filter reads classifier metadata for parameter-combination
//! validation, then does targeted JSON field extraction for fields
//! the classifier does not cover (`instructions`, `metadata`,
//! `conversation.id`, `include`). It does **not** deserialize the
//! full body into a typed struct.
//!
//! # YAML
//!
//! ```yaml
//! filter: request_validate
//! ```

mod validate;

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use bytes::Bytes;
use tracing::debug;

use self::validate::validate_request;
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// RequestValidateFilter
// -----------------------------------------------------------------------------

/// Validates and enriches Responses API requests.
///
/// Reads classifier metadata for parameter-combination checks, then
/// parses the body as [`serde_json::Value`] for targeted field
/// extraction. Does not deserialize the full body into a typed struct.
///
/// This filter has no configuration — body buffering is handled by
/// the upstream `responses_format` classifier.
pub struct RequestValidateFilter {
    /// Monotonic counter for unique ID generation.
    counter: AtomicU64,
}

impl RequestValidateFilter {
    /// Create a filter from YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config contains unknown fields.
    #[allow(clippy::unnecessary_wraps, reason = "signature required by FilterFactory")]
    pub fn from_config(_config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        Ok(Box::new(Self {
            counter: AtomicU64::new(0),
        }))
    }

    /// Generate a response ID with `resp_` prefix.
    fn generate_response_id(&self) -> String {
        let id = self.generate_raw_id();
        format!("resp_{id}")
    }

    /// Generate a conversation ID with `conv_` prefix.
    fn generate_conversation_id(&self) -> String {
        let id = self.generate_raw_id();
        format!("conv_{id}")
    }

    /// Generate a raw hex ID from timestamp and counter.
    fn generate_raw_id(&self) -> String {
        #[allow(clippy::cast_possible_truncation, reason = "micros fit u64")]
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros()
            .min(u128::from(u64::MAX)) as u64;

        let seq = self.counter.fetch_add(1, Ordering::Relaxed);

        format!("{micros:016x}{seq:04x}")
    }
}

#[async_trait]
impl HttpFilter for RequestValidateFilter {
    fn name(&self) -> &'static str {
        "request_validate"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(67_108_864), // 64 MiB
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

        let chunk = body.as_deref().unwrap_or_default();

        let parsed: serde_json::Value = match serde_json::from_slice(chunk) {
            Ok(v) => v,
            Err(e) => {
                debug!(error = %e, "failed to parse request body");
                return Ok(reject_invalid(&format!("invalid request body: {e}")));
            },
        };

        if let Err(e) = validate_request(ctx) {
            debug!(error = %e, "request validation failed");
            return Ok(FilterAction::Reject(
                Rejection::status(400)
                    .with_header("content-type", "application/json")
                    .with_body(Bytes::from(e.to_json_body())),
            ));
        }

        let response_id = self.generate_response_id();
        let conversation_id = extract_conversation_id(&parsed).unwrap_or_else(|| self.generate_conversation_id());

        debug!(
            response_id = %response_id,
            conversation_id = %conversation_id,
            "request validated"
        );

        write_metadata(ctx, &parsed, &response_id, &conversation_id);
        write_filter_results(ctx, &response_id)?;

        Ok(FilterAction::Release)
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

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
fn extract_conversation_id(body: &serde_json::Value) -> Option<String> {
    body.get("conversation")
        .and_then(|c| c.get("id"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// Write durable metadata for downstream filters.
///
/// Reads `stream`, `store`, `background` from `responses_format.*`
/// classifier metadata and applies spec defaults. Extracts
/// `instructions`, `include`, and `conversation.id` from the body.
fn write_metadata(ctx: &mut HttpFilterContext<'_>, body: &serde_json::Value, response_id: &str, conversation_id: &str) {
    ctx.set_metadata("responses.response_id", response_id);
    ctx.set_metadata("responses.conversation_id", conversation_id);

    let store = ctx.get_metadata("responses_format.store").is_none_or(|v| v != "false");
    ctx.set_metadata("responses.store", if store { "true" } else { "false" });

    let background = ctx
        .get_metadata("responses_format.background")
        .is_some_and(|v| v == "true");
    ctx.set_metadata("responses.background", if background { "true" } else { "false" });

    let stream = ctx.get_metadata("responses_format.stream").is_some_and(|v| v == "true");
    ctx.set_metadata("responses.stream", if stream { "true" } else { "false" });

    if let Some(instructions) = body.get("instructions").and_then(serde_json::Value::as_str) {
        ctx.set_metadata("responses.instructions", instructions);
    }

    if let Some(include) = body.get("include").and_then(serde_json::Value::as_array) {
        let values: Vec<&str> = include.iter().filter_map(serde_json::Value::as_str).collect();
        if !values.is_empty() {
            ctx.set_metadata("responses.include", values.join(","));
        }
    }
}

/// Write filter results for branch chain decisions.
fn write_filter_results(ctx: &mut HttpFilterContext<'_>, response_id: &str) -> Result<(), FilterError> {
    let results = ctx.filter_results.entry("request_validate").or_default();
    results.set("validated", "true")?;
    results.set("response_id", response_id.to_owned())?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
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
        let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let filter = RequestValidateFilter::from_config(&yaml).unwrap();
        assert_eq!(
            filter.name(),
            "request_validate",
            "filter name should be request_validate"
        );
    }

    #[test]
    fn body_access_is_read_only() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let filter = RequestValidateFilter::from_config(&yaml).unwrap();
        assert_eq!(
            filter.request_body_access(),
            BodyAccess::ReadOnly,
            "filter should use read-only body access"
        );
    }

    #[test]
    fn response_id_has_prefix() {
        let filter = make_concrete_filter();
        let id = filter.generate_response_id();
        assert!(id.starts_with("resp_"), "response ID should start with resp_");
    }

    #[test]
    fn conversation_id_has_prefix() {
        let filter = make_concrete_filter();
        let id = filter.generate_conversation_id();
        assert!(id.starts_with("conv_"), "conversation ID should start with conv_");
    }

    #[tokio::test]
    async fn valid_request_produces_metadata() {
        let ctx = run_filter(r#"{"model": "gpt-4.1", "input": "Hello"}"#, &[]).await;

        assert!(
            ctx.filter_metadata
                .get("responses.response_id")
                .is_some_and(|v| v.starts_with("resp_")),
            "response_id should be set with resp_ prefix"
        );
        assert!(
            ctx.filter_metadata.contains_key("responses.conversation_id"),
            "conversation_id should be set"
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
        let ctx = run_filter(r#"{"input": "Hi"}"#, &[("responses_format.stream", "true")]).await;

        assert_eq!(
            ctx.filter_metadata.get("responses.stream").map(String::as_str),
            Some("true"),
            "stream should be read from classifier metadata"
        );
    }

    #[tokio::test]
    async fn reads_store_from_classifier_metadata() {
        let ctx = run_filter(r#"{"input": "Hi"}"#, &[("responses_format.store", "false")]).await;

        assert_eq!(
            ctx.filter_metadata.get("responses.store").map(String::as_str),
            Some("false"),
            "store should be read from classifier metadata"
        );
    }

    #[tokio::test]
    async fn reads_background_from_classifier_metadata() {
        let ctx = run_filter(r#"{"input": "Hi"}"#, &[("responses_format.background", "true")]).await;

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
    async fn valid_request_generates_conversation_id() {
        let ctx = run_filter(r#"{"input": "Hi"}"#, &[]).await;

        assert!(
            ctx.filter_metadata
                .get("responses.conversation_id")
                .is_some_and(|v| v.starts_with("conv_")),
            "conversation_id should be generated with conv_ prefix"
        );
    }

    #[tokio::test]
    async fn valid_request_with_include_passes_through_all_values() {
        let ctx = run_filter(
            r#"{"input": "Hi", "include": ["reasoning.encrypted_content", "unknown_value"]}"#,
            &[],
        )
        .await;

        assert_eq!(
            ctx.filter_metadata.get("responses.include").map(String::as_str),
            Some("reasoning.encrypted_content,unknown_value"),
            "include should pass through all values including unrecognized ones"
        );
    }

    #[tokio::test]
    async fn valid_request_with_instructions() {
        let ctx = run_filter(r#"{"input": "Hi", "instructions": "Be helpful and concise."}"#, &[]).await;

        assert_eq!(
            ctx.filter_metadata.get("responses.instructions").map(String::as_str),
            Some("Be helpful and concise."),
            "instructions should be preserved in metadata"
        );
    }

    #[tokio::test]
    async fn valid_request_sets_filter_results() {
        let ctx = run_filter(r#"{"input": "Hi"}"#, &[]).await;
        let results = ctx.filter_results.get("request_validate").unwrap();

        assert!(results.matches("validated", "true"), "validated result should be true");
        assert!(
            results.get("response_id").is_some_and(|v| v.starts_with("resp_")),
            "response_id result should be set"
        );
    }

    #[tokio::test]
    async fn stream_and_background_rejected() {
        let action = run_filter_raw(
            r#"{"input": "test"}"#,
            &[
                ("responses_format.stream", "true"),
                ("responses_format.background", "true"),
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
                ("responses_format.background", "true"),
                ("responses_format.store", "false"),
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
                ("responses_format.stream", "true"),
                ("responses_format.background", "true"),
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
                ("responses_format.stream", "true"),
                ("responses_format.background", "true"),
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
    async fn not_end_of_stream_continues() {
        let filter = make_filter();
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

    fn make_concrete_filter() -> RequestValidateFilter {
        RequestValidateFilter {
            counter: AtomicU64::new(0),
        }
    }

    fn make_filter() -> Box<dyn HttpFilter> {
        RequestValidateFilter::from_config(&serde_yaml::Value::Null).unwrap()
    }

    async fn run_filter(body_str: &str, classifier_metadata: &[(&str, &str)]) -> HttpFilterContext<'static> {
        let filter = make_filter();
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/responses",
        )));
        let mut ctx = crate::test_utils::make_filter_context(req);
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
        for (k, v) in classifier_metadata {
            ctx.set_metadata(*k, *v);
        }
        let mut body = Some(Bytes::from(body_str.to_owned()));

        filter.on_request_body(&mut ctx, &mut body, true).await.unwrap()
    }
}
