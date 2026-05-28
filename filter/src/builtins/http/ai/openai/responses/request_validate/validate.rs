// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Validation logic for Responses API requests.
//!
//! Parameter-combination checks read from `responses_format.*`
//! classifier metadata. Metadata constraint checks read from the
//! parsed JSON body directly.

use crate::filter::HttpFilterContext;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum number of metadata keys per request.
const MAX_METADATA_KEYS: usize = 16;

/// Maximum length of a metadata key in characters.
const MAX_METADATA_KEY_LEN: usize = 64;

/// Maximum length of a metadata value in characters.
const MAX_METADATA_VALUE_LEN: usize = 512;

// -----------------------------------------------------------------------------
// ValidationError
// -----------------------------------------------------------------------------

/// Validation error with a structured error message.
#[derive(Debug)]
pub(crate) struct ValidationError {
    /// Human-readable error message.
    message: String,
}

impl ValidationError {
    /// Create a new validation error.
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Format as a JSON error response body.
    pub(crate) fn to_json_body(&self) -> String {
        serde_json::json!({
            "error": {
                "message": &self.message,
                "type": "invalid_request_error"
            }
        })
        .to_string()
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Validate a Responses API request.
///
/// Reads `stream`, `store`, `background` from `responses_format.*`
/// classifier metadata. Validates request `metadata` constraints
/// from the raw JSON body.
pub(crate) fn validate_request(ctx: &HttpFilterContext<'_>, body: &serde_json::Value) -> Result<(), ValidationError> {
    validate_stream_background(ctx)?;
    validate_background_store(ctx)?;
    validate_model(ctx)?;
    validate_request_metadata(body)?;
    Ok(())
}

/// Read a boolean from classifier metadata.
fn classifier_bool(ctx: &HttpFilterContext<'_>, key: &str) -> Option<bool> {
    ctx.get_metadata(key).map(|v| v == "true")
}

/// Reject `stream=true` combined with `background=true`.
fn validate_stream_background(ctx: &HttpFilterContext<'_>) -> Result<(), ValidationError> {
    if classifier_bool(ctx, "responses_format.stream") == Some(true)
        && classifier_bool(ctx, "responses_format.background") == Some(true)
    {
        return Err(ValidationError::new("stream and background cannot both be true"));
    }
    Ok(())
}

/// Reject `background=true` when `store=false`.
fn validate_background_store(ctx: &HttpFilterContext<'_>) -> Result<(), ValidationError> {
    if classifier_bool(ctx, "responses_format.background") == Some(true)
        && classifier_bool(ctx, "responses_format.store") == Some(false)
    {
        return Err(ValidationError::new("background responses require store to be true"));
    }
    Ok(())
}

/// Validate model field if present (must be non-empty).
fn validate_model(ctx: &HttpFilterContext<'_>) -> Result<(), ValidationError> {
    if ctx.get_metadata("responses_format.model") == Some("") {
        return Err(ValidationError::new("model must not be an empty string"));
    }
    Ok(())
}

/// Validate request metadata constraints from the JSON body.
fn validate_request_metadata(body: &serde_json::Value) -> Result<(), ValidationError> {
    let Some(metadata) = body.get("metadata") else {
        return Ok(());
    };

    let Some(obj) = metadata.as_object() else {
        return Err(ValidationError::new("metadata must be an object"));
    };

    if obj.len() > MAX_METADATA_KEYS {
        return Err(ValidationError::new(format!(
            "metadata exceeds maximum of {MAX_METADATA_KEYS} keys (got {})",
            obj.len()
        )));
    }

    for (key, value) in obj {
        if key.chars().count() > MAX_METADATA_KEY_LEN {
            return Err(ValidationError::new(format!(
                "metadata key '{key}' exceeds maximum length of {MAX_METADATA_KEY_LEN} characters"
            )));
        }
        let Some(v) = value.as_str() else {
            return Err(ValidationError::new(format!(
                "metadata value for key '{key}' must be a string"
            )));
        };
        if v.chars().count() > MAX_METADATA_VALUE_LEN {
            return Err(ValidationError::new(format!(
                "metadata value for key '{key}' exceeds maximum length of {MAX_METADATA_VALUE_LEN} characters"
            )));
        }
    }

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
    use super::*;

    fn make_ctx_with_metadata(pairs: &[(&str, &str)]) -> Box<HttpFilterContext<'static>> {
        let req = Box::leak(Box::new(crate::test_utils::make_request(
            http::Method::POST,
            "/v1/responses",
        )));
        let mut ctx = Box::new(crate::test_utils::make_filter_context(req));
        for (k, v) in pairs {
            ctx.set_metadata(*k, *v);
        }
        ctx
    }

    fn empty_body() -> serde_json::Value {
        serde_json::json!({"input": "test"})
    }

    #[test]
    fn valid_minimal_request() {
        let ctx = make_ctx_with_metadata(&[]);
        assert!(
            validate_request(&ctx, &empty_body()).is_ok(),
            "minimal request should be valid"
        );
    }

    #[test]
    fn stream_and_background_rejected() {
        let ctx = make_ctx_with_metadata(&[
            ("responses_format.stream", "true"),
            ("responses_format.background", "true"),
        ]);
        let err = validate_request(&ctx, &empty_body()).unwrap_err();
        assert!(
            err.message.contains("stream and background"),
            "error should mention stream and background: {err}"
        );
    }

    #[test]
    fn stream_true_background_false_accepted() {
        let ctx = make_ctx_with_metadata(&[
            ("responses_format.stream", "true"),
            ("responses_format.background", "false"),
        ]);
        assert!(
            validate_request(&ctx, &empty_body()).is_ok(),
            "stream=true background=false should be valid"
        );
    }

    #[test]
    fn background_without_store_rejected() {
        let ctx = make_ctx_with_metadata(&[
            ("responses_format.background", "true"),
            ("responses_format.store", "false"),
        ]);
        let err = validate_request(&ctx, &empty_body()).unwrap_err();
        assert!(err.message.contains("store"), "error should mention store: {err}");
    }

    #[test]
    fn background_with_store_accepted() {
        let ctx = make_ctx_with_metadata(&[
            ("responses_format.background", "true"),
            ("responses_format.store", "true"),
        ]);
        assert!(
            validate_request(&ctx, &empty_body()).is_ok(),
            "background=true store=true should be valid"
        );
    }

    #[test]
    fn empty_model_rejected() {
        let ctx = make_ctx_with_metadata(&[("responses_format.model", "")]);
        let err = validate_request(&ctx, &empty_body()).unwrap_err();
        assert!(err.message.contains("model"), "error should mention model: {err}");
    }

    #[test]
    fn absent_model_accepted() {
        let ctx = make_ctx_with_metadata(&[]);
        assert!(
            validate_request(&ctx, &empty_body()).is_ok(),
            "absent model should be valid"
        );
    }

    #[test]
    fn metadata_too_many_keys_rejected() {
        let ctx = make_ctx_with_metadata(&[]);
        let mut metadata = serde_json::Map::new();
        for i in 0..17 {
            metadata.insert(format!("k{i}"), serde_json::json!("v"));
        }
        let body = serde_json::json!({"input": "test", "metadata": metadata});
        let err = validate_request(&ctx, &body).unwrap_err();
        assert!(err.message.contains("metadata"), "error should mention metadata: {err}");
    }

    #[test]
    fn metadata_key_too_long() {
        let ctx = make_ctx_with_metadata(&[]);
        let body = serde_json::json!({"input": "test", "metadata": {"k".repeat(65): "v"}});
        let err = validate_request(&ctx, &body).unwrap_err();
        assert!(err.message.contains("metadata key"), "error should mention key: {err}");
    }

    #[test]
    fn metadata_value_too_long() {
        let ctx = make_ctx_with_metadata(&[]);
        let body = serde_json::json!({"input": "test", "metadata": {"k": "v".repeat(513)}});
        let err = validate_request(&ctx, &body).unwrap_err();
        assert!(
            err.message.contains("metadata value"),
            "error should mention value: {err}"
        );
    }

    #[test]
    fn metadata_non_object_rejected() {
        let ctx = make_ctx_with_metadata(&[]);
        let body = serde_json::json!({"input": "test", "metadata": []});
        let err = validate_request(&ctx, &body).unwrap_err();
        assert!(err.message.contains("metadata"), "error should mention metadata: {err}");
        assert!(err.message.contains("object"), "error should mention object: {err}");
    }

    #[test]
    fn metadata_non_string_value_rejected() {
        let ctx = make_ctx_with_metadata(&[]);
        let body = serde_json::json!({"input": "test", "metadata": {"k": 123}});
        let err = validate_request(&ctx, &body).unwrap_err();
        assert!(
            err.message.contains("metadata value"),
            "error should mention metadata value: {err}"
        );
        assert!(err.message.contains("string"), "error should mention string: {err}");
    }

    #[test]
    fn validation_error_json_body() {
        let err = ValidationError::new("test error");
        let body = err.to_json_body();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            parsed["error"]["message"].as_str(),
            Some("test error"),
            "JSON body should contain the error message"
        );
        assert_eq!(
            parsed["error"]["type"].as_str(),
            Some("invalid_request_error"),
            "JSON body should have the correct error type"
        );
    }

    #[test]
    fn validation_error_escapes_quotes() {
        let err = ValidationError::new(r#"bad "value""#);
        let body = err.to_json_body();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            parsed["error"]["message"].as_str(),
            Some(r#"bad "value""#),
            "quotes in error message should be properly escaped"
        );
    }

    #[test]
    fn validation_error_escapes_control_characters() {
        let err = ValidationError::new("line1\nline2");
        let body = err.to_json_body();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            parsed["error"]["message"].as_str(),
            Some("line1\nline2"),
            "control characters in error message should be JSON-escaped"
        );
    }
}
