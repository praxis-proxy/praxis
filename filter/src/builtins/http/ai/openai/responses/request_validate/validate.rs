// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Validation logic for Responses API requests.
//!
//! Only validates parameters the proxy needs for its own operation
//! (stream/background interaction, background/store dependency).
//! All other validation is left to the inference server.

use crate::filter::HttpFilterContext;

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
/// Only checks parameter combinations the proxy needs for its own
/// operation. All other validation is left to the inference server.
pub(crate) fn validate_request(ctx: &HttpFilterContext<'_>) -> Result<(), ValidationError> {
    validate_stream_background(ctx)?;
    validate_background_store(ctx)?;
    Ok(())
}

/// Read a boolean from classifier metadata.
fn classifier_bool(ctx: &HttpFilterContext<'_>, key: &str) -> Option<bool> {
    ctx.get_metadata(key).map(|v| v == "true")
}

/// Reject `stream=true` combined with `background=true`.
fn validate_stream_background(ctx: &HttpFilterContext<'_>) -> Result<(), ValidationError> {
    if classifier_bool(ctx, "openai_responses_format.stream") == Some(true)
        && classifier_bool(ctx, "openai_responses_format.background") == Some(true)
    {
        return Err(ValidationError::new("stream and background cannot both be true"));
    }
    Ok(())
}

/// Reject `background=true` when `store=false`.
fn validate_background_store(ctx: &HttpFilterContext<'_>) -> Result<(), ValidationError> {
    if classifier_bool(ctx, "openai_responses_format.background") == Some(true)
        && classifier_bool(ctx, "openai_responses_format.store") == Some(false)
    {
        return Err(ValidationError::new("background responses require store to be true"));
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

    #[test]
    fn valid_minimal_request() {
        let ctx = make_ctx_with_metadata(&[]);
        assert!(validate_request(&ctx).is_ok(), "minimal request should be valid");
    }

    #[test]
    fn stream_and_background_rejected() {
        let ctx = make_ctx_with_metadata(&[
            ("openai_responses_format.stream", "true"),
            ("openai_responses_format.background", "true"),
        ]);
        let err = validate_request(&ctx).unwrap_err();
        assert!(
            err.message.contains("stream and background"),
            "error should mention stream and background: {err}"
        );
    }

    #[test]
    fn stream_true_background_false_accepted() {
        let ctx = make_ctx_with_metadata(&[
            ("openai_responses_format.stream", "true"),
            ("openai_responses_format.background", "false"),
        ]);
        assert!(
            validate_request(&ctx).is_ok(),
            "stream=true background=false should be valid"
        );
    }

    #[test]
    fn background_without_store_rejected() {
        let ctx = make_ctx_with_metadata(&[
            ("openai_responses_format.background", "true"),
            ("openai_responses_format.store", "false"),
        ]);
        let err = validate_request(&ctx).unwrap_err();
        assert!(err.message.contains("store"), "error should mention store: {err}");
    }

    #[test]
    fn background_with_store_accepted() {
        let ctx = make_ctx_with_metadata(&[
            ("openai_responses_format.background", "true"),
            ("openai_responses_format.store", "true"),
        ]);
        assert!(
            validate_request(&ctx).is_ok(),
            "background=true store=true should be valid"
        );
    }
}
