// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Shared config validation helpers for payload processing filters.

use crate::{FilterError, body::MAX_JSON_BODY_BYTES};

// ---------------------------------------------------------------------------
// Header Name Validation
// ---------------------------------------------------------------------------

/// Validate an optional header name using the HTTP header-name parser.
///
/// Returns `Ok` when the name is `None` (promotion disabled) or a
/// valid HTTP header name.
///
/// # Errors
///
/// Returns [`FilterError`] for empty strings or names that fail
/// [`http::HeaderName::from_bytes`].
///
/// [`FilterError`]: crate::FilterError
/// [`http::HeaderName::from_bytes`]: http::HeaderName::from_bytes
pub fn validate_header_name(filter: &str, field: &str, header_name: Option<&str>) -> Result<(), FilterError> {
    let Some(name) = header_name else {
        return Ok(());
    };

    if name.is_empty() {
        return Err(format!("{filter}: {field} header name must not be empty").into());
    }

    if http::HeaderName::from_bytes(name.as_bytes()).is_err() {
        return Err(format!("{filter}: {field} header name is not a valid HTTP header name").into());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Body Size Validation
// ---------------------------------------------------------------------------

/// Validate `max_body_bytes` is non-zero and within the ceiling.
///
/// # Errors
///
/// Returns [`FilterError`] when the value is zero or exceeds
/// the `MAX_JSON_BODY_BYTES` ceiling (64 MiB).
///
/// [`FilterError`]: crate::FilterError
pub fn validate_max_body_bytes(filter: &str, value: usize) -> Result<(), FilterError> {
    if value == 0 {
        return Err(format!("{filter}: 'max_body_bytes' must be greater than 0").into());
    }

    if value > MAX_JSON_BODY_BYTES {
        return Err(format!("{filter}: max_body_bytes ({value}) exceeds maximum ({MAX_JSON_BODY_BYTES})").into());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn header_name_none_accepted() {
        validate_header_name("test", "field", None).expect("None header name should be accepted");
    }

    #[test]
    fn header_name_valid_accepted() {
        validate_header_name("test", "field", Some("X-Custom")).expect("valid header name should be accepted");
    }

    #[test]
    fn header_name_empty_rejected() {
        let err = validate_header_name("test", "field", Some("")).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "empty header name should be rejected, got: {err}"
        );
    }

    #[test]
    fn header_name_invalid_chars_rejected() {
        let err = validate_header_name("test", "field", Some("Bad Header")).unwrap_err();
        assert!(
            err.to_string().contains("not a valid HTTP header name"),
            "header with spaces should be rejected, got: {err}"
        );
    }

    #[test]
    fn max_body_bytes_valid_accepted() {
        validate_max_body_bytes("test", 1024).expect("1024 bytes should be accepted");
    }

    #[test]
    fn max_body_bytes_zero_rejected() {
        let err = validate_max_body_bytes("test", 0).unwrap_err();
        assert!(
            err.to_string().contains("greater than 0"),
            "zero should be rejected, got: {err}"
        );
    }

    #[test]
    fn max_body_bytes_exceeds_ceiling_rejected() {
        let err = validate_max_body_bytes("test", MAX_JSON_BODY_BYTES + 1).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "above ceiling should be rejected, got: {err}"
        );
    }

    #[test]
    fn max_body_bytes_at_ceiling_accepted() {
        validate_max_body_bytes("test", MAX_JSON_BODY_BYTES).expect("exactly at ceiling should be accepted");
    }
}
