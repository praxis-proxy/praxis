// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Shared config validation helpers for AI classifier filters.

use crate::{FilterError, body::limits::MAX_JSON_BODY_BYTES};

// ---------------------------------------------------------------------------
// Header Name Validation
// ---------------------------------------------------------------------------

/// Validate an optional header name using the HTTP header-name parser.
///
/// Returns `Ok` when the name is `None` (promotion disabled) or a
/// valid HTTP header name. Returns a [`FilterError`] for empty
/// strings or names that fail [`http::HeaderName::from_bytes`].
///
/// [`FilterError`]: crate::FilterError
/// [`http::HeaderName::from_bytes`]: http::HeaderName::from_bytes
pub(crate) fn validate_header_name(filter: &str, field: &str, header_name: Option<&str>) -> Result<(), FilterError> {
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
/// Returns a [`FilterError`] when the value is zero or exceeds
/// the `MAX_JSON_BODY_BYTES` ceiling (64 MiB).
///
/// [`FilterError`]: crate::FilterError
pub(crate) fn validate_max_body_bytes(filter: &str, value: usize) -> Result<(), FilterError> {
    if value == 0 {
        return Err(format!("{filter}: 'max_body_bytes' must be greater than 0").into());
    }

    if value > MAX_JSON_BODY_BYTES {
        return Err(format!("{filter}: max_body_bytes ({value}) exceeds maximum ({MAX_JSON_BODY_BYTES})").into());
    }

    Ok(())
}
