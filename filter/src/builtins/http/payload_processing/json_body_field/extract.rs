// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Field extraction logic and header-value validation.

use std::borrow::Cow;

use tracing::{trace, warn};

use super::super::MAX_DYNAMIC_VALUE_LEN;

// -----------------------------------------------------------------------------
// Field Extraction
// -----------------------------------------------------------------------------

/// Extract mapped JSON fields into request headers, skipping values
/// that are not safe header values. Returns `true` if any field was promoted.
pub(super) fn extract_fields(
    mappings: &[(String, String)],
    value: &serde_json::Value,
    headers: &mut Vec<(Cow<'static, str>, String)>,
) -> bool {
    let mut found_any = false;
    for (field, header) in mappings {
        if let Some(field_val) = value.get(field.as_str()) {
            let text = match field_val {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if !is_safe_header_value(&text, field, header) {
                continue;
            }
            trace!(
                field = %field,
                header = %header,
                value_len = text.len(),
                "promoting JSON field to header"
            );
            headers.push((Cow::Owned(header.clone()), text));
            found_any = true;
        }
    }
    found_any
}

/// Reject values that are too long or contain control characters.
fn is_safe_header_value(text: &str, field: &str, header: &str) -> bool {
    if text.len() > MAX_DYNAMIC_VALUE_LEN {
        warn!(
            field = %field, header = %header,
            len = text.len(), max = MAX_DYNAMIC_VALUE_LEN,
            "skipping header promotion: value exceeds maximum length"
        );
        return false;
    }
    if contains_control_chars(text) {
        warn!(
            field = %field, header = %header,
            "skipping header promotion: value contains control characters"
        );
        return false;
    }
    true
}

// -----------------------------------------------------------------------------
// Header Value Validation
// -----------------------------------------------------------------------------

pub(super) use crate::builtins::http::value_safety::contains_control_chars;
