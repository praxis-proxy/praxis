// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Field extraction logic and header-value validation.

use std::borrow::Cow;

use tracing::{trace, warn};

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
            if contains_control_chars(&text) {
                warn!(
                    field = %field,
                    header = %header,
                    "skipping header injection: value is not safe for header promotion"
                );
                continue;
            }
            trace!(
                field = %field,
                header = %header,
                value = %text,
                "promoting JSON field to header"
            );
            headers.push((Cow::Owned(header.clone()), text));
            found_any = true;
        }
    }
    found_any
}

// -----------------------------------------------------------------------------
// Header Value Validation
// -----------------------------------------------------------------------------

pub(super) use crate::builtins::http::value_safety::contains_control_chars;
