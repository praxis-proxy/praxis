// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Metadata validation for conversation objects.

use serde_json::Value;

/// Maximum number of metadata keys.
const MAX_METADATA_KEYS: usize = 16;

/// Maximum length of a metadata key in bytes.
const MAX_KEY_BYTES: usize = 64;

/// Maximum length of a metadata string value in bytes.
const MAX_VALUE_BYTES: usize = 512;

/// Validate conversation metadata.
///
/// Rules:
/// - Must be a JSON object (or null/absent → default `{}`)
/// - At most 16 keys
/// - Each key ≤ 64 bytes
/// - Each value must be a string ≤ 512 bytes
pub(crate) fn validate_metadata(metadata: &Value) -> Result<(), String> {
    let obj = match metadata {
        Value::Object(map) => map,
        Value::Null => return Ok(()),
        _ => return Err("metadata must be a JSON object".to_owned()),
    };

    if obj.len() > MAX_METADATA_KEYS {
        return Err(format!(
            "metadata must have at most {MAX_METADATA_KEYS} keys, got {}",
            obj.len()
        ));
    }

    for (key, value) in obj {
        if key.len() > MAX_KEY_BYTES {
            return Err(format!("metadata key exceeds {MAX_KEY_BYTES} bytes: '{key}'"));
        }
        match value {
            Value::String(s) => {
                if s.len() > MAX_VALUE_BYTES {
                    return Err(format!(
                        "metadata value for key '{key}' exceeds {MAX_VALUE_BYTES} bytes"
                    ));
                }
            },
            _ => return Err(format!("metadata value for key '{key}' must be a string")),
        }
    }

    Ok(())
}
