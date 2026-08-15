// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Field extraction logic and header-value validation.
//!
//! Walks a top-level JSON object with a serde map visitor: mapped keys are
//! converted to header text, unmapped values are skipped via [`IgnoredAny`],
//! and parsing stops as soon as every configured field has been seen
//! (first-wins on duplicate keys). Trailing bytes after early exit are not
//! validated.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fmt,
};

use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde_json::value::RawValue;
use tracing::{debug, trace, warn};

use super::super::MAX_DYNAMIC_VALUE_LEN;

/// Marker embedded in a serde error to signal intentional early exit.
const EARLY_EXIT: &str = "praxis_json_body_field_early_exit";

// -----------------------------------------------------------------------------
// Field Extraction
// -----------------------------------------------------------------------------

/// Extract mapped top-level JSON fields into request headers.
///
/// Returns `true` if any field was promoted. Invalid or non-object JSON,
/// or a parse error before all needed fields are found, yields `false`.
pub(super) fn extract_fields(
    mappings: &[(String, String)],
    bytes: &[u8],
    headers: &mut Vec<(Cow<'static, str>, String)>,
) -> bool {
    if mappings.is_empty() {
        return false;
    }

    let needed: HashSet<&str> = mappings.iter().map(|(field, _)| field.as_str()).collect();
    let mut found: HashMap<String, String> = HashMap::with_capacity(needed.len());

    let mut de = serde_json::Deserializer::from_slice(bytes);
    let seed = RootSeed {
        needed: &needed,
        found: &mut found,
    };

    match seed.deserialize(&mut de) {
        Ok(()) => {},
        Err(err) if err.to_string().contains(EARLY_EXIT) => {},
        Err(err) => {
            debug!(error = %err, body_len = bytes.len(), "JSON field extraction failed");
            return false;
        },
    }

    emit_headers(mappings, &found, headers)
}

/// Promote collected field values in config mapping order.
fn emit_headers(
    mappings: &[(String, String)],
    found: &HashMap<String, String>,
    headers: &mut Vec<(Cow<'static, str>, String)>,
) -> bool {
    let mut found_any = false;
    for (field, header) in mappings {
        let Some(text) = found.get(field.as_str()) else {
            continue;
        };
        if !is_safe_header_value(text, field, header) {
            continue;
        }
        trace!(
            field = %field,
            header = %header,
            value_len = text.len(),
            "promoting JSON field to header"
        );
        headers.push((Cow::Owned(header.clone()), text.clone()));
        found_any = true;
    }
    found_any
}

// -----------------------------------------------------------------------------
// Root + Map Visitors
// -----------------------------------------------------------------------------

/// `DeserializeSeed` entry that dispatches on the JSON root value kind.
struct RootSeed<'a> {
    /// Field names that still need to be collected.
    needed: &'a HashSet<&'a str>,
    /// Field name → header text collected so far (first-wins).
    found: &'a mut HashMap<String, String>,
}

impl<'de> DeserializeSeed<'de> for RootSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(RootVisitor {
            needed: self.needed,
            found: self.found,
        })
    }
}

/// Visitor that extracts mapped top-level object fields and ignores other roots.
struct RootVisitor<'a> {
    /// Field names that still need to be collected.
    needed: &'a HashSet<&'a str>,
    /// Field name → header text collected so far (first-wins).
    found: &'a mut HashMap<String, String>,
}

impl<'de> Visitor<'de> for RootVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<Cow<'_, str>>()? {
            if self.needed.contains(key.as_ref()) && !self.found.contains_key(key.as_ref()) {
                let raw: Box<RawValue> = map.next_value()?;
                let text = header_text_from_raw(&raw).map_err(de::Error::custom)?;
                self.found.insert(key.into_owned(), text);
                if self.found.len() == self.needed.len() {
                    return Err(de::Error::custom(EARLY_EXIT));
                }
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_string<E: de::Error>(self, _: String) -> Result<(), E> {
        Ok(())
    }

    fn visit_none<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<(), A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }
}

/// Convert a single JSON value's raw bytes into header text.
///
/// Strings are unescaped; objects, arrays, and scalars use the raw token text
/// (`null`, `true`, numbers, or the original object/array JSON).
fn header_text_from_raw(raw: &RawValue) -> Result<String, String> {
    let s = raw.get();
    match s.as_bytes().first() {
        Some(b'"') => serde_json::from_str::<String>(s).map_err(|e| e.to_string()),
        _ => Ok(s.to_owned()),
    }
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
