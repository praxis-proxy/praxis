// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Field extraction logic and header-value validation.
//!
//! Walks the complete top-level JSON object with a serde map visitor:
//! mapped keys are converted to header text, unmapped values are skipped
//! via [`IgnoredAny`], duplicate keys are last-wins (matching
//! `serde_json` and typical backend parsers), and trailing non-whitespace
//! content after the document is rejected so a value is only promoted
//! from a body the backend will parse the same way.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fmt,
};

use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde_json::value::RawValue;
use tracing::{debug, trace, warn};

use super::super::MAX_DYNAMIC_VALUE_LEN;

// -----------------------------------------------------------------------------
// Field Extraction
// -----------------------------------------------------------------------------

/// Extract mapped top-level JSON fields into request headers.
///
/// Returns `true` if any field was promoted. Invalid or non-object JSON,
/// or a parse error before all needed fields are found, yields `false`.
pub(super) fn extract_fields(
    mappings: &[(String, String)],
    needed: &HashSet<String>,
    bytes: &[u8],
    headers: &mut Vec<(Cow<'static, str>, String)>,
) -> bool {
    if mappings.is_empty() {
        return false;
    }

    let mut found: HashMap<String, String> = HashMap::with_capacity(needed.len());

    let mut de = serde_json::Deserializer::from_slice(bytes);
    let seed = RootSeed {
        needed,
        found: &mut found,
    };

    match seed.deserialize(&mut de) {
        // Reject trailing content: only promote from a body the backend will
        // also accept as a single JSON value, so the proxy's promoted header
        // cannot disagree with what the backend parses.
        Ok(()) => {
            if de.end().is_err() {
                debug!(body_len = bytes.len(), "JSON body has trailing content; not promoting");
                return false;
            }
        },
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
    needed: &'a HashSet<String>,
    /// Field name → header text collected so far (last-wins on duplicates).
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
    needed: &'a HashSet<String>,
    /// Field name → header text collected so far (last-wins on duplicates).
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
        // Scan every top-level entry (no early exit) and keep the LAST value
        // for a duplicated key, matching standard JSON parsers (serde_json,
        // Python, JS). Taking the first value while the backend takes the last
        // desynchronizes the proxy's promoted routing/classification header
        // from what the backend actually processes.
        while let Some(key) = map.next_key::<Cow<'_, str>>()? {
            if self.needed.contains(key.as_ref()) {
                let raw: Box<RawValue> = map.next_value()?;
                let text = header_text_from_raw(&raw).map_err(de::Error::custom)?;
                self.found.insert(key.into_owned(), text);
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    /// Promoted headers collected by [`extract_one`].
    type PromotedHeaders = Vec<(Cow<'static, str>, String)>;

    /// Run extraction of `field` -> `x-field` over `body`.
    fn extract_one(body: &str) -> (bool, PromotedHeaders) {
        let mappings = vec![("field".to_owned(), "x-field".to_owned())];
        let mut headers = Vec::new();
        let needed: HashSet<String> = mappings.iter().map(|(f, _)| f.clone()).collect();
        let found = extract_fields(&mappings, &needed, body.as_bytes(), &mut headers);
        (found, headers)
    }

    #[test]
    fn empty_mappings_extract_nothing() {
        let mut headers = Vec::new();
        assert!(
            !extract_fields(&[], &HashSet::new(), b"{\"a\":1}", &mut headers),
            "no mappings means nothing to promote"
        );
        assert!(headers.is_empty(), "no headers should be emitted");
    }

    #[test]
    fn invalid_json_extracts_nothing() {
        let (found, headers) = extract_one("{not json");
        assert!(!found, "malformed JSON must not promote fields");
        assert!(headers.is_empty(), "no headers should be emitted");
    }

    #[test]
    fn non_object_roots_extract_nothing() {
        for body in ["true", "false", "-3", "17", "2.5", "\"text\"", "null", "[1,2,3]"] {
            let (found, headers) = extract_one(body);
            assert!(!found, "root {body} must not promote fields");
            assert!(headers.is_empty(), "no headers for root {body}");
        }
    }

    #[test]
    fn nested_array_roots_are_skipped() {
        let (found, _) = extract_one("[{\"field\":\"x\"},[1,[2]]]");
        assert!(!found, "fields inside array roots must not be promoted");
    }

    #[test]
    fn string_value_is_unescaped() {
        let (found, headers) = extract_one("{\"field\":\"a\\nb\\u0041\"}");
        assert!(!found, "unescaped control characters must be rejected");
        assert!(headers.is_empty(), "control characters must never reach headers");
    }

    #[test]
    fn escaped_string_value_promotes_unescaped_text() {
        let (found, headers) = extract_one("{\"field\":\"caf\\u00e9\"}");
        assert!(found, "escaped values must promote");
        assert_eq!(
            headers.first().map(|(_, v)| v.as_str()),
            Some("café"),
            "the unescaped text must be promoted"
        );
    }

    #[test]
    fn overlong_value_is_skipped() {
        let long = "x".repeat(MAX_DYNAMIC_VALUE_LEN + 1);
        let (found, headers) = extract_one(&format!("{{\"field\":\"{long}\"}}"));
        assert!(!found, "values beyond the length ceiling must be skipped");
        assert!(headers.is_empty(), "no headers should be emitted for overlong values");
    }

    #[test]
    fn object_value_uses_raw_json_text() {
        let (found, headers) = extract_one("{\"field\":{\"a\":1}}");
        assert!(found, "object values promote their raw JSON");
        assert_eq!(
            headers.first().map(|(_, v)| v.as_str()),
            Some("{\"a\":1}"),
            "raw object text must be preserved"
        );
    }

    #[test]
    fn truncated_body_after_needed_field_still_fails_cleanly() {
        let (found, headers) = extract_one("{\"other\":1,\"fie");
        assert!(!found, "truncated JSON must not promote fields");
        assert!(headers.is_empty(), "no headers should be emitted");
    }
}
