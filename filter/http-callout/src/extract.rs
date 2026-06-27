// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `JSONPath` extraction from callout response bodies.

use praxis_filter::{FilterError, FilterResultSet};
use serde_json::Value;
use serde_json_path::JsonPath;
use tracing::debug;

// -----------------------------------------------------------------------------
// Compiled Extraction
// -----------------------------------------------------------------------------

/// A pre-compiled `JSONPath` extraction rule.
#[derive(Debug)]
pub(crate) struct CompiledExtraction {
    /// The compiled `JSONPath` expression.
    path: JsonPath,

    /// Key to write into [`FilterResultSet`].
    result_key: String,
}

impl CompiledExtraction {
    /// Parse and compile a `JSONPath` expression at config time.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the expression is invalid.
    pub(crate) fn compile(json_path: &str, result_key: String) -> Result<Self, FilterError> {
        let path = JsonPath::parse(json_path)
            .map_err(|e| -> FilterError { format!("http_callout: invalid JSONPath '{json_path}': {e}").into() })?;
        Ok(Self { path, result_key })
    }

    /// Evaluate this extraction against a JSON value and write
    /// results into the result set.
    ///
    /// Coercion rules for the first matched node:
    /// - `bool` → `"true"` / `"false"`
    /// - `number` → decimal string
    /// - `string` → as-is
    /// - `array` / `object` → compact JSON
    /// - `null` or no match → skip (no entry written)
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the result set rejects the
    /// key or value.
    pub(crate) fn evaluate(&self, json: &Value, results: &mut FilterResultSet) -> Result<(), FilterError> {
        let node_list = self.path.query(json);
        let nodes: Vec<&Value> = node_list.all();

        let Some(first) = nodes.first() else {
            debug!(key = %self.result_key, "JSONPath matched no nodes; skipping");
            return Ok(());
        };

        let coerced = coerce_value(first);
        let Some(value) = coerced else {
            debug!(key = %self.result_key, "JSONPath matched null; skipping");
            return Ok(());
        };

        results.set(self.result_key.clone(), value)?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Coercion
// -----------------------------------------------------------------------------

/// Coerce a JSON value to a string for [`FilterResultSet`].
///
/// Returns `None` for null values.
fn coerce_value(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        Value::Array(_) | Value::Object(_) => Some(value.to_string()),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn compile_valid_expression() {
        assert!(
            CompiledExtraction::compile("$.flagged", "flagged".into()).is_ok(),
            "valid JSONPath should compile"
        );
    }

    #[test]
    fn compile_invalid_expression() {
        let err = CompiledExtraction::compile("$[invalid", "key".into()).unwrap_err();
        assert!(
            err.to_string().contains("invalid JSONPath"),
            "should report invalid expression: {err}"
        );
    }

    #[test]
    fn evaluate_bool_true() {
        let ext = CompiledExtraction::compile("$.flagged", "flagged".into()).unwrap();
        let json = json!({"flagged": true});
        let mut rs = FilterResultSet::new();
        ext.evaluate(&json, &mut rs).unwrap();
        assert_eq!(rs.get("flagged"), Some("true"));
    }

    #[test]
    fn evaluate_bool_false() {
        let ext = CompiledExtraction::compile("$.flagged", "flagged".into()).unwrap();
        let json = json!({"flagged": false});
        let mut rs = FilterResultSet::new();
        ext.evaluate(&json, &mut rs).unwrap();
        assert_eq!(rs.get("flagged"), Some("false"));
    }

    #[test]
    fn evaluate_number() {
        let ext = CompiledExtraction::compile("$.score", "score".into()).unwrap();
        let json = json!({"score": 0.95});
        let mut rs = FilterResultSet::new();
        ext.evaluate(&json, &mut rs).unwrap();
        assert_eq!(rs.get("score"), Some("0.95"));
    }

    #[test]
    fn evaluate_string() {
        let ext = CompiledExtraction::compile("$.label", "label".into()).unwrap();
        let json = json!({"label": "safe"});
        let mut rs = FilterResultSet::new();
        ext.evaluate(&json, &mut rs).unwrap();
        assert_eq!(rs.get("label"), Some("safe"));
    }

    #[test]
    fn evaluate_array() {
        let ext = CompiledExtraction::compile("$.tags", "tags".into()).unwrap();
        let json = json!({"tags": ["a", "b"]});
        let mut rs = FilterResultSet::new();
        ext.evaluate(&json, &mut rs).unwrap();
        assert_eq!(rs.get("tags"), Some(r#"["a","b"]"#));
    }

    #[test]
    fn evaluate_object() {
        let ext = CompiledExtraction::compile("$.meta", "meta".into()).unwrap();
        let json = json!({"meta": {"k": "v"}});
        let mut rs = FilterResultSet::new();
        ext.evaluate(&json, &mut rs).unwrap();
        assert_eq!(rs.get("meta"), Some(r#"{"k":"v"}"#));
    }

    #[test]
    fn evaluate_null_skips() {
        let ext = CompiledExtraction::compile("$.missing", "missing".into()).unwrap();
        let json = json!({"missing": null});
        let mut rs = FilterResultSet::new();
        ext.evaluate(&json, &mut rs).unwrap();
        assert!(rs.get("missing").is_none(), "null should be skipped");
    }

    #[test]
    fn evaluate_no_match_skips() {
        let ext = CompiledExtraction::compile("$.nonexistent", "key".into()).unwrap();
        let json = json!({"other": 1});
        let mut rs = FilterResultSet::new();
        ext.evaluate(&json, &mut rs).unwrap();
        assert!(rs.get("key").is_none(), "no-match should be skipped");
    }
}
