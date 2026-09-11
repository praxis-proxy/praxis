// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the JSON Pointer tokenizer rewrite engine.

use bytes::Bytes;
use serde_json::json;

use super::{
    JsonError,
    ops::OpKind,
    pointer::compile_pointer,
    rewrite::{ResolvedOp, rewrite},
};

fn resolved(kind: OpKind, pointer: &str, payload: Option<&str>) -> ResolvedOp {
    ResolvedOp {
        tokens: compile_pointer(pointer).unwrap(),
        kind,
        payload: payload.map(|s| Bytes::from(s.to_owned())),
    }
}

fn rewrite_str(input: &str, ops: &[ResolvedOp]) -> Result<String, JsonError> {
    rewrite(input.as_bytes(), ops).map(|b| String::from_utf8(b).unwrap())
}

use super::{ExtractDest, JsonOpStore as _, JsonOps, JsonValue, MapStore};

#[test]
fn replace_object_field() {
    let out = rewrite_str(
        r#"{"model":"old","n":1}"#,
        &[resolved(OpKind::Replace, "/model", Some(r#""forced""#))],
    )
    .unwrap();
    assert_eq!(out, r#"{"model":"forced","n":1}"#);
}

#[test]
fn replace_missing_is_noop() {
    let out = rewrite_str(r#"{"n":1}"#, &[resolved(OpKind::Replace, "/model", Some(r#""x""#))]).unwrap();
    assert_eq!(out, r#"{"n":1}"#);
}

#[test]
fn remove_first_middle_last_only() {
    assert_eq!(
        rewrite_str(r#"{"a":1,"b":2,"c":3}"#, &[resolved(OpKind::Remove, "/a", None)]).unwrap(),
        r#"{"b":2,"c":3}"#
    );
    assert_eq!(
        rewrite_str(r#"{"a":1,"b":2,"c":3}"#, &[resolved(OpKind::Remove, "/b", None)]).unwrap(),
        r#"{"a":1,"c":3}"#
    );
    assert_eq!(
        rewrite_str(r#"{"a":1,"b":2,"c":3}"#, &[resolved(OpKind::Remove, "/c", None)]).unwrap(),
        r#"{"a":1,"b":2}"#
    );
    assert_eq!(
        rewrite_str(r#"{"a":1}"#, &[resolved(OpKind::Remove, "/a", None)]).unwrap(),
        "{}"
    );
}

#[test]
fn remove_missing_is_noop() {
    let out = rewrite_str(r#"{"a":1}"#, &[resolved(OpKind::Remove, "/nope", None)]).unwrap();
    assert_eq!(out, r#"{"a":1}"#);
}

#[test]
fn add_missing_object_field() {
    let out = rewrite_str(r#"{"a":1}"#, &[resolved(OpKind::Add, "/b", Some("2"))]).unwrap();
    assert_eq!(out, r#"{"a":1,"b":2}"#);
}

#[test]
fn add_to_empty_object() {
    let out = rewrite_str("{}", &[resolved(OpKind::Add, "/k", Some(r#""v""#))]).unwrap();
    assert_eq!(out, r#"{"k":"v"}"#);
}

#[test]
fn add_existing_object_key_overwrites() {
    let out = rewrite_str(r#"{"a":1}"#, &[resolved(OpKind::Add, "/a", Some("9"))]).unwrap();
    assert_eq!(out, r#"{"a":9}"#);
}

#[test]
fn missing_parent_skips_add() {
    let out = rewrite_str(r#"{"a":1}"#, &[resolved(OpKind::Add, "/x/y", Some("1"))]).unwrap();
    assert_eq!(out, r#"{"a":1}"#);
}

#[test]
fn duplicate_keys_remove_all_matches() {
    let out = rewrite_str(r#"{"a":1,"a":2}"#, &[resolved(OpKind::Remove, "/a", None)]).unwrap();
    assert_eq!(out, "{}");
}

#[test]
fn duplicate_keys_replace_all_matches() {
    let out = rewrite_str(r#"{"a":1,"a":2,"b":3}"#, &[resolved(OpKind::Replace, "/a", Some("9"))]).unwrap();
    assert_eq!(out, r#"{"a":9,"a":9,"b":3}"#);
}

#[test]
fn duplicate_keys_add_replaces_all_existing() {
    let out = rewrite_str(r#"{"a":1,"a":2}"#, &[resolved(OpKind::Add, "/a", Some("9"))]).unwrap();
    assert_eq!(out, r#"{"a":9,"a":9}"#);
}

#[test]
fn untargeted_duplicate_keys_are_preserved() {
    let out = rewrite_str(r#"{"a":1,"a":2}"#, &[resolved(OpKind::Add, "/b", Some("3"))]).unwrap();
    assert_eq!(out, r#"{"a":1,"a":2,"b":3}"#);
}

#[test]
fn remove_object_valued_field() {
    let out = rewrite_str(
        r#"{"keep":1,"drop":{"x":2}}"#,
        &[resolved(OpKind::Remove, "/drop", None)],
    )
    .unwrap();
    assert_eq!(out, r#"{"keep":1}"#);
}

#[test]
fn nested_replace() {
    let out = rewrite_str(
        r#"{"user":{"id":"old","n":1}}"#,
        &[resolved(OpKind::Replace, "/user/id", Some(r#""new""#))],
    )
    .unwrap();
    assert_eq!(out, r#"{"user":{"id":"new","n":1}}"#);
}

#[test]
fn unused_nested_object_and_array_are_copied() {
    let out = rewrite_str(
        r#"{"model":"old","obj":{"id":1,"tag":"bench"},"arr":["a","b","0"]}"#,
        &[
            resolved(OpKind::Replace, "/model", Some(r#""forced""#)),
            resolved(OpKind::Add, "/tenant", Some(r#""acme""#)),
        ],
    )
    .unwrap();
    let got: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        got,
        json!({"model":"forced","obj":{"id":1,"tag":"bench"},"arr":["a","b","0"],"tenant":"acme"})
    );
}

#[test]
fn escaped_pointer_key() {
    let out = rewrite_str(r#"{"a/b":1}"#, &[resolved(OpKind::Replace, "/a~1b", Some("2"))]).unwrap();
    assert_eq!(out, r#"{"a/b":2}"#);
}

#[test]
fn escaped_key_extract_and_replace() {
    let out = rewrite_str(
        r#"{"a/b":{"x":1},"keep":true}"#,
        &[resolved(OpKind::Replace, "/a~1b/x", Some("2"))],
    )
    .unwrap();
    assert_eq!(out, r#"{"a/b":{"x":2},"keep":true}"#);
}

#[test]
fn root_replace() {
    let out = rewrite_str(r#"{"a":1}"#, &[resolved(OpKind::Replace, "", Some("[1,2]"))]).unwrap();
    assert_eq!(out, "[1,2]");
}

// -----------------------------------------------------------------------------
// Tokenizer: arrays
// -----------------------------------------------------------------------------

#[test]
fn array_replace_index() {
    let out = rewrite_str("[1,2,3]", &[resolved(OpKind::Replace, "/1", Some("9"))]).unwrap();
    assert_eq!(out, "[1,9,3]");
}

#[test]
fn array_remove_index() {
    assert_eq!(
        rewrite_str("[1,2,3]", &[resolved(OpKind::Remove, "/0", None)]).unwrap(),
        "[2,3]"
    );
    assert_eq!(
        rewrite_str("[1,2,3]", &[resolved(OpKind::Remove, "/1", None)]).unwrap(),
        "[1,3]"
    );
    assert_eq!(
        rewrite_str("[1,2,3]", &[resolved(OpKind::Remove, "/2", None)]).unwrap(),
        "[1,2]"
    );
}

#[test]
fn array_insert_at_index() {
    let out = rewrite_str("[1,3]", &[resolved(OpKind::Add, "/1", Some("2"))]).unwrap();
    assert_eq!(out, "[1,2,3]");
}

#[test]
fn array_append() {
    let out = rewrite_str("[1]", &[resolved(OpKind::Add, "/-", Some("2"))]).unwrap();
    assert_eq!(out, "[1,2]");
}

#[test]
fn array_append_empty() {
    let out = rewrite_str("[]", &[resolved(OpKind::Add, "/-", Some("1"))]).unwrap();
    assert_eq!(out, "[1]");
}

#[test]
fn array_insert_at_length() {
    let out = rewrite_str("[1,2]", &[resolved(OpKind::Add, "/2", Some("3"))]).unwrap();
    assert_eq!(out, "[1,2,3]");
}

#[test]
fn array_out_of_range_add_skipped() {
    let out = rewrite_str("[1]", &[resolved(OpKind::Add, "/3", Some("9"))]).unwrap();
    assert_eq!(out, "[1]");
}

#[test]
fn array_append_on_object_is_skipped() {
    let out = rewrite_str(r#"{"a":1}"#, &[resolved(OpKind::Add, "/-", Some("2"))]).unwrap();
    assert_eq!(out, r#"{"a":1}"#, "add / - is array-only; objects are left unchanged");
}

#[test]
fn array_append_does_not_replace_object_dash_key() {
    let out = rewrite_str(r#"{"-":1}"#, &[resolved(OpKind::Add, "/-", Some("2"))]).unwrap();
    assert_eq!(out, r#"{"-":1}"#, "array append must not rewrite object key '-'");
}

#[test]
fn numeric_pointer_replace_on_object_key() {
    let out = rewrite_str(r#"{"0":1,"a":2}"#, &[resolved(OpKind::Replace, "/0", Some("9"))]).unwrap();
    assert_eq!(out, r#"{"0":9,"a":2}"#);
}

#[test]
fn numeric_pointer_add_on_object_emits_key() {
    let out = rewrite_str(r#"{"a":1}"#, &[resolved(OpKind::Add, "/0", Some("9"))]).unwrap();
    let got: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("rewrite must emit valid JSON, got {out:?}: {e}"));
    assert_eq!(got, json!({"a": 1, "0": 9}));
}

// -----------------------------------------------------------------------------
// Invalid JSON
// -----------------------------------------------------------------------------

#[test]
fn invalid_json_errors() {
    assert_eq!(rewrite_str("{", &[]).unwrap_err(), JsonError::InvalidJson);
    assert_eq!(rewrite_str(r#"{"a":1,}"#, &[]).unwrap_err(), JsonError::InvalidJson);
    assert_eq!(rewrite_str("true extra", &[]).unwrap_err(), JsonError::InvalidJson);
}

#[test]
fn depth_exceeded_errors() {
    let mut nested = String::from("1");
    for _ in 0..130 {
        nested = format!("[{nested}]");
    }
    assert_eq!(rewrite_str(&nested, &[]).unwrap_err(), JsonError::Depth);
}

#[test]
fn pretty_printed_object_rewrites() {
    let input = "{\n  \"a\": 1,\n  \"b\": 2\n}";
    let out = rewrite_str(input, &[resolved(OpKind::Remove, "/b", None)]).unwrap();
    assert_eq!(out, r#"{"a":1}"#);
}

// -----------------------------------------------------------------------------
// Filter hooks
// -----------------------------------------------------------------------------

#[test]
fn add_nested_under_existing_object() {
    let out = rewrite_str(
        r#"{"user":{"id":1}}"#,
        &[resolved(OpKind::Add, "/user/role", Some(r#""admin""#))],
    )
    .unwrap();
    assert_eq!(out, r#"{"user":{"id":1,"role":"admin"}}"#);
}

#[test]
fn scalar_root_without_matching_ops_copied() {
    let out = rewrite_str("42", &[resolved(OpKind::Remove, "/a", None)]).unwrap();
    assert_eq!(out, "42");
}

#[test]
fn string_value_with_escapes_copied() {
    let input = r#"{"a":"x\"y"}"#;
    let out = rewrite_str(input, &[resolved(OpKind::Add, "/b", Some("1"))]).unwrap();
    assert_eq!(out, r#"{"a":"x\"y","b":1}"#);
}

#[test]
fn builder_rejects_overlapping_mutators() {
    let err = JsonOps::builder()
        .remove("/a")
        .unwrap()
        .remove("/a/b")
        .unwrap()
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("overlapping"), "got: {err}");
}

#[test]
fn builder_apply_extracts_into_map_store() {
    let ops = JsonOps::builder()
        .extract("/model", ExtractDest::metadata("original.model"))
        .unwrap()
        .build()
        .unwrap();
    let mut store = MapStore::new();
    let rewrite = ops.apply(br#"{"model":"old","n":1}"#, Some(&mut store)).unwrap();
    assert!(rewrite.output.is_none(), "extract-only");
    assert_eq!(store.metadata().get("original.model").map(String::as_str), Some("old"));
}

#[test]
fn builder_static_replace() {
    let ops = JsonOps::builder()
        .replace("/model", JsonValue::static_json(json!("forced")).unwrap())
        .unwrap()
        .build()
        .unwrap();
    let out = ops.apply(br#"{"model":"old"}"#, None).unwrap().output.unwrap();
    assert_eq!(out, br#"{"model":"forced"}"#);
}

#[test]
fn env_var_missing_fails_at_build() {
    let err = JsonValue::env_var("PRAXIS_JSON_OPS_ENV_DEFINITELY_MISSING").unwrap_err();
    assert!(err.to_string().contains("not set"), "got: {err}");
}

#[test]
fn builder_rejects_invalid_extract_header_name() {
    let err = JsonOps::builder()
        .extract("/model", ExtractDest::header("bad name"))
        .unwrap_err();
    assert!(err.to_string().contains("invalid header name"), "got: {err}");
}

#[test]
fn extract_to_request_header() {
    let ops = JsonOps::builder()
        .extract("/model", ExtractDest::header("X-Model"))
        .unwrap()
        .build()
        .unwrap();
    let mut store = MapStore::new();
    ops.apply(br#"{"model":"gpt-4"}"#, Some(&mut store)).unwrap();
    assert_eq!(store.request_headers(), &[("X-Model".to_owned(), "gpt-4".to_owned())]);
}

#[test]
fn extract_header_skips_oversized_value() {
    use crate::builtins::http::payload_processing::MAX_DYNAMIC_VALUE_LEN;

    let ops = JsonOps::builder()
        .extract("/model", ExtractDest::header("X-Model"))
        .unwrap()
        .build()
        .unwrap();
    let long = "a".repeat(MAX_DYNAMIC_VALUE_LEN + 1);
    let body = format!(r#"{{"model":"{long}"}}"#);
    let mut store = MapStore::new();
    ops.apply(body.as_bytes(), Some(&mut store)).unwrap();
    assert!(
        store.request_headers().is_empty(),
        "oversized header values must be skipped"
    );
}

#[test]
fn extract_header_skips_control_characters() {
    let ops = JsonOps::builder()
        .extract("/model", ExtractDest::header("X-Model"))
        .unwrap()
        .build()
        .unwrap();
    let mut store = MapStore::new();
    ops.apply(br#"{"model":"bad\nvalue"}"#, Some(&mut store)).unwrap();
    assert!(
        store.request_headers().is_empty(),
        "control characters must not reach headers"
    );
}

#[test]
fn extract_header_skips_on_trailing_junk() {
    let ops = JsonOps::builder()
        .extract("/model", ExtractDest::header("X-Model"))
        .unwrap()
        .build()
        .unwrap();
    let mut store = MapStore::new();
    let err = ops
        .apply(br#"{"model":"premium"} garbage"#, Some(&mut store))
        .unwrap_err();
    assert_eq!(err, JsonError::InvalidJson);
    assert!(
        store.request_headers().is_empty(),
        "trailing junk must block header promotion"
    );
}

#[test]
fn extract_only_trailing_junk_does_not_promote_metadata() {
    let ops = JsonOps::builder()
        .extract("/model", ExtractDest::metadata("original.model"))
        .unwrap()
        .build()
        .unwrap();
    let mut store = MapStore::new();
    let err = ops.apply(br#"{"model":"old"} garbage"#, Some(&mut store)).unwrap_err();
    assert_eq!(err, JsonError::InvalidJson);
    assert!(store.metadata().is_empty());
}

#[test]
fn extract_only_trailing_junk_blocks_structured_metadata() {
    let ops = JsonOps::builder()
        .extract("/user", ExtractDest::structured("ext", "user"))
        .unwrap()
        .build()
        .unwrap();
    let mut store = MapStore::new();
    let err = ops
        .apply(br#"{"user":{"id":1}} garbage"#, Some(&mut store))
        .unwrap_err();
    assert_eq!(err, JsonError::InvalidJson);
    assert!(store.get_structured("ext", "user").is_none());
}

#[test]
fn extract_descendant_before_remove_parent() {
    let ops = JsonOps::builder()
        .extract("/a/b", ExtractDest::metadata("nested.b"))
        .unwrap()
        .remove("/a")
        .unwrap()
        .build()
        .unwrap();
    let mut store = MapStore::new();
    let rewrite = ops.apply(br#"{"a":{"b":"keep"},"other":1}"#, Some(&mut store)).unwrap();
    assert_eq!(rewrite.output.as_deref(), Some(br#"{"other":1}"#.as_ref()));
    assert_eq!(store.metadata().get("nested.b").map(String::as_str), Some("keep"));
}

#[test]
fn extract_descendant_before_replace_parent() {
    let ops = JsonOps::builder()
        .extract("/a/b", ExtractDest::metadata("nested.b"))
        .unwrap()
        .replace("/a", JsonValue::static_json(json!({"x":9})).unwrap())
        .unwrap()
        .build()
        .unwrap();
    let mut store = MapStore::new();
    let rewrite = ops.apply(br#"{"a":{"b":"keep"},"other":1}"#, Some(&mut store)).unwrap();
    let out = rewrite.output.expect("mutating ops emit a body");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out).unwrap(),
        json!({"a": {"x": 9}, "other": 1})
    );
    assert_eq!(store.metadata().get("nested.b").map(String::as_str), Some("keep"));
}

#[test]
fn extract_root_before_root_replace() {
    let ops = JsonOps::builder()
        .extract("", ExtractDest::metadata("original.root"))
        .unwrap()
        .replace("", JsonValue::static_json(json!({"replaced":true})).unwrap())
        .unwrap()
        .build()
        .unwrap();
    let mut store = MapStore::new();
    let rewrite = ops.apply(br#"{"model":"old","n":1}"#, Some(&mut store)).unwrap();
    assert_eq!(rewrite.output.as_deref(), Some(br#"{"replaced":true}"#.as_ref()));
    assert_eq!(
        store.metadata().get("original.root").map(String::as_str),
        Some(r#"{"model":"old","n":1}"#)
    );
}

#[test]
fn extract_header_allows_trailing_whitespace() {
    let ops = JsonOps::builder()
        .extract("/model", ExtractDest::header("X-Model"))
        .unwrap()
        .build()
        .unwrap();
    let mut store = MapStore::new();
    ops.apply(b"{\"model\":\"premium\"}\n  \t\r\n", Some(&mut store))
        .unwrap();
    assert_eq!(store.request_headers(), &[("X-Model".to_owned(), "premium".to_owned())]);
}
