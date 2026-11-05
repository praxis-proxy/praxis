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

#[test]
fn large_rewrites_preserve_unaffected_spans_and_duplicate_semantics() {
    let padding = "x".repeat(1_048_576);
    let input =
        format!(r#"{{"a/b":1,"padding":{{"text":"{padding}", "values":[1, 2, 3]}},"a\u002fb":2,"tail":[10,20,30]}}"#);
    let replacement = rewrite_str(&input, &[resolved(OpKind::Replace, "/a~1b", Some("9"))]).unwrap();
    assert_eq!(
        replacement,
        format!(r#"{{"a/b":9,"padding":{{"text":"{padding}", "values":[1, 2, 3]}},"a\u002fb":9,"tail":[10,20,30]}}"#)
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&replacement).unwrap()["a/b"],
        9
    );
    let removed = rewrite_str(&input, &[resolved(OpKind::Remove, "/a~1b", None)]).unwrap();
    assert_eq!(
        removed,
        format!(r#"{{"padding":{{"text":"{padding}", "values":[1, 2, 3]}},"tail":[10,20,30]}}"#)
    );
    let added = rewrite_str(&input, &[resolved(OpKind::Add, "/tail/1", Some("15"))]).unwrap();
    assert!(added.ends_with(r#""tail":[10,15,20,30]}"#));
    assert!(added.contains(&format!(r#""padding":{{"text":"{padding}", "values":[1, 2, 3]}}"#)));
    let missing = rewrite_str(&input, &[resolved(OpKind::Replace, "/missing", Some("0"))]).unwrap();
    assert_eq!(missing, input, "unchanged value spans must be copied verbatim");
    assert_duplicate_extraction_uses_last(&input);
}

/// Duplicate escaped and literal keys use the final value for extraction.
fn assert_duplicate_extraction_uses_last(input: &str) {
    let ops = JsonOps::builder()
        .extract("/a~1b", ExtractDest::metadata("chosen"))
        .unwrap()
        .build()
        .unwrap();
    let mut store = MapStore::new();
    let outcome = ops.apply(input.as_bytes(), Some(&mut store)).unwrap();
    assert!(outcome.output.is_none());
    assert_eq!(
        store.get_metadata("chosen"),
        Some("2"),
        "extraction agrees with serde last-wins behavior"
    );
}

#[test]
fn large_array_edits_preserve_values_before_and_after_each_position() {
    let items: Vec<_> = (0..8192)
        .map(|index| json!({"id": index, "padding": "x".repeat(128)}))
        .collect();
    let document = json!({"items": items, "tail": "unchanged"});
    let input = serde_json::to_string(&document).unwrap();
    for index in [0, 4096, 8191] {
        for (kind, value) in [
            (OpKind::Remove, None),
            (OpKind::Replace, Some(r#"{"changed":true}"#)),
            (OpKind::Add, Some(r#"{"changed":true}"#)),
        ] {
            let mut expected = document.clone();
            let array = expected["items"].as_array_mut().unwrap();
            match kind {
                OpKind::Remove => {
                    array.remove(index);
                },
                OpKind::Replace => array[index] = json!({"changed": true}),
                OpKind::Add => array.insert(index, json!({"changed": true})),
                OpKind::Extract => unreachable!(),
            }
            let output = rewrite_str(&input, &[resolved(kind, &format!("/items/{index}"), value)]).unwrap();
            assert_eq!(serde_json::from_str::<serde_json::Value>(&output).unwrap(), expected);
        }
    }
}

#[test]
fn mixed_container_depth_boundary_applies_to_skipped_and_edited_paths() {
    for depth in [127, 128, 129] {
        let mut input = String::from("1");
        let mut pointer = String::new();
        for index in 1..depth {
            if index % 2 == 0 {
                input = format!("[{input}]");
                pointer = format!("/0{pointer}");
            } else {
                input = format!(r#"{{"n":{input}}}"#);
                pointer = format!("/n{pointer}");
            }
        }
        input = format!(r#"{{"padding":"{}","nested":{input}}}"#, "x".repeat(1_048_576));
        pointer = format!("/nested{pointer}");
        for op in [
            resolved(OpKind::Replace, "/missing", Some("2")),
            resolved(OpKind::Replace, &pointer, Some("2")),
        ] {
            let result = rewrite_str(&input, &[op]);
            if depth <= 128 {
                let output = result.unwrap();
                assert!(output.len() <= input.len());
            } else {
                assert_eq!(result.unwrap_err(), JsonError::Depth, "depth {depth}");
            }
        }
    }
}

#[test]
fn generated_json_rewrites_match_reference_and_reject_truncated_tails() {
    for width in [0, 1, 15, 16, 17, 127, 1024, 65_536] {
        for original in ["plain", "café", "quote\"slash\\", "line\nend"] {
            let document = json!({"before": "x".repeat(width), "target": original, "array": [true, null, 17]});
            let input = serde_json::to_vec(&document).unwrap();
            let ops = JsonOps::builder()
                .extract("/target", ExtractDest::metadata("old"))
                .unwrap()
                .replace("/target", JsonValue::static_json(json!("new")).unwrap())
                .unwrap()
                .build()
                .unwrap();
            let mut store = MapStore::new();
            let outcome = ops.apply(&input, Some(&mut store)).unwrap();
            let mut expected = document.clone();
            expected["target"] = json!("new");
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&outcome.output.unwrap()).unwrap(),
                expected
            );
            assert_eq!(store.get_metadata("old"), Some(original));
            assert_truncated_tail_preserves_metadata(&ops, &input);
        }
    }
}

/// A truncated document must leave existing and newly requested captures intact.
fn assert_truncated_tail_preserves_metadata(ops: &JsonOps, input: &[u8]) {
    let mut damaged = input.to_vec();
    damaged.pop();
    let mut untouched = MapStore::new();
    untouched.set_metadata("trusted".to_owned(), "keep".to_owned());
    assert!(matches!(
        ops.apply(&damaged, Some(&mut untouched)),
        Err(JsonError::InvalidJson)
    ));
    assert_eq!(untouched.get_metadata("trusted"), Some("keep"));
    assert_eq!(
        untouched.get_metadata("old"),
        None,
        "failed walk must not commit captures"
    );
}

#[test]
fn invalid_encoding_in_skipped_values_cannot_commit_extraction_or_rewrite() {
    let ops = JsonOps::builder()
        .extract("/model", ExtractDest::header("X-Model"))
        .unwrap()
        .replace("/model", JsonValue::static_json(json!("rewritten")).unwrap())
        .unwrap()
        .build()
        .unwrap();
    let cases: &[&[u8]] = &[b"{\"model\":\"trusted\",\"unused\":\"\xff\"}"];
    for input in cases {
        assert!(
            serde_json::from_slice::<serde_json::Value>(input).is_err(),
            "reference must reject the input"
        );
        let mut store = MapStore::new();
        store.set_metadata("trusted".to_owned(), "keep".to_owned());
        assert!(
            matches!(ops.apply(input, Some(&mut store)), Err(JsonError::InvalidJson)),
            "input {input:?}"
        );
        assert!(
            store.request_headers().is_empty(),
            "invalid document must not promote metadata"
        );
        assert_eq!(store.get_metadata("trusted"), Some("keep"));
    }
}

#[test]
fn lexical_mutations_of_large_documents_match_shared_json_grammar() {
    let padding = "x".repeat(1_048_576);
    let ops = JsonOps::builder()
        .extract("/target", ExtractDest::metadata("chosen"))
        .unwrap()
        .replace("/target", JsonValue::static_json(json!("new")).unwrap())
        .unwrap()
        .build()
        .unwrap();
    assert_valid_large_lexical_tokens(&ops, &padding);
    assert_invalid_large_lexical_tokens(&ops, &padding);
    let bom = b"\xef\xbb\xbf{\"target\":\"old\"}";
    serde_json::from_slice::<serde_json::Value>(bom).expect_err("reference rejects a leading UTF-8 BOM");
    assert!(
        ops.apply(bom, None).unwrap().output.is_some(),
        "the walker deliberately accepts a leading UTF-8 BOM"
    );
}

/// Compare valid large-document token rewrites with a serde reference.
fn assert_valid_large_lexical_tokens(ops: &JsonOps, padding: &str) {
    for token in [
        "-123456789.0123456789e+25",
        "0.00000000000000000001",
        r#""escaped\\\\quotes\\\"and\\u00e9""#,
    ] {
        let input = format!(r#"{{"target":"old","padding":"{padding}","value":{token}}}"#);
        let mut reference: serde_json::Value = serde_json::from_str(&input).unwrap();
        reference["target"] = json!("new");
        let mut store = MapStore::new();
        let output = ops.apply(input.as_bytes(), Some(&mut store)).unwrap().output.unwrap();
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&output).unwrap(), reference);
        assert_eq!(store.get_metadata("chosen"), Some("old"));
    }
}

/// Invalid late tokens must not commit an earlier field capture.
fn assert_invalid_large_lexical_tokens(ops: &JsonOps, padding: &str) {
    for token in [
        "01",
        "1e+",
        "1.",
        r#""bad\q""#,
        r#""bad\u00xz""#,
        "\"unfinished",
        "[true,]",
        "null false",
    ] {
        let input = format!(r#"{{"target":"old","padding":"{padding}","value":{token}}}"#);
        assert!(
            serde_json::from_str::<serde_json::Value>(&input).is_err(),
            "reference unexpectedly accepted {token:?}"
        );
        let mut store = MapStore::new();
        assert!(
            matches!(
                ops.apply(input.as_bytes(), Some(&mut store)),
                Err(JsonError::InvalidJson)
            ),
            "token {token:?}"
        );
        assert_eq!(store.get_metadata("chosen"), None);
    }
}

/// One deterministic JSON document and the operation selected for it.
struct SeededJsonCase {
    /// Seed identifying the deterministic corpus.
    seed: u64,
    /// Index of this case within the seed.
    index: usize,
    /// Complete serialized JSON document.
    input: String,
    /// Original final value of the selected route field.
    selected: &'static str,
    /// Whether an earlier duplicate route member is present.
    duplicate: bool,
    /// One of the four selected rewrite operations.
    kind: usize,
}

/// Deterministically choose a nested shape without affecting the other draws.
fn seeded_json_shape(state: &mut u64) -> serde_json::Value {
    match next_json_seed(state) % 4 {
        0 => json!([]),
        1 => json!([true, null, 17]),
        2 => json!([{"inside": ["café", false]}, 3]),
        3 => json!({"array": [[1, 2], {"route": "decoy"}]}),
        _ => unreachable!(),
    }
}

/// Choose a literal or Unicode-escaped spelling for the same route key.
fn seeded_route_key(state: &mut u64) -> &'static str {
    if next_json_seed(state) & 1 == 0 {
        "route"
    } else {
        r"\u0072oute"
    }
}

/// Produce the same widths, keys, duplicates and operation draws per seed.
fn seeded_json_case(state: &mut u64, seed: u64, index: usize) -> SeededJsonCase {
    let widths = [0_usize, 1, 15, 16, 17, 63, 255, 1024, 4096, 65_536];
    let values = ["alpha", "café", "quote\"slash\\", "snowman ☃", "emoji 🦀"];
    let width = if index == 0 {
        1_048_576
    } else {
        widths[usize::try_from(next_json_seed(state) % widths.len() as u64).unwrap()]
    };
    let selected = values[usize::try_from(next_json_seed(state) % values.len() as u64).unwrap()];
    let key = seeded_route_key(state);
    let duplicate = next_json_seed(state) & 1 == 0;
    let earlier = if duplicate { r#""route":"first","# } else { "" };
    let shape = seeded_json_shape(state);
    let input = format!(
        r#"{{{earlier}"padding":"{}","nested":{{"route":"decoy","value":42}},"shape":{shape},"n":42,"{key}":{}}}"#,
        "x".repeat(width),
        serde_json::to_string(selected).unwrap()
    );
    let kind = usize::try_from(next_json_seed(state) % 4).unwrap();
    SeededJsonCase {
        seed,
        index,
        input,
        selected,
        duplicate,
        kind,
    }
}

/// Apply the same mutation to the DOM oracle and to the compiled tokenizer ops.
fn seeded_json_ops(kind: usize, reference: &mut serde_json::Value) -> JsonOps {
    let builder = JsonOps::builder()
        .extract("/route", ExtractDest::metadata("chosen"))
        .unwrap();
    let operation = match kind {
        0 => {
            reference["route"] = json!("rewritten");
            builder.replace("/route", JsonValue::static_json(json!("rewritten")).unwrap())
        },
        1 => {
            reference["nested"]["value"] = json!("rewritten");
            builder.replace("/nested/value", JsonValue::static_json(json!("rewritten")).unwrap())
        },
        2 => {
            assert_eq!(
                reference["nested"].as_object_mut().unwrap().remove("value"),
                Some(json!(42))
            );
            builder.remove("/nested/value")
        },
        3 => {
            reference["nested"]["new"] = json!([1, "added"]);
            builder.add("/nested/new", JsonValue::static_json(json!([1, "added"])).unwrap())
        },
        _ => unreachable!(),
    };
    operation.unwrap().build().unwrap()
}

/// Check the complete valid rewrite, duplicate semantics and extracted value.
fn assert_seeded_valid(case: &SeededJsonCase) -> JsonOps {
    let (seed, index, kind) = (case.seed, case.index, case.kind);
    let mut reference: serde_json::Value = serde_json::from_str(&case.input).unwrap();
    assert_eq!(
        reference["route"], case.selected,
        "last duplicate seed={seed:#x} case={index}"
    );
    let ops = seeded_json_ops(kind, &mut reference);
    let mut store = MapStore::new();
    let output = ops
        .apply(case.input.as_bytes(), Some(&mut store))
        .unwrap_or_else(|err| panic!("valid seed={seed:#x} case={index} kind={kind}: {err}"));
    let actual: serde_json::Value = serde_json::from_slice(&output.output.unwrap()).unwrap();
    assert!(
        actual == reference,
        "semantic rewrite seed={seed:#x} case={index} kind={kind}"
    );
    assert_eq!(
        store.get_metadata("chosen"),
        Some(case.selected),
        "capture seed={seed:#x} case={index} kind={kind}"
    );
    ops
}

/// Stable byte offsets for each invalid mutation of a generated document.
struct SeededOffsets {
    /// Start of the string value used for escape and encoding mutations.
    padding: usize,
    /// Cut point for the truncated-document case.
    truncated: usize,
    /// Start of the integer mutated to an invalid leading-zero number.
    number: usize,
}

/// Choose the original per-case truncation draw after its valid rewrite.
fn seeded_offsets(case: &SeededJsonCase, state: &mut u64) -> SeededOffsets {
    SeededOffsets {
        padding: case.input.find(r#""padding":""#).unwrap() + r#""padding":""#.len(),
        truncated: 1 + usize::try_from(next_json_seed(state) % u64::try_from(case.input.len() - 1).unwrap()).unwrap(),
        number: case.input.find(r#""n":42"#).unwrap() + r#""n":"#.len(),
    }
}

/// Construct each of the six original truncation, suffix and lexical faults.
fn seeded_damage(case: &SeededJsonCase, offsets: &SeededOffsets, mutation: usize) -> Vec<u8> {
    let mut damaged = case.input.as_bytes().to_vec();
    match mutation {
        0 => damaged.truncate(offsets.truncated),
        1 => damaged.extend_from_slice(b"{}"),
        2 => {
            damaged.insert(offsets.padding, b'q');
            damaged.insert(offsets.padding, b'\\');
        },
        3 => damaged.insert(offsets.padding, 0),
        4 => damaged.insert(offsets.padding, 0xFF),
        5 => {
            damaged[offsets.number] = b'0';
            damaged.insert(offsets.number + 1, b'1');
        },
        _ => unreachable!(),
    }
    damaged
}

/// Compare every damaged input with serde and ensure no partial capture leaks.
fn assert_seeded_invalid(case: &SeededJsonCase, ops: &JsonOps, state: &mut u64) {
    let (seed, index, kind) = (case.seed, case.index, case.kind);
    let offsets = seeded_offsets(case, state);
    for mutation in 0..6 {
        let damaged = seeded_damage(case, &offsets, mutation);
        assert!(
            serde_json::from_slice::<serde_json::Value>(&damaged).is_err(),
            "reference accepted seed={seed:#x} case={index} mutation={mutation}"
        );
        let mut untouched = MapStore::new();
        untouched.set_metadata("trusted".to_owned(), "keep".to_owned());
        let result = ops.apply(&damaged, Some(&mut untouched));
        assert!(
            matches!(result, Err(JsonError::InvalidJson)),
            "invalid seed={seed:#x} case={index} kind={kind} mutation={mutation}"
        );
        assert_eq!(
            untouched.get_metadata("trusted"),
            Some("keep"),
            "seed={seed:#x} case={index} mutation={mutation}"
        );
        assert_eq!(
            untouched.get_metadata("chosen"),
            None,
            "partial capture seed={seed:#x} case={index} mutation={mutation}"
        );
    }
}

#[test]
fn seeded_json_mutations_match_reference_without_partial_captures() {
    let seeds = [0xA11C_E001_u64, 0x5EED_2026, 0xBADC_0FFE, 0xF00D_3131];
    let mut rewrites_seen = [false; 4];
    let mut duplicates_seen = [false; 2];
    for seed in seeds {
        let mut state = seed;
        for index in 0..24 {
            let case = seeded_json_case(&mut state, seed, index);
            rewrites_seen[case.kind] = true;
            duplicates_seen[usize::from(case.duplicate)] = true;
            let ops = assert_seeded_valid(&case);
            assert_seeded_invalid(&case, &ops, &mut state);
        }
    }
    assert!(rewrites_seen.into_iter().all(|seen| seen));
    assert!(duplicates_seen.into_iter().all(|seen| seen));
}

/// Deterministically advance the bounded JSON mutation corpus.
fn next_json_seed(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state >> 32
}
