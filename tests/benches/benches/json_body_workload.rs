// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Shared workload and fixtures for `json_body` benchmarks.
//!
//! Fixtures mimic an OpenAI-style chat completion request body: `model`,
//! `messages`, `temperature`, `max_tokens`, and `stream`.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::items_after_statements,
    clippy::let_underscore_must_use,
    clippy::missing_docs_in_private_items,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used,
    reason = "benchmarks"
)]

use std::sync::LazyLock;

use praxis_filter::json_ops::{ExtractDest, JsonOps, JsonValue};
use serde_json::json;

/// Default `json_body` max body size (10 MiB).
pub(crate) const TARGET_10_MIB: usize = 10_485_760;

/// Benchmark body size labels and targets.
pub(crate) const BODY_SIZES: &[(&str, usize)] = &[
    ("10kiB", 10 * 1024),
    ("256kiB", 256 * 1024),
    ("512kiB", 512 * 1024),
    ("10miB", TARGET_10_MIB),
];

/// Where op-target keys sit in generated chat completion bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BodyLayout {
    /// `secret` appears before the `messages` array (early in the document).
    Prefix,
    /// `secret` appears after `messages` and sampling params (late in the document).
    Spread,
}

static REQUEST_OPS: LazyLock<JsonOps> = LazyLock::new(|| {
    JsonOps::builder()
        .extract("/model", ExtractDest::metadata("original.model"))
        .expect("bench extract")
        .replace(
            "/model",
            JsonValue::static_json(json!("forced-model")).expect("static model"),
        )
        .expect("bench replace")
        .add("/tenant", JsonValue::static_json(json!("acme")).expect("static tenant"))
        .expect("bench add tenant")
        .add("/original_model", JsonValue::metadata("original.model"))
        .expect("bench add original_model")
        .remove("/secret")
        .expect("bench remove")
        .build()
        .expect("bench ops must compile")
});

static BODIES_PREFIX_10_KIB: LazyLock<Vec<u8>> = LazyLock::new(|| make_json_body(BodyLayout::Prefix, 10 * 1024));
static BODIES_PREFIX_256_KIB: LazyLock<Vec<u8>> = LazyLock::new(|| make_json_body(BodyLayout::Prefix, 256 * 1024));
static BODIES_PREFIX_512_KIB: LazyLock<Vec<u8>> = LazyLock::new(|| make_json_body(BodyLayout::Prefix, 512 * 1024));
static BODIES_PREFIX_10_MIB: LazyLock<Vec<u8>> = LazyLock::new(|| make_json_body(BodyLayout::Prefix, TARGET_10_MIB));

static BODIES_SPREAD_10_KIB: LazyLock<Vec<u8>> = LazyLock::new(|| make_json_body(BodyLayout::Spread, 10 * 1024));
static BODIES_SPREAD_256_KIB: LazyLock<Vec<u8>> = LazyLock::new(|| make_json_body(BodyLayout::Spread, 256 * 1024));
static BODIES_SPREAD_512_KIB: LazyLock<Vec<u8>> = LazyLock::new(|| make_json_body(BodyLayout::Spread, 512 * 1024));
static BODIES_SPREAD_10_MIB: LazyLock<Vec<u8>> = LazyLock::new(|| make_json_body(BodyLayout::Spread, TARGET_10_MIB));

/// Compiled tokenizer ops for the example workload.
pub(crate) fn request_ops() -> &'static JsonOps {
    &REQUEST_OPS
}

/// Pre-generated body for a layout and size label.
pub(crate) fn body_for_layout(layout: BodyLayout, label: &str) -> &'static [u8] {
    match (layout, label) {
        (BodyLayout::Prefix, "10kiB") => BODIES_PREFIX_10_KIB.as_slice(),
        (BodyLayout::Prefix, "256kiB") => BODIES_PREFIX_256_KIB.as_slice(),
        (BodyLayout::Prefix, "512kiB") => BODIES_PREFIX_512_KIB.as_slice(),
        (BodyLayout::Prefix, "10miB") => BODIES_PREFIX_10_MIB.as_slice(),
        (BodyLayout::Spread, "10kiB") => BODIES_SPREAD_10_KIB.as_slice(),
        (BodyLayout::Spread, "256kiB") => BODIES_SPREAD_256_KIB.as_slice(),
        (BodyLayout::Spread, "512kiB") => BODIES_SPREAD_512_KIB.as_slice(),
        (BodyLayout::Spread, "10miB") => BODIES_SPREAD_10_MIB.as_slice(),
        (_, other) => panic!("unknown body size label: {other}"),
    }
}

/// Tokenizer path used by Criterion and heap benches.
pub(crate) fn tokenizer_apply(body: &[u8]) -> Vec<u8> {
    request_ops()
        .apply(body, None)
        .expect("tokenizer apply must succeed on fixtures")
        .output
        .expect("mutating bench ops emit a body")
}

/// Build a chat completion request body of at least `target_bytes`.
pub(crate) fn make_json_body(layout: BodyLayout, target_bytes: usize) -> Vec<u8> {
    let mut body = String::with_capacity(target_bytes + 256);
    body.push('{');
    let mut first = true;

    emit_member(&mut body, &mut first, r#""model":"old""#);
    if layout == BodyLayout::Prefix {
        emit_member(&mut body, &mut first, r#""secret":"s3cret""#);
    }

    emit_member(&mut body, &mut first, r#""messages":["#);
    let mut first_msg = true;
    let mut turn = 0_usize;
    let trailer_len = chat_trailer_len(layout);
    while body.len() + trailer_len + 1 < target_bytes {
        append_message_turn(&mut body, turn, &mut first_msg);
        turn += 1;
    }
    pad_messages_to_target(&mut body, &mut first_msg, target_bytes, trailer_len);
    body.push(']');

    emit_chat_trailer(&mut body, &mut first);
    if layout == BodyLayout::Spread {
        emit_member(&mut body, &mut first, r#""secret":"s3cret""#);
    }
    body.push('}');

    assert!(
        body.len() >= target_bytes,
        "chat fixture must reach target size: got {} want {target_bytes}",
        body.len()
    );
    assert!(
        body.contains(r#""messages":["#) && body.contains(r#""role":"#),
        "fixture must look like chat completion JSON"
    );
    body.into_bytes()
}

/// Bytes for sampling params, optional late `secret`, and closing `}`.
fn chat_trailer_len(layout: BodyLayout) -> usize {
    let mut len = 1 + r#","temperature":0.7,"max_tokens":4096,"stream":false"#.len();
    if layout == BodyLayout::Spread {
        len += r#","secret":"s3cret""#.len();
    }
    len + 1
}

fn pad_messages_to_target(body: &mut String, first_msg: &mut bool, target_bytes: usize, trailer_len: usize) {
    let closing = 1;
    let deficit = target_bytes.saturating_sub(body.len() + trailer_len + closing);
    if deficit <= 2 {
        return;
    }
    // {"role":"user","content":"..."} with ASCII padding (no JSON escapes needed).
    const OVERHEAD: usize = r#"{"role":"user","content":""}"#.len();
    if deficit <= OVERHEAD {
        return;
    }
    let pad_len = deficit - OVERHEAD;
    if !*first_msg {
        body.push(',');
    }
    *first_msg = false;
    body.push_str(r#"{"role":"user","content":""#);
    body.push_str(&"x".repeat(pad_len));
    body.push_str(r#""}"#);
}

fn emit_chat_trailer(body: &mut String, first: &mut bool) {
    emit_member(body, first, r#""temperature":0.7"#);
    emit_member(body, first, r#""max_tokens":4096"#);
    emit_member(body, first, r#""stream":false"#);
}

fn append_message_turn(body: &mut String, turn: usize, first_msg: &mut bool) {
    if !*first_msg {
        body.push(',');
    }
    *first_msg = false;

    let role = match turn % 3 {
        0 => "system",
        1 => "user",
        _ => "assistant",
    };
    let content = if turn == 0 {
        "You are a helpful assistant.".to_owned()
    } else {
        format!("bench-turn-{turn}: {}", "x".repeat(48 + (turn % 16)))
    };
    let _ = std::fmt::Write::write_fmt(body, format_args!(r#"{{"role":"{role}","content":"{content}"}}"#));
}

fn emit_member(body: &mut String, first: &mut bool, member: &str) {
    if !*first {
        body.push(',');
    }
    *first = false;
    body.push_str(member);
}
