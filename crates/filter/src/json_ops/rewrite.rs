// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! One-pass JSON Pointer rewriter: tokenize, copy unmatched spans, splice ops.
//!
//! Does not build a `serde_json::Value` tree. Injected literals are
//! pre-serialized JSON bytes. Extract captures run in the same walk as
//! mutating splices; metadata payloads resolve lazily at each splice site.
//! Subtrees with no remaining op are copied as raw spans (`skip_value` + memcpy).

use std::{borrow::Cow, collections::HashMap};

use bytes::Bytes;
use smallvec::SmallVec;

use super::{
    error::JsonError,
    index::{PathToken, path_eq_tokens},
    ops::{CompiledOp, CompiledOpSet, ExtractDest, OpKind, ValueSource},
    skip::{bump_depth, expect_byte, next_byte, skip_bom, skip_string_with_meta, skip_value, skip_ws},
    store::JsonOpStore,
};
use crate::builtins::http::{payload_processing::MAX_DYNAMIC_VALUE_LEN, value_safety::contains_control_chars};

/// Extra bytes reserved beyond input length and the compile-time growth hint.
const OUTPUT_GROWTH_SLACK: usize = 64;

/// An operation with values already resolved from context (unit tests).
#[cfg(test)]
#[derive(Clone, Debug)]
pub(super) struct ResolvedOp {
    /// Decoded pointer tokens (empty = root).
    pub tokens: Vec<String>,
    /// Operation kind.
    pub kind: OpKind,
    /// Serialized JSON to inject; `None` for remove.
    pub payload: Option<Bytes>,
}

/// Result of a unified document walk.
#[derive(Clone, Debug)]
pub(super) struct RewriteOutcome {
    /// Rewritten bytes; `None` when `CompiledOpSet::extract_only`.
    pub output: Option<Vec<u8>>,
}

// -----------------------------------------------------------------------------
// Session
// -----------------------------------------------------------------------------

/// Per-request capture and lazy resolution state.
struct RewriteSession {
    /// Metadata captured this walk or preloaded from context.
    scratch_metadata: HashMap<String, String>,
    /// Structured values preloaded from context for injection.
    scratch_structured: HashMap<(String, String), serde_json::Value>,
    /// Raw JSON spans captured for structured metadata extract.
    capture_structured: HashMap<(String, String), Bytes>,
    /// Header names and promoted text captured this walk.
    capture_headers: HashMap<String, String>,
    /// Cached serialized payloads per op index (prefilled for `ValueSource::Static`).
    resolved: Vec<Option<Bytes>>,
    /// JSON Pointer tokens for the value currently being walked.
    path: SmallVec<[PathToken; 8]>,
}

impl RewriteSession {
    /// Allocate scratch maps and cache static payloads for this walk.
    fn new(op_set: &CompiledOpSet) -> Self {
        let mut resolved = vec![None; op_set.ops.len()];
        for (idx, op) in op_set.ops.iter().enumerate() {
            if let Some(ValueSource::Static(bytes)) = &op.source
                && let Some(slot) = resolved.get_mut(idx)
            {
                *slot = Some(bytes.clone());
            }
        }
        Self {
            scratch_metadata: HashMap::new(),
            scratch_structured: HashMap::new(),
            capture_structured: HashMap::new(),
            capture_headers: HashMap::new(),
            resolved,
            path: SmallVec::new(),
        }
    }

    /// Write scratch captures into the op store.
    fn flush_to_store(&self, store: &mut dyn JsonOpStore) {
        for (key, text) in &self.scratch_metadata {
            store.set_metadata(key.clone(), text.clone());
        }
        for ((namespace, key), bytes) in &self.capture_structured {
            if let Ok(value) = serde_json::from_slice(bytes) {
                store.set_structured(namespace, key, value);
            }
        }
        for (name, text) in &self.capture_headers {
            if is_safe_header_promotion(text, name) {
                store.push_request_header(name.clone(), text.clone());
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Entry
// -----------------------------------------------------------------------------

/// Reserve output bytes from input size and compile-time growth hint.
pub(super) fn rewrite_output_capacity(input_len: usize, growth_hint: usize) -> usize {
    if growth_hint == 0 {
        input_len
    } else {
        input_len
            .saturating_add(growth_hint)
            .saturating_add(OUTPUT_GROWTH_SLACK)
    }
}

/// Walk `input` once, capturing extracts and optionally rewriting mutating ops.
///
/// Extract-only and mutating walks both require a single JSON value; only
/// trailing whitespace may follow the document. Non-whitespace trailing content
/// returns [`JsonError::InvalidJson`] so extract promotion cannot disagree with
/// what a strict backend would parse.
///
/// # Errors
///
/// Returns [`JsonError`] when the input is not valid JSON before the walk
/// completes or nesting exceeds [`super::error::MAX_JSON_DEPTH`].
pub(super) fn rewrite_document(
    input: &[u8],
    op_set: &CompiledOpSet,
    store: Option<&mut dyn JsonOpStore>,
) -> Result<RewriteOutcome, JsonError> {
    let mut session = RewriteSession::new(op_set);
    if let Some(store) = store.as_deref() {
        preload_context_sources(op_set, store, &mut session);
    }

    let mut i = skip_bom(input);
    skip_ws(input, &mut i);
    if i >= input.len() {
        return Err(JsonError::InvalidJson);
    }

    let emit = !op_set.extract_only;
    if let Some(root) = root_replace(op_set, &mut session) {
        consume_value_for_mutate(input, &mut i, 0, op_set, &mut session)?;
        skip_ws(input, &mut i);
        if i != input.len() {
            return Err(JsonError::InvalidJson);
        }
        return Ok(finish_document(&session, store, emit.then(|| root.to_vec())));
    }

    let mut out = emit.then(|| Vec::with_capacity(rewrite_output_capacity(input.len(), op_set.growth_hint)));
    rewrite_value(input, &mut i, op_set, out.as_mut(), 0, &mut session)?;

    skip_ws(input, &mut i);
    if i != input.len() {
        return Err(JsonError::InvalidJson);
    }

    Ok(finish_document(&session, store, out))
}

/// Flush captures and wrap the optional output buffer.
fn finish_document(
    session: &RewriteSession,
    store: Option<&mut dyn JsonOpStore>,
    output: Option<Vec<u8>>,
) -> RewriteOutcome {
    if let Some(store) = store {
        session.flush_to_store(store);
    }
    RewriteOutcome { output }
}

/// Rewrite `input` using pre-resolved ops (unit tests).
#[cfg(test)]
pub(super) fn rewrite(input: &[u8], ops: &[ResolvedOp]) -> Result<Vec<u8>, JsonError> {
    let compiled = ops
        .iter()
        .map(|op| {
            let encoded_last_token = op.tokens.last().map(|t| super::skip::encode_json_string(t));
            CompiledOp {
                pointer: String::new(),
                tokens: op.tokens.clone(),
                kind: op.kind,
                source: op.payload.as_ref().map(|bytes| ValueSource::Static(bytes.clone())),
                dest: None,
                encoded_last_token,
            }
        })
        .collect::<Vec<_>>();
    let op_set = CompiledOpSet::finalize(compiled);
    rewrite_document(input, &op_set, None).map(|outcome| outcome.output.unwrap_or_default())
}

// -----------------------------------------------------------------------------
// Capture + lazy resolve
// -----------------------------------------------------------------------------

/// Decode a captured JSON span for `filter_metadata` (strings unescaped).
fn metadata_text(json: &[u8]) -> Option<String> {
    if json.first() == Some(&b'"') {
        serde_json::from_slice(json).ok()
    } else {
        String::from_utf8(json.to_vec()).ok()
    }
}

/// Reject header promotions that exceed the length ceiling or contain controls.
fn is_safe_header_promotion(text: &str, header: &str) -> bool {
    if text.len() > MAX_DYNAMIC_VALUE_LEN {
        tracing::warn!(
            header = %header,
            len = text.len(),
            max = MAX_DYNAMIC_VALUE_LEN,
            "skipping header promotion: value exceeds maximum length"
        );
        return false;
    }
    if contains_control_chars(text) {
        tracing::warn!(
            header = %header,
            "skipping header promotion: value contains control characters"
        );
        return false;
    }
    true
}

/// Capture an extract at `session.path` from `input[start..end]`.
///
/// Duplicate object keys: extract keeps the last match by overwriting.
fn store_capture(input: &[u8], start: usize, end: usize, op_set: &CompiledOpSet, session: &mut RewriteSession) {
    if !op_set.index.extract_branch_at(&session.path) {
        return;
    }
    let Some(op_idx) = op_set.index.extract_at(&session.path) else {
        return;
    };
    let Some(op) = op_at(&op_set.ops, op_idx) else {
        return;
    };
    if let (Some(json), Some(dest)) = (input.get(start..end), op.dest.as_ref()) {
        write_capture_dest(json, dest, session);
    }
}

/// Write one captured JSON span into the matching scratch map.
fn write_capture_dest(json: &[u8], dest: &ExtractDest, session: &mut RewriteSession) {
    match dest {
        ExtractDest::Metadata(key) => {
            if let Some(text) = metadata_text(json) {
                session.scratch_metadata.insert(key.clone(), text);
            }
        },
        ExtractDest::Structured { namespace, key } => {
            session
                .capture_structured
                .insert((namespace.clone(), key.clone()), Bytes::copy_from_slice(json));
        },
        ExtractDest::Header(name) => {
            if let Some(text) = metadata_text(json) {
                session.capture_headers.insert(name.clone(), text);
            }
        },
    }
}

/// Advance past one JSON value during remove/replace, capturing extracts.
///
/// Descendant extracts under a removed/replaced parent require a full walk;
/// otherwise a fast skip plus capture at exactly `session.path` is enough.
fn consume_value_for_mutate(
    input: &[u8],
    i: &mut usize,
    depth: u32,
    op_set: &CompiledOpSet,
    session: &mut RewriteSession,
) -> Result<(), JsonError> {
    if op_set.index.has_descendant_extracts(&session.path) {
        rewrite_value(input, i, op_set, None, depth, session)
    } else {
        let start = *i;
        skip_value(input, i, depth)?;
        store_capture(input, start, *i, op_set, session);
        Ok(())
    }
}

/// Copy one JSON value as a raw span (no per-member tokenize of its interior).
fn copy_span(input: &[u8], i: &mut usize, depth: u32, out: Option<&mut Vec<u8>>) -> Result<(), JsonError> {
    skip_ws(input, i);
    let start = *i;
    skip_value(input, i, depth)?;
    if let Some(out) = out {
        let span = input.get(start..*i).ok_or(JsonError::InvalidJson)?;
        out.extend_from_slice(span);
    }
    Ok(())
}

/// Copy context metadata/structured values into scratch before the walk.
fn preload_context_sources(op_set: &CompiledOpSet, store: &dyn JsonOpStore, session: &mut RewriteSession) {
    for op in &op_set.ops {
        if op.kind == OpKind::Extract {
            continue;
        }
        match &op.source {
            Some(ValueSource::Metadata(key)) => {
                if let Some(text) = store.get_metadata(key) {
                    session.scratch_metadata.insert(key.clone(), text.to_owned());
                }
            },
            Some(ValueSource::Structured { namespace, key }) => {
                if let Some(value) = store.get_structured(namespace, key) {
                    session
                        .scratch_structured
                        .insert((namespace.clone(), key.clone()), value.clone());
                }
            },
            Some(ValueSource::Static(_)) | None => {},
        }
    }
}

/// Resolve a mutating op's payload from cache, static bytes, or session scratch.
fn resolve_payload(op_idx: u32, op: &CompiledOp, session: &mut RewriteSession) -> Option<Bytes> {
    let idx = usize::try_from(op_idx).ok()?;
    if let Some(cached) = session.resolved.get(idx).and_then(|slot| slot.as_ref()) {
        return Some(cached.clone());
    }
    let bytes = match op.source.as_ref()? {
        ValueSource::Static(bytes) => Some(bytes.clone()),
        ValueSource::Metadata(key) => session
            .scratch_metadata
            .get(key)
            .and_then(|text| serde_json::to_vec(text).ok())
            .map(Bytes::from),
        ValueSource::Structured { namespace, key } => session
            .scratch_structured
            .get(&(namespace.clone(), key.clone()))
            .and_then(|value| serde_json::to_vec(value).ok())
            .map(Bytes::from),
    };
    if let Some(payload) = &bytes
        && let Some(slot) = session.resolved.get_mut(idx)
    {
        *slot = Some(payload.clone());
    }
    bytes
}

/// Root-level replace payload, if configured and resolvable.
fn root_replace(op_set: &CompiledOpSet, session: &mut RewriteSession) -> Option<Bytes> {
    op_set
        .ops
        .iter()
        .enumerate()
        .find(|(_, op)| op.tokens.is_empty() && op.kind == OpKind::Replace)
        .and_then(|(idx, op)| {
            let op_idx = u32::try_from(idx).ok()?;
            resolve_payload(op_idx, op, session)
        })
}

/// Compiled op at `idx`, if `idx` fits this platform's `usize`.
fn op_at(ops: &[CompiledOp], idx: u32) -> Option<&CompiledOp> {
    ops.get(usize::try_from(idx).ok()?)
}

/// Emit a resolved add/replace payload, or skip when context is missing.
fn try_emit_payload(
    op_idx: u32,
    op: &CompiledOp,
    out: Option<&mut Vec<u8>>,
    emitted_any: &mut bool,
    session: &mut RewriteSession,
) {
    let Some(payload) = resolve_payload(op_idx, op, session) else {
        return;
    };
    let Some(out) = out else {
        return;
    };
    emit_separator(out, emitted_any);
    out.extend_from_slice(&payload);
}

/// Emit an array `add` at `op_idx` when that op is add and the payload resolves.
fn try_emit_add(
    op_set: &CompiledOpSet,
    op_idx: u32,
    out: Option<&mut Vec<u8>>,
    emitted_any: &mut bool,
    session: &mut RewriteSession,
) {
    let Some(op) = op_at(&op_set.ops, op_idx) else {
        return;
    };
    if op.kind != OpKind::Add {
        return;
    }
    try_emit_payload(op_idx, op, out, emitted_any, session);
}

// -----------------------------------------------------------------------------
// Value walk
// -----------------------------------------------------------------------------

/// Rewrite one JSON value at `session.path`.
#[expect(clippy::too_many_arguments, reason = "walker state is threaded per recursive call")]
fn rewrite_value(
    input: &[u8],
    i: &mut usize,
    op_set: &CompiledOpSet,
    mut out: Option<&mut Vec<u8>>,
    depth: u32,
    session: &mut RewriteSession,
) -> Result<(), JsonError> {
    skip_ws(input, i);
    if !op_set.index.has_descendant_ops(&session.path) {
        let start = *i;
        copy_span(input, i, depth, out.as_deref_mut())?;
        store_capture(input, start, *i, op_set, session);
        return Ok(());
    }
    let start = *i;
    let kind = next_byte(input, *i)?;
    match kind {
        b'{' => rewrite_object(input, i, op_set, out.as_deref_mut(), depth, session)?,
        b'[' => rewrite_array(input, i, op_set, out.as_deref_mut(), depth, session)?,
        _ => {
            *i = start;
            copy_span(input, i, depth, out)?;
            store_capture(input, start, *i, op_set, session);
            return Ok(());
        },
    }
    store_capture(input, start, *i, op_set, session);
    Ok(())
}

/// Rewrite an object, splicing member ops and injecting missing adds at close.
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "object member walk is a linear tokenizer loop"
)]
fn rewrite_object(
    input: &[u8],
    i: &mut usize,
    op_set: &CompiledOpSet,
    mut out: Option<&mut Vec<u8>>,
    depth: u32,
    session: &mut RewriteSession,
) -> Result<(), JsonError> {
    let depth = bump_depth(depth)?;
    expect_byte(input, i, b'{')?;
    if let Some(out) = out.as_mut() {
        out.push(b'{');
    }

    let mut emitted_any = false;
    let mut seen_input_member = false;
    let mut satisfied_add_keys: Vec<&str> = Vec::new();

    loop {
        skip_ws(input, i);
        if next_byte(input, *i)? == b'}' {
            *i += 1;
            break;
        }
        if seen_input_member {
            expect_byte(input, i, b',')?;
            skip_ws(input, i);
            if next_byte(input, *i)? == b'}' {
                return Err(JsonError::InvalidJson);
            }
        }
        seen_input_member = true;

        let (key_span, key) = parse_string(input, i)?;
        skip_ws(input, i);
        expect_byte(input, i, b':')?;

        if let Some(op_idx) = op_set.index.mutate_child_key(&session.path, key.as_ref())
            && let Some(op) = op_at(&op_set.ops, op_idx)
        {
            session.path.push(PathToken::Key(key.into_owned()));
            apply_object_mutate(
                input,
                i,
                key_span,
                op_idx,
                op,
                &mut out,
                &mut emitted_any,
                depth,
                op_set,
                session,
            )?;
            if op.kind == OpKind::Add && resolve_payload(op_idx, op, session).is_some() {
                satisfied_add_keys.push(op.tokens.last().map_or("", String::as_str));
            }
            session.path.pop();
            continue;
        }

        if let Some(out) = out.as_mut() {
            emit_separator(out, &mut emitted_any);
            out.extend_from_slice(key_span);
            out.push(b':');
        }
        if op_set.index.child_needs_rewrite(&session.path, key.as_ref()) {
            session.path.push(PathToken::Key(key.into_owned()));
            rewrite_value(input, i, op_set, out.as_deref_mut(), depth, session)?;
            session.path.pop();
        } else {
            copy_span(input, i, depth, out.as_deref_mut())?;
        }
    }

    inject_object_adds(
        op_set,
        &satisfied_add_keys,
        out.as_deref_mut(),
        &mut emitted_any,
        session,
    );
    if let Some(out) = out.as_mut() {
        out.push(b'}');
    }
    Ok(())
}

/// Apply a mutating op to an existing object member. Path already includes the key.
#[expect(clippy::too_many_arguments, reason = "mutate splice needs walk + emit state")]
fn apply_object_mutate(
    input: &[u8],
    i: &mut usize,
    key_span: &[u8],
    op_idx: u32,
    op: &CompiledOp,
    out: &mut Option<&mut Vec<u8>>,
    emitted_any: &mut bool,
    depth: u32,
    op_set: &CompiledOpSet,
    session: &mut RewriteSession,
) -> Result<(), JsonError> {
    match op.kind {
        OpKind::Remove => consume_value_for_mutate(input, i, depth, op_set, session),
        OpKind::Replace | OpKind::Add => {
            skip_ws(input, i);
            let value_start = *i;
            consume_value_for_mutate(input, i, depth, op_set, session)?;
            if let Some(out_buf) = out.as_mut() {
                if let Some(payload) = resolve_payload(op_idx, op, session) {
                    emit_separator(out_buf, emitted_any);
                    out_buf.extend_from_slice(key_span);
                    out_buf.push(b':');
                    out_buf.extend_from_slice(&payload);
                } else {
                    emit_original_member(input, value_start, *i, key_span, out_buf, emitted_any)?;
                }
            }
            Ok(())
        },
        OpKind::Extract => Ok(()),
    }
}

/// Emit unsatisfied object `add` ops at `session.path` in config order.
fn inject_object_adds(
    op_set: &CompiledOpSet,
    satisfied: &[&str],
    out: Option<&mut Vec<u8>>,
    emitted_any: &mut bool,
    session: &mut RewriteSession,
) {
    let Some(out) = out else {
        return;
    };
    for (idx, op) in op_set.ops.iter().enumerate() {
        if op.kind != OpKind::Add || !parent_is(op, &session.path) {
            continue;
        }
        let Some(last) = op.tokens.last() else {
            continue;
        };
        if last == "-" || satisfied.contains(&last.as_str()) {
            continue;
        }
        let Some(op_idx) = u32::try_from(idx).ok() else {
            continue;
        };
        let Some(payload) = resolve_payload(op_idx, op, session) else {
            continue;
        };
        let Some(encoded) = &op.encoded_last_token else {
            continue;
        };
        emit_separator(out, emitted_any);
        out.extend_from_slice(encoded);
        out.push(b':');
        out.extend_from_slice(&payload);
    }
}

/// Rewrite an array, inserting at original indices and appending at close.
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "array element walk is a linear tokenizer loop"
)]
fn rewrite_array(
    input: &[u8],
    i: &mut usize,
    op_set: &CompiledOpSet,
    mut out: Option<&mut Vec<u8>>,
    depth: u32,
    session: &mut RewriteSession,
) -> Result<(), JsonError> {
    let depth = bump_depth(depth)?;
    expect_byte(input, i, b'[')?;
    if let Some(out) = out.as_mut() {
        out.push(b'[');
    }

    let mut emitted_any = false;
    let mut orig_idx: usize = 0;

    loop {
        skip_ws(input, i);
        if next_byte(input, *i)? == b']' {
            *i += 1;
            break;
        }
        if orig_idx > 0 {
            expect_byte(input, i, b',')?;
            skip_ws(input, i);
            if next_byte(input, *i)? == b']' {
                return Err(JsonError::InvalidJson);
            }
        }

        let mutate_idx = op_set.index.mutate_at_index(&session.path, orig_idx);
        if let Some(op_idx) = mutate_idx {
            try_emit_add(op_set, op_idx, out.as_deref_mut(), &mut emitted_any, session);
        }

        let replace_or_remove = mutate_idx.and_then(|op_idx| {
            op_at(&op_set.ops, op_idx)
                .and_then(|op| matches!(op.kind, OpKind::Remove | OpKind::Replace).then_some(op_idx))
        });

        if let Some(op_idx) = replace_or_remove {
            rewrite_array_member(
                input,
                i,
                orig_idx,
                op_idx,
                op_set,
                out.as_deref_mut(),
                &mut emitted_any,
                depth,
                session,
            )?;
        } else {
            if let Some(out) = out.as_mut() {
                emit_separator(out, &mut emitted_any);
            }
            if op_set.index.child_index_needs_rewrite(&session.path, orig_idx) {
                session.path.push(PathToken::Index(orig_idx));
                rewrite_value(input, i, op_set, out.as_deref_mut(), depth, session)?;
                session.path.pop();
            } else {
                copy_span(input, i, depth, out.as_deref_mut())?;
            }
        }
        orig_idx = orig_idx.saturating_add(1);
    }

    if let Some(op_idx) = op_set.index.mutate_at_index(&session.path, orig_idx) {
        try_emit_add(op_set, op_idx, out.as_deref_mut(), &mut emitted_any, session);
    }
    if let Some(op_idx) = op_set.index.add_append(&session.path) {
        try_emit_add(op_set, op_idx, out.as_deref_mut(), &mut emitted_any, session);
    }

    if let Some(out) = out.as_mut() {
        out.push(b']');
    }
    Ok(())
}

/// Remove or replace the array element at `orig_idx`.
#[expect(clippy::too_many_arguments, reason = "member splice needs walk + emit state")]
fn rewrite_array_member(
    input: &[u8],
    i: &mut usize,
    orig_idx: usize,
    op_idx: u32,
    op_set: &CompiledOpSet,
    mut out: Option<&mut Vec<u8>>,
    emitted_any: &mut bool,
    depth: u32,
    session: &mut RewriteSession,
) -> Result<(), JsonError> {
    let Some(op) = op_at(&op_set.ops, op_idx) else {
        return Ok(());
    };
    session.path.push(PathToken::Index(orig_idx));
    match op.kind {
        OpKind::Remove => consume_value_for_mutate(input, i, depth, op_set, session)?,
        OpKind::Replace => {
            skip_ws(input, i);
            let value_start = *i;
            consume_value_for_mutate(input, i, depth, op_set, session)?;
            if let Some(out_buf) = out.as_mut() {
                if let Some(payload) = resolve_payload(op_idx, op, session) {
                    emit_separator(out_buf, emitted_any);
                    out_buf.extend_from_slice(&payload);
                } else {
                    emit_separator(out_buf, emitted_any);
                    copy_input_span(input, value_start, *i, out_buf)?;
                }
            }
        },
        OpKind::Add | OpKind::Extract => {},
    }
    session.path.pop();
    Ok(())
}

/// Whether `op.tokens[..len-1]` equals `path`.
fn parent_is(op: &CompiledOp, path: &[PathToken]) -> bool {
    let Some(prefix) = op.tokens.get(..path.len()) else {
        return false;
    };
    op.tokens.len() == path.len().saturating_add(1) && path_eq_tokens(path, prefix)
}

/// Insert a comma before the next emitted member or element.
fn emit_separator(out: &mut Vec<u8>, emitted_any: &mut bool) {
    if *emitted_any {
        out.push(b',');
    }
    *emitted_any = true;
}

/// Re-emit an object member whose mutating op was skipped (missing context).
#[expect(
    clippy::too_many_arguments,
    reason = "member emit needs key span, value span, and comma state"
)]
fn emit_original_member(
    input: &[u8],
    value_start: usize,
    value_end: usize,
    key_span: &[u8],
    out: &mut Vec<u8>,
    emitted_any: &mut bool,
) -> Result<(), JsonError> {
    emit_separator(out, emitted_any);
    out.extend_from_slice(key_span);
    out.push(b':');
    copy_input_span(input, value_start, value_end, out)
}

/// Copy `input[start..end]` into `out`.
fn copy_input_span(input: &[u8], start: usize, end: usize, out: &mut Vec<u8>) -> Result<(), JsonError> {
    let span = input.get(start..end).ok_or(JsonError::InvalidJson)?;
    out.extend_from_slice(span);
    Ok(())
}

/// Parse a JSON string; returns the original quoted span and the decoded text.
fn parse_string<'a>(input: &'a [u8], i: &mut usize) -> Result<(&'a [u8], Cow<'a, str>), JsonError> {
    let start = *i;
    let escaped = skip_string_with_meta(input, i)?;
    let raw = input.get(start..*i).ok_or(JsonError::InvalidJson)?;
    let inner = raw.get(1..raw.len().saturating_sub(1)).ok_or(JsonError::InvalidJson)?;
    if escaped {
        let decoded = serde_json::from_slice(raw).map_err(|_e| JsonError::InvalidJson)?;
        Ok((raw, Cow::Owned(decoded)))
    } else {
        let decoded = std::str::from_utf8(inner).map_err(|_e| JsonError::InvalidJson)?;
        Ok((raw, Cow::Borrowed(decoded)))
    }
}

#[cfg(test)]
mod header_promotion_tests {
    use super::is_safe_header_promotion;
    use crate::builtins::http::payload_processing::MAX_DYNAMIC_VALUE_LEN;

    #[test]
    fn rejects_oversized_values() {
        let text = "a".repeat(MAX_DYNAMIC_VALUE_LEN + 1);
        assert!(!is_safe_header_promotion(&text, "X-Model"));
    }

    #[test]
    fn allows_values_at_limit() {
        let text = "a".repeat(MAX_DYNAMIC_VALUE_LEN);
        assert!(is_safe_header_promotion(&text, "X-Model"));
    }

    #[test]
    fn rejects_newlines() {
        assert!(!is_safe_header_promotion("bad\nvalue", "X-Model"));
    }

    #[test]
    fn rejects_carriage_returns() {
        assert!(!is_safe_header_promotion("bad\rvalue", "X-Model"));
    }

    #[test]
    fn allows_horizontal_tab() {
        assert!(is_safe_header_promotion("ok\tvalue", "X-Model"));
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::{OUTPUT_GROWTH_SLACK, rewrite_output_capacity};

    #[test]
    fn remove_only_uses_input_len() {
        assert_eq!(rewrite_output_capacity(10_485_760, 0), 10_485_760);
    }

    #[test]
    fn growth_hint_adds_slack() {
        let hint = 100;
        assert_eq!(
            rewrite_output_capacity(1000, hint),
            1_000_usize.saturating_add(hint).saturating_add(OUTPUT_GROWTH_SLACK)
        );
    }

    #[test]
    fn zero_input_with_growth() {
        assert_eq!(
            rewrite_output_capacity(0, 10),
            10_usize.saturating_add(OUTPUT_GROWTH_SLACK)
        );
    }
}
