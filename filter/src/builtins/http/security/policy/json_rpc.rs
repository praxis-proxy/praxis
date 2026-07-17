// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! JSON-RPC body parsing + typed CMF content-part builders.
//!
//! The upstream protocol classifier filter (from `praxis-ai`) parses JSON-RPC bodies
//! and stashes `protocol.method` / `protocol.name` in `filter_metadata`, but
//! it doesn't materialize `params.arguments` (or `result.content`)
//! into a typed form that APL `args.*` / `result.*` predicates can
//! evaluate. This module does that second parse, builds the matching
//! `ContentPart`, and re-serializes mutated payloads back into
//! JSON-RPC envelopes when `body_access: read_write` is on.

use bytes::Bytes;
use cpex::cpex_core::cmf::{
    ContentPart, Message, PromptRequest, ResourceReference, ResourceType, ToolCall, ToolResult,
};

// -----------------------------------------------------------------------------
// JSON-RPC id extraction
// -----------------------------------------------------------------------------

/// Read the JSON-RPC `id` field as a string for use as a CMF
/// correlation id. JSON-RPC permits string or numeric ids; we
/// stringify either to a single canonical key. Returns an empty
/// string when the body is missing or malformed — the correlation
/// id isn't load-bearing for policy, only for audit linkage.
///
/// Delegates to [`json_rpc_id_value`] so the body is parsed by a single
/// implementation rather than two independent `from_slice` calls.
pub(super) fn json_rpc_id(body: &Bytes) -> String {
    match json_rpc_id_value(body) {
        serde_json::Value::String(s) => s,
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Typed companion to [`json_rpc_id`]. Returns the raw `id` JSON value
/// from the request body — preserves the original shape (string or
/// number) so a JSON-RPC error envelope echoes back exactly what the
/// client sent. Returns `Value::Null` when the body is missing or
/// malformed; per JSON-RPC 2.0, an error response MAY use `null` when
/// the original id could not be determined.
pub(super) fn json_rpc_id_value(body: &Bytes) -> serde_json::Value {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .unwrap_or(serde_json::Value::Null)
}

// -----------------------------------------------------------------------------
// Request-side: body → typed ContentPart list
// -----------------------------------------------------------------------------

/// Build the typed CMF `ContentPart` list for a JSON-RPC method.
/// Parses `params` out of the body so APL `args.*` /
/// `prompt.args.*` / `resource.*` predicates have something to
/// evaluate against. On
/// malformed or absent body, falls back to an empty content list — the
/// caller can still dispatch CMF (entity coords drive routing), just
/// without typed args available to predicates.
#[expect(
    clippy::too_many_lines,
    reason = "per-method envelope orchestration; splitting per-method obscures the JSON-RPC shape"
)]
pub(super) fn build_content_for_method(
    method: &str,
    entity_name: &str,
    correlation_id: &str,
    body: &Bytes,
) -> Vec<ContentPart> {
    let params: serde_json::Value = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("params").cloned())
        .unwrap_or(serde_json::Value::Null);

    match method {
        "tools/call" => {
            let arguments = params
                .get("arguments")
                .and_then(|v| v.as_object())
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: correlation_id.to_owned(),
                    name: entity_name.to_owned(),
                    arguments,
                    namespace: None,
                },
            }]
        },
        "prompts/get" => {
            let arguments = params
                .get("arguments")
                .and_then(|v| v.as_object())
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();
            vec![ContentPart::PromptRequest {
                content: PromptRequest {
                    prompt_request_id: correlation_id.to_owned(),
                    name: entity_name.to_owned(),
                    arguments,
                    server_id: None,
                },
            }]
        },
        "resources/read" => {
            // For `resource/read`, `params.uri` is the resource
            // identifier; `protocol.name` is set to the same URI by the
            // protocol classifier filter (it treats `uri` as the "selector"). Carry
            // it through as the `ResourceReference`.
            let uri = params
                .get("uri")
                .and_then(|v| v.as_str())
                .unwrap_or(entity_name)
                .to_owned();
            vec![ContentPart::ResourceRef {
                content: ResourceReference {
                    resource_request_id: correlation_id.to_owned(),
                    uri,
                    name: None,
                    resource_type: ResourceType::Uri,
                    range_start: None,
                    range_end: None,
                    selector: None,
                },
            }]
        },
        _ => Vec::new(),
    }
}

// -----------------------------------------------------------------------------
// Request-side: re-serialize mutated payload back into the body
// -----------------------------------------------------------------------------

/// Re-serialize a JSON-RPC request body, replacing only the fields
/// APL mutated in the typed `MessagePayload`. Returns `Some(new_bytes)`
/// when the body changed, `None` when nothing needed rewriting
/// (no matching content part, malformed original, etc.).
///
/// Touched fields by JSON-RPC method:
///   * `service/invoke`     → `params.arguments` (from the first `ContentPart::ToolCall.arguments`)
///   * `template/get`    → `params.arguments` (from the first `ContentPart::PromptRequest.arguments`)
///   * `resource/read` → `params.uri` (from `ContentPart::ResourceRef.uri`)
///
/// All other JSON-RPC envelope fields (`jsonrpc`, `id`, `method`,
/// `params.name`) pass through unchanged. This minimizes the
/// blast radius of the rewrite — operators relying on a byte-stable
/// envelope (signature validation, content-hash matching) only see
/// changes when APL actually mutated.
#[expect(
    clippy::too_many_lines,
    reason = "per-method envelope orchestration; splitting per-method obscures the JSON-RPC shape"
)]
pub(super) fn reserialize_json_rpc_body(original: &Bytes, method: &str, message: &Message) -> Option<Bytes> {
    let mut envelope: serde_json::Value = serde_json::from_slice(original).ok()?;
    let params = envelope.get_mut("params")?;
    let params_obj = params.as_object_mut()?;

    match method {
        "tools/call" | "prompts/get" => {
            for part in &message.content {
                let new_args = match part {
                    ContentPart::ToolCall { content } if method == "tools/call" => Some(&content.arguments),
                    ContentPart::PromptRequest { content } if method == "prompts/get" => Some(&content.arguments),
                    _ => None,
                };
                if let Some(args) = new_args {
                    let new_args_value: serde_json::Value = args
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect::<serde_json::Map<_, _>>()
                        .into();
                    params_obj.insert("arguments".to_owned(), new_args_value);
                    return Some(Bytes::from(serde_json::to_vec(&envelope).ok()?));
                }
            }
            None
        },
        "resources/read" => {
            for part in &message.content {
                if let ContentPart::ResourceRef { content } = part {
                    params_obj.insert("uri".to_owned(), serde_json::Value::String(content.uri.clone()));
                    return Some(Bytes::from(serde_json::to_vec(&envelope).ok()?));
                }
            }
            None
        },
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// Response-side: body → typed ContentPart list (post-phase)
// -----------------------------------------------------------------------------

/// Build the typed CMF `ContentPart` list from a JSON-RPC *response*
/// body — the post-phase mirror of [`build_content_for_method`]. Today
/// only `service/invoke` produces a structured `ToolResult`; `template/get`
/// and `resource/read` return TBD shapes the filter can extend later.
///
/// The actual tool data lives in `result.content[].text` (a
/// JSON-stringified payload) and/or `result.structuredContent`
/// (newer 2025-06-18 shape). We try
/// `structuredContent` first; on miss, fold **every** text block (not
/// just the first) so APL evaluates against all of the response's text
/// content. A lone text block that parses as JSON is exposed as that
/// object (so `result.<field>` predicates resolve); otherwise the raw
/// text — or the concatenation of multiple blocks — is wrapped as
/// `{ "text": "<raw>" }` so `result.text` predicates still resolve.
///
/// Folding all blocks is load-bearing for policy: if APL only saw the
/// first block, a later block could carry data the policy never vetted
/// and [`reserialize_json_rpc_response_body`] never rewrote, leaking it
/// downstream. The view here and the bytes emitted there are kept to
/// the same content set.
#[expect(
    clippy::too_many_lines,
    reason = "per-method envelope orchestration; splitting per-method obscures the JSON-RPC shape"
)]
pub(super) fn build_response_content_for_method(
    method: &str,
    entity_name: &str,
    correlation_id: &str,
    body: &Bytes,
) -> Vec<ContentPart> {
    if method != "tools/call" {
        return Vec::new();
    }
    let envelope: serde_json::Value = match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let Some(result) = envelope.get("result") else {
        return Vec::new();
    };
    let is_error = result
        .get("isError")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    let content_value = if let Some(structured) = result.get("structuredContent") {
        structured.clone()
    } else {
        let texts: Vec<&str> = result
            .get("content")
            .and_then(|c| c.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
                    .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                    .collect()
            })
            .unwrap_or_default();
        match texts.as_slice() {
            [] => serde_json::Value::Null,
            [single] => serde_json::from_str::<serde_json::Value>(single)
                .unwrap_or_else(|_| serde_json::json!({ "text": single })),
            // Multiple text blocks can't be merged into one JSON object
            // unambiguously; expose their concatenation under `text` so
            // every block is in APL's view (and gets collapsed into a
            // single vetted block on re-serialization).
            many => serde_json::json!({ "text": many.join("\n") }),
        }
    };

    vec![ContentPart::ToolResult {
        content: ToolResult {
            tool_call_id: correlation_id.to_owned(),
            tool_name: entity_name.to_owned(),
            content: content_value,
            is_error,
        },
    }]
}

// -----------------------------------------------------------------------------
// Response-side: re-serialize mutated payload back into the body
// -----------------------------------------------------------------------------

/// Re-serialize a JSON-RPC response body, replacing only the fields
/// the post-phase APL pipeline mutated. Mirror of
/// [`reserialize_json_rpc_body`] for the response side.
///
/// When the original response carried a `result.content` array, the
/// **entire** array is replaced with a single canonical text block
/// holding the vetted `ToolResult.content` (JSON-stringified — the
/// legacy JSON-RPC shape every client supports). Collapsing to one block is
/// deliberate: [`build_response_content_for_method`] folds every text
/// block into the single value APL evaluates, so any *other* block left
/// in place here would be content the policy never inspected and never
/// rewrote — a redaction bypass. Dropping the extra (text and non-text)
/// blocks guarantees the bytes we emit are exactly what APL vetted.
///
/// `result.structuredContent` is mirrored to the same value, but
/// only when the original response already had it (we don't invent
/// fields).
pub(super) fn reserialize_json_rpc_response_body(original: &Bytes, method: &str, message: &Message) -> Option<Bytes> {
    if method != "tools/call" {
        return None;
    }
    let mut envelope: serde_json::Value = serde_json::from_slice(original).ok()?;
    let result = envelope.get_mut("result")?;
    let result_obj = result.as_object_mut()?;

    let new_content = message.content.iter().find_map(|part| match part {
        ContentPart::ToolResult { content } => Some(content.content.clone()),
        _ => None,
    })?;

    if result_obj.contains_key("content") {
        let text = serde_json::to_string(&new_content).ok()?;
        result_obj.insert(
            "content".to_owned(),
            serde_json::json!([{ "type": "text", "text": text }]),
        );
    }

    // Only mirror to structuredContent when the original had it.
    if result_obj.contains_key("structuredContent") {
        result_obj.insert("structuredContent".to_owned(), new_content);
    }

    Some(Bytes::from(serde_json::to_vec(&envelope).ok()?))
}
