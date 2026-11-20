// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! JSON-RPC body parsing + typed CMF content-part builders.
//!
//! The upstream protocol classifier filter (from `praxis-ai`) parses JSON-RPC bodies
//! and stashes `mcp.method` / `mcp.name` in `filter_metadata`, but
//! it doesn't materialize `params.arguments` (or `result.content`)
//! into a typed form that policy `args.*` / `result.*` predicates can
//! evaluate. This module does that second parse, builds the matching
//! `ContentPart`, and re-serializes mutated payloads back into
//! JSON-RPC envelopes when `body_access: read_write` is on.

use bytes::Bytes;
use ppe::praxis_policy_core::cmf::{
    ContentPart, Message, PromptRequest, PromptResult, Resource, ResourceReference, ResourceType, Role, ToolCall,
    ToolResult,
};

// -----------------------------------------------------------------------------
// JSON-RPC id extraction
// -----------------------------------------------------------------------------

/// A JSON-RPC body parsed once per filter phase.
///
/// A missing or malformed body parses to `Null`.
pub(super) struct ParsedEnvelope(serde_json::Value);

impl ParsedEnvelope {
    /// Parse one complete JSON value, retaining malformed-input errors.
    pub(super) fn try_parse(body: &Bytes) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(body).map(Self)
    }

    /// Parse `body`; malformed or empty input yields a `Null` envelope.
    pub(super) fn parse(body: &Bytes) -> Self {
        Self::try_parse(body).unwrap_or(Self(serde_json::Value::Null))
    }

    /// The raw `id` value (`Null` when absent), preserving the original
    /// shape so error envelopes echo exactly what the client sent.
    pub(super) fn id_value(&self) -> serde_json::Value {
        self.0.get("id").cloned().unwrap_or(serde_json::Value::Null)
    }

    /// The `id` rendered for correlation strings.
    pub(super) fn id_string(&self) -> String {
        match self.id_value() {
            serde_json::Value::String(s) => s,
            serde_json::Value::Null => String::new(),
            other => other.to_string(),
        }
    }

    /// A top-level field of the envelope, if the body parsed to an
    /// object carrying it.
    fn field(&self, name: &str) -> Option<&serde_json::Value> {
        self.0.get(name)
    }

    /// Identify a JSON-RPC error without treating arbitrary objects as errors.
    pub(super) fn is_json_rpc_error(&self) -> bool {
        let Some(object) = self.0.as_object() else {
            return false;
        };
        let version = object.get("jsonrpc").and_then(serde_json::Value::as_str) == Some("2.0");
        let id = object
            .get("id")
            .is_some_and(|id| id.is_null() || id.is_string() || id.is_number());
        let error = object.get("error").and_then(serde_json::Value::as_object);
        let code = error
            .and_then(|error| error.get("code"))
            .and_then(serde_json::Value::as_number);
        let message = error
            .and_then(|error| error.get("message"))
            .is_some_and(serde_json::Value::is_string);
        version && id && code.is_some_and(|code| code.is_i64() || code.is_u64()) && message
    }

    /// Consume the envelope, yielding the parsed DOM for rewriting.
    ///
    /// A malformed body is `Null` here, short-circuiting the rewrite.
    pub(super) fn into_value(self) -> serde_json::Value {
        self.0
    }
}

// -----------------------------------------------------------------------------
// Request-side: body → typed ContentPart list
// -----------------------------------------------------------------------------

/// Build the typed CMF `ContentPart` list for a JSON-RPC method.
/// Parses `params` out of the body so policy `args.*` /
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
    envelope: &ParsedEnvelope,
) -> Vec<ContentPart> {
    // Borrow `params` in place: only `arguments` / `uri` are read out
    // of it, and cloning the whole subtree — most of the body for
    // typical payloads — per request served nothing.
    let params = envelope.field("params");

    match method {
        "tools/call" => {
            let arguments = params
                .and_then(|p| p.get("arguments"))
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
                .and_then(|p| p.get("arguments"))
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
            // For `resources/read`, `params.uri` is the resource
            // identifier; `mcp.name` is set to the same URI by the
            // protocol classifier filter (it treats `uri` as the "selector"). Carry
            // it through as the `ResourceReference`.
            let uri = params
                .and_then(|p| p.get("uri"))
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
/// mutated by policy in the typed `MessagePayload`. Returns `Some(new_bytes)`
/// when the body changed, `None` when nothing needed rewriting
/// (no matching content part, malformed original, etc.).
///
/// Touched fields by JSON-RPC method:
///   * `tools/call`     → `params.arguments` (from the first `ContentPart::ToolCall.arguments`)
///   * `prompts/get`    → `params.arguments` (from the first `ContentPart::PromptRequest.arguments`)
///   * `resources/read` → `params.uri` (from `ContentPart::ResourceRef.uri`)
///
/// All other JSON-RPC envelope fields (`jsonrpc`, `id`, `method`,
/// `params.name`) pass through unchanged. This minimizes the
/// blast radius of the rewrite — operators relying on a byte-stable
/// envelope (signature validation, content-hash matching) only see
/// changes only when policy modifies the payload.
#[expect(
    clippy::too_many_lines,
    reason = "per-method envelope orchestration; splitting per-method obscures the JSON-RPC shape"
)]
pub(super) fn reserialize_json_rpc_body(envelope: serde_json::Value, method: &str, message: &Message) -> Option<Bytes> {
    let mut envelope = envelope;
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
/// body — the post-phase mirror of [`build_content_for_method`].
/// `tools/call` produces a structured `ToolResult`, `resources/read` one
/// `Resource` per entry and `prompts/get` one `PromptResult` (see
/// [`build_resource_result`] and [`build_prompt_result`]). Other methods
/// produce no content parts.
///
/// The actual tool data lives in `result.content[].text` (a
/// JSON-stringified payload) and/or `result.structuredContent`. We prefer
/// `structuredContent` for `result.*` projection; alongside it,
/// expose each text block as CMF Text for whole-message scanners. Without
/// structured content, fold **every** text block. A lone text block that
/// parses as JSON is exposed as that
/// object (so `result.<field>` predicates resolve); otherwise the raw
/// text — or the concatenation of multiple blocks — is wrapped as
/// `{ "text": "<raw>" }` so `result.text` predicates still resolve.
///
/// PPE's `result.*` projection still prefers the structured `ToolResult`;
/// secondary Text parts are visible only to scanners of the whole CMF
/// message. No-mutation allows keep the original response bytes.
#[expect(
    clippy::too_many_lines,
    reason = "per-method envelope orchestration; splitting per-method obscures the JSON-RPC shape"
)]
pub(super) fn build_response_content_for_method(
    method: &str,
    entity_name: &str,
    correlation_id: &str,
    envelope: &ParsedEnvelope,
) -> Vec<ContentPart> {
    let Some(result) = envelope.field("result") else {
        return Vec::new();
    };
    match method {
        "tools/call" => {},
        "resources/read" => return build_resource_result(result, entity_name, correlation_id),
        "prompts/get" => return build_prompt_result(result, entity_name, correlation_id),
        _ => return Vec::new(),
    }
    let is_error = result
        .get("isError")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    let texts: Vec<&str> = result
        .get("content")
        .and_then(serde_json::Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter(|block| block.get("type").and_then(serde_json::Value::as_str) == Some("text"))
                .filter_map(|block| block.get("text").and_then(serde_json::Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    let structured = result.get("structuredContent");
    let content_value = if let Some(structured) = structured {
        structured.clone()
    } else {
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

    let mut parts = vec![ContentPart::ToolResult {
        content: ToolResult {
            tool_call_id: correlation_id.to_owned(),
            tool_name: entity_name.to_owned(),
            content: content_value,
            is_error,
        },
    }];
    if structured.is_some() {
        parts.extend(
            texts
                .into_iter()
                .map(|text| ContentPart::Text { text: text.to_owned() }),
        );
    }
    parts
}

/// `resources/read` response → one `ContentPart::Resource` per
/// `result.contents[]` entry, in order.
///
/// Every entry gets a part, a `blob`-only entry included (with no `content`),
/// so part `i` always corresponds to entry `i` on write-back.
///
/// Known gap: PPE projects only the first `Resource` part of a message, so
/// entries after the first are not inspected until PPE issue 76 projects every
/// part. No text is joined across entries.
fn build_resource_result(result: &serde_json::Value, entity_name: &str, correlation_id: &str) -> Vec<ContentPart> {
    let Some(entries) = result.get("contents").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    // A valid read with no entries still yields a part, carrying no content,
    // so it is not mistaken for an uninspectable response and failed closed.
    if entries.is_empty() {
        return vec![ContentPart::Resource {
            content: Resource {
                resource_request_id: correlation_id.to_owned(),
                uri: entity_name.to_owned(),
                resource_type: ResourceType::Uri,
                ..Resource::default()
            },
        }];
    }
    entries
        .iter()
        .map(|entry| ContentPart::Resource {
            content: Resource {
                resource_request_id: correlation_id.to_owned(),
                uri: string_field(entry, "uri").unwrap_or(entity_name).to_owned(),
                mime_type: string_field(entry, "mimeType").map(str::to_owned),
                content: string_field(entry, "text").map(str::to_owned),
                resource_type: ResourceType::Uri,
                ..Resource::default()
            },
        })
        .collect()
}

/// `prompts/get` response → one `ContentPart::PromptResult`.
///
/// `content` is the first message's text, which is what PPE inspects today.
/// `messages` carries every message, in order, for PPE issue 76, which
/// projects them. No text is joined across messages.
///
/// Known gap: until issue 76, messages after the first are not inspected.
fn build_prompt_result(result: &serde_json::Value, entity_name: &str, correlation_id: &str) -> Vec<ContentPart> {
    // A valid prompt with no messages still yields a part (no `content`), so
    // it is not mistaken for an uninspectable response and failed closed.
    let Some(messages) = result.get("messages").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };

    vec![ContentPart::PromptResult {
        content: PromptResult {
            prompt_request_id: correlation_id.to_owned(),
            prompt_name: entity_name.to_owned(),
            description: string_field(result, "description").map(str::to_owned),
            messages: messages.iter().map(prompt_message).collect(),
            content: messages.first().and_then(message_text).map(str::to_owned),
            is_error: false,
            error_message: None,
        },
    }]
}

/// A JSON object's string field, if present.
fn string_field<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

/// One MCP prompt message as a CMF message: its role, and its text as a
/// `Text` part when it has one.
fn prompt_message(message: &serde_json::Value) -> Message {
    let role = match string_field(message, "role") {
        Some("assistant") => Role::Assistant,
        Some(_) | None => Role::User,
    };
    let content = message_text(message)
        .map(|text| vec![ContentPart::Text { text: text.to_owned() }])
        .unwrap_or_default();
    Message::with_content(role, content)
}

/// The text of an MCP prompt message: its `content` block when that is a
/// text block, or the first text block when `content` is an array.
fn message_text(message: &serde_json::Value) -> Option<&str> {
    let content = message.get("content")?;
    let is_text = |block: &&serde_json::Value| string_field(block, "type") == Some("text");
    let block = match content.as_array() {
        Some(blocks) => blocks.iter().find(is_text)?,
        None => Some(content).filter(is_text)?,
    };
    string_field(block, "text")
}

// -----------------------------------------------------------------------------
// Response-side: re-serialize mutated payload back into the body
// -----------------------------------------------------------------------------

/// Re-serialize a JSON-RPC response body, replacing only the fields
/// the post-phase policy pipeline mutated. Mirror of
/// [`reserialize_json_rpc_body`] for the response side.
///
/// When the original response carried a `result.content` array, the
/// **entire** array is replaced with a single canonical text block
/// holding the vetted `ToolResult.content` (JSON-stringified — the
/// legacy JSON-RPC shape every client supports). Collapsing to one block is
/// deliberate: a mutator rewrites the selected `ToolResult`, not each parallel
/// text or binary representation. Dropping the original blocks prevents a
/// stale unmodified copy from surviving the mutation.
///
/// `result.structuredContent` is mirrored to the same value, but
/// only when the original response already had it (we don't invent
/// fields).
///
/// `resources/read` and `prompts/get` are rewritten from the one folded part
/// [`build_response_content_for_method`] built; see [`rewrite_resource_result`]
/// and [`rewrite_prompt_result`].
pub(super) fn reserialize_json_rpc_response_body(
    envelope: serde_json::Value,
    method: &str,
    message: &Message,
) -> Option<Bytes> {
    let mut envelope = envelope;
    let result_obj = envelope.get_mut("result")?.as_object_mut()?;
    match method {
        "tools/call" => rewrite_tool_result(result_obj, message)?,
        "resources/read" => rewrite_resource_result(result_obj, message)?,
        "prompts/get" => rewrite_prompt_result(result_obj, message)?,
        _ => return None,
    }
    Some(Bytes::from(serde_json::to_vec(&envelope).ok()?))
}

/// Rewrite a `tools/call` result from the vetted `ToolResult`.
fn rewrite_tool_result(result_obj: &mut serde_json::Map<String, serde_json::Value>, message: &Message) -> Option<()> {
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
    Some(())
}

/// Rewrite a `resources/read` result from the vetted `Resource` parts.
///
/// Part `i` is written into `result.contents[i]` (see
/// [`build_resource_result`]), so the response keeps its entries and their
/// order. Only `text` and `mimeType` change; `uri` and `blob` stay as sent.
fn rewrite_resource_result(
    result_obj: &mut serde_json::Map<String, serde_json::Value>,
    message: &Message,
) -> Option<()> {
    let resources = message.content.iter().filter_map(|part| match part {
        ContentPart::Resource { content } => Some(content),
        _ => None,
    });
    let entries = result_obj.get_mut("contents")?.as_array_mut()?;
    for (entry, resource) in entries.iter_mut().zip(resources) {
        let entry = entry.as_object_mut()?;
        if let Some(mime_type) = &resource.mime_type {
            entry.insert("mimeType".to_owned(), mime_type.clone().into());
        }
        // Policy removing the text sends empty text, never the original.
        if resource.content.is_some() || entry.contains_key("text") {
            let text = resource.content.clone().unwrap_or_default();
            entry.insert("text".to_owned(), text.into());
        }
    }
    Some(())
}

/// Rewrite a `prompts/get` result from the vetted `PromptResult`.
///
/// The response keeps its messages, roles and order. The first message's text
/// comes from `PromptResult.content`, which is what policy inspects today;
/// later messages' text comes from `PromptResult.messages` (see
/// [`build_prompt_result`]). Removed text is sent as empty text, never the
/// original. `result.description` follows the vetted value.
fn rewrite_prompt_result(
    result_obj: &mut serde_json::Map<String, serde_json::Value>,
    message: &Message,
) -> Option<()> {
    let prompt = message.content.iter().find_map(|part| match part {
        ContentPart::PromptResult { content } => Some(content),
        _ => None,
    })?;

    let messages = result_obj.get_mut("messages")?.as_array_mut()?;
    for (index, original) in messages.iter_mut().enumerate() {
        let vetted = match index {
            0 => Some(prompt.content.as_deref().unwrap_or_default()),
            _ => prompt.messages.get(index).and_then(first_text_part),
        };
        if let Some(text) = vetted {
            set_message_text(original, text);
        }
    }
    match &prompt.description {
        Some(description) => result_obj.insert("description".to_owned(), description.clone().into()),
        None => result_obj.remove("description"),
    };
    Some(())
}

/// The first `Text` part of a CMF message.
fn first_text_part(message: &Message) -> Option<&str> {
    message.content.iter().find_map(|part| match part {
        ContentPart::Text { text } => Some(text.as_str()),
        _ => None,
    })
}

/// Set the text of an MCP prompt message: the text block [`message_text`]
/// reads. A message with no text block is left unchanged.
fn set_message_text(message: &mut serde_json::Value, text: &str) {
    let Some(content) = message.get_mut("content") else {
        return;
    };
    let is_text = |block: &&mut serde_json::Value| string_field(block, "type") == Some("text");
    let block = match content.as_array_mut() {
        Some(blocks) => blocks.iter_mut().find(is_text),
        None => Some(content).filter(is_text),
    };
    if let Some(serde_json::Value::Object(block)) = block {
        block.insert("text".to_owned(), text.to_owned().into());
    }
}
