// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Inference request and response parsing for CMF policy evaluation.

use std::{cell::Cell, collections::HashSet, fmt};

use bytes::Bytes;
use ppe::praxis_policy_core::{
    cmf::{ContentPart, Message, Role},
    extensions::{
        CompletionExtension, LlmInstruction, LlmInstructionRole, LlmRequestParts, StopReason, TokenUsage, ToolChoice,
        ToolMetadata,
    },
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum model identifier length accepted by filter metadata.
const MAX_MODEL_BYTES: usize = 256;

/// Top-level request fields with boolean semantics.
const BOOLEAN_PARAMS: &[&str] = &["stream"];

/// Content part types that carry prompt text in an `input` item.
const INPUT_TEXT_TYPES: &[&str] = &["input_text", "text", "output_text", "reasoning_text", "summary_text"];

/// Fields of a non-message `input` item (tool calls, tool outputs,
/// reasoning) that carry text, in projection order.
const INPUT_ITEM_TEXT_FIELDS: &[&str] = &["arguments", "input", "output", "text", "content", "summary"];

/// Top-level Chat Completions keys the parts normalizer models or knows
/// offer no tool, add no instruction, and leave the completion cap alone.
///
/// Any other key, including a case variant of one of these, leaves the parts
/// absent: a lenient backend may act on what the normalizer cannot see.
const CHAT_REQUEST_KEYS: &[&str] = &[
    "model",
    "messages",
    "tools",
    "tool_choice",
    "functions",
    "function_call",
    "max_tokens",
    "max_completion_tokens",
    "n",
    "temperature",
    "top_p",
    "stop",
    "stream",
    "stream_options",
    "frequency_penalty",
    "presence_penalty",
    "logit_bias",
    "logprobs",
    "top_logprobs",
    "response_format",
    "seed",
    "user",
    "metadata",
    "parallel_tool_calls",
    "store",
    "service_tier",
    "reasoning_effort",
];

/// Top-level Anthropic Messages keys, on the terms of [`CHAT_REQUEST_KEYS`].
///
/// [`CHAT_REQUEST_KEYS`]: CHAT_REQUEST_KEYS
const MESSAGES_REQUEST_KEYS: &[&str] = &[
    "model",
    "messages",
    "system",
    "tools",
    "tool_choice",
    "max_tokens",
    "stop_sequences",
    "temperature",
    "top_p",
    "top_k",
    "metadata",
    "stream",
    "thinking",
    "service_tier",
];

/// Keys of a conversation message, across both shapes.
const MESSAGE_KEYS: &[&str] = &[
    "role",
    "content",
    "name",
    "tool_calls",
    "tool_call_id",
    "function_call",
    "refusal",
];

/// Keys of a Chat Completions `{"type": "function", "function": ...}` tool entry.
const FUNCTION_TOOL_KEYS: &[&str] = &["type", "function"];

/// Keys of a Chat Completions function definition.
const FUNCTION_KEYS: &[&str] = &["name", "description", "parameters", "strict"];

/// Keys of an Anthropic custom tool.
const CUSTOM_TOOL_KEYS: &[&str] = &["type", "name", "description", "input_schema", "cache_control"];

/// Keys of a legacy Chat Completions `functions` entry.
const LEGACY_FUNCTION_KEYS: &[&str] = &["name", "description", "parameters"];

/// Keys of an instruction text block.
const TEXT_BLOCK_KEYS: &[&str] = &["type", "text", "cache_control"];

/// Message roles that carry no instruction; matched exactly, since a backend may fold
/// a case variant such as `SYSTEM` into an instruction.
const NON_INSTRUCTION_ROLES: &[&str] = &["user", "assistant", "tool", "function"];

/// Maximum nesting depth followed into content parts (e.g. a `tool_result`
/// block whose `content` is itself an array of parts).
const MAX_CONTENT_DEPTH: u8 = 4;

// -----------------------------------------------------------------------------
// Request side
// -----------------------------------------------------------------------------

/// A parsed inference request body.
pub(super) struct ParsedLlmRequest(serde_json::Value);

/// An inference request body that repeats a key within one JSON object.
///
/// Parsers disagree on which copy wins, so policy could judge a value the
/// backend never acts on. The error carries neither the key nor a value.
#[derive(Debug)]
pub(super) struct DuplicateKey;

impl ParsedLlmRequest {
    /// Parse `body`, refusing a repeated object key at any depth.
    ///
    /// Valid JSON that repeats a key is an error. Input that is not valid
    /// JSON, including empty input and nesting past `serde_json`'s recursion
    /// limit, yields a `Null` document whether or not it also repeats a key.
    /// Without duplicates the document equals what `serde_json::from_slice`
    /// builds.
    pub(super) fn parse(body: &Bytes) -> Result<Self, DuplicateKey> {
        let duplicate = Cell::new(false);
        let mut deserializer = serde_json::Deserializer::from_slice(body);
        let parsed = serde::de::DeserializeSeed::deserialize(UniqueKeys { duplicate: &duplicate }, &mut deserializer)
            .and_then(|value| deserializer.end().map(|()| value));
        match parsed {
            Ok(_) if duplicate.get() => Err(DuplicateKey),
            Ok(value) => Ok(Self(value)),
            Err(_) => Ok(Self(serde_json::Value::Null)),
        }
    }

    /// Parse `body` with `serde_json`'s last-wins handling of repeated keys.
    ///
    /// Malformed or empty input yields a `Null` document.
    pub(super) fn parse_last_wins(body: &Bytes) -> Self {
        Self(serde_json::from_slice(body).unwrap_or(serde_json::Value::Null))
    }

    /// The top-level `model`, when it is a usable string.
    ///
    /// Empty, overlong, and control-character-bearing values are rejected.
    pub(super) fn model(&self) -> Option<&str> {
        self.0
            .get("model")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|model| !model.is_empty() && model.len() <= MAX_MODEL_BYTES && !model.chars().any(char::is_control))
    }

    /// Whether the body carries a JSON-RPC `jsonrpc` or `method` marker.
    pub(super) fn carries_json_rpc_envelope(&self) -> bool {
        ["jsonrpc", "method"]
            .iter()
            .any(|key| self.0.get(key).is_some_and(serde_json::Value::is_string))
    }

    /// Whether the body requests a streamed response.
    pub(super) fn is_streaming(&self) -> bool {
        self.0.get("stream").is_some_and(truthy)
    }

    /// Return configured scalar fields keyed for `custom.llm.<name>`.
    /// Boolean fields are normalized before promotion.
    pub(super) fn promoted_params(&self, names: &[String]) -> serde_json::Map<String, serde_json::Value> {
        names
            .iter()
            .filter_map(|name| {
                self.0
                    .get(name)
                    .filter(|value| !matches!(value, serde_json::Value::Object(_) | serde_json::Value::Array(_)))
                    .filter(|value| !value.is_null())
                    .map(|value| (name.clone(), normalize_param(name, value)))
            })
            .collect()
    }

    /// Build CMF text parts from prompt-bearing fields in wire order.
    pub(super) fn content(&self) -> Vec<ContentPart> {
        let mut parts = Vec::new();

        // Anthropic carries the system prompt beside `messages` rather
        // than as a message with `role: system`.
        if let Some(system) = self.0.get("system") {
            push_text(&mut parts, system);
        }

        // Responses carries its system prompt in `instructions`.
        if let Some(instructions) = self.0.get("instructions") {
            push_text(&mut parts, instructions);
        }

        if let Some(messages) = self.0.get("messages").and_then(serde_json::Value::as_array) {
            for message in messages {
                if let Some(content) = message.get("content") {
                    push_text(&mut parts, content);
                }
                push_call_arguments(&mut parts, message);
            }
        }

        if let Some(prompt) = self.0.get("prompt") {
            push_text(&mut parts, prompt);
        }

        // Responses and embeddings carry the prompt in `input`.
        if let Some(input) = self.0.get("input") {
            push_input_text(&mut parts, input);
        }

        parts
    }

    /// Normalized parts, when every instruction, tool, and limit is understood.
    ///
    /// Covers Chat Completions and Anthropic Messages bodies. Any other
    /// shape, unknown entry, or malformed value leaves the parts absent, so
    /// an incomplete request is never reported as complete.
    pub(super) fn parts(&self) -> Option<LlmRequestParts> {
        normalize_parts(&self.0).ok()
    }

    /// Consume the request, yielding the parsed document.
    pub(super) fn into_value(self) -> serde_json::Value {
        self.0
    }
}

/// Whether a request field uses a commonly coerced true value.
fn truthy(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Bool(flag) => *flag,
        serde_json::Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        serde_json::Value::String(text) => {
            matches!(text.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on")
        },
        _ => false,
    }
}

/// Normalize a promoted boolean field and clone other scalar values.
fn normalize_param(name: &str, value: &serde_json::Value) -> serde_json::Value {
    if BOOLEAN_PARAMS.contains(&name) {
        return serde_json::Value::Bool(truthy(value));
    }
    value.clone()
}

/// Append text from a string or multimodal content array.
fn push_text(parts: &mut Vec<ContentPart>, value: &serde_json::Value) {
    push_text_at(parts, value, 0);
}

/// Append text from `value`, following nested content parts up to
/// [`MAX_CONTENT_DEPTH`] levels deep.
fn push_text_at(parts: &mut Vec<ContentPart>, value: &serde_json::Value, depth: u8) {
    if depth > MAX_CONTENT_DEPTH {
        return;
    }
    let next = depth.saturating_add(1);
    match value {
        serde_json::Value::String(text) => {
            if !text.is_empty() {
                parts.push(ContentPart::Text { text: text.clone() });
            }
        },
        serde_json::Value::Array(items) => {
            for item in items {
                match item {
                    serde_json::Value::String(_) => push_text_at(parts, item, next),
                    serde_json::Value::Object(_) => push_object_text(parts, item, next),
                    _ => {},
                }
            }
        },
        _ => {},
    }
}

/// Append text from a Responses or embeddings `input`.
///
/// Token-ID arrays and non-text content parts are skipped.
fn push_input_text(parts: &mut Vec<ContentPart>, input: &serde_json::Value) {
    match input {
        serde_json::Value::String(_) => push_text(parts, input),
        serde_json::Value::Array(items) => {
            for item in items {
                match item {
                    serde_json::Value::String(_) => push_text(parts, item),
                    serde_json::Value::Object(_) => push_input_item_text(parts, item),
                    _ => {},
                }
            }
        },
        _ => {},
    }
}

/// Append message or tool-history text from one `input` item.
///
/// Unlisted item types contribute any text found in the common fields in
/// [`INPUT_ITEM_TEXT_FIELDS`]; known types can contribute additional fields.
fn push_input_item_text(parts: &mut Vec<ContentPart>, item: &serde_json::Value) {
    let kind = item.get("type").and_then(serde_json::Value::as_str);
    let fields = match kind {
        Some("message") | None => &["content"][..],
        Some(_) => INPUT_ITEM_TEXT_FIELDS,
    };
    for value in fields.iter().filter_map(|field| item.get(field)) {
        push_input_parts_text(parts, value);
    }
    match kind {
        Some("file_search_call") => push_nested_item_text(parts, item, "results", "text"),
        Some("code_interpreter_call") => {
            if let Some(code) = item.get("code") {
                push_text(parts, code);
            }
            push_nested_item_text(parts, item, "outputs", "logs");
        },
        Some("mcp_list_tools") => push_nested_item_text(parts, item, "tools", "description"),
        Some(_) | None => {},
    }
}

/// Project named text from an array of tool-history records.
fn push_nested_item_text(parts: &mut Vec<ContentPart>, item: &serde_json::Value, array: &str, field: &str) {
    if let Some(records) = item.get(array).and_then(serde_json::Value::as_array) {
        for value in records.iter().filter_map(|record| record.get(field)) {
            push_text(parts, value);
        }
    }
}

/// Append text from a string or a content-part array, skipping image and file parts.
fn push_input_parts_text(parts: &mut Vec<ContentPart>, value: &serde_json::Value) {
    let serde_json::Value::Array(content) = value else {
        return push_text(parts, value);
    };
    for part in content {
        let text_part = match part.get("type") {
            Some(kind) => kind.as_str().is_some_and(|kind| INPUT_TEXT_TYPES.contains(&kind)),
            None => true,
        };
        if text_part {
            push_text(parts, part);
            push_object_text(parts, part, 1);
        }
    }
}

/// Append the `text` and nested `content` of one content-part object
/// (e.g. an Anthropic `tool_result` block carrying its own parts).
fn push_object_text(parts: &mut Vec<ContentPart>, item: &serde_json::Value, depth: u8) {
    if let Some(text) = item.get("text") {
        push_text_at(parts, text, depth);
    }
    if let Some(content) = item.get("content") {
        push_text_at(parts, content, depth);
    }
}

/// Append tool-call arguments carried by one chat message
/// (`tool_calls[].function.arguments` and legacy `function_call.arguments`).
fn push_call_arguments(parts: &mut Vec<ContentPart>, message: &serde_json::Value) {
    if let Some(calls) = message.get("tool_calls").and_then(serde_json::Value::as_array) {
        for call in calls {
            if let Some(arguments) = call.get("function").and_then(|function| function.get("arguments")) {
                push_text(parts, arguments);
            }
        }
    }
    if let Some(arguments) = message.get("function_call").and_then(|call| call.get("arguments")) {
        push_text(parts, arguments);
    }
}

/// The CMF payload message for an inference request.
pub(super) fn request_message(parsed: &ParsedLlmRequest) -> Message {
    Message::with_content(Role::User, parsed.content())
}

// -----------------------------------------------------------------------------
// Normalized request parts
// -----------------------------------------------------------------------------

/// A request shape or value the parts normalizer cannot fully account for.
struct Unsupported;

/// A top-level request object.
type JsonObject = serde_json::Map<String, serde_json::Value>;

/// Normalize a Chat Completions or Anthropic Messages body.
fn normalize_parts(body: &serde_json::Value) -> Result<LlmRequestParts, Unsupported> {
    let object = body.as_object().ok_or(Unsupported)?;
    let messages = object
        .get("messages")
        .and_then(serde_json::Value::as_array)
        .ok_or(Unsupported)?;
    if !(keys_within(object, CHAT_REQUEST_KEYS) || keys_within(object, MESSAGES_REQUEST_KEYS)) {
        return Err(Unsupported);
    }
    Ok(LlmRequestParts {
        instructions: instructions(object.get("system"), messages)?,
        offered_tools: offered_tools(object)?,
        tool_choice: tool_choice(object)?,
        max_tokens: completion_cap(object)?,
        candidate_count: optional(object, "n", as_u32)?,
        temperature: optional(object, "temperature", serde_json::Value::as_f64)?,
        top_p: optional(object, "top_p", serde_json::Value::as_f64)?,
        stop_sequences: stop_sequences(object)?,
        stream: optional(object, "stream", serde_json::Value::as_bool)?,
    })
}

/// Whether every key of `object` is exactly one of `allowed`.
fn keys_within(object: &JsonObject, allowed: &[&str]) -> bool {
    object.keys().all(|key| allowed.contains(&key.as_str()))
}

/// The object `value`, when it has no key outside `allowed`.
fn strict_object<'doc>(value: &'doc serde_json::Value, allowed: &[&str]) -> Result<&'doc JsonObject, Unsupported> {
    value
        .as_object()
        .filter(|object| keys_within(object, allowed))
        .ok_or(Unsupported)
}

/// Read an optional field; `null` counts as unset, any other unreadable value is unsupported.
fn optional<'doc, T>(
    object: &'doc JsonObject,
    key: &str,
    read: impl Fn(&'doc serde_json::Value) -> Option<T>,
) -> Result<Option<T>, Unsupported> {
    match object.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => read(value).map(Some).ok_or(Unsupported),
    }
}

/// A non-negative integer that fits `u32`.
fn as_u32(value: &serde_json::Value) -> Option<u32> {
    value.as_u64().and_then(|number| u32::try_from(number).ok())
}

/// Effective completion cap: `max_completion_tokens` wins over `max_tokens`.
fn completion_cap(object: &JsonObject) -> Result<Option<u32>, Unsupported> {
    let preferred = optional(object, "max_completion_tokens", as_u32)?;
    let legacy = optional(object, "max_tokens", as_u32)?;
    Ok(preferred.or(legacy))
}

/// Ordered instructions: Anthropic's top-level `system`, then system and developer messages.
fn instructions(
    system: Option<&serde_json::Value>,
    messages: &[serde_json::Value],
) -> Result<Vec<LlmInstruction>, Unsupported> {
    let mut out = Vec::new();
    if let Some(system) = system.filter(|value| !value.is_null()) {
        push_instruction(&mut out, LlmInstructionRole::System, system)?;
    }
    for message in messages {
        strict_object(message, MESSAGE_KEYS)?;
        let role = match message.get("role").and_then(serde_json::Value::as_str) {
            Some("system") => LlmInstructionRole::System,
            Some("developer") => LlmInstructionRole::Developer,
            Some(role) if NON_INSTRUCTION_ROLES.contains(&role) => continue,
            Some(_) | None => return Err(Unsupported),
        };
        push_instruction(&mut out, role, message.get("content").ok_or(Unsupported)?)?;
    }
    Ok(out)
}

/// Append one instruction per string or text block, keeping block boundaries.
fn push_instruction(
    out: &mut Vec<LlmInstruction>,
    role: LlmInstructionRole,
    content: &serde_json::Value,
) -> Result<(), Unsupported> {
    let texts = match content {
        serde_json::Value::String(text) => vec![text.as_str()],
        serde_json::Value::Array(blocks) => blocks.iter().map(text_block).collect::<Result<_, _>>()?,
        _ => return Err(Unsupported),
    };
    out.extend(texts.into_iter().map(|text| LlmInstruction {
        role,
        text: text.to_owned(),
    }));
    Ok(())
}

/// The text of a `{"type": "text", "text": ...}` block with no unrecognized key.
fn text_block(block: &serde_json::Value) -> Result<&str, Unsupported> {
    let block = strict_object(block, TEXT_BLOCK_KEYS)?;
    block
        .get("type")
        .and_then(serde_json::Value::as_str)
        .filter(|kind| *kind == "text")
        .and_then(|_| block.get("text"))
        .and_then(serde_json::Value::as_str)
        .ok_or(Unsupported)
}

/// Parses one tool entry.
type ToolReader = fn(&serde_json::Value) -> Result<ToolMetadata, Unsupported>;

/// Every offered tool, from `tools` and the legacy `functions` list.
fn offered_tools(object: &JsonObject) -> Result<Vec<ToolMetadata>, Unsupported> {
    let mut tools = Vec::new();
    let readers: [(&str, ToolReader); 2] = [("tools", tool), ("functions", legacy_function)];
    for (key, read) in readers {
        let Some(list) = object.get(key).filter(|value| !value.is_null()) else {
            continue;
        };
        for entry in list.as_array().ok_or(Unsupported)? {
            tools.push(read(entry)?);
        }
    }
    Ok(tools)
}

/// A Chat Completions function tool or an Anthropic custom tool.
fn tool(entry: &serde_json::Value) -> Result<ToolMetadata, Unsupported> {
    match entry.get("type").map(serde_json::Value::as_str) {
        Some(Some("function")) => {
            let function = strict_object(entry, FUNCTION_TOOL_KEYS)?
                .get("function")
                .ok_or(Unsupported)?;
            named_tool(function, "parameters", FUNCTION_KEYS)
        },
        Some(Some("custom")) | None => named_tool(entry, "input_schema", CUSTOM_TOOL_KEYS),
        Some(_) => Err(Unsupported),
    }
}

/// An entry of the legacy Chat Completions `functions` list.
fn legacy_function(entry: &serde_json::Value) -> Result<ToolMetadata, Unsupported> {
    named_tool(entry, "parameters", LEGACY_FUNCTION_KEYS)
}

/// Tool metadata from an object carrying `name`, `description`, and a schema field.
fn named_tool(value: &serde_json::Value, schema_key: &str, allowed: &[&str]) -> Result<ToolMetadata, Unsupported> {
    let object = strict_object(value, allowed)?;
    let name = optional(object, "name", serde_json::Value::as_str)?
        .filter(|name| !name.is_empty())
        .ok_or(Unsupported)?;
    Ok(ToolMetadata {
        name: name.to_owned(),
        description: optional(object, "description", serde_json::Value::as_str)?.map(str::to_owned),
        input_schema: object.get(schema_key).filter(|schema| !schema.is_null()).cloned(),
        ..ToolMetadata::default()
    })
}

/// Tool choice from `tool_choice` or the legacy `function_call`; both at once is ambiguous.
fn tool_choice(object: &JsonObject) -> Result<Option<ToolChoice>, Unsupported> {
    match (
        optional(object, "tool_choice", read_tool_choice)?,
        optional(object, "function_call", read_function_call)?,
    ) {
        (Some(_), Some(_)) => Err(Unsupported),
        (choice, legacy) => Ok(choice.or(legacy)),
    }
}

/// A Chat Completions or Anthropic `tool_choice`.
fn read_tool_choice(value: &serde_json::Value) -> Option<ToolChoice> {
    if let Some(mode) = value.as_str() {
        return match mode {
            "auto" => Some(ToolChoice::Auto),
            "none" => Some(ToolChoice::None),
            "required" => Some(ToolChoice::Required),
            _ => None,
        };
    }
    match value.get("type")?.as_str()? {
        "function" => forced_tool(value.get("function")?),
        "tool" => forced_tool(value),
        "auto" => Some(ToolChoice::Auto),
        "any" => Some(ToolChoice::Required),
        "none" => Some(ToolChoice::None),
        _ => None,
    }
}

/// A legacy `function_call`: `"auto"`, `"none"`, or `{"name": ...}`.
fn read_function_call(value: &serde_json::Value) -> Option<ToolChoice> {
    match value.as_str() {
        Some("auto") => Some(ToolChoice::Auto),
        Some("none") => Some(ToolChoice::None),
        Some(_) => None,
        None => forced_tool(value),
    }
}

/// A choice that forces the tool named by `value.name`.
fn forced_tool(value: &serde_json::Value) -> Option<ToolChoice> {
    value
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.is_empty())
        .map(|name| ToolChoice::Tool { name: name.to_owned() })
}

/// Stop sequences from `stop` (string or array) and `stop_sequences`.
fn stop_sequences(object: &JsonObject) -> Result<Vec<String>, Unsupported> {
    let mut out = Vec::new();
    for key in ["stop", "stop_sequences"] {
        match object.get(key) {
            None | Some(serde_json::Value::Null) => {},
            Some(serde_json::Value::String(stop)) => out.push(stop.clone()),
            Some(serde_json::Value::Array(items)) => {
                for item in items {
                    out.push(item.as_str().ok_or(Unsupported)?.to_owned());
                }
            },
            Some(_) => return Err(Unsupported),
        }
    }
    Ok(out)
}

// -----------------------------------------------------------------------------
// Strict JSON parsing
// -----------------------------------------------------------------------------

/// Builds a [`serde_json::Value`] and records any repeated object key.
///
/// `serde_json` drives the parse, so its number handling and recursion limit
/// apply unchanged. A repeated key is recorded rather than raised, so the
/// parse still reaches any later syntax error and malformed input stays
/// distinguishable from valid JSON with duplicates.
#[derive(Clone, Copy)]
struct UniqueKeys<'a> {
    /// Set when an object repeats a key.
    duplicate: &'a Cell<bool>,
}

impl<'de> serde::de::DeserializeSeed<'de> for UniqueKeys<'_> {
    type Value = serde_json::Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> serde::de::Visitor<'de> for UniqueKeys<'_> {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(v.into()))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E> {
        Ok(serde_json::Number::from_f64(v).map_or(serde_json::Value::Null, serde_json::Value::Number))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(item) = seq.next_element_seed(self)? {
            items.push(item);
        }
        Ok(serde_json::Value::Array(items))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut object = serde_json::Map::new();
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value_seed(self)?;
            // Go backends also match JSON field names without regard to case.
            if !seen.insert(unicase::UniCase::new(key.as_str()).to_folded_case()) {
                self.duplicate.set(true);
            }
            object.insert(key, value);
        }
        Ok(serde_json::Value::Object(object))
    }
}

// -----------------------------------------------------------------------------
// Response side
// -----------------------------------------------------------------------------

/// An inference response body parsed once for the response phase.
pub(super) struct ParsedLlmResponse(serde_json::Value);

impl ParsedLlmResponse {
    /// Parse `body`; malformed or empty input yields a `Null` document.
    pub(super) fn parse(body: &Bytes) -> Self {
        Self(serde_json::from_slice(body).unwrap_or(serde_json::Value::Null))
    }

    /// Whether the body is a JSON object.
    pub(super) fn is_object(&self) -> bool {
        self.0.is_object()
    }

    /// Build metadata for the `completion.*` attributes.
    pub(super) fn completion(&self) -> CompletionExtension {
        CompletionExtension {
            model: self
                .0
                .get("model")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            tokens: self.token_usage(),
            stop_reason: self.stop_reason(),
            ..Default::default()
        }
    }

    /// Token counts, when the response reported any.
    fn token_usage(&self) -> Option<TokenUsage> {
        let usage = self.0.get("usage")?;
        let input = count(usage, "prompt_tokens").or_else(|| count(usage, "input_tokens"));
        let output = count(usage, "completion_tokens").or_else(|| count(usage, "output_tokens"));
        let total = count(usage, "total_tokens");
        // Anthropic omits the total, so derive it for provider-neutral rules.
        let total = total.or_else(|| {
            (input.is_some() || output.is_some()).then(|| input.unwrap_or(0).saturating_add(output.unwrap_or(0)))
        });
        (input.is_some() || output.is_some() || total.is_some()).then(|| TokenUsage {
            input_tokens: input.unwrap_or(0),
            output_tokens: output.unwrap_or(0),
            total_tokens: total.unwrap_or(0),
        })
    }

    /// Map a recognized provider stop reason to CMF.
    fn stop_reason(&self) -> Option<StopReason> {
        let raw = self
            .0
            .get("choices")
            .and_then(serde_json::Value::as_array)
            .and_then(|choices| choices.first())
            .and_then(|choice| choice.get("finish_reason"))
            .or_else(|| self.0.get("stop_reason"))
            .and_then(serde_json::Value::as_str)?;
        match raw {
            "stop" | "end_turn" => Some(StopReason::End),
            "length" | "max_tokens" => Some(StopReason::MaxTokens),
            "tool_calls" | "function_call" | "tool_use" => Some(StopReason::Call),
            "stop_sequence" => Some(StopReason::StopSequence),
            _ => None,
        }
    }

    /// The assistant text, as CMF content.
    pub(super) fn content(&self) -> Vec<ContentPart> {
        let mut parts = Vec::new();

        if let Some(choices) = self.0.get("choices").and_then(serde_json::Value::as_array) {
            for choice in choices {
                if let Some(content) = choice.get("message").and_then(|message| message.get("content")) {
                    push_text(&mut parts, content);
                }
                if let Some(text) = choice.get("text") {
                    push_text(&mut parts, text);
                }
            }
        }

        if let Some(content) = self.0.get("content") {
            push_text(&mut parts, content);
        }

        parts
    }
}

/// Read a token count, rounding up fractions and saturating at `u32::MAX`.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is finite, non-negative, and clamped below u32::MAX before the cast"
)]
fn count(usage: &serde_json::Value, field: &str) -> Option<u32> {
    let value = usage.get(field)?;
    if let Some(exact) = value.as_u64() {
        return Some(u32::try_from(exact).unwrap_or(u32::MAX));
    }
    value.as_f64().filter(|n| n.is_finite() && *n >= 0.0).map(|n| {
        let ceiled = n.ceil();
        if ceiled >= f64::from(u32::MAX) {
            u32::MAX
        } else {
            ceiled as u32
        }
    })
}

/// The CMF payload message for an inference response.
pub(super) fn response_message(parsed: &ParsedLlmResponse) -> Message {
    Message::with_content(Role::Assistant, parsed.content())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn reads_top_level_model() {
        assert_eq!(request(r#"{"model":"gpt-4o"}"#).model(), Some("gpt-4o"));
    }

    #[test]
    fn surrounding_whitespace_is_trimmed_from_the_model() {
        assert_eq!(
            request(r#"{"model":"  gpt-4o  "}"#).model(),
            Some("gpt-4o"),
            "the trimmed value is what routes match, so a padded model cannot slip past an \
             exact `llm:` selector",
        );
    }

    #[test]
    fn unusable_models_report_none() {
        for body in [
            "{}",
            r#"{"model":null}"#,
            r#"{"model":42}"#,
            r#"{"model":""}"#,
            r#"{"model":"   "}"#,
            r#"{"model":{"name":"gpt-4o"}}"#,
            r#"{"model":"gpt-4o\r\nX-Injected: yes"}"#,
            r#"{"model":"gpt\u00004o"}"#,
            r#"["gpt-4o"]"#,
            "not json",
            "",
        ] {
            assert_eq!(request(body).model(), None, "body {body} must not yield a model");
        }
    }

    #[test]
    fn an_over_long_model_is_not_usable() {
        let at_limit = "m".repeat(MAX_MODEL_BYTES);
        assert_eq!(
            request(&format!(r#"{{"model":"{at_limit}"}}"#)).model(),
            Some(at_limit.as_str()),
            "a model at the metadata ceiling is still usable",
        );

        let over_limit = "m".repeat(MAX_MODEL_BYTES + 1);
        assert_eq!(
            request(&format!(r#"{{"model":"{over_limit}"}}"#)).model(),
            None,
            "past the ceiling the model would not reach `llm.model`, so the request must fail \
             closed rather than be authorized with no record of what it asked for",
        );
    }

    #[test]
    fn duplicate_model_keys_are_rejected() {
        assert!(
            matches!(
                try_request(r#"{"model":"gpt-4o-mini","model":"gpt-4o"}"#),
                Err(DuplicateKey)
            ),
            "backends disagree on which copy wins, so policy cannot know which model it judges",
        );
    }

    #[test]
    fn duplicate_top_level_tools_are_rejected() {
        assert!(
            matches!(
                try_request(
                    r#"{"model":"m","tools":[{"type":"function","function":{"name":"transfer_funds"}}],"tools":[]}"#
                ),
                Err(DuplicateKey)
            ),
            "a second `tools` could hide the first from policy while the backend acts on it",
        );
    }

    #[test]
    fn case_variant_keys_are_rejected_at_every_depth() {
        for body in [
            r#"{"model":"allowed","MODEL":"forbidden"}"#,
            r#"{"model":"m","tools":[],"Tools":[{"name":"forbidden"}]}"#,
            r#"{"model":"m","tools":[],"toolſ":[{"name":"forbidden"}]}"#,
            r#"{"model":"m","tools":[{"function":{"name":"allowed","Name":"forbidden"}}]}"#,
        ] {
            assert!(
                matches!(try_request(body), Err(DuplicateKey)),
                "case variants can name the same backend field: {body}"
            );
        }
    }

    #[test]
    fn a_duplicate_nested_key_is_rejected() {
        assert!(
            matches!(
                try_request(
                    r#"{"model":"m","tools":[{"type":"function","function":{"name":"lookup","name":"transfer_funds"}}]}"#
                ),
                Err(DuplicateKey)
            ),
            "a repeated key deep inside `tools` is as ambiguous as one at the top",
        );
    }

    #[test]
    fn a_key_repeated_in_sibling_objects_is_not_a_duplicate() {
        let parsed = request(r#"{"model":"m","tools":[{"name":"a"},{"name":"b"}],"name":"c"}"#);
        assert_eq!(parsed.model(), Some("m"), "each object has its own key namespace");
    }

    #[test]
    fn a_duplicate_is_found_after_escape_decoding() {
        assert!(
            matches!(try_request(r#"{"model":"m","mod\u0065l":"other"}"#), Err(DuplicateKey)),
            "an escaped spelling names the same key once decoded",
        );
    }

    #[test]
    fn malformed_json_is_not_reported_as_a_duplicate() {
        for body in [
            "not json",
            "",
            r#"{"model":"m""#,
            r#"{"model":"m"} trailing"#,
            r#"{"model":"m","model""#,
            r#"{"model":"m","model":"n"} trailing"#,
        ] {
            assert!(
                try_request(body).is_ok_and(|parsed| parsed.into_value().is_null()),
                "body {body} is malformed, not a duplicate, so it must yield a null document",
            );
        }
    }

    #[test]
    fn a_body_without_duplicates_matches_serde_json() {
        for body in [
            r#"{"model":"m","temperature":0.7,"n":1,"seed":-42,"stop":null,"stream":true}"#,
            r#"{"model":"m","big":18446744073709551615,"bigger":18446744073709551616,"neg":-9223372036854775808}"#,
            r#"{"model":"m","exp":1e300,"tiny":5e-324,"frac":1.000000000000000000001}"#,
            r#"{"model":"\u00e9\ud83d\ude00","messages":[{"content":"caf\u00e9 \"quoted\" \\ \n"}]}"#,
            r#"{"z":1,"a":2,"m":{"y":[1,[2,{"x":null}]],"b":false}}"#,
            r#"[1,"two",{"three":3}]"#,
            r#""scalar""#,
            "  {\"model\" : \"m\"}  ",
        ] {
            let strict = request(body).into_value();
            let reference: serde_json::Value = serde_json::from_slice(body.as_bytes()).unwrap();
            assert_eq!(strict, reference, "body {body} must parse as serde_json parses it");
            assert_eq!(
                serde_json::to_string(&strict).unwrap(),
                serde_json::to_string(&reference).unwrap(),
                "key order and number spelling must match too for body {body}",
            );
        }
    }

    #[test]
    fn nesting_past_the_recursion_limit_stays_malformed() {
        let depth = 129;
        let body = format!(r#"{{"model":"m","deep":{}{}}}"#, "[".repeat(depth), "]".repeat(depth));
        assert!(
            try_request(&body).is_ok_and(|parsed| parsed.into_value().is_null()),
            "deep nesting is not a duplicate, and serde_json's recursion limit still applies, \
             so the body is malformed",
        );

        let depth = 100;
        let body = format!(r#"{{"model":"m","deep":{}{}}}"#, "[".repeat(depth), "]".repeat(depth));
        assert_eq!(
            request(&body).model(),
            Some("m"),
            "nesting under the limit still parses"
        );
    }

    #[test]
    fn large_shallow_padding_does_not_change_serde_depth_or_duplicate_semantics() {
        let padding = "x".repeat(900_000);
        for depth in [125, 126, 127, 128, 129] {
            let body = format!(
                r#"{{"padding":"{padding}","deep":{}0{},"model":"m"}}"#,
                "[".repeat(depth),
                "]".repeat(depth)
            );
            let reference = serde_json::from_str::<serde_json::Value>(&body);
            let parsed = try_request(&body).unwrap().into_value();
            assert_eq!(parsed, reference.unwrap_or(serde_json::Value::Null), "depth {depth}");
        }
        let duplicate = format!(r#"{{"model":"m","padding":"{padding}","mo\u0064el":"n"}}"#);
        assert!(matches!(try_request(&duplicate), Err(DuplicateKey)));
        let malformed = format!("{duplicate} trailing");
        assert!(try_request(&malformed).unwrap().into_value().is_null());
    }

    #[test]
    fn the_last_wins_parse_keeps_serde_json_semantics() {
        assert_eq!(
            ParsedLlmRequest::parse_last_wins(&Bytes::from_static(br#"{"model":"a","model":"b"}"#)).model(),
            Some("b"),
        );
        assert!(
            ParsedLlmRequest::parse_last_wins(&Bytes::from_static(b"not json"))
                .into_value()
                .is_null()
        );
    }

    #[test]
    fn detects_the_streaming_flag() {
        assert!(request(r#"{"model":"m","stream":true}"#).is_streaming());
        assert!(!request(r#"{"model":"m","stream":false}"#).is_streaming());
        assert!(!request(r#"{"model":"m"}"#).is_streaming());
    }

    #[test]
    fn every_spelling_a_backend_honors_reads_as_streaming() {
        for body in [
            r#"{"model":"m","stream":"true"}"#,
            r#"{"model":"m","stream":"TRUE"}"#,
            r#"{"model":"m","stream":" true "}"#,
            r#"{"model":"m","stream":"yes"}"#,
            r#"{"model":"m","stream":"on"}"#,
            r#"{"model":"m","stream":"1"}"#,
            r#"{"model":"m","stream":1}"#,
        ] {
            assert!(
                request(body).is_streaming(),
                "body {body} streams on a lax backend, so policy must read it as streaming",
            );
        }
        for body in [
            r#"{"model":"m","stream":"false"}"#,
            r#"{"model":"m","stream":"0"}"#,
            r#"{"model":"m","stream":0}"#,
            r#"{"model":"m","stream":"maybe"}"#,
        ] {
            assert!(!request(body).is_streaming(), "body {body} must not read as streaming");
        }
    }

    #[test]
    fn a_boolean_param_is_promoted_as_a_bool_whatever_the_client_wrote() {
        let names = vec!["stream".to_owned(), "n".to_owned()];
        let promoted = request(r#"{"model":"m","stream":"true","n":1}"#).promoted_params(&names);

        assert_eq!(
            promoted.get("stream"),
            Some(&serde_json::json!(true)),
            "APL reads custom.llm.stream with get_bool, so a string spelling has to arrive as a bool",
        );
        assert_eq!(
            promoted.get("n"),
            Some(&serde_json::json!(1)),
            "a numeric param must stay numeric; normalizing it would break an order comparison",
        );
    }

    #[test]
    fn promotes_only_configured_scalars() {
        let names = vec![
            "stream".to_owned(),
            "max_tokens".to_owned(),
            "tools".to_owned(),
            "absent".to_owned(),
        ];
        let promoted = request(r#"{"model":"m","stream":true,"max_tokens":16,"tools":[{"a":1}],"top_p":1}"#)
            .promoted_params(&names);

        assert_eq!(promoted.get("stream"), Some(&serde_json::json!(true)));
        assert_eq!(promoted.get("max_tokens"), Some(&serde_json::json!(16)));
        assert!(!promoted.contains_key("tools"), "arrays must not be promoted");
        assert!(!promoted.contains_key("absent"));
        assert!(!promoted.contains_key("top_p"), "unlisted fields must not be promoted");
    }

    #[test]
    fn a_configured_list_replaces_the_defaults_rather_than_extending_them() {
        let parsed = request(r#"{"model":"m","stream":true,"max_tokens":16}"#);
        let promoted = parsed.promoted_params(&["max_tokens".to_owned()]);

        assert_eq!(promoted.get("max_tokens"), Some(&serde_json::json!(16)));
        assert!(
            !promoted.contains_key("stream"),
            "naming only max_tokens drops `stream`, which the default covered — the operator has \
             to list every field their rules read",
        );
    }

    #[test]
    fn builds_content_from_openai_chat_messages() {
        let parsed = request(
            r#"{"model":"gpt-4o","messages":[
                 {"role":"system","content":"be terse"},
                 {"role":"user","content":"hello"}]}"#,
        );
        assert_eq!(texts(&parsed.content()), vec!["be terse", "hello"]);
    }

    #[test]
    fn builds_content_from_multimodal_parts() {
        let parsed = request(
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":[
                 {"type":"text","text":"describe"},
                 {"type":"image_url","image_url":{"url":"http://x/y.png"}},
                 {"type":"text","text":"briefly"}]}]}"#,
        );
        assert_eq!(
            texts(&parsed.content()),
            vec!["describe", "briefly"],
            "text parts are collected in order and non-text parts contribute nothing",
        );
    }

    #[test]
    fn builds_content_from_legacy_prompt() {
        assert_eq!(texts(&request(r#"{"model":"m","prompt":"hi"}"#).content()), vec!["hi"]);
    }

    #[test]
    fn builds_content_from_anthropic_system_and_messages() {
        let parsed =
            request(r#"{"model":"claude","system":"be terse","messages":[{"role":"user","content":"hello"}]}"#);
        assert_eq!(
            texts(&parsed.content()),
            vec!["be terse", "hello"],
            "the separate system prompt must reach the scanner too",
        );
    }

    #[test]
    fn builds_content_from_responses_instructions() {
        let parsed =
            request(r#"{"model":"gpt-4o","instructions":"be terse","input":[{"role":"user","content":"hello"}]}"#);
        assert_eq!(
            texts(&parsed.content()),
            vec!["be terse", "hello"],
            "Responses `instructions` is a system prompt, so a scanner must read it before `input`",
        );
    }

    #[test]
    fn input_is_projected_even_when_messages_is_present() {
        for messages in ["null", "[]", r#"[{"content":"chat"}]"#] {
            let body = format!(r#"{{"model":"m","messages":{messages},"input":"hidden"}}"#);
            let content = texts(&request(&body).content());
            assert!(
                content.iter().any(|part| part == "hidden"),
                "a messages field cannot hide Responses input: {body}"
            );
        }
    }

    #[test]
    fn unknown_body_shape_yields_no_content_but_keeps_the_model() {
        let parsed = request(r#"{"model":"m","inputs":{"nested":"value"}}"#);
        assert!(parsed.content().is_empty());
        assert_eq!(parsed.model(), Some("m"), "authorization never depends on the prompt");
    }

    #[test]
    fn builds_content_from_nested_tool_result_parts() {
        let parsed = request(
            r#"{"model":"claude","messages":[{"role":"user","content":[
                {"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"tool says hi"}]}]}]}"#,
        );
        assert_eq!(
            texts(&parsed.content()),
            vec!["tool says hi"],
            "nested tool_result text must reach the scanner",
        );
    }

    #[test]
    fn builds_content_from_tool_call_arguments() {
        let parsed = request(
            r#"{"model":"gpt-4o","messages":[{"role":"assistant","content":null,
                "tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"q\":1}"}}]},
                {"role":"assistant","function_call":{"name":"g","arguments":"legacy"}}]}"#,
        );
        assert_eq!(
            texts(&parsed.content()),
            vec![r#"{"q":1}"#, "legacy"],
            "tool-call arguments must reach the scanner",
        );
    }

    #[test]
    fn builds_content_from_responses_api_input_items() {
        let parsed = request(
            r#"{"model":"gpt-4o","input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]},
                {"type":"function_call_output","call_id":"c1","output":"result"}]}"#,
        );
        assert_eq!(
            texts(&parsed.content()),
            vec!["hello", "result"],
            "Responses API input items must reach the scanner",
        );
    }

    #[test]
    fn content_depth_is_bounded() {
        let parsed = request(
            r#"{"model":"m","messages":[{"role":"user","content":[{"content":[{"content":[{"content":
                [{"content":[{"content":[{"text":"too deep"}]}]}]}]}]}]}]}"#,
        );
        assert!(parsed.content().is_empty(), "parts beyond the depth cap are not walked");
    }

    #[test]
    fn embeddings_array_input_is_projected() {
        let parsed = request(r#"{"model":"text-embedding-3-small","input":["a","b"]}"#);
        assert_eq!(texts(&parsed.content()), vec!["a", "b"]);
    }

    #[test]
    fn embeddings_string_input_is_projected() {
        let parsed = request(r#"{"model":"text-embedding-3-small","input":"hello"}"#);
        assert_eq!(parsed.model(), Some("text-embedding-3-small"));
        assert_eq!(
            texts(&parsed.content()),
            vec!["hello"],
            "a string `input` is prompt text a policy must be able to read",
        );
        assert!(parsed.into_value().is_object());
    }

    #[test]
    fn builds_content_from_responses_input_text_parts() {
        let parsed =
            request(r#"{"model":"gpt-4o","input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}]}"#);
        assert_eq!(texts(&parsed.content()), vec!["hi"]);
    }

    #[test]
    fn token_id_input_projects_nothing() {
        for body in [
            r#"{"model":"m","input":[1,2,3]}"#,
            r#"{"model":"m","input":[[1,2,3]]}"#,
            r#"{"model":"m","input":[[1,2],[3]]}"#,
        ] {
            assert!(request(body).content().is_empty(), "token IDs are not text: {body}");
        }
    }

    #[test]
    fn non_text_input_parts_are_skipped() {
        let parsed = request(
            r#"{"model":"m","input":[{"role":"user","content":[
                 {"type":"input_text","text":"describe"},
                 {"type":"input_image","image_url":"http://x/y.png","text":"hidden"},
                 {"type":"input_file","file_id":"f1"},
                 {"type":"output_text","text":"earlier"}]}]}"#,
        );
        assert_eq!(texts(&parsed.content()), vec!["describe", "earlier"]);
    }

    #[test]
    fn function_call_input_items_are_projected() {
        let parsed = request(
            r#"{"model":"m","input":[
                 {"type":"function_call","call_id":"c1","name":"f","arguments":"{\"q\":\"x\"}"},
                 {"type":"function_call_output","call_id":"c1","output":"result"},
                 {"type":"message","role":"user","content":"next"}]}"#,
        );
        assert_eq!(
            texts(&parsed.content()),
            vec![r#"{"q":"x"}"#, "result", "next"],
            "function inputs and outputs are part of the context the policy scans",
        );
    }

    #[test]
    fn custom_tool_call_outputs_are_projected() {
        let parsed = request(
            r#"{"model":"m","input":[
                 {"type":"custom_tool_call_output","call_id":"c1","output":"first"},
                 {"type":"custom_tool_call_output","call_id":"c2","output":[
                     {"type":"input_text","text":"second"},
                     {"type":"input_image","image_url":"http://x/y.png"}]}]}"#,
        );
        assert_eq!(
            texts(&parsed.content()),
            vec!["first", "second"],
            "custom-tool output text must reach prompt rules and scanners",
        );
    }

    #[test]
    fn unlisted_tool_history_items_are_projected() {
        let parsed = request(
            r#"{"model":"m","input":[
                 {"type":"local_shell_call_output","call_id":"c1","output":"shell"},
                 {"type":"custom_tool_call","call_id":"c2","name":"run","input":"custom"},
                 {"type":"reasoning","id":"r1",
                  "summary":[{"type":"summary_text","text":"summary"}],
                  "content":[{"type":"reasoning_text","text":"reasoning"}]},
                 {"type":"future_tool_output","output":"unknown"}]}"#,
        );
        assert_eq!(
            texts(&parsed.content()),
            vec!["shell", "custom", "reasoning", "summary", "unknown"],
            "an item type outside the known set must not hide its text from scanners",
        );
    }

    #[test]
    fn standard_responses_history_fields_are_projected() {
        let parsed = request(
            r#"{"model":"m","input":[
                {"type":"file_search_call","results":[{"text":"search result"}]},
                {"type":"code_interpreter_call","code":"print(1)","outputs":[{"type":"logs","logs":"execution log"}]},
                {"type":"mcp_list_tools","tools":[{"name":"lookup","description":"tool description"}]}]}"#,
        );
        assert_eq!(
            texts(&parsed.content()),
            vec!["search result", "print(1)", "execution log", "tool description"],
        );
    }

    #[test]
    fn non_text_parts_of_tool_outputs_are_skipped() {
        let parsed = request(
            r#"{"model":"m","input":[
                 {"type":"function_call_output","call_id":"c1","output":[
                     {"type":"input_text","text":"kept"},
                     {"type":"input_image","text":"dropped","image_url":"http://x/y.png"}]}]}"#,
        );
        assert_eq!(
            texts(&parsed.content()),
            vec!["kept"],
            "tool outputs filter part types the same way message content does",
        );
    }

    #[test]
    fn mcp_call_arguments_and_outputs_are_projected() {
        let parsed = request(
            r#"{"model":"m","input":[
                 {"role":"user","content":"before"},
                 {"type":"mcp_call","id":"mcp1","name":"lookup","server_label":"server",
                  "arguments":"{\"q\":\"query\"}","output":"result"},
                 {"role":"user","content":"after"}]}"#,
        );
        assert_eq!(
            texts(&parsed.content()),
            vec!["before", r#"{"q":"query"}"#, "result", "after"],
            "MCP arguments and output must reach prompt rules and scanners in context order",
        );
    }

    #[test]
    fn string_input_items_mix_with_message_items() {
        let parsed = request(
            r#"{"model":"m","input":["first",{"role":"user","content":"second"},
                 {"role":"user","content":[{"text":"third"}]}]}"#,
        );
        assert_eq!(texts(&parsed.content()), vec!["first", "second", "third"]);
    }

    #[test]
    fn reads_openai_usage_and_finish_reason() {
        let completion = response(
            r#"{"model":"gpt-4o","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15},
                "choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"hi"}}]}"#,
        )
        .completion();

        assert_eq!(completion.model.as_deref(), Some("gpt-4o"));
        let tokens = completion.tokens.unwrap();
        assert_eq!(
            (tokens.input_tokens, tokens.output_tokens, tokens.total_tokens),
            (10, 5, 15)
        );
        assert_eq!(completion.stop_reason, Some(StopReason::End));
    }

    #[test]
    fn derives_the_total_for_a_provider_that_reports_only_halves() {
        let tokens = response(r#"{"usage":{"input_tokens":7,"output_tokens":3}}"#)
            .completion()
            .tokens
            .unwrap();
        assert_eq!(
            tokens.total_tokens, 10,
            "one rule on completion.tokens.total must work for both"
        );
    }

    #[test]
    fn a_partially_reported_usage_still_totals() {
        let tokens = response(r#"{"usage":{"output_tokens":5000}}"#)
            .completion()
            .tokens
            .unwrap();
        assert_eq!(
            (tokens.input_tokens, tokens.output_tokens, tokens.total_tokens),
            (0, 5000, 5000),
            "a provider that omits the prompt half must not read as zero total: a budget rule \
             would admit the response",
        );
    }

    #[test]
    fn out_of_range_counts_saturate_rather_than_vanishing() {
        let huge = response(r#"{"usage":{"total_tokens":99999999999}}"#)
            .completion()
            .tokens
            .unwrap();
        assert_eq!(
            huge.total_tokens,
            u32::MAX,
            "clamping keeps a budget rule firing; dropping the field would read as zero",
        );

        let fractional = response(r#"{"usage":{"total_tokens":1000.4}}"#)
            .completion()
            .tokens
            .unwrap();
        assert_eq!(
            fractional.total_tokens, 1001,
            "a fractional count rounds up, never down"
        );

        assert!(
            response(r#"{"usage":{"total_tokens":-5}}"#)
                .completion()
                .tokens
                .is_none(),
            "a negative count is not a count",
        );
    }

    #[test]
    fn absent_usage_leaves_tokens_unset() {
        assert!(
            response(r#"{"model":"m"}"#).completion().tokens.is_none(),
            "a rule must be able to tell \"no usage reported\" from \"zero tokens\"",
        );
        assert!(
            response(r#"{"usage":{}}"#).completion().tokens.is_none(),
            "an empty usage object reports nothing, so it must not read as zero",
        );
    }

    #[test]
    fn maps_known_stop_reasons_and_leaves_unknown_unset() {
        for (raw, expected) in [
            ("stop", Some(StopReason::End)),
            ("end_turn", Some(StopReason::End)),
            ("length", Some(StopReason::MaxTokens)),
            ("max_tokens", Some(StopReason::MaxTokens)),
            ("tool_calls", Some(StopReason::Call)),
            ("tool_use", Some(StopReason::Call)),
            ("stop_sequence", Some(StopReason::StopSequence)),
            ("content_filter", None),
        ] {
            let body = format!(r#"{{"choices":[{{"finish_reason":"{raw}"}}]}}"#);
            assert_eq!(response(&body).completion().stop_reason, expected, "reason {raw}");
        }
    }

    #[test]
    fn reads_anthropic_top_level_stop_reason() {
        assert_eq!(
            response(r#"{"stop_reason":"end_turn"}"#).completion().stop_reason,
            Some(StopReason::End),
        );
    }

    #[test]
    fn builds_response_content_for_each_provider_shape() {
        assert_eq!(
            texts(&response(r#"{"choices":[{"message":{"content":"chat"}}]}"#).content()),
            vec!["chat"],
        );
        assert_eq!(
            texts(&response(r#"{"choices":[{"text":"legacy"}]}"#).content()),
            vec!["legacy"]
        );
        assert_eq!(
            texts(&response(r#"{"content":[{"type":"text","text":"anthropic"}]}"#).content()),
            vec!["anthropic"],
        );
    }

    #[test]
    fn malformed_response_is_not_an_object() {
        assert!(!response("not json").is_object());
        assert!(!response("[1,2]").is_object());
        assert!(response(r#"{"model":"m"}"#).is_object());
    }

    #[test]
    fn messages_carry_the_cmf_roles_their_phase_implies() {
        assert!(matches!(request_message(&request(r#"{"model":"m"}"#)).role, Role::User));
        assert!(matches!(
            response_message(&response(r#"{"model":"m"}"#)).role,
            Role::Assistant
        ));
    }

    mod properties {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn strict_parse_matches_serde_json_without_duplicates(value in json_value()) {
                let body = serde_json::to_string(&value).unwrap();
                let reference: serde_json::Value = serde_json::from_str(&body).unwrap();
                prop_assert!(
                    try_request(&body).is_ok_and(|parsed| parsed.into_value() == reference),
                    "body {} must parse as serde_json parses it",
                    body,
                );
            }

            #[test]
            fn a_repeated_key_is_always_rejected(
                key in "[a-z]{1,8}",
                first in json_value(),
                second in json_value(),
                outer in json_value(),
            ) {
                let key = serde_json::to_string(&key).unwrap();
                let body = format!(
                    r#"{{"model":"m","outer":{},"nested":[{{{key}:{},{key}:{}}}]}}"#,
                    serde_json::to_string(&outer).unwrap(),
                    serde_json::to_string(&first).unwrap(),
                    serde_json::to_string(&second).unwrap(),
                );
                prop_assert!(
                    matches!(try_request(&body), Err(DuplicateKey)),
                    "body {} repeats a key and must be rejected",
                    body,
                );
            }
        }

        /// Arbitrary JSON documents with unique keys per object.
        fn json_value() -> impl Strategy<Value = serde_json::Value> {
            let leaf = prop_oneof![
                Just(serde_json::Value::Null),
                any::<bool>().prop_map(serde_json::Value::Bool),
                any::<i64>().prop_map(serde_json::Value::from),
                any::<u64>().prop_map(serde_json::Value::from),
                any::<f64>()
                    .prop_filter("finite", |n| n.is_finite())
                    .prop_map(serde_json::Value::from),
                any::<String>().prop_map(serde_json::Value::String),
            ];
            leaf.prop_recursive(4, 32, 6, |inner| {
                prop_oneof![
                    prop::collection::vec(inner.clone(), 0..6).prop_map(serde_json::Value::Array),
                    prop::collection::btree_map(any::<String>(), inner, 0..6)
                        .prop_map(|map| serde_json::Value::Object(map.into_iter().collect())),
                ]
            })
        }
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "one request covering every normalized field")]
    fn chat_request_parts_are_normalized() {
        let parts = request(
            r#"{"model":"gpt-4o","messages":[
                {"role":"system","content":"be terse"},
                {"role":"user","content":"hi"},
                {"role":"developer","content":[{"type":"text","text":"no salaries"}]}
            ],
            "tools":[{"type":"function","function":{"name":"search","description":"web","parameters":{"type":"object"}}}],
            "tool_choice":{"type":"function","function":{"name":"search"}},
            "max_completion_tokens":512,"n":2,"stop":["END","STOP"],
            "temperature":0.5,"top_p":0.9,"stream":true}"#,
        )
        .parts()
        .unwrap();

        let instructions: Vec<_> = parts.instructions.iter().map(|i| (i.role, i.text.as_str())).collect();
        assert_eq!(
            instructions,
            [
                (LlmInstructionRole::System, "be terse"),
                (LlmInstructionRole::Developer, "no salaries")
            ],
        );
        assert_eq!(parts.offered_tools.len(), 1);
        assert_eq!(parts.offered_tools[0].name, "search");
        assert_eq!(parts.offered_tools[0].description.as_deref(), Some("web"));
        assert!(parts.offered_tools[0].input_schema.is_some());
        assert_eq!(
            parts.tool_choice,
            Some(ToolChoice::Tool {
                name: "search".to_owned()
            })
        );
        assert_eq!(parts.max_tokens, Some(512));
        assert_eq!(parts.candidate_count, Some(2));
        assert_eq!(parts.stop_sequences, ["END", "STOP"]);
        assert_eq!(parts.temperature, Some(0.5));
        assert_eq!(parts.top_p, Some(0.9));
        assert_eq!(parts.stream, Some(true));
    }

    #[test]
    fn unset_optional_parts_stay_absent() {
        let parts = request(r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#)
            .parts()
            .unwrap();
        assert!(parts.instructions.is_empty());
        assert!(parts.offered_tools.is_empty());
        assert!(parts.stop_sequences.is_empty());
        assert_eq!(parts.tool_choice, None);
        assert_eq!(parts.max_tokens, None);
        assert_eq!(parts.candidate_count, None);
        assert_eq!(parts.temperature, None);
        assert_eq!(parts.stream, None);
    }

    #[test]
    fn instruction_order_is_preserved() {
        let forward =
            request(r#"{"model":"m","messages":[{"role":"system","content":"a"},{"role":"developer","content":"b"}]}"#)
                .parts()
                .unwrap();
        let reversed =
            request(r#"{"model":"m","messages":[{"role":"developer","content":"b"},{"role":"system","content":"a"}]}"#)
                .parts()
                .unwrap();
        let digest =
            |parts: &LlmRequestParts| ppe::praxis_policy_apl_cmf::llm::instruction_digest(&parts.instructions).unwrap();
        assert!(digest(&forward).starts_with("sha256-v1:"));
        assert_ne!(
            digest(&forward),
            digest(&reversed),
            "reordered instructions must not pin the same digest"
        );
    }

    #[test]
    fn max_completion_tokens_wins_over_max_tokens() {
        let parts = request(r#"{"model":"m","messages":[],"max_tokens":4096,"max_completion_tokens":256}"#)
            .parts()
            .unwrap();
        assert_eq!(parts.max_tokens, Some(256));
        let legacy = request(r#"{"model":"m","messages":[],"max_tokens":4096}"#)
            .parts()
            .unwrap();
        assert_eq!(legacy.max_tokens, Some(4096));
    }

    #[test]
    fn anthropic_messages_parts_are_normalized() {
        let parts = request(
            r#"{"model":"claude","system":[{"type":"text","text":"s1"},{"type":"text","text":"s2"}],
            "messages":[{"role":"user","content":"hi"}],
            "tools":[{"name":"get_weather","input_schema":{"type":"object"}}],
            "tool_choice":{"type":"any"},"max_tokens":1024,"stop_sequences":["\n\nHuman:"]}"#,
        )
        .parts()
        .unwrap();
        let texts: Vec<_> = parts.instructions.iter().map(|i| i.text.as_str()).collect();
        assert_eq!(texts, ["s1", "s2"]);
        assert_eq!(parts.offered_tools[0].name, "get_weather");
        assert_eq!(parts.tool_choice, Some(ToolChoice::Required));
        assert_eq!(parts.max_tokens, Some(1024));
        assert_eq!(parts.stop_sequences, ["\n\nHuman:"]);
    }

    #[test]
    fn legacy_functions_are_offered_tools() {
        let parts = request(
            r#"{"model":"m","messages":[],"tools":[{"type":"function","function":{"name":"a"}}],
            "functions":[{"name":"b"}],"stop":"END"}"#,
        )
        .parts()
        .unwrap();
        let names: Vec<_> = parts.offered_tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
        assert_eq!(parts.stop_sequences, ["END"]);
    }

    #[test]
    fn an_explicit_empty_tools_array_is_an_empty_list() {
        let parts = request(r#"{"model":"m","messages":[],"tools":[]}"#).parts().unwrap();
        assert!(parts.offered_tools.is_empty());
    }

    #[test]
    fn inert_top_level_fields_keep_the_parts() {
        for body in [
            r#"{"model":"m","messages":[{"role":"user","content":"hi","name":"bob"}],"seed":7,"user":"u",
            "response_format":{"type":"json_object"},"parallel_tool_calls":false,"store":false}"#,
            r#"{"model":"m","messages":[],"tools":[{"name":"a","input_schema":{},"cache_control":{"type":"ephemeral"}}],
            "top_k":5,"thinking":{"type":"disabled"},"max_tokens":16}"#,
        ] {
            assert!(request(body).parts().is_some(), "body {body} must keep its parts");
        }
    }

    #[test]
    fn unknown_or_malformed_shapes_leave_parts_absent() {
        for body in [
            r#"{"model":"m","messages":[],"tools":[{"type":"web_search_preview"}]}"#,
            r#"{"model":"m","messages":[],"tools":[{"type":"function","function":{"name":"a"}},{"type":"mcp"}]}"#,
            r#"{"model":"m","messages":[],"tools":[{"type":"function"}]}"#,
            r#"{"model":"m","messages":[],"tools":"search"}"#,
            r#"{"model":"m","messages":[{"role":"system","content":[{"type":"image_url"}]}]}"#,
            r#"{"model":"m","messages":[{"role":"system"}]}"#,
            r#"{"model":"m","messages":[{"content":"no role"}]}"#,
            r#"{"model":"m","messages":[],"max_tokens":-1}"#,
            r#"{"model":"m","messages":[],"max_completion_tokens":"512"}"#,
            r#"{"model":"m","messages":[],"max_tokens":5000000000}"#,
            r#"{"model":"m","messages":[],"n":1.5}"#,
            r#"{"model":"m","messages":[],"temperature":"hot"}"#,
            r#"{"model":"m","messages":[],"stop":[1]}"#,
            r#"{"model":"m","messages":[],"stream":"yes"}"#,
            r#"{"model":"m","messages":[],"tool_choice":"sometimes"}"#,
            r#"{"model":"m","messages":[],"tool_choice":"auto","function_call":"none"}"#,
            r#"{"model":"m","input":"hi"}"#,
            r#"{"model":"m","messages":[],"instructions":"x"}"#,
            r#"{"model":"m","prompt":"hi"}"#,
            "not json",
        ] {
            assert!(request(body).parts().is_none(), "body {body} must leave parts absent");
        }
    }

    #[test]
    fn only_exact_known_roles_keep_the_parts() {
        for role in ["SYSTEM", "System", "Developer", "custom"] {
            let body = format!(r#"{{"model":"m","messages":[{{"role":"{role}","content":"x"}}]}}"#);
            assert!(request(&body).parts().is_none(), "role {role} must leave parts absent");
        }
        assert!(
            request(r#"{"model":"m","messages":[{"role":1,"content":"x"}]}"#)
                .parts()
                .is_none()
        );
        let parts = request(
            r#"{"model":"m","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":null,
            "function_call":{"name":"a","arguments":"{}"}},{"role":"function","name":"a","content":"ok"},
            {"role":"tool","tool_call_id":"t","content":"ok"}]}"#,
        )
        .parts()
        .unwrap();
        assert!(parts.instructions.is_empty());
    }

    #[test]
    fn text_blocks_with_unrecognized_keys_leave_parts_absent() {
        for body in [
            r#"{"model":"m","messages":[{"role":"system","content":[{"type":"text","text":"approved","content":"more"}]}]}"#,
            r#"{"model":"m","system":[{"type":"text","text":"approved","extra":"more"}],"messages":[],"max_tokens":1}"#,
        ] {
            assert!(request(body).parts().is_none(), "body {body} must leave parts absent");
        }
        let cached = request(
            r#"{"model":"m","system":[{"type":"text","text":"s","cache_control":{"type":"ephemeral"}}],"messages":[],"max_tokens":1}"#,
        )
        .parts()
        .unwrap();
        assert_eq!(cached.instructions.len(), 1);
    }

    #[test]
    fn unrecognized_keys_leave_parts_absent() {
        for body in [
            r#"{"model":"m","messages":[],"future_tool_list":[{"name":"transfer_funds"}]}"#,
            r#"{"model":"m","messages":[],"mcp_servers":[{"type":"url","url":"https://x","name":"x"}]}"#,
            r#"{"model":"m","messages":[],"web_search_options":{}}"#,
            r#"{"model":"m","messages":[],"Tools":[{"name":"transfer_funds"}]}"#,
            r#"{"model":"m","messages":[],"Max_Tokens":100000}"#,
            r#"{"model":"m","messages":[],"system":"s","functions":[{"name":"a"}]}"#,
            r#"{"model":"m","messages":[{"Role":"system","content":"x"}]}"#,
            r#"{"model":"m","messages":[{"role":"user","Content":"x"}]}"#,
            r#"{"model":"m","messages":[],"tools":[{"name":"a","Type":"mcp"}]}"#,
            r#"{"model":"m","messages":[],"tools":[{"type":"function","function":{"name":"a"},"server_url":"x"}]}"#,
            r#"{"model":"m","messages":[],"tools":[{"type":"function","function":{"name":"a","Parameters":{}}}]}"#,
            r#"{"model":"m","messages":[],"functions":[{"name":"a","input_schema":{}}]}"#,
        ] {
            assert!(request(body).parts().is_none(), "body {body} must leave parts absent");
        }
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    fn request(json: &str) -> ParsedLlmRequest {
        try_request(json).unwrap()
    }

    fn try_request(json: &str) -> Result<ParsedLlmRequest, DuplicateKey> {
        ParsedLlmRequest::parse(&Bytes::from(json.to_owned()))
    }

    fn response(json: &str) -> ParsedLlmResponse {
        ParsedLlmResponse::parse(&Bytes::from(json.to_owned()))
    }

    fn texts(parts: &[ContentPart]) -> Vec<String> {
        parts
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.clone()),
                _ => None,
            })
            .collect()
    }
}
