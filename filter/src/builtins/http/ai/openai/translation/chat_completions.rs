// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `OpenAI` Responses API translation for Chat Completions-compatible providers.

use serde_json::{Map, Number, Value, json};
use thiserror::Error;
use tracing::warn;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default `Responses` truncation behavior for translated responses.
const DEFAULT_TRUNCATION: &str = "disabled";

/// Default service tier for providers that omit it.
const DEFAULT_SERVICE_TIER: &str = "default";

/// Default `Responses` tool choice when the request did not specify one.
const DEFAULT_TOOL_CHOICE: &str = "auto";

/// Default text format for translated responses.
const DEFAULT_TEXT_FORMAT: &str = "text";

/// Build the default `Responses` text configuration.
fn default_text_config() -> Value {
    json!({"format": {"type": DEFAULT_TEXT_FORMAT}})
}

// -----------------------------------------------------------------------------
// Public Types
// -----------------------------------------------------------------------------

/// Request-scoped context needed to build a `Responses` resource from a provider
/// Chat Completions response.
#[derive(Debug, Clone)]
pub(crate) struct ResponseContext {
    /// Stable `Responses` resource id assigned by the caller.
    pub(crate) response_id: String,
    /// Creation timestamp for the `Responses` resource.
    pub(crate) created_at: u64,
    /// Terminal timestamp for completed or incomplete `Responses` resources.
    pub(crate) completed_at: Option<u64>,
    /// Requested model name to expose on the `Responses` resource.
    pub(crate) model: String,
    /// Optional `Responses` instructions carried from the original request.
    pub(crate) instructions: Option<String>,
    /// Original `Responses` input value.
    pub(crate) input: Value,
    /// Original request metadata to carry onto the response.
    pub(crate) metadata: Value,
    /// Original `Responses` text configuration to carry onto the response.
    pub(crate) text: Value,
    /// Request temperature to echo, or the `Responses` default when absent.
    pub(crate) temperature: Option<Value>,
    /// Request top-p value to echo, or the `Responses` default when absent.
    pub(crate) top_p: Option<Value>,
    /// Request output token limit to echo.
    pub(crate) max_output_tokens: Option<u64>,
    /// Request tool-call limit to echo.
    pub(crate) max_tool_calls: Option<u64>,
    /// Whether the original request allowed parallel tool calls.
    pub(crate) parallel_tool_calls: bool,
    /// Optional predecessor response id from the original request.
    pub(crate) previous_response_id: Option<String>,
    /// Whether the caller asked the `Responses` API to store the response.
    pub(crate) store: bool,
    /// Original `Responses` tool definitions.
    pub(crate) tools: Vec<Value>,
    /// Original `Responses` tool choice value.
    pub(crate) tool_choice: Option<Value>,
    /// Request presence penalty to echo on the `Responses` resource.
    pub(crate) presence_penalty: Option<Value>,
    /// Request frequency penalty to echo on the `Responses` resource.
    pub(crate) frequency_penalty: Option<Value>,
    /// Request top-logprobs value to echo on the `Responses` resource.
    pub(crate) top_logprobs: Option<u64>,
    /// Request service tier to echo when the provider omits one.
    pub(crate) service_tier: Option<Value>,
    /// Request safety identifier to echo on the `Responses` resource.
    pub(crate) safety_identifier: Option<Value>,
    /// Request prompt cache key to echo on the `Responses` resource.
    pub(crate) prompt_cache_key: Option<Value>,
}

impl ResponseContext {
    /// Build a response context from the original `Responses` request.
    pub(crate) fn from_responses_request(request: &Value, response_id: String, created_at: u64) -> Self {
        let request = ResponseRequestFields::new(request);
        Self {
            response_id,
            created_at,
            completed_at: None,
            model: request.string("model").unwrap_or_default(),
            instructions: request.string("instructions"),
            input: request.cloned("input").unwrap_or(Value::Null),
            metadata: request.cloned("metadata").unwrap_or_else(|| json!({})),
            text: request.cloned("text").unwrap_or_else(default_text_config),
            temperature: request.cloned("temperature"),
            top_p: request.cloned("top_p"),
            max_output_tokens: request.u64("max_output_tokens"),
            max_tool_calls: request.u64("max_tool_calls"),
            parallel_tool_calls: request.bool("parallel_tool_calls").unwrap_or(true),
            previous_response_id: request.string("previous_response_id"),
            store: request.bool("store").unwrap_or(true),
            tools: request.array("tools").unwrap_or_default(),
            tool_choice: request.cloned("tool_choice"),
            presence_penalty: request.cloned("presence_penalty"),
            frequency_penalty: request.cloned("frequency_penalty"),
            top_logprobs: request.u64("top_logprobs"),
            service_tier: request.cloned("service_tier"),
            safety_identifier: request.cloned("safety_identifier"),
            prompt_cache_key: request.cloned("prompt_cache_key"),
        }
    }

    /// Return a response context with a terminal completion timestamp.
    #[must_use]
    pub(crate) fn with_completed_at(mut self, completed_at: u64) -> Self {
        self.completed_at = Some(completed_at);
        self
    }
}

/// Borrowed accessor for optional fields in a Responses request.
#[derive(Debug, Clone, Copy)]
struct ResponseRequestFields<'a> {
    /// Optional request object.
    obj: Option<&'a Map<String, Value>>,
}

impl<'a> ResponseRequestFields<'a> {
    /// Create accessors for a request value.
    fn new(request: &'a Value) -> Self {
        Self {
            obj: request.as_object(),
        }
    }

    /// Clone a field value.
    fn cloned(self, key: &str) -> Option<Value> {
        self.obj.and_then(|obj| obj.get(key)).cloned()
    }

    /// Clone a string field.
    fn string(self, key: &str) -> Option<String> {
        self.obj
            .and_then(|obj| obj.get(key))
            .and_then(Value::as_str)
            .map(str::to_owned)
    }

    /// Read an unsigned integer field.
    fn u64(self, key: &str) -> Option<u64> {
        self.obj.and_then(|obj| obj.get(key)).and_then(Value::as_u64)
    }

    /// Read a boolean field.
    fn bool(self, key: &str) -> Option<bool> {
        self.obj.and_then(|obj| obj.get(key)).and_then(Value::as_bool)
    }

    /// Clone an array field.
    fn array(self, key: &str) -> Option<Vec<Value>> {
        self.obj.and_then(|obj| obj.get(key)).and_then(Value::as_array).cloned()
    }
}

/// Errors produced while translating between `Responses` and Chat Completions.
#[derive(Debug, Error)]
pub(crate) enum TranslationError {
    /// The provided JSON value was not the expected object type.
    #[error("{0} must be a JSON object")]
    ExpectedObject(&'static str),
    /// A Responses input item has no Chat Completions-compatible representation.
    #[error("unsupported Responses input item type for Chat Completions translation: {0}")]
    UnsupportedInputItemType(String),
    /// A Responses content part has no Chat Completions-compatible representation.
    #[error("unsupported Responses content part type for Chat Completions translation: {0}")]
    UnsupportedContentPartType(String),
    /// A Responses content part has a supported type but unsupported fields.
    #[error("unsupported Responses content part for Chat Completions translation: {0}")]
    UnsupportedContentPart(String),
    /// A Responses tool has no Chat Completions-compatible representation.
    #[error("unsupported Responses tool type for Chat Completions translation: {0}")]
    UnsupportedToolType(String),
}

// -----------------------------------------------------------------------------
// Request Translation
// -----------------------------------------------------------------------------

/// Convert an `OpenAI` `Responses` create request into a Chat Completions request.
pub(crate) fn responses_request_to_chat_request(request: &Value) -> Result<Value, TranslationError> {
    let obj = request
        .as_object()
        .ok_or(TranslationError::ExpectedObject("Responses request"))?;

    let mut chat = Map::new();
    copy_field(obj, &mut chat, "model");
    copy_field(obj, &mut chat, "temperature");
    copy_field(obj, &mut chat, "top_p");
    copy_field(obj, &mut chat, "presence_penalty");
    copy_field(obj, &mut chat, "frequency_penalty");
    copy_field(obj, &mut chat, "parallel_tool_calls");
    copy_field(obj, &mut chat, "prompt_cache_key");
    copy_field(obj, &mut chat, "service_tier");
    copy_field(obj, &mut chat, "extra_body");
    map_top_logprobs(obj, &mut chat);
    map_reasoning_effort(obj, &mut chat);
    map_text_format(obj, &mut chat);

    if let Some(max_output_tokens) = obj.get("max_output_tokens") {
        chat.insert("max_completion_tokens".to_owned(), max_output_tokens.clone());
    }

    let messages = build_chat_messages(obj)?;
    chat.insert("messages".to_owned(), Value::Array(messages));

    if let Some(tools) = build_chat_tools(obj)? {
        chat.insert("tools".to_owned(), tools);
    }
    if let Some(tool_choice) = build_chat_tool_choice(obj)? {
        chat.insert("tool_choice".to_owned(), tool_choice);
    }

    Ok(Value::Object(chat))
}

/// Copy a field from one JSON object to another.
fn copy_field(source: &Map<String, Value>, target: &mut Map<String, Value>, key: &str) {
    if let Some(value) = source.get(key) {
        target.insert(key.to_owned(), value.clone());
    }
}

/// Map `top_logprobs` and required Chat Completions `logprobs` toggle together.
fn map_top_logprobs(source: &Map<String, Value>, target: &mut Map<String, Value>) {
    if let Some(top_logprobs) = source.get("top_logprobs") {
        target.insert("top_logprobs".to_owned(), top_logprobs.clone());
        target.insert("logprobs".to_owned(), Value::Bool(true));
    }
}

/// Convert `Responses` reasoning controls to the Chat Completions field shape.
fn map_reasoning_effort(source: &Map<String, Value>, target: &mut Map<String, Value>) {
    if let Some(effort) = source.get("reasoning").and_then(|reasoning| reasoning.get("effort")) {
        target.insert("reasoning_effort".to_owned(), effort.clone());
    }
}

/// Convert `Responses` structured-output text format to Chat `response_format`.
fn map_text_format(source: &Map<String, Value>, target: &mut Map<String, Value>) {
    let Some(format) = source
        .get("text")
        .and_then(|text| text.get("format"))
        .and_then(Value::as_object)
    else {
        return;
    };

    let Some(format_type) = format.get("type").and_then(Value::as_str) else {
        return;
    };

    match format_type {
        "json_object" => {
            target.insert("response_format".to_owned(), json!({"type": "json_object"}));
        },
        "json_schema" => {
            target.insert("response_format".to_owned(), json_schema_response_format(format));
        },
        _ => {},
    }
}

/// Build Chat Completions `json_schema` response format from a Responses format.
fn json_schema_response_format(format: &Map<String, Value>) -> Value {
    if let Some(json_schema) = format.get("json_schema").and_then(Value::as_object) {
        return json!({
            "type": "json_schema",
            "json_schema": Value::Object(json_schema.clone())
        });
    }

    let mut json_schema = Map::new();
    copy_field(format, &mut json_schema, "name");
    copy_field(format, &mut json_schema, "description");
    copy_field(format, &mut json_schema, "schema");
    copy_field(format, &mut json_schema, "strict");

    json!({
        "type": "json_schema",
        "json_schema": Value::Object(json_schema)
    })
}

/// Build Chat Completions messages from `Responses` instructions and input.
fn build_chat_messages(obj: &Map<String, Value>) -> Result<Vec<Value>, TranslationError> {
    let mut messages = Vec::new();

    if let Some(instructions) = obj.get("instructions").and_then(Value::as_str)
        && !instructions.is_empty()
    {
        messages.push(json!({"role": "system", "content": instructions}));
    }

    if let Some(input) = obj.get("input") {
        append_input_messages(&mut messages, input)?;
    }

    Ok(messages)
}

/// Append converted input messages to a Chat Completions message list.
fn append_input_messages(messages: &mut Vec<Value>, input: &Value) -> Result<(), TranslationError> {
    match input {
        Value::String(text) => messages.push(json!({"role": "user", "content": text})),
        Value::Array(items) => append_input_item_sequence(messages, items)?,
        Value::Object(_) => append_input_item_sequence(messages, std::slice::from_ref(input))?,
        _ => {
            warn!(
                input_type = json_type_name(input),
                "dropping unsupported Responses input during Chat Completions translation"
            );
        },
    }

    Ok(())
}

/// Append a sequence of Responses input items, batching adjacent function calls.
fn append_input_item_sequence(messages: &mut Vec<Value>, items: &[Value]) -> Result<(), TranslationError> {
    let mut pending_tool_calls = Vec::new();
    for item in items {
        if let Some(obj) = item.as_object()
            && obj.get("type").and_then(Value::as_str) == Some("function_call")
        {
            if let Some(tool_call) = function_call_tool_call(obj) {
                pending_tool_calls.push(tool_call);
            }
            continue;
        }

        flush_pending_function_calls(messages, &mut pending_tool_calls);
        append_input_item(messages, item)?;
    }
    flush_pending_function_calls(messages, &mut pending_tool_calls);
    Ok(())
}

/// Flush adjacent Responses function calls into one assistant message.
fn flush_pending_function_calls(messages: &mut Vec<Value>, pending_tool_calls: &mut Vec<Value>) {
    if pending_tool_calls.is_empty() {
        return;
    }

    messages.push(json!({
        "role": "assistant",
        "content": null,
        "tool_calls": std::mem::take(pending_tool_calls),
    }));
}

/// Convert a single `Responses` input item into one Chat Completions message.
fn append_input_item(messages: &mut Vec<Value>, item: &Value) -> Result<(), TranslationError> {
    let Some(obj) = item.as_object() else {
        return Ok(());
    };

    match obj.get("type").and_then(Value::as_str) {
        Some("function_call_output") => append_tool_output(messages, obj),
        Some("message") => append_message_item(messages, obj)?,
        None if obj.contains_key("role") || obj.contains_key("content") => append_message_item(messages, obj)?,
        None => return Err(TranslationError::UnsupportedInputItemType("unknown".to_owned())),
        Some(input_type) => return Err(TranslationError::UnsupportedInputItemType(input_type.to_owned())),
    }

    Ok(())
}

/// Convert a Responses message item into a Chat Completions message.
fn append_message_item(messages: &mut Vec<Value>, obj: &Map<String, Value>) -> Result<(), TranslationError> {
    let role = obj.get("role").and_then(Value::as_str).unwrap_or("user");
    let content = obj
        .get("content")
        .map_or_else(|| Ok(json!("")), convert_input_content)?;
    messages.push(json!({"role": role, "content": content}));
    Ok(())
}

/// Convert one Responses function-call item to a Chat tool-call object.
fn function_call_tool_call(obj: &Map<String, Value>) -> Option<Value> {
    let Some(call_id) = obj.get("call_id").and_then(Value::as_str) else {
        warn!("dropping Responses function_call without call_id during Chat Completions translation");
        return None;
    };
    let Some(name) = obj.get("name").and_then(Value::as_str) else {
        warn!("dropping Responses function_call without name during Chat Completions translation");
        return None;
    };

    Some(json!({
        "id": call_id,
        "type": "function",
        "function": {
            "name": name,
            "arguments": chat_string_field(obj.get("arguments")),
        }
    }))
}

/// Convert a `Responses` function call output item into a Chat tool message.
fn append_tool_output(messages: &mut Vec<Value>, obj: &Map<String, Value>) {
    let Some(call_id) = obj.get("call_id").and_then(Value::as_str) else {
        warn!("dropping Responses function_call_output without call_id during Chat Completions translation");
        return;
    };

    messages.push(json!({
        "role": "tool",
        "tool_call_id": call_id,
        "content": chat_string_field(obj.get("output"))
    }));
}

/// Convert an optional JSON field to Chat's string-valued history fields.
fn chat_string_field(value: Option<&Value>) -> Value {
    match value {
        Some(Value::String(text)) => Value::String(text.clone()),
        Some(value) => Value::String(value.to_string()),
        None => Value::String(String::new()),
    }
}

/// Convert `Responses` text content into the most compatible Chat form.
fn convert_input_content(content: &Value) -> Result<Value, TranslationError> {
    match content {
        Value::Array(parts) => convert_input_content_parts(parts),
        _ => Ok(content.clone()),
    }
}

/// Convert `Responses` content parts, collapsing text-only content to a string.
fn convert_input_content_parts(parts: &[Value]) -> Result<Value, TranslationError> {
    let mut converted = ConvertedContentParts::default();

    for part in parts {
        converted.push(part)?;
    }

    Ok(converted.finish())
}

/// Accumulates converted Chat content parts.
#[derive(Debug)]
struct ConvertedContentParts {
    /// Raw text fragments for text-only content.
    text_parts: Vec<String>,
    /// Chat content parts for mixed content.
    chat_parts: Vec<Value>,
    /// Whether every observed part was a text part.
    all_text: bool,
}

impl ConvertedContentParts {
    /// Push one Responses content part.
    fn push(&mut self, part: &Value) -> Result<(), TranslationError> {
        match part.get("type").and_then(Value::as_str) {
            Some("input_text" | "output_text" | "text") => self.push_text(part),
            Some("input_image") => {
                self.push_non_text(convert_input_image_part(part)?);
            },
            Some("input_file") => {
                self.push_non_text(convert_input_file_part(part)?);
            },
            Some(part_type) => return Err(TranslationError::UnsupportedContentPartType(part_type.to_owned())),
            None => return Err(TranslationError::UnsupportedContentPartType("unknown".to_owned())),
        }

        Ok(())
    }

    /// Push a text content part.
    fn push_text(&mut self, part: &Value) {
        if let Some(text) = part.get("text").and_then(Value::as_str) {
            self.text_parts.push(text.to_owned());
            self.chat_parts.push(json!({"type": "text", "text": text}));
        }
    }

    /// Push a content part that prevents text-only collapse.
    fn push_non_text(&mut self, part: Value) {
        self.all_text = false;
        self.chat_parts.push(part);
    }

    /// Finish as either a collapsed text string or mixed content parts.
    fn finish(self) -> Value {
        if self.all_text {
            Value::String(self.text_parts.join(""))
        } else {
            Value::Array(self.chat_parts)
        }
    }
}

impl Default for ConvertedContentParts {
    fn default() -> Self {
        Self {
            text_parts: Vec::new(),
            chat_parts: Vec::new(),
            all_text: true,
        }
    }
}

/// Convert a `Responses` image part into a Chat Completions image part.
fn convert_input_image_part(part: &Value) -> Result<Value, TranslationError> {
    let Some(obj) = part.as_object() else {
        return Err(TranslationError::UnsupportedContentPartType("input_image".to_owned()));
    };
    let Some(url) = obj.get("image_url").cloned() else {
        let reason = if obj.contains_key("file_id") {
            "input_image requires image_url; file_id references are not supported"
        } else {
            "input_image requires image_url"
        };
        return Err(TranslationError::UnsupportedContentPart(reason.to_owned()));
    };

    let mut image_url = Map::new();
    image_url.insert("url".to_owned(), url);
    copy_field(obj, &mut image_url, "detail");

    Ok(json!({
        "type": "image_url",
        "image_url": Value::Object(image_url)
    }))
}

/// Convert a `Responses` file content part into Chat Completions shape.
fn convert_input_file_part(part: &Value) -> Result<Value, TranslationError> {
    let Some(obj) = part.as_object() else {
        return Err(TranslationError::UnsupportedContentPartType("input_file".to_owned()));
    };
    let mut file = Map::new();
    copy_field(obj, &mut file, "file_id");
    copy_field(obj, &mut file, "filename");
    copy_field(obj, &mut file, "file_data");
    // Praxis executors can resolve Responses file URLs before making the
    // provider call, so keep them explicit in the translated file part.
    copy_field(obj, &mut file, "file_url");

    if file.is_empty() {
        return Err(TranslationError::UnsupportedContentPart(
            "input_file requires file_id, filename, file_data, or file_url".to_owned(),
        ));
    }

    Ok(json!({
        "type": "file",
        "file": Value::Object(file)
    }))
}

/// Build Chat Completions tool definitions from `Responses` tools.
fn build_chat_tools(obj: &Map<String, Value>) -> Result<Option<Value>, TranslationError> {
    let Some(tools) = obj.get("tools").and_then(Value::as_array) else {
        return Ok(None);
    };
    let mut chat_tools = Vec::new();

    for tool in tools {
        let Some(tool_obj) = tool.as_object() else {
            continue;
        };

        if tool_obj.get("type").and_then(Value::as_str) == Some("function") {
            chat_tools.push(convert_function_tool(tool_obj));
        } else {
            let tool_type = tool_obj.get("type").and_then(Value::as_str).unwrap_or("unknown");
            return Err(TranslationError::UnsupportedToolType(tool_type.to_owned()));
        }
    }

    Ok((!chat_tools.is_empty()).then_some(Value::Array(chat_tools)))
}

/// Convert a `Responses` function tool to the Chat Completions nested shape.
fn convert_function_tool(tool: &Map<String, Value>) -> Value {
    if tool.contains_key("function") {
        return Value::Object(tool.clone());
    }

    let mut function = Map::new();
    copy_field(tool, &mut function, "name");
    copy_field(tool, &mut function, "description");
    copy_field(tool, &mut function, "parameters");
    copy_field(tool, &mut function, "strict");

    json!({
        "type": "function",
        "function": Value::Object(function)
    })
}

/// Convert Responses `tool_choice` into Chat Completions-compatible shape.
fn build_chat_tool_choice(obj: &Map<String, Value>) -> Result<Option<Value>, TranslationError> {
    let Some(choice) = obj.get("tool_choice") else {
        return Ok(None);
    };

    let tool_choice = match choice {
        Value::String(_) => Some(choice.clone()),
        Value::Object(choice_obj) => match choice_obj.get("type").and_then(Value::as_str) {
            Some("function") => {
                let mut function = Map::new();
                copy_field(choice_obj, &mut function, "name");
                Some(json!({"type": "function", "function": Value::Object(function)}))
            },
            Some("allowed_tools") => {
                let allowed_tools = build_allowed_tools_choice(choice_obj)?;
                Some(json!({"type": "allowed_tools", "allowed_tools": allowed_tools}))
            },
            Some(other) => {
                warn!(
                    tool_choice_type = other,
                    "dropping unsupported Responses tool_choice object"
                );
                None
            },
            None => None,
        },
        _ => None,
    };

    Ok(tool_choice)
}

/// Convert Responses allowed-tools choice payloads to Chat's nested tool shape.
fn build_allowed_tools_choice(choice: &Map<String, Value>) -> Result<Value, TranslationError> {
    let source = choice.get("allowed_tools").and_then(Value::as_object).unwrap_or(choice);
    let mut allowed_tools = Map::new();

    copy_field(source, &mut allowed_tools, "mode");
    if let Some(tools) = source.get("tools").and_then(Value::as_array) {
        allowed_tools.insert(
            "tools".to_owned(),
            Value::Array(
                tools
                    .iter()
                    .map(convert_allowed_tool_choice_tool)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        );
    }

    Ok(Value::Object(allowed_tools))
}

/// Convert a Responses allowed function entry into Chat's nested function entry.
fn convert_allowed_tool_choice_tool(tool: &Value) -> Result<Value, TranslationError> {
    let Some(tool_obj) = tool.as_object() else {
        return Ok(tool.clone());
    };
    let Some(tool_type) = tool_obj.get("type").and_then(Value::as_str) else {
        return Ok(tool.clone());
    };
    if tool_type != "function" {
        return Err(TranslationError::UnsupportedToolType(tool_type.to_owned()));
    }
    if tool_obj.contains_key("function") {
        return Ok(tool.clone());
    }

    let mut function = Map::new();
    copy_field(tool_obj, &mut function, "name");
    copy_field(tool_obj, &mut function, "description");
    copy_field(tool_obj, &mut function, "parameters");
    copy_field(tool_obj, &mut function, "strict");

    Ok(json!({
        "type": "function",
        "function": Value::Object(function)
    }))
}

/// Return a stable JSON type name for diagnostics.
fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// -----------------------------------------------------------------------------
// Response Translation
// -----------------------------------------------------------------------------

/// Convert a Chat Completions response into an `OpenAI` `Responses` resource.
pub(crate) fn chat_response_to_response_resource(
    response: &Value,
    context: &ResponseContext,
) -> Result<Value, TranslationError> {
    let obj = response
        .as_object()
        .ok_or(TranslationError::ExpectedObject("Chat Completions response"))?;

    let finish_reason = first_choice(obj)
        .and_then(|choice| choice.get("finish_reason"))
        .and_then(Value::as_str);
    let status = response_status(finish_reason);
    let incomplete_details = incomplete_details(finish_reason);
    let output = build_output_items(obj, context, status);
    let usage = build_usage(obj);
    let service_tier = service_tier_value_with_context(obj, context);
    let parts = ResponseResourceParts {
        status,
        incomplete_details: &incomplete_details,
        output: &output,
        usage: &usage,
        service_tier: &service_tier,
    };

    Ok(response_resource(context, &parts))
}

/// Values that vary between response resource snapshots.
#[derive(Debug)]
struct ResponseResourceParts<'a> {
    /// Current `Responses` status.
    status: &'a str,
    /// Current incomplete details value.
    incomplete_details: &'a Value,
    /// Current output items.
    output: &'a [Value],
    /// Current usage object.
    usage: &'a Value,
    /// Current service tier.
    service_tier: &'a Value,
}

/// Build a full `Responses` resource snapshot.
fn response_resource(context: &ResponseContext, parts: &ResponseResourceParts<'_>) -> Value {
    let mut resource = json!({
        "id": context.response_id,
        "object": "response",
        "created_at": context.created_at,
        "status": parts.status,
        "error": Value::Null,
        "incomplete_details": parts.incomplete_details,
        "instructions": instructions_value(context),
        "max_output_tokens": max_output_tokens_value(context),
        "model": context.model,
        "input": context.input,
        "output": Value::Array(parts.output.to_vec()),
        "parallel_tool_calls": context.parallel_tool_calls,
        "previous_response_id": previous_response_id_value(context),
        "reasoning": Value::Null,
        "store": context.store,
        "temperature": number_or_default(context.temperature.as_ref(), 1.0),
        "text": context.text,
        "tool_choice": tool_choice_value(context),
        "tools": context.tools,
        "top_p": number_or_default(context.top_p.as_ref(), 1.0),
        // TODO(responses): preserve request truncation when the compatibility
        // layer supports truncation semantics instead of emitting the default.
        "truncation": DEFAULT_TRUNCATION,
        "usage": parts.usage,
        "metadata": metadata_value(context),
        // TODO(responses): surface true once the background jobs filter owns
        // queued Responses resources; this translator only builds foreground responses.
        "background": false,
        "service_tier": parts.service_tier
    });
    insert_request_resource_fields(&mut resource, context, parts.status);
    resource
}

/// Insert required response fields that are sourced from the original request.
fn insert_request_resource_fields(resource: &mut Value, context: &ResponseContext, status: &str) {
    if let Some(obj) = resource.as_object_mut() {
        obj.insert("completed_at".to_owned(), completed_at_value(status, context));
        obj.insert("max_tool_calls".to_owned(), max_tool_calls_value(context));
        obj.insert(
            "prompt_cache_key".to_owned(),
            request_field_or_null(context.prompt_cache_key.as_ref()),
        );
        obj.insert(
            "safety_identifier".to_owned(),
            request_field_or_null(context.safety_identifier.as_ref()),
        );
        obj.insert(
            "presence_penalty".to_owned(),
            number_or_default(context.presence_penalty.as_ref(), 0.0),
        );
        obj.insert(
            "frequency_penalty".to_owned(),
            number_or_default(context.frequency_penalty.as_ref(), 0.0),
        );
        obj.insert(
            "top_logprobs".to_owned(),
            Value::Number(context.top_logprobs.unwrap_or(0).into()),
        );
    }
}

/// Extract the first Chat Completions choice.
fn first_choice(obj: &Map<String, Value>) -> Option<&Value> {
    obj.get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
}

/// Extract Chat Completions token logprobs from one choice.
fn chat_logprobs_content(choice: &Value) -> &[Value] {
    choice
        .get("logprobs")
        .and_then(|logprobs| logprobs.get("content"))
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// Map a Chat Completions finish reason to a `Responses` status.
fn response_status(finish_reason: Option<&str>) -> &'static str {
    match finish_reason {
        Some("length" | "content_filter") => "incomplete",
        _ => "completed",
    }
}

/// Build `Responses` incomplete details from a Chat Completions finish reason.
fn incomplete_details(finish_reason: Option<&str>) -> Value {
    match finish_reason {
        Some("length") => json!({"reason": "max_output_tokens"}),
        Some("content_filter") => json!({"reason": "content_filter"}),
        _ => Value::Null,
    }
}

/// Build the `instructions` response field.
fn instructions_value(context: &ResponseContext) -> Value {
    context
        .instructions
        .as_ref()
        .map_or(Value::Null, |instructions| Value::String(instructions.clone()))
}

/// Build the `max_output_tokens` response field.
fn max_output_tokens_value(context: &ResponseContext) -> Value {
    context
        .max_output_tokens
        .map_or(Value::Null, |max_output_tokens| Value::Number(max_output_tokens.into()))
}

/// Build the `max_tool_calls` response field.
fn max_tool_calls_value(context: &ResponseContext) -> Value {
    context
        .max_tool_calls
        .map_or(Value::Null, |max_tool_calls| Value::Number(max_tool_calls.into()))
}

/// Build the `completed_at` response field.
fn completed_at_value(status: &str, context: &ResponseContext) -> Value {
    if status == "in_progress" {
        Value::Null
    } else {
        Value::Number(context.completed_at.unwrap_or(context.created_at).into())
    }
}

/// Clone nullable request fields onto the response resource.
fn request_field_or_null(value: Option<&Value>) -> Value {
    value.cloned().unwrap_or(Value::Null)
}

/// Build the `previous_response_id` response field.
fn previous_response_id_value(context: &ResponseContext) -> Value {
    context
        .previous_response_id
        .as_ref()
        .map_or(Value::Null, |response_id| Value::String(response_id.clone()))
}

/// Build the `tool_choice` response field.
fn tool_choice_value(context: &ResponseContext) -> Value {
    context
        .tool_choice
        .as_ref()
        .cloned()
        .unwrap_or_else(|| Value::String(DEFAULT_TOOL_CHOICE.to_owned()))
}

/// Build the `metadata` response field.
fn metadata_value(context: &ResponseContext) -> Value {
    if context.metadata.is_object() {
        context.metadata.clone()
    } else {
        json!({})
    }
}

/// Build provider service tier, falling back to the request context when absent.
fn service_tier_value_with_context(obj: &Map<String, Value>, context: &ResponseContext) -> Value {
    obj.get("service_tier")
        .cloned()
        .or_else(|| context.service_tier.clone())
        .unwrap_or_else(|| Value::String(DEFAULT_SERVICE_TIER.to_owned()))
}

/// Use a JSON number when provided, otherwise emit a finite default.
fn number_or_default(value: Option<&Value>, default: f64) -> Value {
    value
        .filter(|candidate| candidate.is_number())
        .cloned()
        .unwrap_or_else(|| number_value(default))
}

/// Convert a finite floating point value into a JSON number.
fn number_value(value: f64) -> Value {
    Number::from_f64(value).map_or(Value::Null, Value::Number)
}

/// Build all `Responses` output items from the first Chat choice.
fn build_output_items(obj: &Map<String, Value>, context: &ResponseContext, status: &str) -> Vec<Value> {
    let mut output = Vec::new();
    let Some(choice) = first_choice(obj) else {
        return output;
    };

    let message = choice.get("message");
    let logprobs = chat_logprobs_content(choice);
    append_message_output(&mut output, message, context, status, logprobs);
    append_tool_call_outputs(&mut output, message, status);

    output
}

/// Append a message output item when the Chat response includes assistant text.
fn append_message_output(
    output: &mut Vec<Value>,
    message: Option<&Value>,
    context: &ResponseContext,
    status: &str,
    logprobs: &[Value],
) {
    let content_items = message_content_items(message, logprobs);

    if content_items.is_empty() {
        return;
    }

    output.push(message_output_item(context, status, &content_items));
}

/// Build a stable assistant message output item id.
fn message_item_id(context: &ResponseContext) -> String {
    format!("msg_{}", context.response_id)
}

/// Build a schema-complete `Responses` assistant message item.
fn message_output_item(context: &ResponseContext, status: &str, content: &[Value]) -> Value {
    json!({
        "id": message_item_id(context),
        "type": "message",
        "status": status,
        "role": "assistant",
        "content": Value::Array(content.to_vec())
    })
}

/// Convert Chat assistant message content into `Responses` message content items.
fn message_content_items(message: Option<&Value>, logprobs: &[Value]) -> Vec<Value> {
    let mut content_items = output_text_items(message.and_then(|message| message.get("content")), logprobs);

    if let Some(refusal) = message
        .and_then(|message| message.get("refusal"))
        .and_then(Value::as_str)
        && !refusal.is_empty()
    {
        content_items.push(refusal_item(refusal));
    }

    content_items
}

/// Convert Chat assistant content into `Responses` output text items.
fn output_text_items(content: Option<&Value>, logprobs: &[Value]) -> Vec<Value> {
    let Some(content) = content else {
        return Vec::new();
    };

    match content {
        Value::String(text) if !text.is_empty() => vec![output_text_item(text, logprobs)],
        Value::Array(parts) => output_text_items_from_parts(parts, logprobs),
        _ => Vec::new(),
    }
}

/// Convert Chat content parts into `Responses` output text items.
fn output_text_items_from_parts(parts: &[Value], logprobs: &[Value]) -> Vec<Value> {
    let mut items = Vec::new();
    let mut logprobs_used = false;

    for part in parts {
        if let Some(text) = part.get("text").and_then(Value::as_str)
            && !text.is_empty()
        {
            let part_logprobs = if logprobs_used { &[] } else { logprobs };
            items.push(output_text_item(text, part_logprobs));
            logprobs_used = true;
        }
    }

    items
}

/// Build a single schema-complete `Responses` output text item.
fn output_text_item(text: &str, logprobs: &[Value]) -> Value {
    json!({
        "type": "output_text",
        "text": text,
        "annotations": [],
        "logprobs": logprobs
    })
}

/// Build a single `Responses` refusal content item.
fn refusal_item(refusal: &str) -> Value {
    json!({
        "type": "refusal",
        "refusal": refusal
    })
}

/// Append function call output items for Chat Completions tool calls.
fn append_tool_call_outputs(output: &mut Vec<Value>, message: Option<&Value>, status: &str) {
    let Some(tool_calls) = message
        .and_then(|message| message.get("tool_calls"))
        .and_then(Value::as_array)
    else {
        return;
    };

    for tool_call in tool_calls {
        output.push(function_call_output_item(tool_call, status));
    }
}

/// Build one `Responses` function call item from a Chat Completions tool call.
fn function_call_output_item(tool_call: &Value, status: &str) -> Value {
    let call_id = tool_call.get("id").and_then(Value::as_str).unwrap_or("");
    let name = tool_call
        .get("function")
        .and_then(|function| function.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let arguments = tool_call
        .get("function")
        .and_then(|function| function.get("arguments"))
        .and_then(Value::as_str)
        .unwrap_or("{}");

    function_call_output_item_from_parts(call_id, name, arguments, status)
}

/// Build one `Responses` function call item from normalized parts.
fn function_call_output_item_from_parts(call_id: &str, name: &str, arguments: &str, status: &str) -> Value {
    json!({
        "id": format!("fc_{call_id}"),
        "type": "function_call",
        "status": status,
        "call_id": call_id,
        "name": name,
        "arguments": arguments
    })
}

/// Build `Responses` usage from Chat Completions usage fields.
fn build_usage(obj: &Map<String, Value>) -> Value {
    let usage = obj.get("usage");
    build_usage_from_value(usage)
}

/// Build `Responses` usage from an optional Chat Completions usage value.
fn build_usage_from_value(usage: Option<&Value>) -> Value {
    let input_tokens = usage_tokens(usage, "prompt_tokens");
    let output_tokens = usage_tokens(usage, "completion_tokens");
    let total_tokens = usage_tokens(usage, "total_tokens");
    let cached_tokens = usage
        .and_then(|usage| usage.get("prompt_tokens_details"))
        .and_then(|details| details.get("cached_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let reasoning_tokens = usage
        .and_then(|usage| usage.get("completion_tokens_details"))
        .and_then(|details| details.get("reasoning_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    json!({
        "input_tokens": input_tokens,
        "input_tokens_details": {
            "cached_tokens": cached_tokens
        },
        "output_tokens": output_tokens,
        "output_tokens_details": {
            "reasoning_tokens": reasoning_tokens
        },
        "total_tokens": total_tokens
    })
}

/// Extract a token count from a Chat Completions usage object.
fn usage_tokens(usage: Option<&Value>, field: &str) -> u64 {
    usage
        .and_then(|usage| usage.get(field))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}
