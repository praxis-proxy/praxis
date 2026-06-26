// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `OpenAI` Responses API translation for Chat Completions-compatible providers.

use serde_json::{Map, Value, json};
use thiserror::Error;
use tracing::warn;

/// Errors produced while translating between `Responses` and Chat Completions.
#[derive(Debug, Error)]
pub(crate) enum TranslationError {
    /// The provided JSON value was not the expected object type.
    #[error("{0} must be a JSON object")]
    ExpectedObject(&'static str),
    /// The request uses a Responses tool that Chat Completions cannot represent.
    #[error("unsupported Responses tool type for Chat Completions translation: {0}")]
    UnsupportedToolType(String),
}

/// Convert an `OpenAI` `Responses` create request into a Chat Completions request.
pub(crate) fn responses_request_to_chat_request(request: &Value) -> Result<Value, TranslationError> {
    let obj = request
        .as_object()
        .ok_or(TranslationError::ExpectedObject("Responses request"))?;

    let mut chat = Map::new();
    copy_field(obj, &mut chat, "model");
    copy_field(obj, &mut chat, "stream");
    copy_field(obj, &mut chat, "temperature");
    copy_field(obj, &mut chat, "top_p");
    copy_field(obj, &mut chat, "presence_penalty");
    copy_field(obj, &mut chat, "frequency_penalty");
    copy_field(obj, &mut chat, "parallel_tool_calls");
    copy_field(obj, &mut chat, "service_tier");
    copy_field(obj, &mut chat, "extra_body");
    map_top_logprobs(obj, &mut chat);
    map_reasoning_effort(obj, &mut chat);
    map_text_format(obj, &mut chat);

    if let Some(max_output_tokens) = obj.get("max_output_tokens") {
        chat.insert("max_completion_tokens".to_owned(), max_output_tokens.clone());
    }

    let messages = build_chat_messages(obj);
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

    match format.get("type").and_then(Value::as_str) {
        Some("json_object") => {
            target.insert("response_format".to_owned(), json!({"type": "json_object"}));
        },
        Some("json_schema") => {
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
fn build_chat_messages(obj: &Map<String, Value>) -> Vec<Value> {
    let mut messages = Vec::new();

    if let Some(instructions) = obj.get("instructions").and_then(Value::as_str)
        && !instructions.is_empty()
    {
        messages.push(json!({"role": "system", "content": instructions}));
    }

    if let Some(input) = obj.get("input") {
        append_input_messages(&mut messages, input);
    }

    messages
}

/// Append converted input messages to a Chat Completions message list.
fn append_input_messages(messages: &mut Vec<Value>, input: &Value) {
    match input {
        Value::String(text) => messages.push(json!({"role": "user", "content": text})),
        Value::Array(items) => {
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
                append_input_item(messages, item);
            }
            flush_pending_function_calls(messages, &mut pending_tool_calls);
        },
        Value::Object(_) => append_input_item(messages, input),
        _ => {
            warn!(
                input_type = json_type_name(input),
                "dropping unsupported Responses input during Chat Completions translation"
            );
        },
    }
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
fn append_input_item(messages: &mut Vec<Value>, item: &Value) {
    let Some(obj) = item.as_object() else {
        return;
    };

    match obj.get("type").and_then(Value::as_str) {
        Some("function_call") => append_function_call_item(messages, obj),
        Some("function_call_output") => append_function_call_output_item(messages, obj),
        Some("message") | None => append_message_item(messages, obj),
        Some(input_type) => {
            warn!(
                input_type,
                "dropping unsupported typed Responses input item during Chat Completions translation"
            );
        },
    }
}

/// Convert a Responses message item into a Chat Completions message.
fn append_message_item(messages: &mut Vec<Value>, obj: &Map<String, Value>) {
    let role = obj.get("role").and_then(Value::as_str).unwrap_or("user");
    let content = obj.get("content").map_or_else(|| json!(""), convert_input_content);
    messages.push(json!({"role": role, "content": content}));
}

/// Convert a Responses function-call item into an assistant tool-call message.
fn append_function_call_item(messages: &mut Vec<Value>, obj: &Map<String, Value>) {
    let Some(tool_call) = function_call_tool_call(obj) else {
        return;
    };

    messages.push(json!({
        "role": "assistant",
        "content": null,
        "tool_calls": [tool_call]
    }));
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
            "arguments": stringify_chat_field(obj.get("arguments")),
        }
    }))
}

/// Convert a Responses function-call output into a Chat Completions tool message.
fn append_function_call_output_item(messages: &mut Vec<Value>, obj: &Map<String, Value>) {
    let Some(call_id) = obj.get("call_id").and_then(Value::as_str) else {
        warn!("dropping Responses function_call_output without call_id during Chat Completions translation");
        return;
    };

    messages.push(json!({
        "role": "tool",
        "tool_call_id": call_id,
        "content": stringify_chat_field(obj.get("output")),
    }));
}

/// Convert an optional JSON field to Chat's string-valued history fields.
fn stringify_chat_field(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(value) => value.to_string(),
        None => String::new(),
    }
}

/// Convert `Responses` text content into the most compatible Chat form.
fn convert_input_content(content: &Value) -> Value {
    match content {
        Value::Array(parts) => convert_input_content_parts(parts),
        _ => content.clone(),
    }
}

/// Convert `Responses` content parts, collapsing text-only content to a string.
fn convert_input_content_parts(parts: &[Value]) -> Value {
    let mut converted = ConvertedContentParts::default();

    for part in parts {
        converted.push(part);
    }

    converted.finish()
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
    fn push(&mut self, part: &Value) {
        match part.get("type").and_then(Value::as_str) {
            Some("input_text" | "output_text" | "text") => self.push_text(part),
            Some("input_image") => {
                if let Some(part) = convert_input_image_part(part) {
                    self.push_non_text(part);
                }
            },
            Some("input_file") => {
                if let Some(part) = convert_input_file_part(part) {
                    self.push_non_text(part);
                }
            },
            Some(part_type) => {
                warn!(
                    part_type,
                    "dropping unsupported Responses content part during Chat Completions translation"
                );
            },
            None => warn!("dropping Responses content part without type during Chat Completions translation"),
        }
    }

    /// Push a text content part.
    fn push_text(&mut self, part: &Value) {
        if let Some(text) = part.get("text").and_then(Value::as_str) {
            self.text_parts.push(text.to_owned());
            self.chat_parts.push(json!({"type": "text", "text": text}));
        }
    }

    /// Push a non-text content part.
    fn push_non_text(&mut self, part: Value) {
        self.all_text = false;
        self.chat_parts.push(part);
    }

    /// Finish conversion to either a text string or Chat content-part array.
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

/// Convert a `Responses` image content part into Chat Completions shape.
fn convert_input_image_part(part: &Value) -> Option<Value> {
    let obj = part.as_object()?;
    let Some(url) = obj.get("image_url").cloned() else {
        warn!("dropping Responses input_image without image_url during Chat Completions translation");
        return None;
    };

    let mut image_url = Map::new();
    image_url.insert("url".to_owned(), url);
    copy_field(obj, &mut image_url, "detail");

    Some(json!({
        "type": "image_url",
        "image_url": Value::Object(image_url)
    }))
}

/// Convert a `Responses` file content part into Chat Completions shape.
fn convert_input_file_part(part: &Value) -> Option<Value> {
    let obj = part.as_object()?;
    let mut file = Map::new();
    copy_field(obj, &mut file, "file_id");
    copy_field(obj, &mut file, "filename");
    copy_field(obj, &mut file, "file_data");

    if file.is_empty() {
        warn!("dropping Responses input_file without file_id or file_data during Chat Completions translation");
        return None;
    }

    Some(json!({
        "type": "file",
        "file": Value::Object(file)
    }))
}

/// Convert `Responses` function tools into Chat Completions tools.
fn build_chat_tools(obj: &Map<String, Value>) -> Result<Option<Value>, TranslationError> {
    let Some(tools) = obj.get("tools").and_then(Value::as_array) else {
        return Ok(None);
    };
    let mut mapped = Vec::new();

    for tool in tools {
        let Some(tool_obj) = tool.as_object() else {
            continue;
        };
        let Some("function") = tool_obj.get("type").and_then(Value::as_str) else {
            let tool_type = tool_obj.get("type").and_then(Value::as_str).unwrap_or("unknown");
            return Err(TranslationError::UnsupportedToolType(tool_type.to_owned()));
        };
        mapped.push(convert_function_tool(tool_obj));
    }

    if mapped.is_empty() {
        return Ok(None);
    }

    Ok(Some(Value::Array(mapped)))
}

/// Convert one `Responses` function tool into Chat Completions function shape.
fn convert_function_tool(tool: &Map<String, Value>) -> Value {
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

/// Convert simple `Responses` tool-choice values into Chat Completions shape.
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
