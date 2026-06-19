// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Anthropic Messages to Chat Completions-compatible request transformation.

use serde_json::{Map, Value, json};
use tracing::warn;

// -----------------------------------------------------------------------------
// Request Transformation
// -----------------------------------------------------------------------------

/// Transform an Anthropic Messages request body into Chat
/// Completions-compatible format.
///
/// Returns the transformed JSON bytes, or an error message.
pub(crate) fn transform_request(body: &[u8]) -> Result<Vec<u8>, String> {
    let value: Value = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let Some(obj) = value.as_object() else {
        return Err("request body is not a JSON object".to_owned());
    };

    let mut chat = Map::new();

    if let Some(model) = obj.get("model") {
        chat.insert("model".to_owned(), model.clone());
    }

    let mut messages = Vec::new();
    hoist_system(&mut messages, obj);
    convert_messages(&mut messages, obj);
    chat.insert("messages".to_owned(), Value::Array(messages));

    if let Some(max_tokens) = obj.get("max_tokens") {
        chat.insert("max_tokens".to_owned(), max_tokens.clone());
    }

    if let Some(stream) = obj.get("stream") {
        chat.insert("stream".to_owned(), stream.clone());
    }

    map_parameters(&mut chat, obj);
    convert_tools(&mut chat, obj);
    convert_parallel_tool_calls(&mut chat, obj);
    convert_tool_choice(&mut chat, obj);

    serde_json::to_vec(&Value::Object(chat)).map_err(|e| format!("serialization failed: {e}"))
}

// -----------------------------------------------------------------------------
// System Message Hoisting
// -----------------------------------------------------------------------------

/// Hoist Anthropic top-level `system` to a Chat Completions system message.
fn hoist_system(messages: &mut Vec<Value>, obj: &Map<String, Value>) {
    let Some(system) = obj.get("system") else {
        return;
    };

    let content = match system {
        Value::String(s) => s.clone(),
        Value::Array(blocks) => {
            let mut parts = Vec::new();
            for block in blocks {
                if let Some(text) = block.get("text").and_then(Value::as_str) {
                    parts.push(text.to_owned());
                }
            }
            parts.join("\n")
        },
        _ => return,
    };

    if !content.is_empty() {
        messages.push(json!({"role": "system", "content": content}));
    }
}

// -----------------------------------------------------------------------------
// Message Conversion
// -----------------------------------------------------------------------------

/// Convert Anthropic messages array to Chat Completions messages.
fn convert_messages(messages: &mut Vec<Value>, obj: &Map<String, Value>) {
    let Some(Value::Array(anthropic_messages)) = obj.get("messages") else {
        return;
    };

    for msg in anthropic_messages {
        let Some(role) = msg.get("role").and_then(Value::as_str) else {
            continue;
        };

        match msg.get("content") {
            Some(Value::String(text)) => {
                messages.push(json!({"role": role, "content": text}));
            },
            Some(Value::Array(blocks)) => {
                convert_content_blocks(messages, role, blocks);
            },
            _ => {
                messages.push(json!({"role": role, "content": ""}));
            },
        }
    }
}

/// Convert typed content blocks to Chat Completions-compatible format.
fn convert_content_blocks(messages: &mut Vec<Value>, role: &str, blocks: &[Value]) {
    let mut text_parts = Vec::new();
    let mut content_parts: Vec<Value> = Vec::new();
    let mut tool_calls: Vec<Value> = Vec::new();

    for block in blocks {
        let block_type = block.get("type").and_then(Value::as_str).unwrap_or("");
        convert_single_block(
            block,
            block_type,
            messages,
            role,
            &mut text_parts,
            &mut content_parts,
            &mut tool_calls,
        );
    }

    finalize_content_blocks(messages, role, &mut text_parts, &mut content_parts, tool_calls);
}

/// Process a single content block within a message.
#[expect(
    clippy::too_many_arguments,
    reason = "accumulator pattern requires passing all state"
)]
fn convert_single_block(
    block: &Value,
    block_type: &str,
    messages: &mut Vec<Value>,
    role: &str,
    text_parts: &mut Vec<String>,
    content_parts: &mut Vec<Value>,
    tool_calls: &mut Vec<Value>,
) {
    match block_type {
        "text" => convert_text_block(block, text_parts, content_parts),
        "image" => convert_image_block(block, content_parts),
        "tool_use" => convert_tool_use_block(block, tool_calls),
        "tool_result" => {
            flush_text_parts(messages, text_parts, content_parts, role);
            convert_tool_result_block(block, messages);
        },
        "thinking" | "redacted_thinking" => {
            warn!(block_type, "dropping unsupported Anthropic content block");
        },
        _ => {
            warn!(block_type, "dropping unknown Anthropic content block type");
        },
    }
}

/// Convert a text content block.
fn convert_text_block(block: &Value, text_parts: &mut Vec<String>, content_parts: &mut Vec<Value>) {
    if let Some(text) = block.get("text").and_then(Value::as_str) {
        text_parts.push(text.to_owned());
        content_parts.push(json!({"type": "text", "text": text}));
    }
}

/// Convert an image content block.
fn convert_image_block(block: &Value, content_parts: &mut Vec<Value>) {
    if let Some(source) = block.get("source")
        && let Some(url_val) = convert_image_source(source)
    {
        content_parts.push(json!({"type": "image_url", "image_url": {"url": url_val}}));
    }
}

/// Convert a `tool_use` content block to a Chat Completions tool call.
fn convert_tool_use_block(block: &Value, tool_calls: &mut Vec<Value>) {
    let id = block.get("id").and_then(Value::as_str).unwrap_or("");
    let name = block.get("name").and_then(Value::as_str).unwrap_or("");
    let input = block.get("input").cloned().unwrap_or_else(|| Value::Object(Map::new()));
    let args = serde_json::to_string(&input).unwrap_or_default();

    tool_calls.push(json!({
        "id": id,
        "type": "function",
        "function": {"name": name, "arguments": args}
    }));
}

/// Convert a `tool_result` content block to a Chat Completions tool message.
fn convert_tool_result_block(block: &Value, messages: &mut Vec<Value>) {
    let tool_call_id = block.get("tool_use_id").and_then(Value::as_str).unwrap_or("");
    let result_content = extract_tool_result_content(block);
    let image_content = extract_tool_result_image_content(block);

    messages.push(json!({
        "role": "tool",
        "tool_call_id": tool_call_id,
        "content": result_content
    }));

    if !image_content.is_empty() {
        messages.push(json!({
            "role": "user",
            "content": image_content
        }));
    }
}

/// Emit the final message for accumulated content and tool calls.
fn finalize_content_blocks(
    messages: &mut Vec<Value>,
    role: &str,
    text_parts: &mut Vec<String>,
    content_parts: &mut Vec<Value>,
    tool_calls: Vec<Value>,
) {
    if role == "assistant" && !tool_calls.is_empty() {
        let mut msg = json!({"role": "assistant"});
        if let Some(obj) = msg.as_object_mut() {
            if !text_parts.is_empty() {
                obj.insert("content".to_owned(), Value::String(text_parts.join("")));
            }
            obj.insert("tool_calls".to_owned(), Value::Array(tool_calls));
        }
        messages.push(msg);
    } else {
        flush_text_parts(messages, text_parts, content_parts, role);
    }
}

/// Flush accumulated text/content parts as a message.
fn flush_text_parts(
    messages: &mut Vec<Value>,
    text_parts: &mut Vec<String>,
    content_parts: &mut Vec<Value>,
    role: &str,
) {
    if content_parts.is_empty() && text_parts.is_empty() {
        return;
    }

    if content_parts.len() == 1
        && content_parts
            .first()
            .and_then(|p| p.get("type"))
            .and_then(Value::as_str)
            == Some("text")
    {
        messages.push(json!({"role": role, "content": text_parts.join("")}));
    } else if !content_parts.is_empty() {
        messages.push(json!({"role": role, "content": content_parts.clone()}));
    }

    text_parts.clear();
    content_parts.clear();
}

// -----------------------------------------------------------------------------
// Image Source Conversion
// -----------------------------------------------------------------------------

/// Convert Anthropic image source to an `image_url` URL string.
fn convert_image_source(source: &Value) -> Option<String> {
    let source_type = source.get("type").and_then(Value::as_str)?;

    match source_type {
        "base64" => {
            let media_type = source.get("media_type").and_then(Value::as_str)?;
            let data = source.get("data").and_then(Value::as_str)?;
            Some(format!("data:{media_type};base64,{data}"))
        },
        "url" => source.get("url").and_then(Value::as_str).map(str::to_owned),
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// Tool Result Content Extraction
// -----------------------------------------------------------------------------

/// Extract text content from a `tool_result` block.
fn extract_tool_result_content(block: &Value) -> String {
    match block.get("content") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => {
            let mut text_parts = Vec::new();
            for part in parts {
                if part.get("type").and_then(Value::as_str) == Some("text")
                    && let Some(text) = part.get("text").and_then(Value::as_str)
                {
                    text_parts.push(text.to_owned());
                }
            }
            text_parts.join("\n")
        },
        _ => String::new(),
    }
}

/// Extract image content from a `tool_result` block.
fn extract_tool_result_image_content(block: &Value) -> Vec<Value> {
    let Some(Value::Array(parts)) = block.get("content") else {
        return Vec::new();
    };

    let mut image_parts = Vec::new();
    for part in parts {
        if part.get("type").and_then(Value::as_str) == Some("image") {
            convert_image_block(part, &mut image_parts);
        }
    }
    image_parts
}

// -----------------------------------------------------------------------------
// Parameter Mapping
// -----------------------------------------------------------------------------

/// Map Anthropic parameters to Chat Completions-compatible equivalents.
///
/// `top_k` has no standard Chat Completions equivalent but is preserved
/// as an extra body parameter for backends that support it
/// (e.g. vLLM).
fn map_parameters(chat: &mut Map<String, Value>, obj: &Map<String, Value>) {
    if let Some(stop) = obj.get("stop_sequences") {
        chat.insert("stop".to_owned(), stop.clone());
    }

    if let Some(temp) = obj.get("temperature") {
        chat.insert("temperature".to_owned(), temp.clone());
    }

    if let Some(top_p) = obj.get("top_p") {
        chat.insert("top_p".to_owned(), top_p.clone());
    }

    if let Some(top_k) = obj.get("top_k") {
        chat.insert("top_k".to_owned(), top_k.clone());
    }
}

// -----------------------------------------------------------------------------
// Tool Conversion
// -----------------------------------------------------------------------------

/// Convert Anthropic tool definitions to Chat Completions function tools.
fn convert_tools(chat: &mut Map<String, Value>, obj: &Map<String, Value>) {
    let Some(Value::Array(tools)) = obj.get("tools") else {
        return;
    };

    let mut chat_tools = Vec::new();

    for tool in tools {
        let tool_type = tool.get("type").and_then(Value::as_str).unwrap_or("custom");

        if tool_type.starts_with("web_search") || tool_type.starts_with("bash") || tool_type.starts_with("text_editor")
        {
            warn!(tool_type, "dropping server-side Anthropic tool");
            continue;
        }

        let name = tool.get("name").and_then(Value::as_str).unwrap_or("");
        let description = tool.get("description").and_then(Value::as_str).unwrap_or("");
        let parameters = tool
            .get("input_schema")
            .cloned()
            .unwrap_or_else(|| json!({"type": "object"}));

        chat_tools.push(json!({
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": parameters
            }
        }));
    }

    if !chat_tools.is_empty() {
        chat.insert("tools".to_owned(), Value::Array(chat_tools));
    }
}

// -----------------------------------------------------------------------------
// Tool Choice Conversion
// -----------------------------------------------------------------------------

/// Convert Anthropic `disable_parallel_tool_use` to Chat Completions format.
fn convert_parallel_tool_calls(chat: &mut Map<String, Value>, obj: &Map<String, Value>) {
    let Some(Value::Object(tool_choice)) = obj.get("tool_choice") else {
        return;
    };

    if tool_choice
        .get("disable_parallel_tool_use")
        .and_then(Value::as_bool)
        .is_some_and(|disabled| disabled)
    {
        chat.insert("parallel_tool_calls".to_owned(), Value::Bool(false));
    }
}

/// Convert Anthropic `tool_choice` to Chat Completions format.
fn convert_tool_choice(chat: &mut Map<String, Value>, obj: &Map<String, Value>) {
    let Some(tool_choice) = obj.get("tool_choice") else {
        return;
    };

    if obj.contains_key("tools") && !chat.contains_key("tools") {
        return;
    }

    let chat_choice = match tool_choice {
        Value::String(s) => match s.as_str() {
            "any" => Value::String("required".to_owned()),
            "none" => Value::String("none".to_owned()),
            _ => Value::String("auto".to_owned()),
        },
        Value::Object(tc) => match tc.get("type").and_then(Value::as_str) {
            Some("any") => Value::String("required".to_owned()),
            Some("none") => Value::String("none".to_owned()),
            Some("tool") => {
                if let Some(name) = tc.get("name").and_then(Value::as_str) {
                    json!({"type": "function", "function": {"name": name}})
                } else {
                    Value::String("auto".to_owned())
                }
            },
            _ => Value::String("auto".to_owned()),
        },
        _ => return,
    };

    chat.insert("tool_choice".to_owned(), chat_choice);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn basic_text_request() {
        let body = br#"{"model":"claude-opus-4-8","max_tokens":1024,"messages":[{"role":"user","content":"Hello"}]}"#;
        let result = transform_request(body).unwrap();
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(parsed["model"], "claude-opus-4-8", "model preserved");
        assert_eq!(parsed["max_tokens"], 1024, "max_tokens preserved");
        assert_eq!(parsed["messages"][0]["role"], "user", "user message role");
        assert_eq!(parsed["messages"][0]["content"], "Hello", "user message content");
    }

    #[test]
    fn system_hoisted() {
        let body = br#"{"model":"claude-opus-4-8","max_tokens":1024,"system":"Be helpful.","messages":[{"role":"user","content":"Hi"}]}"#;
        let result = transform_request(body).unwrap();
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(
            parsed["messages"][0]["role"], "system",
            "system message should be first"
        );
        assert_eq!(parsed["messages"][0]["content"], "Be helpful.", "system content");
        assert_eq!(parsed["messages"][1]["role"], "user", "user message follows system");
    }

    #[test]
    fn system_text_blocks_joined() {
        let body = br#"{"model":"claude-opus-4-8","max_tokens":1024,"system":[{"type":"text","text":"Part 1"},{"type":"text","text":"Part 2"}],"messages":[{"role":"user","content":"Hi"}]}"#;
        let result = transform_request(body).unwrap();
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(
            parsed["messages"][0]["content"], "Part 1\nPart 2",
            "text blocks should be joined"
        );
    }

    #[test]
    fn tool_use_converted() {
        let body = br#"{"model":"claude-opus-4-8","max_tokens":1024,"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"call_1","name":"get_weather","input":{"city":"NYC"}}]}]}"#;
        let result = transform_request(body).unwrap();
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        let msg = &parsed["messages"][0];
        assert_eq!(msg["role"], "assistant", "assistant role");
        assert_eq!(msg["tool_calls"][0]["function"]["name"], "get_weather", "tool name");
        assert!(
            msg["tool_calls"][0]["function"]["arguments"]
                .as_str()
                .unwrap()
                .contains("NYC"),
            "tool arguments contain city"
        );
    }

    #[test]
    fn tool_result_converted() {
        let body = br#"{"model":"claude-opus-4-8","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_1","content":"72F sunny"}]}]}"#;
        let result = transform_request(body).unwrap();
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(parsed["messages"][0]["role"], "tool", "tool role");
        assert_eq!(parsed["messages"][0]["tool_call_id"], "call_1", "tool_call_id");
        assert_eq!(parsed["messages"][0]["content"], "72F sunny", "tool result content");
    }

    #[test]
    fn tool_result_image_promoted_to_followup_user_message() {
        let body = br#"{"model":"claude-opus-4-8","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_1","content":[{"type":"text","text":"chart"},{"type":"image","source":{"type":"url","url":"https://example.com/chart.png"}}]}]}]}"#;
        let result = transform_request(body).unwrap();
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(parsed["messages"][0]["role"], "tool", "first message is tool result");
        assert_eq!(parsed["messages"][0]["content"], "chart", "tool text content");
        assert_eq!(
            parsed["messages"][1]["role"], "user",
            "image should be promoted to user message"
        );
        assert_eq!(
            parsed["messages"][1]["content"][0]["type"], "image_url",
            "promoted image content type"
        );
        assert_eq!(
            parsed["messages"][1]["content"][0]["image_url"]["url"], "https://example.com/chart.png",
            "promoted image URL"
        );
    }

    #[test]
    fn stop_sequences_mapped() {
        let body =
            br#"{"model":"claude-opus-4-8","max_tokens":1024,"stop_sequences":["END"],"messages":[{"role":"user","content":"Hi"}]}"#;
        let result = transform_request(body).unwrap();
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(parsed["stop"][0], "END", "stop_sequences mapped to stop");
    }

    #[test]
    fn tool_choice_any_mapped() {
        let body = br#"{"model":"claude-opus-4-8","max_tokens":1024,"tool_choice":"any","messages":[{"role":"user","content":"Hi"}]}"#;
        let result = transform_request(body).unwrap();
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(parsed["tool_choice"], "required", "any maps to required");
    }

    #[test]
    fn tool_choice_object_any_mapped() {
        let body = br#"{"model":"claude-opus-4-8","max_tokens":1024,"tools":[{"name":"get_weather","description":"Get weather","input_schema":{"type":"object","properties":{}}}],"tool_choice":{"type":"any"},"messages":[{"role":"user","content":"Hi"}]}"#;
        let result = transform_request(body).unwrap();
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(parsed["tool_choice"], "required", "object-form any maps to required");
    }

    #[test]
    fn tool_choice_dropped_when_all_tools_filtered() {
        let body = br#"{"model":"claude-opus-4-8","max_tokens":1024,"tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"any","messages":[{"role":"user","content":"Hi"}]}"#;
        let result = transform_request(body).unwrap();
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert!(parsed.get("tools").is_none(), "server-side tools should be filtered");
        assert!(
            parsed.get("tool_choice").is_none(),
            "tool_choice without translated tools should be dropped"
        );
    }

    #[test]
    fn disable_parallel_tool_use_mapped() {
        let body = br#"{"model":"claude-opus-4-8","max_tokens":1024,"tools":[{"name":"get_weather","description":"Get weather","input_schema":{"type":"object","properties":{}}}],"tool_choice":{"type":"auto","disable_parallel_tool_use":true},"messages":[{"role":"user","content":"Hi"}]}"#;
        let result = transform_request(body).unwrap();
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(
            parsed["parallel_tool_calls"], false,
            "disable_parallel_tool_use should disable parallel tool calls"
        );
    }

    #[test]
    fn tool_definitions_converted() {
        let body = br#"{"model":"claude-opus-4-8","max_tokens":1024,"tools":[{"name":"get_weather","description":"Get weather","input_schema":{"type":"object","properties":{"city":{"type":"string"}}}}],"messages":[{"role":"user","content":"Hi"}]}"#;
        let result = transform_request(body).unwrap();
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(parsed["tools"][0]["type"], "function", "tool type should be function");
        assert_eq!(parsed["tools"][0]["function"]["name"], "get_weather", "tool name");
    }

    #[test]
    fn image_base64_converted() {
        let body = br#"{"model":"claude-opus-4-8","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/jpeg","data":"abc123"}},{"type":"text","text":"What is this?"}]}]}"#;
        let result = transform_request(body).unwrap();
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        let content = &parsed["messages"][0]["content"];
        assert_eq!(content[0]["type"], "image_url", "image type");
        assert_eq!(
            content[0]["image_url"]["url"], "data:image/jpeg;base64,abc123",
            "data URL"
        );
        assert_eq!(content[1]["type"], "text", "text part follows");
    }

    #[test]
    fn top_k_preserved_as_extra_param() {
        let body =
            br#"{"model":"claude-opus-4-8","max_tokens":1024,"top_k":40,"messages":[{"role":"user","content":"Hi"}]}"#;
        let result = transform_request(body).unwrap();
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(parsed["top_k"], 40, "top_k should be preserved as extra body parameter");
    }
}
