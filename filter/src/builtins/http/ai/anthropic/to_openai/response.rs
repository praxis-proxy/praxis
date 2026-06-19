// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Chat Completions-compatible response to Anthropic Messages transformation.

use serde_json::{Map, Value, json};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default response type.
const RESPONSE_TYPE: &str = "message";

/// Default response role.
const RESPONSE_ROLE: &str = "assistant";

// -----------------------------------------------------------------------------
// Response Transformation
// -----------------------------------------------------------------------------

/// Result of a response transformation.
pub(crate) struct TransformResult {
    /// Transformed response body bytes.
    pub body: Vec<u8>,
    /// Original Chat Completions `finish_reason` (preserved for metadata).
    pub original_finish_reason: String,
}

/// Transform a Chat Completions-compatible response body into Anthropic
/// Messages format.
pub(crate) fn transform_response(body: &[u8], request_model: &str) -> Result<TransformResult, String> {
    let value: Value = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let Some(obj) = value.as_object() else {
        return Err("response body is not a JSON object".to_owned());
    };

    let mut anthropic = Map::new();

    let id = match obj.get("id").and_then(Value::as_str) {
        Some(id) => format!("msg_{id}"),
        None => format!("msg_{}", timestamp_hex_id()),
    };

    anthropic.insert("id".to_owned(), Value::String(id));
    anthropic.insert("type".to_owned(), Value::String(RESPONSE_TYPE.to_owned()));
    anthropic.insert("role".to_owned(), Value::String(RESPONSE_ROLE.to_owned()));

    let model = obj.get("model").and_then(Value::as_str).unwrap_or(request_model);
    anthropic.insert("model".to_owned(), Value::String(model.to_owned()));

    let content = build_content_blocks(obj);
    anthropic.insert("content".to_owned(), Value::Array(content));

    let (stop_reason, original_finish_reason) = map_finish_reason(obj);
    anthropic.insert("stop_reason".to_owned(), Value::String(stop_reason));
    anthropic.insert("stop_sequence".to_owned(), Value::Null);

    let usage = build_usage(obj);
    anthropic.insert("usage".to_owned(), usage);

    let body = serde_json::to_vec(&Value::Object(anthropic)).map_err(|e| format!("serialization failed: {e}"))?;
    Ok(TransformResult {
        body,
        original_finish_reason,
    })
}

// -----------------------------------------------------------------------------
// Content Block Building
// -----------------------------------------------------------------------------

/// Extract content blocks from the first choice.
fn build_content_blocks(obj: &Map<String, Value>) -> Vec<Value> {
    let mut blocks = Vec::new();

    let choice = obj.get("choices").and_then(Value::as_array).and_then(|c| c.first());

    let Some(choice) = choice else {
        return blocks;
    };

    let message = choice.get("message");
    extract_text_block(message, &mut blocks);
    extract_tool_call_blocks(message, &mut blocks);

    blocks
}

/// Extract a text content block from the message if present.
fn extract_text_block(message: Option<&Value>, blocks: &mut Vec<Value>) {
    if let Some(content) = message.and_then(|m| m.get("content")).and_then(Value::as_str)
        && !content.is_empty()
    {
        blocks.push(json!({"type": "text", "text": content}));
    }
}

/// Extract tool call blocks from the message.
fn extract_tool_call_blocks(message: Option<&Value>, blocks: &mut Vec<Value>) {
    let Some(Value::Array(tool_calls)) = message.and_then(|m| m.get("tool_calls")) else {
        return;
    };

    for tc in tool_calls {
        let id = tc.get("id").and_then(Value::as_str).unwrap_or("");
        let name = tc
            .get("function")
            .and_then(|f| f.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let args_str = tc
            .get("function")
            .and_then(|f| f.get("arguments"))
            .and_then(Value::as_str)
            .unwrap_or("{}");
        let input: Value = serde_json::from_str(args_str).unwrap_or_else(|_| Value::Object(Map::new()));

        blocks.push(json!({
            "type": "tool_use",
            "id": id,
            "name": name,
            "input": input
        }));
    }
}

// -----------------------------------------------------------------------------
// Finish Reason Mapping
// -----------------------------------------------------------------------------

/// Map Chat Completions `finish_reason` to Anthropic `stop_reason`.
///
/// Returns `(anthropic_stop_reason, original_finish_reason)`.
/// The `content_filter` to `end_turn` mapping is lossy; the
/// original is preserved so callers can store it in metadata.
fn map_finish_reason(obj: &Map<String, Value>) -> (String, String) {
    let finish_reason = obj
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|c| c.get("finish_reason"))
        .and_then(Value::as_str)
        .unwrap_or("stop");

    let mapped = match finish_reason {
        "tool_calls" => "tool_use",
        "length" => "max_tokens",
        _ => "end_turn",
    };

    (mapped.to_owned(), finish_reason.to_owned())
}

// -----------------------------------------------------------------------------
// Usage Mapping
// -----------------------------------------------------------------------------

/// Build Anthropic usage object from Chat Completions usage.
fn build_usage(obj: &Map<String, Value>) -> Value {
    let usage = obj.get("usage");

    let input_tokens = usage
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let output_tokens = usage
        .and_then(|u| u.get("completion_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let cache_read = usage
        .and_then(|u| u.get("prompt_tokens_details"))
        .and_then(|d| d.get("cached_tokens"))
        .and_then(Value::as_u64);

    let mut usage_obj = json!({
        "input_tokens": input_tokens,
        "output_tokens": output_tokens
    });

    if let Some(cached) = cache_read
        && let Some(obj) = usage_obj.as_object_mut()
    {
        obj.insert("cache_read_input_tokens".to_owned(), Value::Number(cached.into()));
    }

    usage_obj
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Generate a timestamp-based hex identifier for response IDs.
fn timestamp_hex_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    format!("{nanos:024x}")
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn basic_text_response() {
        let body = br#"{"id":"chatcmpl-1","model":"gpt-4","choices":[{"message":{"role":"assistant","content":"Hello!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#;
        let tr = transform_response(body, "gpt-4").unwrap();
        let result = tr.body;
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(parsed["type"], "message", "type should be message");
        assert_eq!(parsed["role"], "assistant", "role should be assistant");
        assert_eq!(parsed["content"][0]["type"], "text", "content block type");
        assert_eq!(parsed["content"][0]["text"], "Hello!", "content text");
        assert_eq!(parsed["stop_reason"], "end_turn", "stop → end_turn");
        assert_eq!(parsed["usage"]["input_tokens"], 10, "input tokens");
        assert_eq!(parsed["usage"]["output_tokens"], 5, "output tokens");
    }

    #[test]
    fn tool_calls_response() {
        let body = br#"{"id":"chatcmpl-2","model":"gpt-4","choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"NYC\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":20,"completion_tokens":15}}"#;
        let tr = transform_response(body, "gpt-4").unwrap();
        let result = tr.body;
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(parsed["stop_reason"], "tool_use", "tool_calls → tool_use");
        assert_eq!(parsed["content"][0]["type"], "tool_use", "tool_use block");
        assert_eq!(parsed["content"][0]["name"], "get_weather", "tool name");
        assert_eq!(parsed["content"][0]["input"]["city"], "NYC", "parsed input");
    }

    #[test]
    fn length_finish_reason() {
        let body = br#"{"id":"chatcmpl-3","model":"gpt-4","choices":[{"message":{"role":"assistant","content":"truncated..."},"finish_reason":"length"}],"usage":{"prompt_tokens":10,"completion_tokens":100}}"#;
        let tr = transform_response(body, "gpt-4").unwrap();
        let result = tr.body;
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(parsed["stop_reason"], "max_tokens", "length → max_tokens");
    }

    #[test]
    fn cached_tokens_in_usage() {
        let body = br#"{"id":"chatcmpl-4","model":"gpt-4","choices":[{"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":80}}}"#;
        let tr = transform_response(body, "gpt-4").unwrap();
        let result = tr.body;
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(parsed["usage"]["cache_read_input_tokens"], 80, "cached tokens mapped");
    }
}
