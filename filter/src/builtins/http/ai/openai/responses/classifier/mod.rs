// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Pure request body classifier for Responses API versus Chat Completions.

// -----------------------------------------------------------------------------
// AiRequestFormat
// -----------------------------------------------------------------------------

/// Classified request body format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AiRequestFormat {
    /// `OpenAI` Responses API (has `input` field).
    Responses,
    /// Chat Completions API (has `messages` field).
    ChatCompletions,
    /// Valid JSON but neither recognized format.
    UnknownJson,
    /// Body is not valid JSON.
    InvalidJson,
    /// Body is empty or absent.
    NonJson,
}

impl AiRequestFormat {
    /// Stable string representation for headers, metadata, and filter results.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Responses => "openai_responses",
            Self::ChatCompletions => "openai_chat_completions",
            Self::UnknownJson => "unknown",
            Self::InvalidJson => "invalid_json",
            Self::NonJson => "non_json",
        }
    }
}

// -----------------------------------------------------------------------------
// ClassifiedRequest
// -----------------------------------------------------------------------------

/// Extracted facts from a classified request body.
#[derive(Debug)]
pub(crate) struct ClassifiedRequest {
    /// Extracted `background` field value, if present.
    pub background: Option<bool>,
    /// Detected body format.
    pub format: AiRequestFormat,
    /// Whether `conversation` is present and non-null.
    pub has_conversation: bool,
    /// Whether `previous_response_id` is present and non-null.
    pub has_previous_response_id: bool,
    /// Extracted `model` field value, if present.
    pub model: Option<String>,
    /// Extracted `store` field value, if present.
    pub store: Option<bool>,
    /// Extracted `stream` field value, if present.
    pub stream: Option<bool>,
}

// -----------------------------------------------------------------------------
// Classification
// -----------------------------------------------------------------------------

/// Classify a request body and extract routing facts.
///
/// This function is pure: no I/O, no side effects, no mutation of
/// the input bytes.
pub(crate) fn classify_request_body(body: &[u8]) -> ClassifiedRequest {
    if body.is_empty() {
        return empty_result(AiRequestFormat::NonJson);
    }

    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return empty_result(AiRequestFormat::InvalidJson);
    };

    let Some(obj) = value.as_object() else {
        return empty_result(AiRequestFormat::InvalidJson);
    };

    let format = classify_format(obj);

    ClassifiedRequest {
        background: obj.get("background").and_then(serde_json::Value::as_bool),
        format,
        has_conversation: obj.get("conversation").is_some_and(|v| !v.is_null()),
        has_previous_response_id: obj.get("previous_response_id").is_some_and(|v| !v.is_null()),
        model: extract_string(obj, "model"),
        store: obj.get("store").and_then(serde_json::Value::as_bool),
        stream: obj.get("stream").and_then(serde_json::Value::as_bool),
    }
}

/// Determine format from top-level keys. When both `input` and
/// `messages` are present, `input` takes precedence (Responses API).
fn classify_format(obj: &serde_json::Map<String, serde_json::Value>) -> AiRequestFormat {
    if obj.contains_key("input") {
        AiRequestFormat::Responses
    } else if obj.contains_key("messages") {
        AiRequestFormat::ChatCompletions
    } else {
        AiRequestFormat::UnknownJson
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Build a result with no extracted facts.
fn empty_result(format: AiRequestFormat) -> ClassifiedRequest {
    ClassifiedRequest {
        background: None,
        format,
        has_conversation: false,
        has_previous_response_id: false,
        model: None,
        store: None,
        stream: None,
    }
}

/// Extract a string field from a JSON object, converting numbers/booleans
/// to their string representation.
fn extract_string(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    obj.get(key).and_then(|v| match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn responses_string_input() {
        let body = br#"{"model":"gpt-4.1-mini","input":"Hello, world!"}"#;
        let result = classify_request_body(body);

        assert_eq!(
            result.format,
            AiRequestFormat::Responses,
            "string input should classify as responses"
        );
        assert_eq!(
            result.model.as_deref(),
            Some("gpt-4.1-mini"),
            "model should be extracted"
        );
    }

    #[test]
    fn responses_array_input() {
        let body = br#"{"model":"gpt-4.1","input":[{"type":"message","role":"user","content":"Hi"}]}"#;
        let result = classify_request_body(body);

        assert_eq!(
            result.format,
            AiRequestFormat::Responses,
            "array input should classify as responses"
        );
        assert_eq!(result.model.as_deref(), Some("gpt-4.1"), "model should be extracted");
    }

    #[test]
    fn responses_null_input_classifies_as_responses() {
        let body = br#"{"model":"gpt-4.1","input":null}"#;
        let result = classify_request_body(body);

        assert_eq!(
            result.format,
            AiRequestFormat::Responses,
            "input key should classify as responses even when input is null"
        );
        assert_eq!(result.model.as_deref(), Some("gpt-4.1"), "model should be extracted");
    }

    #[test]
    fn responses_with_stream_store_previous_response_id() {
        let body =
            br#"{"model":"gpt-4.1","input":"test","stream":true,"store":false,"background":true,"previous_response_id":"resp_abc"}"#;
        let result = classify_request_body(body);

        assert_eq!(result.format, AiRequestFormat::Responses, "should be responses");
        assert_eq!(result.stream, Some(true), "stream should be extracted");
        assert_eq!(result.store, Some(false), "store should be extracted");
        assert_eq!(result.background, Some(true), "background should be extracted");
        assert!(
            result.has_previous_response_id,
            "previous_response_id should be detected"
        );
    }

    #[test]
    fn responses_with_conversation() {
        let body = br#"{"model":"gpt-4.1","input":"test","conversation":{"id":"conv_123"}}"#;
        let result = classify_request_body(body);

        assert_eq!(result.format, AiRequestFormat::Responses, "should be responses");
        assert!(result.has_conversation, "conversation should be detected");
        assert!(!result.has_previous_response_id, "no previous_response_id");
    }

    #[test]
    fn chat_completions_messages() {
        let body = br#"{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}"#;
        let result = classify_request_body(body);

        assert_eq!(
            result.format,
            AiRequestFormat::ChatCompletions,
            "messages array should classify as openai_chat_completions"
        );
        assert_eq!(result.model.as_deref(), Some("gpt-4"), "model should be extracted");
    }

    #[test]
    fn chat_completions_with_stream() {
        let body = br#"{"model":"gpt-4","messages":[],"stream":true}"#;
        let result = classify_request_body(body);

        assert_eq!(
            result.format,
            AiRequestFormat::ChatCompletions,
            "should be openai_chat_completions"
        );
        assert_eq!(result.stream, Some(true), "stream should be extracted");
    }

    #[test]
    fn unknown_json_no_input_no_messages() {
        let body = br#"{"model":"gpt-4","prompt":"hello"}"#;
        let result = classify_request_body(body);

        assert_eq!(
            result.format,
            AiRequestFormat::UnknownJson,
            "JSON without input or messages should be unknown"
        );
        assert_eq!(
            result.model.as_deref(),
            Some("gpt-4"),
            "model should still be extracted"
        );
    }

    #[test]
    fn invalid_json() {
        let body = b"not json at all {{{";
        let result = classify_request_body(body);

        assert_eq!(
            result.format,
            AiRequestFormat::InvalidJson,
            "garbage should be invalid_json"
        );
        assert!(result.model.is_none(), "no model from invalid JSON");
    }

    #[test]
    fn empty_body() {
        let result = classify_request_body(b"");

        assert_eq!(result.format, AiRequestFormat::NonJson, "empty body should be non_json");
    }

    #[test]
    fn json_array_is_invalid() {
        let body = b"[1, 2, 3]";
        let result = classify_request_body(body);

        assert_eq!(
            result.format,
            AiRequestFormat::InvalidJson,
            "JSON array should be invalid (not an object)"
        );
    }

    #[test]
    fn null_previous_response_id_not_detected() {
        let body = br#"{"model":"gpt-4.1","input":"test","previous_response_id":null}"#;
        let result = classify_request_body(body);

        assert!(
            !result.has_previous_response_id,
            "null previous_response_id should not be detected as present"
        );
    }

    #[test]
    fn null_conversation_not_detected() {
        let body = br#"{"model":"gpt-4.1","input":"test","conversation":null}"#;
        let result = classify_request_body(body);

        assert!(
            !result.has_conversation,
            "null conversation should not be detected as present"
        );
    }

    #[test]
    fn missing_model_returns_none() {
        let body = br#"{"input":"test"}"#;
        let result = classify_request_body(body);

        assert_eq!(
            result.format,
            AiRequestFormat::Responses,
            "should still classify as responses"
        );
        assert!(result.model.is_none(), "missing model should return None");
    }

    #[test]
    fn stream_and_store_absent_returns_none() {
        let body = br#"{"model":"gpt-4.1","input":"test"}"#;
        let result = classify_request_body(body);

        assert!(result.stream.is_none(), "absent stream should be None");
        assert!(result.store.is_none(), "absent store should be None");
        assert!(result.background.is_none(), "absent background should be None");
    }

    #[test]
    fn background_false_extracted() {
        let body = br#"{"model":"gpt-4.1","input":"test","background":false}"#;
        let result = classify_request_body(body);

        assert_eq!(
            result.background,
            Some(false),
            "top-level boolean background:false should be extracted"
        );
    }

    #[test]
    fn null_background_not_detected() {
        let body = br#"{"model":"gpt-4.1","input":"test","background":null}"#;
        let result = classify_request_body(body);

        assert!(
            result.background.is_none(),
            "null background should not be detected as present"
        );
    }

    #[test]
    fn non_boolean_background_not_detected() {
        let body = br#"{"model":"gpt-4.1","input":"test","background":"true"}"#;
        let result = classify_request_body(body);

        assert!(
            result.background.is_none(),
            "non-boolean background should not be detected as present"
        );
    }

    #[test]
    fn nested_background_not_detected() {
        let body = br#"{"model":"gpt-4.1","input":[{"type":"input_image","background":true}]}"#;
        let result = classify_request_body(body);

        assert!(
            result.background.is_none(),
            "nested background fields should not be detected as top-level background"
        );
    }

    #[test]
    fn oversized_model_extracted() {
        let long_model = "x".repeat(1024);
        let body = format!(r#"{{"model":"{long_model}","input":"test"}}"#);
        let result = classify_request_body(body.as_bytes());

        assert_eq!(
            result.model.as_deref(),
            Some(long_model.as_str()),
            "oversized model should still be extracted by classifier"
        );
    }

    #[test]
    fn both_input_and_messages_classifies_as_responses() {
        let body = br#"{"model":"gpt-4.1","input":"test","messages":[{"role":"user","content":"Hi"}]}"#;
        let result = classify_request_body(body);

        assert_eq!(
            result.format,
            AiRequestFormat::Responses,
            "input takes precedence when both input and messages are present"
        );
    }

    #[test]
    fn control_char_model_extracted() {
        let body = b"{\"model\":\"bad\\nmodel\",\"input\":\"test\"}";
        let result = classify_request_body(body);

        assert_eq!(
            result.model.as_deref(),
            Some("bad\nmodel"),
            "model with control chars should still be extracted by classifier"
        );
    }
}
