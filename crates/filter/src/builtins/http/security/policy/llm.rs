// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Inference body parsing + typed CMF content builders.
//!
//! | Read | Used for |
//! |---|---|
//! | top-level `model` | the entity name and `llm.model_id` |
//! | top-level `stream` | a `custom.llm.stream` attribute a rule can deny |
//! | configured scalars | `custom.llm.<name>` bag attributes |
//! | `messages` / `prompt` / `system` | the CMF message a scanner reads |
//! | `usage` / `finish_reason` | the `completion.*` bag attributes |
//!
//! Every OpenAI and Anthropic shape carries `model` at the top level, so
//! authorization needs no per-API mode. Prompt text is best-effort by
//! contrast: an unrecognized shape yields no content and the route still
//! authorizes on `llm.model_id`.

use bytes::Bytes;
use ppe::praxis_policy_core::cmf::{ContentPart, Message, Role};

// -----------------------------------------------------------------------------
// Request side
// -----------------------------------------------------------------------------

/// An inference request body, parsed once for the whole phase: every
/// reader below walks the same document.
pub(super) struct ParsedLlmRequest(serde_json::Value);

impl ParsedLlmRequest {
    /// Parse `body`; malformed or empty input yields a `Null` document.
    pub(super) fn parse(body: &Bytes) -> Self {
        Self(serde_json::from_slice(body).unwrap_or(serde_json::Value::Null))
    }

    /// The top-level `model`, when it is a non-empty string.
    ///
    /// Anything else is `None` — a request the caller cannot attribute to
    /// a model. Control characters are rejected too: the value becomes
    /// the entity name, so it reaches route matching, audit records and
    /// log lines, and no real model identifier carries them.
    pub(super) fn model(&self) -> Option<&str> {
        self.0
            .get("model")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|model| !model.is_empty() && !model.chars().any(char::is_control))
    }

    /// Whether the caller asked for a streamed response.
    pub(super) fn is_streaming(&self) -> bool {
        self.0
            .get("stream")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    }

    /// The configured top-level scalars, keyed for `custom.llm.<name>`.
    ///
    /// Scalars only. A parameter that is an object is nothing a rule can
    /// compare, and promoting it would put arbitrary client-supplied
    /// structure in the bag.
    pub(super) fn promoted_params(&self, names: &[String]) -> serde_json::Map<String, serde_json::Value> {
        names
            .iter()
            .filter_map(|name| {
                self.0
                    .get(name)
                    .filter(|value| !matches!(value, serde_json::Value::Object(_) | serde_json::Value::Array(_)))
                    .filter(|value| !value.is_null())
                    .map(|value| (name.clone(), value.clone()))
            })
            .collect()
    }

    /// The CMF content a `cmf.llm_input` handler evaluates: one text
    /// part per prompt-bearing field, in wire order, so a scanner sees
    /// the whole prompt rather than the last turn.
    pub(super) fn content(&self) -> Vec<ContentPart> {
        let mut parts = Vec::new();

        // Anthropic carries the system prompt beside `messages` rather
        // than as a message with `role: system`.
        if let Some(system) = self.0.get("system") {
            push_text(&mut parts, system);
        }

        if let Some(messages) = self.0.get("messages").and_then(serde_json::Value::as_array) {
            for message in messages {
                if let Some(content) = message.get("content") {
                    push_text(&mut parts, content);
                }
            }
        }

        // Legacy completions. Also an array of prompts, which the
        // multimodal walker already handles.
        if let Some(prompt) = self.0.get("prompt") {
            push_text(&mut parts, prompt);
        }

        parts
    }

    /// The parsed document, for a caller that needs the raw shape.
    #[cfg(test)]
    pub(super) fn as_value(&self) -> &serde_json::Value {
        &self.0
    }
}

/// Append the text `value` carries as a content part.
///
/// A message's `content` is either a string or the multimodal array of
/// `{type, text}` parts; anything carrying no text contributes nothing.
fn push_text(parts: &mut Vec<ContentPart>, value: &serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            if !text.is_empty() {
                parts.push(ContentPart::Text { text: text.clone() });
            }
        },
        serde_json::Value::Array(items) => {
            for item in items {
                match item {
                    serde_json::Value::String(_) => push_text(parts, item),
                    serde_json::Value::Object(_) => {
                        if let Some(text) = item.get("text") {
                            push_text(parts, text);
                        }
                    },
                    _ => {},
                }
            }
        },
        _ => {},
    }
}

/// The CMF payload message for an inference request.
pub(super) fn request_message(parsed: &ParsedLlmRequest) -> Message {
    Message::with_content(Role::User, parsed.content())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    fn request(json: &str) -> ParsedLlmRequest {
        ParsedLlmRequest::parse(&Bytes::from(json.to_owned()))
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
    fn duplicate_model_keys_are_last_wins() {
        assert_eq!(
            request(r#"{"model":"gpt-4o-mini","model":"gpt-4o"}"#).model(),
            Some("gpt-4o"),
            "last-wins matches serde_json and typical backend parsers, so policy sees the \
             value the backend will act on",
        );
    }

    #[test]
    fn detects_the_streaming_flag() {
        assert!(request(r#"{"model":"m","stream":true}"#).is_streaming());
        assert!(!request(r#"{"model":"m","stream":false}"#).is_streaming());
        assert!(!request(r#"{"model":"m"}"#).is_streaming());
        assert!(!request(r#"{"model":"m","stream":"true"}"#).is_streaming());
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
    fn unknown_body_shape_yields_no_content_but_keeps_the_model() {
        let parsed = request(r#"{"model":"m","inputs":{"nested":"value"}}"#);
        assert!(parsed.content().is_empty());
        assert_eq!(parsed.model(), Some("m"), "authorization never depends on the prompt");
    }

    #[test]
    fn embeddings_request_has_a_model_and_no_prompt_text() {
        let parsed = request(r#"{"model":"text-embedding-3-small","input":"hello"}"#);
        assert_eq!(parsed.model(), Some("text-embedding-3-small"));
        assert!(parsed.content().is_empty());
        assert!(parsed.as_value().is_object());
    }


    #[test]
    fn the_request_message_speaks_as_the_caller() {
        assert!(matches!(request_message(&request(r#"{"model":"m"}"#)).role, Role::User));
    }
}
