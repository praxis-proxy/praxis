// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Inference body parsing + typed CMF content builders.
//!
//! | Read | Used for |
//! |---|---|
//! | top-level `model` | the entity name and `llm.model_id` |
//! | top-level `stream` | skipping the response phase for SSE |
//! | configured scalars | `custom.llm.<name>` bag attributes |
//! | `messages` / `prompt` / `system` | the CMF message a scanner reads |
//! | `usage` / `finish_reason` | the `completion.*` bag attributes |
//!
//! Every OpenAI and Anthropic shape carries `model` at the top level, so
//! authorization needs no per-API mode. Prompt text is best-effort by
//! contrast: an unrecognized shape yields no content and the route still
//! authorizes on `llm.model_id`.

use bytes::Bytes;
use ppe::praxis_policy_core::{
    cmf::{ContentPart, Message, Role},
    extensions::{CompletionExtension, StopReason, TokenUsage},
};

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

    /// Whether the caller asked for a streamed response. Read here
    /// because the upstream may ignore the flag and answer either way.
    ///
    /// Every spelling a lax backend coerces counts, not just JSON
    /// `true` — see [`truthy`].
    pub(super) fn is_streaming(&self) -> bool {
        self.0.get("stream").is_some_and(truthy)
    }

    /// The configured top-level scalars, keyed for `custom.llm.<name>`.
    ///
    /// Scalars only. A parameter that is an object is nothing a rule can
    /// compare, and promoting it would put arbitrary client-supplied
    /// structure in the bag.
    ///
    /// A boolean parameter is normalized to a JSON bool, so a rule reads
    /// the value the upstream would act on rather than the client's
    /// spelling of it.
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

/// Top-level request fields whose value is semantically a boolean.
///
/// Only these are normalized: a numeric field like `n` must stay a
/// number, or `custom.llm.n > 0` would compare against a bool.
const BOOLEAN_PARAMS: &[&str] = &["stream"];

/// Whether a request field reads as true in any spelling a backend
/// would act on.
///
/// An OpenAI-compatible backend built on lax deserialization coerces
/// `"true"` and `1`, so policy has to agree: a rule over
/// `custom.llm.stream` must fire on whatever the upstream will honor,
/// not only on JSON `true`.
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

/// The value promoted to `custom.llm.<name>`: a boolean field as a JSON
/// bool, anything else unchanged.
fn normalize_param(name: &str, value: &serde_json::Value) -> serde_json::Value {
    if BOOLEAN_PARAMS.contains(&name) {
        return serde_json::Value::Bool(truthy(value));
    }
    value.clone()
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
// Response side
// -----------------------------------------------------------------------------

/// An inference response body parsed once for the response phase.
pub(super) struct ParsedLlmResponse(serde_json::Value);

impl ParsedLlmResponse {
    /// Parse `body`; malformed or empty input yields a `Null` document.
    pub(super) fn parse(body: &Bytes) -> Self {
        Self(serde_json::from_slice(body).unwrap_or(serde_json::Value::Null))
    }

    /// Whether the body parsed to a JSON object at all. A response the
    /// caller cannot read has no completion to evaluate.
    pub(super) fn is_object(&self) -> bool {
        self.0.is_object()
    }

    /// Completion metadata for the `completion.*` bag attributes.
    ///
    /// Reads both providers' spellings of `usage`. `tokens` is unset
    /// when the response reported no counts at all; once any count is
    /// present the others default to 0, because `TokenUsage` carries
    /// three plain `u32`s and cannot record a single field as unset.
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
        // Anthropic reports the two halves and no total; deriving it
        // keeps one rule (`completion.tokens.total`) working for both.
        // A half the provider omitted counts as 0 rather than voiding the
        // total: a budget rule reading 0 would admit the response.
        let total = total.or_else(|| {
            (input.is_some() || output.is_some()).then(|| input.unwrap_or(0).saturating_add(output.unwrap_or(0)))
        });
        (input.is_some() || output.is_some() || total.is_some()).then(|| TokenUsage {
            input_tokens: input.unwrap_or(0),
            output_tokens: output.unwrap_or(0),
            total_tokens: total.unwrap_or(0),
        })
    }

    /// Why generation stopped. An unrecognized reason is left unset
    /// rather than mapped to a plausible neighbour.
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

/// A `u32` token count, whatever numeric shape the provider used.
///
/// Saturates instead of discarding. A count above `u32::MAX`, or a
/// fractional one, still has to reach a budget rule: dropping it would
/// leave the field at 0 and admit a response the rule meant to deny.
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

    // -----------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------

    fn request(json: &str) -> ParsedLlmRequest {
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
