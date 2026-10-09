// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Inference request and response parsing for CMF policy evaluation.

use std::{cell::Cell, collections::HashSet, fmt};

use bytes::Bytes;
use ppe::praxis_policy_core::{
    cmf::{ContentPart, Message, Role},
    extensions::{CompletionExtension, StopReason, TokenUsage},
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
/// Every non-message item type is scanned, so a tool call or output of a
/// type not named here still reaches prompt rules and scanners.
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

    // -----------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------

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
