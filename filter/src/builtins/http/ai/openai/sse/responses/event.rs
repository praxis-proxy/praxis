// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Typed Responses API SSE event enum.

use serde_json::Value;

use super::super::{SseFrame, SseParseError};

/// A parsed Responses API streaming event.
#[expect(dead_code, reason = "variants consumed by stream_events filter (#433)")]
#[derive(Debug)]
pub(crate) enum ResponsesEvent {
    // Response lifecycle
    /// `response.created` — response object created.
    ResponseCreated(Value),
    /// `response.queued` — response queued for generation.
    ResponseQueued(Value),
    /// `response.in_progress` — response generation in progress.
    ResponseInProgress(Value),
    /// `response.completed` — response generation completed (terminal).
    ResponseCompleted(Value),
    /// `response.incomplete` — response generation incomplete (terminal).
    ResponseIncomplete(Value),
    /// `response.failed` — response generation failed (terminal).
    ResponseFailed(Value),

    // Output items
    /// `response.output_item.added` — new output item added.
    OutputItemAdded(Value),
    /// `response.output_item.done` — output item completed.
    OutputItemDone(Value),

    // Content parts
    /// `response.content_part.added` — new content part added.
    ContentPartAdded(Value),
    /// `response.content_part.done` — content part completed.
    ContentPartDone(Value),

    // Text
    /// `response.output_text.delta` — incremental text output.
    OutputTextDelta(Value),
    /// `response.output_text.done` — text output completed.
    OutputTextDone(Value),
    /// `response.output_text.annotation.added` — annotation added to text.
    OutputTextAnnotationAdded(Value),

    // Function calls
    /// `response.function_call_arguments.delta` — incremental function call arguments.
    FunctionCallArgumentsDelta(Value),
    /// `response.function_call_arguments.done` — function call arguments completed.
    FunctionCallArgumentsDone(Value),

    // Refusal
    /// `response.refusal.delta` — incremental refusal text.
    RefusalDelta(Value),
    /// `response.refusal.done` — refusal text completed.
    RefusalDone(Value),

    // Reasoning
    /// `response.reasoning.delta` — incremental reasoning content.
    ReasoningDelta(Value),
    /// `response.reasoning.done` — reasoning content completed.
    ReasoningDone(Value),
    /// `response.reasoning_summary_text.delta` — incremental reasoning summary text.
    ReasoningSummaryTextDelta(Value),
    /// `response.reasoning_summary_text.done` — reasoning summary text completed.
    ReasoningSummaryTextDone(Value),
    /// `response.reasoning_summary_part.added` — reasoning summary part added.
    ReasoningSummaryPartAdded(Value),
    /// `response.reasoning_summary_part.done` — reasoning summary part completed.
    ReasoningSummaryPartDone(Value),

    // Error
    /// `error` — error event.
    Error(Value),

    /// Unknown or future event type.
    Unknown {
        /// Event type string.
        event_type: String,
        /// JSON payload.
        data: Value,
    },
}

impl ResponsesEvent {
    /// Parse an [`SseFrame`] into a typed event.
    pub fn from_frame(frame: &SseFrame) -> Result<Self, SseParseError> {
        let data: Value = serde_json::from_slice(&frame.data).map_err(|e| SseParseError::MalformedJson {
            event_type: frame.event_type.clone().unwrap_or_default(),
            err: e.to_string(),
        })?;

        let data_type = data
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| SseParseError::MissingEventType {
                field: "data.type",
                event_type: frame.event_type.clone().unwrap_or_default(),
            })?;

        if let Some(event_type) = frame.event_type.as_deref()
            && canonical_event_type(event_type) != canonical_event_type(data_type)
        {
            return Err(SseParseError::EventTypeMismatch {
                sse_event_type: event_type.to_owned(),
                data_event_type: data_type.to_owned(),
            });
        }

        let event_type = data_type.to_owned();
        Ok(Self::from_event_type(&event_type, data))
    }

    /// Match event type string to enum variant.
    fn from_event_type(event_type: &str, data: Value) -> Self {
        match event_type {
            "response.created" => Self::ResponseCreated(data),
            "response.queued" => Self::ResponseQueued(data),
            "response.in_progress" => Self::ResponseInProgress(data),
            "response.completed" => Self::ResponseCompleted(data),
            "response.incomplete" => Self::ResponseIncomplete(data),
            "response.failed" => Self::ResponseFailed(data),
            "response.output_item.added" => Self::OutputItemAdded(data),
            "response.output_item.done" => Self::OutputItemDone(data),
            "response.content_part.added" => Self::ContentPartAdded(data),
            "response.content_part.done" => Self::ContentPartDone(data),
            "response.output_text.delta" => Self::OutputTextDelta(data),
            "response.output_text.done" => Self::OutputTextDone(data),
            "response.output_text.annotation.added" => Self::OutputTextAnnotationAdded(data),
            "response.function_call_arguments.delta" => Self::FunctionCallArgumentsDelta(data),
            "response.function_call_arguments.done" => Self::FunctionCallArgumentsDone(data),
            "response.refusal.delta" => Self::RefusalDelta(data),
            "response.refusal.done" => Self::RefusalDone(data),
            // OpenResponses uses `response.reasoning.*`; OpenAI's schema also
            // publishes `response.reasoning_text.*` for the same stream shape.
            "response.reasoning.delta" | "response.reasoning_text.delta" => Self::ReasoningDelta(data),
            "response.reasoning.done" | "response.reasoning_text.done" => Self::ReasoningDone(data),
            "response.reasoning_summary_text.delta" => Self::ReasoningSummaryTextDelta(data),
            "response.reasoning_summary_text.done" => Self::ReasoningSummaryTextDone(data),
            "response.reasoning_summary_part.added" => Self::ReasoningSummaryPartAdded(data),
            "response.reasoning_summary_part.done" => Self::ReasoningSummaryPartDone(data),
            "error" => Self::Error(data),
            other => Self::Unknown {
                event_type: other.to_owned(),
                data,
            },
        }
    }

    /// Whether this event terminates the stream.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::ResponseCompleted(_) | Self::ResponseIncomplete(_) | Self::ResponseFailed(_) | Self::Error(_)
        )
    }

    /// Return the event type string.
    pub fn event_type(&self) -> &str {
        match self {
            Self::ResponseCreated(_) => "response.created",
            Self::ResponseQueued(_) => "response.queued",
            Self::ResponseInProgress(_) => "response.in_progress",
            Self::ResponseCompleted(_) => "response.completed",
            Self::ResponseIncomplete(_) => "response.incomplete",
            Self::ResponseFailed(_) => "response.failed",
            Self::OutputItemAdded(_) => "response.output_item.added",
            Self::OutputItemDone(_) => "response.output_item.done",
            Self::ContentPartAdded(_) => "response.content_part.added",
            Self::ContentPartDone(_) => "response.content_part.done",
            Self::OutputTextDelta(_) => "response.output_text.delta",
            Self::OutputTextDone(_) => "response.output_text.done",
            Self::OutputTextAnnotationAdded(_) => "response.output_text.annotation.added",
            Self::FunctionCallArgumentsDelta(_) => "response.function_call_arguments.delta",
            Self::FunctionCallArgumentsDone(_) => "response.function_call_arguments.done",
            Self::RefusalDelta(_) => "response.refusal.delta",
            Self::RefusalDone(_) => "response.refusal.done",
            Self::ReasoningDelta(_) => "response.reasoning.delta",
            Self::ReasoningDone(_) => "response.reasoning.done",
            Self::ReasoningSummaryTextDelta(_) => "response.reasoning_summary_text.delta",
            Self::ReasoningSummaryTextDone(_) => "response.reasoning_summary_text.done",
            Self::ReasoningSummaryPartAdded(_) => "response.reasoning_summary_part.added",
            Self::ReasoningSummaryPartDone(_) => "response.reasoning_summary_part.done",
            Self::Error(_) => "error",
            Self::Unknown { event_type, .. } => event_type,
        }
    }
}

/// Return the canonical event type for equivalent provider aliases.
fn canonical_event_type(event_type: &str) -> &str {
    match event_type {
        "response.reasoning_text.delta" => "response.reasoning.delta",
        "response.reasoning_text.done" => "response.reasoning.done",
        other => other,
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn frame(event_type: Option<&str>, data: &[u8]) -> SseFrame {
        SseFrame {
            event_type: event_type.map(ToOwned::to_owned),
            data: data.to_vec(),
        }
    }

    fn typed_data(event_type: &str, mut data: Value) -> Vec<u8> {
        if let Value::Object(obj) = &mut data {
            obj.insert("type".to_owned(), Value::String(event_type.to_owned()));
        }
        serde_json::to_vec(&data).unwrap()
    }

    fn typed_frame(event_type: &str, data: Value) -> SseFrame {
        let data = typed_data(event_type, data);
        frame(Some(event_type), &data)
    }

    #[test]
    fn response_created() {
        let f = typed_frame("response.created", json!({"id": "resp_1"}));
        let event = ResponsesEvent::from_frame(&f).unwrap();
        assert!(
            matches!(event, ResponsesEvent::ResponseCreated(_)),
            "response.created should parse"
        );
    }

    #[test]
    fn response_queued() {
        let f = typed_frame("response.queued", json!({"id": "resp_1"}));
        let event = ResponsesEvent::from_frame(&f).unwrap();
        assert!(
            matches!(event, ResponsesEvent::ResponseQueued(_)),
            "response.queued should parse"
        );
    }

    #[test]
    fn response_completed_is_terminal() {
        let f = typed_frame("response.completed", json!({"id": "resp_1"}));
        let event = ResponsesEvent::from_frame(&f).unwrap();
        assert!(event.is_terminal(), "response.completed should be terminal");
    }

    #[test]
    fn response_failed_is_terminal() {
        let f = typed_frame("response.failed", json!({"error": {}}));
        let event = ResponsesEvent::from_frame(&f).unwrap();
        assert!(event.is_terminal(), "response.failed should be terminal");
    }

    #[test]
    fn response_incomplete_is_terminal() {
        let f = typed_frame("response.incomplete", json!({"id": "resp_1"}));
        let event = ResponsesEvent::from_frame(&f).unwrap();
        assert!(event.is_terminal(), "response.incomplete should be terminal");
    }

    #[test]
    fn output_text_delta() {
        let f = typed_frame("response.output_text.delta", json!({"delta": "hello"}));
        let event = ResponsesEvent::from_frame(&f).unwrap();
        assert!(
            matches!(event, ResponsesEvent::OutputTextDelta(_)),
            "response.output_text.delta should parse"
        );
    }

    #[test]
    fn function_call_arguments_delta() {
        let f = typed_frame("response.function_call_arguments.delta", json!({"delta": "{\"city\":"}));
        let event = ResponsesEvent::from_frame(&f).unwrap();
        assert!(
            matches!(event, ResponsesEvent::FunctionCallArgumentsDelta(_)),
            "response.function_call_arguments.delta should parse"
        );
    }

    #[test]
    fn function_call_arguments_done() {
        let f = typed_frame("response.function_call_arguments.done", json!({"arguments": "{}"}));
        let event = ResponsesEvent::from_frame(&f).unwrap();
        assert!(
            matches!(event, ResponsesEvent::FunctionCallArgumentsDone(_)),
            "response.function_call_arguments.done should parse"
        );
    }

    #[test]
    fn reasoning_delta() {
        let f = typed_frame("response.reasoning.delta", json!({"delta": "step"}));
        let event = ResponsesEvent::from_frame(&f).unwrap();
        assert!(
            matches!(event, ResponsesEvent::ReasoningDelta(_)),
            "response.reasoning.delta should parse"
        );
    }

    #[test]
    fn reasoning_done() {
        let f = typed_frame("response.reasoning.done", json!({"text": "done"}));
        let event = ResponsesEvent::from_frame(&f).unwrap();
        assert!(
            matches!(event, ResponsesEvent::ReasoningDone(_)),
            "response.reasoning.done should parse"
        );
    }

    #[test]
    fn reasoning_text_compatibility() {
        let f = typed_frame("response.reasoning_text.delta", json!({"delta": "step"}));
        let event = ResponsesEvent::from_frame(&f).unwrap();
        assert!(
            matches!(event, ResponsesEvent::ReasoningDelta(_)),
            "response.reasoning_text.delta should parse for OpenAI compatibility"
        );
    }

    #[test]
    fn unknown_event_type_yields_unknown() {
        let f = typed_frame("response.some_future_event", json!({"foo": "bar"}));
        let event = ResponsesEvent::from_frame(&f).unwrap();
        assert!(
            matches!(event, ResponsesEvent::Unknown { .. }),
            "future matching event type should remain Unknown"
        );
    }

    #[test]
    fn malformed_json_yields_error() {
        let f = frame(Some("response.created"), b"not json {{{");
        let result = ResponsesEvent::from_frame(&f);
        assert!(
            matches!(result, Err(SseParseError::MalformedJson { .. })),
            "invalid JSON should return MalformedJson"
        );
    }

    #[test]
    fn missing_sse_event_type_uses_payload_type() {
        let data = typed_data("response.created", json!({"id": "resp_1"}));
        let f = frame(None, &data);
        let event = ResponsesEvent::from_frame(&f).unwrap();
        assert!(
            matches!(event, ResponsesEvent::ResponseCreated(_)),
            "missing SSE event type should parse from payload type"
        );
    }

    #[test]
    fn missing_payload_event_type_errors_even_with_sse_event_type() {
        let data = serde_json::to_vec(&json!({"id": "resp_1"})).unwrap();
        let f = frame(Some("response.created"), &data);
        let result = ResponsesEvent::from_frame(&f);
        assert!(
            matches!(result, Err(SseParseError::MissingEventType { field: "data.type", .. })),
            "missing payload type should fail instead of trusting SSE event type"
        );
    }

    #[test]
    fn done_sentinel_is_malformed_json() {
        let f = frame(None, b"[DONE]");
        let result = ResponsesEvent::from_frame(&f);
        assert!(
            matches!(result, Err(SseParseError::MalformedJson { .. })),
            "[DONE] is not a Responses JSON event"
        );
    }

    #[test]
    fn missing_both_event_types_errors() {
        let data = serde_json::to_vec(&json!({"id": "resp_1"})).unwrap();
        let f = frame(None, &data);
        let result = ResponsesEvent::from_frame(&f);
        assert!(
            matches!(result, Err(SseParseError::MissingEventType { .. })),
            "missing payload and SSE event types should error"
        );
    }

    #[test]
    fn mismatched_event_type_errors() {
        let data = typed_data("response.output_text.delta", json!({"delta": "hello"}));
        let f = frame(Some("response.completed"), &data);
        let result = ResponsesEvent::from_frame(&f);
        assert!(
            matches!(result, Err(SseParseError::EventTypeMismatch { .. })),
            "mismatched SSE and JSON event types should error"
        );
    }

    #[test]
    fn reasoning_alias_mismatch_parses() {
        let data = typed_data("response.reasoning_text.delta", json!({"delta": "step"}));
        let f = frame(Some("response.reasoning.delta"), &data);
        let event = ResponsesEvent::from_frame(&f).unwrap();
        assert!(
            matches!(event, ResponsesEvent::ReasoningDelta(_)),
            "equivalent reasoning event aliases should parse"
        );
    }

    #[test]
    fn error_event() {
        let f = typed_frame("error", json!({"message": "bad"}));
        let event = ResponsesEvent::from_frame(&f).unwrap();
        assert!(matches!(event, ResponsesEvent::Error(_)), "error event should parse");
    }

    #[test]
    fn error_event_is_terminal() {
        let f = typed_frame("error", json!({"message": "bad"}));
        let event = ResponsesEvent::from_frame(&f).unwrap();
        assert!(event.is_terminal(), "error event should be terminal");
    }

    #[test]
    fn all_lifecycle_events_parse() {
        for event_type in [
            "response.created",
            "response.queued",
            "response.in_progress",
            "response.completed",
            "response.incomplete",
            "response.failed",
        ] {
            let f = typed_frame(event_type, json!({"id": "resp_1"}));
            let event = ResponsesEvent::from_frame(&f).unwrap();
            assert!(
                !matches!(event, ResponsesEvent::Unknown { .. }),
                "{event_type} should not be Unknown"
            );
        }
    }

    #[test]
    fn all_content_events_parse() {
        for event_type in [
            "response.output_item.added",
            "response.output_item.done",
            "response.content_part.added",
            "response.content_part.done",
            "response.output_text.delta",
            "response.output_text.done",
            "response.output_text.annotation.added",
            "response.function_call_arguments.delta",
            "response.function_call_arguments.done",
            "response.refusal.delta",
            "response.refusal.done",
            "response.reasoning.delta",
            "response.reasoning.done",
            "response.reasoning_summary_text.delta",
            "response.reasoning_summary_text.done",
            "response.reasoning_summary_part.added",
            "response.reasoning_summary_part.done",
        ] {
            let f = typed_frame(event_type, json!({}));
            let event = ResponsesEvent::from_frame(&f).unwrap();
            assert!(
                !matches!(event, ResponsesEvent::Unknown { .. }),
                "{event_type} should not be Unknown"
            );
        }
    }

    #[test]
    fn non_terminal_events_are_not_terminal() {
        for event_type in [
            "response.created",
            "response.queued",
            "response.in_progress",
            "response.output_text.delta",
        ] {
            let f = typed_frame(event_type, json!({}));
            let event = ResponsesEvent::from_frame(&f).unwrap();
            assert!(!event.is_terminal(), "{event_type} should not be terminal");
        }
    }
}
