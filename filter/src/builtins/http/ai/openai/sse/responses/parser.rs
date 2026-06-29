// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Orchestrated Responses SSE parser with limit enforcement.

use std::time::{Duration, Instant};

use super::{
    super::{SseFrameParser, SseParseError, SseParserConfig},
    event::ResponsesEvent,
};

/// Wraps [`SseFrameParser`] to yield typed [`ResponsesEvent`] values
/// with event count, timeout, and fail-closed enforcement.
pub(crate) struct ResponsesSseParser {
    /// Current stream completion state.
    completion_state: CompletionState,
    /// Byte-level frame parser.
    frame_parser: SseFrameParser,
    /// Number of events parsed so far.
    event_count: usize,
    /// Maximum allowed event count.
    max_events: usize,
    /// Maximum allowed wall-clock time.
    timeout: Duration,
    /// Timestamp of first chunk.
    started_at: Option<Instant>,
    /// Timestamp when a terminal state was first observed.
    completed_at: Option<Instant>,
}

/// Completion state observed while parsing a Responses SSE stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletionState {
    /// No completion signal has been observed.
    Open,
    /// A terminal lifecycle event was observed.
    TerminalLifecycle,
    /// A stream-level error event was observed.
    Error,
}

impl ResponsesSseParser {
    /// Create a parser from config.
    pub fn new(config: &SseParserConfig) -> Self {
        Self {
            completion_state: CompletionState::Open,
            frame_parser: SseFrameParser::new(config.max_buffer_bytes),
            event_count: 0,
            max_events: config.max_events,
            timeout: config.timeout,
            started_at: None,
            completed_at: None,
        }
    }

    /// Feed a raw chunk, returning typed events.
    pub fn parse_chunk(&mut self, chunk: &[u8]) -> Result<Vec<ResponsesEvent>, SseParseError> {
        let now = Instant::now();
        self.started_at.get_or_insert(now);
        self.check_timeout(now)?;

        let frames = self
            .frame_parser
            .parse_chunk_with_event_limit(chunk, self.event_count, self.max_events)?;
        let mut events = Vec::with_capacity(frames.len());

        for frame in &frames {
            self.event_count += 1;

            let event = ResponsesEvent::from_frame(frame)?;
            self.record_completion(&event, now)?;
            events.push(event);
        }

        Ok(events)
    }

    /// Verify the stream ended with a terminal lifecycle event or stream-level error.
    pub fn validate_complete(&self) -> Result<(), SseParseError> {
        let checked_at = self.completed_at.unwrap_or_else(Instant::now);
        self.check_timeout(checked_at)?;

        match self.completion_state {
            CompletionState::Error | CompletionState::TerminalLifecycle => Ok(()),
            CompletionState::Open => Err(SseParseError::MissingTerminalEvent),
        }
    }

    /// Check whether the stream has exceeded its wall-clock timeout.
    fn check_timeout(&self, now: Instant) -> Result<(), SseParseError> {
        let Some(started_at) = self.started_at else {
            return Ok(());
        };

        let elapsed = now.duration_since(started_at);
        if elapsed > self.timeout {
            return Err(SseParseError::Timeout {
                elapsed,
                limit: self.timeout,
            });
        }

        Ok(())
    }

    /// Record whether an event signals stream completion.
    fn record_completion(&mut self, event: &ResponsesEvent, now: Instant) -> Result<(), SseParseError> {
        if matches!(event, ResponsesEvent::Error(_)) {
            if self.completion_state == CompletionState::Error {
                return Err(SseParseError::EventAfterTerminal {
                    event_type: event.event_type().to_owned(),
                });
            }
            self.mark_complete(CompletionState::Error, now);
            return Ok(());
        }

        if self.completion_state != CompletionState::Open {
            return Err(SseParseError::EventAfterTerminal {
                event_type: event.event_type().to_owned(),
            });
        }

        if event.is_terminal() {
            self.mark_complete(CompletionState::TerminalLifecycle, now);
        }

        Ok(())
    }

    /// Record the first terminal-state timestamp while allowing stronger states to replace weaker ones.
    fn mark_complete(&mut self, state: CompletionState, now: Instant) {
        self.completion_state = state;
        if self.completed_at.is_none() {
            self.completed_at = Some(now);
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::indexing_slicing, reason = "tests")]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn config() -> SseParserConfig {
        SseParserConfig {
            max_buffer_bytes: 65_536,
            max_events: 100,
            timeout: Duration::from_secs(60),
        }
    }

    fn sse_bytes(event_type: &str, data: &Value) -> Vec<u8> {
        let mut data = data.clone();
        if let Value::Object(obj) = &mut data {
            obj.insert("type".to_owned(), Value::String(event_type.to_owned()));
        }
        format!("event: {event_type}\ndata: {data}\n\n").into_bytes()
    }

    fn full_lifecycle_chunks() -> Vec<Vec<u8>> {
        vec![
            sse_bytes("response.created", &json!({"id": "resp_1"})),
            sse_bytes("response.in_progress", &json!({"id": "resp_1"})),
            sse_bytes("response.output_item.added", &json!({"index": 0})),
            sse_bytes("response.content_part.added", &json!({"index": 0})),
            sse_bytes("response.output_text.delta", &json!({"delta": "Hello"})),
            sse_bytes("response.output_text.delta", &json!({"delta": " world"})),
            sse_bytes("response.output_text.done", &json!({"text": "Hello world"})),
            sse_bytes("response.content_part.done", &json!({"index": 0})),
            sse_bytes("response.output_item.done", &json!({"index": 0})),
            sse_bytes("response.completed", &json!({"id": "resp_1"})),
        ]
    }

    #[test]
    fn end_to_end_single_event() {
        let mut parser = ResponsesSseParser::new(&config());
        let chunk = sse_bytes("response.created", &json!({"id": "resp_1"}));
        let events = parser.parse_chunk(&chunk).unwrap();
        assert_eq!(events.len(), 1, "single event should parse");
        assert!(
            matches!(events[0], ResponsesEvent::ResponseCreated(_)),
            "response.created should parse"
        );
    }

    #[test]
    fn end_to_end_multiple_chunks() {
        let mut parser = ResponsesSseParser::new(&config());

        let chunk1 = sse_bytes("response.created", &json!({"id": "resp_1"}));
        let events1 = parser.parse_chunk(&chunk1).unwrap();
        assert_eq!(events1.len(), 1, "first chunk should yield one event");

        let chunk2 = sse_bytes("response.output_text.delta", &json!({"delta": "hi"}));
        let events2 = parser.parse_chunk(&chunk2).unwrap();
        assert_eq!(events2.len(), 1, "second chunk should yield one event");
        assert!(
            matches!(events2[0], ResponsesEvent::OutputTextDelta(_)),
            "response.output_text.delta should parse"
        );
    }

    #[test]
    fn event_limit_enforced() {
        let cfg = SseParserConfig {
            max_events: 2,
            ..config()
        };
        let mut parser = ResponsesSseParser::new(&cfg);

        let chunk1 = sse_bytes("response.created", &json!({}));
        parser.parse_chunk(&chunk1).unwrap();

        let chunk2 = sse_bytes("response.in_progress", &json!({}));
        parser.parse_chunk(&chunk2).unwrap();

        let chunk3 = sse_bytes("response.output_text.delta", &json!({}));
        let result = parser.parse_chunk(&chunk3);
        assert!(
            matches!(result, Err(SseParseError::EventLimitExceeded { .. })),
            "third event should exceed max_events=2"
        );
    }

    #[test]
    fn event_limit_enforced_with_multiple_events_in_one_chunk() {
        let cfg = SseParserConfig {
            max_events: 2,
            ..config()
        };
        let mut parser = ResponsesSseParser::new(&cfg);
        let chunk = [
            sse_bytes("response.created", &json!({})),
            sse_bytes("response.in_progress", &json!({})),
            sse_bytes("response.output_text.delta", &json!({})),
        ]
        .concat();

        let result = parser.parse_chunk(&chunk);
        assert!(
            matches!(result, Err(SseParseError::EventLimitExceeded { count: 3, limit: 2 })),
            "third same-chunk event should exceed max_events=2"
        );
    }

    #[test]
    fn validate_complete_passes_with_terminal() {
        let mut parser = ResponsesSseParser::new(&config());
        let chunk = sse_bytes("response.completed", &json!({"id": "resp_1"}));
        parser.parse_chunk(&chunk).unwrap();
        assert!(
            parser.validate_complete().is_ok(),
            "terminal lifecycle event should validate complete"
        );
    }

    #[test]
    fn done_sentinel_is_rejected() {
        let mut parser = ResponsesSseParser::new(&config());
        let result = parser.parse_chunk(b"data: [DONE]\n\n");
        assert!(
            matches!(result, Err(SseParseError::MalformedJson { .. })),
            "[DONE] is not a Responses JSON event"
        );
    }

    #[test]
    fn validate_complete_passes_with_error() {
        let mut parser = ResponsesSseParser::new(&config());
        let chunk = sse_bytes("error", &json!({"message": "upstream failed"}));
        parser.parse_chunk(&chunk).unwrap();
        assert!(
            parser.validate_complete().is_ok(),
            "stream-level error should validate complete"
        );
    }

    #[test]
    fn late_error_replaces_terminal_lifecycle() {
        let mut parser = ResponsesSseParser::new(&config());
        let completed = sse_bytes("response.completed", &json!({"id": "resp_1"}));
        let error = sse_bytes("error", &json!({"message": "late failure"}));

        parser.parse_chunk(&completed).unwrap();
        parser.parse_chunk(&error).unwrap();

        assert_eq!(
            parser.completion_state,
            CompletionState::Error,
            "stream-level error should replace prior lifecycle completion"
        );
    }

    #[test]
    fn second_error_after_stream_error_fails() {
        let mut parser = ResponsesSseParser::new(&config());
        let first_error = sse_bytes("error", &json!({"message": "first failure"}));
        let second_error = sse_bytes("error", &json!({"message": "second failure"}));

        parser.parse_chunk(&first_error).unwrap();
        let result = parser.parse_chunk(&second_error);

        assert!(
            matches!(
                result,
                Err(SseParseError::EventAfterTerminal {
                    event_type
                }) if event_type == "error"
            ),
            "second stream-level error after terminal error should fail"
        );
    }

    #[test]
    fn non_error_event_after_terminal_lifecycle_fails() {
        let mut parser = ResponsesSseParser::new(&config());
        let completed = sse_bytes("response.completed", &json!({"id": "resp_1"}));
        let delta = sse_bytes("response.output_text.delta", &json!({"delta": "late"}));

        parser.parse_chunk(&completed).unwrap();
        let result = parser.parse_chunk(&delta);

        assert!(
            matches!(
                result,
                Err(SseParseError::EventAfterTerminal {
                    event_type
                }) if event_type == "response.output_text.delta"
            ),
            "non-error events after terminal lifecycle should fail"
        );
    }

    #[test]
    fn malformed_terminal_event_does_not_validate_complete() {
        let mut parser = ResponsesSseParser::new(&config());
        let result = parser.parse_chunk(b"event: response.completed\ndata: {}\n\n");
        assert!(
            matches!(result, Err(SseParseError::MissingEventType { field: "data.type", .. })),
            "terminal-looking SSE event must still contain data.type"
        );
        assert!(
            matches!(parser.validate_complete(), Err(SseParseError::MissingTerminalEvent)),
            "malformed terminal-looking event should not mark the stream complete"
        );
    }

    #[test]
    fn validate_complete_fails_without_terminal() {
        let mut parser = ResponsesSseParser::new(&config());
        let chunk = sse_bytes("response.output_text.delta", &json!({"delta": "hi"}));
        parser.parse_chunk(&chunk).unwrap();
        let result = parser.validate_complete();
        assert!(
            matches!(result, Err(SseParseError::MissingTerminalEvent)),
            "stream without terminal event should fail validation"
        );
    }

    #[test]
    fn validate_complete_enforces_timeout_at_completion_time() {
        let cfg = SseParserConfig {
            timeout: Duration::from_secs(1),
            ..config()
        };
        let mut parser = ResponsesSseParser::new(&cfg);
        let started_at = Instant::now() - Duration::from_secs(3);
        parser.started_at = Some(started_at);
        parser.completed_at = Some(started_at + Duration::from_secs(2));
        parser.completion_state = CompletionState::TerminalLifecycle;

        let result = parser.validate_complete();
        assert!(
            matches!(result, Err(SseParseError::Timeout { .. })),
            "completion validation should enforce elapsed stream timeout"
        );
    }

    #[test]
    fn validate_complete_uses_terminal_timestamp() {
        let cfg = SseParserConfig {
            timeout: Duration::from_secs(1),
            ..config()
        };
        let mut parser = ResponsesSseParser::new(&cfg);
        let started_at = Instant::now() - Duration::from_secs(3);
        parser.started_at = Some(started_at);
        parser.completed_at = Some(started_at + Duration::from_millis(500));
        parser.completion_state = CompletionState::TerminalLifecycle;

        assert!(
            parser.validate_complete().is_ok(),
            "later validation should not timeout a stream that completed within the limit"
        );
    }

    #[test]
    fn validate_complete_enforces_timeout_without_terminal_event() {
        let cfg = SseParserConfig {
            timeout: Duration::from_secs(1),
            ..config()
        };
        let mut parser = ResponsesSseParser::new(&cfg);
        parser.started_at = Some(Instant::now() - Duration::from_secs(2));

        let result = parser.validate_complete();
        assert!(
            matches!(result, Err(SseParseError::Timeout { .. })),
            "completion validation should timeout an unfinished stream before reporting missing terminal"
        );
    }

    #[test]
    fn malformed_json_propagated() {
        let mut parser = ResponsesSseParser::new(&config());
        let chunk = b"event: response.created\ndata: not-json\n\n";
        let result = parser.parse_chunk(chunk);
        assert!(
            matches!(result, Err(SseParseError::MalformedJson { .. })),
            "malformed event data should propagate MalformedJson"
        );
    }

    #[test]
    fn split_chunk_assembles_correctly() {
        let mut parser = ResponsesSseParser::new(&config());
        let full = sse_bytes("response.created", &json!({"id": "resp_1"}));
        let (a, b) = full.split_at(full.len() / 2);

        let events1 = parser.parse_chunk(a).unwrap();
        assert!(events1.is_empty(), "partial event should not dispatch");

        let events2 = parser.parse_chunk(b).unwrap();
        assert_eq!(events2.len(), 1, "completed split event should dispatch");
        assert!(
            matches!(events2[0], ResponsesEvent::ResponseCreated(_)),
            "split response.created should parse"
        );
    }

    #[test]
    fn buffer_overflow_propagated() {
        let cfg = SseParserConfig {
            max_buffer_bytes: 10,
            ..config()
        };
        let mut parser = ResponsesSseParser::new(&cfg);
        let chunk = sse_bytes(
            "response.created",
            &json!({"a very long key": "a very long value that exceeds the buffer"}),
        );
        let result = parser.parse_chunk(&chunk);
        assert!(
            matches!(result, Err(SseParseError::BufferOverflow { .. })),
            "oversized buffered event should propagate BufferOverflow"
        );
    }

    #[test]
    fn full_stream_lifecycle() {
        let mut parser = ResponsesSseParser::new(&config());
        let mut all_events = Vec::new();

        for chunk in &full_lifecycle_chunks() {
            let events = parser.parse_chunk(chunk).unwrap();
            all_events.extend(events);
        }

        assert_eq!(all_events.len(), 10, "full lifecycle should emit all events");
        assert!(
            matches!(all_events[0], ResponsesEvent::ResponseCreated(_)),
            "first event should be response.created"
        );
        assert!(
            matches!(all_events[9], ResponsesEvent::ResponseCompleted(_)),
            "last event should be response.completed"
        );
        assert!(
            parser.validate_complete().is_ok(),
            "full stream should validate complete"
        );
    }
}
