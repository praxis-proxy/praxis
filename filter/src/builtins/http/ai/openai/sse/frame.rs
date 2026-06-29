// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Byte-level SSE frame reassembly.

use std::{fmt, time::Duration};

/// A completed SSE frame: one event boundary's worth of data.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SseFrame {
    /// Value from the `event:` field, if present.
    pub event_type: Option<String>,
    /// Joined `data:` field values, separated by `\n`.
    pub data: Vec<u8>,
}

/// Incremental SSE frame parser.
///
/// Buffers partial lines across chunk boundaries and yields
/// complete [`SseFrame`] values on each blank-line event boundary.
pub(crate) struct SseFrameParser {
    /// Accumulates the current line being parsed.
    line_buf: Vec<u8>,
    /// The `event:` value for the current frame, if any.
    event_type: Option<String>,
    /// Joined `data:` field values for the current frame.
    data_buf: Vec<u8>,
    /// Whether at least one `data:` field has been seen.
    has_data: bool,
    /// Whether the previous chunk ended with a bare `\r`.
    prev_cr: bool,
    /// Current total buffered bytes retained across chunks.
    scratch_bytes: usize,
    /// Maximum allowed buffered bytes.
    max_buffer_bytes: usize,
}

impl SseFrameParser {
    /// Create a new parser with the given buffer byte limit.
    pub fn new(max_buffer_bytes: usize) -> Self {
        Self {
            line_buf: Vec::new(),
            event_type: None,
            data_buf: Vec::new(),
            has_data: false,
            prev_cr: false,
            scratch_bytes: 0,
            max_buffer_bytes,
        }
    }

    /// Feed a chunk of bytes, returning any complete SSE frames.
    pub fn parse_chunk(&mut self, chunk: &[u8]) -> Result<Vec<SseFrame>, SseParseError> {
        self.parse_chunk_inner(chunk, None)
    }

    /// Feed a chunk and stop before emitting more frames than the event budget allows.
    pub fn parse_chunk_with_event_limit(
        &mut self,
        chunk: &[u8],
        current_events: usize,
        max_events: usize,
    ) -> Result<Vec<SseFrame>, SseParseError> {
        self.parse_chunk_inner(chunk, Some((current_events, max_events)))
    }

    /// Feed a chunk with optional event-budget enforcement.
    #[expect(clippy::too_many_lines, reason = "linear byte-processing loop")]
    fn parse_chunk_inner(
        &mut self,
        chunk: &[u8],
        event_limit: Option<(usize, usize)>,
    ) -> Result<Vec<SseFrame>, SseParseError> {
        if chunk.is_empty() {
            self.scratch_bytes = self.buffered_bytes();
            return Ok(Vec::new());
        }

        let mut frames = Vec::new();
        let mut i = 0;

        if self.prev_cr && chunk.first() == Some(&b'\n') {
            i = 1;
        }
        self.prev_cr = false;

        while let Some(&b) = chunk.get(i) {
            if b == b'\n' || b == b'\r' {
                if self.line_buf.is_empty() && self.has_data {
                    Self::check_event_limit(event_limit, frames.len())?;
                }
                if let Some(frame) = self.process_line() {
                    frames.push(frame);
                }
                self.line_buf.clear();
                self.scratch_bytes = self.buffered_bytes();

                if b == b'\r' {
                    if let Some(&next) = chunk.get(i + 1) {
                        if next == b'\n' {
                            i += 1;
                        }
                    } else {
                        self.prev_cr = true;
                    }
                }
            } else {
                self.line_buf.push(b);
                self.scratch_bytes = self.scratch_bytes.saturating_add(1);
            }

            self.check_buffer_limit()?;

            i += 1;
        }

        self.scratch_bytes = self.buffered_bytes();
        Ok(frames)
    }

    /// Return the number of bytes currently retained by the parser.
    fn buffered_bytes(&self) -> usize {
        self.line_buf
            .len()
            .saturating_add(self.data_buf.len())
            .saturating_add(self.event_type.as_ref().map_or(0, String::len))
    }

    /// Check whether the current retained byte count exceeds the buffer limit.
    fn check_buffer_limit(&self) -> Result<(), SseParseError> {
        if self.scratch_bytes > self.max_buffer_bytes {
            return Err(SseParseError::BufferOverflow {
                buffered_bytes: self.scratch_bytes,
                limit: self.max_buffer_bytes,
            });
        }

        Ok(())
    }

    /// Check whether another completed frame would exceed the event budget.
    fn check_event_limit(event_limit: Option<(usize, usize)>, parsed_in_chunk: usize) -> Result<(), SseParseError> {
        let Some((current_events, max_events)) = event_limit else {
            return Ok(());
        };

        let count = current_events.saturating_add(parsed_in_chunk).saturating_add(1);
        if count > max_events {
            return Err(SseParseError::EventLimitExceeded {
                count,
                limit: max_events,
            });
        }

        Ok(())
    }

    /// Process a completed line, emitting a frame on blank lines.
    #[expect(clippy::indexing_slicing, reason = "colon_pos from position() guarantees bounds")]
    #[expect(clippy::too_many_lines, reason = "linear SSE field processing")]
    fn process_line(&mut self) -> Option<SseFrame> {
        if self.line_buf.is_empty() {
            let frame = self.has_data.then(|| SseFrame {
                event_type: self.event_type.take(),
                data: self.data_buf.clone(),
            });

            if self.has_data {
                self.data_buf.clear();
                self.has_data = false;
            }
            self.event_type = None;
            return frame;
        }

        if self.line_buf.first() == Some(&b':') {
            return None;
        }

        let colon_pos = self.line_buf.iter().position(|&b| b == b':')?;

        let field = &self.line_buf[..colon_pos];
        let value_start = if self.line_buf.get(colon_pos + 1) == Some(&b' ') {
            colon_pos + 2
        } else {
            colon_pos + 1
        };
        let value = self.line_buf.get(value_start..).unwrap_or_default();

        if field == b"data" {
            if self.has_data {
                self.data_buf.push(b'\n');
            }
            self.has_data = true;
            self.data_buf.extend_from_slice(value);
        } else if field == b"event" {
            self.event_type = Some(String::from_utf8_lossy(value).into_owned());
        }

        None
    }
}

/// Errors from SSE parsing, shared across frame and event layers.
#[derive(Debug)]
pub(crate) enum SseParseError {
    /// Buffered bytes exceeded the configured limit.
    BufferOverflow {
        /// The number of bytes currently buffered.
        buffered_bytes: usize,
        /// The maximum allowed buffered bytes.
        limit: usize,
    },

    /// A `data:` payload was not valid JSON.
    MalformedJson {
        /// The SSE event type that had invalid JSON.
        event_type: String,
        /// The JSON parsing error description.
        err: String,
    },

    /// A required event type field was missing or not a string.
    MissingEventType {
        /// Missing field name.
        field: &'static str,
        /// Event type observed in the other event location.
        event_type: String,
    },

    /// The SSE `event:` field did not match the JSON payload `type`.
    EventTypeMismatch {
        /// Event type from the SSE `event:` field.
        sse_event_type: String,
        /// Event type from the JSON payload `type` field.
        data_event_type: String,
    },

    /// The number of parsed events exceeded the configured limit.
    EventLimitExceeded {
        /// The actual event count.
        count: usize,
        /// The maximum allowed events.
        limit: usize,
    },

    /// The stream exceeded the configured timeout.
    Timeout {
        /// The elapsed time since stream start.
        elapsed: Duration,
        /// The maximum allowed time.
        limit: Duration,
    },

    /// Stream ended without a terminal event.
    MissingTerminalEvent,

    /// A non-error event arrived after stream termination.
    EventAfterTerminal {
        /// Event type observed after termination.
        event_type: String,
    },
}

impl fmt::Display for SseParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferOverflow { buffered_bytes, limit } => write!(
                f,
                "SSE buffer overflow: {buffered_bytes} bytes exceeds {limit} byte limit"
            ),
            Self::MalformedJson { event_type, err } => {
                write!(f, "malformed JSON in SSE event '{event_type}': {err}")
            },
            Self::MissingEventType { field, event_type } => {
                write!(f, "missing string SSE event type field '{field}' near '{event_type}'")
            },
            Self::EventTypeMismatch {
                sse_event_type,
                data_event_type,
            } => write!(
                f,
                "SSE event type '{sse_event_type}' does not match JSON payload type '{data_event_type}'"
            ),
            Self::EventLimitExceeded { count, limit } => {
                write!(f, "SSE event limit exceeded: {count} events exceeds {limit} limit")
            },
            Self::Timeout { elapsed, limit } => {
                write!(f, "SSE stream timeout: {elapsed:?} exceeds {limit:?} limit")
            },
            Self::MissingTerminalEvent => write!(f, "SSE stream ended without terminal event"),
            Self::EventAfterTerminal { event_type } => {
                write!(f, "SSE event '{event_type}' arrived after terminal event")
            },
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    const MAX_BUF: usize = 65_536;

    #[test]
    fn single_frame_yields_one_result() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let chunk = b"data: hello\n\n";
        let frames = parser.parse_chunk(chunk).unwrap();
        assert_eq!(frames.len(), 1, "single complete frame should dispatch");
        assert_eq!(frames[0].data, b"hello", "frame data should match");
        assert_eq!(frames[0].event_type, None, "frame should not have event type");
    }

    #[test]
    fn event_type_captured() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let chunk = b"event: response.created\ndata: {\"id\":\"r1\"}\n\n";
        let frames = parser.parse_chunk(chunk).unwrap();
        assert_eq!(frames.len(), 1, "single event frame should dispatch");
        assert_eq!(
            frames[0].event_type.as_deref(),
            Some("response.created"),
            "event type should be captured"
        );
        assert_eq!(frames[0].data, b"{\"id\":\"r1\"}", "event data should match");
    }

    #[test]
    fn event_type_resets_between_frames() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let chunk = b"event: first\ndata: a\n\ndata: b\n\n";
        let frames = parser.parse_chunk(chunk).unwrap();
        assert_eq!(frames.len(), 2, "two frames should dispatch");
        assert_eq!(
            frames[0].event_type.as_deref(),
            Some("first"),
            "first event type should be captured"
        );
        assert_eq!(frames[1].event_type, None, "event type should reset between frames");
    }

    #[test]
    fn multiple_frames_in_one_chunk() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let chunk = b"data: first\n\ndata: second\n\n";
        let frames = parser.parse_chunk(chunk).unwrap();
        assert_eq!(frames.len(), 2, "two frames should dispatch from one chunk");
        assert_eq!(frames[0].data, b"first", "first frame data should match");
        assert_eq!(frames[1].data, b"second", "second frame data should match");
    }

    #[test]
    fn frame_split_across_chunks() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let frames1 = parser.parse_chunk(b"data: hel").unwrap();
        assert!(frames1.is_empty(), "partial frame should not dispatch");
        let frames2 = parser.parse_chunk(b"lo\n\n").unwrap();
        assert_eq!(frames2.len(), 1, "completed split frame should dispatch");
        assert_eq!(frames2[0].data, b"hello", "joined frame data should match");
    }

    #[test]
    fn blank_line_split_across_chunks() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let frames1 = parser.parse_chunk(b"data: hello\n").unwrap();
        assert!(frames1.is_empty(), "line ending alone should not dispatch");
        let frames2 = parser.parse_chunk(b"\n").unwrap();
        assert_eq!(frames2.len(), 1, "blank line should dispatch frame");
        assert_eq!(frames2[0].data, b"hello", "frame data should match");
    }

    #[test]
    fn multiline_data_joined_with_newline() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let chunk = b"data: line1\ndata: line2\ndata: line3\n\n";
        let frames = parser.parse_chunk(chunk).unwrap();
        assert_eq!(frames.len(), 1, "multiline data should dispatch one frame");
        assert_eq!(
            frames[0].data, b"line1\nline2\nline3",
            "data lines should be joined with newlines"
        );
    }

    #[test]
    fn crlf_line_endings() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let chunk = b"data: hello\r\n\r\n";
        let frames = parser.parse_chunk(chunk).unwrap();
        assert_eq!(frames.len(), 1, "CRLF frame should dispatch");
        assert_eq!(frames[0].data, b"hello", "frame data should match");
    }

    #[test]
    fn crlf_split_across_chunks() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let frames1 = parser.parse_chunk(b"data: hello\r").unwrap();
        assert!(frames1.is_empty(), "CR at chunk boundary should wait for LF");
        let frames2 = parser.parse_chunk(b"\n\r\n").unwrap();
        assert_eq!(frames2.len(), 1, "CRLF split across chunks should dispatch");
        assert_eq!(frames2[0].data, b"hello", "frame data should match");
    }

    #[test]
    fn crlf_split_by_empty_chunk_preserves_event_type() {
        let mut parser = SseFrameParser::new(MAX_BUF);

        let frames1 = parser.parse_chunk(b"event: response.completed\r").unwrap();
        assert!(frames1.is_empty(), "event line alone should not dispatch");

        let frames2 = parser.parse_chunk(b"").unwrap();
        assert!(frames2.is_empty(), "empty chunk should not dispatch");

        let frames3 = parser.parse_chunk(b"\ndata: {}\r\n\r\n").unwrap();
        assert_eq!(frames3.len(), 1, "data frame should dispatch after split CRLF");
        assert_eq!(
            frames3[0].event_type.as_deref(),
            Some("response.completed"),
            "empty chunk should preserve pending CRLF state"
        );
    }

    #[test]
    fn bare_cr_line_ending() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let chunk = b"data: hello\r\r";
        let frames = parser.parse_chunk(chunk).unwrap();
        assert_eq!(frames.len(), 1, "bare CR frame should dispatch");
        assert_eq!(frames[0].data, b"hello", "frame data should match");
    }

    #[test]
    fn comments_ignored() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let chunk = b": this is a comment\ndata: hello\n\n";
        let frames = parser.parse_chunk(chunk).unwrap();
        assert_eq!(frames.len(), 1, "comment should be ignored");
        assert_eq!(frames[0].data, b"hello", "frame data should match");
    }

    #[test]
    fn unknown_fields_ignored() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let chunk = b"id: 42\nretry: 1000\ndata: hello\n\n";
        let frames = parser.parse_chunk(chunk).unwrap();
        assert_eq!(frames.len(), 1, "unknown fields should be ignored");
        assert_eq!(frames[0].data, b"hello", "frame data should match");
    }

    #[test]
    fn empty_frames_ignored() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let chunk = b"\n\ndata: hello\n\n";
        let frames = parser.parse_chunk(chunk).unwrap();
        assert_eq!(frames.len(), 1, "empty frames should be ignored");
        assert_eq!(frames[0].data, b"hello", "non-empty frame data should match");
    }

    #[test]
    fn data_without_space_after_colon() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let chunk = b"data:nospace\n\n";
        let frames = parser.parse_chunk(chunk).unwrap();
        assert_eq!(frames.len(), 1, "data without optional space should dispatch");
        assert_eq!(frames[0].data, b"nospace", "frame data should match");
    }

    #[test]
    fn data_with_empty_value() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let chunk = b"data:\n\n";
        let frames = parser.parse_chunk(chunk).unwrap();
        assert_eq!(frames.len(), 1, "empty data value should dispatch");
        assert!(frames[0].data.is_empty(), "empty data value should remain empty");
    }

    #[test]
    fn line_without_colon_ignored() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let chunk = b"justtext\ndata: hello\n\n";
        let frames = parser.parse_chunk(chunk).unwrap();
        assert_eq!(frames.len(), 1, "line without colon should be ignored");
        assert_eq!(frames[0].data, b"hello", "frame data should match");
    }

    #[test]
    fn buffer_overflow_returns_error() {
        let mut parser = SseFrameParser::new(10);
        let result = parser.parse_chunk(b"data: this line is way too long for the limit\n\n");
        assert!(result.is_err(), "oversized line should return an error");
    }

    #[test]
    fn overflow_after_completed_frame() {
        let mut parser = SseFrameParser::new(15);
        let chunk = b"data: ok\n\ndata: this-is-way-too-long\n\n";
        let result = parser.parse_chunk(chunk);
        assert!(
            result.is_err(),
            "overflow after a completed frame should return an error"
        );
    }

    #[test]
    fn event_type_counts_toward_buffer_limit() {
        let mut parser = SseFrameParser::new(20);
        let result = parser.parse_chunk(b"event: 1234567890123\ndata: 12345678\n\n");
        assert!(
            matches!(result, Err(SseParseError::BufferOverflow { .. })),
            "retained event type bytes should count toward the buffer limit"
        );
    }

    #[test]
    fn lossy_event_type_expansion_counts_after_line_processing() {
        let mut parser = SseFrameParser::new(11);
        let result = parser.parse_chunk(b"event: \xFF\xFF\xFF\xFF\n");
        assert!(
            matches!(
                result,
                Err(SseParseError::BufferOverflow {
                    buffered_bytes: 12,
                    limit: 11
                })
            ),
            "lossy UTF-8 expansion in event type should be checked after line processing"
        );
    }

    #[test]
    fn event_limit_returns_error_before_extra_frame() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let chunk = b"data: one\n\ndata: two\n\n";
        let result = parser.parse_chunk_with_event_limit(chunk, 1, 1);
        assert!(
            matches!(result, Err(SseParseError::EventLimitExceeded { count: 2, limit: 1 })),
            "event limit should stop before emitting another frame"
        );
    }

    #[test]
    fn event_type_with_space_after_colon() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let chunk = b"event: response.completed\ndata: {}\n\n";
        let frames = parser.parse_chunk(chunk).unwrap();
        assert_eq!(
            frames[0].event_type.as_deref(),
            Some("response.completed"),
            "event type with space should be captured"
        );
    }

    #[test]
    fn event_type_without_space_after_colon() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let chunk = b"event:response.completed\ndata: {}\n\n";
        let frames = parser.parse_chunk(chunk).unwrap();
        assert_eq!(
            frames[0].event_type.as_deref(),
            Some("response.completed"),
            "event type without space should be captured"
        );
    }

    #[test]
    fn multiline_data_split_across_chunks() {
        let mut parser = SseFrameParser::new(MAX_BUF);
        let frames1 = parser.parse_chunk(b"data: line1\n").unwrap();
        assert!(frames1.is_empty(), "first data line should not dispatch");
        let frames2 = parser.parse_chunk(b"data: line2\n\n").unwrap();
        assert_eq!(frames2.len(), 1, "second data line with blank line should dispatch");
        assert_eq!(frames2[0].data, b"line1\nline2", "split multiline data should match");
    }
}
