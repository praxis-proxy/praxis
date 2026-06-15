// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Bounded incremental SSE scanner for A2A streaming task-route capture.
//!
//! Processes `text/event-stream` response body chunks, extracts completed
//! `data:` payloads from SSE frames, and returns them for task-route
//! extraction. Handles arbitrary chunk boundaries, multi-line `data:`
//! fields, CRLF/LF/CR line endings, and comment lines.
//!
//! The scanner never modifies response bytes. It inspects chunks and
//! yields completed payloads; the caller passes bytes through unchanged.

// -----------------------------------------------------------------------------
// SseScanState
// -----------------------------------------------------------------------------

/// Incremental SSE parser state carried across response body chunks.
///
/// Stored in `filter_metadata` via hex encoding between
/// [`on_response_body`] calls.
///
/// [`on_response_body`]: crate::filter::HttpFilter::on_response_body
#[derive(Default)]
pub(crate) struct SseScanState {
    /// Bytes of an incomplete line from the previous chunk.
    pub line_buf: Vec<u8>,

    /// Accumulated `data:` field values for the current SSE event,
    /// joined with `\n` per the SSE specification.
    pub data_buf: Vec<u8>,

    /// Whether any `data:` field has been seen for the current event.
    /// Distinguishes "no data lines" from "data lines with empty value".
    pub has_data: bool,

    /// Whether the previous chunk ended with CR, so a leading LF
    /// in the next chunk should be consumed as part of a CRLF pair.
    pub prev_cr: bool,

    /// Total scratch bytes consumed (`line_buf` + `data_buf`).
    pub scratch_bytes: usize,
}

// -----------------------------------------------------------------------------
// SseScanResult
// -----------------------------------------------------------------------------

/// Outcome of [`scan_sse_chunk`].
///
/// Always returns completed payloads, even when the scratch limit is
/// exceeded partway through a chunk. The caller should process the
/// payloads first, then check `overflowed` to decide whether to
/// continue or disable capture.
pub(crate) struct SseScanResult {
    /// Completed `data:` payloads dispatched during this chunk.
    pub payloads: Vec<Vec<u8>>,

    /// Whether the scratch limit was exceeded. When `true`, the
    /// caller should store routes from `payloads`, then clear
    /// capture state and stop scanning further chunks.
    pub overflowed: bool,
}

// -----------------------------------------------------------------------------
// Scanning
// -----------------------------------------------------------------------------

/// Process one SSE chunk, returning completed `data:` payloads and
/// an overflow flag.
#[allow(clippy::too_many_lines, reason = "linear byte-processing loop")]
pub(crate) fn scan_sse_chunk(state: &mut SseScanState, chunk: &[u8], max_scratch_bytes: usize) -> SseScanResult {
    let mut payloads = Vec::new();
    let mut i = 0;

    // If previous chunk ended with CR and this starts with LF, consume it
    // as the second half of a CRLF pair (not a new line boundary).
    if state.prev_cr && chunk.first() == Some(&b'\n') {
        i = 1;
    }
    state.prev_cr = false;

    while let Some(&b) = chunk.get(i) {
        if b == b'\n' || b == b'\r' {
            process_line(&state.line_buf, &mut state.data_buf, &mut state.has_data, &mut payloads);
            state.line_buf.clear();

            // CRLF within the same chunk: skip the LF.
            if b == b'\r' {
                if let Some(&next) = chunk.get(i + 1) {
                    if next == b'\n' {
                        i += 1;
                    }
                } else {
                    state.prev_cr = true;
                }
            }
        } else {
            state.line_buf.push(b);
        }

        state.scratch_bytes = state.line_buf.len() + state.data_buf.len();
        if state.scratch_bytes > max_scratch_bytes {
            return SseScanResult {
                payloads,
                overflowed: true,
            };
        }

        i += 1;
    }

    state.scratch_bytes = state.line_buf.len() + state.data_buf.len();
    SseScanResult {
        payloads,
        overflowed: false,
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Only `data:` fields are captured; other SSE fields (`event:`, `id:`,
/// `retry:`) and comment lines are intentionally ignored because A2A
/// task payloads are always in `data:`.
fn process_line(line: &[u8], data_buf: &mut Vec<u8>, has_data: &mut bool, payloads: &mut Vec<Vec<u8>>) {
    if line.is_empty() {
        if *has_data {
            payloads.push(data_buf.clone());
            data_buf.clear();
            *has_data = false;
        }
        return;
    }

    if line.first() == Some(&b':') {
        return;
    }

    let Some(colon_pos) = line.iter().position(|&b| b == b':') else {
        return;
    };

    if line.get(..colon_pos) != Some(b"data".as_slice()) {
        return;
    }

    // Skip one optional space after the colon per SSE spec.
    let value_start = if line.get(colon_pos + 1) == Some(&b' ') {
        colon_pos + 2
    } else {
        colon_pos + 1
    };
    let value = line.get(value_start..).unwrap_or_default();

    if *has_data {
        data_buf.push(b'\n');
    }
    *has_data = true;
    data_buf.extend_from_slice(value);
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
    reason = "tests"
)]
mod tests {
    use super::*;

    const MAX_SCRATCH: usize = 65_536;

    // -------------------------------------------------------------------------
    // Single Complete Frame
    // -------------------------------------------------------------------------

    #[test]
    fn single_data_frame_yields_payload() {
        let mut state = SseScanState::default();
        let chunk = b"data: {\"id\":\"task-1\"}\n\n";

        let SseScanResult { payloads, .. } = scan_sse_chunk(&mut state, chunk, MAX_SCRATCH);

        assert_eq!(payloads.len(), 1, "one event should yield one payload");
        assert_eq!(payloads[0], b"{\"id\":\"task-1\"}");
    }

    #[test]
    fn multiple_frames_in_one_chunk() {
        let mut state = SseScanState::default();
        let chunk = b"data: first\n\ndata: second\n\n";

        let SseScanResult { payloads, .. } = scan_sse_chunk(&mut state, chunk, MAX_SCRATCH);

        assert_eq!(payloads.len(), 2, "two events should yield two payloads");
        assert_eq!(payloads[0], b"first");
        assert_eq!(payloads[1], b"second");
    }

    // -------------------------------------------------------------------------
    // Chunk Splitting
    // -------------------------------------------------------------------------

    #[test]
    fn frame_split_across_two_chunks() {
        let mut state = SseScanState::default();

        let r = scan_sse_chunk(&mut state, b"data: {\"id\":", MAX_SCRATCH);
        assert!(r.payloads.is_empty(), "incomplete frame yields no payload");

        let r = scan_sse_chunk(&mut state, b"\"task-1\"}\n\n", MAX_SCRATCH);
        assert_eq!(r.payloads.len(), 1, "completed frame yields payload");
        assert_eq!(r.payloads[0], b"{\"id\":\"task-1\"}");
    }

    #[test]
    fn line_split_across_chunks() {
        let mut state = SseScanState::default();

        let r = scan_sse_chunk(&mut state, b"da", MAX_SCRATCH);
        assert!(r.payloads.is_empty(), "partial field name yields no payload");

        let r = scan_sse_chunk(&mut state, b"ta: hello\n\n", MAX_SCRATCH);
        assert_eq!(r.payloads.len(), 1, "completed line yields payload");
        assert_eq!(r.payloads[0], b"hello");
    }

    #[test]
    fn blank_line_split_across_chunks() {
        let mut state = SseScanState::default();

        let r = scan_sse_chunk(&mut state, b"data: hello\n", MAX_SCRATCH);
        assert!(r.payloads.is_empty(), "first newline is end-of-line, not dispatch");

        let r = scan_sse_chunk(&mut state, b"\n", MAX_SCRATCH);
        assert_eq!(r.payloads.len(), 1, "second newline dispatches event");
        assert_eq!(r.payloads[0], b"hello");
    }

    // -------------------------------------------------------------------------
    // Multi-line Data
    // -------------------------------------------------------------------------

    #[test]
    fn multiline_data_joined_with_newline() {
        let mut state = SseScanState::default();
        let chunk = b"data: line1\ndata: line2\ndata: line3\n\n";

        let SseScanResult { payloads, .. } = scan_sse_chunk(&mut state, chunk, MAX_SCRATCH);

        assert_eq!(payloads.len(), 1, "one event with multi-line data");
        assert_eq!(payloads[0], b"line1\nline2\nline3");
    }

    #[test]
    fn multiline_data_split_across_chunks() {
        let mut state = SseScanState::default();

        let r = scan_sse_chunk(&mut state, b"data: line1\n", MAX_SCRATCH);
        assert!(r.payloads.is_empty(), "not dispatched yet");

        let r = scan_sse_chunk(&mut state, b"data: line2\n\n", MAX_SCRATCH);
        assert_eq!(r.payloads.len(), 1, "dispatched on blank line");
        assert_eq!(r.payloads[0], b"line1\nline2");
    }

    // -------------------------------------------------------------------------
    // CRLF
    // -------------------------------------------------------------------------

    #[test]
    fn crlf_line_endings() {
        let mut state = SseScanState::default();
        let chunk = b"data: hello\r\n\r\n";

        let SseScanResult { payloads, .. } = scan_sse_chunk(&mut state, chunk, MAX_SCRATCH);

        assert_eq!(payloads.len(), 1, "CRLF should work as line endings");
        assert_eq!(payloads[0], b"hello");
    }

    #[test]
    fn crlf_split_across_chunks() {
        let mut state = SseScanState::default();

        let r = scan_sse_chunk(&mut state, b"data: hello\r", MAX_SCRATCH);
        assert!(r.payloads.is_empty(), "CR at end of chunk, waiting for potential LF");

        let r = scan_sse_chunk(&mut state, b"\n\r\n", MAX_SCRATCH);
        assert_eq!(r.payloads.len(), 1, "CRLF spanning chunks should dispatch");
        assert_eq!(r.payloads[0], b"hello");
    }

    #[test]
    fn bare_cr_line_ending() {
        let mut state = SseScanState::default();
        let chunk = b"data: hello\r\r";

        let SseScanResult { payloads, .. } = scan_sse_chunk(&mut state, chunk, MAX_SCRATCH);

        assert_eq!(payloads.len(), 1, "bare CR should be a valid line terminator");
        assert_eq!(payloads[0], b"hello");
    }

    // -------------------------------------------------------------------------
    // Comments and Unknown Fields
    // -------------------------------------------------------------------------

    #[test]
    fn comments_ignored() {
        let mut state = SseScanState::default();
        let chunk = b": this is a comment\ndata: hello\n\n";

        let SseScanResult { payloads, .. } = scan_sse_chunk(&mut state, chunk, MAX_SCRATCH);

        assert_eq!(payloads.len(), 1, "comment should be ignored");
        assert_eq!(payloads[0], b"hello");
    }

    #[test]
    fn unknown_fields_ignored() {
        let mut state = SseScanState::default();
        let chunk = b"event: message\nid: 42\ndata: hello\nretry: 1000\n\n";

        let SseScanResult { payloads, .. } = scan_sse_chunk(&mut state, chunk, MAX_SCRATCH);

        assert_eq!(payloads.len(), 1, "unknown fields should be ignored");
        assert_eq!(payloads[0], b"hello");
    }

    #[test]
    fn empty_frames_ignored() {
        let mut state = SseScanState::default();
        let chunk = b"\n\ndata: hello\n\n";

        let SseScanResult { payloads, .. } = scan_sse_chunk(&mut state, chunk, MAX_SCRATCH);

        assert_eq!(
            payloads.len(),
            1,
            "empty frames (consecutive blank lines) should be ignored"
        );
        assert_eq!(payloads[0], b"hello");
    }

    #[test]
    fn line_without_colon_ignored() {
        let mut state = SseScanState::default();
        let chunk = b"justtext\ndata: hello\n\n";

        let SseScanResult { payloads, .. } = scan_sse_chunk(&mut state, chunk, MAX_SCRATCH);

        assert_eq!(payloads.len(), 1, "line without colon should be ignored per SSE spec");
        assert_eq!(payloads[0], b"hello");
    }

    // -------------------------------------------------------------------------
    // Data Without Leading Space
    // -------------------------------------------------------------------------

    #[test]
    fn data_without_space_after_colon() {
        let mut state = SseScanState::default();
        let chunk = b"data:nospace\n\n";

        let SseScanResult { payloads, .. } = scan_sse_chunk(&mut state, chunk, MAX_SCRATCH);

        assert_eq!(payloads.len(), 1, "data without space after colon should work");
        assert_eq!(payloads[0], b"nospace");
    }

    #[test]
    fn data_with_empty_value() {
        let mut state = SseScanState::default();
        let chunk = b"data:\n\n";

        let SseScanResult { payloads, .. } = scan_sse_chunk(&mut state, chunk, MAX_SCRATCH);

        assert_eq!(payloads.len(), 1, "data with empty value should yield empty payload");
        assert!(payloads[0].is_empty(), "payload should be empty");
    }

    // -------------------------------------------------------------------------
    // Scratch Overflow
    // -------------------------------------------------------------------------

    #[test]
    fn scratch_overflow_sets_overflowed_flag() {
        let mut state = SseScanState::default();
        let chunk = b"data: a]very long line that exceeds the limit\n";

        let result = scan_sse_chunk(&mut state, chunk, 10);

        assert!(result.overflowed, "exceeding scratch limit should set overflowed");
        assert!(result.payloads.is_empty(), "no completed events before overflow");
    }

    #[test]
    fn completed_payload_returned_before_later_overflow() {
        let mut state = SseScanState::default();
        // First event completes (short), then a second event overflows (long).
        let chunk = b"data: ok\n\ndata: this-is-way-too-long-for-the-limit\n\n";

        let result = scan_sse_chunk(&mut state, chunk, 15);

        assert!(result.overflowed, "should overflow on the second event");
        assert_eq!(
            result.payloads.len(),
            1,
            "first completed event should still be returned"
        );
        assert_eq!(result.payloads[0], b"ok");
    }

    #[test]
    fn scratch_resets_after_dispatch() {
        let mut state = SseScanState::default();

        let r = scan_sse_chunk(&mut state, b"data: ab\n\n", 20);
        assert_eq!(r.payloads.len(), 1, "first event dispatched");

        assert_eq!(
            state.scratch_bytes, 0,
            "scratch should reset after data_buf is cleared by dispatch"
        );

        let r = scan_sse_chunk(&mut state, b"data: cd\n\n", 20);
        assert_eq!(r.payloads.len(), 1, "second event should also succeed after reset");
    }

    // -------------------------------------------------------------------------
    // No Event Name Required
    // -------------------------------------------------------------------------

    #[test]
    fn data_without_event_name_yields_payload() {
        let mut state = SseScanState::default();
        let chunk = b"data: {\"task\":{\"id\":\"t1\"}}\n\n";

        let SseScanResult { payloads, .. } = scan_sse_chunk(&mut state, chunk, MAX_SCRATCH);

        assert_eq!(payloads.len(), 1, "data without event: name should still yield payload");
    }

    // -------------------------------------------------------------------------
    // Mixed Content
    // -------------------------------------------------------------------------

    #[test]
    fn json_rpc_response_in_sse_data() {
        let mut state = SseScanState::default();
        let chunk = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"task\":{\"id\":\"task-42\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}}\n\n";

        let SseScanResult { payloads, .. } = scan_sse_chunk(&mut state, chunk, MAX_SCRATCH);

        assert_eq!(payloads.len(), 1, "JSON-RPC response in SSE data");
        let parsed: serde_json::Value = serde_json::from_slice(&payloads[0]).expect("should be valid JSON");
        assert_eq!(
            parsed["result"]["task"]["id"].as_str(),
            Some("task-42"),
            "task ID should be extractable from parsed payload"
        );
    }
}
