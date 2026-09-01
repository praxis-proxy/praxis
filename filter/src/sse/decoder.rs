// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Bounded, incremental SSE decoder and its limits / batch / error types.

use bytes::Bytes;

use super::record::{SseField, SseRecord};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// UTF-8 byte order mark, stripped once at stream start.
const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Lifecycle state of an `SseDecoder`.
#[derive(Clone, Copy, Debug)]
enum DecoderState {
    /// Normal operation.
    Active,
    /// `finish` has been called; `push` reports `Finished`.
    Finished,
    /// A limit violation occurred; the stored error is re-reported until reset.
    Poisoned(SseDecodeError),
}

/// Bounds on retained memory. Enforced continuously as bytes accumulate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SseLimits {
    /// Max bytes for a single field line held across chunks.
    pub max_line_bytes: usize,
    /// Max total retained bytes for one in-progress record: the sum of every
    /// field's value plus every `Unknown` field name, so large unknown names
    /// cannot bypass the limit.
    pub max_record_bytes: usize,
    /// Max number of fields in one record (bounds per-field allocations so many
    /// tiny fields cannot evade `max_record_bytes`).
    pub max_fields_per_record: usize,
}

impl Default for SseLimits {
    fn default() -> Self {
        Self {
            max_line_bytes: 10_485_760,   // 10 MiB
            max_record_bytes: 10_485_760, // 10 MiB
            max_fields_per_record: 4096,  // far above any real record
        }
    }
}

/// Result of one `SseDecoder::push` or `SseDecoder::finish`.
///
/// Carries records completed *before* any error, so a size violation never
/// discards earlier records from the same chunk. A limit violation poisons the
/// decoder; an `error` of `Finished` instead signals a `push` after `finish` and
/// does not poison.
#[derive(Debug, Default, PartialEq, Eq)]
#[must_use]
pub struct SseBatch {
    /// Records completed by this call, in order.
    pub records: Vec<SseRecord>,
    /// The error that stopped decoding this call, if any.
    pub error: Option<SseDecodeError>,
}

/// Decode-time errors. The three limit violations poison the decoder (the error
/// is re-reported until `reset`); `Finished` is not a poison.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SseDecodeError {
    /// A single field line exceeded `max_line_bytes`. Poisons.
    #[error("SSE line exceeded limit: {size} bytes > {limit} byte limit")]
    LineTooLong {
        /// Observed line size in bytes.
        size: usize,
        /// Configured `max_line_bytes`.
        limit: usize,
    },
    /// The in-progress record's retained bytes (values + `Unknown` names)
    /// exceeded `max_record_bytes`. Poisons.
    #[error("SSE record exceeded limit: {size} bytes > {limit} byte limit")]
    RecordTooLarge {
        /// Observed retained record size in bytes.
        size: usize,
        /// Configured `max_record_bytes`.
        limit: usize,
    },
    /// The in-progress record exceeded `max_fields_per_record`. Poisons.
    #[error("SSE record exceeded field limit: {count} fields > {limit} field limit")]
    TooManyFields {
        /// Observed field count.
        count: usize,
        /// Configured `max_fields_per_record`.
        limit: usize,
    },
    /// `push` was called after `finish`. Does not poison.
    #[error("SSE decoder push called after finish")]
    Finished,
}

/// Bounded, incremental SSE record decoder.
///
/// Feed body chunks with `push`; each call returns the records that chunk
/// completed. Only the in-progress line and record are retained between calls.
/// Call `finish` at end of stream.
#[derive(Debug)]
pub struct SseDecoder {
    /// Bytes of the current, not-yet-terminated field line.
    line_buf: Vec<u8>,
    /// Fields accumulated for the in-progress record, in wire order.
    fields: Vec<SseField>,
    /// Set when the previous chunk ended on a bare `\r`, so a leading `\n` in
    /// the next chunk completes the `\r\n` pair.
    prev_cr: bool,
    /// Retained-memory bounds applied while decoding.
    limits: SseLimits,
    /// Retained bytes of the in-progress record: field values plus `Unknown`
    /// names. Reset to 0 when a record is dispatched.
    record_bytes: usize,
    /// Current lifecycle state.
    state: DecoderState,
    /// Leading BOM bytes matched so far (0..=3), before resolution.
    bom_len: usize,
    /// Whether the leading-BOM check has completed (stripped or ruled out).
    bom_resolved: bool,
}

impl Default for SseDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl SseDecoder {
    /// Create a decoder with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(SseLimits::default())
    }

    /// Create a decoder with explicit limits.
    #[must_use]
    pub fn with_limits(limits: SseLimits) -> Self {
        Self {
            line_buf: Vec::new(),
            fields: Vec::new(),
            prev_cr: false,
            limits,
            record_bytes: 0,
            state: DecoderState::Active,
            bom_len: 0,
            bom_resolved: false,
        }
    }

    /// Feed one body chunk; returns the records it completed and an optional
    /// error.
    pub fn push(&mut self, chunk: &[u8]) -> SseBatch {
        if let DecoderState::Finished = self.state {
            return SseBatch {
                records: Vec::new(),
                error: Some(SseDecodeError::Finished),
            };
        }
        if let DecoderState::Poisoned(err) = self.state {
            return SseBatch {
                records: Vec::new(),
                error: Some(err),
            };
        }
        let mut records = Vec::new();
        match self.parse(chunk, &mut records) {
            Ok(()) => SseBatch { records, error: None },
            Err(err) => {
                self.state = DecoderState::Poisoned(err);
                SseBatch {
                    records,
                    error: Some(err),
                }
            },
        }
    }

    /// `true` only in the poisoned state (after a limit violation).
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        matches!(self.state, DecoderState::Poisoned(_))
    }

    /// Signal end of stream, transitioning `Active` to `Finished`.
    ///
    /// Processes any buffered partial line as if terminated and, if the
    /// in-progress block accumulated any field, returns it as a single trailing
    /// record. Idempotent: a second call returns an empty batch. While poisoned,
    /// re-reports the limit error.
    pub fn finish(&mut self) -> SseBatch {
        if let DecoderState::Poisoned(err) = self.state {
            return SseBatch {
                records: Vec::new(),
                error: Some(err),
            };
        }
        if let DecoderState::Finished = self.state {
            return SseBatch::default();
        }
        let mut records = Vec::new();
        match self.flush(&mut records) {
            Ok(()) => {
                self.state = DecoderState::Finished;
                SseBatch { records, error: None }
            },
            Err(err) => {
                self.state = DecoderState::Poisoned(err);
                SseBatch {
                    records,
                    error: Some(err),
                }
            },
        }
    }

    /// Flush a trailing partial line and dispatch any accumulated fields.
    fn flush(&mut self, records: &mut Vec<SseRecord>) -> Result<(), SseDecodeError> {
        if !self.bom_resolved && self.bom_len > 0 {
            let prior = self.bom_len;
            self.bom_resolved = true;
            self.bom_len = 0;
            self.feed(BOM.get(..prior).unwrap_or_default(), records)?;
        }
        if !self.line_buf.is_empty() {
            // `process_line` returns `Some` only for an empty `line_buf` (a blank
            // line ends a record); here the buffer is non-empty (BOM replay above
            // only pushes bytes, never a terminator), so it commits the trailing
            // line as a field and returns `None` — the record is emitted by the
            // `!self.fields.is_empty()` block below. The `Some` arm is defensive.
            if let Some(record) = self.process_line()? {
                records.push(record);
            }
            self.line_buf.clear();
        }
        if !self.fields.is_empty() {
            records.push(SseRecord::from_fields(std::mem::take(&mut self.fields)));
            self.record_bytes = 0;
        }
        Ok(())
    }

    /// Reset to `Active`, clearing buffers and any `Finished`/`Poisoned` state.
    pub fn reset(&mut self) {
        self.line_buf.clear();
        self.fields.clear();
        self.record_bytes = 0;
        self.prev_cr = false;
        self.state = DecoderState::Active;
        self.bom_len = 0;
        self.bom_resolved = false;
    }

    /// `true` only in the `Finished` state (after `finish`).
    #[must_use]
    pub fn is_finished(&self) -> bool {
        matches!(self.state, DecoderState::Finished)
    }

    /// Strip a single leading UTF-8 BOM (possibly split across chunks) before
    /// delegating to `feed`.
    fn parse(&mut self, chunk: &[u8], records: &mut Vec<SseRecord>) -> Result<(), SseDecodeError> {
        if self.bom_resolved {
            return self.feed(chunk, records);
        }
        let prior = self.bom_len;
        let mut matched = prior;
        let mut i = 0;
        while matched < BOM.len() {
            let Some(&b) = chunk.get(i) else {
                self.bom_len = matched; // wait for more bytes
                return Ok(());
            };
            if BOM.get(matched) == Some(&b) {
                matched += 1;
                i += 1;
            } else {
                self.bom_resolved = true;
                self.bom_len = 0;
                self.feed(BOM.get(..prior).unwrap_or_default(), records)?;
                return self.feed(chunk, records);
            }
        }
        self.bom_resolved = true;
        self.bom_len = 0;
        self.feed(chunk.get(i..).unwrap_or_default(), records)
    }

    /// Consume a byte slice, appending completed records to `records`.
    fn feed(&mut self, bytes: &[u8], records: &mut Vec<SseRecord>) -> Result<(), SseDecodeError> {
        if bytes.is_empty() {
            return Ok(()); // empty chunk must preserve prev_cr
        }
        let mut i = 0;
        if self.prev_cr && bytes.first() == Some(&b'\n') {
            i = 1;
        }
        self.prev_cr = false;
        while let Some(&b) = bytes.get(i) {
            match b {
                b'\n' => self.end_line(records)?,
                b'\r' => self.handle_cr(bytes, &mut i, records)?,
                _ => self.push_byte(b)?,
            }
            i += 1;
        }
        Ok(())
    }

    /// Handle a `\r`: end the line and pair a following `\n` (this chunk or the
    /// next) so `\r\n` counts as one line ending.
    fn handle_cr(&mut self, bytes: &[u8], i: &mut usize, records: &mut Vec<SseRecord>) -> Result<(), SseDecodeError> {
        self.end_line(records)?;
        match bytes.get(*i + 1) {
            Some(&b'\n') => *i += 1,
            Some(_) => {},
            None => self.prev_cr = true,
        }
        Ok(())
    }

    /// Append a data byte to the current line, enforcing `max_line_bytes`.
    fn push_byte(&mut self, b: u8) -> Result<(), SseDecodeError> {
        self.line_buf.push(b);
        if self.line_buf.len() > self.limits.max_line_bytes {
            return Err(SseDecodeError::LineTooLong {
                size: self.line_buf.len(),
                limit: self.limits.max_line_bytes,
            });
        }
        Ok(())
    }

    /// Process the current line as terminated, then clear the line buffer.
    fn end_line(&mut self, records: &mut Vec<SseRecord>) -> Result<(), SseDecodeError> {
        if let Some(record) = self.process_line()? {
            records.push(record);
        }
        self.line_buf.clear();
        Ok(())
    }

    /// Interpret the current line: blank dispatches a record; otherwise commit a
    /// field.
    fn process_line(&mut self) -> Result<Option<SseRecord>, SseDecodeError> {
        if self.line_buf.is_empty() {
            if self.fields.is_empty() {
                return Ok(None);
            }
            let record = SseRecord::from_fields(std::mem::take(&mut self.fields));
            self.record_bytes = 0;
            return Ok(Some(record));
        }
        let field = self.classify_line();
        self.push_field(field)?;
        Ok(None)
    }

    /// Derive the field for the current (non-empty) line per the event-stream
    /// interpretation rules.
    fn classify_line(&self) -> SseField {
        let line = self.line_buf.as_slice();
        match line.iter().position(|&b| b == b':') {
            Some(colon) => {
                let name = line.get(..colon).unwrap_or_default();
                let rest = line.get(colon + 1..).unwrap_or_default();
                let value = rest.strip_prefix(b" ").unwrap_or(rest);
                classify(name, value)
            },
            None => classify(line, b""),
        }
    }

    /// Append a field, enforcing `max_fields_per_record` and `max_record_bytes`.
    fn push_field(&mut self, field: SseField) -> Result<(), SseDecodeError> {
        if self.fields.len() >= self.limits.max_fields_per_record {
            return Err(SseDecodeError::TooManyFields {
                count: self.fields.len() + 1,
                limit: self.limits.max_fields_per_record,
            });
        }
        let new_bytes = self.record_bytes + field_cost(&field);
        if new_bytes > self.limits.max_record_bytes {
            return Err(SseDecodeError::RecordTooLarge {
                size: new_bytes,
                limit: self.limits.max_record_bytes,
            });
        }
        self.record_bytes = new_bytes;
        self.fields.push(field);
        Ok(())
    }
}

/// Classify a name/value pair into a typed field, copying bytes out of the line
/// buffer. An empty name means a `:`-prefixed comment line.
fn classify(name: &[u8], value: &[u8]) -> SseField {
    match name {
        b"" => SseField::Comment(Bytes::copy_from_slice(value)),
        b"event" => SseField::Event(Bytes::copy_from_slice(value)),
        b"data" => SseField::Data(Bytes::copy_from_slice(value)),
        b"id" => SseField::Id(Bytes::copy_from_slice(value)),
        b"retry" => SseField::Retry(Bytes::copy_from_slice(value)),
        other => SseField::Unknown {
            name: Bytes::copy_from_slice(other),
            value: Bytes::copy_from_slice(value),
        },
    }
}

/// Retained-byte cost of a field: value length, plus name length for `Unknown`.
fn field_cost(field: &SseField) -> usize {
    match field {
        SseField::Unknown { name, value } => name.len() + value.len(),
        SseField::Event(value)
        | SseField::Data(value)
        | SseField::Id(value)
        | SseField::Retry(value)
        | SseField::Comment(value) => value.len(),
    }
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_match_spec() {
        let limits = SseLimits::default();
        assert_eq!(limits.max_line_bytes, 10_485_760, "default line limit is 10 MiB");
        assert_eq!(limits.max_record_bytes, 10_485_760, "default record limit is 10 MiB");
        assert_eq!(limits.max_fields_per_record, 4096, "default field cap is 4096");
    }

    #[test]
    fn batch_default_is_empty() {
        let batch = SseBatch::default();
        assert!(batch.records.is_empty(), "default batch has no records");
        assert_eq!(batch.error, None, "default batch has no error");
    }

    #[test]
    fn decode_errors_are_copy_and_boxable() {
        let err = SseDecodeError::LineTooLong { size: 20, limit: 10 };
        let copy = err;
        assert_eq!(err, copy, "SseDecodeError is Copy");
        assert!(err.to_string().contains("20"), "Display includes the size");
        assert!(err.to_string().contains("10"), "Display includes the limit");
        let _boxed: Box<dyn std::error::Error + Send + Sync> = err.into();
    }

    // ----- Test Utilities -----

    // Module-scoped BOM constant for the tests below.
    const BOM_BYTES: &[u8] = &[0xEF, 0xBB, 0xBF];

    // Push one chunk, assert no error, return the completed records.
    fn push_ok(decoder: &mut SseDecoder, chunk: &[u8]) -> Vec<SseRecord> {
        let batch = decoder.push(chunk);
        assert_eq!(batch.error, None, "unexpected decode error");
        batch.records
    }

    // Decode the whole input in one push then finish; return all records.
    fn decode_whole(input: &[u8]) -> Vec<SseRecord> {
        let mut decoder = SseDecoder::new();
        let mut records = decoder.push(input).records;
        records.extend(decoder.finish().records);
        records
    }

    // Decode the input split at byte offsets a and b; return all records.
    fn decode_split(input: &[u8], a: usize, b: usize) -> Vec<SseRecord> {
        let mut decoder = SseDecoder::new();
        let mut records = Vec::new();
        for part in [&input[..a], &input[a..b], &input[b..]] {
            records.extend(decoder.push(part).records);
        }
        records.extend(decoder.finish().records);
        records
    }

    // Assert every 3-way split of the input decodes identically to the whole.
    fn assert_all_splits_match(input: &[u8]) {
        let expected = decode_whole(input);
        let len = input.len();
        for a in 0..=len {
            for b in a..=len {
                assert_eq!(
                    decode_split(input, a, b),
                    expected,
                    "split ({a},{b}) diverged for {input:?}"
                );
            }
        }
    }

    #[test]
    fn single_record() {
        let mut decoder = SseDecoder::new();
        let records = push_ok(&mut decoder, b"data: hello\n\n");
        assert_eq!(records.len(), 1, "one complete record");
        assert_eq!(records[0].data(), Bytes::from_static(b"hello"), "data decoded");
    }

    #[test]
    fn event_type_and_multiple_records_in_one_chunk() {
        let mut decoder = SseDecoder::new();
        let records = push_ok(&mut decoder, b"event: a\ndata: 1\n\ndata: 2\n\n");
        assert_eq!(records.len(), 2, "two records in one chunk");
        assert_eq!(records[0].event(), Some(b"a".as_slice()), "first event type");
        assert_eq!(records[0].data(), Bytes::from_static(b"1"), "first data");
        assert_eq!(records[1].event(), None, "second has no event");
        assert_eq!(records[1].data(), Bytes::from_static(b"2"), "second data");
    }

    #[test]
    fn multiline_data_joined() {
        let mut decoder = SseDecoder::new();
        let records = push_ok(&mut decoder, b"data: a\ndata: b\n\n");
        assert_eq!(records[0].data(), Bytes::from_static(b"a\nb"), "multi-line data joined");
    }

    #[test]
    fn record_split_across_chunks() {
        let mut decoder = SseDecoder::new();
        assert!(
            push_ok(&mut decoder, b"data: hel").is_empty(),
            "partial line yields nothing"
        );
        assert!(
            push_ok(&mut decoder, b"lo\n").is_empty(),
            "line without blank yields nothing"
        );
        let records = push_ok(&mut decoder, b"\n");
        assert_eq!(
            records[0].data(),
            Bytes::from_static(b"hello"),
            "record completes on blank line"
        );
    }

    #[test]
    fn empty_blocks_ignored() {
        let mut decoder = SseDecoder::new();
        assert!(
            push_ok(&mut decoder, b"\n\n\n").is_empty(),
            "blank lines dispatch nothing"
        );
    }

    #[test]
    fn field_kinds_and_optional_space() {
        let mut decoder = SseDecoder::new();
        let records = push_ok(
            &mut decoder,
            b": ping\nevent: e\ndata:nospace\nid: 7\nretry: 500\nx-foo: bar\n\n",
        );
        let fields = records[0].fields();
        assert_eq!(
            fields[0],
            SseField::Comment(Bytes::from_static(b"ping")),
            "comment field"
        );
        assert_eq!(fields[1], SseField::Event(Bytes::from_static(b"e")), "event field");
        assert_eq!(
            fields[2],
            SseField::Data(Bytes::from_static(b"nospace")),
            "no leading space to strip"
        );
        assert_eq!(fields[3], SseField::Id(Bytes::from_static(b"7")), "id field");
        assert_eq!(fields[4], SseField::Retry(Bytes::from_static(b"500")), "retry field");
        assert_eq!(
            fields[5],
            SseField::Unknown {
                name: Bytes::from_static(b"x-foo"),
                value: Bytes::from_static(b"bar")
            },
            "unknown field preserved"
        );
    }

    #[test]
    fn colon_less_lines_classified_by_name() {
        let mut decoder = SseDecoder::new();
        let records = push_ok(&mut decoder, b"data\nevent\nid\nretry\nnope\n\n");
        let fields = records[0].fields();
        assert_eq!(fields[0], SseField::Data(Bytes::new()), "bare data name");
        assert_eq!(fields[1], SseField::Event(Bytes::new()), "bare event name");
        assert_eq!(fields[2], SseField::Id(Bytes::new()), "bare id name");
        assert_eq!(fields[3], SseField::Retry(Bytes::new()), "bare retry name");
        assert_eq!(
            fields[4],
            SseField::Unknown {
                name: Bytes::from_static(b"nope"),
                value: Bytes::new()
            },
            "bare unknown name"
        );
    }

    #[test]
    fn data_with_empty_value_is_event() {
        let mut decoder = SseDecoder::new();
        let records = push_ok(&mut decoder, b"data: \n\n");
        assert_eq!(records[0].data(), Bytes::new(), "empty data value");
        assert!(records[0].is_event(), "empty-value data still dispatches an event");
    }

    #[test]
    fn crlf_line_endings() {
        let mut decoder = SseDecoder::new();
        let records = push_ok(&mut decoder, b"data: hello\r\n\r\n");
        assert_eq!(records[0].data(), Bytes::from_static(b"hello"), "CRLF endings handled");
    }

    #[test]
    fn bare_cr_line_ending() {
        let mut decoder = SseDecoder::new();
        let records = push_ok(&mut decoder, b"data: hello\r\r");
        assert_eq!(
            records[0].data(),
            Bytes::from_static(b"hello"),
            "bare CR endings handled"
        );
    }

    #[test]
    fn line_too_long_returns_error() {
        let limits = SseLimits {
            max_line_bytes: 4,
            ..SseLimits::default()
        };
        let mut decoder = SseDecoder::with_limits(limits);
        let batch = decoder.push(b"data: toolong\n\n");
        assert!(
            matches!(batch.error, Some(SseDecodeError::LineTooLong { size, limit }) if size > limit),
            "over-long line reports LineTooLong"
        );
    }

    #[test]
    fn too_many_fields_returns_error() {
        let limits = SseLimits {
            max_fields_per_record: 2,
            ..SseLimits::default()
        };
        let mut decoder = SseDecoder::with_limits(limits);
        let batch = decoder.push(b"data: 1\ndata: 2\ndata: 3\n\n");
        assert!(
            matches!(batch.error, Some(SseDecodeError::TooManyFields { count, limit }) if count > limit),
            "exceeding field cap reports TooManyFields"
        );
    }

    #[test]
    fn crlf_split_across_chunks() {
        let mut decoder = SseDecoder::new();
        assert!(push_ok(&mut decoder, b"data: hello\r").is_empty(), "trailing CR waits");
        let records = push_ok(&mut decoder, b"\n\r\n");
        assert_eq!(
            records[0].data(),
            Bytes::from_static(b"hello"),
            "leading LF completes CRLF"
        );
    }

    #[test]
    fn empty_chunk_preserves_pending_cr() {
        let mut decoder = SseDecoder::new();
        assert!(push_ok(&mut decoder, b"event: keep\r").is_empty(), "trailing CR waits");
        assert!(
            push_ok(&mut decoder, b"").is_empty(),
            "empty chunk must preserve prev_cr"
        );
        let records = push_ok(&mut decoder, b"\ndata: x\r\n\r\n");
        assert_eq!(
            records[0].event(),
            Some(b"keep".as_slice()),
            "event survived the boundary"
        );
        assert_eq!(
            records[0].data(),
            Bytes::from_static(b"x"),
            "data decoded after boundary"
        );
    }

    #[test]
    fn mixed_endings_in_one_record() {
        let mut decoder = SseDecoder::new();
        let records = push_ok(&mut decoder, b"event: a\rdata: b\ndata: c\r\n\n");
        assert_eq!(records[0].event(), Some(b"a".as_slice()), "CR-terminated event line");
        assert_eq!(
            records[0].data(),
            Bytes::from_static(b"b\nc"),
            "mixed LF/CRLF data joined"
        );
    }

    #[test]
    fn record_too_large_counts_values() {
        let limits = SseLimits {
            max_record_bytes: 6,
            ..SseLimits::default()
        };
        let mut decoder = SseDecoder::with_limits(limits);
        let batch = decoder.push(b"data: aaaa\ndata: bbbb\n\n");
        assert!(
            matches!(batch.error, Some(SseDecodeError::RecordTooLarge { size, limit }) if size > limit),
            "summed data values over the cap report RecordTooLarge"
        );
    }

    #[test]
    fn record_too_large_counts_unknown_names() {
        let limits = SseLimits {
            max_record_bytes: 8,
            ..SseLimits::default()
        };
        let mut decoder = SseDecoder::with_limits(limits);
        let batch = decoder.push(b"aaaaa\nbbbbb\n\n");
        assert!(
            matches!(batch.error, Some(SseDecodeError::RecordTooLarge { .. })),
            "unknown-field names must count toward max_record_bytes"
        );
    }

    #[test]
    fn record_bytes_reset_between_records() {
        let limits = SseLimits {
            max_record_bytes: 3,
            ..SseLimits::default()
        };
        let mut decoder = SseDecoder::with_limits(limits);
        let records = push_ok(&mut decoder, b"data: ab\n\ndata: cd\n\n");
        assert_eq!(records.len(), 2, "byte budget must reset after each dispatched record");
    }

    #[test]
    fn records_before_overflow_returned_then_poisoned() {
        let limits = SseLimits {
            max_line_bytes: 8,
            ..SseLimits::default()
        };
        let mut decoder = SseDecoder::with_limits(limits);
        let batch = decoder.push(b"data: ok\n\ndata: waytoolong\n\n");
        assert_eq!(batch.records.len(), 1, "record completed before the overflow is kept");
        assert_eq!(
            batch.records[0].data(),
            Bytes::from_static(b"ok"),
            "kept record is correct"
        );
        assert!(
            matches!(batch.error, Some(SseDecodeError::LineTooLong { .. })),
            "overflow reported after the kept record"
        );
        assert!(decoder.is_poisoned(), "limit violation poisons the decoder");
    }

    #[test]
    fn poisoned_decoder_re_reports_and_yields_no_records() {
        let limits = SseLimits {
            max_line_bytes: 4,
            ..SseLimits::default()
        };
        let mut decoder = SseDecoder::with_limits(limits);
        let first_err = decoder.push(b"data: toolong\n\n").error.unwrap();
        let second = decoder.push(b"data: x\n\n");
        assert!(second.records.is_empty(), "poisoned decoder yields no records");
        assert_eq!(
            second.error,
            Some(first_err),
            "poisoned decoder re-reports the same error"
        );
        assert!(decoder.is_poisoned(), "stays poisoned");
    }

    #[test]
    fn healthy_decoder_is_not_poisoned() {
        let mut decoder = SseDecoder::new();
        let records = push_ok(&mut decoder, b"data: hi\n\n");
        assert_eq!(records.len(), 1, "healthy decode");
        assert!(!decoder.is_poisoned(), "no poison on clean input");
    }

    #[test]
    fn finish_flushes_trailing_record_without_blank_line() {
        let mut decoder = SseDecoder::new();
        assert!(push_ok(&mut decoder, b"data: tail\n").is_empty(), "no blank line yet");
        let batch = decoder.finish();
        assert_eq!(batch.error, None, "clean finish");
        assert_eq!(batch.records.len(), 1, "trailing record flushed");
        assert_eq!(
            batch.records[0].data(),
            Bytes::from_static(b"tail"),
            "trailing data correct"
        );
        assert!(decoder.is_finished(), "finish transitions to Finished");
        assert!(!decoder.is_poisoned(), "clean finish is not poison");
    }

    #[test]
    fn finish_flushes_unterminated_final_line() {
        let mut decoder = SseDecoder::new();
        assert!(push_ok(&mut decoder, b"data: tail").is_empty(), "no terminator at all");
        let batch = decoder.finish();
        assert_eq!(
            batch.records[0].data(),
            Bytes::from_static(b"tail"),
            "unterminated line flushed"
        );
    }

    #[test]
    fn finish_is_idempotent_and_push_after_finish_errors() {
        let mut decoder = SseDecoder::new();
        let records = push_ok(&mut decoder, b"data: x\n\n");
        assert_eq!(records.len(), 1, "record before finish");
        let first = decoder.finish();
        assert!(first.records.is_empty(), "nothing pending to flush");
        assert_eq!(first.error, None, "first finish is clean");

        let second = decoder.finish();
        assert_eq!(second, SseBatch::default(), "second finish is an empty batch");

        let after = decoder.push(b"data: y\n\n");
        assert!(after.records.is_empty(), "push after finish yields nothing");
        assert_eq!(
            after.error,
            Some(SseDecodeError::Finished),
            "push after finish reports Finished"
        );
    }

    #[test]
    fn finish_on_poisoned_reports_limit_error() {
        let limits = SseLimits {
            max_line_bytes: 4,
            ..SseLimits::default()
        };
        let mut decoder = SseDecoder::with_limits(limits);
        let err = decoder.push(b"data: toolong\n\n").error.unwrap();
        let batch = decoder.finish();
        assert_eq!(batch.error, Some(err), "finish re-reports the poison error");
        assert!(decoder.is_poisoned(), "still poisoned after finish");
    }

    #[test]
    fn reset_resumes_after_finish() {
        let mut decoder = SseDecoder::new();
        assert!(
            decoder.finish().records.is_empty(),
            "finish on empty stream yields nothing"
        );
        assert!(decoder.is_finished(), "finished before reset");
        decoder.reset();
        assert!(!decoder.is_finished(), "reset clears Finished");
        let records = push_ok(&mut decoder, b"data: again\n\n");
        assert_eq!(
            records[0].data(),
            Bytes::from_static(b"again"),
            "decoding resumes after reset"
        );
    }

    #[test]
    fn bom_stripped_at_stream_start() {
        let mut decoder = SseDecoder::new();
        let mut chunk = BOM_BYTES.to_vec();
        chunk.extend_from_slice(b"data: hi\n\n");
        let records = push_ok(&mut decoder, &chunk);
        assert_eq!(records[0].data(), Bytes::from_static(b"hi"), "leading BOM stripped");
    }

    #[test]
    fn bom_split_across_chunks() {
        let mut decoder = SseDecoder::new();
        assert!(push_ok(&mut decoder, &[0xEF]).is_empty(), "BOM byte 1 buffered");
        assert!(push_ok(&mut decoder, &[0xBB]).is_empty(), "BOM byte 2 buffered");
        assert!(push_ok(&mut decoder, &[0xBF]).is_empty(), "BOM byte 3 buffered");
        let records = push_ok(&mut decoder, b"data: hi\n\n");
        assert_eq!(records[0].data(), Bytes::from_static(b"hi"), "split BOM stripped");
    }

    #[test]
    fn partial_bom_mismatch_is_preserved_as_data() {
        let mut decoder = SseDecoder::new();
        assert!(push_ok(&mut decoder, &[0xEF]).is_empty(), "possible BOM start buffered");
        assert!(push_ok(&mut decoder, &[0x41]).is_empty(), "divergent byte buffered");
        let batch = decoder.finish();
        assert_eq!(
            batch.records[0].fields()[0],
            SseField::Unknown {
                name: Bytes::copy_from_slice(&[0xEF, 0x41]),
                value: Bytes::new()
            },
            "non-BOM bytes are preserved as data"
        );
    }

    #[test]
    fn feff_mid_stream_is_ordinary_data() {
        let mut decoder = SseDecoder::new();
        let mut chunk = b"data: a\n\n".to_vec();
        chunk.extend_from_slice(BOM_BYTES);
        chunk.extend_from_slice(b"\n\n");
        let records = push_ok(&mut decoder, &chunk);
        assert_eq!(records.len(), 2, "two records");
        assert_eq!(
            records[1].fields()[0],
            SseField::Unknown {
                name: Bytes::copy_from_slice(BOM_BYTES),
                value: Bytes::new()
            },
            "mid-stream BOM bytes are data, not stripped"
        );
    }

    #[test]
    fn bom_stripped_again_after_reset() {
        let mut decoder = SseDecoder::new();
        assert!(decoder.finish().records.is_empty(), "empty finish");
        decoder.reset();
        let mut chunk = BOM_BYTES.to_vec();
        chunk.extend_from_slice(b"data: fresh\n\n");
        let records = push_ok(&mut decoder, &chunk);
        assert_eq!(
            records[0].data(),
            Bytes::from_static(b"fresh"),
            "reset re-arms BOM stripping"
        );
    }

    #[test]
    fn every_split_point_matches_unsplit_decode() {
        let corpus: &[&[u8]] = &[
            b"data: hello\n\n",
            b"event: e\ndata: 1\ndata: 2\n\ndata: 3\n\n",
            b"data: a\r\nid: 1\r\n\r\n",
            b": comment\ndata: x\n\n",
            b"retry: 500\n\ndata: y\n\n",
            &[0xEF, 0xBB, 0xBF, b'd', b'a', b't', b'a', b':', b' ', b'z', b'\n', b'\n'],
            b"data: a\rid: 1\r\r",
            &[b'd', b'a', b't', b'a', b':', b' ', 0xFF, 0xFE, b'\n', b'\n'],
        ];
        for input in corpus {
            assert_all_splits_match(input);
        }
    }
}
