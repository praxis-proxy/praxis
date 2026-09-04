// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Provider-neutral SSE field and record types.

use bytes::{Bytes, BytesMut};

/// One field line within a record.
///
/// Values are raw bytes; the codec performs no UTF-8 normalization. A
/// well-formed value never contains CR or LF (those are line terminators), and
/// an `Unknown` name is non-empty and free of `:`, CR, and LF. These invariants
/// are enforced when a record is *built* (see `SseRecordBuilder`) and hold for
/// every record the decoder produces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SseField {
    /// An `event` field naming the record's event type.
    Event(Bytes),
    /// A `data` field; repeats form multi-line data.
    Data(Bytes),
    /// An `id` field carrying the last-event-id token.
    Id(Bytes),
    /// A `retry` field carrying the reconnection time in milliseconds.
    Retry(Bytes),
    /// A `:`-prefixed comment line; value is the text after the colon.
    Comment(Bytes),
    /// A field whose name is not `event`/`data`/`id`/`retry` and is not a
    /// comment. The name is non-empty and never equals a known field name, so
    /// an encode-then-decode round-trip preserves the variant.
    Unknown {
        /// The field name (non-empty, colon-free, not a known name).
        name: Bytes,
        /// The field value.
        value: Bytes,
    },
}

/// A framing block delimited by a blank line.
///
/// A record may be a dispatched `EventSource` event (at least one `Data` field),
/// or a comment-only heartbeat, an id/retry-only block, or an unknown-field
/// block. Fields are retained in wire order.
///
/// There is no public constructor and no `Default`: an empty record cannot
/// round-trip (the decoder ignores empty blocks). Build one with
/// `SseRecord::builder`; the decoder is the only other source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SseRecord {
    /// Fields in wire order.
    fields: Vec<SseField>,
}

impl SseRecord {
    /// Construct directly from ordered fields. Crate-internal: the decoder and
    /// `SseRecordBuilder::build` are the only callers, and both uphold the field
    /// invariants documented on `SseField`.
    pub(crate) fn from_fields(fields: Vec<SseField>) -> Self {
        Self { fields }
    }

    /// The record's fields, in wire order.
    #[must_use]
    pub fn fields(&self) -> &[SseField] {
        &self.fields
    }

    /// `Data` field values joined with a single `b'\n'`; empty when the record
    /// has no `Data` field.
    #[must_use]
    pub fn data(&self) -> Bytes {
        let mut values = self.fields.iter().filter_map(|field| match field {
            SseField::Data(value) => Some(value),
            _ => None,
        });
        let Some(first) = values.next() else {
            return Bytes::new();
        };
        let Some(second) = values.next() else {
            return first.clone();
        };
        let mut out = BytesMut::new();
        out.extend_from_slice(first);
        for value in std::iter::once(second).chain(values) {
            out.extend_from_slice(b"\n");
            out.extend_from_slice(value);
        }
        out.freeze()
    }

    /// Effective event type: the value of the last `Event` field, if any.
    #[must_use]
    pub fn event(&self) -> Option<&[u8]> {
        self.fields.iter().rev().find_map(|field| match field {
            SseField::Event(value) => Some(value.as_ref()),
            _ => None,
        })
    }

    /// Effective id: the last `Id` field whose value has no NUL. Later
    /// NUL-containing id lines are ignored and do not clear an earlier id.
    #[must_use]
    pub fn id(&self) -> Option<&[u8]> {
        self.fields.iter().rev().find_map(|field| match field {
            SseField::Id(value) if !value.contains(&0) => Some(value.as_ref()),
            _ => None,
        })
    }

    /// Effective retry (ms): the last `Retry` field that is all ASCII digits and
    /// fits in `u64`. Later invalid retry lines are ignored.
    #[must_use]
    pub fn retry(&self) -> Option<u64> {
        self.fields.iter().rev().find_map(|field| match field {
            SseField::Retry(value) => parse_retry(value),
            _ => None,
        })
    }

    /// Whether this record has at least one `Data` field, i.e. whether an
    /// `EventSource` client would dispatch an event for it.
    #[must_use]
    pub fn is_event(&self) -> bool {
        self.fields.iter().any(|field| matches!(field, SseField::Data(_)))
    }

    /// Start building a record for local generation / encoding.
    #[must_use = "call `.build()` to finalize the record"]
    pub fn builder() -> SseRecordBuilder {
        SseRecordBuilder::default()
    }
}

/// Validated construction for local generation / encoding. Setters are
/// infallible (they accumulate fields); validation happens in `build`.
#[derive(Debug, Default)]
#[must_use]
pub struct SseRecordBuilder {
    /// Accumulated fields, validated on `build`.
    fields: Vec<SseField>,
}

impl SseRecordBuilder {
    /// Append an `event` field.
    #[must_use = "builder methods should be chained"]
    pub fn event(mut self, value: impl Into<Bytes>) -> Self {
        self.fields.push(SseField::Event(value.into()));
        self
    }

    /// Append a `data` field. Repeat for multi-line data.
    #[must_use = "builder methods should be chained"]
    pub fn data(mut self, value: impl Into<Bytes>) -> Self {
        self.fields.push(SseField::Data(value.into()));
        self
    }

    /// Append an `id` field.
    #[must_use = "builder methods should be chained"]
    pub fn id(mut self, value: impl Into<Bytes>) -> Self {
        self.fields.push(SseField::Id(value.into()));
        self
    }

    /// Append a `retry` field (milliseconds); always numeric and valid.
    #[must_use = "builder methods should be chained"]
    pub fn retry(mut self, ms: u64) -> Self {
        self.fields.push(SseField::Retry(Bytes::from(ms.to_string())));
        self
    }

    /// Append a comment field.
    #[must_use = "builder methods should be chained"]
    pub fn comment(mut self, value: impl Into<Bytes>) -> Self {
        self.fields.push(SseField::Comment(value.into()));
        self
    }

    /// Append an arbitrary field for full control over kind and order.
    #[must_use = "builder methods should be chained"]
    pub fn field(mut self, field: SseField) -> Self {
        self.fields.push(field);
        self
    }

    /// Validate and finalize.
    ///
    /// # Errors
    ///
    /// Returns `SseBuildError` if any value contains CR or LF, any `Unknown`
    /// name is empty / contains `:`/CR/LF / equals a known field name, or the
    /// record has no fields.
    pub fn build(self) -> Result<SseRecord, SseBuildError> {
        if self.fields.is_empty() {
            return Err(SseBuildError::EmptyRecord);
        }
        for field in &self.fields {
            validate_field(field)?;
        }
        Ok(SseRecord::from_fields(self.fields))
    }
}

/// Build-time validation errors for `SseRecordBuilder::build`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SseBuildError {
    /// A field value contained a raw CR or LF, which would break framing.
    #[error("SSE field value contains a raw CR or LF")]
    NewlineInValue,
    /// An `Unknown` field name was empty, contained `:`/CR/LF, or equaled a
    /// known field name.
    #[error("SSE unknown field name is empty, contains ':'/CR/LF, or is a known name")]
    InvalidFieldName,
    /// The record had no fields; empty records cannot be represented.
    #[error("SSE record has no fields")]
    EmptyRecord,
}

// -----------------------------------------------------------------------------
// Private helpers
// -----------------------------------------------------------------------------

/// Parse an SSE `retry` value: all-ASCII-digit `u64`, else `None`.
fn parse_retry(value: &[u8]) -> Option<u64> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse::<u64>().ok()
}

/// Whether the slice contains a raw CR or LF (which would break framing).
fn has_newline(bytes: &[u8]) -> bool {
    bytes.iter().any(|&b| matches!(b, b'\r' | b'\n'))
}

/// Whether `name` equals one of the typed field names.
fn is_known_name(name: &[u8]) -> bool {
    matches!(name, b"event" | b"data" | b"id" | b"retry")
}

/// Validate one field's framing safety for `build`.
fn validate_field(field: &SseField) -> Result<(), SseBuildError> {
    match field {
        SseField::Event(value)
        | SseField::Data(value)
        | SseField::Id(value)
        | SseField::Retry(value)
        | SseField::Comment(value) => {
            if has_newline(value) {
                return Err(SseBuildError::NewlineInValue);
            }
        },
        SseField::Unknown { name, value } => {
            if has_newline(value) {
                return Err(SseBuildError::NewlineInValue);
            }
            let bad_name =
                name.is_empty() || name.iter().any(|&b| matches!(b, b':' | b'\r' | b'\n')) || is_known_name(name);
            if bad_name {
                return Err(SseBuildError::InvalidFieldName);
            }
        },
    }
    Ok(())
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
    fn field_variants_hold_their_bytes() {
        let data = SseField::Data(Bytes::from_static(b"hello"));
        assert_eq!(
            data,
            SseField::Data(Bytes::from_static(b"hello")),
            "Data variant should compare by its bytes"
        );

        let unknown = SseField::Unknown {
            name: Bytes::from_static(b"x-trace"),
            value: Bytes::from_static(b"abc"),
        };
        match unknown {
            SseField::Unknown { name, value } => {
                assert_eq!(name, Bytes::from_static(b"x-trace"), "unknown name should round-trip");
                assert_eq!(value, Bytes::from_static(b"abc"), "unknown value should round-trip");
            },
            _ => panic!("expected Unknown variant"),
        }
    }

    #[test]
    fn data_joins_multiline_with_single_newline() {
        let record = SseRecord::from_fields(vec![
            SseField::Data(Bytes::from_static(b"line1")),
            SseField::Data(Bytes::from_static(b"line2")),
        ]);
        assert_eq!(
            record.data(),
            Bytes::from_static(b"line1\nline2"),
            "multi-line data should join with a single newline"
        );
        assert!(record.is_event(), "record with data should be an event");
    }

    #[test]
    fn data_single_field_shares_backing_storage() {
        // A heap value: copying would reallocate to a new address, so pointer
        // equality is what proves the sole-data path shares the field's buffer.
        let value = Bytes::from(b"only".to_vec());
        let value_ptr = value.as_ptr();
        let record = SseRecord::from_fields(vec![SseField::Data(value)]);
        let data = record.data();
        assert_eq!(data, Bytes::from_static(b"only"), "content preserved");
        assert_eq!(
            data.as_ptr(),
            value_ptr,
            "a sole data field shares the field's backing storage without copying"
        );
        assert!(record.is_event(), "single data field is an event");
    }

    #[test]
    fn data_is_empty_when_no_data_fields() {
        let record = SseRecord::from_fields(vec![SseField::Comment(Bytes::from_static(b"hi"))]);
        assert_eq!(record.data(), Bytes::new(), "comment-only record has empty data");
        assert!(!record.is_event(), "comment-only record is not an event");
    }

    #[test]
    fn event_returns_last_event_value() {
        let record = SseRecord::from_fields(vec![
            SseField::Event(Bytes::from_static(b"first")),
            SseField::Event(Bytes::from_static(b"second")),
        ]);
        assert_eq!(
            record.event(),
            Some(b"second".as_slice()),
            "event should be the last value"
        );
    }

    #[test]
    fn id_ignores_later_nul_containing_value() {
        let record = SseRecord::from_fields(vec![
            SseField::Id(Bytes::from_static(b"good")),
            SseField::Id(Bytes::from_static(b"ba\0d")),
        ]);
        assert_eq!(
            record.id(),
            Some(b"good".as_slice()),
            "NUL-containing id must be ignored"
        );
    }

    #[test]
    fn retry_parses_last_valid_numeric() {
        let record = SseRecord::from_fields(vec![
            SseField::Retry(Bytes::from_static(b"1000")),
            SseField::Retry(Bytes::from_static(b"3000")),
        ]);
        assert_eq!(record.retry(), Some(3000), "retry should be the last numeric value");
    }

    #[test]
    fn retry_ignores_non_digits_and_overflow() {
        let non_digit = SseRecord::from_fields(vec![SseField::Retry(Bytes::from_static(b"1a"))]);
        assert_eq!(non_digit.retry(), None, "non-digit retry is invalid");

        let plus = SseRecord::from_fields(vec![SseField::Retry(Bytes::from_static(b"+5"))]);
        assert_eq!(plus.retry(), None, "signed retry is invalid");

        let overflow = SseRecord::from_fields(vec![SseField::Retry(Bytes::from_static(b"99999999999999999999999999"))]);
        assert_eq!(overflow.retry(), None, "overflowing retry is invalid");
    }

    #[test]
    fn retry_falls_back_to_earlier_valid_when_last_invalid() {
        let record = SseRecord::from_fields(vec![
            SseField::Retry(Bytes::from_static(b"1000")),
            SseField::Retry(Bytes::from_static(b"oops")),
        ]);
        assert_eq!(record.retry(), Some(1000), "should skip the invalid trailing retry");
    }

    #[test]
    fn builder_builds_valid_record_in_order() {
        let record = SseRecord::builder()
            .event("message")
            .data("hello")
            .data("world")
            .id("42")
            .retry(3000)
            .comment("hb")
            .build()
            .unwrap();
        assert_eq!(record.event(), Some(b"message".as_slice()), "event preserved");
        assert_eq!(
            record.data(),
            Bytes::from_static(b"hello\nworld"),
            "multi-line data preserved"
        );
        assert_eq!(record.id(), Some(b"42".as_slice()), "id preserved");
        assert_eq!(record.retry(), Some(3000), "retry preserved");
        assert_eq!(record.fields().len(), 6, "all six fields retained in order");
    }

    #[test]
    fn builder_rejects_empty_record() {
        assert_eq!(
            SseRecord::builder().build().unwrap_err(),
            SseBuildError::EmptyRecord,
            "empty builder must not produce a record"
        );
    }

    #[test]
    fn builder_rejects_newline_in_value() {
        assert_eq!(
            SseRecord::builder().data("a\nb").build().unwrap_err(),
            SseBuildError::NewlineInValue,
            "LF in a value breaks framing"
        );
        assert_eq!(
            SseRecord::builder().event("a\rb").build().unwrap_err(),
            SseBuildError::NewlineInValue,
            "CR in a value breaks framing"
        );
        assert_eq!(
            SseRecord::builder().comment("a\nb").build().unwrap_err(),
            SseBuildError::NewlineInValue,
            "LF in a comment breaks framing"
        );
    }

    #[test]
    fn builder_rejects_bad_unknown_names() {
        assert_invalid_unknown_name(b"", "empty unknown name is invalid");
        assert_invalid_unknown_name(b"a:b", "colon in unknown name is invalid");
        assert_invalid_unknown_name(b"a\nb", "newline in unknown name is invalid");
        assert_invalid_unknown_name(b"data", "known name in Unknown would change variant");
    }

    #[test]
    fn builder_allows_valid_unknown_and_nul_in_id() {
        let record = SseRecord::builder()
            .field(SseField::Unknown {
                name: Bytes::from_static(b"x-trace"),
                value: Bytes::from_static(b"abc"),
            })
            .id(Bytes::from_static(b"n\0ul"))
            .build()
            .unwrap();
        assert_eq!(record.fields().len(), 2, "valid unknown and NUL-in-id are accepted");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    fn assert_invalid_unknown_name(name: &[u8], msg: &str) {
        let err = SseRecord::builder()
            .field(SseField::Unknown {
                name: Bytes::copy_from_slice(name),
                value: Bytes::from_static(b"v"),
            })
            .build()
            .unwrap_err();
        assert_eq!(err, SseBuildError::InvalidFieldName, "{msg}");
    }
}
