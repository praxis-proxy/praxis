// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Canonical SSE encoder for locally generated records.

use bytes::{Bytes, BytesMut};

use super::record::{SseField, SseRecord};

/// Serialize a record to canonical event-stream bytes.
///
/// Infallible: an `SseRecord` is validated at construction, so it cannot express
/// a value that would break framing.
#[must_use]
pub fn encode(record: &SseRecord) -> Bytes {
    let mut out = BytesMut::new();
    encode_into(record, &mut out);
    out.freeze()
}

/// Append a record's canonical bytes to a caller-provided buffer, letting the
/// caller serialize several records into one buffer.
pub fn encode_into(record: &SseRecord, out: &mut BytesMut) {
    for field in record.fields() {
        match field {
            SseField::Event(value) => write_named(out, b"event", value),
            SseField::Data(value) => write_named(out, b"data", value),
            SseField::Id(value) => write_named(out, b"id", value),
            SseField::Retry(value) => write_named(out, b"retry", value),
            SseField::Comment(value) => write_named(out, b"", value),
            SseField::Unknown { name, value } => write_named(out, name, value),
        }
    }
    out.extend_from_slice(b"\n");
}

/// Emit `NAME: VALUE\n` (or `: VALUE\n` for an empty name).
fn write_named(out: &mut BytesMut, name: &[u8], value: &[u8]) {
    out.extend_from_slice(name);
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(b"\n");
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
    use crate::sse::SseDecoder;

    #[test]
    fn encodes_canonical_fields_in_order() {
        let record = SseRecord::builder()
            .event("message")
            .data("hello")
            .data("world")
            .comment("hb")
            .build()
            .unwrap();
        assert_eq!(
            encode(&record),
            Bytes::from_static(b"event: message\ndata: hello\ndata: world\n: hb\n\n"),
            "canonical encoding in wire order with a trailing blank line"
        );
    }

    #[test]
    fn encodes_empty_value_with_single_space() {
        let record = SseRecord::builder().data("").build().unwrap();
        assert_eq!(
            encode(&record),
            Bytes::from_static(b"data: \n\n"),
            "empty value still emits one space after the colon"
        );
    }

    #[test]
    fn encodes_unknown_field() {
        let record = SseRecord::builder()
            .field(SseField::Unknown {
                name: Bytes::from_static(b"x-foo"),
                value: Bytes::from_static(b"bar"),
            })
            .build()
            .unwrap();
        assert_eq!(
            encode(&record),
            Bytes::from_static(b"x-foo: bar\n\n"),
            "unknown field uses its name"
        );
    }

    #[test]
    fn encode_into_appends_multiple_records() {
        let a = SseRecord::builder().data("a").build().unwrap();
        let b = SseRecord::builder().data("b").build().unwrap();
        let mut out = BytesMut::new();
        encode_into(&a, &mut out);
        encode_into(&b, &mut out);
        assert_eq!(
            out.freeze(),
            Bytes::from_static(b"data: a\n\ndata: b\n\n"),
            "encode_into appends without a separator"
        );
    }

    #[test]
    fn round_trip_is_field_stable() {
        let record = SseRecord::builder()
            .event("msg")
            .data("l1")
            .data("l2")
            .id("id1")
            .retry(4200)
            .comment("keepalive")
            .field(SseField::Unknown {
                name: Bytes::from_static(b"x-trace"),
                value: Bytes::from_static(b"t"),
            })
            .build()
            .unwrap();
        let bytes = encode(&record);
        let mut decoder = SseDecoder::new();
        let batch = decoder.push(&bytes);
        assert_eq!(batch.error, None, "round-trip decodes cleanly");
        assert_eq!(batch.records.len(), 1, "one record round-trips");
        assert_eq!(
            batch.records[0].fields(),
            record.fields(),
            "fields are byte-stable across round-trip"
        );
    }

    #[test]
    fn round_trip_preserves_non_utf8_and_nul_in_id() {
        let record = SseRecord::builder()
            .data(Bytes::copy_from_slice(&[0xFF, 0xFE, b'x']))
            .id(Bytes::copy_from_slice(b"a\0b"))
            .build()
            .unwrap();
        let bytes = encode(&record);
        let mut decoder = SseDecoder::new();
        let batch = decoder.push(&bytes);
        assert_eq!(
            batch.records[0].fields(),
            record.fields(),
            "non-UTF-8 data and NUL-in-id survive a round-trip"
        );
    }
}
