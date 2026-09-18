// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `grpc.health.v1` message framing and protobuf codec.
//!
//! The health checking protocol is two tiny messages, so Praxis encodes
//! them by hand rather than pulling in a protobuf runtime and a code
//! generator for eleven bytes of wire format.

use bytes::Bytes;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// `content-type` for length-prefixed protobuf gRPC messages.
pub(crate) const GRPC_CONTENT_TYPE: &str = "application/grpc+proto";

/// Trailer, or Trailers-Only header, carrying the call's status code.
pub(crate) const GRPC_STATUS: &str = "grpc-status";

/// Trailer carrying the human-readable status description.
pub(crate) const GRPC_MESSAGE: &str = "grpc-message";

/// `grpc-status` value for a successful call.
pub(crate) const GRPC_STATUS_OK: u32 = 0;

/// Fixed method path of the gRPC health checking protocol.
pub(crate) const HEALTH_CHECK_PATH: &str = "/grpc.health.v1.Health/Check";

/// Largest response frame accepted from an upstream health server.
pub(crate) const MAX_RESPONSE_BYTES: usize = 4_096; // 4 KiB

/// Length-prefix size: one compression flag plus a four-byte length.
const PREFIX_LEN: usize = 5;

/// Protobuf key for `HealthCheckRequest.service` (field 1, wire type 2).
const TAG_SERVICE: u8 = 0x0A;

/// Protobuf field number of `HealthCheckResponse.status`.
const FIELD_STATUS: u64 = 1;

/// Protobuf wire type for a varint.
const WIRE_VARINT: u64 = 0;

/// Protobuf wire type for a length-delimited field.
const WIRE_LENGTH_DELIMITED: u64 = 2;

/// Protobuf wire type for a fixed 64-bit field.
const WIRE_FIXED64: u64 = 1;

/// Protobuf wire type for a fixed 32-bit field.
const WIRE_FIXED32: u64 = 5;

/// Maximum bytes in a base-128 varint encoding a `u64`.
const MAX_VARINT_BYTES: usize = 10;

// -----------------------------------------------------------------------------
// ServingStatus
// -----------------------------------------------------------------------------

/// `grpc.health.v1.HealthCheckResponse.ServingStatus`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServingStatus {
    /// The server reported no status (the proto3 default).
    Unknown,

    /// The service is serving requests.
    Serving,

    /// The service is up but not serving.
    NotServing,

    /// The server does not know the requested service.
    ServiceUnknown,
}

// -----------------------------------------------------------------------------
// Codec
// -----------------------------------------------------------------------------

/// Encode a `HealthCheckRequest` as one gRPC length-prefixed message.
///
/// An empty service name is encoded as an empty message, which the
/// health protocol defines as "the server's overall status".
pub(crate) fn encode_request(service: &str) -> Bytes {
    let mut message = Vec::new();
    if !service.is_empty() {
        message.push(TAG_SERVICE);
        write_varint(&mut message, u64::try_from(service.len()).unwrap_or(u64::MAX));
        message.extend_from_slice(service.as_bytes());
    }

    let length = u32::try_from(message.len()).unwrap_or(u32::MAX);
    let mut framed = Vec::with_capacity(PREFIX_LEN.saturating_add(message.len()));
    framed.push(0); // compression flag: identity
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(&message);
    Bytes::from(framed)
}

/// Decode the serving status from a length-prefixed `HealthCheckResponse`.
///
/// Returns `None` for a frame that is compressed, truncated, or longer
/// than [`MAX_RESPONSE_BYTES`] — none of which a health server should
/// ever send, and all of which mean the answer cannot be trusted.
pub(crate) fn decode_serving_status(frame: &[u8]) -> Option<ServingStatus> {
    let (compression, rest) = frame.split_first()?;
    if *compression != 0 {
        return None;
    }
    let declared = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?);
    let length = usize::try_from(declared).ok()?;
    if length > MAX_RESPONSE_BYTES {
        return None;
    }
    let message = rest.get(4..4_usize.checked_add(length)?)?;

    // An absent field is the proto3 default, which is UNKNOWN — not a
    // decode failure.
    let mut status = ServingStatus::Unknown;
    let mut pos = 0;
    while pos < message.len() {
        let key = read_varint(message, &mut pos)?;
        let field = key.checked_shr(3)?;
        let wire_type = key & 0b111;
        if field == FIELD_STATUS && wire_type == WIRE_VARINT {
            status = serving_status_from_u64(read_varint(message, &mut pos)?);
        } else {
            skip_field(message, &mut pos, wire_type)?;
        }
    }
    Some(status)
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Map a protobuf enum value onto a serving status.
///
/// Unrecognised values become `Unknown`: proto3 enums are open, so a
/// newer server may report a status this build has never heard of, and
/// "not SERVING" is the safe reading of it.
fn serving_status_from_u64(value: u64) -> ServingStatus {
    match value {
        1 => ServingStatus::Serving,
        2 => ServingStatus::NotServing,
        3 => ServingStatus::ServiceUnknown,
        _ => ServingStatus::Unknown,
    }
}

/// Append a base-128 varint.
fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        let byte = u8::try_from(value & 0x7F).unwrap_or(0);
        out.push(byte | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).unwrap_or(0));
}

/// Read a base-128 varint, advancing `pos`.
///
/// Returns `None` on a truncated or over-long encoding.
fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value: u64 = 0;
    for index in 0..MAX_VARINT_BYTES {
        let byte = *buf.get(*pos)?;
        *pos = pos.checked_add(1)?;
        let shift = u32::try_from(index).ok()?.checked_mul(7)?;
        value |= u64::from(byte & 0x7F).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// Skip a field Praxis does not read, so an upstream that adds one does
/// not break the probe.
fn skip_field(buf: &[u8], pos: &mut usize, wire_type: u64) -> Option<()> {
    match wire_type {
        WIRE_VARINT => {
            let _skipped = read_varint(buf, pos)?;
            Some(())
        },
        WIRE_FIXED64 => advance(pos, 8, buf.len()),
        WIRE_LENGTH_DELIMITED => {
            let length = usize::try_from(read_varint(buf, pos)?).ok()?;
            advance(pos, length, buf.len())
        },
        WIRE_FIXED32 => advance(pos, 4, buf.len()),
        _ => None,
    }
}

/// Advance `pos` by `count`, refusing to run past `limit`.
fn advance(pos: &mut usize, count: usize, limit: usize) -> Option<()> {
    let next = pos.checked_add(count)?;
    if next > limit {
        return None;
    }
    *pos = next;
    Some(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    /// Frame a protobuf message body the way a server would.
    fn frame(body: &[u8]) -> Vec<u8> {
        let mut out = vec![0];
        out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn an_empty_service_encodes_an_empty_message() {
        let encoded = encode_request("");
        assert_eq!(
            encoded.as_ref(),
            &[0, 0, 0, 0, 0],
            "the whole-server probe is an empty message, not an empty string field"
        );
    }

    #[test]
    fn a_named_service_encodes_field_one() {
        let encoded = encode_request("svc");
        assert_eq!(
            encoded.as_ref(),
            &[0, 0, 0, 0, 5, TAG_SERVICE, 3, b's', b'v', b'c'],
            "field 1 should carry the length-delimited service name"
        );
    }

    #[test]
    fn serving_is_decoded() {
        let decoded = decode_serving_status(&frame(&[0x08, 0x01]));
        assert_eq!(
            decoded,
            Some(ServingStatus::Serving),
            "0x08 0x01 (field 1 = 1) is SERVING"
        );
    }

    #[test]
    fn every_known_status_is_decoded() {
        for (value, expected) in [
            (0, ServingStatus::Unknown),
            (1, ServingStatus::Serving),
            (2, ServingStatus::NotServing),
            (3, ServingStatus::ServiceUnknown),
        ] {
            assert_eq!(
                decode_serving_status(&frame(&[0x08, value])),
                Some(expected),
                "status {value} should decode to {expected:?}"
            );
        }
    }

    #[test]
    fn an_empty_message_is_unknown() {
        assert_eq!(
            decode_serving_status(&frame(&[])),
            Some(ServingStatus::Unknown),
            "an absent field is the proto3 default, not a decode error"
        );
    }

    #[test]
    fn a_future_status_value_reads_as_unknown() {
        assert_eq!(
            decode_serving_status(&frame(&[0x08, 0x7F])),
            Some(ServingStatus::Unknown),
            "proto3 enums are open; an unrecognised value must not read as SERVING"
        );
    }

    #[test]
    fn unknown_fields_are_skipped() {
        let decoded = decode_serving_status(&frame(&[0x12, 0x02, b'h', b'i', 0x08, 0x01]));
        assert_eq!(
            decoded,
            Some(ServingStatus::Serving),
            "an unknown field 2 before field 1 = 1 must not break the probe"
        );
    }

    #[test]
    fn compressed_frames_are_rejected() {
        let mut compressed = frame(&[0x08, 0x01]);
        compressed[0] = 1;
        assert_eq!(
            decode_serving_status(&compressed),
            None,
            "Praxis advertises identity encoding, so a compressed frame is unreadable"
        );
    }

    #[test]
    fn truncated_frames_are_rejected() {
        for truncated in [&[][..], &[0][..], &[0, 0, 0][..], &[0, 0, 0, 0, 5, 0x08][..]] {
            assert_eq!(
                decode_serving_status(truncated),
                None,
                "{truncated:?} is truncated and must not decode"
            );
        }
    }

    #[test]
    fn oversized_frames_are_rejected() {
        let mut oversized = vec![0];
        oversized.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            decode_serving_status(&oversized),
            None,
            "a length past the cap must be refused, not allocated"
        );
    }

    #[test]
    fn a_truncated_varint_is_rejected() {
        assert_eq!(
            decode_serving_status(&frame(&[0x08, 0x80])),
            None,
            "0x80 sets a continuation bit with no byte after it, so the varint is unterminated"
        );
    }

    #[test]
    fn varints_round_trip() {
        for value in [0_u64, 1, 127, 128, 300, 16_384, u64::from(u32::MAX)] {
            let mut encoded = Vec::new();
            write_varint(&mut encoded, value);
            let mut pos = 0;
            assert_eq!(
                read_varint(&encoded, &mut pos),
                Some(value),
                "{value} should round-trip through varint coding"
            );
            assert_eq!(pos, encoded.len(), "the reader should consume exactly the encoding");
        }
    }
}
