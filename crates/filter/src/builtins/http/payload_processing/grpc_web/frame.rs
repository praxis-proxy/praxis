// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! gRPC-Web trailer frames and the streaming base64 encoder.

use base64::Engine as _;
use bytes::Bytes;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Flag byte marking an uncompressed trailer frame.
///
/// gRPC-Web reuses the length-prefixed message framing and sets the most
/// significant bit of the flag byte to say "this frame is trailers, not
/// a message".
const TRAILER_FLAG: u8 = 0x80;

/// Header names never forwarded into a trailer frame.
///
/// These describe the HTTP hop, not the gRPC call, and a browser has no
/// use for them.
const SKIPPED_TRAILERS: &[&str] = &["connection", "content-length", "te", "trailer", "transfer-encoding"];

// -----------------------------------------------------------------------------
// Trailer Frames
// -----------------------------------------------------------------------------

/// Encode response trailers as a gRPC-Web trailer frame.
///
/// The payload is HTTP/1.1-style `name: value\r\n` lines with lowercase
/// names, prefixed by the flag byte and a big-endian length.
///
/// ```
/// use praxis_filter::encode_trailer_frame;
///
/// let mut trailers = http::HeaderMap::new();
/// trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
///
/// let frame = encode_trailer_frame(&trailers);
/// assert_eq!(frame[0], 0x80, "the trailer flag bit must be set");
/// assert_eq!(&frame[5..], b"grpc-status: 0\r\n");
/// ```
pub fn encode_trailer_frame(trailers: &http::HeaderMap) -> Bytes {
    let mut payload = Vec::new();
    for (name, value) in trailers {
        let name = name.as_str();
        if SKIPPED_TRAILERS
            .iter()
            .any(|skipped| name.eq_ignore_ascii_case(skipped))
        {
            continue;
        }
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(b": ");
        payload.extend_from_slice(value.as_bytes());
        payload.extend_from_slice(b"\r\n");
    }

    let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut frame = Vec::with_capacity(payload.len().saturating_add(5));
    frame.push(TRAILER_FLAG);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Bytes::from(frame)
}

// -----------------------------------------------------------------------------
// Streaming Base64
// -----------------------------------------------------------------------------

/// Base64 encoder that can be fed a byte stream in arbitrary chunks.
///
/// A naive per-chunk encoder pads every chunk, and padding in the middle
/// of a stream is not decodable. This one emits only whole three-byte
/// groups, carrying the remainder into the next chunk, and pads exactly
/// once at the end.
#[derive(Debug, Default)]
pub(crate) struct Base64Stream {
    /// Bytes left over from the previous chunk (fewer than three).
    pending: Vec<u8>,
}

impl Base64Stream {
    /// Encode a chunk, returning the base64 available so far.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Bytes {
        self.pending.extend_from_slice(chunk);
        let encodable = self.pending.len().saturating_sub(self.pending.len() % 3);
        if encodable == 0 {
            return Bytes::new();
        }
        let tail = self.pending.split_off(encodable);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&self.pending);
        self.pending = tail;
        Bytes::from(encoded)
    }

    /// Flush the final partial group, padding it.
    pub(crate) fn finish(&mut self) -> Bytes {
        if self.pending.is_empty() {
            return Bytes::new();
        }
        let encoded = base64::engine::general_purpose::STANDARD.encode(&self.pending);
        self.pending.clear();
        Bytes::from(encoded)
    }
}

/// Decode a base64 gRPC-Web body.
///
/// # Errors
///
/// Returns the decode error when the body is not valid base64.
pub(crate) fn decode_base64(body: &[u8]) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(body)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    /// Build a trailer map from `(name, value)` pairs.
    fn trailers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for (name, value) in pairs {
            let name: http::HeaderName = (*name).parse().unwrap();
            let _prev = map.insert(name, http::HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn the_trailer_flag_bit_is_set() {
        let frame = encode_trailer_frame(&trailers(&[("grpc-status", "0")]));
        assert_eq!(
            frame[0], 0x80,
            "the MSB is what tells a client this frame is trailers, not a message"
        );
    }

    #[test]
    fn the_length_prefix_is_big_endian() {
        let frame = encode_trailer_frame(&trailers(&[("grpc-status", "0")]));
        let declared = u32::from_be_bytes(frame[1..5].try_into().unwrap());
        assert_eq!(
            usize::try_from(declared).unwrap(),
            frame.len() - 5,
            "the length prefix should describe the payload"
        );
    }

    #[test]
    fn trailers_are_crlf_delimited_with_lowercase_names() {
        let frame = encode_trailer_frame(&trailers(&[("Grpc-Status", "5"), ("grpc-message", "nope")]));
        let payload = String::from_utf8(frame[5..].to_vec()).unwrap();
        assert!(
            payload.contains("grpc-status: 5\r\n"),
            "names must be lowercase: {payload:?}"
        );
        assert!(
            payload.contains("grpc-message: nope\r\n"),
            "every trailer should appear: {payload:?}"
        );
    }

    #[test]
    fn hop_by_hop_trailers_are_dropped() {
        let frame = encode_trailer_frame(&trailers(&[("grpc-status", "0"), ("connection", "close")]));
        let payload = String::from_utf8(frame[5..].to_vec()).unwrap();
        assert!(
            !payload.contains("connection"),
            "hop-by-hop headers describe the HTTP hop, not the call: {payload:?}"
        );
    }

    #[test]
    fn an_empty_trailer_map_still_frames() {
        let frame = encode_trailer_frame(&http::HeaderMap::new());
        assert_eq!(frame.len(), 5, "an empty frame is header-only");
        assert_eq!(
            u32::from_be_bytes(frame[1..5].try_into().unwrap()),
            0,
            "its declared length is zero"
        );
    }

    #[test]
    fn streaming_base64_matches_encoding_the_whole_body() {
        let body: Vec<u8> = (0..=255_u8).collect();
        for chunk_size in [1_usize, 2, 3, 5, 64, 256] {
            let mut encoder = Base64Stream::default();
            let mut out = Vec::new();
            for chunk in body.chunks(chunk_size) {
                out.extend_from_slice(&encoder.push(chunk));
            }
            out.extend_from_slice(&encoder.finish());

            let expected = base64::engine::general_purpose::STANDARD.encode(&body);
            assert_eq!(
                String::from_utf8(out).unwrap(),
                expected,
                "chunking at {chunk_size} bytes must not change the encoding"
            );
        }
    }

    #[test]
    fn streaming_base64_never_pads_mid_stream() {
        let mut encoder = Base64Stream::default();
        let first = encoder.push(b"hello");
        assert!(
            !first.contains(&b'='),
            "padding before the end of the stream would break decoding: {first:?}"
        );
    }

    #[test]
    fn streaming_base64_round_trips() {
        let mut encoder = Base64Stream::default();
        let mut out = Vec::new();
        out.extend_from_slice(&encoder.push(b"grpc-web"));
        out.extend_from_slice(&encoder.push(b" payload"));
        out.extend_from_slice(&encoder.finish());

        assert_eq!(
            decode_base64(&out).unwrap(),
            b"grpc-web payload",
            "the stream should decode back to the original bytes"
        );
    }

    #[test]
    fn an_empty_stream_encodes_to_nothing() {
        let mut encoder = Base64Stream::default();
        assert!(encoder.push(b"").is_empty(), "no input, no output");
        assert!(encoder.finish().is_empty(), "and nothing to flush");
    }

    #[test]
    fn invalid_base64_is_rejected() {
        assert!(decode_base64(b"not base64!!").is_err(), "a bad body should not decode");
    }

    #[test]
    fn boundaries_and_large_fragmented_stream_keep_only_the_carry() {
        for length in [0_usize, 1, 2, 3, 4, 5, 6, 7, 65_535, 65_536, 65_537, 1_048_579] {
            let input: Vec<_> = (0..length).map(|offset| u8::try_from(offset % 251).unwrap()).collect();
            for chunk_size in [1, 2, 3, 4, 7, 4_093] {
                assert_fragmented_carry(&input, chunk_size);
            }
        }
    }

    /// Check each carry and the final encoding for a given fragmentation.
    fn assert_fragmented_carry(input: &[u8], chunk_size: usize) {
        let mut encoder = Base64Stream::default();
        let mut encoded = Vec::new();
        for chunk in input.chunks(chunk_size) {
            let output = encoder.push(chunk);
            assert!(!output.contains(&b'='), "padding belongs only to the final group");
            encoded.extend_from_slice(&output);
            assert!(encoder.pending.len() < 3, "at most two bytes remain between chunks");
            assert!(encoder.pending.capacity() <= 16, "the carry allocation must stay small");
        }
        encoded.extend_from_slice(&encoder.finish());
        assert!(encoder.pending.is_empty(), "finish consumes the carry");
        assert!(encoder.finish().is_empty(), "finish does not emit the carry twice");
        let expected_length = input.len().div_ceil(3) * 4;
        assert_eq!(encoded.len(), expected_length, "encoded length includes final padding");
        assert_eq!(
            decode_base64(&encoded).unwrap(),
            input,
            "fragmentation preserves every byte"
        );
    }

    #[test]
    fn fragmented_message_and_trailers_form_one_padded_stream() {
        let message = b"\0\0\0\0\x04body";
        let frame = encode_trailer_frame(&trailers(&[("grpc-status", "0"), ("grpc-message", "complete")]));
        let mut encoder = Base64Stream::default();
        let mut encoded = Vec::new();
        for chunk in message.chunks(2).chain(frame.chunks(5)) {
            encoded.extend_from_slice(&encoder.push(chunk));
            assert!(encoder.pending.len() < 3);
        }
        encoded.extend_from_slice(&encoder.finish());
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(&decoded[..message.len()], message);
        assert_eq!(&decoded[message.len()..], frame.as_ref());
        assert_eq!(frame[0], TRAILER_FLAG);
        assert_eq!(
            usize::try_from(u32::from_be_bytes(frame[1..5].try_into().unwrap())).unwrap(),
            frame.len() - 5
        );
        assert_eq!(encoded.len(), (message.len() + frame.len()).div_ceil(3) * 4);
    }

    #[test]
    fn invalid_final_quartets_are_not_accepted() {
        for invalid in [
            b"Z".as_slice(),
            b"Zg=".as_slice(),
            b"Zg==A".as_slice(),
            b"Zm9!".as_slice(),
            b"Zm=8".as_slice(),
        ] {
            assert!(decode_base64(invalid).is_err(), "invalid final quartet {invalid:?}");
        }
        assert_eq!(decode_base64(b"Zg==").unwrap(), b"f");
        assert_eq!(decode_base64(b"Zm8=").unwrap(), b"fo");
        assert_eq!(decode_base64(b"Zm9v").unwrap(), b"foo");
    }
}
