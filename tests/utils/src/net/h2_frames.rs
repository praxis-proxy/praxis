// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Minimal HTTP/2 frame writer for exercising server-side resource limits.
//!
//! The `h2` client always emits well-formed frame sequences, so a test that
//! needs to push a server past one of its frame, stream, reset or header
//! limits has to write the frames itself. This module writes just enough of
//! the wire format (RFC 9113) for those tests: the connection preface, a
//! handful of frame types, and HPACK header blocks encoded as literals without
//! indexing (RFC 7541 §6.2.2), which need no dynamic-table state on either
//! side. It is deliberately not a general HTTP/2 implementation.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

// -----------------------------------------------------------------------------
// Wire constants
// -----------------------------------------------------------------------------

/// The 24-byte client connection preface (RFC 9113 §3.4).
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// HTTP/2 frame type codes (RFC 9113 §6).
pub mod frame_type {
    /// DATA frame.
    pub const DATA: u8 = 0x0;
    /// HEADERS frame.
    pub const HEADERS: u8 = 0x1;
    /// `RST_STREAM` frame.
    pub const RST_STREAM: u8 = 0x3;
    /// SETTINGS frame.
    pub const SETTINGS: u8 = 0x4;
    /// PING frame.
    pub const PING: u8 = 0x6;
    /// GOAWAY frame.
    pub const GOAWAY: u8 = 0x7;
    /// `WINDOW_UPDATE` frame.
    pub const WINDOW_UPDATE: u8 = 0x8;
    /// CONTINUATION frame.
    pub const CONTINUATION: u8 = 0x9;
}

/// `END_STREAM` flag on DATA and HEADERS frames.
pub const END_STREAM: u8 = 0x1;
/// `ACK` flag on SETTINGS and PING frames.
pub const ACK: u8 = 0x1;
/// `END_HEADERS` flag on HEADERS and CONTINUATION frames.
pub const END_HEADERS: u8 = 0x4;

/// RFC 9113 error code `FLOW_CONTROL_ERROR`.
pub const FLOW_CONTROL_ERROR: u32 = 0x3;
/// RFC 9113 error code `REFUSED_STREAM`.
pub const REFUSED_STREAM: u32 = 0x7;
/// RFC 9113 error code `ENHANCE_YOUR_CALM`.
pub const ENHANCE_YOUR_CALM: u32 = 0xB;

/// How long a frame read waits before it is treated as "nothing more coming".
const READ_TIMEOUT: Duration = Duration::from_secs(2);

// -----------------------------------------------------------------------------
// A frame read back from the server
// -----------------------------------------------------------------------------

/// One frame read from the server: its type, flags, stream id and payload.
#[derive(Clone, Debug)]
pub struct RawFrame {
    /// Frame type code (see [`frame_type`]).
    pub ftype: u8,
    /// Frame flags byte.
    pub flags: u8,
    /// Stream identifier (0 for connection-level frames).
    pub stream_id: u32,
    /// Raw frame payload.
    pub payload: Vec<u8>,
}

impl RawFrame {
    /// The 32-bit error code carried by a `RST_STREAM` or `GOAWAY` frame.
    ///
    /// For GOAWAY the code sits after the 4-byte last-stream-id; for
    /// `RST_STREAM` it is the whole payload. Returns `None` for any other
    /// frame or a short payload.
    #[must_use]
    pub fn error_code(&self) -> Option<u32> {
        let bytes = match self.ftype {
            frame_type::RST_STREAM => self.payload.get(0..4),
            frame_type::GOAWAY => self.payload.get(4..8),
            _ => None,
        }?;
        Some(u32::from_be_bytes(bytes.try_into().ok()?))
    }
}

// -----------------------------------------------------------------------------
// Connection
// -----------------------------------------------------------------------------

/// A raw HTTP/2 (h2c, prior-knowledge) connection over cleartext TCP.
pub struct H2TestConnection {
    /// Underlying socket, with a read timeout set so reads do not block forever.
    stream: TcpStream,
}

impl H2TestConnection {
    /// Connect to `addr`, send the preface and an empty SETTINGS frame.
    ///
    /// The server's own SETTINGS and its ACK are left in the socket for the
    /// caller to read (or ignore) through [`Self::next_frame`].
    #[must_use]
    pub fn connect(addr: &str) -> Self {
        Self::connect_with_settings(addr, &[])
    }

    /// Connect as [`Self::connect`] but advertise `settings` (id, value pairs)
    /// in the client SETTINGS frame, e.g. a zero `INITIAL_WINDOW_SIZE`.
    ///
    /// # Panics
    ///
    /// Panics if the connection or the initial writes fail.
    #[must_use]
    pub fn connect_with_settings(addr: &str, settings: &[(u16, u32)]) -> Self {
        let stream = TcpStream::connect(addr).expect("connect to proxy");
        stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(READ_TIMEOUT)).unwrap();
        let mut conn = Self { stream };
        conn.stream.write_all(PREFACE).unwrap();
        let mut payload = Vec::new();
        for &(id, value) in settings {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&value.to_be_bytes());
        }
        conn.send_frame(frame_type::SETTINGS, 0, 0, &payload);
        conn
    }

    /// Write one frame: a 9-byte header (RFC 9113 §4.1) followed by `payload`.
    pub fn send_frame(&mut self, ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) {
        self.send_raw(&frame_bytes(ftype, flags, stream_id, payload));
    }

    /// Write pre-built bytes straight to the socket in a single call, so a
    /// burst of frames reaches the server together rather than interleaved
    /// with its own processing.
    ///
    /// # Panics
    ///
    /// Panics if the write fails.
    pub fn send_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).unwrap();
    }

    /// Send a complete request HEADERS block (the four pseudo-headers for a
    /// GET of `/` on `localhost`, plus `extra`), ending the stream when
    /// `end_stream`.
    pub fn send_request(&mut self, stream_id: u32, extra: &[(&str, &str)], end_stream: bool) {
        let flags = END_HEADERS | if end_stream { END_STREAM } else { 0 };
        self.send_frame(
            frame_type::HEADERS,
            flags,
            stream_id,
            &request_block("/", "localhost", extra),
        );
    }

    /// Acknowledge the server's SETTINGS frame.
    pub fn send_settings_ack(&mut self) {
        self.send_frame(frame_type::SETTINGS, ACK, 0, &[]);
    }

    /// Send a HEADERS frame carrying `headers` HPACK-encoded as literals
    /// without indexing. The block must fit one frame (≤ 16 KiB here).
    pub fn send_headers(&mut self, stream_id: u32, headers: &[(&str, &str)], end_stream: bool) {
        let flags = END_HEADERS | if end_stream { END_STREAM } else { 0 };
        self.send_frame(frame_type::HEADERS, flags, stream_id, &encode_headers(headers));
    }

    /// Send a HEADERS frame without `END_HEADERS`, so `CONTINUATION` frames follow.
    pub fn send_headers_unterminated(&mut self, stream_id: u32, block: &[u8]) {
        self.send_frame(frame_type::HEADERS, 0, stream_id, block);
    }

    /// Send a CONTINUATION frame, optionally ending the header block.
    pub fn send_continuation(&mut self, stream_id: u32, block: &[u8], end_headers: bool) {
        let flags = if end_headers { END_HEADERS } else { 0 };
        self.send_frame(frame_type::CONTINUATION, flags, stream_id, block);
    }

    /// Send a `RST_STREAM` frame with error `code`.
    pub fn send_rst_stream(&mut self, stream_id: u32, code: u32) {
        self.send_frame(frame_type::RST_STREAM, 0, stream_id, &code.to_be_bytes());
    }

    /// Send a DATA frame with `payload` (empty for a zero-length frame).
    pub fn send_data(&mut self, stream_id: u32, payload: &[u8], end_stream: bool) {
        let flags = if end_stream { END_STREAM } else { 0 };
        self.send_frame(frame_type::DATA, flags, stream_id, payload);
    }

    /// Send a (non-ACK) PING frame with an 8-byte opaque payload.
    pub fn send_ping(&mut self, payload: [u8; 8]) {
        self.send_frame(frame_type::PING, 0, 0, &payload);
    }

    /// Send a `WINDOW_UPDATE` frame adding `increment` to `stream_id`'s window
    /// (stream 0 is the connection window).
    pub fn send_window_update(&mut self, stream_id: u32, increment: u32) {
        self.send_frame(frame_type::WINDOW_UPDATE, 0, stream_id, &increment.to_be_bytes());
    }

    /// Read the next frame, or `None` on EOF or read timeout.
    ///
    /// # Panics
    ///
    /// Panics if a frame's declared length does not fit a `usize`.
    pub fn next_frame(&mut self) -> Option<RawFrame> {
        let mut header = [0_u8; 9];
        self.stream.read_exact(&mut header).ok()?;
        let len = usize::try_from(u32::from_be_bytes([0, header[0], header[1], header[2]])).unwrap();
        let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7FFF_FFFF;
        let mut payload = vec![0_u8; len];
        self.stream.read_exact(&mut payload).ok()?;
        Some(RawFrame {
            ftype: header[3],
            flags: header[4],
            stream_id,
            payload,
        })
    }

    /// Read frames until one satisfies `want`, returning it, or `None` if the
    /// connection closes or goes quiet (read timeout) first.
    pub fn read_until<F: FnMut(&RawFrame) -> bool>(&mut self, mut want: F) -> Option<RawFrame> {
        while let Some(frame) = self.next_frame() {
            if want(&frame) {
                return Some(frame);
            }
        }
        None
    }

    /// Read until a GOAWAY frame arrives, returning its error code, or `None`
    /// if the connection goes quiet or closes without one.
    pub fn wait_for_goaway(&mut self) -> Option<u32> {
        self.read_until(|frame| frame.ftype == frame_type::GOAWAY)
            .and_then(|frame| frame.error_code())
    }
}

// -----------------------------------------------------------------------------
// HPACK (literals without indexing only)
// -----------------------------------------------------------------------------

/// Build one frame's bytes: the 9-byte header (RFC 9113 §4.1) and `payload`.
///
/// # Panics
///
/// Panics if `payload` is longer than a frame's 24-bit length field allows.
#[must_use]
pub fn frame_bytes(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame payload fits in 24 bits");
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&len.to_be_bytes()[1..4]);
    out.push(ftype);
    out.push(flags);
    out.extend_from_slice(&(stream_id & 0x7FFF_FFFF).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// HPACK-encode `headers` as literal header fields without indexing, each with
/// a new name (RFC 7541 §6.2.2): a `0x00` prefix byte, then the name and value
/// as length-prefixed strings. This never touches the dynamic table, so the
/// encoded size tracks the decoded header-list size closely.
#[must_use]
pub fn encode_headers(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(name, value) in headers {
        out.push(0x00);
        encode_string(&mut out, name.as_bytes());
        encode_string(&mut out, value.as_bytes());
    }
    out
}

/// A minimal request header block: the four pseudo-headers a server needs,
/// plus `extra` fields. Encoded as literals without indexing.
#[must_use]
pub fn request_block(path: &str, authority: &str, extra: &[(&str, &str)]) -> Vec<u8> {
    let mut headers = vec![
        (":method", "GET"),
        (":path", path),
        (":scheme", "http"),
        (":authority", authority),
    ];
    headers.extend_from_slice(extra);
    encode_headers(&headers)
}

/// Append an HPACK string: a 7-bit-prefix length (no Huffman) then the bytes.
fn encode_string(out: &mut Vec<u8>, bytes: &[u8]) {
    encode_integer(out, bytes.len(), 7, 0);
    out.extend_from_slice(bytes);
}

/// Append an HPACK integer with an `prefix_bits`-bit prefix (RFC 7541 §5.1),
/// OR-ing `flags` into the high bits of the first byte.
fn encode_integer(out: &mut Vec<u8>, value: usize, prefix_bits: u32, flags: u8) {
    let max_prefix = (1_usize << prefix_bits) - 1;
    if value < max_prefix {
        out.push(flags | u8::try_from(value).unwrap());
        return;
    }
    out.push(flags | u8::try_from(max_prefix).unwrap());
    let mut rest = value - max_prefix;
    while rest >= 128 {
        out.push(u8::try_from(rest % 128).unwrap() | 0x80);
        rest /= 128;
    }
    out.push(u8::try_from(rest).unwrap());
}
