// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Zero-copy `ClientHello` SNI parser for TLS 1.0-1.3.
//!
//! Extracts the Server Name Indication (SNI) hostname from the
//! beginning of a TLS `ClientHello` message without performing a
//! full TLS handshake. Used by the TCP proxy to populate
//! [`TcpFilterContext::sni`] before running filters.
//!
//! # Wire Format
//!
//! ```text
//! TLS Record:      ContentType(1) | Version(2) | Length(2) | Fragment
//! Handshake:       HandshakeType(1) | Length(3) | ClientHello
//! ClientHello:     Version(2) | Random(32) | SessionID(var) | CipherSuites(var) | CompressionMethods(var) | Extensions(var)
//! Extension:       Type(2) | Length(2) | Data
//! SNI Extension:   ListLength(2) | NameType(1) | NameLength(2) | HostName
//! ```
//!
//! # Example
//!
//! ```
//! use praxis_tls::sni::{SniParseError, parse_sni};
//!
//! let err = parse_sni(b"GET / HTTP/1.1");
//! assert!(matches!(err, Err(SniParseError::NotHandshake)));
//! ```
//!
//! [`TcpFilterContext::sni`]: https://docs.rs/praxis-filter

use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// TLS `ContentType` for Handshake records.
const CONTENT_TYPE_HANDSHAKE: u8 = 22;

/// TLS `HandshakeType` for `ClientHello`.
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

/// TLS extension type for Server Name Indication ([RFC 6066]).
///
/// [RFC 6066]: https://datatracker.ietf.org/doc/html/rfc6066
const EXTENSION_TYPE_SNI: u16 = 0;

/// SNI `NameType` for DNS hostnames.
const SNI_NAME_TYPE_HOST: u8 = 0;

/// Minimum TLS record header length: `ContentType`(1) + Version(2) + Length(2).
const TLS_RECORD_HEADER_LEN: usize = 5;

/// Size of the TLS handshake header: Type(1) + Length(3).
const HANDSHAKE_HEADER_LEN: usize = 4;

/// Size of the `ClientHello` fixed fields before `SessionID`:
/// Version(2) + Random(32).
const CLIENT_HELLO_FIXED_LEN: usize = 34;

// -----------------------------------------------------------------------------
// ClientHelloInfo
// -----------------------------------------------------------------------------

/// Information extracted from a TLS `ClientHello` message.
///
/// ```
/// use praxis_tls::sni::ClientHelloInfo;
///
/// let info = ClientHelloInfo {
///     sni: Some("example.com".to_owned()),
/// };
/// assert_eq!(info.sni.as_deref(), Some("example.com"));
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloInfo {
    /// The SNI hostname, if present in the `ClientHello`.
    pub sni: Option<String>,
}

// -----------------------------------------------------------------------------
// SniParseError
// -----------------------------------------------------------------------------

/// Errors from parsing TLS `ClientHello` SNI.
///
/// ```
/// use praxis_tls::sni::SniParseError;
///
/// let e = SniParseError::TooShort;
/// assert!(e.to_string().contains("too short"));
/// ```
#[derive(Debug, Eq, Error, PartialEq)]
pub enum SniParseError {
    /// The buffer is too short to contain a valid TLS record header.
    #[error("buffer too short for TLS record header")]
    TooShort,

    /// The record's content type is not Handshake (22).
    #[error("not a TLS handshake record")]
    NotHandshake,

    /// The handshake message type is not `ClientHello` (1).
    #[error("handshake message is not a ClientHello")]
    NotClientHello,

    /// The record declares more data than the buffer contains.
    #[error("need more data to parse complete ClientHello")]
    NeedMoreData,

    /// An extension or sub-field is malformed.
    #[error("malformed TLS extension")]
    MalformedExtension,

    /// The SNI hostname is empty ([RFC 6066] requires a valid DNS name).
    ///
    /// [RFC 6066]: https://datatracker.ietf.org/doc/html/rfc6066
    #[error("SNI hostname must not be empty (RFC 6066)")]
    EmptyHostname,

    /// The SNI hostname is an IP literal (rejected per [RFC 6066 Section 3]).
    ///
    /// [RFC 6066 Section 3]: https://datatracker.ietf.org/doc/html/rfc6066#section-3
    #[error("SNI must not be an IP address (RFC 6066)")]
    InvalidHostname,
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Parse the SNI hostname from a TLS `ClientHello` in `buf`.
///
/// Returns [`ClientHelloInfo`] with `sni: None` when the
/// `ClientHello` is valid but contains no SNI extension.
///
/// # Errors
///
/// Returns [`SniParseError`] when the buffer is incomplete,
/// not a TLS handshake, or contains a malformed `ClientHello`.
///
/// # Example
///
/// ```
/// use praxis_tls::sni::{SniParseError, parse_sni};
///
/// assert!(matches!(parse_sni(&[]), Err(SniParseError::TooShort)));
/// assert!(matches!(parse_sni(b"HTTP"), Err(SniParseError::TooShort)));
/// ```
pub fn parse_sni(buf: &[u8]) -> Result<ClientHelloInfo, SniParseError> {
    // Fast path: the whole ClientHello lives in the first TLS record. This is
    // the overwhelmingly common case and stays zero-copy.
    let fragment = parse_record_header(buf)?;
    match parse_handshake_header(fragment) {
        Ok(hello_body) => parse_client_hello(hello_body),
        // A ClientHello may be fragmented across several handshake records
        // (RFC 8446 §5.1) — e.g. a large ClientHello carrying post-quantum key
        // shares. The first record alone is then incomplete; reassemble the
        // handshake bytes across consecutive records before parsing.
        Err(SniParseError::NeedMoreData) => {
            let hello_body = reassemble_handshake(buf)?;
            parse_client_hello(&hello_body)
        },
        Err(e) => Err(e),
    }
}

/// Reassemble a `ClientHello` handshake message fragmented across consecutive
/// TLS handshake records, returning the handshake body (after the 4-byte
/// handshake header).
///
/// Only handshake-content-type (22) records are concatenated; the first
/// non-handshake record ends reassembly. The output is bounded by `buf`, which
/// the caller caps (the TCP proxy limits its SNI peek buffer), so this cannot
/// allocate unboundedly.
fn reassemble_handshake(buf: &[u8]) -> Result<Vec<u8>, SniParseError> {
    // The 4-byte handshake header accumulates in a stack array so the body
    // can be returned as-is, without the front-drain memmove of up to the
    // whole peek buffer the old single-Vec shape paid. The body Vec is
    // sized once from the caller-capped peek buffer instead of growing by
    // doubling; this path is attacker-triggerable per read on a fragmented
    // hello, so its per-invocation cost matters.
    let mut header = [0_u8; HANDSHAKE_HEADER_LEN];
    let mut header_filled = 0_usize;
    let mut body: Vec<u8> = Vec::with_capacity(buf.len().saturating_sub(TLS_RECORD_HEADER_LEN));
    let mut pos = 0;

    loop {
        let (mut fragment, next_pos) = handshake_record_fragment(buf, pos)?;

        if header_filled < HANDSHAKE_HEADER_LEN {
            (fragment, header_filled) = fill_handshake_header(&mut header, header_filled, fragment);
        }
        body.extend_from_slice(fragment);

        // Once the 4-byte handshake header is complete, we know the total
        // ClientHello length and can stop as soon as enough bytes are gathered.
        if header_filled == HANDSHAKE_HEADER_LEN {
            if *header.first().ok_or(SniParseError::NeedMoreData)? != HANDSHAKE_TYPE_CLIENT_HELLO {
                return Err(SniParseError::NotClientHello);
            }
            let hs_len = read_u24(&header, 1)? as usize;
            if body.len() >= hs_len {
                body.truncate(hs_len);
                return Ok(body);
            }
        }

        pos = next_pos;
    }
}

/// Resumable reassembly of a `ClientHello` fragmented across TLS
/// records, fed in monotonically growing peek buffers.
///
/// [`parse_sni`] is stateless: a caller polling a socket re-parses —
/// and, on the fragmented path, re-reassembles — the entire buffer on
/// every read, which an attacker trickling a fragmented hello in tiny
/// segments turns into quadratic work (up to ~134 MB of memcpy against
/// a 16 KiB peek cap). This form scans each buffered byte once:
/// [`advance`] walks only the records that completed since the previous
/// call, accumulating the handshake header and body exactly like the
/// stateless reassembly and classifying errors identically.
///
/// The caller feeds the same buffer, grown; once [`advance`] returns
/// a terminal result (`Ok(Some(_))` or `Err(_)`) it must not be called
/// again.
///
/// [`advance`]: Self::advance
pub struct SniReassembler {
    /// Offset of the first unconsumed record-header byte.
    pos: usize,
    /// Handshake-header accumulator (may span records).
    header: [u8; HANDSHAKE_HEADER_LEN],
    /// Filled bytes of `header`.
    header_filled: usize,
    /// Handshake body accumulated so far.
    body: Vec<u8>,
}

impl SniReassembler {
    /// Create an empty reassembler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pos: 0,
            header: [0_u8; HANDSHAKE_HEADER_LEN],
            header_filled: 0,
            body: Vec::new(),
        }
    }

    /// Consume any records that completed since the previous call.
    ///
    /// Returns `Ok(None)` when more bytes are needed, `Ok(Some(info))`
    /// on a fully reassembled and parsed `ClientHello`.
    ///
    /// # Errors
    ///
    /// Returns [`SniParseError`] exactly as the stateless
    /// [`parse_sni`] path would on the same grown buffer: a
    /// non-handshake record ends reassembly, a non-`ClientHello`
    /// handshake type is rejected, and `ClientHello` body errors come
    /// from the shared body parser.
    pub fn advance(&mut self, buf: &[u8]) -> Result<Option<ClientHelloInfo>, SniParseError> {
        loop {
            let (mut fragment, next_pos) = match handshake_record_fragment(buf, self.pos) {
                Ok(parts) => parts,
                Err(SniParseError::NeedMoreData | SniParseError::TooShort) => return Ok(None),
                Err(e) => return Err(e),
            };
            self.pos = next_pos;

            if self.header_filled < HANDSHAKE_HEADER_LEN {
                (fragment, self.header_filled) = fill_handshake_header(&mut self.header, self.header_filled, fragment);
            }
            self.body.extend_from_slice(fragment);

            if self.header_filled == HANDSHAKE_HEADER_LEN {
                if *self.header.first().ok_or(SniParseError::NeedMoreData)? != HANDSHAKE_TYPE_CLIENT_HELLO {
                    return Err(SniParseError::NotClientHello);
                }
                let hs_len = read_u24(&self.header, 1)? as usize;
                if self.body.len() >= hs_len {
                    self.body.truncate(hs_len);
                    let body = std::mem::take(&mut self.body);
                    return parse_client_hello(&body).map(Some);
                }
                // Size the accumulator from the claimed total, clamped
                // to what the current buffer can still supply. The u24
                // length is attacker-chosen (up to 16 MiB), while the
                // caller's peek cap bounds real data to a few KiB: a
                // 9-byte record must not drive a 16 MiB reservation.
                self.body
                    .reserve((hs_len - self.body.len()).min(buf.len().saturating_sub(self.pos)));
            }
        }
    }
}

impl Default for SniReassembler {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse the TLS record header at `pos` and return the record's handshake
/// fragment plus the offset of the next record.
fn handshake_record_fragment(buf: &[u8], pos: usize) -> Result<(&[u8], usize), SniParseError> {
    let record_header = buf
        .get(pos..pos + TLS_RECORD_HEADER_LEN)
        .ok_or(SniParseError::NeedMoreData)?;
    if *record_header.first().ok_or(SniParseError::NeedMoreData)? != CONTENT_TYPE_HANDSHAKE {
        return Err(SniParseError::NotHandshake);
    }
    let record_len = read_u16(record_header, 3)? as usize;
    let frag_start = pos + TLS_RECORD_HEADER_LEN;
    let fragment = buf
        .get(frag_start..frag_start + record_len)
        .ok_or(SniParseError::NeedMoreData)?;
    Ok((fragment, frag_start + record_len))
}

/// Copy up to the remaining handshake-header bytes from the front of
/// `fragment` into `header`, returning the body remainder and the new
/// fill count.
fn fill_handshake_header<'frag>(
    header: &mut [u8; HANDSHAKE_HEADER_LEN],
    filled: usize,
    fragment: &'frag [u8],
) -> (&'frag [u8], usize) {
    let take = fragment.len().min(HANDSHAKE_HEADER_LEN - filled);
    let (head, rest) = fragment.split_at(take);
    for (dst, src) in header.iter_mut().skip(filled).zip(head) {
        *dst = *src;
    }
    (rest, filled + take)
}

// -----------------------------------------------------------------------------
// Record Layer
// -----------------------------------------------------------------------------

/// Parse the TLS record header, returning the fragment payload.
fn parse_record_header(buf: &[u8]) -> Result<&[u8], SniParseError> {
    if buf.len() < TLS_RECORD_HEADER_LEN {
        return Err(SniParseError::TooShort);
    }

    if *buf.first().ok_or(SniParseError::TooShort)? != CONTENT_TYPE_HANDSHAKE {
        return Err(SniParseError::NotHandshake);
    }

    let record_len = read_u16(buf, 3)? as usize;
    let total = TLS_RECORD_HEADER_LEN + record_len;

    buf.get(TLS_RECORD_HEADER_LEN..total).ok_or(SniParseError::NeedMoreData)
}

/// Parse the handshake message header, returning the `ClientHello` body.
fn parse_handshake_header(fragment: &[u8]) -> Result<&[u8], SniParseError> {
    if fragment.len() < HANDSHAKE_HEADER_LEN {
        return Err(SniParseError::NeedMoreData);
    }

    if *fragment.first().ok_or(SniParseError::NeedMoreData)? != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(SniParseError::NotClientHello);
    }

    let hs_len = read_u24(fragment, 1)? as usize;
    let end = HANDSHAKE_HEADER_LEN + hs_len;

    fragment
        .get(HANDSHAKE_HEADER_LEN..end)
        .ok_or(SniParseError::NeedMoreData)
}

// -----------------------------------------------------------------------------
// ClientHello Parsing Utilities
// -----------------------------------------------------------------------------

/// Parse a `ClientHello` body and extract the SNI hostname.
fn parse_client_hello(data: &[u8]) -> Result<ClientHelloInfo, SniParseError> {
    if data.len() < CLIENT_HELLO_FIXED_LEN {
        return Err(SniParseError::MalformedExtension);
    }

    let mut pos = CLIENT_HELLO_FIXED_LEN;

    pos = skip_variable_u8(data, pos)?;
    pos = skip_variable_u16(data, pos)?;
    pos = skip_variable_u8(data, pos)?;

    if pos >= data.len() {
        return Ok(ClientHelloInfo { sni: None });
    }

    let extensions = read_variable_u16(data, pos)?;
    parse_extensions(extensions)
}

/// Skip a variable-length field preceded by a 1-byte length.
fn skip_variable_u8(data: &[u8], pos: usize) -> Result<usize, SniParseError> {
    let len_byte = *data.get(pos).ok_or(SniParseError::MalformedExtension)?;
    let len = len_byte as usize;
    let end = pos + 1 + len;
    if end > data.len() {
        return Err(SniParseError::MalformedExtension);
    }
    Ok(end)
}

/// Skip a variable-length field preceded by a 2-byte length.
fn skip_variable_u16(data: &[u8], pos: usize) -> Result<usize, SniParseError> {
    let len = read_u16(data, pos)? as usize;
    let end = pos + 2 + len;
    if end > data.len() {
        return Err(SniParseError::MalformedExtension);
    }
    Ok(end)
}

/// Read a variable-length sub-slice preceded by a 2-byte length.
fn read_variable_u16(data: &[u8], pos: usize) -> Result<&[u8], SniParseError> {
    let len = read_u16(data, pos)? as usize;
    let start = pos + 2;
    let end = start + len;
    if end > data.len() {
        return Err(SniParseError::MalformedExtension);
    }
    data.get(start..end).ok_or(SniParseError::MalformedExtension)
}

// -----------------------------------------------------------------------------
// SNI Extension Parsing Utilities
// -----------------------------------------------------------------------------

/// Walk extensions looking for the SNI extension (type 0).
fn parse_extensions(mut ext: &[u8]) -> Result<ClientHelloInfo, SniParseError> {
    while ext.len() >= 4 {
        let ext_type = read_u16(ext, 0)?;
        let ext_len = read_u16(ext, 2)? as usize;

        if ext.len() < 4 + ext_len {
            return Err(SniParseError::MalformedExtension);
        }

        let ext_data = ext.get(4..4 + ext_len).ok_or(SniParseError::MalformedExtension)?;

        if ext_type == EXTENSION_TYPE_SNI {
            return parse_sni_extension(ext_data);
        }

        ext = ext.get(4 + ext_len..).ok_or(SniParseError::MalformedExtension)?;
    }

    Ok(ClientHelloInfo { sni: None })
}

/// Parse the SNI extension payload and extract the hostname.
fn parse_sni_extension(data: &[u8]) -> Result<ClientHelloInfo, SniParseError> {
    let list_len = read_u16(data, 0)? as usize;
    if data.len() < 2 + list_len {
        return Err(SniParseError::MalformedExtension);
    }

    let mut list = data.get(2..2 + list_len).ok_or(SniParseError::MalformedExtension)?;

    let mut hostname: Option<String> = None;

    while list.len() >= 3 {
        let name_type = *list.first().ok_or(SniParseError::MalformedExtension)?;
        let name_len = read_u16(list, 1)? as usize;

        if list.len() < 3 + name_len {
            return Err(SniParseError::MalformedExtension);
        }

        if name_type == SNI_NAME_TYPE_HOST {
            // RFC 6066 §3: a ServerNameList MUST NOT contain more than one name
            // of the same name_type. Reject a second host_name rather than
            // silently taking the first — a duplicate could disagree with a
            // downstream parser's choice and mislead SNI-based routing.
            if hostname.is_some() {
                return Err(SniParseError::MalformedExtension);
            }

            let name_bytes = list.get(3..3 + name_len).ok_or(SniParseError::MalformedExtension)?;

            if name_bytes.is_empty() {
                return Err(SniParseError::EmptyHostname);
            }

            let name = std::str::from_utf8(name_bytes).map_err(|_utf8| SniParseError::InvalidHostname)?;

            reject_ip_literal(name)?;
            crate::dns::validate_dns_hostname(name).map_err(|_dns| SniParseError::InvalidHostname)?;

            hostname = Some(name.to_owned());
        }

        list = list.get(3 + name_len..).ok_or(SniParseError::MalformedExtension)?;
    }

    Ok(ClientHelloInfo { sni: hostname })
}

// -----------------------------------------------------------------------------
// Binary Utilities
// -----------------------------------------------------------------------------

/// Read a big-endian `u16` from `data` at `offset`.
fn read_u16(data: &[u8], offset: usize) -> Result<u16, SniParseError> {
    let a = *data.get(offset).ok_or(SniParseError::MalformedExtension)?;
    let b = *data.get(offset + 1).ok_or(SniParseError::MalformedExtension)?;
    Ok(u16::from_be_bytes([a, b]))
}

/// Read a big-endian 24-bit integer as `u32` from `data` at `offset`.
fn read_u24(data: &[u8], offset: usize) -> Result<u32, SniParseError> {
    let a = *data.get(offset).ok_or(SniParseError::MalformedExtension)?;
    let b = *data.get(offset + 1).ok_or(SniParseError::MalformedExtension)?;
    let c = *data.get(offset + 2).ok_or(SniParseError::MalformedExtension)?;
    Ok(u32::from_be_bytes([0, a, b, c]))
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Reject IP address literals per [RFC 6066 Section 3].
///
/// [RFC 6066 Section 3]: https://datatracker.ietf.org/doc/html/rfc6066#section-3
fn reject_ip_literal(hostname: &str) -> Result<(), SniParseError> {
    if hostname.parse::<std::net::IpAddr>().is_ok() {
        return Err(SniParseError::InvalidHostname);
    }

    // The IpAddr parse above already tried the unbracketed IPv6 form;
    // a second parse is only needed when brackets were actually stripped.
    if let Some(trimmed) = hostname.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        && trimmed.parse::<std::net::Ipv6Addr>().is_ok()
    {
        return Err(SniParseError::InvalidHostname);
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn empty_buffer_returns_too_short() {
        assert_eq!(
            parse_sni(&[]),
            Err(SniParseError::TooShort),
            "empty buffer should be too short"
        );
    }

    #[test]
    fn short_buffer_returns_too_short() {
        assert_eq!(
            parse_sni(&[22, 3, 3]),
            Err(SniParseError::TooShort),
            "3-byte buffer should be too short"
        );
    }

    #[test]
    fn non_handshake_content_type() {
        assert_eq!(
            parse_sni(&[23, 3, 3, 0, 1, 0]),
            Err(SniParseError::NotHandshake),
            "content type 23 (application data) should be rejected"
        );
    }

    #[test]
    fn http_request_rejected() {
        assert_eq!(
            parse_sni(b"GET / HTTP/1.1\r\n"),
            Err(SniParseError::NotHandshake),
            "HTTP request should not parse as TLS"
        );
    }

    #[test]
    fn truncated_record_returns_need_more_data() {
        let buf = [22, 3, 3, 0, 100, 1];
        assert_eq!(
            parse_sni(&buf),
            Err(SniParseError::NeedMoreData),
            "record declares 100 bytes but buffer is shorter"
        );
    }

    #[test]
    fn non_client_hello_handshake() {
        let mut buf = vec![22, 3, 3, 0, 4];
        buf.push(2);
        buf.extend_from_slice(&[0, 0, 0]);
        assert_eq!(
            parse_sni(&buf),
            Err(SniParseError::NotClientHello),
            "handshake type 2 (ServerHello) should be rejected"
        );
    }

    #[test]
    fn fragmented_non_client_hello_rejected() {
        // Handshake type 2 (ServerHello) with its 4-byte header split across
        // two TLS records: the fast path sees an incomplete header and defers
        // to reassembly, which must still reject the wrong handshake type.
        let mut buf = vec![22, 3, 3, 0, 2, 2, 0];
        buf.extend_from_slice(&[22, 3, 3, 0, 2, 0, 0]);
        assert_eq!(
            parse_sni(&buf),
            Err(SniParseError::NotClientHello),
            "a fragmented non-ClientHello handshake should be rejected"
        );
    }

    #[test]
    fn minimal_client_hello_no_sni() {
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &[]);
        let record = wrap_in_record(&hello);
        let result = parse_sni(&record).expect("valid ClientHello without SNI should parse");
        assert_eq!(result.sni, None, "no SNI extension should yield None");
    }

    #[test]
    fn client_hello_with_sni() {
        let sni_ext = build_sni_extension("example.com");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &sni_ext);
        let record = wrap_in_record(&hello);

        let result = parse_sni(&record).expect("valid ClientHello with SNI should parse");
        assert_eq!(result.sni.as_deref(), Some("example.com"), "SNI should be extracted");
    }

    #[test]
    fn client_hello_with_multiple_extensions() {
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&build_dummy_extension(0x0017, &[1, 2, 3]));
        extensions.extend_from_slice(&build_sni_extension("api.example.com"));
        extensions.extend_from_slice(&build_dummy_extension(0x000D, &[4, 5]));

        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &extensions);
        let record = wrap_in_record(&hello);

        let result = parse_sni(&record).expect("SNI should be found among multiple extensions");
        assert_eq!(result.sni.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn ip_address_sni_rejected() {
        let sni_ext = build_sni_extension("192.168.1.1");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &sni_ext);
        let record = wrap_in_record(&hello);

        assert_eq!(
            parse_sni(&record),
            Err(SniParseError::InvalidHostname),
            "IPv4 literal SNI should be rejected per RFC 6066"
        );
    }

    #[test]
    fn ipv6_address_sni_rejected() {
        let sni_ext = build_sni_extension("::1");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &sni_ext);
        let record = wrap_in_record(&hello);

        assert_eq!(
            parse_sni(&record),
            Err(SniParseError::InvalidHostname),
            "IPv6 literal SNI should be rejected per RFC 6066"
        );
    }

    #[test]
    fn bracketed_ipv6_sni_rejected() {
        let sni_ext = build_sni_extension("[::1]");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &sni_ext);
        let record = wrap_in_record(&hello);

        assert_eq!(
            parse_sni(&record),
            Err(SniParseError::InvalidHostname),
            "bracketed IPv6 literal SNI should be rejected"
        );
    }

    #[test]
    fn client_hello_info_equality() {
        let a = ClientHelloInfo {
            sni: Some("a.com".to_owned()),
        };
        let b = ClientHelloInfo {
            sni: Some("a.com".to_owned()),
        };
        let c = ClientHelloInfo { sni: None };

        assert_eq!(a, b, "identical SNI should be equal");
        assert_ne!(a, c, "different SNI should not be equal");
    }

    /// RFC 6066 section 3: SNI hostname must not be empty.
    #[test]
    fn empty_hostname_rejected() {
        let sni_ext = build_sni_extension("");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &sni_ext);
        let record = wrap_in_record(&hello);

        assert_eq!(
            parse_sni(&record),
            Err(SniParseError::EmptyHostname),
            "zero-length SNI hostname should be rejected per RFC 6066"
        );
    }

    #[test]
    fn error_display_messages() {
        assert!(
            SniParseError::TooShort.to_string().contains("too short"),
            "TooShort display mismatch"
        );
        assert!(
            SniParseError::NotHandshake.to_string().contains("not a TLS"),
            "NotHandshake display mismatch"
        );
        assert!(
            SniParseError::NotClientHello.to_string().contains("not a ClientHello"),
            "NotClientHello display mismatch"
        );
        assert!(
            SniParseError::NeedMoreData.to_string().contains("need more data"),
            "NeedMoreData display mismatch"
        );
        assert!(
            SniParseError::MalformedExtension.to_string().contains("malformed"),
            "MalformedExtension display mismatch"
        );
        assert!(
            SniParseError::EmptyHostname.to_string().contains("must not be empty"),
            "EmptyHostname display mismatch"
        );
        assert!(
            SniParseError::InvalidHostname.to_string().contains("IP address"),
            "InvalidHostname display mismatch"
        );
    }

    #[test]
    fn session_id_is_skipped() {
        let session_id = vec![0xAA; 32];
        let sni_ext = build_sni_extension("with-session.example.com");
        let hello = build_client_hello(&session_id, &[0x00, 0xFF], &[0x00], &sni_ext);
        let record = wrap_in_record(&hello);

        let result = parse_sni(&record).expect("ClientHello with session ID should parse");
        assert_eq!(result.sni.as_deref(), Some("with-session.example.com"));
    }

    #[test]
    fn trailing_bytes_after_record_are_ignored() {
        let sni_ext = build_sni_extension("exact.example.com");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &sni_ext);
        let mut record = wrap_in_record(&hello);
        record.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF]);

        let result = parse_sni(&record).expect("trailing garbage after record should be ignored");
        assert_eq!(
            result.sni.as_deref(),
            Some("exact.example.com"),
            "SNI should be extracted despite trailing bytes"
        );
    }

    #[test]
    fn unknown_name_type_in_sni_extension_is_skipped() {
        let mut sni_data = Vec::new();
        let unknown_name = b"mystery";
        let host_name = b"real.example.com";

        let unknown_entry_len = 1 + 2 + unknown_name.len();
        let host_entry_len = 1 + 2 + host_name.len();
        let list_len = unknown_entry_len + host_entry_len;

        #[expect(clippy::cast_possible_truncation, reason = "test data is small")]
        let list_len_u16 = list_len as u16;
        sni_data.extend_from_slice(&0_u16.to_be_bytes());

        #[expect(clippy::cast_possible_truncation, reason = "test data is small")]
        let ext_data_len = (2 + list_len) as u16;
        sni_data.extend_from_slice(&ext_data_len.to_be_bytes());
        sni_data.extend_from_slice(&list_len_u16.to_be_bytes());

        sni_data.push(0x01);
        #[expect(clippy::cast_possible_truncation, reason = "test data is small")]
        let unknown_len = unknown_name.len() as u16;
        sni_data.extend_from_slice(&unknown_len.to_be_bytes());
        sni_data.extend_from_slice(unknown_name);

        sni_data.push(SNI_NAME_TYPE_HOST);
        #[expect(clippy::cast_possible_truncation, reason = "test data is small")]
        let host_len = host_name.len() as u16;
        sni_data.extend_from_slice(&host_len.to_be_bytes());
        sni_data.extend_from_slice(host_name);

        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &sni_data);
        let record = wrap_in_record(&hello);

        let result = parse_sni(&record).expect("unknown name_type should be skipped");
        assert_eq!(
            result.sni.as_deref(),
            Some("real.example.com"),
            "host_name entry should be found after skipping unknown name_type"
        );
    }

    #[test]
    fn read_helpers_big_endian() {
        assert_eq!(
            read_u16(&[0x01, 0x00], 0).expect("valid u16"),
            256,
            "read_u16 big-endian"
        );
        assert_eq!(
            read_u24(&[0x00, 0x01, 0x00], 0).expect("valid u24"),
            256,
            "read_u24 big-endian"
        );
        assert_eq!(
            read_u24(&[0x01, 0x00, 0x00], 0).expect("valid u24"),
            65536,
            "read_u24 high byte"
        );
    }

    #[test]
    fn non_utf8_hostname_returns_invalid_hostname() {
        let name_data: &[u8] = &[0xFF, 0xFE];

        #[expect(clippy::cast_possible_truncation, reason = "test data is small")]
        let name_len = name_data.len() as u16;
        let entry_len: u16 = 1 + 2 + name_len;
        let list_len: u16 = entry_len;
        let ext_data_len: u16 = 2 + list_len;

        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&0_u16.to_be_bytes());
        sni_ext.extend_from_slice(&ext_data_len.to_be_bytes());
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(SNI_NAME_TYPE_HOST);
        sni_ext.extend_from_slice(&name_len.to_be_bytes());
        sni_ext.extend_from_slice(name_data);

        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &sni_ext);
        let record = wrap_in_record(&hello);

        assert_eq!(
            parse_sni(&record),
            Err(SniParseError::InvalidHostname),
            "non-UTF-8 SNI hostname bytes should be rejected"
        );
    }

    #[test]
    fn dns_validation_accepts_valid_hostname() {
        crate::dns::validate_dns_hostname("example.com").expect("bare domain should be valid");
        crate::dns::validate_dns_hostname("a-b.example.com").expect("hyphenated subdomain should be valid");
        crate::dns::validate_dns_hostname("sub.domain.example.com").expect("nested subdomain should be valid");
    }

    #[test]
    fn dns_validation_rejects_leading_hyphen() {
        assert_eq!(
            crate::dns::validate_dns_hostname("-example.com"),
            Err(crate::dns::DnsHostnameError::Label(
                crate::dns::DnsLabelError::HyphenBoundary
            )),
        );
    }

    #[test]
    fn dns_validation_rejects_trailing_hyphen() {
        assert_eq!(
            crate::dns::validate_dns_hostname("example-.com"),
            Err(crate::dns::DnsHostnameError::Label(
                crate::dns::DnsLabelError::HyphenBoundary
            )),
        );
    }

    #[test]
    fn dns_validation_rejects_space() {
        assert_eq!(
            crate::dns::validate_dns_hostname("ex ample.com"),
            Err(crate::dns::DnsHostnameError::Label(
                crate::dns::DnsLabelError::InvalidCharacter
            )),
        );
    }

    #[test]
    fn dns_validation_rejects_label_over_63_chars() {
        let long_label = "a".repeat(64);
        let hostname = format!("{long_label}.com");
        assert_eq!(
            crate::dns::validate_dns_hostname(&hostname),
            Err(crate::dns::DnsHostnameError::Label(
                crate::dns::DnsLabelError::LabelTooLong
            )),
        );
    }

    #[test]
    fn dns_validation_rejects_total_over_253_chars() {
        let hostname = format!("{}.com", "a".repeat(250));
        assert_eq!(
            crate::dns::validate_dns_hostname(&hostname),
            Err(crate::dns::DnsHostnameError::HostnameTooLong),
        );
    }

    #[test]
    fn dns_validation_rejects_control_chars() {
        assert_eq!(
            crate::dns::validate_dns_hostname("host\r\nname.com"),
            Err(crate::dns::DnsHostnameError::Label(
                crate::dns::DnsLabelError::InvalidCharacter
            )),
        );
    }

    #[test]
    fn trailing_dot_hostname_rejected() {
        assert_eq!(
            crate::dns::validate_dns_hostname("example.com."),
            Err(crate::dns::DnsHostnameError::Label(
                crate::dns::DnsLabelError::EmptyLabel
            )),
        );
    }

    #[test]
    fn single_label_hostname_accepted() {
        assert!(
            crate::dns::validate_dns_hostname("localhost").is_ok(),
            "single-label hostname like 'localhost' should be accepted"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build an SNI extension payload (type 0x0000).
    fn build_sni_extension(hostname: &str) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();

        #[expect(clippy::cast_possible_truncation, reason = "test hostnames are short")]
        let name_len = name_bytes.len() as u16;

        let entry_len = 1 + 2 + name_len;
        let list_len = entry_len;

        let mut ext = Vec::new();
        ext.extend_from_slice(&0_u16.to_be_bytes());
        let ext_data_len = 2 + list_len;
        ext.extend_from_slice(&ext_data_len.to_be_bytes());
        ext.extend_from_slice(&list_len.to_be_bytes());
        ext.push(SNI_NAME_TYPE_HOST);
        ext.extend_from_slice(&name_len.to_be_bytes());
        ext.extend_from_slice(name_bytes);
        ext
    }

    /// Build an SNI extension payload carrying two `host_name` entries, which
    /// RFC 6066 forbids.
    #[expect(clippy::cast_possible_truncation, reason = "test hostnames are short")]
    fn build_sni_extension_two_hosts(a: &str, b: &str) -> Vec<u8> {
        let entry = |name: &str| {
            let nb = name.as_bytes();
            let mut e = Vec::new();
            e.push(SNI_NAME_TYPE_HOST);
            e.extend_from_slice(&(nb.len() as u16).to_be_bytes());
            e.extend_from_slice(nb);
            e
        };
        let mut list = entry(a);
        list.extend_from_slice(&entry(b));

        let mut ext = Vec::new();
        ext.extend_from_slice(&0_u16.to_be_bytes());
        let ext_data_len = (2 + list.len()) as u16;
        ext.extend_from_slice(&ext_data_len.to_be_bytes());
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);
        ext
    }

    #[test]
    fn duplicate_host_name_entries_rejected() {
        let ext = build_sni_extension_two_hosts("a.example.com", "b.example.com");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &ext);
        let record = wrap_in_record(&hello);
        assert_eq!(
            parse_sni(&record),
            Err(SniParseError::MalformedExtension),
            "two host_name entries violate RFC 6066 §3 and must be rejected, not silently first-wins"
        );
    }

    /// Build a non-SNI extension with the given type and data.
    fn build_dummy_extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&ext_type.to_be_bytes());

        #[expect(clippy::cast_possible_truncation, reason = "test data is short")]
        let len = data.len() as u16;

        ext.extend_from_slice(&len.to_be_bytes());
        ext.extend_from_slice(data);
        ext
    }

    /// Build a `ClientHello` body from components.
    #[expect(clippy::cast_possible_truncation, reason = "test payloads are small")]
    fn build_client_hello(session_id: &[u8], cipher_suites: &[u8], compression: &[u8], extensions: &[u8]) -> Vec<u8> {
        let mut hello = Vec::new();

        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0_u8; 32]);

        hello.push(session_id.len() as u8);
        hello.extend_from_slice(session_id);

        let cs_len = cipher_suites.len() as u16;
        hello.extend_from_slice(&cs_len.to_be_bytes());
        hello.extend_from_slice(cipher_suites);

        hello.push(compression.len() as u8);
        hello.extend_from_slice(compression);

        if !extensions.is_empty() {
            let ext_len = extensions.len() as u16;
            hello.extend_from_slice(&ext_len.to_be_bytes());
            hello.extend_from_slice(extensions);
        }

        hello
    }

    /// Wrap a `ClientHello` body in handshake + record headers.
    #[expect(clippy::cast_possible_truncation, reason = "test payloads are small")]
    fn wrap_in_record(hello_body: &[u8]) -> Vec<u8> {
        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let hs_len = hello_body.len() as u32;
        handshake.push((hs_len >> 16) as u8);
        handshake.push((hs_len >> 8) as u8);
        handshake.push(hs_len as u8);
        handshake.extend_from_slice(hello_body);

        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        let rec_len = handshake.len() as u16;
        record.extend_from_slice(&rec_len.to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    /// Build the raw handshake message bytes (type + 3-byte length + body).
    #[expect(clippy::cast_possible_truncation, reason = "test payloads are small")]
    fn build_handshake_message(hello_body: &[u8]) -> Vec<u8> {
        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let hs_len = hello_body.len() as u32;
        handshake.push((hs_len >> 16) as u8);
        handshake.push((hs_len >> 8) as u8);
        handshake.push(hs_len as u8);
        handshake.extend_from_slice(hello_body);
        handshake
    }

    /// Wrap raw handshake bytes (which may be a partial fragment) in one TLS record.
    #[expect(clippy::cast_possible_truncation, reason = "test payloads are small")]
    fn wrap_fragment_in_record(fragment: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        let rec_len = fragment.len() as u16;
        record.extend_from_slice(&rec_len.to_be_bytes());
        record.extend_from_slice(fragment);
        record
    }

    #[test]
    fn client_hello_fragmented_across_two_records_parses_sni() {
        let ext = build_sni_extension("example.com");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &ext);
        let handshake = build_handshake_message(&hello);
        let split = handshake.len() / 2;
        let mut buf = wrap_fragment_in_record(&handshake[..split]);
        buf.extend_from_slice(&wrap_fragment_in_record(&handshake[split..]));
        let result = parse_sni(&buf).expect("ClientHello fragmented across records should parse");
        assert_eq!(
            result.sni.as_deref(),
            Some("example.com"),
            "SNI should be extracted from a multi-record ClientHello"
        );
    }

    #[test]
    fn client_hello_fragmented_across_three_records_parses_sni() {
        let ext = build_sni_extension("shard.example.net");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &ext);
        let handshake = build_handshake_message(&hello);
        let third = handshake.len() / 3;
        let mut buf = wrap_fragment_in_record(&handshake[..third]);
        buf.extend_from_slice(&wrap_fragment_in_record(&handshake[third..2 * third]));
        buf.extend_from_slice(&wrap_fragment_in_record(&handshake[2 * third..]));
        let result = parse_sni(&buf).expect("ClientHello across three records should parse");
        assert_eq!(
            result.sni.as_deref(),
            Some("shard.example.net"),
            "SNI should span three records"
        );
    }

    #[test]
    fn client_hello_header_split_across_records_parses_sni() {
        // The first record carries only half of the 4-byte handshake
        // header, so reassembly must accumulate the header itself across
        // record boundaries before it can size the message.
        let ext = build_sni_extension("split.example.org");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &ext);
        let handshake = build_handshake_message(&hello);
        let mut buf = wrap_fragment_in_record(handshake.get(..2).expect("head"));
        buf.extend_from_slice(&wrap_fragment_in_record(handshake.get(2..).expect("tail")));
        let result = parse_sni(&buf).expect("ClientHello with a split handshake header should parse");
        assert_eq!(
            result.sni.as_deref(),
            Some("split.example.org"),
            "SNI should be extracted when the handshake header spans records"
        );
    }

    #[test]
    fn reassembler_trickle_matches_one_shot_parse() {
        // Feeding the buffer one byte at a time must produce exactly the
        // one-shot parse_sni result, scanning each byte once.
        let ext = build_sni_extension("trickle.example.com");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &ext);
        let handshake = build_handshake_message(&hello);
        let third = handshake.len() / 3;
        let mut buf = wrap_fragment_in_record(handshake.get(..third).expect("head"));
        buf.extend_from_slice(&wrap_fragment_in_record(handshake.get(third..2 * third).expect("mid")));
        buf.extend_from_slice(&wrap_fragment_in_record(handshake.get(2 * third..).expect("tail")));

        let mut reassembler = SniReassembler::new();
        let mut result = None;
        for end in 1..=buf.len() {
            let step = reassembler
                .advance(buf.get(..end).expect("prefix"))
                .expect("trickled reassembly must not error");
            if let Some(info) = step {
                result = Some(info);
                break;
            }
        }
        let expected = parse_sni(&buf).expect("one-shot parse");
        assert_eq!(
            result.expect("trickled parse must complete").sni,
            expected.sni,
            "trickled reassembly must match the one-shot result"
        );
    }

    #[test]
    fn reassembler_rejects_non_client_hello_like_one_shot() {
        // Handshake type 2 split across records: the reassembler must
        // classify it exactly as the stateless path does.
        let mut buf = wrap_fragment_in_record(&[2, 0]);
        buf.extend_from_slice(&wrap_fragment_in_record(&[0, 0]));
        let mut reassembler = SniReassembler::new();
        assert!(
            matches!(reassembler.advance(&buf), Err(SniParseError::NotClientHello)),
            "a fragmented non-ClientHello must be rejected"
        );
    }

    #[test]
    fn reassembler_stops_at_non_handshake_record() {
        let ext = build_sni_extension("example.com");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &ext);
        let handshake = build_handshake_message(&hello);
        let split = handshake.len() / 2;
        let mut buf = wrap_fragment_in_record(handshake.get(..split).expect("head"));
        buf.extend_from_slice(&[23, 0x03, 0x01, 0x00, 0x01, 0x00]);
        let mut reassembler = SniReassembler::new();
        assert!(
            matches!(reassembler.advance(&buf), Err(SniParseError::NotHandshake)),
            "a non-handshake record must end reassembly"
        );
    }

    #[test]
    fn reassembler_reservation_bounded_by_supplied_bytes() {
        // A 9-byte record claiming the maximum u24 handshake length
        // (16 MiB) must not drive the accumulator's capacity past the
        // bytes actually supplied: the length field is attacker-chosen
        // while the caller's peek cap bounds real data.
        let buf = [22, 3, 1, 0, 4, HANDSHAKE_TYPE_CLIENT_HELLO, 0xFF, 0xFF, 0xFF];
        let mut reassembler = SniReassembler::new();
        assert!(
            matches!(reassembler.advance(&buf), Ok(None)),
            "an incomplete hello must ask for more data"
        );
        assert!(
            reassembler.body.capacity() <= buf.len(),
            "capacity {} must not exceed the {} supplied bytes",
            reassembler.body.capacity(),
            buf.len()
        );
    }

    #[test]
    fn client_hello_fragmented_missing_tail_needs_more_data() {
        let ext = build_sni_extension("example.com");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &ext);
        let handshake = build_handshake_message(&hello);
        let split = handshake.len() / 2;
        // Only the first fragment record is present; the tail has not arrived.
        let buf = wrap_fragment_in_record(&handshake[..split]);
        assert_eq!(
            parse_sni(&buf),
            Err(SniParseError::NeedMoreData),
            "an incomplete fragmented ClientHello should request more data, not misparse"
        );
    }

    #[test]
    fn fragmented_reassembly_stops_at_non_handshake_record() {
        let ext = build_sni_extension("example.com");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &ext);
        let handshake = build_handshake_message(&hello);
        let split = handshake.len() / 2;
        let mut buf = wrap_fragment_in_record(&handshake[..split]);
        // Follow the partial handshake with an application-data record (type 23).
        buf.extend_from_slice(&[23, 0x03, 0x01, 0x00, 0x01, 0x00]);
        assert_eq!(
            parse_sni(&buf),
            Err(SniParseError::NotHandshake),
            "a non-handshake record must end reassembly rather than being concatenated"
        );
    }
}
