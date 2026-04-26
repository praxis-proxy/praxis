// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

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

// ---------------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------------

/// TLS `ContentType` for Handshake records.
const CONTENT_TYPE_HANDSHAKE: u8 = 22;

/// TLS `HandshakeType` for `ClientHello`.
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

/// TLS extension type for Server Name Indication (RFC 6066).
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

// ---------------------------------------------------------------------------------
// ClientHelloInfo
// ---------------------------------------------------------------------------------

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// The SNI hostname, if present in the `ClientHello`.
    pub sni: Option<String>,
}

// ---------------------------------------------------------------------------------
// SniParseError
// ---------------------------------------------------------------------------------

/// Errors from parsing TLS `ClientHello` SNI.
///
/// ```
/// use praxis_tls::sni::SniParseError;
///
/// let e = SniParseError::TooShort;
/// assert!(e.to_string().contains("too short"));
/// ```
#[derive(Debug, Error, PartialEq, Eq)]
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

    /// The SNI hostname is empty (RFC 6066 requires a valid DNS name).
    #[error("SNI hostname must not be empty (RFC 6066)")]
    EmptyHostname,

    /// The SNI hostname is an IP literal (rejected per RFC 6066 section 3).
    #[error("SNI must not be an IP address (RFC 6066)")]
    InvalidHostname,
}

// ---------------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------------

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
    let fragment = parse_record_header(buf)?;
    let hello_body = parse_handshake_header(fragment)?;
    parse_client_hello(hello_body)
}

// ---------------------------------------------------------------------------------
// Record Layer
// ---------------------------------------------------------------------------------

/// Parse the TLS record header, returning the fragment payload.
#[allow(clippy::indexing_slicing, reason = "bounds checked before access")]
fn parse_record_header(buf: &[u8]) -> Result<&[u8], SniParseError> {
    if buf.len() < TLS_RECORD_HEADER_LEN {
        return Err(SniParseError::TooShort);
    }

    if buf[0] != CONTENT_TYPE_HANDSHAKE {
        return Err(SniParseError::NotHandshake);
    }

    let record_len = read_u16(buf, 3)? as usize;
    let total = TLS_RECORD_HEADER_LEN + record_len;

    if buf.len() < total {
        return Err(SniParseError::NeedMoreData);
    }

    Ok(&buf[TLS_RECORD_HEADER_LEN..total])
}

/// Parse the handshake message header, returning the `ClientHello` body.
#[allow(clippy::indexing_slicing, reason = "bounds checked before access")]
fn parse_handshake_header(fragment: &[u8]) -> Result<&[u8], SniParseError> {
    if fragment.len() < HANDSHAKE_HEADER_LEN {
        return Err(SniParseError::NeedMoreData);
    }

    if fragment[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(SniParseError::NotClientHello);
    }

    let hs_len = read_u24(fragment, 1)? as usize;
    let end = HANDSHAKE_HEADER_LEN + hs_len;

    if fragment.len() < end {
        return Err(SniParseError::NeedMoreData);
    }

    Ok(&fragment[HANDSHAKE_HEADER_LEN..end])
}

// ---------------------------------------------------------------------------------
// ClientHello Parsing Utilities
// ---------------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------------
// SNI Extension Parsing Utilities
// ---------------------------------------------------------------------------------

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

    while list.len() >= 3 {
        let name_type = *list.first().ok_or(SniParseError::MalformedExtension)?;
        let name_len = read_u16(list, 1)? as usize;

        if list.len() < 3 + name_len {
            return Err(SniParseError::MalformedExtension);
        }

        if name_type == SNI_NAME_TYPE_HOST {
            let name_bytes = list.get(3..3 + name_len).ok_or(SniParseError::MalformedExtension)?;

            if name_bytes.is_empty() {
                return Err(SniParseError::EmptyHostname);
            }

            let hostname = std::str::from_utf8(name_bytes).map_err(|_utf8| SniParseError::InvalidHostname)?;

            reject_ip_literal(hostname)?;

            return Ok(ClientHelloInfo {
                sni: Some(hostname.to_owned()),
            });
        }

        list = list.get(3 + name_len..).ok_or(SniParseError::MalformedExtension)?;
    }

    Ok(ClientHelloInfo { sni: None })
}

// ---------------------------------------------------------------------------------
// Binary Utilities
// ---------------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------------

/// Reject IP address literals per RFC 6066 section 3.
fn reject_ip_literal(hostname: &str) -> Result<(), SniParseError> {
    if hostname.parse::<std::net::IpAddr>().is_ok() {
        return Err(SniParseError::InvalidHostname);
    }

    let trimmed = hostname
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(hostname);

    if trimmed.parse::<std::net::Ipv6Addr>().is_ok() {
        return Err(SniParseError::InvalidHostname);
    }

    Ok(())
}

// ---------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------

#[cfg(test)]
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
        assert_eq!(parse_sni(&[]), Err(SniParseError::TooShort));
    }

    #[test]
    fn short_buffer_returns_too_short() {
        assert_eq!(parse_sni(&[22, 3, 3]), Err(SniParseError::TooShort));
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
        assert!(SniParseError::TooShort.to_string().contains("too short"));
        assert!(SniParseError::NotHandshake.to_string().contains("not a TLS"));
        assert!(SniParseError::NotClientHello.to_string().contains("not a ClientHello"));
        assert!(SniParseError::NeedMoreData.to_string().contains("need more data"));
        assert!(SniParseError::MalformedExtension.to_string().contains("malformed"));
        assert!(SniParseError::EmptyHostname.to_string().contains("must not be empty"));
        assert!(SniParseError::InvalidHostname.to_string().contains("IP address"));
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

        #[allow(clippy::cast_possible_truncation, reason = "test data is small")]
        let list_len_u16 = list_len as u16;
        sni_data.extend_from_slice(&0u16.to_be_bytes());

        #[allow(clippy::cast_possible_truncation, reason = "test data is small")]
        let ext_data_len = (2 + list_len) as u16;
        sni_data.extend_from_slice(&ext_data_len.to_be_bytes());
        sni_data.extend_from_slice(&list_len_u16.to_be_bytes());

        sni_data.push(0x01);
        #[allow(clippy::cast_possible_truncation, reason = "test data is small")]
        let unknown_len = unknown_name.len() as u16;
        sni_data.extend_from_slice(&unknown_len.to_be_bytes());
        sni_data.extend_from_slice(unknown_name);

        sni_data.push(SNI_NAME_TYPE_HOST);
        #[allow(clippy::cast_possible_truncation, reason = "test data is small")]
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

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    /// Build an SNI extension payload (type 0x0000).
    fn build_sni_extension(hostname: &str) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();

        #[allow(clippy::cast_possible_truncation, reason = "test hostnames are short")]
        let name_len = name_bytes.len() as u16;

        let entry_len = 1 + 2 + name_len;
        let list_len = entry_len;

        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes());
        let ext_data_len = 2 + list_len;
        ext.extend_from_slice(&ext_data_len.to_be_bytes());
        ext.extend_from_slice(&list_len.to_be_bytes());
        ext.push(SNI_NAME_TYPE_HOST);
        ext.extend_from_slice(&name_len.to_be_bytes());
        ext.extend_from_slice(name_bytes);
        ext
    }

    /// Build a non-SNI extension with the given type and data.
    fn build_dummy_extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&ext_type.to_be_bytes());

        #[allow(clippy::cast_possible_truncation, reason = "test data is short")]
        let len = data.len() as u16;

        ext.extend_from_slice(&len.to_be_bytes());
        ext.extend_from_slice(data);
        ext
    }

    /// Build a `ClientHello` body from components.
    #[allow(clippy::cast_possible_truncation, reason = "test payloads are small")]
    fn build_client_hello(session_id: &[u8], cipher_suites: &[u8], compression: &[u8], extensions: &[u8]) -> Vec<u8> {
        let mut hello = Vec::new();

        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);

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
    #[allow(clippy::cast_possible_truncation, reason = "test payloads are small")]
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
}
