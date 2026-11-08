// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Bounded HTTP/1 response framing and streaming body observation.

use std::io::{self, BufRead, ErrorKind};

/// Maximum bytes accepted for one header or trailer block.
const MAX_HEADER_BYTES: usize = 65_536; // 64 KiB
/// Maximum informational responses preceding a final response.
const MAX_INFORMATIONAL_RESPONSES: usize = 16;

/// How a response body was completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H1Completion {
    /// A bodyless response completed at the end of its headers.
    Headers,
    /// The declared `Content-Length` bytes were received.
    ContentLength,
    /// A terminating chunk and its trailers were received.
    Chunked,
    /// The peer closed a response without explicit length framing.
    CloseDelimited,
}

/// An observed HTTP/1 response, including incomplete responses.
#[derive(Debug)]
pub struct H1Response {
    /// The final response status, if its headers arrived.
    pub status: Option<u16>,
    /// Informational responses received before the final status.
    pub interim_statuses: Vec<u16>,
    /// Final response headers, with lowercase names.
    pub headers: Vec<(String, String)>,
    /// Body bytes delivered to the sink, excluding HTTP framing.
    pub body_bytes: u64,
    /// Completion mechanism, absent if parsing or transport failed.
    pub completion: Option<H1Completion>,
    /// Error kind and message if the response did not complete.
    pub abort: Option<(ErrorKind, String)>,
}

/// Read a response without collecting its body, passing content bytes to `sink`.
///
/// The caller controls socket deadlines. `max_body` limits bytes accepted by
/// the sink. Informational responses, chunk extensions, and trailers are parsed;
/// arbitrary body bytes are never searched for chunk markers. EOF on a
/// close-delimited body is reported separately because it cannot prove the
/// sender produced its intended length.
pub fn read_h1_response<R, F>(reader: &mut R, is_head: bool, max_body: u64, mut sink: F) -> H1Response
where
    R: BufRead,
    F: FnMut(&[u8]) -> io::Result<()>,
{
    let mut result = H1Response {
        status: None,
        interim_statuses: Vec::new(),
        headers: Vec::new(),
        body_bytes: 0,
        completion: None,
        abort: None,
    };
    if let Err(error) = read_response(reader, is_head, max_body, &mut sink, &mut result) {
        result.abort = Some((error.kind(), error.to_string()));
    }
    result
}

/// Verify rejection of a buffered upstream 200 response without releasing its body.
///
/// Before headers are committed, Praxis sends its default internal-error response.
/// After commitment, it must abort without delivering any buffered content.
///
/// # Panics
///
/// Panics on leaked content, incomplete error responses, or any other outcome,
/// including a read deadline expiring instead of a peer abort.
pub fn assert_buffered_response_rejected(response: &H1Response, body: &[u8]) {
    assert_eq!(response.body_bytes, body.len() as u64, "{response:?}");
    if response.status == Some(500) {
        assert_internal_error_response(response, body);
        return;
    }
    assert_eq!(response.status, Some(200), "{response:?}");
    assert!(body.is_empty(), "buffered content escaped: {response:?}");
    assert_eq!(response.completion, None, "overrun must not complete: {response:?}");
    assert!(
        response.abort.as_ref().is_some_and(|(kind, _)| matches!(
            kind,
            ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
        )),
        "overrun must abort at the peer, not time out: {response:?}"
    );
}

/// Require the complete default error envelope, with no upstream bytes mixed in.
fn assert_internal_error_response(response: &H1Response, body: &[u8]) {
    assert_eq!(response.completion, Some(H1Completion::ContentLength), "{response:?}");
    assert_eq!(response.abort, None, "{response:?}");
    assert!(
        response
            .headers
            .iter()
            .any(|(name, value)| name == "content-type" && value == "application/problem+json"),
        "{response:?}"
    );
    assert_eq!(
        body, br#"{"type":"about:blank","title":"Internal Server Error","status":500,"detail":"Internal proxy error"}"#,
        "only the sanitized proxy error may be delivered: {response:?}"
    );
}

/// Parsed bounded HTTP/1 header block.
#[derive(Debug)]
pub(crate) struct Head {
    /// Status or request line.
    pub start: String,
    /// Lowercase header names and original trimmed values.
    pub headers: Vec<(String, String)>,
}

/// A body's framing as determined from its headers.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Framing {
    /// No body is present.
    None,
    /// Exactly this many content bytes.
    Fixed(u64),
    /// HTTP chunk framing with trailers.
    Chunked,
    /// Content ends when the connection closes.
    Close,
}

/// Parse the complete final response while preserving partial observations.
fn read_response<R, F>(reader: &mut R, is_head: bool, max: u64, sink: &mut F, result: &mut H1Response) -> io::Result<()>
where
    R: BufRead,
    F: FnMut(&[u8]) -> io::Result<()>,
{
    let head = loop {
        let head = read_head(reader)?;
        let status = response_status(&head.start)?;
        if (100..200).contains(&status) && status != 101 {
            if result.interim_statuses.len() == MAX_INFORMATIONAL_RESPONSES {
                return Err(invalid("too many informational responses"));
            }
            result.interim_statuses.push(status);
        } else {
            result.status = Some(status);
            break head;
        }
    };
    let status = result.status.expect("final status was just set");
    let no_body = is_head || (100..200).contains(&status) || status == 204 || status == 304;
    let framing = if no_body {
        Framing::None
    } else {
        framing(&head.headers, true)?
    };
    result.headers = head.headers;
    result.completion = Some(read_body(reader, framing, max, sink, &mut result.body_bytes)?);
    Ok(())
}

/// Parse a response status line.
fn response_status(line: &str) -> io::Result<u16> {
    let mut parts = line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(invalid("invalid HTTP/1 status line"));
    }
    parts
        .next()
        .and_then(|status| status.parse::<u16>().ok())
        .filter(|status| (100..=999).contains(status))
        .ok_or_else(|| invalid("invalid HTTP status"))
}

/// Read a start line and header block under a fixed byte limit.
pub(crate) fn read_head<R: BufRead>(reader: &mut R) -> io::Result<Head> {
    let mut budget = MAX_HEADER_BYTES;
    let start = read_line(reader, &mut budget)?;
    if start.is_empty() {
        return Err(invalid("empty HTTP start line"));
    }
    let mut headers = Vec::new();
    loop {
        let line = read_line(reader, &mut budget)?;
        if line.is_empty() {
            return Ok(Head { start, headers });
        }
        let (name, value) = parse_header_line(&line)?;
        headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
}

/// Determine framing; requests without framing have no body.
pub(crate) fn framing(headers: &[(String, String)], response: bool) -> io::Result<Framing> {
    let mut length = None;
    let mut transfer = None;
    for (name, value) in headers {
        if name == "content-length" {
            let parsed = value
                .parse::<u64>()
                .map_err(|_error| invalid("invalid Content-Length"))?;
            if length.is_some_and(|previous| previous != parsed) {
                return Err(invalid("conflicting Content-Length"));
            }
            length = Some(parsed);
        } else if name == "transfer-encoding" {
            if transfer.is_some() {
                return Err(invalid("multiple Transfer-Encoding headers"));
            }
            transfer = Some(value);
        }
    }
    if let Some(encoding) = transfer {
        if length.is_some() || !encoding.eq_ignore_ascii_case("chunked") {
            return Err(invalid("unsupported or ambiguous transfer framing"));
        }
        return Ok(Framing::Chunked);
    }
    Ok(length.map_or(if response { Framing::Close } else { Framing::None }, Framing::Fixed))
}

/// Stream a body according to its framing, recording bytes already delivered.
pub(crate) fn read_body<R, F>(
    reader: &mut R,
    framing: Framing,
    max: u64,
    sink: &mut F,
    count: &mut u64,
) -> io::Result<H1Completion>
where
    R: BufRead,
    F: FnMut(&[u8]) -> io::Result<()>,
{
    read_body_with_trailers(reader, framing, max, sink, count).map(|end| end.completion)
}

/// A completed body and its validated trailer fields.
pub(crate) struct BodyEnd {
    /// The framing event that completed the content.
    pub(crate) completion: H1Completion,
    /// Trailer fields present at that completion, in wire order.
    pub(crate) trailers: Vec<(String, String)>,
}

/// Stream a body while retaining its bounded, validated trailer fields.
pub(crate) fn read_body_with_trailers<R, F>(
    reader: &mut R,
    framing: Framing,
    max: u64,
    sink: &mut F,
    count: &mut u64,
) -> io::Result<BodyEnd>
where
    R: BufRead,
    F: FnMut(&[u8]) -> io::Result<()>,
{
    let mut trailers = Vec::new();
    let completion = match framing {
        Framing::None => H1Completion::Headers,
        Framing::Fixed(length) => {
            copy_exact(reader, length, max, sink, count)?;
            H1Completion::ContentLength
        },
        Framing::Chunked => {
            read_chunks(reader, max, sink, count, &mut trailers)?;
            H1Completion::Chunked
        },
        Framing::Close => {
            copy_to_eof(reader, max, sink, count)?;
            H1Completion::CloseDelimited
        },
    };
    Ok(BodyEnd { completion, trailers })
}

/// Read chunk sizes and trailers without searching body data for delimiters.
fn read_chunks<R, F>(
    reader: &mut R,
    max: u64,
    sink: &mut F,
    count: &mut u64,
    trailers: &mut Vec<(String, String)>,
) -> io::Result<()>
where
    R: BufRead,
    F: FnMut(&[u8]) -> io::Result<()>,
{
    loop {
        let mut budget = MAX_HEADER_BYTES;
        let size_line = read_line(reader, &mut budget)?;
        let size = size_line.split(';').next().unwrap_or_default();
        let length = u64::from_str_radix(size.trim(), 16).map_err(|_error| invalid("invalid chunk size"))?;
        if length == 0 {
            let mut budget = MAX_HEADER_BYTES;
            loop {
                let line = read_line(reader, &mut budget)?;
                if line.is_empty() {
                    break;
                }
                let (name, value) = parse_header_line(&line)?;
                trailers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
            }
            return Ok(());
        }
        copy_exact(reader, length, max, sink, count)?;
        let mut ending = [0; 2];
        reader.read_exact(&mut ending)?;
        if ending != *b"\r\n" {
            return Err(invalid("chunk lacks CRLF"));
        }
    }
}

/// Deliver exactly `length` bytes or report premature EOF.
fn copy_exact<R, F>(reader: &mut R, mut length: u64, max: u64, sink: &mut F, count: &mut u64) -> io::Result<()>
where
    R: BufRead,
    F: FnMut(&[u8]) -> io::Result<()>,
{
    while length > 0 {
        let bytes = reader.fill_buf()?;
        if bytes.is_empty() {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "body ended before its framing",
            ));
        }
        let available = u64::try_from(bytes.len()).unwrap_or(u64::MAX).min(length);
        let amount = deliver(bytes, available, max, sink, count)?;
        reader.consume(amount);
        length -= amount as u64;
    }
    Ok(())
}

/// Deliver bytes until EOF for an explicitly close-delimited response.
fn copy_to_eof<R, F>(reader: &mut R, max: u64, sink: &mut F, count: &mut u64) -> io::Result<()>
where
    R: BufRead,
    F: FnMut(&[u8]) -> io::Result<()>,
{
    loop {
        let bytes = reader.fill_buf()?;
        if bytes.is_empty() {
            return Ok(());
        }
        let amount = deliver(bytes, bytes.len() as u64, max, sink, count)?;
        reader.consume(amount);
    }
}

/// Deliver a bounded available slice and update the observed byte count.
fn deliver<F>(bytes: &[u8], available: u64, max: u64, sink: &mut F, count: &mut u64) -> io::Result<usize>
where
    F: FnMut(&[u8]) -> io::Result<()>,
{
    let accepted = available.min(max.saturating_sub(*count));
    if accepted == 0 {
        return Err(invalid("body exceeds observation limit"));
    }
    let amount = usize::try_from(accepted).map_err(|_error| invalid("body count exceeds platform size"))?;
    sink(&bytes[..amount])?;
    *count += accepted;
    Ok(amount)
}

/// Read one CRLF-terminated UTF-8 line without exceeding `budget`.
fn read_line<R: BufRead>(reader: &mut R, budget: &mut usize) -> io::Result<String> {
    let mut line = Vec::new();
    loop {
        let bytes = reader.fill_buf()?;
        if bytes.is_empty() {
            return Err(io::Error::new(ErrorKind::UnexpectedEof, "incomplete HTTP line"));
        }
        let count = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |index| index + 1);
        if count > *budget {
            return Err(invalid("HTTP headers exceed observation limit"));
        }
        line.extend_from_slice(&bytes[..count]);
        let ended = bytes[count - 1] == b'\n';
        reader.consume(count);
        *budget -= count;
        if ended {
            break;
        }
    }
    if !line.ends_with(b"\r\n") {
        return Err(invalid("HTTP line lacks CRLF"));
    }
    line.truncate(line.len() - 2);
    String::from_utf8(line).map_err(|_error| invalid("HTTP line is not UTF-8"))
}

/// Make a malformed-data error with a stable message.
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

/// Validate a header or trailer field line and return its name and value.
fn parse_header_line(line: &str) -> io::Result<(&str, &str)> {
    let (name, value) = line.split_once(':').ok_or_else(|| invalid("malformed HTTP header"))?;
    let valid = |byte: u8| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte);
    if name.is_empty() || !name.bytes().all(valid) {
        return Err(invalid("invalid HTTP header name"));
    }
    Ok((name, value))
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor, ErrorKind};

    use super::{H1Completion, assert_buffered_response_rejected, read_h1_response};

    #[test]
    fn buffered_rejection_accepts_errors_before_and_after_headers() {
        let problem =
            br#"{"type":"about:blank","title":"Internal Server Error","status":500,"detail":"Internal proxy error"}"#;
        let error = format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/problem+json\r\nContent-Length: {}\r\n\r\n{}",
            problem.len(),
            str::from_utf8(problem).unwrap()
        );
        for wire in [
            error.as_bytes(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 65538\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            let mut body = Vec::new();
            let result = read_h1_response(&mut Cursor::new(wire), false, 1024, |part| {
                body.extend_from_slice(part);
                Ok(())
            });
            assert_buffered_response_rejected(&result, &body);
        }
    }

    #[test]
    fn buffered_rejection_rejects_leaks_success_and_broken_errors() {
        for wire in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 65538\r\n\r\nleaked".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/problem+json\r\nContent-Length: 99\r\n\r\n{",
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/problem+json\r\nContent-Length: 6\r\n\r\nleaked",
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
        ] {
            let mut body = Vec::new();
            let result = read_h1_response(&mut Cursor::new(wire), false, 1024, |part| {
                body.extend_from_slice(part);
                Ok(())
            });
            assert!(std::panic::catch_unwind(|| assert_buffered_response_rejected(&result, &body)).is_err());
        }
    }

    #[test]
    fn buffered_rejection_does_not_mistake_deadlines_for_peer_aborts() {
        let mut result = read_h1_response(
            &mut Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 65538\r\n\r\n"),
            false,
            1024,
            |_| Ok(()),
        );
        for kind in [ErrorKind::TimedOut, ErrorKind::WouldBlock] {
            result.abort = Some((kind, "deadline expired".to_owned()));
            assert!(std::panic::catch_unwind(|| assert_buffered_response_rejected(&result, &[])).is_err());
        }
    }

    #[test]
    fn chunk_body_can_contain_terminal_marker_and_have_trailers() {
        let wire = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7;ext=ok\r\n0\r\n\r\nxy\r\n0\r\nX-Result: ok\r\n\r\n";
        let mut reader = BufReader::with_capacity(2, Cursor::new(wire));
        let mut body = Vec::new();
        let result = read_h1_response(&mut reader, false, 100, |chunk| {
            body.extend_from_slice(chunk);
            Ok(())
        });
        assert_eq!(result.status, Some(200));
        assert_eq!(result.interim_statuses, [100]);
        assert_eq!(result.completion, Some(H1Completion::Chunked));
        assert_eq!(result.body_bytes, 7);
        assert_eq!(body, b"0\r\n\r\nxy");
        assert_eq!(result.abort, None);
    }

    #[test]
    fn fixed_and_chunked_truncation_preserve_partial_count() {
        for wire in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc".as_slice(),
        ] {
            let mut reader = BufReader::new(Cursor::new(wire));
            let result = read_h1_response(&mut reader, false, 20, |_| Ok(()));
            assert_eq!(result.status, Some(200));
            assert_eq!(result.body_bytes, 3);
            assert_eq!(result.completion, None);
            assert_eq!(result.abort.map(|abort| abort.0), Some(ErrorKind::UnexpectedEof));
        }
    }

    #[test]
    fn close_delimited_eof_and_observation_cap_are_distinct() {
        let wire = b"HTTP/1.1 200 OK\r\n\r\nabc";
        let result = read_h1_response(&mut BufReader::new(Cursor::new(wire)), false, 3, |_| Ok(()));
        assert_eq!(result.completion, Some(H1Completion::CloseDelimited));
        let result = read_h1_response(&mut BufReader::new(Cursor::new(wire)), false, 2, |_| Ok(()));
        assert_eq!(result.body_bytes, 2);
        assert_eq!(result.completion, None);
        assert_eq!(result.abort.map(|abort| abort.0), Some(ErrorKind::InvalidData));
    }

    #[test]
    fn informational_responses_have_a_finite_limit() {
        let wire = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(17);
        let result = read_h1_response(&mut BufReader::new(Cursor::new(wire)), false, 3, |_| Ok(()));
        assert_eq!(result.interim_statuses.len(), 16);
        assert_eq!(result.status, None);
        assert_eq!(result.abort.map(|abort| abort.0), Some(ErrorKind::InvalidData));
    }

    #[test]
    fn malformed_or_incomplete_trailers_do_not_complete() {
        for wire in [
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nnot-a-header\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Foo: value\r\n".as_slice(),
        ] {
            let result = read_h1_response(&mut BufReader::new(Cursor::new(wire)), false, 1, |_| Ok(()));
            assert_eq!(result.completion, None);
            assert!(result.abort.is_some());
        }
    }
}
