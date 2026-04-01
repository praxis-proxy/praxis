//! Lightweight HTTP client for integration tests.
//!
//! Uses raw TCP sockets so tests are not coupled to any
//! particular HTTP client library.

use std::{
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};

// -----------------------------------------------------------------------------
// Raw Request / Response
// -----------------------------------------------------------------------------

/// Connect, send an already-formatted HTTP request, and
/// return the raw response.
pub fn http_send(addr: &str, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();

    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(request.as_bytes()).unwrap();

    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);

    response
}

// -----------------------------------------------------------------------------
// Convenience Wrappers
// -----------------------------------------------------------------------------

/// Send an HTTP GET and return `(status, body)`.
pub fn http_get(addr: &str, path: &str, host: Option<&str>) -> (u16, String) {
    let host_header = host.unwrap_or("localhost");
    let raw = http_send(
        addr,
        &format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host_header}\r\n\
             Connection: close\r\n\r\n"
        ),
    );

    (parse_status(&raw), parse_body(&raw))
}

/// Send an HTTP POST and return `(status, body)`.
pub fn http_post(addr: &str, path: &str, body: &str) -> (u16, String) {
    let raw = http_send(
        addr,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    );

    (parse_status(&raw), parse_body(&raw))
}

// -----------------------------------------------------------------------------
// Response Parsing
// -----------------------------------------------------------------------------

/// Parse the status code from a raw HTTP response string.
pub fn parse_status(raw: &str) -> u16 {
    raw.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// Parse the body from a raw HTTP response string.
///
/// Handles both plain and chunked
/// (`Transfer-Encoding: chunked`) responses so that
/// assertions do not silently pass with chunk-size lines
/// mixed into the body.
pub fn parse_body(raw: &str) -> String {
    let Some((headers_part, body_part)) = raw.split_once("\r\n\r\n") else {
        return String::new();
    };

    let is_chunked = headers_part.lines().any(|line| {
        let lower = line.to_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });

    if is_chunked {
        decode_chunked(body_part)
    } else {
        body_part.to_owned()
    }
}

/// Decode an HTTP/1.1 chunked-encoded body into a plain
/// string.
pub fn decode_chunked(body: &str) -> String {
    let mut result = String::new();
    let mut remaining = body;

    loop {
        let Some(crlf) = remaining.find("\r\n") else {
            break;
        };

        let size_hex = remaining[..crlf].trim();
        let size = usize::from_str_radix(size_hex, 16).unwrap_or(0);
        remaining = &remaining[crlf + 2..];

        if size == 0 {
            break;
        }

        if remaining.len() < size {
            break;
        }

        result.push_str(&remaining[..size]);
        remaining = &remaining[size..];

        if remaining.starts_with("\r\n") {
            remaining = &remaining[2..];
        }
    }

    result
}

/// Extract a response header value by name
/// (case-insensitive). Returns `None` if absent.
pub fn parse_header(raw: &str, name: &str) -> Option<String> {
    let headers_part = raw.split_once("\r\n\r\n")?.0;
    let lower_name = name.to_lowercase();
    headers_part.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().to_lowercase() == lower_name {
            Some(value.trim().to_owned())
        } else {
            None
        }
    })
}
