// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Lightweight HTTP client for integration tests.

use std::{
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};

// -----------------------------------------------------------------------------
// Raw Request / Response
// -----------------------------------------------------------------------------

/// Connect, send an already-formatted HTTP request, and return the raw response.
///
/// # Panics
///
/// Panics if the TCP connection or write fails.
pub fn http_send(addr: &str, request: &str) -> String {
    let mut stream = tcp_connect(addr);

    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(request.as_bytes()).unwrap();

    let mut response = String::new();
    let _bytes = stream.read_to_string(&mut response);

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

/// Send an HTTP GET, retrying up to 3 times on 5xx responses.
pub fn http_get_retry(addr: &str, path: &str, host: Option<&str>) -> (u16, String) {
    for _ in 0..2 {
        let (status, body) = http_get(addr, path, host);
        if status < 500 {
            return (status, body);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    http_get(addr, path, host)
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
// IPv6 Wrappers
// -----------------------------------------------------------------------------

/// Send an HTTP GET to an IPv6 address and return `(status, body)`.
pub fn http_get_v6(addr: &str, path: &str) -> (u16, String) {
    let raw = http_send(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    );
    (parse_status(&raw), parse_body(&raw))
}

/// Build a raw HTTP POST request with `Content-Type: application/json`.
///
/// Returns a fully formatted HTTP/1.1 request string ready to pass to [`http_send`].
///
/// ```
/// # use praxis_test_utils::json_post;
/// let req = json_post("/v1/chat", r#"{"model":"test"}"#);
/// assert!(req.starts_with("POST /v1/chat HTTP/1.1\r\n"));
/// assert!(req.contains("Content-Type: application/json"));
/// ```
///
/// [`http_send`]: crate::net::http_client::http_send
pub fn json_post(path: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    )
}

// -----------------------------------------------------------------------------
// Connection Utilities
// -----------------------------------------------------------------------------

/// Connect to `addr` with short retries on transient failures.
///
/// Retries up to 20 times (1 s total) before a final attempt that
/// panics on failure. Guards against brief accept-queue gaps that
/// can occur in CI after [`wait_for_http`] returns.
///
/// [`wait_for_http`]: crate::net::wait::wait_for_http
fn tcp_connect(addr: &str) -> TcpStream {
    for _ in 0..20 {
        if let Ok(stream) = TcpStream::connect(addr) {
            return stream;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    TcpStream::connect(addr).unwrap()
}

// -----------------------------------------------------------------------------
// Response Parsing
// -----------------------------------------------------------------------------

/// Parse the status code from a raw HTTP response string.
pub fn parse_status(raw: &str) -> u16 {
    raw.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// Parse the body from a raw HTTP response string.
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

    while let Some(crlf) = remaining.find("\r\n") {
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

/// Extract a response header value by name (case-insensitive).
///
/// Returns `None` if absent.
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

/// Extract all values for a response header by name (case-insensitive).
///
/// Returns an empty `Vec` if no matching headers are found. Useful for
/// headers like `Set-Cookie` that appear multiple times and must not be folded.
///
/// ```
/// # use praxis_test_utils::parse_header_all;
/// let raw = "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nbody";
/// let cookies = parse_header_all(raw, "set-cookie");
/// assert_eq!(cookies, vec!["a=1", "b=2"]);
/// ```
pub fn parse_header_all(raw: &str, name: &str) -> Vec<String> {
    let Some(headers_part) = raw.split_once("\r\n\r\n").map(|(h, _)| h) else {
        return Vec::new();
    };
    let lower_name = name.to_lowercase();
    headers_part
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            if key.trim().to_lowercase() == lower_name {
                Some(value.trim().to_owned())
            } else {
                None
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn parse_status_valid_http11() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(parse_status(raw), 200, "should extract 200 from status line");
    }

    #[test]
    fn parse_status_not_found() {
        let raw = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(parse_status(raw), 404, "should extract 404 from status line");
    }

    #[test]
    fn parse_status_empty_returns_zero() {
        assert_eq!(parse_status(""), 0, "empty input should produce status 0");
    }

    #[test]
    fn parse_body_extracts_after_separator() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nbody content";
        assert_eq!(parse_body(raw), "body content", "should extract body after blank line");
    }

    #[test]
    fn parse_body_no_separator_returns_empty() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 0";
        assert_eq!(parse_body(raw), "", "no CRLFCRLF separator should yield empty body");
    }

    #[test]
    fn decode_chunked_valid() {
        let input = "5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(input), "hello", "single chunk should decode correctly");
    }

    #[test]
    fn decode_chunked_multiple_chunks() {
        let input = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(
            decode_chunked(input),
            "hello world",
            "multiple chunks should concatenate"
        );
    }

    #[test]
    fn parse_header_found() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody";
        assert_eq!(
            parse_header(raw, "Content-Type"),
            Some("text/plain".to_owned()),
            "should find Content-Type header"
        );
    }

    #[test]
    fn parse_header_case_insensitive() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody";
        assert_eq!(
            parse_header(raw, "content-type"),
            Some("text/plain".to_owned()),
            "header lookup should be case-insensitive"
        );
    }

    #[test]
    fn parse_header_missing() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody";
        assert_eq!(parse_header(raw, "X-Missing"), None, "absent header should return None");
    }

    #[test]
    fn parse_header_all_multiple() {
        let raw = "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nbody";
        let values = parse_header_all(raw, "Set-Cookie");
        assert_eq!(values.len(), 2, "should find both Set-Cookie headers");
        assert_eq!(values[0], "a=1", "first cookie value");
        assert_eq!(values[1], "b=2", "second cookie value");
    }

    #[test]
    fn parse_header_all_none() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody";
        let values = parse_header_all(raw, "X-Missing");
        assert!(values.is_empty(), "no matching headers should yield empty vec");
    }
}
