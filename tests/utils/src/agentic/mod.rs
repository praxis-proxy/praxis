// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Agentic protocol mock servers for integration tests.
//!
//! Provides deterministic MCP and A2A backends that record
//! inbound requests for assertion in integration tests.

pub mod a2a;
pub mod mcp;

pub use a2a::{
    A2aMockConfig, A2aMockServerGuard, A2aRecordedRequest, start_a2a_mock_server, start_a2a_mock_server_with_config,
};
pub use mcp::{
    McpMockConfig, McpMockServerGuard, McpRecordedRequest, McpToolFixture, start_mcp_mock_server,
    start_mcp_mock_server_with_config,
};

// -----------------------------------------------------------------------------
// Path Validation
// -----------------------------------------------------------------------------

/// Rejects paths that are not plain absolute paths
/// (no query, fragment, scheme, or authority).
///
/// # Panics
///
/// Panics if the path is malformed for use as a mock
/// endpoint.
fn validate_config_path(path: &str) {
    assert!(
        path.starts_with('/'),
        "mock config path must start with '/', got: {path}"
    );
    assert!(
        !path.starts_with("//"),
        "mock config path must not contain an authority (//), got: {path}"
    );
    assert!(
        !path.contains('?'),
        "mock config path must not contain a query string, got: {path}"
    );
    assert!(
        !path.contains('#'),
        "mock config path must not contain a fragment, got: {path}"
    );
    assert!(
        !path.contains("://"),
        "mock config path must not contain a scheme, got: {path}"
    );
    assert!(
        !path.contains(|c: char| c.is_whitespace() || c.is_control()),
        "mock config path must not contain whitespace or control characters, got: {path}"
    );
}

// -----------------------------------------------------------------------------
// Shared HTTP Parsing
// -----------------------------------------------------------------------------

/// Internal module providing lightweight HTTP request
/// parsing shared by both MCP and A2A mock servers.
pub(super) mod http {
    use std::{
        io::{Read, Write},
        net::TcpStream,
    };

    /// Parsed HTTP request used by agentic mock servers.
    pub(crate) struct AgenticHttpRequest {
        /// Raw request body.
        pub(crate) body: String,

        /// Request headers as `(lowercase-name, value)` pairs.
        pub(crate) headers: Vec<(String, String)>,

        /// HTTP method (e.g. `POST`, `DELETE`).
        pub(crate) method: String,

        /// URL path without query string.
        pub(crate) path: String,

        /// Full request URI including query string.
        pub(crate) uri: String,
    }

    impl AgenticHttpRequest {
        /// Case-insensitive header value lookup.
        pub(crate) fn header_value(&self, name: &str) -> Option<String> {
            let lower = name.to_lowercase();
            self.headers.iter().find(|(k, _)| k == &lower).map(|(_, v)| v.clone())
        }
    }

    /// Parse an HTTP request from a TCP stream.
    ///
    /// Returns `None` if the stream yields no usable data.
    pub(crate) fn parse_agentic_request(stream: &mut TcpStream) -> Option<AgenticHttpRequest> {
        let data = read_with_body(stream)?;
        let (head, body) = split_and_slice_body(&data);

        let mut lines = head.lines();
        let request_line = lines.next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?.to_owned();
        let uri = parts.next()?.to_owned();

        let path = uri.split_once('?').map_or(uri.as_str(), |(p, _)| p).to_owned();

        let headers: Vec<(String, String)> = lines
            .filter_map(|line| {
                let (key, value) = line.split_once(':')?;
                Some((key.trim().to_lowercase(), value.trim().to_owned()))
            })
            .collect();

        Some(AgenticHttpRequest {
            body,
            headers,
            method,
            path,
            uri,
        })
    }

    /// Write a complete HTTP response to a TCP stream.
    pub(crate) fn write_response(
        stream: &mut TcpStream,
        status: u16,
        reason: &str,
        headers: &[(&str, String)],
        body: &str,
    ) {
        let mut resp = format!("HTTP/1.1 {status} {reason}\r\n");

        for (name, value) in headers {
            use std::fmt::Write as FmtWrite;
            let _written = write!(resp, "{name}: {value}\r\n");
        }

        if !body.is_empty() {
            use std::fmt::Write as FmtWrite;
            let _written = write!(resp, "Content-Length: {}\r\n", body.len());
        }

        resp.push_str("Connection: close\r\n\r\n");
        resp.push_str(body);

        let _sent = stream.write_all(resp.as_bytes());
    }

    /// Slice body bytes to exactly `Content-Length`
    /// before UTF-8 decoding to avoid panics on
    /// multi-byte boundaries. `Content-Length: 0`
    /// produces an empty body, not "read all remaining."
    fn split_and_slice_body(data: &[u8]) -> (String, String) {
        let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") else {
            return (String::from_utf8_lossy(data).into_owned(), String::new());
        };

        let head = String::from_utf8_lossy(&data[..pos]).into_owned();
        let body_start = pos + 4;
        let remaining = data.len() - body_start;

        let body_len = parse_content_length(&head).unwrap_or(remaining);
        let body_end = body_start + body_len.min(remaining);

        let body = String::from_utf8_lossy(&data[body_start..body_end]).into_owned();
        (head, body)
    }

    /// Read headers + `Content-Length` bytes from a TCP
    /// stream, returned as raw bytes.
    fn read_with_body(stream: &mut TcpStream) -> Option<Vec<u8>> {
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];

        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => data.extend_from_slice(&buf[..n]),
            }

            if let Some(header_end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                let header_section = String::from_utf8_lossy(&data[..header_end]);
                let cl = parse_content_length(&header_section).unwrap_or(0);
                if data.len() >= header_end + 4 + cl {
                    break;
                }
            }
        }

        if data.is_empty() {
            return None;
        }

        Some(data)
    }

    /// `Some(n)` when `Content-Length` is present;
    /// `None` when the header is absent, so callers
    /// can distinguish "no header" from "zero."
    fn parse_content_length(headers: &str) -> Option<usize> {
        headers
            .lines()
            .find(|l| l.to_lowercase().starts_with("content-length:"))
            .and_then(|l| l.split_once(':').map(|(_, v)| v))
            .and_then(|v| v.trim().parse().ok())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::validate_config_path;

    #[test]
    fn validate_config_path_valid() {
        validate_config_path("/foo/bar");
    }

    #[test]
    #[should_panic(expected = "must start with '/'")]
    fn validate_config_path_no_leading_slash() {
        validate_config_path("foo");
    }

    #[test]
    #[should_panic(expected = "must not contain an authority")]
    fn validate_config_path_double_slash() {
        validate_config_path("//foo");
    }

    #[test]
    #[should_panic(expected = "must not contain a query string")]
    fn validate_config_path_query_string() {
        validate_config_path("/foo?bar");
    }

    #[test]
    #[should_panic(expected = "must not contain a fragment")]
    fn validate_config_path_fragment() {
        validate_config_path("/foo#bar");
    }

    #[test]
    #[should_panic(expected = "must not contain a scheme")]
    fn validate_config_path_scheme() {
        validate_config_path("/foo://bar");
    }
}
