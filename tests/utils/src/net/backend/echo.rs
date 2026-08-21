// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Echo backends that reflect request data back in
//! the response.

use std::{net::TcpStream, time::Duration};

use super::specialized::{
    BackendGuard, parse_content_length, read_until_headers_complete, spawn_tcp_server_with_shutdown,
    write_http_response,
};

// -----------------------------------------------------------------------------
// Echo Backends
// -----------------------------------------------------------------------------

/// Start a mock backend that echoes the request body back
/// as the response body.
///
/// Returns a [`BackendGuard`] that shuts down the listener
/// thread when dropped.
///
/// # Panics
///
/// Panics if the server fails to bind or accept connections.
pub fn start_echo_backend() -> BackendGuard {
    spawn_tcp_server_with_shutdown(|mut stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let body = read_request_body(&mut stream);
        let _sent = write_http_response(&mut stream, &body);
    })
}

/// Start a backend that echoes the request URI (path and query)
/// as the response body.
///
/// Returns a [`BackendGuard`] that shuts down the listener
/// thread when dropped.
///
/// # Panics
///
/// Panics if the server fails to bind or accept connections.
pub fn start_uri_echo_backend() -> BackendGuard {
    spawn_tcp_server_with_shutdown(|mut stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let raw = read_until_headers_complete(&mut stream);
        let uri = raw
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/")
            .to_owned();
        let _sent = write_http_response(&mut stream, &uri);
    })
}

/// Start a backend that echoes request headers as the
/// response body (one per line).
///
/// Returns a [`BackendGuard`] that shuts down the listener
/// thread when dropped.
///
/// # Panics
///
/// Panics if the server fails to bind or accept connections.
pub fn start_header_echo_backend() -> BackendGuard {
    spawn_tcp_server_with_shutdown(|mut stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let raw = read_until_headers_complete(&mut stream);

        let headers: String = raw
            .lines()
            .skip(1)
            .take_while(|l| !l.is_empty())
            .fold(String::new(), |mut acc, line| {
                if !acc.is_empty() {
                    acc.push('\n');
                }
                acc.push_str(line);
                acc
            });

        let _sent = write_http_response(&mut stream, &headers);
    })
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Read a complete HTTP request body from a raw TCP stream.
///
/// Understands both Content-Length and chunked transfer framing, so
/// echo assertions verify the semantic body regardless of how the
/// proxy framed the forwarded request.
fn read_request_body(stream: &mut TcpStream) -> String {
    use std::io::Read as _;

    let mut data = Vec::new();
    let mut buf = [0_u8; 4096];

    loop {
        let raw = String::from_utf8_lossy(&data).into_owned();
        if let Some(body) = raw.split_once("\r\n\r\n").and_then(|(h, rest)| complete_body(h, rest)) {
            return body;
        }
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
    }

    let raw = String::from_utf8_lossy(&data);
    raw.split_once("\r\n\r\n")
        .map(|(header_section, rest)| {
            if is_chunked_request(header_section) {
                decode_chunked_body(rest)
            } else {
                rest.to_owned()
            }
        })
        .unwrap_or_default()
}

/// Return the decoded body when the framing shows all bytes have arrived.
fn complete_body(header_section: &str, rest: &str) -> Option<String> {
    if is_chunked_request(header_section) {
        let terminated = rest.ends_with("\r\n\r\n") && (rest.starts_with("0\r\n") || rest.contains("\r\n0\r\n"));
        terminated.then(|| decode_chunked_body(rest))
    } else {
        let content_length = parse_content_length(header_section);
        (rest.len() >= content_length).then(|| rest.get(..content_length).unwrap_or(rest).to_owned())
    }
}

/// Whether the request header section declares chunked transfer framing.
fn is_chunked_request(header_section: &str) -> bool {
    header_section.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value.trim().to_ascii_lowercase().ends_with("chunked")
        })
    })
}

/// Decode a chunked-framed body into its payload bytes.
fn decode_chunked_body(mut rest: &str) -> String {
    let mut out = String::new();
    while let Some((size_line, tail)) = rest.split_once("\r\n") {
        let size = size_line
            .split(';')
            .next()
            .and_then(|s| usize::from_str_radix(s.trim(), 16).ok())
            .unwrap_or(0);
        if size == 0 || tail.len() < size {
            break;
        }
        out.push_str(tail.get(..size).unwrap_or(""));
        rest = tail.get(size..).map_or("", |t| t.strip_prefix("\r\n").unwrap_or(t));
    }
    out
}
