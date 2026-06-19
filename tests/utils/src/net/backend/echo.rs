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

/// Read a complete HTTP request body from a raw TCP stream,
/// using Content-Length to determine when all bytes have arrived.
fn read_request_body(stream: &mut TcpStream) -> String {
    use std::io::Read as _;

    let mut data = Vec::new();
    let mut buf = [0_u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }

        let raw = String::from_utf8_lossy(&data);
        if let Some(header_section) = raw.split("\r\n\r\n").next() {
            let content_length = parse_content_length(header_section);
            let header_len = header_section.len() + 4;
            if data.len() >= header_len + content_length {
                break;
            }
        }
    }

    let raw = String::from_utf8_lossy(&data);
    raw.split("\r\n\r\n").nth(1).unwrap_or("").to_owned()
}
