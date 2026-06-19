// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Readiness check utilities for integration tests.

use std::{net::TcpStream, time::Duration};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// HTTP/2 connection preface ([RFC 9113 Section 3.4]).
///
/// [RFC 9113 Section 3.4]: https://datatracker.ietf.org/doc/html/rfc9113#section-3.4
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Empty SETTINGS frame: length=0, type=0x04, flags=0, stream=0.
const SETTINGS: &[u8] = &[0, 0, 0, 4, 0, 0, 0, 0, 0];

/// SETTINGS ACK frame: length=0, type=0x04, flags=0x01 (ACK), stream=0.
const SETTINGS_ACK: &[u8] = &[0, 0, 0, 4, 1, 0, 0, 0, 0];

/// GOAWAY frame: `length=8`, `type=0x07`, `flags=0`, `stream=0`,
/// `last_stream_id=0`, `error_code=0` (`NO_ERROR`).
const GOAWAY: &[u8] = &[0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

// -----------------------------------------------------------------------------
// Readiness Checks
// -----------------------------------------------------------------------------

/// Block until a TCP connection to `addr` succeeds, or panic after 2 seconds.
///
/// # Panics
///
/// Panics if the server does not become ready within 2 seconds.
pub fn wait_for_tcp(addr: &str) {
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server at {addr} did not become ready within 2s");
}

/// Block until an HTTP request to `addr` gets a valid response, or panic after 5 seconds.
///
/// # Panics
///
/// Panics if the server does not become ready within 5 seconds.
pub fn wait_for_http(addr: &str) {
    use std::io::{Read as _, Write as _};

    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    for _ in 0..500 {
        if let Ok(mut stream) = TcpStream::connect(addr) {
            drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
            drop(stream.set_write_timeout(Some(Duration::from_secs(2))));
            if stream.write_all(request).is_ok() {
                let mut buf = [0_u8; 16];
                if let Ok(n) = stream.read(&mut buf)
                    && n >= 5
                    && buf.starts_with(b"HTTP/")
                {
                    let mut drain = [0_u8; 4096];
                    while stream.read(&mut drain).unwrap_or(0) > 0 {}
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("HTTP server at {addr} did not become ready within 5s");
}

/// Block until a full HTTP/2 handshake with `addr` completes, or panic after 5 seconds.
///
/// # Panics
///
/// Panics if the server does not become ready within 5 seconds.
pub fn wait_for_http2(addr: &str) {
    use std::io::{Read as _, Write as _};

    for _ in 0..500 {
        if let Ok(mut stream) = TcpStream::connect(addr) {
            drop(stream.set_read_timeout(Some(Duration::from_secs(1))));
            drop(stream.set_write_timeout(Some(Duration::from_secs(1))));
            if stream.write_all(PREFACE).is_ok() && stream.write_all(SETTINGS).is_ok() {
                let mut buf = [0_u8; 64];
                if let Ok(n) = stream.read(&mut buf)
                    && n >= 9
                    && buf[3] == 0x04
                {
                    let _ack = stream.write_all(SETTINGS_ACK);
                    let _goaway = stream.write_all(GOAWAY);
                    let mut drain = [0_u8; 256];
                    while stream.read(&mut drain).unwrap_or(0) > 0 {}
                    drop(stream);
                    std::thread::sleep(Duration::from_millis(100));
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("HTTP/2 server at {addr} did not become ready within 5s");
}
