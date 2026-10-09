// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Raw HTTP backends for integration tests that need precise wire behavior.

use std::{
    io::Read as _,
    net::TcpStream,
    thread::{self, JoinHandle},
};

/// Start a one-request backend with direct control of its TCP response.
///
/// Returns the listener port and a thread that exits after one accepted
/// connection is handled.
///
/// # Panics
///
/// Panics if binding or accepting the backend connection fails.
pub fn spawn_raw_http_backend<F>(handler: F) -> (u16, JoinHandle<()>)
where
    F: FnOnce(TcpStream) + Send + 'static,
{
    // Through the shared allocator so the port joins the process-wide set:
    // an ephemeral bind can otherwise land on a port `free_port` already
    // handed out, and a test treating that port as a dead backend then
    // reaches this one.
    let (listener, port) = crate::net::port::bind_unique_port();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept raw HTTP backend request");
        handler(stream);
    });
    (port, handle)
}

/// Read one complete HTTP/1 request, including its declared fixed-length body.
///
/// This is intended for tests whose raw backend must consume the request before
/// writing or deliberately truncating its response.
///
/// # Panics
///
/// Panics if the peer closes before the headers or declared body are complete.
pub fn read_http_request(stream: &mut TcpStream) {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        let count = stream.read(&mut buffer).expect("read HTTP request headers");
        assert_ne!(count, 0, "HTTP request ended before its headers");
        request.extend_from_slice(&buffer[..count]);
    };
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let body_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    while request.len() < header_end + body_length {
        let count = stream.read(&mut buffer).expect("read HTTP request body");
        assert_ne!(count, 0, "HTTP request body ended before Content-Length");
        request.extend_from_slice(&buffer[..count]);
    }
}
