// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Bounded wire test utilities that distinguish a completed response from timeout.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Deadline for each blocking socket operation in an attack fixture.
pub(super) const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum raw response retained by these small attack fixtures.
const MAX_RESPONSE_BYTES: u64 = 2_097_152; // 2 MiB

/// Connect with bounded reads and writes.
pub(super) fn connect(addr: &str) -> TcpStream {
    let mut addresses = std::net::ToSocketAddrs::to_socket_addrs(&addr).unwrap();
    let address = addresses.next().expect("proxy address");
    let stream = TcpStream::connect_timeout(&address, IO_TIMEOUT).expect("connect to proxy");
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    stream
}

/// Read through EOF, failing on timeout, truncation errors, or excessive output.
pub(super) fn read_closed(stream: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut response)
        .expect("response must end before timeout");
    assert!(
        u64::try_from(response.len()).unwrap() <= MAX_RESPONSE_BYTES,
        "response exceeded fixture bound"
    );
    response
}

/// Send a Connection-close request and preserve the response's binary bytes.
pub(super) fn send_bytes(addr: &str, request: &str) -> Vec<u8> {
    let mut stream = connect(addr);
    stream.write_all(request.as_bytes()).expect("send attack request");
    read_closed(&mut stream)
}

/// Send a Connection-close request whose complete response must be UTF-8.
pub(super) fn send_text(addr: &str, request: &str) -> String {
    String::from_utf8(send_bytes(addr, request)).expect("text response must be UTF-8")
}

/// Count response frames in fixtures whose bodies cannot contain a status line.
pub(super) fn status_lines(raw: &str) -> usize {
    raw.match_indices("HTTP/1.").count()
}
