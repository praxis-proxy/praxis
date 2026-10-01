// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Test utilities for driving concurrent HTTP/1.1 load at a proxy.
//!
//! Clients are plain threads over raw sockets so every connection, reuse,
//! and close is explicit, which descriptor accounting tests depend on.

use std::{
    collections::BTreeMap,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::TcpStream,
    sync::{Arc, Barrier},
    time::Duration,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Per-socket read and write timeout for load clients.
const IO_TIMEOUT: Duration = Duration::from_secs(20);

/// Read timeout for requests held in flight by [`open_requests`], whose
/// backends answer within seconds when the proxy admits them at all.
const IN_FLIGHT_TIMEOUT: Duration = Duration::from_secs(5);

// -----------------------------------------------------------------------------
// LoadReport
// -----------------------------------------------------------------------------

/// Outcome counts for a batch of requests.
#[derive(Debug, Default)]
pub struct LoadReport {
    /// Transport failures (refused, reset, timed out, or malformed), with the
    /// error text.
    pub failures: Vec<String>,

    /// Response count by status code.
    pub statuses: BTreeMap<u16, usize>,
}

impl LoadReport {
    /// Responses with `status`.
    pub fn count(&self, status: u16) -> usize {
        self.statuses.get(&status).copied().unwrap_or(0)
    }

    /// Total requests attempted.
    pub fn total(&self) -> usize {
        self.statuses.values().sum::<usize>() + self.failures.len()
    }

    /// Whether every request got a response with one of `allowed`.
    pub fn only(&self, allowed: &[u16]) -> bool {
        self.failures.is_empty() && self.statuses.keys().all(|status| allowed.contains(status))
    }

    /// Merge another report into this one.
    fn absorb(&mut self, other: Self) {
        self.failures.extend(other.failures);
        for (status, count) in other.statuses {
            *self.statuses.entry(status).or_default() += count;
        }
    }
}

// -----------------------------------------------------------------------------
// Load
// -----------------------------------------------------------------------------

/// Run `clients` concurrent clients against `addr`, each sending
/// `requests_per_client` `GET path` requests, starting together.
///
/// With `keep_alive`, a client reuses its connection until the proxy closes
/// it and then reconnects; otherwise every request uses a new connection.
///
/// # Panics
///
/// Panics if a client thread panics.
pub fn concurrent_gets(
    addr: &str,
    path: &str,
    clients: usize,
    requests_per_client: usize,
    keep_alive: bool,
) -> LoadReport {
    let barrier = Arc::new(Barrier::new(clients));
    let handles: Vec<_> = std::iter::repeat_with(|| {
        let barrier = Arc::clone(&barrier);
        let addr = addr.to_owned();
        let path = path.to_owned();
        std::thread::spawn(move || {
            barrier.wait();
            run_client(&addr, &path, requests_per_client, keep_alive)
        })
    })
    .take(clients)
    .collect();

    let mut report = LoadReport::default();
    for handle in handles {
        report.absorb(handle.join().expect("load client thread"));
    }
    report
}

/// Open `count` connections to `addr` and send one `GET path` on each
/// without reading the responses, so every exchange stays in flight.
///
/// # Panics
///
/// Panics if a connection cannot be opened or written.
pub fn open_requests(addr: &str, path: &str, count: usize) -> Vec<TcpStream> {
    std::iter::repeat_with(|| {
        let mut stream = TcpStream::connect(addr).expect("connect");
        stream.set_read_timeout(Some(IN_FLIGHT_TIMEOUT)).expect("read timeout");
        stream.write_all(request(path, true).as_bytes()).expect("write request");
        stream
    })
    .take(count)
    .collect()
}

/// Open `count` keep-alive connections to `addr`, complete one `GET path` on
/// each, and return them still open and idle.
///
/// # Panics
///
/// Panics if a connection cannot be opened or its request fails.
pub fn idle_keepalive_connections(addr: &str, path: &str, count: usize) -> Vec<TcpStream> {
    std::iter::repeat_with(|| {
        let mut conn = None;
        let status = send(addr, path, true, &mut conn).expect("keep-alive request");
        assert_eq!(status, 200, "warm-up request on an idle keep-alive connection");
        conn.expect("the proxy kept the connection alive").into_inner()
    })
    .take(count)
    .collect()
}

/// Whether the peer has closed `stream`, without blocking.
///
/// # Panics
///
/// Panics if the socket mode cannot be changed.
pub fn is_closed_by_peer(stream: &TcpStream) -> bool {
    stream.set_nonblocking(true).expect("nonblocking");
    let mut probe = [0_u8; 1];
    let closed = match stream.peek(&mut probe) {
        Ok(read) => read == 0,
        Err(err) => err.kind() != std::io::ErrorKind::WouldBlock,
    };
    stream.set_nonblocking(false).expect("blocking");
    closed
}

/// Read each of `streams` to its end, returning the raw response text and
/// whether the peer closed the connection (rather than the read timing out).
pub fn read_raw_responses(streams: Vec<TcpStream>) -> Vec<(String, bool)> {
    streams
        .into_iter()
        .map(|mut stream| {
            let mut raw = Vec::new();
            let closed = stream.read_to_end(&mut raw).is_ok();
            (String::from_utf8_lossy(&raw).into_owned(), closed)
        })
        .collect()
}

/// Read one response from each of `streams` into a report.
pub fn collect_responses(streams: Vec<TcpStream>) -> LoadReport {
    let mut report = LoadReport::default();
    for stream in streams {
        match read_response(&mut BufReader::new(stream)) {
            Ok((status, _)) => *report.statuses.entry(status).or_default() += 1,
            Err(err) => report.failures.push(err),
        }
    }
    report
}

// -----------------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------------

/// One client's sequential requests.
fn run_client(addr: &str, path: &str, requests: usize, keep_alive: bool) -> LoadReport {
    let mut report = LoadReport::default();
    let mut conn: Option<BufReader<TcpStream>> = None;
    for _ in 0..requests {
        let outcome = send(addr, path, keep_alive, &mut conn);
        match outcome {
            Ok(status) => *report.statuses.entry(status).or_default() += 1,
            Err(err) => {
                conn = None;
                report.failures.push(err);
            },
        }
    }
    report
}

/// Send one request, reusing `conn` when open, and keep it open only when
/// both sides allow reuse.
fn send(addr: &str, path: &str, keep_alive: bool, conn: &mut Option<BufReader<TcpStream>>) -> Result<u16, String> {
    let mut reader = if let Some(reader) = conn.take() {
        reader
    } else {
        let stream = TcpStream::connect(addr).map_err(|err| format!("connect: {err}"))?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|err| err.to_string())?;
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(|err| err.to_string())?;
        BufReader::new(stream)
    };
    reader
        .get_mut()
        .write_all(request(path, !keep_alive).as_bytes())
        .map_err(|err| format!("write: {err}"))?;
    let (status, reusable) = read_response(&mut reader)?;
    if keep_alive && reusable {
        *conn = Some(reader);
    }
    Ok(status)
}

/// An HTTP/1.1 `GET` for `path`, asking to close when `close` is set.
fn request(path: &str, close: bool) -> String {
    let connection = if close { "close" } else { "keep-alive" };
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: {connection}\r\n\r\n")
}

/// Read one response, returning its status and whether the connection may
/// carry another request.
fn read_response(reader: &mut BufReader<TcpStream>) -> Result<(u16, bool), String> {
    let status = read_status(reader)?;
    let framing = read_headers(reader)?;
    if framing.chunked {
        read_chunked(reader)?;
        Ok((status, !framing.close))
    } else if let Some(length) = framing.content_length {
        let mut body = vec![0_u8; length];
        reader
            .read_exact(&mut body)
            .map_err(|err| format!("read body: {err}"))?;
        Ok((status, !framing.close))
    } else {
        let mut body = Vec::new();
        reader
            .read_to_end(&mut body)
            .map_err(|err| format!("read body: {err}"))?;
        Ok((status, false))
    }
}

/// How a response body is delimited and whether the connection closes.
#[derive(Default)]
struct Framing {
    /// `Transfer-Encoding: chunked`.
    chunked: bool,

    /// `Connection: close`.
    close: bool,

    /// `Content-Length`, when present.
    content_length: Option<usize>,
}

/// Read the status line and return the status code.
fn read_status(reader: &mut BufReader<TcpStream>) -> Result<u16, String> {
    let mut status_line = String::new();
    let read = reader
        .read_line(&mut status_line)
        .map_err(|err| format!("read status: {err}"))?;
    if read == 0 {
        return Err("connection closed before a response".to_owned());
    }
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("malformed status line: {status_line:?}"))
}

/// Read headers through the blank line, keeping only framing.
fn read_headers(reader: &mut BufReader<TcpStream>) -> Result<Framing, String> {
    let mut framing = Framing::default();
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|err| format!("read header: {err}"))?;
        let Some((name, value)) = line.trim_end().split_once(':') else {
            return Ok(framing);
        };
        let value = value.trim().to_ascii_lowercase();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => framing.content_length = value.parse::<usize>().ok(),
            "transfer-encoding" => framing.chunked = value.contains("chunked"),
            "connection" => framing.close = value.contains("close"),
            _ => {},
        }
    }
}

/// Consume a chunked body up to and including its terminating chunk.
fn read_chunked(reader: &mut BufReader<TcpStream>) -> Result<(), String> {
    loop {
        let mut size_line = String::new();
        reader
            .read_line(&mut size_line)
            .map_err(|err| format!("read chunk size: {err}"))?;
        let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or(""), 16)
            .map_err(|err| format!("malformed chunk size {size_line:?}: {err}"))?;
        let mut chunk = vec![0_u8; size + 2];
        reader
            .read_exact(&mut chunk)
            .map_err(|err| format!("read chunk: {err}"))?;
        if size == 0 {
            return Ok(());
        }
    }
}
