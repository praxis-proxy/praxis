// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Bounded request-recording HTTP/1 test utilities.

use std::{
    io::{self, BufReader, Write as _},
    net::TcpStream,
    sync::{Arc, Mutex},
    time::Duration,
};

use super::specialized::{BackendGuard, spawn_tcp_server_with_shutdown};
use crate::net::http1::{framing, read_body, read_head};

/// Maximum body retained by the recording backend.
const MAX_RECORDED_BODY: u64 = 1_048_576; // 1 MiB

/// A complete request received by a recording backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedRequest {
    /// Request content after decoding transfer framing.
    pub body: Vec<u8>,
    /// Lowercase header names and their trimmed values.
    pub headers: Vec<(String, String)>,
    /// Method, request target, and HTTP version from the wire.
    pub request_line: String,
}

/// Complete requests in the order the backend finished reading them.
pub type RequestLog = Arc<Mutex<Vec<RecordedRequest>>>;

/// Start an HTTP/1 backend that records the complete request before responding.
///
/// `respond` supplies a raw HTTP response and may synchronize backend attempts.
/// Fixed-length and chunked request bodies are decoded with a 1 MiB limit.
/// Invalid or incomplete requests close without producing a log entry.
///
/// # Panics
///
/// Panics if the listener cannot bind or the request log is poisoned.
pub fn start_recording_backend<F>(respond: F) -> (BackendGuard, RequestLog)
where
    F: Fn(&RecordedRequest) -> Vec<u8> + Send + Sync + 'static,
{
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&log);
    let respond = Arc::new(respond);
    let guard = spawn_tcp_server_with_shutdown(move |mut stream| {
        if let Ok(request) = record_request(&mut stream) {
            seen.lock().expect("recording backend lock").push(request.clone());
            let _sent = stream.write_all(&respond(&request));
        }
    });
    (guard, log)
}

/// Read and decode one bounded HTTP/1 request.
fn record_request(stream: &mut TcpStream) -> io::Result<RecordedRequest> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream);
    let head = read_head(&mut reader)?;
    let mut body = Vec::new();
    let mut count = 0;
    read_body(
        &mut reader,
        framing(&head.headers, false)?,
        MAX_RECORDED_BODY,
        &mut |chunk| {
            body.extend_from_slice(chunk);
            Ok(())
        },
        &mut count,
    )?;
    Ok(RecordedRequest {
        body,
        headers: head.headers,
        request_line: head.start,
    })
}
