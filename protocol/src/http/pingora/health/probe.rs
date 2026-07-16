// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Health check probe functions for HTTP, HTTP/2, and TCP endpoints.

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};
use tracing::trace;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// HTTP/2 connection preface ([RFC 9113 Section 3.4]).
///
/// [RFC 9113 Section 3.4]: https://datatracker.ietf.org/doc/html/rfc9113#section-3.4
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Empty SETTINGS frame: length=0, type=0x04, flags=0, stream=0.
const H2_SETTINGS: &[u8] = &[0, 0, 0, 4, 0, 0, 0, 0, 0];

/// SETTINGS ACK frame: length=0, type=0x04, flags=0x01 (ACK), stream=0.
const H2_SETTINGS_ACK: &[u8] = &[0, 0, 0, 4, 1, 0, 0, 0, 0];

/// GOAWAY frame: `length=8`, `type=0x07`, `flags=0`, `stream=0`,
/// `last_stream_id=0`, `error_code=0` (`NO_ERROR`).
const H2_GOAWAY: &[u8] = &[0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// H2 frame type for SETTINGS frames.
const H2_FRAME_TYPE_SETTINGS: u8 = 0x04;

/// Minimum H2 frame header size (9 bytes).
const H2_FRAME_HEADER_LEN: usize = 9;

// -----------------------------------------------------------------------------
// HTTP Probe
// -----------------------------------------------------------------------------

/// Probe an endpoint with a raw HTTP/1.1 GET request.
///
/// ```ignore
/// # async fn example() {
/// use std::time::Duration;
///
/// use praxis_protocol::http::pingora::health::probe::http_probe;
///
/// let healthy = http_probe("127.0.0.1:8080", "/healthz", 200, Duration::from_secs(2)).await;
/// assert!(healthy);
/// # }
/// ```
pub async fn http_probe(addr: &str, path: &str, expected_status: u16, timeout: Duration) -> bool {
    let result = tokio::time::timeout(timeout, http_probe_inner(addr, path, expected_status)).await;
    if let Ok(ok) = result {
        ok
    } else {
        trace!(addr, "health check timed out");
        false
    }
}

/// Inner HTTP probe logic (no timeout wrapper).
async fn http_probe_inner(addr: &str, path: &str, expected_status: u16) -> bool {
    let mut stream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            trace!(addr, error = %e, "health check connect failed");
            return false;
        },
    };

    let request = format!("GET {path} HTTP/1.1\r\nHost: health-check\r\nConnection: close\r\n\r\n");
    if let Err(e) = stream.write_all(request.as_bytes()).await {
        trace!(addr, error = %e, "health check write failed");
        return false;
    }

    match read_status_line(&mut stream, addr).await {
        Some(data) => parse_status_code(&data) == Some(expected_status),
        None => false,
    }
}

/// Read from `stream` until the first `\r\n` (end of status line) or buffer full.
///
/// Returns `None` on empty response or I/O error.
#[expect(clippy::indexing_slicing, reason = "bounded by filled counter")]
async fn read_status_line(stream: &mut TcpStream, addr: &str) -> Option<String> {
    let mut buf = [0_u8; 256];
    let mut filled = 0;
    loop {
        match stream.read(&mut buf[filled..]).await {
            Ok(0) => break,
            Ok(n) => {
                filled += n;
                if buf[..filled].windows(2).any(|w| w == b"\r\n") || filled >= buf.len() {
                    break;
                }
            },
            Err(e) => {
                trace!(addr, error = %e, "health check read failed");
                return None;
            },
        }
    }
    if filled == 0 {
        trace!(addr, "health check received empty response");
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..filled]).into_owned())
}

/// Extract the HTTP status code from a response status line.
///
/// ```ignore
/// use praxis_protocol::http::pingora::health::probe::parse_status_code;
///
/// assert_eq!(parse_status_code("HTTP/1.1 200 OK\r\n"), Some(200));
/// assert_eq!(
///     parse_status_code("HTTP/1.1 503 Service Unavailable\r\n"),
///     Some(503)
/// );
/// assert_eq!(parse_status_code("garbage"), None);
/// ```
#[expect(clippy::indexing_slicing, reason = "guarded by length check")]
pub(crate) fn parse_status_code(response: &str) -> Option<u16> {
    let first_line = response.lines().next()?;
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    parts[1].parse().ok()
}

// -----------------------------------------------------------------------------
// HTTP/2 Probe
// -----------------------------------------------------------------------------

/// Probe an endpoint with an HTTP/2 connection preface and SETTINGS exchange.
///
/// Sends the h2c connection preface followed by an empty SETTINGS frame,
/// then verifies the server responds with a SETTINGS frame. This confirms
/// the HTTP/2 code path is functional without sending any application data.
///
/// A clean GOAWAY is sent after the handshake to close the connection
/// gracefully.
///
/// ```ignore
/// # async fn example() {
/// use std::time::Duration;
///
/// use praxis_protocol::http::pingora::health::probe::h2_probe;
///
/// let healthy = h2_probe("127.0.0.1:8080", Duration::from_secs(2)).await;
/// assert!(healthy);
/// # }
/// ```
pub async fn h2_probe(addr: &str, timeout: Duration) -> bool {
    let result = tokio::time::timeout(timeout, h2_probe_inner(addr)).await;
    if let Ok(ok) = result {
        ok
    } else {
        trace!(addr, "h2 health check timed out");
        false
    }
}

/// Inner HTTP/2 probe logic (no timeout wrapper).
async fn h2_probe_inner(addr: &str) -> bool {
    let mut stream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            trace!(addr, error = %e, "h2 health check connect failed");
            return false;
        },
    };

    if !h2_send_preface(&mut stream, addr).await {
        return false;
    }

    if !h2_read_settings(&mut stream, addr).await {
        return false;
    }

    h2_close_gracefully(&mut stream).await;
    true
}

/// Send the HTTP/2 connection preface and initial SETTINGS frame.
async fn h2_send_preface(stream: &mut TcpStream, addr: &str) -> bool {
    if let Err(e) = stream.write_all(H2_PREFACE).await {
        trace!(addr, error = %e, "h2 health check preface write failed");
        return false;
    }
    if let Err(e) = stream.write_all(H2_SETTINGS).await {
        trace!(addr, error = %e, "h2 health check settings write failed");
        return false;
    }
    true
}

/// Read the server's response and verify it contains a SETTINGS frame.
async fn h2_read_settings(stream: &mut TcpStream, addr: &str) -> bool {
    let mut buf = [0_u8; 64];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n >= H2_FRAME_HEADER_LEN => n,
        Ok(n) => {
            trace!(addr, bytes = n, "h2 health check response too short");
            return false;
        },
        Err(e) => {
            trace!(addr, error = %e, "h2 health check read failed");
            return false;
        },
    };

    if !is_settings_frame(buf.get(..n).unwrap_or_default()) {
        trace!(addr, "h2 health check did not receive SETTINGS frame");
        return false;
    }
    true
}

/// Send SETTINGS ACK and GOAWAY, then drain remaining data.
async fn h2_close_gracefully(stream: &mut TcpStream) {
    drop(stream.write_all(H2_SETTINGS_ACK).await);
    drop(stream.write_all(H2_GOAWAY).await);

    let mut drain = [0_u8; 256];
    while stream.read(&mut drain).await.unwrap_or(0) > 0 {}
}

/// Check whether a buffer starts with an H2 SETTINGS frame.
///
/// ```ignore
/// use praxis_protocol::http::pingora::health::probe::is_settings_frame;
///
/// let settings = &[0, 0, 0, 4, 0, 0, 0, 0, 0];
/// assert!(is_settings_frame(settings));
///
/// let not_settings = &[0, 0, 0, 1, 0, 0, 0, 0, 0];
/// assert!(!is_settings_frame(not_settings));
/// ```
#[expect(clippy::indexing_slicing, reason = "guarded by length check")]
pub(crate) fn is_settings_frame(buf: &[u8]) -> bool {
    buf.len() >= H2_FRAME_HEADER_LEN && buf[3] == H2_FRAME_TYPE_SETTINGS
}

// -----------------------------------------------------------------------------
// TCP Probe
// -----------------------------------------------------------------------------

/// Probe an endpoint by attempting a TCP connection.
///
/// Returns `true` if the connection succeeds within the timeout.
/// The connection is immediately closed on success.
///
/// ```ignore
/// # async fn example() {
/// use std::time::Duration;
///
/// use praxis_protocol::http::pingora::health::probe::tcp_probe;
///
/// let healthy = tcp_probe("127.0.0.1:5432", Duration::from_secs(2)).await;
/// assert!(healthy);
/// # }
/// ```
pub async fn tcp_probe(addr: &str, timeout: Duration) -> bool {
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => {
            trace!(addr, "tcp health check succeeded");
            true
        },
        Ok(Err(e)) => {
            trace!(addr, error = %e, "tcp health check connect failed");
            false
        },
        Err(_) => {
            trace!(addr, "tcp health check timed out");
            false
        },
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn parse_status_200() {
        assert_eq!(
            parse_status_code("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"),
            Some(200),
            "should parse 200 from status line"
        );
    }

    #[test]
    fn parse_status_503() {
        assert_eq!(
            parse_status_code("HTTP/1.1 503 Service Unavailable\r\n"),
            Some(503),
            "should parse 503 from status line"
        );
    }

    #[test]
    fn parse_status_204() {
        assert_eq!(
            parse_status_code("HTTP/1.1 204 No Content\r\n"),
            Some(204),
            "should parse 204 from status line"
        );
    }

    #[test]
    fn parse_status_garbage() {
        assert_eq!(
            parse_status_code("not a valid http response"),
            None,
            "should return None for garbage input"
        );
    }

    #[test]
    fn parse_status_empty() {
        assert_eq!(parse_status_code(""), None, "should return None for empty input");
    }

    #[test]
    fn parse_status_partial() {
        assert_eq!(
            parse_status_code("HTTP/1.1"),
            None,
            "should return None for incomplete status line"
        );
    }

    #[test]
    fn parse_status_http10() {
        assert_eq!(
            parse_status_code("HTTP/1.0 301 Moved Permanently\r\n"),
            Some(301),
            "should parse HTTP/1.0 status lines"
        );
    }

    #[tokio::test]
    async fn tcp_probe_refuses_nonexistent() {
        let result = tcp_probe("127.0.0.1:1", Duration::from_millis(100)).await;
        assert!(!result, "should fail for non-listening port");
    }

    #[tokio::test]
    async fn http_probe_refuses_nonexistent() {
        let result = http_probe("127.0.0.1:1", "/", 200, Duration::from_millis(100)).await;
        assert!(!result, "should fail for non-listening port");
    }

    #[tokio::test]
    async fn tcp_probe_succeeds_on_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let probe = tokio::spawn(async move { tcp_probe(&addr, Duration::from_secs(1)).await });

        let (_socket, _peer) = listener.accept().await.unwrap();
        let result = probe.await.unwrap();
        assert!(result, "should succeed when endpoint is listening");
    }

    #[tokio::test]
    async fn http_probe_succeeds_with_matching_status() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let probe_addr = addr.clone();
        let probe = tokio::spawn(async move { http_probe(&probe_addr, "/health", 200, Duration::from_secs(1)).await });

        let (mut socket, _peer) = listener.accept().await.unwrap();
        let mut buf = [0_u8; 512];
        let _ = socket.read(&mut buf).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        socket.shutdown().await.unwrap();

        let result = probe.await.unwrap();
        assert!(result, "should succeed with matching 200 status");
    }

    #[test]
    fn is_settings_frame_valid() {
        assert!(
            is_settings_frame(&[0, 0, 0, 4, 0, 0, 0, 0, 0]),
            "valid SETTINGS frame should be recognized"
        );
    }

    #[test]
    fn is_settings_frame_with_ack() {
        assert!(
            is_settings_frame(&[0, 0, 0, 4, 1, 0, 0, 0, 0]),
            "SETTINGS ACK frame should be recognized"
        );
    }

    #[test]
    fn is_settings_frame_wrong_type() {
        assert!(
            !is_settings_frame(&[0, 0, 0, 1, 0, 0, 0, 0, 0]),
            "non-SETTINGS frame type should be rejected"
        );
    }

    #[test]
    fn is_settings_frame_too_short() {
        assert!(
            !is_settings_frame(&[0, 0, 0, 4]),
            "buffer shorter than frame header should be rejected"
        );
    }

    #[test]
    fn is_settings_frame_empty() {
        assert!(!is_settings_frame(&[]), "empty buffer should be rejected");
    }

    #[tokio::test]
    async fn h2_probe_refuses_nonexistent() {
        let result = h2_probe("127.0.0.1:1", Duration::from_millis(100)).await;
        assert!(!result, "should fail for non-listening port");
    }

    #[tokio::test]
    async fn h2_probe_succeeds_with_settings_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let probe_addr = addr.clone();
        let probe = tokio::spawn(async move { h2_probe(&probe_addr, Duration::from_secs(2)).await });

        let (mut socket, _peer) = listener.accept().await.unwrap();
        let mut buf = [0_u8; 512];
        let _ = socket.read(&mut buf).await.unwrap();
        socket.write_all(H2_SETTINGS).await.unwrap();
        socket.write_all(H2_SETTINGS_ACK).await.unwrap();
        socket.shutdown().await.unwrap();

        let result = probe.await.unwrap();
        assert!(result, "should succeed when server responds with SETTINGS");
    }

    #[tokio::test]
    async fn h2_probe_fails_with_non_settings_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let probe_addr = addr.clone();
        let probe = tokio::spawn(async move { h2_probe(&probe_addr, Duration::from_secs(2)).await });

        let (mut socket, _peer) = listener.accept().await.unwrap();
        let mut buf = [0_u8; 512];
        let _ = socket.read(&mut buf).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        socket.shutdown().await.unwrap();

        let result = probe.await.unwrap();
        assert!(
            !result,
            "should fail when server responds with HTTP/1.1 instead of SETTINGS"
        );
    }

    #[tokio::test]
    async fn h2_probe_times_out_on_no_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let probe_addr = addr.clone();
        let probe = tokio::spawn(async move { h2_probe(&probe_addr, Duration::from_millis(100)).await });

        let (_socket, _peer) = listener.accept().await.unwrap();

        let result = probe.await.unwrap();
        assert!(!result, "should fail when server does not respond within timeout");
    }

    #[tokio::test]
    async fn http_probe_fails_with_wrong_status() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let probe_addr = addr.clone();
        let probe = tokio::spawn(async move { http_probe(&probe_addr, "/", 200, Duration::from_secs(1)).await });

        let (mut socket, _peer) = listener.accept().await.unwrap();
        let mut buf = [0_u8; 512];
        let _ = socket.read(&mut buf).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        socket.shutdown().await.unwrap();

        let result = probe.await.unwrap();
        assert!(!result, "should fail when status code does not match");
    }
}
