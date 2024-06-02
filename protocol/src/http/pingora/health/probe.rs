// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! Health check probe functions for HTTP and TCP endpoints.

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::trace;

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
#[allow(clippy::indexing_slicing, reason = "bounded by read length")]
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

    let mut buf = [0u8; 256];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n > 0 => n,
        Ok(_) => {
            trace!(addr, "health check received empty response");
            return false;
        },
        Err(e) => {
            trace!(addr, error = %e, "health check read failed");
            return false;
        },
    };

    let response = String::from_utf8_lossy(&buf[..n]);
    parse_status_code(&response) == Some(expected_status)
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
#[allow(clippy::indexing_slicing, reason = "guarded by length check")]
pub(crate) fn parse_status_code(response: &str) -> Option<u16> {
    let first_line = response.lines().next()?;
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    parts[1].parse().ok()
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
        let mut buf = [0u8; 512];
        let _ = socket.read(&mut buf).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        socket.shutdown().await.unwrap();

        let result = probe.await.unwrap();
        assert!(result, "should succeed with matching 200 status");
    }

    #[tokio::test]
    async fn http_probe_fails_with_wrong_status() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let probe_addr = addr.clone();
        let probe = tokio::spawn(async move { http_probe(&probe_addr, "/", 200, Duration::from_secs(1)).await });

        let (mut socket, _peer) = listener.accept().await.unwrap();
        let mut buf = [0u8; 512];
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
