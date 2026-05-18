// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Specialized backends: hop-by-hop responses, slow backends,
//! and shared TCP server utilities.

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

// -----------------------------------------------------------------------------
// Specialized Backends
// -----------------------------------------------------------------------------

/// Start a backend that includes hop-by-hop headers in its
/// responses. Used to verify the proxy strips them before
/// forwarding to the client.
///
/// # Panics
///
/// Panics if the server fails to bind or accept connections.
pub fn start_hop_by_hop_response_backend() -> u16 {
    spawn_tcp_server(|mut stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _headers = read_until_headers_complete(&mut stream);

        let body = "hop-by-hop-test";
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Length: {}\r\n\
             Connection: X-Internal-Token\r\n\
             Keep-Alive: timeout=300\r\n\
             Upgrade: websocket\r\n\
             Proxy-Authenticate: Basic realm=\"test\"\r\n\
             Trailer: X-Checksum\r\n\
             X-Internal-Token: secret-value\r\n\
             X-Safe-Header: visible\r\n\
             Server: test-backend\r\n\
             \r\n\
             {body}",
            body.len()
        );
        let _sent = stream.write_all(response.as_bytes());
    })
}

/// Start a backend that includes reserved internal headers
/// (`x-praxis-*`, `x-mcp-*`, `x-a2a-*`) in its responses.
/// Used to verify the proxy strips them before forwarding to
/// the client.
///
/// # Panics
///
/// Panics if the server fails to bind or accept connections.
pub fn start_reserved_header_response_backend() -> u16 {
    spawn_tcp_server(|mut stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _headers = read_until_headers_complete(&mut stream);

        let body = "reserved-header-test";
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Length: {}\r\n\
             X-Praxis-Mcp-Method: tools/call\r\n\
             X-Mcp-Servername: backend-1\r\n\
             X-A2a-Method: task/send\r\n\
             X-Request-Id: abc-123\r\n\
             Server: test-backend\r\n\
             \r\n\
             {body}",
            body.len()
        );
        let _sent = stream.write_all(response.as_bytes());
    })
}

/// Start a backend that waits `delay` before responding.
pub fn start_slow_backend(body: &str, delay: Duration) -> u16 {
    let body = body.to_owned();
    spawn_tcp_server(move |mut stream| {
        let mut buf = [0u8; 4096];
        let _bytes = stream.read(&mut buf);
        std::thread::sleep(delay);
        let _sent = write_http_response(&mut stream, &body);
    })
}

// -----------------------------------------------------------------------------
// Shared TCP Server Utilities
// -----------------------------------------------------------------------------

/// Spawn a raw TCP server that calls `handler` in a new
/// thread for each accepted connection. Returns the port.
pub(crate) fn spawn_tcp_server(handler: impl Fn(TcpStream) + Send + Clone + 'static) -> u16 {
    let (listener, port) = crate::net::port::bind_unique_port();

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let handler = handler.clone();
            std::thread::spawn(move || handler(stream));
        }
    });

    port
}

/// RAII guard that shuts down a backend spawned by
/// `spawn_tcp_server_with_shutdown` when dropped.
pub struct BackendGuard {
    /// The port the backend is listening on.
    port: u16,

    /// Shared flag signalling the listener loop to exit.
    shutdown: Arc<AtomicBool>,
}

impl BackendGuard {
    /// The allocated port number.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for BackendGuard {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
    }
}

/// Spawn a raw TCP server with a shutdown guard. The
/// listener loop exits when the returned [`BackendGuard`]
/// is dropped.
pub(crate) fn spawn_tcp_server_with_shutdown(handler: impl Fn(TcpStream) + Send + Clone + 'static) -> BackendGuard {
    let (listener, port) = crate::net::port::bind_unique_port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&shutdown);

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            if flag.load(Ordering::Acquire) {
                break;
            }
            let handler = handler.clone();
            std::thread::spawn(move || handler(stream));
        }
    });

    BackendGuard { port, shutdown }
}

/// Read from a TCP stream until the HTTP header terminator
/// (`\r\n\r\n`) is received. Returns the raw request as a
/// string. Prevents partial-read flakiness under load.
pub(crate) fn read_until_headers_complete(stream: &mut TcpStream) -> String {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
        if data.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    String::from_utf8_lossy(&data).into_owned()
}

/// Extract Content-Length from raw HTTP headers.
pub(crate) fn parse_content_length(headers: &str) -> usize {
    headers
        .lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split_once(':').map(|(_, v)| v))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

/// Write a minimal HTTP 200 response with the given body.
pub(crate) fn write_http_response(stream: &mut TcpStream, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}
