// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Specialized backends: hop-by-hop responses, slow backends,
//! and shared TCP server utilities.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    sync::{
        Arc, Mutex,
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
/// (`x-praxis-*`, `x-ext-protocol-*`, `x-ext-agent-*`) in its responses.
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
             X-Praxis-Filter-Action: routed\r\n\
             X-Ext-Servername: backend-1\r\n\
             X-Ext-Agent-Method: task/send\r\n\
             X-Request-Id: abc-123\r\n\
             Server: test-backend\r\n\
             \r\n\
             {body}",
            body.len()
        );
        let _sent = stream.write_all(response.as_bytes());
    })
}

/// Start a backend that returns the caller's chosen response headers.
///
/// # Panics
///
/// Panics if the server fails to bind or accept connections.
pub fn start_response_header_backend(headers: Vec<(String, String)>) -> BackendGuard {
    spawn_tcp_server_with_shutdown(move |mut stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _request = read_until_headers_complete(&mut stream);

        let body = "response-header-test";
        let extra = headers.iter().fold(String::new(), |mut acc, (name, value)| {
            acc.push_str(name);
            acc.push_str(": ");
            acc.push_str(value);
            acc.push_str("\r\n");
            acc
        });
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             {extra}\
             \r\n\
             {body}",
            body.len()
        );
        let _sent = stream.write_all(response.as_bytes());
    })
}

/// Start a backend that waits `delay` before responding.
#[expect(clippy::disallowed_methods, reason = "blocking thread, not async")]
pub fn start_slow_backend(body: &str, delay: Duration) -> u16 {
    let body = body.to_owned();
    spawn_tcp_server(move |mut stream| {
        let mut buf = [0_u8; 4096];
        let _bytes = stream.read(&mut buf);
        std::thread::sleep(delay);
        let _sent = write_http_response(&mut stream, &body);
    })
}

/// Start a backend that returns different responses on each call.
///
/// Each entry in `responses` is `(status, body)`. After all entries
/// are exhausted, the backend returns 500 with "exhausted".
///
/// # Panics
///
/// Panics if the server fails to bind.
pub fn start_stateful_backend(responses: Vec<(u16, String)>) -> BackendGuard {
    let state = Arc::new(Mutex::new(responses));

    spawn_tcp_server_with_shutdown(move |mut stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _headers = read_until_headers_complete(&mut stream);

        let (status, body) = {
            let mut queue = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if queue.is_empty() {
                (500_u16, "exhausted".to_owned())
            } else {
                queue.remove(0)
            }
        };
        let reason = super::simple::reason_phrase(status);
        let resp = format!(
            "HTTP/1.1 {status} {reason}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Server: praxis-stateful-backend\r\n\
             \r\n\
             {body}",
            body.len()
        );
        let _sent = stream.write_all(resp.as_bytes());
    })
}

/// Start a backend that injects raw bytes as a response header line.
///
/// `malformed_header` may contain CRLF, control characters, or other
/// illegal sequences inside what looks like a single header field.
/// Used for response-side injection / response-splitting tests.
///
/// # Panics
///
/// Panics if the server fails to bind or accept connections.
pub fn start_malicious_response_header_backend(malformed_header: Vec<u8>) -> BackendGuard {
    spawn_tcp_server_with_shutdown(move |mut stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _headers = read_until_headers_complete(&mut stream);

        let body = b"ok";
        let mut response = Vec::new();
        response.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
        response.extend_from_slice(&malformed_header);
        if !malformed_header.ends_with(b"\r\n") {
            response.extend_from_slice(b"\r\n");
        }
        response.extend_from_slice(
            format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        );
        response.extend_from_slice(body);
        let _sent = stream.write_all(&response);
    })
}

/// Start a backend that sends the given raw HTTP response bytes
/// after reading request headers.
///
/// # Panics
///
/// Panics if the server fails to bind or accept connections.
pub fn start_raw_response_backend(response: Vec<u8>) -> BackendGuard {
    spawn_tcp_server_with_shutdown(move |mut stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _headers = read_until_headers_complete(&mut stream);
        let _sent = stream.write_all(&response);
    })
}

/// Start a backend that writes a partial response (status +
/// `Content-Length`) then drops the connection before finishing
/// headers or body. Used for mid-response failure tests.
///
/// # Panics
///
/// Panics if the server fails to bind or accept connections.
pub fn start_mid_response_drop_backend() -> u16 {
    spawn_tcp_server(|mut stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0_u8; 4096];
        let _bytes = stream.read(&mut buf);
        let _sent = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n");
        let _flushed = stream.flush();
        drop(stream);
    })
}

/// Start a backend that answers with `Connection: keep-alive` and then
/// appends a second forged response on the same socket. Used to verify
/// the proxy does not forward keep-alive poisoning to the client.
///
/// # Panics
///
/// Panics if the server fails to bind or accept connections.
pub fn start_keepalive_poison_backend() -> BackendGuard {
    spawn_tcp_server_with_shutdown(|mut stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _headers = read_until_headers_complete(&mut stream);

        let body = b"safe";
        let mut response = Vec::new();
        response.extend_from_slice(
            format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Length: {}\r\n\
                 Connection: keep-alive\r\n\
                 Keep-Alive: timeout=300\r\n\
                 \r\n",
                body.len()
            )
            .as_bytes(),
        );
        response.extend_from_slice(body);
        // Extra bytes that would become a second response if the proxy
        // blindly reused or forwarded the upstream connection framing.
        response.extend_from_slice(
            b"HTTP/1.1 200 OK\r\n\
              Content-Length: 6\r\n\
              X-Poisoned: true\r\n\
              \r\n\
              poison",
        );
        let _sent = stream.write_all(&response);
    })
}

/// Start a backend that returns a `Content-Encoding: gzip` body.
///
/// # Panics
///
/// Panics if the server fails to bind or accept connections.
pub fn start_gzip_encoded_backend(gzip_body: Vec<u8>) -> BackendGuard {
    spawn_tcp_server_with_shutdown(move |mut stream| {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _headers = read_until_headers_complete(&mut stream);

        let mut response = Vec::new();
        response.extend_from_slice(
            format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-Encoding: gzip\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n",
                gzip_body.len()
            )
            .as_bytes(),
        );
        response.extend_from_slice(&gzip_body);
        let _sent = stream.write_all(&response);
    })
}

/// Shared request log for [`start_reused_connection_kill_backend`]:
/// `(connection_number, request_number_within_connection, method, path)`.
pub type ReusedConnectionLog = Arc<Mutex<Vec<(usize, usize, String, String)>>>;

/// Start a keep-alive backend that kills the connection on its second
/// request without responding.
///
/// The first request on each connection is answered `200 OK` with
/// keep-alive so the proxy pools the connection. The second request on
/// the same connection is read fully, recorded, and the socket closed
/// without a response — simulating an upstream that received a request
/// on a reused connection and died before responding. Used to verify
/// retry safety for requests whose bytes were already written upstream.
///
/// # Panics
///
/// Panics if the server fails to bind.
pub fn start_reused_connection_kill_backend() -> (BackendGuard, ReusedConnectionLog) {
    let log: ReusedConnectionLog = Arc::new(Mutex::new(Vec::new()));
    let log_handle = Arc::clone(&log);
    let connection_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let guard = spawn_tcp_server_with_shutdown(move |stream| {
        let connection_num = connection_counter.fetch_add(1, Ordering::Relaxed);
        serve_then_kill_connection(stream, connection_num, &log);
    });

    (guard, log_handle)
}

/// Serve the first request on `stream` with keep-alive, then read and
/// drop the second without responding, recording each into `log`.
fn serve_then_kill_connection(mut stream: TcpStream, connection_num: usize, log: &ReusedConnectionLog) {
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    for request_num in 0_usize.. {
        let Some((method, path)) = read_one_request(&mut stream) else {
            break;
        };
        log.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((connection_num, request_num, method, path));

        if request_num > 0 {
            tracing::debug!(connection_num, request_num, "killing reused connection");
            break;
        }

        let body = "pooled-ok";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
            body.len()
        );
        if stream.write_all(response.as_bytes()).is_err() {
            break;
        }
    }
}

// -----------------------------------------------------------------------------
// Shared TCP Server Utilities
// -----------------------------------------------------------------------------

/// Read exactly one HTTP request (headers plus `Content-Length` body)
/// from the stream. Returns the method and path, or `None` on EOF or
/// read error.
fn read_one_request(stream: &mut TcpStream) -> Option<(String, String)> {
    let mut data = Vec::new();
    let mut buf = [0_u8; 4096];

    let header_end = loop {
        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
    };

    let headers = String::from_utf8_lossy(&data[..header_end]).into_owned();
    let content_length = parse_content_length(&headers);
    while data.len() < header_end + content_length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
    }

    let mut request_line = headers.lines().next().unwrap_or("").split(' ');
    let method = request_line.next().unwrap_or("").to_owned();
    let path = request_line.next().unwrap_or("").to_owned();
    Some((method, path))
}

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
        _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
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
    let mut buf = [0_u8; 4096];

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
