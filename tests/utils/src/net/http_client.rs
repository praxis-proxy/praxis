// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Lightweight HTTP client for integration tests.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::{Duration, Instant},
};

// -----------------------------------------------------------------------------
// Raw Request / Response
// -----------------------------------------------------------------------------

/// Connect, send an already-formatted HTTP request, and return the raw response.
///
/// # Panics
///
/// Panics if the TCP connection or write fails.
pub fn http_send(addr: &str, request: &str) -> String {
    let mut stream = tcp_connect(addr);

    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    http_send_on_connection(&mut stream, request)
}

/// Send a request on an existing HTTP/1.1 connection and read one response.
///
/// The caller can use the same stream again after the response's framing is
/// complete, which lets tests verify that a proxy keeps the connection usable.
///
/// # Panics
///
/// Panics if writing the request fails.
pub fn http_send_on_connection(stream: &mut TcpStream, request: &str) -> String {
    stream.write_all(request.as_bytes()).unwrap();
    read_full_response(stream)
}

/// Sends a request while distinguishing stale sockets from incomplete responses.
///
/// # Errors
///
/// Returns I/O failures before any response, or an incomplete-response error
/// after response bytes have arrived.
#[cfg(test)]
pub(crate) fn try_http_send_on_connection(stream: &mut TcpStream, request: &str) -> std::io::Result<String> {
    stream.write_all(request.as_bytes())?;
    let (data, result) = read_response(stream);
    result.map_err(|error| {
        if data.is_empty() {
            error
        } else {
            std::io::Error::other(format!("incomplete HTTP response: {error}"))
        }
    })?;
    Ok(String::from_utf8_lossy(&data).into_owned())
}

/// Send a request on an existing connection and read the response before
/// `deadline`, keeping at most `max_body` body bytes.
///
/// A peer that drips bytes cannot extend the exchange past the deadline, and a
/// response body larger than `max_body` is rejected instead of buffered.
pub(crate) fn try_http_send_on_connection_until(
    stream: &mut TcpStream,
    request: &str,
    deadline: Instant,
    max_body: usize,
) -> std::io::Result<String> {
    stream.write_all(request.as_bytes())?;
    let (data, result) = read_response_with(stream, Some(deadline), max_body);
    result.map_err(|error| {
        if data.is_empty() {
            error
        } else {
            std::io::Error::other(format!("incomplete HTTP response: {error}"))
        }
    })?;
    Ok(String::from_utf8_lossy(&data).into_owned())
}

/// Read a complete HTTP/1.1 response from `stream`, returning the raw bytes
/// as a string.
///
/// Uses whatever framing the response advertises so the read returns as soon
/// as the message is complete: the zero-length chunk and complete trailers for
/// `Transfer-Encoding: chunked`, exactly `Content-Length` body bytes for a
/// fixed-size body, and read-to-EOF otherwise (connection-close framing).
///
/// Reading to EOF unconditionally (the old behaviour) blocked on the socket
/// read timeout whenever the proxy kept a keep-alive connection open after the
/// response was already fully received, adding seconds to every such test. The
/// read timeout set by the caller remains a backstop for misbehaving peers.
fn read_full_response(stream: &mut TcpStream) -> String {
    let (data, _) = read_response(stream);
    String::from_utf8_lossy(&data).into_owned()
}

/// Retains partial bytes for legacy callers while preserving I/O errors.
fn read_response(stream: &mut TcpStream) -> (Vec<u8>, std::io::Result<()>) {
    read_response_with(stream, None, usize::MAX)
}

/// Limits applied to one response read.
#[derive(Clone, Copy)]
struct ReadBudget {
    /// Total deadline for the exchange, if any.
    deadline: Option<Instant>,
    /// Largest body the reader retains.
    max_body: usize,
}

/// Reads a response with an optional total deadline and body limit.
fn read_response_with(
    stream: &mut TcpStream,
    deadline: Option<Instant>,
    max_body: usize,
) -> (Vec<u8>, std::io::Result<()>) {
    let mut data = Vec::new();
    let mut buf = [0_u8; 4096];
    let header_end = loop {
        if let Some(pos) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos + 4;
        }
        match read_chunk(stream, &mut buf, deadline) {
            Ok(0) if data.is_empty() => return (data, Ok(())),
            Ok(0) => return (data, Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))),
            Err(error) => return (data, Err(error)),
            Ok(count) => data.extend_from_slice(&buf[..count]),
        }
    };
    let budget = ReadBudget { deadline, max_body };
    let result = read_body(stream, &mut data, header_end, budget);
    (data, result)
}

/// Reads one chunk, bounding the wait by the remaining exchange deadline.
fn read_chunk(stream: &mut TcpStream, buffer: &mut [u8], deadline: Option<Instant>) -> std::io::Result<usize> {
    if let Some(deadline) = deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "response deadline exceeded",
            ));
        }
        stream.set_read_timeout(Some(remaining))?;
    }
    stream.read(buffer)
}

/// Read the response body into `data`, using whatever framing the already-read
/// headers advertise: the zero-length chunk and complete trailers for
/// `Transfer-Encoding: chunked`, exactly `Content-Length` body bytes for a
/// fixed-size body, and read-to-EOF otherwise (connection-close framing).
/// Responses with status 204 or 304 finish at the end of their headers.
fn read_body(stream: &mut TcpStream, data: &mut Vec<u8>, header_end: usize, budget: ReadBudget) -> std::io::Result<()> {
    let headers = String::from_utf8_lossy(&data[..header_end]).into_owned();
    if matches!(parse_status(&headers), 204 | 304) {
        return Ok(());
    }
    let is_chunked = headers.lines().any(|line| {
        let lower = line.to_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });
    let content_length = content_length(&headers);

    if is_chunked {
        read_chunked(stream, data, header_end, budget)
    } else if let Some(len) = content_length {
        if len > budget.max_body {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "response body of {len} bytes exceeds the {}-byte limit",
                    budget.max_body
                ),
            ));
        }
        read_framed(stream, data, header_end, budget, |d| {
            d.len().saturating_sub(header_end) >= len
        })
    } else {
        read_until(stream, data, header_end, budget, |_| false)
    }
}

/// Parses the declared body length, if the headers set one.
fn content_length(headers: &str) -> Option<usize> {
    headers
        .lines()
        .find(|line| line.to_lowercase().starts_with("content-length:"))
        .and_then(|line| line.split_once(':').map(|(_, value)| value))
        .and_then(|value| value.trim().parse::<usize>().ok())
}

/// Reads through the last chunk and trailers without scanning chunk payloads.
fn read_chunked(
    stream: &mut TcpStream,
    data: &mut Vec<u8>,
    header_end: usize,
    budget: ReadBudget,
) -> std::io::Result<()> {
    let mut buffer = [0_u8; 4096];
    while !chunked_complete(&data[header_end..])? {
        let count = read_chunk(stream, &mut buffer, budget.deadline)?;
        if count == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        data.extend_from_slice(&buffer[..count]);
        if data.len().saturating_sub(header_end) > budget.max_body {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("chunked response exceeds the {}-byte limit", budget.max_body),
            ));
        }
    }
    Ok(())
}

/// Walks size-delimited chunks before looking for the trailer section's end.
fn chunked_complete(mut body: &[u8]) -> std::io::Result<bool> {
    loop {
        let Some(line_end) = body.windows(2).position(|window| window == b"\r\n") else {
            return Ok(false);
        };
        let size = chunk_size(&body[..line_end])?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(body.starts_with(b"\r\n") || body.windows(4).any(|window| window == b"\r\n\r\n"));
        }
        let chunk_end = size
            .checked_add(2)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk size overflow"))?;
        if body.len() < chunk_end {
            return Ok(false);
        }
        if &body[size..chunk_end] != b"\r\n" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing chunk CRLF",
            ));
        }
        body = &body[chunk_end..];
    }
}

/// Parses the hexadecimal size, leaving optional chunk extensions uninterpreted.
fn chunk_size(line: &[u8]) -> std::io::Result<usize> {
    let mut parts = line.splitn(2, |byte| *byte == b';');
    let token = std::str::from_utf8(parts.next().unwrap_or_default())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let size = if parts.next().is_some() {
        token.trim_end_matches([' ', '\t'])
    } else {
        token
    };
    if size.is_empty() || !size.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid chunk size",
        ));
    }
    usize::from_str_radix(size, 16).map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

/// Rejects EOF before a fixed-length response is complete.
fn read_framed(
    stream: &mut TcpStream,
    data: &mut Vec<u8>,
    body_start: usize,
    budget: ReadBudget,
    done: impl Fn(&[u8]) -> bool,
) -> std::io::Result<()> {
    read_until(stream, data, body_start, budget, &done)?;
    if done(data) {
        Ok(())
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    }
}

/// Read 4 KiB chunks from `stream` into `data` until `done` reports the message
/// is complete or the stream ends. The caller's read timeout is the backstop
/// for a misbehaving peer that never satisfies `done`.
fn read_until(
    stream: &mut TcpStream,
    data: &mut Vec<u8>,
    body_start: usize,
    budget: ReadBudget,
    done: impl Fn(&[u8]) -> bool,
) -> std::io::Result<()> {
    let mut buf = [0_u8; 4096];
    while !done(data) {
        if data.len().saturating_sub(body_start) > budget.max_body {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("response body exceeds the {}-byte limit", budget.max_body),
            ));
        }
        match read_chunk(stream, &mut buf, budget.deadline) {
            Ok(0) => break,
            Err(error) => return Err(error),
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Convenience Wrappers
// -----------------------------------------------------------------------------

/// Send an HTTP GET and return `(status, body)`.
pub fn http_get(addr: &str, path: &str, host: Option<&str>) -> (u16, String) {
    let host_header = host.unwrap_or("localhost");
    let raw = http_send(
        addr,
        &format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host_header}\r\n\
             Connection: close\r\n\r\n"
        ),
    );

    (parse_status(&raw), parse_body(&raw))
}

/// Send an HTTP GET, retrying up to 3 times on 5xx responses.
#[expect(clippy::disallowed_methods, reason = "blocking test utility, not async")]
pub fn http_get_retry(addr: &str, path: &str, host: Option<&str>) -> (u16, String) {
    for _ in 0..2 {
        let (status, body) = http_get(addr, path, host);
        if status < 500 {
            return (status, body);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    http_get(addr, path, host)
}

/// Send an HTTP PUT with a JSON body and return `(status, body)`.
pub fn http_put_json(addr: &str, path: &str, body: &str) -> (u16, String) {
    let raw = http_send(
        addr,
        &format!(
            "PUT {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {body}",
            body.len()
        ),
    );
    (parse_status(&raw), parse_body(&raw))
}

/// Send an HTTP DELETE and return `(status, body)`.
pub fn http_delete(addr: &str, path: &str) -> (u16, String) {
    let raw = http_send(
        addr,
        &format!(
            "DELETE {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Connection: close\r\n\r\n"
        ),
    );
    (parse_status(&raw), parse_body(&raw))
}

/// Send an HTTP POST and return `(status, body)`.
pub fn http_post(addr: &str, path: &str, body: &str) -> (u16, String) {
    let raw = http_send(
        addr,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    );

    (parse_status(&raw), parse_body(&raw))
}

// -----------------------------------------------------------------------------
// IPv6 Wrappers
// -----------------------------------------------------------------------------

/// Send an HTTP GET to an IPv6 address and return `(status, body)`.
pub fn http_get_v6(addr: &str, path: &str) -> (u16, String) {
    let raw = http_send(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    );
    (parse_status(&raw), parse_body(&raw))
}

/// Build a raw HTTP POST request with `Content-Type: application/json`.
///
/// Returns a fully formatted HTTP/1.1 request string ready to pass to [`http_send`].
///
/// ```
/// # use praxis_test_utils::json_post;
/// let req = json_post("/v1/chat", r#"{"model":"test"}"#);
/// assert!(req.starts_with("POST /v1/chat HTTP/1.1\r\n"));
/// assert!(req.contains("Content-Type: application/json"));
/// ```
///
/// [`http_send`]: crate::net::http_client::http_send
pub fn json_post(path: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    )
}

// -----------------------------------------------------------------------------
// H2C (HTTP/2 Cleartext) Client
// -----------------------------------------------------------------------------

/// Send `request` over a fresh h2c connection to `addr` and return `(status, body)`.
///
/// # Panics
///
/// Panics if the TCP connection, H2 handshake, or response read fails.
fn h2c_exchange(addr: &str, request: http::Request<()>) -> (u16, String) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for h2c");

    rt.block_on(async {
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("TCP connect for h2c");

        let (mut client, h2_conn) = h2::client::handshake(tcp).await.expect("h2c handshake");
        tokio::spawn(async move {
            let _result = h2_conn.await;
        });

        let (response_fut, _) = client.send_request(request, true).expect("send h2c request");
        let response = response_fut.await.expect("h2c response");
        let status = response.status().as_u16();
        let mut body_stream = response.into_body();

        let mut body = Vec::new();
        while let Some(chunk) = body_stream.data().await {
            let data = chunk.expect("h2c body chunk");
            body.extend_from_slice(&data);
            drop(body_stream.flow_control().release_capacity(data.len()));
        }

        (status, String::from_utf8_lossy(&body).into_owned())
    })
}

/// Send an h2c (HTTP/2 cleartext, prior-knowledge) GET and return `(status, body)`.
///
/// Connects via plain TCP and performs the HTTP/2 handshake directly
/// (no upgrade from HTTP/1.1). Builds an origin-form request for `path`
/// and sets the `Host` header to `host` (default `localhost`).
///
/// The h2 encoder derives `:authority` from the URI authority component,
/// not from `Host`. This helper does not place an authority on the URI, so
/// it does not control `:authority`. Per [RFC 9113], `:authority` and `Host`
/// are distinct; use [`h2c_get_authority_only`] or [`h2c_get_absolute`] when
/// a test must send a specific `:authority`.
///
/// [RFC 9113]: https://datatracker.ietf.org/doc/html/rfc9113
///
/// # Panics
///
/// Panics if the TCP connection, H2 handshake, or response read fails.
pub fn h2c_get(addr: &str, path: &str, host: Option<&str>) -> (u16, String) {
    let host_value = host.unwrap_or("localhost");
    let request = http::Request::get(path)
        .header("host", host_value)
        .body(())
        .expect("build h2c request");
    h2c_exchange(addr, request)
}

/// The outcome of an h2c gRPC call: response headers, plus whether the
/// header block itself ended the stream.
#[derive(Clone, Debug)]
pub struct GrpcCallResult {
    /// Whether the response HEADERS frame carried `END_STREAM`.
    ///
    /// A gRPC Trailers-Only response must set it: without it a client
    /// waits for trailers that never arrive and reports the call as
    /// broken rather than reading the status.
    pub end_stream: bool,

    /// Response headers.
    pub headers: http::HeaderMap,

    /// HTTP status.
    pub status: u16,

    /// Trailers, when the response sent any.
    pub trailers: Option<http::HeaderMap>,
}

impl GrpcCallResult {
    /// A header or trailer value as text.
    ///
    /// Looks in the header block first, then the trailers, matching how
    /// a gRPC client resolves `grpc-status`.
    #[must_use]
    pub fn grpc_header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .or_else(|| self.trailers.as_ref().and_then(|trailers| trailers.get(name)))
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }
}

/// Make an h2c gRPC call through `addr` and return the response shape.
///
/// Speaks HTTP/2 with prior knowledge, as a gRPC client does over
/// plaintext, so tests can assert on framing an HTTP/1.1 client cannot
/// observe.
///
/// # Panics
///
/// Panics if the connection, handshake, or exchange fails.
#[must_use]
pub fn h2c_grpc_call(addr: &str, path: &str, extra_headers: &[(&str, &str)]) -> GrpcCallResult {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for h2c");

    rt.block_on(Box::pin(grpc_call(addr, path, extra_headers)))
}

/// Build the request for [`h2c_grpc_call`].
fn grpc_request(path: &str, extra_headers: &[(&str, &str)]) -> http::Request<()> {
    let mut builder = http::Request::post(path)
        .header("host", "localhost")
        .header("te", "trailers");
    // Only default the codec when the caller did not pick one: two
    // content-type headers is a malformed request, not a codec choice.
    if !extra_headers
        .iter()
        .any(|(name, _value)| name.eq_ignore_ascii_case("content-type"))
    {
        builder = builder.header("content-type", "application/grpc");
    }
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }
    builder.body(()).expect("build gRPC request")
}

/// Drive one h2c gRPC exchange.
async fn grpc_call(addr: &str, path: &str, extra_headers: &[(&str, &str)]) -> GrpcCallResult {
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("TCP connect for h2c");
    let (mut client, h2_conn) = h2::client::handshake(tcp).await.expect("h2c handshake");
    tokio::spawn(async move {
        let _result = h2_conn.await;
    });

    let (response_fut, _send) = client
        .send_request(grpc_request(path, extra_headers), true)
        .expect("send gRPC request");
    let response = response_fut.await.expect("gRPC response");
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let mut body = response.into_body();
    let end_stream = body.is_end_stream();

    while let Some(chunk) = body.data().await {
        let data = chunk.expect("gRPC body chunk");
        let _release = body.flow_control().release_capacity(data.len());
    }
    let trailers = body.trailers().await.ok().flatten();

    GrpcCallResult {
        end_stream,
        headers,
        status,
        trailers,
    }
}

/// Send an h2c GET whose URI carries `authority` and has no `Host` header field.
///
/// Builds `http://{authority}{path}` so the encoder emits `:authority` from the
/// URI. Use this instead of [`h2c_get`] when a test must exercise HTTP/2
/// authority without relying on `Host` (see [RFC 9113]).
///
/// [RFC 9113]: https://datatracker.ietf.org/doc/html/rfc9113
///
/// # Panics
///
/// Panics if the TCP connection, H2 handshake, or response read fails.
pub fn h2c_get_authority_only(addr: &str, path: &str, authority: &str) -> (u16, String) {
    let uri = http::Uri::builder()
        .scheme("http")
        .authority(authority)
        .path_and_query(path)
        .build()
        .expect("build h2 authority URI");
    let request = http::Request::get(uri).body(()).expect("build h2c request");
    h2c_exchange(addr, request)
}

/// Send an h2c GET whose request URI is absolute (explicit `:scheme` and
/// `:authority` pseudo-headers) and return `(status, body)`.
///
/// Like [`h2c_get_authority_only`], the authority comes from the URI rather
/// than a `Host` header field.
///
/// # Panics
///
/// Panics if the connection, handshake, or exchange fails.
pub fn h2c_get_absolute(addr: &str, absolute_uri: &str) -> (u16, String) {
    let request = http::Request::get(absolute_uri).body(()).expect("build h2c request");
    h2c_exchange(addr, request)
}

// -----------------------------------------------------------------------------
// Connection Utilities
// -----------------------------------------------------------------------------

/// Connect to `addr` with short retries on transient failures.
///
/// Retries up to 20 times (1 s total) before a final attempt that
/// panics on failure. Guards against brief accept-queue gaps that
/// can occur in CI after [`wait_for_http`] returns.
///
/// [`wait_for_http`]: crate::net::wait::wait_for_http
#[expect(clippy::disallowed_methods, reason = "blocking test utility, not async")]
#[expect(clippy::unwrap_used, reason = "test utility panics on failure")]
fn tcp_connect(addr: &str) -> TcpStream {
    for _ in 0..20 {
        if let Ok(stream) = TcpStream::connect(addr) {
            return stream;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    TcpStream::connect(addr).unwrap()
}

// -----------------------------------------------------------------------------
// Response Parsing
// -----------------------------------------------------------------------------

/// Parse the status code from a raw HTTP response string.
pub fn parse_status(raw: &str) -> u16 {
    raw.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// Parse the body from a raw HTTP response string.
pub fn parse_body(raw: &str) -> String {
    let Some((headers_part, body_part)) = raw.split_once("\r\n\r\n") else {
        return String::new();
    };

    let is_chunked = headers_part.lines().any(|line| {
        let lower = line.to_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });

    if is_chunked {
        decode_chunked(body_part)
    } else {
        body_part.to_owned()
    }
}

/// Decode an HTTP/1.1 chunked-encoded body into a plain
/// string.
pub fn decode_chunked(body: &str) -> String {
    let mut result = String::new();
    let mut remaining = body;

    while let Some(crlf) = remaining.find("\r\n") {
        let size_hex = remaining.get(..crlf).unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16).unwrap_or(0);
        remaining = remaining.get(crlf + 2..).unwrap_or_default();

        if size == 0 {
            break;
        }

        if remaining.len() < size {
            break;
        }

        result.push_str(remaining.get(..size).unwrap_or_default());
        remaining = remaining.get(size..).unwrap_or_default();

        if remaining.starts_with("\r\n") {
            remaining = remaining.get(2..).unwrap_or_default();
        }
    }

    result
}

/// Extract a response header value by name (case-insensitive).
///
/// Returns `None` if absent.
pub fn parse_header(raw: &str, name: &str) -> Option<String> {
    let headers_part = raw.split_once("\r\n\r\n")?.0;
    let lower_name = name.to_lowercase();
    headers_part.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim().to_lowercase() == lower_name).then(|| value.trim().to_owned())
    })
}

/// Extract all values for a response header by name (case-insensitive).
///
/// Returns an empty `Vec` if no matching headers are found. Useful for
/// headers like `Set-Cookie` that appear multiple times and must not be folded.
///
/// ```
/// # use praxis_test_utils::parse_header_all;
/// let raw = "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nbody";
/// let cookies = parse_header_all(raw, "set-cookie");
/// assert_eq!(cookies, vec!["a=1", "b=2"]);
/// ```
pub fn parse_header_all(raw: &str, name: &str) -> Vec<String> {
    let Some(headers_part) = raw.split_once("\r\n\r\n").map(|(h, _)| h) else {
        return Vec::new();
    };
    let lower_name = name.to_lowercase();
    headers_part
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim().to_lowercase() == lower_name).then(|| value.trim().to_owned())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    /// Complete request consumed by the raw response fixtures.
    const RAW_GET: &str = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";

    #[test]
    fn fallible_client_rejects_premature_framed_eof() {
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nshort".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nshort\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Checksum: value\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n0\r\n\r\n\r\n".as_slice(),
        ] {
            let (mut stream, server) = response_socket(response);
            let error = try_http_send_on_connection(&mut stream, RAW_GET).expect_err("incomplete framed response");
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::Other,
                "partial responses must not look like a replayable idle close"
            );
            assert!(
                error.to_string().contains("incomplete HTTP response"),
                "framed EOF must retain its diagnostic"
            );
            server.join().expect("server");
        }
    }

    #[test]
    fn fallible_client_rejects_oversized_content_length_without_overflow() {
        let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\nshort", usize::MAX);
        let (mut stream, server) = response_socket(response.as_bytes());
        let error = try_http_send_on_connection(&mut stream, RAW_GET).expect_err("incomplete enormous response");
        assert!(
            error.to_string().contains("incomplete HTTP response"),
            "oversized lengths must fail as incomplete responses"
        );
        server.join().expect("server");
    }

    #[test]
    fn legacy_client_retains_partial_bytes_on_framed_eof() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nshort";
        let (mut stream, server) = response_socket(response);
        assert_eq!(
            http_send_on_connection(&mut stream, RAW_GET).as_bytes(),
            response,
            "legacy callers must retain partial responses"
        );
        server.join().expect("server");
    }

    #[test]
    fn fallible_client_accepts_complete_framing_and_normal_close() {
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2 \t;name=value\r\nok\r\n0\r\nX-Checksum: value\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok".as_slice(),
        ] {
            let (mut stream, server) = response_socket(response);
            assert_eq!(
                try_http_send_on_connection(&mut stream, RAW_GET)
                    .expect("complete response")
                    .as_bytes(),
                response,
                "valid framing must remain successful"
            );
            server.join().expect("server");
        }
    }

    #[test]
    fn chunked_framing_requires_boundaries_and_complete_trailers() {
        let body = b"5;name=value\r\n0\r\n\r\n\r\n1\r\nx\r\n0\r\nX-Checksum: value\r\nAnother: value\r\n\r\n";
        for length in 0..body.len() {
            assert!(
                !chunked_complete(&body[..length]).expect("valid partial framing"),
                "an incomplete prefix of length {length} must not finish the message"
            );
        }
        assert!(
            chunked_complete(body).expect("complete framing"),
            "trailers finish the message"
        );
        for invalid in [
            b"z\r\n".as_slice(),
            b"+1\r\n",
            b"1\r\nx!!",
            b"ffffffffffffffffffffffff\r\n",
        ] {
            assert!(
                chunked_complete(invalid).is_err(),
                "invalid framing must fail: {invalid:?}"
            );
        }
    }

    #[test]
    fn chunk_extensions_allow_only_spaces_and_tabs_before_the_semicolon() {
        for (line, expected) in [
            (b"2 ;name=value".as_slice(), 2),
            (b"A \t ;name=value", 10),
            (b"0\t;name=value", 0),
        ] {
            assert_eq!(
                chunk_size(line).expect("valid chunk extension"),
                expected,
                "spaces and tabs before the extension semicolon must preserve the chunk size: {line:?}"
            );
        }
        for line in [
            b"2 ".as_slice(),
            b"2\t",
            b" 2;name=value",
            b"2\x0b;name=value",
            b"2\x0c;name=value",
            b"2\n;name=value",
        ] {
            assert!(
                chunk_size(line).is_err(),
                "invalid whitespace must remain rejected: {line:?}"
            );
        }
    }

    #[test]
    fn bodyless_statuses_leave_keepalive_connection_usable() {
        for response in [
            b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n".as_slice(),
            b"HTTP/1.1 304 Not Modified\r\nConnection: keep-alive\r\n\r\n",
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 123\r\n\r\n",
            b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            assert_persistent_response(response);
        }
    }

    #[test]
    fn chunked_trailers_leave_keepalive_connection_usable() {
        assert_persistent_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n0\r\n\r\n\r\n0\r\nX-End: yes\r\n\r\n",
        );
    }

    /// Verifies fragmented responses complete before a server closes its socket.
    fn assert_persistent_response(response: &[u8]) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
        let address = listener.local_addr().expect("address");
        let expected = response.to_vec();
        let response = expected.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
            for _ in 0..2 {
                let mut request = [0; RAW_GET.len()];
                stream
                    .read_exact(&mut request)
                    .expect("next request without waiting for EOF");
                for fragment in response.chunks(3) {
                    stream.write_all(fragment).expect("response fragment");
                }
            }
        });
        let mut stream = TcpStream::connect(address).expect("connect");
        stream.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        for _ in 0..2 {
            assert_eq!(
                try_http_send_on_connection(&mut stream, RAW_GET)
                    .expect("complete response")
                    .as_bytes(),
                expected,
                "framing must preserve the full response and allow the next request"
            );
        }
        server.join().expect("server");
    }

    /// Returns a socket whose server reads one request then closes its response.
    fn response_socket(response: &[u8]) -> (TcpStream, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
        let address = listener.local_addr().expect("address");
        let response = response.to_vec();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read timeout");
            let mut request = [0; RAW_GET.len()];
            stream.read_exact(&mut request).expect("request");
            stream.write_all(&response).expect("response");
        });
        let stream = TcpStream::connect(address).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        (stream, server)
    }

    #[test]
    fn parse_status_valid_http11() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(parse_status(raw), 200, "should extract 200 from status line");
    }

    #[test]
    fn parse_status_not_found() {
        let raw = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(parse_status(raw), 404, "should extract 404 from status line");
    }

    #[test]
    fn parse_status_empty_returns_zero() {
        assert_eq!(parse_status(""), 0, "empty input should produce status 0");
    }

    #[test]
    fn parse_body_extracts_after_separator() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nbody content";
        assert_eq!(parse_body(raw), "body content", "should extract body after blank line");
    }

    #[test]
    fn parse_body_no_separator_returns_empty() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 0";
        assert_eq!(parse_body(raw), "", "no CRLFCRLF separator should yield empty body");
    }

    #[test]
    fn decode_chunked_valid() {
        let input = "5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(input), "hello", "single chunk should decode correctly");
    }

    #[test]
    fn decode_chunked_multiple_chunks() {
        let input = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(
            decode_chunked(input),
            "hello world",
            "multiple chunks should concatenate"
        );
    }

    #[test]
    fn parse_header_found() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody";
        assert_eq!(
            parse_header(raw, "Content-Type"),
            Some("text/plain".to_owned()),
            "should find Content-Type header"
        );
    }

    #[test]
    fn parse_header_case_insensitive() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody";
        assert_eq!(
            parse_header(raw, "content-type"),
            Some("text/plain".to_owned()),
            "header lookup should be case-insensitive"
        );
    }

    #[test]
    fn parse_header_missing() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody";
        assert_eq!(parse_header(raw, "X-Missing"), None, "absent header should return None");
    }

    #[test]
    fn parse_header_all_multiple() {
        let raw = "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nbody";
        let values = parse_header_all(raw, "Set-Cookie");
        assert_eq!(values.len(), 2, "should find both Set-Cookie headers");
        assert_eq!(values[0], "a=1", "first cookie value");
        assert_eq!(values[1], "b=2", "second cookie value");
    }

    #[test]
    fn parse_header_all_none() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody";
        let values = parse_header_all(raw, "X-Missing");
        assert!(values.is_empty(), "no matching headers should yield empty vec");
    }
}
