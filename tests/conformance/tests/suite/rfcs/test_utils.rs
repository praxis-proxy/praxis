// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Shared test utilities for RFC conformance tests.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

// -----------------------------------------------------------------------------
// H2C Client
// -----------------------------------------------------------------------------

/// Perform an h2c (HTTP/2 cleartext, prior-knowledge) GET and
/// return the response object and body string.
pub(super) fn h2c_get(addr: &str, path: &str) -> (http::Response<()>, String) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("TCP connect for h2c");

        let (mut client, h2_conn) = h2::client::handshake(tcp).await.expect("h2c handshake");
        tokio::spawn(async move {
            if let Err(e) = h2_conn.await {
                eprintln!("h2c connection closed: {e}");
            }
        });

        let request = http::Request::get(path)
            .header("host", "localhost")
            .body(())
            .expect("build h2c request");

        let (response_fut, _) = client.send_request(request, true).expect("send h2c request");
        let response = response_fut.await.expect("h2c response");
        let status = response.status();
        let headers = response.headers().clone();
        let mut body_stream = response.into_body();

        let mut body = Vec::new();
        while let Some(chunk) = body_stream.data().await {
            let data = chunk.expect("h2c body chunk");
            body.extend_from_slice(&data);
            drop(body_stream.flow_control().release_capacity(data.len()));
        }

        let mut resp_builder = http::Response::builder().status(status);
        for (key, value) in &headers {
            resp_builder = resp_builder.header(key, value);
        }
        let resp = resp_builder.body(()).expect("rebuild response");

        (resp, String::from_utf8_lossy(&body).into_owned())
    })
}

// -----------------------------------------------------------------------------
// Specialized Backends
// -----------------------------------------------------------------------------

/// Start a backend that includes hop-by-hop headers in its
/// response (Connection, Keep-Alive, Upgrade).
pub(super) fn start_hop_by_hop_backend() -> u16 {
    praxis_test_utils::start_hop_by_hop_response_backend()
}

/// Start a backend that includes `Transfer-Encoding: chunked`
/// in its response while also sending a Content-Length body.
pub(super) fn start_te_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                handle_te_connection(stream);
            });
        }
    });
    port
}

/// Handle a single connection for the TE backend. Sends a
/// proper chunked response with Transfer-Encoding header
/// that the proxy should strip for H2 clients.
fn handle_te_connection(mut stream: TcpStream) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut buf = [0_u8; 4096];
    let _bytes = stream.read(&mut buf);
    let body = "te-test";
    let chunk = format!("{:x}\r\n{body}\r\n0\r\n\r\n", body.len());
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: close\r\n\
         \r\n\
         {chunk}",
    );
    let _sent = stream.write_all(response.as_bytes());
}

/// Start a backend that sends a malformed response header
/// containing the given raw header bytes (may include CRLF,
/// bare CR, bare LF, or null bytes).
pub(super) fn start_crlf_response_backend(malformed_header: &[u8]) -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    let header_bytes = malformed_header.to_vec();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let header_bytes = header_bytes.clone();
            std::thread::spawn(move || {
                handle_crlf_connection(stream, &header_bytes);
            });
        }
    });
    port
}

/// Handle a single connection for the CRLF backend, sending
/// malformed header bytes in the response.
fn handle_crlf_connection(mut stream: TcpStream, malformed_header: &[u8]) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut buf = [0_u8; 4096];
    let _bytes = stream.read(&mut buf);
    let body = b"ok";
    let mut response = Vec::new();
    response.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
    response.extend_from_slice(malformed_header);
    response.extend_from_slice(b"\r\n");
    response.extend_from_slice(format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes());
    response.extend_from_slice(body);
    let _sent = stream.write_all(&response);
}

/// Start a backend that sends garbage (non-HTTP) bytes.
pub(super) fn start_garbage_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                handle_garbage_connection(stream);
            });
        }
    });
    port
}

/// Handle a single connection for the garbage backend.
fn handle_garbage_connection(mut stream: TcpStream) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut buf = [0_u8; 4096];
    let _bytes = stream.read(&mut buf);
    let _sent = stream.write_all(b"\x00\x01\x02garbage\xff\xfe");
}

/// Start a backend that sends incomplete response headers
/// then drops the connection.
pub(super) fn start_partial_header_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                handle_partial_header_connection(stream);
            });
        }
    });
    port
}

/// Handle a single connection for the partial-header backend.
fn handle_partial_header_connection(mut stream: TcpStream) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut buf = [0_u8; 4096];
    let _bytes = stream.read(&mut buf);
    let _sent = stream.write_all(b"HTTP/1.1 200 OK\r\n");
    let _flushed = stream.flush();
    drop(stream);
}

/// Start a backend that returns a custom `X-Custom-Response`
/// header in its response.
pub(super) fn start_custom_response_header_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                handle_custom_response_header(stream);
            });
        }
    });
    port
}

/// Handle a single connection for the custom response header
/// backend.
fn handle_custom_response_header(mut stream: TcpStream) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut buf = [0_u8; 4096];
    let _bytes = stream.read(&mut buf);
    let body = "ok";
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Length: {}\r\n\
         X-Custom-Response: backend-value-99\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let _sent = stream.write_all(response.as_bytes());
}

/// Start a backend that returns an `ETag` header in its response.
pub(super) fn start_etag_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                handle_etag_connection(stream);
            });
        }
    });
    port
}

/// Handle a single connection for the ETag backend.
fn handle_etag_connection(mut stream: TcpStream) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut buf = [0_u8; 4096];
    let _bytes = stream.read(&mut buf);
    let body = "etag-content";
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Length: {}\r\n\
         ETag: \"v1-abc\"\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let _sent = stream.write_all(response.as_bytes());
}

/// Start a backend that always returns 304 Not Modified with
/// an ETag header.
pub(super) fn start_304_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                handle_304_connection(stream);
            });
        }
    });
    port
}

/// Handle a single connection for the 304 backend.
fn handle_304_connection(mut stream: TcpStream) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut buf = [0_u8; 4096];
    let _bytes = stream.read(&mut buf);
    let response = "HTTP/1.1 304 Not Modified\r\n\
         ETag: \"v1-abc\"\r\n\
         Connection: close\r\n\
         \r\n";
    let _sent = stream.write_all(response.as_bytes());
}

/// Start a backend that returns multiple `Set-Cookie` headers.
pub(super) fn start_multi_set_cookie_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                handle_multi_set_cookie(stream);
            });
        }
    });
    port
}

/// Handle a single connection for the multi-Set-Cookie backend.
fn handle_multi_set_cookie(mut stream: TcpStream) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut buf = [0_u8; 4096];
    let _bytes = stream.read(&mut buf);
    let body = "cookies";
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Length: {}\r\n\
         Set-Cookie: session=abc123; Path=/; HttpOnly\r\n\
         Set-Cookie: theme=dark; Path=/\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let _sent = stream.write_all(response.as_bytes());
}

/// Start a backend that returns a Set-Cookie with full attributes.
pub(super) fn start_set_cookie_with_attributes_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                handle_set_cookie_attributes(stream);
            });
        }
    });
    port
}

/// Handle a single connection for the Set-Cookie attributes backend.
fn handle_set_cookie_attributes(mut stream: TcpStream) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut buf = [0_u8; 4096];
    let _bytes = stream.read(&mut buf);
    let body = "ok";
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Length: {}\r\n\
         Set-Cookie: session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let _sent = stream.write_all(response.as_bytes());
}

/// Start a backend that returns a 206 Partial Content response
/// with a `Content-Range` header.
pub(super) fn start_range_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                handle_range_connection(stream);
            });
        }
    });
    port
}

/// Handle a single connection for the range backend.
fn handle_range_connection(mut stream: TcpStream) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut buf = [0_u8; 4096];
    let _bytes = stream.read(&mut buf);
    let body = "hello";
    let response = format!(
        "HTTP/1.1 206 Partial Content\r\n\
         Content-Length: {}\r\n\
         Content-Range: bytes 0-4/26\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let _sent = stream.write_all(response.as_bytes());
}

/// Start a backend that returns a redirect response with
/// the given status code and a `Location` header.
pub(super) fn start_redirect_backend(status_code: u16) -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                handle_redirect_connection(stream, status_code);
            });
        }
    });
    port
}

/// Handle a single connection for the redirect backend.
fn handle_redirect_connection(mut stream: TcpStream, status_code: u16) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut buf = [0_u8; 4096];
    let _bytes = stream.read(&mut buf);
    let reason = match status_code {
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        _ => "Unknown",
    };
    let response = format!(
        "HTTP/1.1 {status_code} {reason}\r\n\
         Location: https://example.com/new\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let _sent = stream.write_all(response.as_bytes());
}

/// Start a backend that echoes the HTTP request line (method,
/// URI, and version) as the response body.
pub(super) fn start_request_line_echo_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                handle_request_line_echo(stream);
            });
        }
    });
    port
}

/// Handle a single connection for the request-line echo backend.
fn handle_request_line_echo(mut stream: TcpStream) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
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
    let raw = String::from_utf8_lossy(&data);
    let request_line = raw.lines().next().unwrap_or("").to_owned();
    let body = request_line;
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let _sent = stream.write_all(response.as_bytes());
}

/// Start a backend that returns 417 Expectation Failed.
pub(super) fn start_417_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                handle_417_connection(stream);
            });
        }
    });
    port
}

/// Handle a single connection for the 417 backend.
fn handle_417_connection(mut stream: TcpStream) {
    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut buf = [0_u8; 4096];
    let _bytes = stream.read(&mut buf);
    let body = "expectation failed";
    let response = format!(
        "HTTP/1.1 417 Expectation Failed\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let _sent = stream.write_all(response.as_bytes());
}

// -----------------------------------------------------------------------------
// YAML Config Builders
// -----------------------------------------------------------------------------

/// Build a YAML config with a timeout filter.
pub(super) fn timeout_filter_yaml(proxy_port: u16, backend_port: u16, timeout_ms: u64) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: timeout
        timeout_ms: {timeout_ms}
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    )
}

/// Build a YAML config with `forwarded_headers` using
/// the standard `Forwarded` header.
pub(super) fn forwarded_standard_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: forwarded_headers
        use_standard_header: true
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    )
}

/// Build a YAML config with `forwarded_headers` using the standard
/// header and trusted proxies including the loopback range.
pub(super) fn forwarded_standard_trusted_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: forwarded_headers
        use_standard_header: true
        trusted_proxies:
          - "127.0.0.0/8"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    )
}
