// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! HTTP/1.1 framing after a response filter changes the body length.

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use http::header;
use praxis_core::config::Config;
use praxis_filter::{BodyAccess, BodyMode, FilterAction, FilterError, HttpFilter, HttpFilterContext};
use praxis_test_utils::{
    Backend, custom_filter_yaml, free_port, http_send_on_connection, parse_body, parse_header, parse_status,
    registry_with, start_proxy_with_registry,
};

struct RewriteResponse;
struct RemoveTransferEncoding;
struct FailResponseBody;
struct FailAfterFirstChunk;

#[async_trait]
impl HttpFilter for RewriteResponse {
    fn name(&self) -> &'static str {
        "rewrite_response"
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn response_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(1024) }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if let Some(response) = ctx.response_header.as_mut() {
            response.headers.remove(header::CONTENT_LENGTH);
            ctx.response_headers_modified = true;
        }
        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if end_of_stream {
            *body = Some(Bytes::from_static(b"updated"));
        }
        Ok(FilterAction::Continue)
    }
}

#[async_trait]
impl HttpFilter for RemoveTransferEncoding {
    fn name(&self) -> &'static str {
        "remove_transfer_encoding"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if let Some(response) = ctx.response_header.as_mut() {
            response.headers.remove(header::TRANSFER_ENCODING);
            ctx.response_headers_modified = true;
        }
        Ok(FilterAction::Continue)
    }
}

#[async_trait]
impl HttpFilter for FailResponseBody {
    fn name(&self) -> &'static str {
        "fail_response_body"
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn response_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(1024) }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if let Some(response) = ctx.response_header.as_mut() {
            response.headers.remove(header::CONTENT_LENGTH);
            ctx.response_headers_modified = true;
        }
        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if end_of_stream {
            Err("response rewrite failed".to_owned().into())
        } else {
            Ok(FilterAction::Continue)
        }
    }
}

#[async_trait]
impl HttpFilter for FailAfterFirstChunk {
    fn name(&self) -> &'static str {
        "fail_after_first_chunk"
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if ctx.request.uri.path() == "/stream"
            && let Some(response) = ctx.response_header.as_mut()
        {
            response.headers.remove(header::CONTENT_LENGTH);
            ctx.response_headers_modified = true;
        }
        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if ctx.request.uri.path() == "/stream"
            && body
                .as_ref()
                .is_some_and(|part| part.windows(5).any(|window| window == b"chunk"))
        {
            return Err("second response chunk failed".to_owned().into());
        }
        Ok(FilterAction::Continue)
    }
}

fn split_response_backend() -> (u16, mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind split backend");
    let port = listener.local_addr().expect("backend address").port();
    let (send_second_chunk, first_chunk_received) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        for _ in 0..4 {
            let (mut stream, _) = listener.accept().expect("accept proxy connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("backend timeout");
            let mut request = [0_u8; 4096];
            let size = stream.read(&mut request).expect("read proxy request");
            if request[..size].starts_with(b"GET /stream ") {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nfirst-")
                    .expect("write first response chunk");
                stream.flush().expect("flush first chunk");
                first_chunk_received
                    .recv_timeout(Duration::from_secs(3))
                    .expect("client received the first chunk");
                stream.write_all(b"chunk").expect("write second response chunk");
                return;
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("answer health probe");
        }
        panic!("proxy never requested /stream");
    });
    (port, send_second_chunk, handle)
}

fn status_backend(status: u16) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind status backend");
    let port = listener.local_addr().expect("backend address").port();
    let handle = std::thread::spawn(move || {
        for _ in 0..4 {
            let (mut stream, _) = listener.accept().expect("accept proxy connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("backend timeout");
            let mut request = [0_u8; 4096];
            let size = stream.read(&mut request).expect("read proxy request");
            if request[..size].windows(6).any(|window| window == b" /case") {
                let body = if status == 204 || status == 304 { "" } else { "original" };
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).expect("write case response");
                return;
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("answer health probe");
        }
        panic!("proxy never requested /case");
    });
    (port, handle)
}

fn truncated_backend() -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind truncated backend");
    let port = listener.local_addr().expect("backend address").port();
    let handle = std::thread::spawn(move || {
        for _ in 0..4 {
            let (mut stream, _) = listener.accept().expect("accept proxy connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("backend timeout");
            let mut request = [0_u8; 4096];
            let size = stream.read(&mut request).expect("read proxy request");
            if request[..size].starts_with(b"GET /truncated ") {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\npartial")
                    .expect("write incomplete response");
                return;
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("answer health probe");
        }
        panic!("proxy never requested /truncated");
    });
    (port, handle)
}

fn read_raw_response_with_method(proxy_addr: &str, method: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(proxy_addr).expect("connect to proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("client timeout");
    stream
        .write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes())
        .expect("send client request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read until proxy closes");
    response
}

fn read_raw_response(proxy_addr: &str, path: &str) -> String {
    read_raw_response_with_method(proxy_addr, "GET", path)
}

fn assert_two_responses_on_one_connection(proxy_addr: &str, expected_body: &[u8]) {
    let mut stream = TcpStream::connect(proxy_addr).expect("connect to proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("client timeout");

    for turn in 1..=2 {
        let raw = http_send_on_connection(&mut stream, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(parse_status(&raw), 200, "turn {turn} should succeed: {raw:?}");
        assert_eq!(
            parse_header(&raw, "transfer-encoding").as_deref(),
            Some("chunked"),
            "turn {turn} needs chunked framing: {raw:?}"
        );
        assert_eq!(parse_body(&raw).as_bytes(), expected_body, "turn {turn} body");
    }
}

#[test]
fn rewritten_response_keeps_one_http11_connection_for_two_requests() {
    let backend = Backend::fixed("original").start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend.port(), "rewrite_response"))
        .expect("test proxy config");
    let registry = registry_with("rewrite_response", || Box::new(RewriteResponse));
    let proxy = start_proxy_with_registry(&config, &registry);

    assert_two_responses_on_one_connection(proxy.addr(), b"updated");
    drop(proxy);
}

#[test]
fn removed_upstream_chunked_header_keeps_one_http11_connection_for_two_requests() {
    let backend = Backend::chunked(vec!["original".to_owned()]).start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(
        proxy_port,
        backend.port(),
        "remove_transfer_encoding",
    ))
    .expect("test proxy config");
    let registry = registry_with("remove_transfer_encoding", || Box::new(RemoveTransferEncoding));
    let proxy = start_proxy_with_registry(&config, &registry);

    assert_two_responses_on_one_connection(proxy.addr(), b"original");
    drop(proxy);
}

#[test]
fn truncated_fixed_length_upstream_is_not_completed_as_chunked_success() {
    let (backend_port, backend_thread) = truncated_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "rewrite_response"))
        .expect("test proxy config");
    let registry = registry_with("rewrite_response", || Box::new(RewriteResponse));
    let proxy = start_proxy_with_registry(&config, &registry);

    let raw = read_raw_response(proxy.addr(), "/truncated");
    assert!(
        raw.starts_with("HTTP/1.1 200"),
        "upstream headers were committed before truncation: {raw:?}"
    );
    assert!(
        raw.to_ascii_lowercase().contains("transfer-encoding: chunked"),
        "the client must have explicit chunked framing to detect truncation: {raw:?}"
    );
    assert!(
        !raw.ends_with("0\r\n\r\n"),
        "incomplete upstream body must not become a clean chunked response: {raw:?}"
    );
    assert!(
        !raw.contains("updated"),
        "rewrite must not run on incomplete upstream content: {raw:?}"
    );

    backend_thread.join().expect("backend should exit");
    drop(proxy);
}

#[test]
fn response_body_filter_error_does_not_complete_chunked_success() {
    let backend = Backend::fixed("original").start_with_shutdown();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend.port(), "fail_response_body"))
        .expect("test proxy config");
    let registry = registry_with("fail_response_body", || Box::new(FailResponseBody));
    let proxy = start_proxy_with_registry(&config, &registry);

    let raw = read_raw_response(proxy.addr(), "/");
    assert!(
        raw.starts_with("HTTP/1.1 500"),
        "pre-commit filter error should become an explicit 500: {raw:?}"
    );
    assert!(
        raw.to_ascii_lowercase().contains("content-length:"),
        "error response needs framing: {raw:?}"
    );
    assert!(
        !raw.ends_with("0\r\n\r\n"),
        "failed response rewrite must not get a clean chunked terminator: {raw:?}"
    );
    assert!(
        !raw.contains("updated"),
        "failed rewrite must not return transformed content: {raw:?}"
    );

    drop(proxy);
}

#[test]
fn post_commit_body_error_does_not_send_chunked_terminator() {
    let (backend_port, send_second_chunk, backend_thread) = split_response_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "fail_after_first_chunk"))
        .expect("test proxy config");
    let registry = registry_with("fail_after_first_chunk", || Box::new(FailAfterFirstChunk));
    let proxy = start_proxy_with_registry(&config, &registry);

    let mut stream = TcpStream::connect(proxy.addr()).expect("connect to proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("client timeout");
    stream
        .write_all(b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("send client request");
    let mut response = Vec::new();
    let mut buf = [0_u8; 4096];
    while !response.windows(6).any(|window| window == b"first-") {
        let size = stream.read(&mut buf).expect("read first response chunk");
        assert_ne!(size, 0, "response ended before the first chunk");
        response.extend_from_slice(&buf[..size]);
    }
    send_second_chunk.send(()).expect("release second backend chunk");
    stream.read_to_end(&mut response).expect("read until proxy closes");
    let raw = String::from_utf8(response).expect("ASCII response");
    assert!(
        raw.starts_with("HTTP/1.1 200"),
        "success headers should have been committed: {raw:?}"
    );
    assert!(
        raw.to_ascii_lowercase().contains("transfer-encoding: chunked"),
        "the response must exercise chunked framing: {raw:?}"
    );
    assert!(
        raw.contains("first-"),
        "first body chunk should reach the client: {raw:?}"
    );
    assert!(
        !raw.ends_with("0\r\n\r\n"),
        "post-commit error must not masquerade as a complete chunked response: {raw:?}"
    );

    backend_thread.join().expect("backend should exit");
    drop(proxy);
}

#[test]
fn rewritten_error_responses_keep_explicit_http11_framing() {
    for status in [404, 500] {
        let (backend_port, backend_thread) = status_backend(status);
        let proxy_port = free_port();
        let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "rewrite_response"))
            .expect("test proxy config");
        let registry = registry_with("rewrite_response", || Box::new(RewriteResponse));
        let proxy = start_proxy_with_registry(&config, &registry);

        let raw = read_raw_response(proxy.addr(), "/case");
        assert!(
            raw.starts_with(&format!("HTTP/1.1 {status}")),
            "error status should survive: {raw:?}"
        );
        assert!(
            raw.to_ascii_lowercase().contains("transfer-encoding: chunked"),
            "rewritten error response needs explicit framing: {raw:?}"
        );
        assert!(raw.contains("updated"), "rewritten error body should arrive: {raw:?}");
        assert!(
            raw.ends_with("0\r\n\r\n"),
            "complete error response needs chunked terminator: {raw:?}"
        );

        backend_thread.join().expect("backend should exit");
        drop(proxy);
    }
}

#[test]
fn bodyless_responses_do_not_gain_chunked_framing() {
    for (method, status) in [("HEAD", 200), ("GET", 204), ("GET", 304)] {
        let (backend_port, backend_thread) = status_backend(status);
        let proxy_port = free_port();
        let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "rewrite_response"))
            .expect("test proxy config");
        let registry = registry_with("rewrite_response", || Box::new(RewriteResponse));
        let proxy = start_proxy_with_registry(&config, &registry);

        let raw = read_raw_response_with_method(proxy.addr(), method, "/case");
        assert!(
            raw.starts_with(&format!("HTTP/1.1 {status}")),
            "bodyless status should survive: {raw:?}"
        );
        assert!(
            !raw.to_ascii_lowercase().contains("transfer-encoding: chunked"),
            "{method} {status} cannot gain chunked body framing: {raw:?}"
        );
        assert!(
            raw.split_once("\r\n\r\n").is_some_and(|(_, body)| body.is_empty()),
            "bodyless response must stay empty: {raw:?}"
        );

        backend_thread.join().expect("backend should exit");
        drop(proxy);
    }
}
