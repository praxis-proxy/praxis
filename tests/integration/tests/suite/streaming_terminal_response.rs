// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for `StreamingTerminalResponse` lifecycle.
//!
//! Exercises `run_streaming_terminal_response` end-to-end through
//! a live proxy: chunked framing, multi-chunk delivery, HEAD/204/304
//! suppression with `suppress()` instrumentation, mid-stream source
//! errors, client-disconnect cancellation, and H2 DATA-frame
//! framing.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{
    FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext, StreamingResponseBody,
    StreamingTerminalResponse,
};
use praxis_test_utils::{
    custom_filter_yaml, free_port, http_get, http_send, parse_body, parse_header, parse_status, registry_with,
    start_echo_backend, start_proxy_with_registry,
};

// -----------------------------------------------------------------------------
// Test Filters
// -----------------------------------------------------------------------------

struct MultiChunkStreamingFilter;

#[async_trait]
impl HttpFilter for MultiChunkStreamingFilter {
    fn name(&self) -> &'static str {
        "multi_chunk_streaming"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        struct MultiChunkBody {
            chunks: Vec<Bytes>,
            index: usize,
        }

        #[async_trait]
        impl StreamingResponseBody for MultiChunkBody {
            async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
                if self.index < self.chunks.len() {
                    let chunk = self.chunks[self.index].clone();
                    self.index += 1;
                    Ok(Some(chunk))
                } else {
                    Ok(None)
                }
            }

            async fn suppress(&mut self) -> Result<(), FilterError> {
                self.index = self.chunks.len();
                Ok(())
            }

            async fn cancel(&mut self) {
                self.index = self.chunks.len();
            }
        }

        let body = MultiChunkBody {
            chunks: vec![
                Bytes::from_static(b"chunk1"),
                Bytes::from_static(b"chunk2"),
                Bytes::from_static(b"chunk3"),
            ],
            index: 0,
        };
        let mut headers = http::HeaderMap::new();
        headers.insert("x-streaming-test", "multi-chunk".parse().unwrap());
        // Stale framing headers that prepare_streaming_headers must strip.
        headers.insert("content-length", "999".parse().unwrap());
        headers.insert("transfer-encoding", "gzip".parse().unwrap());
        Ok(FilterAction::StreamingTerminalResponse(Box::new(
            StreamingTerminalResponse::new(200, Box::new(body)).with_headers(headers),
        )))
    }
}

struct InstrumentedSuppressFilter {
    status: u16,
    suppress_count: Arc<AtomicUsize>,
}

#[async_trait]
impl HttpFilter for InstrumentedSuppressFilter {
    fn name(&self) -> &'static str {
        "instrumented_suppress"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let suppress_count = Arc::clone(&self.suppress_count);
        let status = self.status;

        struct InstrumentedBody {
            data: Option<Bytes>,
            suppress_count: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl StreamingResponseBody for InstrumentedBody {
            async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
                Ok(self.data.take())
            }

            async fn suppress(&mut self) -> Result<(), FilterError> {
                self.suppress_count.fetch_add(1, Ordering::SeqCst);
                self.data = None;
                Ok(())
            }

            async fn cancel(&mut self) {
                self.data = None;
            }
        }

        Ok(FilterAction::StreamingTerminalResponse(Box::new(
            StreamingTerminalResponse::new(
                status,
                Box::new(InstrumentedBody {
                    data: Some(Bytes::from_static(b"should-be-suppressed")),
                    suppress_count,
                }),
            ),
        )))
    }
}

struct ErrorStreamingFilter;

#[async_trait]
impl HttpFilter for ErrorStreamingFilter {
    fn name(&self) -> &'static str {
        "error_streaming"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        struct ErrorAfterFirstBody {
            sent_first: bool,
        }

        #[async_trait]
        impl StreamingResponseBody for ErrorAfterFirstBody {
            async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
                if self.sent_first {
                    Err("simulated stream source failure".into())
                } else {
                    self.sent_first = true;
                    Ok(Some(Bytes::from_static(b"first-chunk")))
                }
            }

            async fn suppress(&mut self) -> Result<(), FilterError> {
                Ok(())
            }

            async fn cancel(&mut self) {}
        }

        Ok(FilterAction::StreamingTerminalResponse(Box::new(
            StreamingTerminalResponse::new(200, Box::new(ErrorAfterFirstBody { sent_first: false })),
        )))
    }
}

struct SlowStreamingFilter {
    cancel_count: Arc<AtomicUsize>,
}

#[async_trait]
impl HttpFilter for SlowStreamingFilter {
    fn name(&self) -> &'static str {
        "slow_streaming"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let cancel_count = Arc::clone(&self.cancel_count);

        struct SlowBody {
            sent_first: bool,
            chunks_remaining: u16,
            cancel_count: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl StreamingResponseBody for SlowBody {
            async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
                if !self.sent_first {
                    self.sent_first = true;
                    return Ok(Some(Bytes::from_static(b"first-chunk")));
                }
                if self.chunks_remaining == 0 {
                    return Ok(None);
                }
                self.chunks_remaining -= 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(Some(Bytes::from(vec![b'X'; 65_536])))
            }

            async fn suppress(&mut self) -> Result<(), FilterError> {
                Ok(())
            }

            async fn cancel(&mut self) {
                self.cancel_count.fetch_add(1, Ordering::SeqCst);
            }
        }

        Ok(FilterAction::StreamingTerminalResponse(Box::new(
            StreamingTerminalResponse::new(
                200,
                Box::new(SlowBody {
                    sent_first: false,
                    chunks_remaining: 50,
                    cancel_count,
                }),
            ),
        )))
    }
}

// -----------------------------------------------------------------------------
// Registry Helpers
// -----------------------------------------------------------------------------

fn registry_with_suppress(status: u16, counter: &Arc<AtomicUsize>) -> FilterRegistry {
    let counter = Arc::clone(counter);
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "instrumented_suppress",
            FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(InstrumentedSuppressFilter {
                    status,
                    suppress_count: Arc::clone(&counter),
                }))
            })),
        )
        .unwrap();
    registry
}

fn registry_with_slow_stream(counter: &Arc<AtomicUsize>) -> FilterRegistry {
    let counter = Arc::clone(counter);
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "slow_streaming",
            FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(SlowStreamingFilter {
                    cancel_count: Arc::clone(&counter),
                }))
            })),
        )
        .unwrap();
    registry
}

// -----------------------------------------------------------------------------
// Multi-Chunk Delivery Tests
// -----------------------------------------------------------------------------

#[test]
fn streaming_multi_chunk_body_delivered() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend.port(), "multi_chunk_streaming")).unwrap();
    let registry = registry_with("multi_chunk_streaming", || Box::new(MultiChunkStreamingFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_get(proxy.addr(), "/", None);

    assert_eq!(status, 200, "streaming terminal response should return 200");
    assert_eq!(body, "chunk1chunk2chunk3", "all chunks should be concatenated");
}

#[test]
fn streaming_custom_headers_preserved() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend.port(), "multi_chunk_streaming")).unwrap();
    let registry = registry_with("multi_chunk_streaming", || Box::new(MultiChunkStreamingFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_header(&raw, "x-streaming-test"),
        Some("multi-chunk".to_owned()),
        "custom header should survive the streaming lifecycle"
    );
}

// -----------------------------------------------------------------------------
// Framing Tests
// -----------------------------------------------------------------------------

#[test]
fn streaming_h11_chunked_framing() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend.port(), "multi_chunk_streaming")).unwrap();
    let registry = registry_with("multi_chunk_streaming", || Box::new(MultiChunkStreamingFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(
        parse_header(&raw, "transfer-encoding"),
        Some("chunked".to_owned()),
        "HTTP/1.1 streaming should use chunked transfer-encoding"
    );
    assert!(
        parse_header(&raw, "content-length").is_none(),
        "chunked responses must not have Content-Length"
    );
}

#[test]
fn streaming_h10_close_delimited() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend.port(), "multi_chunk_streaming")).unwrap();
    let registry = registry_with("multi_chunk_streaming", || Box::new(MultiChunkStreamingFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let raw = http_send(proxy.addr(), "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n");

    assert!(
        parse_header(&raw, "transfer-encoding").is_none(),
        "HTTP/1.0 should not have Transfer-Encoding header"
    );
    let body = parse_body(&raw);
    assert_eq!(body, "chunk1chunk2chunk3", "HTTP/1.0 body should be close-delimited");
}

#[test]
fn streaming_h2_data_frames() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend.port(), "multi_chunk_streaming")).unwrap();
    let registry = registry_with("multi_chunk_streaming", || Box::new(MultiChunkStreamingFilter));
    let _proxy = start_proxy_with_registry(&config, &registry);

    let addr = format!("127.0.0.1:{proxy_port}");
    let (resp, body) = h2c_get(&addr, "/");

    assert_eq!(resp.status(), 200, "H2 streaming should return 200");
    assert_eq!(body, "chunk1chunk2chunk3", "H2 DATA frames should deliver all chunks");
    assert!(
        resp.headers().get("transfer-encoding").is_none(),
        "H2 must not have Transfer-Encoding header"
    );
    assert_eq!(
        resp.headers().get("x-streaming-test").map(|v| v.to_str().unwrap()),
        Some("multi-chunk"),
        "custom header should survive H2 streaming lifecycle"
    );
}

// -----------------------------------------------------------------------------
// Suppression Tests (with instrumentation)
// -----------------------------------------------------------------------------

#[test]
fn streaming_head_request_calls_suppress_exactly_once() {
    let suppress_count = Arc::new(AtomicUsize::new(0));
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend.port(), "instrumented_suppress")).unwrap();
    let registry = registry_with_suppress(200, &suppress_count);
    let proxy = start_proxy_with_registry(&config, &registry);
    // Reset after readiness probe (wait_for_http sends GET /)
    suppress_count.store(0, Ordering::SeqCst);

    let raw = http_send(
        proxy.addr(),
        "HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "HEAD should return 200");
    assert!(parse_body(&raw).is_empty(), "HEAD response must have empty body");
    assert_eq!(
        suppress_count.load(Ordering::SeqCst),
        1,
        "suppress() must be called exactly once for HEAD"
    );
}

#[test]
fn streaming_204_calls_suppress_exactly_once() {
    let suppress_count = Arc::new(AtomicUsize::new(0));
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend.port(), "instrumented_suppress")).unwrap();
    let registry = registry_with_suppress(204, &suppress_count);
    let proxy = start_proxy_with_registry(&config, &registry);
    suppress_count.store(0, Ordering::SeqCst);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 204, "should return 204 No Content");
    assert!(parse_body(&raw).is_empty(), "204 response must have empty body");
    assert_eq!(
        suppress_count.load(Ordering::SeqCst),
        1,
        "suppress() must be called exactly once for 204"
    );
}

#[test]
fn streaming_304_calls_suppress_exactly_once() {
    let suppress_count = Arc::new(AtomicUsize::new(0));
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend.port(), "instrumented_suppress")).unwrap();
    let registry = registry_with_suppress(304, &suppress_count);
    let proxy = start_proxy_with_registry(&config, &registry);
    suppress_count.store(0, Ordering::SeqCst);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 304, "should return 304 Not Modified");
    assert!(parse_body(&raw).is_empty(), "304 response must have empty body");
    assert_eq!(
        suppress_count.load(Ordering::SeqCst),
        1,
        "suppress() must be called exactly once for 304"
    );
}

// -----------------------------------------------------------------------------
// Error / Reset Tests
// -----------------------------------------------------------------------------

#[test]
fn streaming_source_error_resets_connection() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend.port(), "error_streaming")).unwrap();
    let registry = registry_with("error_streaming", || Box::new(ErrorStreamingFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let mut stream = TcpStream::connect(proxy.addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();

    let mut response = Vec::new();
    let read_result = stream.read_to_end(&mut response);
    assert!(
        read_result.is_ok(),
        "read should complete (not timeout): {read_result:?}"
    );

    let raw = String::from_utf8_lossy(&response);
    assert_eq!(parse_status(&raw), 200, "headers commit before the source error");

    let (_, body_part) = raw
        .split_once("\r\n\r\n")
        .expect("response must have header/body separator");
    assert!(
        body_part.contains("first-chunk"),
        "first chunk must arrive before the source error: got {body_part:?}"
    );
    assert!(
        !body_part.ends_with("0\r\n\r\n"),
        "truncated stream must not end with a clean chunk terminator"
    );
}

#[test]
fn streaming_h2_source_error_resets_stream() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend.port(), "error_streaming")).unwrap();
    let registry = registry_with("error_streaming", || Box::new(ErrorStreamingFilter));
    let _proxy = start_proxy_with_registry(&config, &registry);

    let addr = format!("127.0.0.1:{proxy_port}");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let (mut client, h2_conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            drop(h2_conn.await);
        });

        let request = http::Request::get("/").header("host", "localhost").body(()).unwrap();
        let (response_fut, _) = client.send_request(request, true).unwrap();

        // RST_STREAM may arrive before or after HEADERS depending on
        // H2 frame batching; both orderings prove the server resets.
        match response_fut.await {
            Ok(response) => {
                assert_eq!(response.status(), 200, "H2 headers commit before source error");
                let mut body_stream = response.into_body();
                let mut got_data = false;
                let mut got_reset = false;
                loop {
                    match body_stream.data().await {
                        Some(Ok(data)) => {
                            got_data = true;
                            drop(body_stream.flow_control().release_capacity(data.len()));
                        },
                        Some(Err(_)) => {
                            got_reset = true;
                            break;
                        },
                        None => break,
                    }
                }
                assert!(
                    got_reset,
                    "H2 stream must reset after source error (got_data={got_data})"
                );
            },
            Err(e) => {
                let msg = format!("{e}");
                assert!(
                    msg.contains("internal error"),
                    "expected internal error RST_STREAM, got: {msg}"
                );
            },
        }
    });
}

// -----------------------------------------------------------------------------
// Cancellation Tests
// -----------------------------------------------------------------------------

#[test]
fn streaming_client_disconnect_calls_cancel() {
    let cancel_count = Arc::new(AtomicUsize::new(0));
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend.port(), "slow_streaming")).unwrap();
    let registry = registry_with_slow_stream(&cancel_count);
    let proxy = start_proxy_with_registry(&config, &registry);
    cancel_count.store(0, Ordering::SeqCst);

    {
        let mut stream = TcpStream::connect(proxy.addr()).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();

        let mut buf = Vec::new();
        let mut temp = [0_u8; 1024];
        loop {
            let n = stream.read(&mut temp).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&temp[..n]);
            if String::from_utf8_lossy(&buf).contains("first-chunk") {
                break;
            }
        }
        assert!(
            String::from_utf8_lossy(&buf).contains("first-chunk"),
            "first chunk must arrive before disconnect"
        );
    }

    std::thread::sleep(Duration::from_secs(3));

    assert!(
        cancel_count.load(Ordering::SeqCst) >= 1,
        "cancel() must be called when the client disconnects mid-stream"
    );
}

// -----------------------------------------------------------------------------
// H2C Client
// -----------------------------------------------------------------------------

fn h2c_get(addr: &str, path: &str) -> (http::Response<()>, String) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut client, h2_conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            drop(h2_conn.await);
        });

        let request = http::Request::get(path).header("host", "localhost").body(()).unwrap();

        let (response_fut, _) = client.send_request(request, true).unwrap();
        let response = response_fut.await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let mut body_stream = response.into_body();

        let mut body = Vec::new();
        while let Some(chunk) = body_stream.data().await {
            let data = chunk.unwrap();
            body.extend_from_slice(&data);
            drop(body_stream.flow_control().release_capacity(data.len()));
        }

        let mut resp_builder = http::Response::builder().status(status);
        for (key, value) in &headers {
            resp_builder = resp_builder.header(key, value);
        }
        let resp = resp_builder.body(()).unwrap();

        (resp, String::from_utf8_lossy(&body).into_owned())
    })
}
