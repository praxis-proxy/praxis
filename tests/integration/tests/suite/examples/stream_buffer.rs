// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for stream buffer behavior.

use std::sync::Arc;
#[cfg(feature = "pingora")]
use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext,
};
use praxis_test_utils::{
    BackendGuard, ProxyGuard, free_port, http_post, http_send, parse_status, start_backend_with_shutdown,
    start_proxy_with_registry,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn stream_buffer_within_limit_succeeds() {
    let (_guard, proxy) = setup(256);
    let body = "a".repeat(100);
    let (status, _) = http_post(proxy.addr(), "/", &body);
    assert_eq!(status, 200, "body within limit should be accepted");
}

#[test]
fn stream_buffer_at_exact_limit_succeeds() {
    let (_guard, proxy) = setup(64);
    let body = "b".repeat(64);
    let (status, _) = http_post(proxy.addr(), "/", &body);
    assert_eq!(status, 200, "body at exact limit should be accepted");
}

#[test]
fn stream_buffer_exceeding_limit_returns_413() {
    let (_guard, proxy) = setup(64);
    let body = "c".repeat(128);
    let (status, _) = http_post(proxy.addr(), "/", &body);
    assert_eq!(status, 413, "body exceeding limit should be rejected with 413");
}

#[test]
fn stream_buffer_one_byte_over_returns_413() {
    let (_guard, proxy) = setup(64);
    let body = "d".repeat(65);
    let (status, _) = http_post(proxy.addr(), "/", &body);
    assert_eq!(status, 413, "body one byte over limit should be rejected with 413");
}

#[test]
fn stream_buffer_empty_body_succeeds() {
    let (_guard, proxy) = setup(64);
    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "empty body should be accepted");
}

#[cfg(feature = "pingora")]
#[test]
fn stream_buffer_large_upload_finishes_before_reading_413() {
    let (_guard, proxy) = setup(10_485_760);

    for size in [16_777_216, 35_651_584, 67_108_864] {
        let body = "a".repeat(size);
        let (status, _) = http_post(proxy.addr(), "/", &body);

        assert_eq!(
            status, 413,
            "a blocking uploader sending {size} bytes must receive 413 rather than a broken pipe"
        );
    }
}

#[cfg(feature = "pingora")]
#[test]
fn stream_buffer_large_content_length_upload_receives_413() {
    assert_large_upload_rejected(false);
}

#[cfg(feature = "pingora")]
#[test]
fn stream_buffer_large_chunked_upload_receives_413() {
    assert_large_upload_rejected(true);
}

#[cfg(feature = "pingora")]
#[tokio::test]
async fn stream_buffer_http2_rejection_keeps_the_connection_usable() {
    let (_guard, proxy) = setup(64);
    let stream = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
    let (mut client, connection) = h2::client::handshake(stream).await.unwrap();
    let driver = tokio::spawn(connection);

    tokio::time::timeout(Duration::from_secs(3), async {
        let request = http::Request::post("/")
            .header("host", "localhost")
            .header("content-length", "16777216")
            .body(())
            .unwrap();
        let (response, mut upload) = client.send_request(request, false).unwrap();
        upload.send_data(Bytes::from(vec![b'a'; 128]), false).unwrap();

        let mut response = response
            .await
            .expect("HTTP/2 must receive a rejection before upload completion");
        assert_eq!(response.status(), 413, "an oversized HTTP/2 stream must receive 413");
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json",
            "the rejection must declare its JSON media type"
        );
        let mut body = Vec::new();
        while let Some(chunk) = response.body_mut().data().await {
            body.extend_from_slice(&chunk.expect("the complete rejection body must arrive before stream cleanup"));
        }
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            error["error"], "request body too large",
            "the rejection must explain the limit failure"
        );

        let request = http::Request::get("/").header("host", "localhost").body(()).unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        assert_eq!(
            response.await.unwrap().status(),
            200,
            "other streams must remain usable"
        );
    })
    .await
    .expect("HTTP/2 rejection must not wait for the HTTP/1 drain timeout");

    driver.abort();
    let _result = driver.await;
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Verify that a client can finish an oversized upload after an early 413.
#[cfg(feature = "pingora")]
fn assert_large_upload_rejected(chunked: bool) {
    let (_guard, proxy) = setup(64);
    let stream = TcpStream::connect(proxy.addr()).expect("connect to proxy");
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut conn = BufReader::new(stream);
    let size = 16_777_216;
    let framing = if chunked {
        "Transfer-Encoding: chunked".to_owned()
    } else {
        format!("Content-Length: {size}")
    };
    write!(
        conn.get_mut(),
        "POST / HTTP/1.1\r\nHost: localhost\r\n{framing}\r\n\r\n"
    )
    .unwrap();
    if chunked {
        write!(conn.get_mut(), "{size:x}\r\n").unwrap();
    }
    conn.get_mut().write_all(&[b'a'; 128]).unwrap();

    let mut head = String::new();
    loop {
        let mut line = String::new();
        assert_ne!(
            conn.read_line(&mut line).unwrap(),
            0,
            "413 headers must arrive before upload completion"
        );
        head.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    assert_eq!(parse_status(&head), 413, "early rejection must be an HTTP response");
    assert!(
        head.to_ascii_lowercase().contains("connection: close"),
        "rejected connections must not be reused"
    );
    assert!(
        head.to_ascii_lowercase().contains("content-type: application/json"),
        "the rejection must declare its JSON media type"
    );
    let length = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
        .expect("JSON rejection must have an explicit length");
    let mut body = vec![0; length];
    conn.read_exact(&mut body).unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        error["error"], "request body too large",
        "the rejection must explain the limit failure"
    );

    let remaining = vec![b'a'; size - 128];
    conn.get_mut()
        .write_all(&remaining)
        .expect("remaining upload must be drained without a broken pipe");
    if chunked {
        conn.get_mut().write_all(b"\r\n0\r\n\r\n").unwrap();
    }
    let mut tail = Vec::new();
    conn.read_to_end(&mut tail)
        .expect("completed rejection must close cleanly");
    assert!(tail.is_empty(), "the connection must carry exactly one response");
}

/// Declares StreamBuffer with a small max_bytes for testing 413 enforcement.
struct TinyStreamBufferFilter {
    max_bytes: usize,
}

impl TinyStreamBufferFilter {
    fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        #[derive(serde::Deserialize)]
        struct Cfg {
            max_bytes: usize,
        }
        let cfg: Cfg = serde_yaml::from_value(config.clone()).map_err(|e| -> FilterError { e.to_string().into() })?;
        Ok(Box::new(Self {
            max_bytes: cfg.max_bytes,
        }))
    }
}

#[async_trait::async_trait]
impl HttpFilter for TinyStreamBufferFilter {
    fn name(&self) -> &'static str {
        "tiny_stream_buffer"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.max_bytes),
        }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Release)
    }
}

/// Start a proxy with a tiny stream buffer filter and return the guard and proxy.
fn setup(max_bytes: usize) -> (BackendGuard, ProxyGuard) {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: tiny_stream_buffer
        max_bytes: {max_bytes}
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "tiny_stream_buffer",
            FilterFactory::Http(Arc::new(TinyStreamBufferFilter::from_config)),
        )
        .expect("duplicate filter name");
    let proxy = start_proxy_with_registry(&config, &registry);
    (backend_port_guard, proxy)
}
