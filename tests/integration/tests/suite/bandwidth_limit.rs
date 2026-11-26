// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the `bandwidth_limit` filter.

use std::{
    io::{ErrorKind, Read as _, Write as _},
    net::TcpStream,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_post, http_send, parse_status, start_backend_with_shutdown, start_echo_backend,
    start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn download_is_paced_when_there_is_no_burst() {
    let body = "x".repeat(16_000);
    let backend = start_backend_with_shutdown(&body);
    let proxy_port = free_port();
    let config = Config::from_yaml(&bandwidth_yaml(proxy_port, backend.port(), 0, true)).unwrap();
    let proxy = start_proxy(&config);

    let started = Instant::now();
    let (status, response) = http_get(proxy.addr(), "/", None);
    let elapsed = started.elapsed();

    assert_eq!(status, 200, "paced download should still succeed");
    assert_eq!(response.len(), 16_000, "the full body should arrive");
    assert!(
        elapsed >= Duration::from_millis(1_200),
        "16000 bytes at 8000 bytes per second should take about two seconds, elapsed {elapsed:?}"
    );
}

#[test]
fn download_burst_covers_a_small_body() {
    let body = "x".repeat(16_000);
    let backend = start_backend_with_shutdown(&body);
    let proxy_port = free_port();
    let config = Config::from_yaml(&bandwidth_yaml(proxy_port, backend.port(), 16_000, true)).unwrap();
    let proxy = start_proxy(&config);

    let started = Instant::now();
    let (status, response) = http_get(proxy.addr(), "/", None);
    let elapsed = started.elapsed();

    assert_eq!(status, 200, "a burst-covered download should succeed");
    assert_eq!(response.len(), 16_000, "the full body should arrive");
    assert!(
        elapsed < Duration::from_millis(1_000),
        "a burst that covers the body should not wait out the byte rate, elapsed {elapsed:?}"
    );
}

#[test]
fn headers_arrive_before_the_paced_body() {
    let body = "x".repeat(16_000);
    let backend = start_backend_with_shutdown(&body);
    let proxy_port = free_port();
    let config = Config::from_yaml(&bandwidth_yaml(proxy_port, backend.port(), 0, true)).unwrap();
    let proxy = start_proxy(&config);

    let (header_at, total, early_body, raw) = read_head_then_body(proxy.addr());

    assert!(
        header_at < Duration::from_millis(700),
        "the response head should arrive before the body wait, elapsed {header_at:?}"
    );
    assert_eq!(early_body, 0, "the body should still be waiting when the head arrives");
    assert!(
        raw.starts_with(b"HTTP/1.1 200") || raw.starts_with(b"HTTP/1.0 200"),
        "the head should be a successful response"
    );
    assert!(
        total >= Duration::from_millis(1_500),
        "16000 bytes at 8000 bytes per second should take about two seconds, elapsed {total:?}"
    );
    assert_eq!(
        praxis_test_utils::parse_body(std::str::from_utf8(&raw).unwrap()),
        "x".repeat(16_000),
        "the paced body should still arrive in full"
    );
}

#[test]
fn upload_is_paced_when_there_is_no_burst() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&bandwidth_yaml(proxy_port, backend.port(), 0, false)).unwrap();
    let proxy = start_proxy(&config);
    let payload = "y".repeat(8_000);

    let started = Instant::now();
    let (status, response) = http_post(proxy.addr(), "/", &payload);
    let elapsed = started.elapsed();

    assert_eq!(status, 200, "paced upload should still succeed");
    assert_eq!(response, payload, "the complete upload should reach the backend");
    assert!(
        elapsed >= Duration::from_millis(700),
        "8000 bytes at 8000 bytes per second should take about a second, elapsed {elapsed:?}"
    );
}

/// Observe upstream ingress while a single large live upload is still in flight.
#[test]
fn oversized_upload_reaches_the_upstream_in_paced_prefixes() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let backend_port = listener.local_addr().unwrap().port();
    let received = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&received);
    let origin = std::thread::spawn(move || {
        let mut stream = loop {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
            let mut head = Vec::new();
            let mut byte = [0; 1];
            while !head.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                head.extend_from_slice(&byte);
            }
            if head.starts_with(b"POST ") {
                break stream;
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        };
        let mut buffer = [0; 16_000];
        while counter.load(Ordering::SeqCst) < 16_000 {
            let count = stream.read(&mut buffer).unwrap();
            assert_ne!(count, 0, "upload must not end early");
            assert!(buffer[..count].iter().all(|byte| *byte == b'y'));
            counter.fetch_add(count, Ordering::SeqCst);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });
    let proxy = start_proxy(&Config::from_yaml(&bandwidth_yaml(free_port(), backend_port, 4_000, false)).unwrap());
    std::thread::scope(|scope| {
        let upload = scope.spawn(|| http_post(proxy.addr(), "/", &"y".repeat(16_000)));
        std::thread::sleep(Duration::from_millis(250));
        let first = received.load(Ordering::SeqCst);
        assert!(
            (4_000..=6_500).contains(&first),
            "the initial burst and refill must reach upstream: {first}"
        );
        std::thread::sleep(Duration::from_millis(500));
        let middle = received.load(Ordering::SeqCst);
        assert!(
            (8_000..=10_500).contains(&middle),
            "the upload must continue at its byte rate: {middle}"
        );
        assert_eq!(upload.join().unwrap(), (200, "ok".into()));
    });
    origin.join().unwrap();
    assert_eq!(received.load(Ordering::SeqCst), 16_000);
}

/// The HTTP/2 upstream writer must apply the same owned upload admission.
#[test]
fn upload_to_http2_upstream_is_paced() {
    let backend = praxis_test_utils::start_grpc_backend(
        praxis_test_utils::GrpcBackend::ok()
            .body("ok")
            .content_type("text/plain"),
    );
    let yaml = bandwidth_yaml(free_port(), backend.port(), 0, false).replace(
        "insecure_options:",
        "            http:\n              version: h2\ninsecure_options:",
    );
    let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());
    let started = Instant::now();
    let response = http_post(proxy.addr(), "/", &"y".repeat(8_000));
    assert_eq!(response, (200, "ok".into()));
    assert!(
        started.elapsed() >= Duration::from_millis(700),
        "H2 upstream upload must wait for its rate"
    );
}

#[cfg(feature = "pingora")]
#[test]
fn compression_keeps_download_pacing() {
    let body = "x".repeat(16_000);
    let backend = praxis_test_utils::Backend::fixed(&body)
        .header("Content-Type", "text/plain")
        .start_with_shutdown();
    let proxy_port = free_port();
    let yaml = bandwidth_yaml(proxy_port, backend.port(), 0, true).replace(
        "      - filter: router",
        "      - filter: compression\n        min_size_bytes: 1\n      - filter: router",
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let started = Instant::now();
    super::compression::assert_gzip_response(proxy.addr(), "/", &body, true);
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1_200),
        "compression must preserve the body wait, elapsed {elapsed:?}",
    );
}

#[test]
fn per_ip_connections_share_the_download_rate() {
    let expected = "x".repeat(8_000);
    let backend = start_backend_with_shutdown(&expected);
    let yaml = bandwidth_yaml(free_port(), backend.port(), 0, true).replace("mode: per_connection", "mode: per_ip");
    let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());
    let started = Instant::now();
    let responses = std::thread::scope(|scope| {
        let first = scope.spawn(|| http_get(proxy.addr(), "/", None));
        let second = scope.spawn(|| http_get(proxy.addr(), "/", None));
        (first.join().unwrap(), second.join().unwrap())
    });
    let elapsed = started.elapsed();
    for (status, body) in [responses.0, responses.1] {
        assert_eq!(status, 200, "both shared-budget downloads must succeed");
        assert_eq!(body, expected, "pacing must preserve each complete body");
    }
    assert!(
        elapsed >= Duration::from_millis(1_600),
        "two connections must share 8000 bytes/sec, elapsed {elapsed:?}"
    );
}

#[test]
fn per_ip_reconnect_does_not_reset_the_burst() {
    let expected = "x".repeat(8_000);
    let backend = start_backend_with_shutdown(&expected);
    let yaml = bandwidth_yaml(free_port(), backend.port(), 8_000, true).replace("mode: per_connection", "mode: per_ip");
    let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());
    let started = Instant::now();
    for _ in 0..2 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "both connections must succeed");
        assert_eq!(body, expected, "the body must be unchanged");
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(700),
        "a reconnect must not receive a second free burst, elapsed {elapsed:?}"
    );
}

#[test]
fn keepalive_requests_share_the_connection_burst() {
    let expected = "x".repeat(8_000);
    let backend = start_backend_with_shutdown(&expected);
    let yaml = bandwidth_yaml(free_port(), backend.port(), 8_000, true);
    let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());
    let mut connection = TcpStream::connect(proxy.addr()).unwrap();
    connection.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let started = Instant::now();
    for _ in 0..2 {
        let raw = praxis_test_utils::http_send_on_connection(
            &mut connection,
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
        );
        assert_eq!(parse_status(&raw), 200);
        assert_eq!(praxis_test_utils::parse_body(&raw), expected);
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(700),
        "a second request on one connection must reuse its budget, elapsed {elapsed:?}"
    );
}

#[test]
fn new_connections_have_independent_bursts() {
    let expected = "x".repeat(8_000);
    let backend = start_backend_with_shutdown(&expected);
    let yaml = bandwidth_yaml(free_port(), backend.port(), 8_000, true);
    let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());
    let started = Instant::now();
    for _ in 0..2 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200);
        assert_eq!(body, expected);
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(900),
        "each downstream connection must receive its own burst, elapsed {elapsed:?}"
    );
}

#[test]
fn http2_streams_share_the_connection_burst() {
    let expected = "x".repeat(8_000);
    let backend = start_backend_with_shutdown(&expected);
    let yaml = bandwidth_yaml(free_port(), backend.port(), 8_000, true);
    let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(8), async {
            let socket = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
            let (client, connection) = h2::client::handshake(socket).await.unwrap();
            let driver = tokio::spawn(async move {
                drop(connection.await);
            });
            let mut sender = client.ready().await.unwrap();
            let request = || http::Request::get("http://localhost/").body(()).unwrap();
            let started = Instant::now();
            let (first, _) = sender.send_request(request(), true).unwrap();
            let mut sender = sender.ready().await.unwrap();
            let (second, _) = sender.send_request(request(), true).unwrap();
            let (first_body, second_body) = tokio::join!(h2_body(first), h2_body(second));
            let elapsed = started.elapsed();
            assert_eq!(first_body, expected.as_bytes());
            assert_eq!(second_body, expected.as_bytes());
            assert!(
                elapsed >= Duration::from_millis(700),
                "HTTP/2 streams must not each get a new burst, elapsed {elapsed:?}"
            );
            driver.abort();
        })
        .await
        .expect("the shared HTTP/2 transfer must finish within eight seconds");
    });
}

#[test]
fn http2_uploads_share_the_connection_rate() {
    let expected = vec![b'u'; 8_000];
    let backend = start_echo_backend();
    let proxy = start_proxy(&Config::from_yaml(&bandwidth_yaml(free_port(), backend.port(), 0, false)).unwrap());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(8), async {
            let socket = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
            let (client, connection) = h2::client::handshake(socket).await.unwrap();
            let driver = tokio::spawn(async move {
                drop(connection.await);
            });
            let request = || {
                http::Request::post("http://localhost/")
                    .header("content-length", "8000")
                    .body(())
                    .unwrap()
            };
            let mut sender = client.ready().await.unwrap();
            let started = Instant::now();
            let (first, mut first_upload) = sender.send_request(request(), false).unwrap();
            first_upload
                .send_data(bytes::Bytes::copy_from_slice(&expected), true)
                .unwrap();
            let mut sender = sender.ready().await.unwrap();
            let (second, mut second_upload) = sender.send_request(request(), false).unwrap();
            second_upload
                .send_data(bytes::Bytes::copy_from_slice(&expected), true)
                .unwrap();
            let (first, second) = tokio::join!(h2_body(first), h2_body(second));
            assert_eq!(first, expected);
            assert_eq!(second, expected);
            assert!(
                started.elapsed() >= Duration::from_millis(1_600),
                "both uploads share 8000 bytes/sec"
            );
            driver.abort();
        })
        .await
        .expect("shared uploads must finish within eight seconds");
    });
}

/// Consume a complete HTTP/2 response while returning flow-control capacity.
async fn h2_body(response: h2::client::ResponseFuture) -> Vec<u8> {
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200, "the paced H2 response must succeed");
    let mut stream = response.into_body();
    let mut body = Vec::new();
    while let Some(chunk) = stream.data().await {
        let chunk = chunk.unwrap();
        body.extend_from_slice(&chunk);
        stream.flow_control().release_capacity(chunk.len()).unwrap();
    }
    body
}

#[test]
fn locally_generated_responses_are_paced() {
    let expected = "x".repeat(16_000);
    let backend = start_backend_with_shutdown("unused");
    let yaml = bandwidth_yaml(free_port(), backend.port(), 0, true).replace(
        "      - filter: router",
        &format!(
            "      - filter: static_response\n        status: 200\n        body: '{expected}'\n      - filter: router"
        ),
    );
    let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());
    let started = Instant::now();
    let (status, body) = http_get(proxy.addr(), "/", None);
    let elapsed = started.elapsed();
    assert_eq!(status, 200);
    assert_eq!(body, expected);
    assert!(
        elapsed >= Duration::from_millis(1_200),
        "a local response must not bypass the download limit, elapsed {elapsed:?}"
    );
}

#[test]
fn closing_rejection_does_not_write_an_http_error_body() {
    use std::sync::Arc;

    use praxis_filter::{FilterFactory, FilterRegistry};

    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "close_probe",
            FilterFactory::Http(Arc::new(|_| Ok(Box::new(CloseProbe)))),
        )
        .unwrap();
    let backend = start_backend_with_shutdown("ready");
    let yaml = bandwidth_yaml(free_port(), backend.port(), 0, true).replace(
        "      - filter: router",
        "      - filter: close_probe\n      - filter: router",
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = praxis_test_utils::start_proxy_with_registry(&config, &registry);
    let raw = http_send(
        proxy.addr(),
        "GET /close HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(
        raw.is_empty(),
        "a typed connection close must send no HTTP response: {raw}"
    );
}

/// Exercise a real bandwidth rejection when a host omits the connection identity.
struct CloseProbe;

#[async_trait::async_trait]
impl praxis_filter::HttpFilter for CloseProbe {
    fn name(&self) -> &'static str {
        "close_probe"
    }

    async fn on_request(
        &self,
        ctx: &mut praxis_filter::HttpFilterContext<'_>,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        if ctx.request.uri.path() == "/close" {
            let _previous = ctx.extensions.remove::<praxis_filter::DownstreamConnectionId>();
            let filter = praxis_filter::BandwidthLimitFilter::from_config(
                &serde_yaml::from_str("mode: per_connection\nupload_bytes_per_sec: 1").unwrap(),
            )?;
            filter.on_request(ctx).await
        } else {
            Ok(praxis_filter::FilterAction::Continue)
        }
    }
}

#[test]
fn http2_reset_refunds_unsent_bytes_for_a_sibling_stream() {
    let expected = "x".repeat(16_000);
    let backend = start_backend_with_shutdown(&expected);
    let yaml = bandwidth_yaml(free_port(), backend.port(), 0, true);
    let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(8), async {
            let socket = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
            let (client, connection) = h2::client::handshake(socket).await.unwrap();
            let driver = tokio::spawn(async move {
                drop(connection.await);
            });
            let mut sender = client.ready().await.unwrap();
            let request = || http::Request::get("http://localhost/").body(()).unwrap();
            let (head, mut reset) = sender.send_request(request(), true).unwrap();
            let response = head.await.unwrap();
            assert_eq!(response.status(), 200, "the paced H2 response must succeed");
            reset.send_reset(h2::Reason::CANCEL);
            drop(response);
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut sender = sender.ready().await.unwrap();
            let started = Instant::now();
            let (sibling, _) = sender.send_request(request(), true).unwrap();
            assert_eq!(h2_body(sibling).await, expected.as_bytes());
            let elapsed = started.elapsed();
            assert!(
                elapsed < Duration::from_millis(3_400),
                "a reset stream must not leave two seconds of unsent debt, elapsed {elapsed:?}"
            );
            driver.abort();
        })
        .await
        .expect("resetting one stream must leave its sibling able to complete");
    });
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Read a response, recording when the head finished and how many body bytes came with it.
fn read_head_then_body(addr: &str) -> (Duration, Duration, usize, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_nodelay(true).expect("nodelay");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("send request");

    let started = Instant::now();
    let mut data = Vec::new();
    let mut buf = [0_u8; 1024];
    let mut header_at = None;
    let mut early_body = 0;
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => note_read(&mut data, &buf[..n], started, &mut header_at, &mut early_body),
            Err(err) if err.kind() == ErrorKind::Interrupted => {},
            Err(err) if err.kind() == ErrorKind::TimedOut || err.kind() == ErrorKind::WouldBlock => break,
            Err(err) => panic!("read response: {err}"),
        }
    }
    let header_at = header_at.expect("response head");
    (header_at, started.elapsed(), early_body, data)
}

/// Append `chunk` and record the first moment the head is complete.
fn note_read(
    data: &mut Vec<u8>,
    chunk: &[u8],
    started: Instant,
    header_at: &mut Option<Duration>,
    early_body: &mut usize,
) {
    data.extend_from_slice(chunk);
    if header_at.is_some() {
        return;
    }
    let Some(end) = data.windows(4).position(|window| window == b"\r\n\r\n") else {
        return;
    };
    *header_at = Some(started.elapsed());
    *early_body = data
        .get(end.saturating_add(4)..)
        .unwrap_or_default()
        .iter()
        .filter(|byte| **byte == b'x')
        .count();
}

#[test]
fn oversized_download_releases_its_burst_before_waiting_for_the_tail() {
    let payload = "x".repeat(16_000);
    for local in [false, true] {
        let backend = start_backend_with_shutdown(&payload);
        let mut yaml = bandwidth_yaml(free_port(), backend.port(), 4_000, true);
        if local {
            yaml = yaml.replace("      - filter: router", &format!("      - filter: static_response\n        status: 200\n        body: {payload}\n      - filter: router"));
        }
        let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());
        let mut stream = TcpStream::connect(proxy.addr()).unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let started = Instant::now();
        let mut response = Vec::new();
        read_until(&mut stream, &mut response, started + Duration::from_millis(250));
        let first = payload_bytes(&response);
        assert!(
            (4_000..=6_500).contains(&first),
            "only the initial burst and refill may arrive early, got {first}"
        );
        read_until(&mut stream, &mut response, started + Duration::from_millis(750));
        let middle = payload_bytes(&response);
        assert!(
            (8_000..=10_500).contains(&middle),
            "the oversized body must progress in bounded portions, got {middle}"
        );
        read_until(&mut stream, &mut response, started + Duration::from_secs(4));
        assert_eq!(payload_bytes(&response), 16_000, "the complete body must arrive");
    }
}

/// Collect bytes only until an absolute observation instant.
fn read_until(stream: &mut TcpStream, response: &mut Vec<u8>, deadline: Instant) {
    let mut buf = [0_u8; 8192];
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        stream.set_read_timeout(Some(remaining)).unwrap();
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(bytes) => response.extend_from_slice(buf.get(..bytes).unwrap()),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(error) => panic!("read paced response: {error}"),
        }
    }
}

/// Count x payload bytes while excluding response headers and chunk framing.
fn payload_bytes(response: &[u8]) -> usize {
    response
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .and_then(|end| response.get(end.saturating_add(4)..))
        .map_or(0, |body| body.iter().filter(|byte| **byte == b'x').count())
}

/// Proxy config that paces either the response or the request.
fn bandwidth_yaml(proxy_port: u16, backend_port: u16, burst_bytes: u64, download: bool) -> String {
    let direction = if download {
        "download_bytes_per_sec: 8000"
    } else {
        "upload_bytes_per_sec: 8000"
    };
    format!(
        r#"
listeners:
  - name: proxy
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: bandwidth_limit
        mode: per_connection
        {direction}
        burst_bytes: {burst_bytes}
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
    )
}
