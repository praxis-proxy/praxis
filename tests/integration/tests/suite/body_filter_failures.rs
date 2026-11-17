// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for body-filter failure handling: response body
//! rejections, filter errors, and stream-buffer ceilings on proxied
//! responses.

use std::{
    io::{BufReader, ErrorKind, Write as _},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};

use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyMode, BodyRequirement, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter,
    HttpFilterContext, Rejection,
};
use praxis_test_utils::{
    Backend, H1Completion, H1Response, PayloadResponseFraming, PayloadSpec, free_port, http_get, http_send, parse_body,
    parse_header, parse_status, read_h1_response, start_full_proxy_with_registry, start_payload_response_backend,
    wait_for_tcp,
};

// ---------------------------------------------------------------------------
// Custom filters
// ---------------------------------------------------------------------------

/// Response-body filter that rejects once the full body has streamed.
struct RejectResponseBodyFilter {
    reject_at_eos: bool,
    eos_seen: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl HttpFilter for RejectResponseBodyFilter {
    fn name(&self) -> &'static str {
        "test_reject_response_body"
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(BodyRequirement::Optional)
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if end_of_stream {
            self.eos_seen.store(true, Ordering::SeqCst);
            if self.reject_at_eos {
                Ok(FilterAction::Reject(Rejection::status(451)))
            } else {
                Ok(FilterAction::Continue)
            }
        } else {
            Ok(FilterAction::Continue)
        }
    }
}

/// Response-phase filter that rejects with configured headers and body.
struct HeaderRejectResponseFilter;

#[async_trait::async_trait]
impl HttpFilter for HeaderRejectResponseFilter {
    fn name(&self) -> &'static str {
        "test_reject_response_phase"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Reject(
            Rejection::status(429)
                .with_header("Retry-After", "7")
                .with_body("slow down"),
        ))
    }
}

/// Response-body filter that errors on every chunk.
struct ErrorResponseBodyFilter;

#[async_trait::async_trait]
impl HttpFilter for ErrorResponseBodyFilter {
    fn name(&self) -> &'static str {
        "test_error_response_body"
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(BodyRequirement::Optional)
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        Err("test_error_response_body: body inspection failed".to_owned().into())
    }
}

/// Response-body filter that fails only on the synthetic end-of-stream hook.
struct ErrorAtResponseEofFilter {
    /// Records that the final callback was reached.
    eof_seen: Arc<AtomicBool>,
    /// Whether the final body callback fails or continues as a control.
    error_at_eof: bool,
}

#[async_trait::async_trait]
impl HttpFilter for ErrorAtResponseEofFilter {
    fn name(&self) -> &'static str {
        "test_error_at_response_eof"
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(BodyRequirement::Optional)
    }

    fn response_trailer_access(&self) -> bool {
        true
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if end_of_stream {
            self.eof_seen.store(true, Ordering::SeqCst);
            if self.error_at_eof {
                return Err("test_error_at_response_eof: synthetic EOF failed".to_owned().into());
            }
        }
        Ok(FilterAction::Continue)
    }
}

/// Response-body filter that buffers with a tiny StreamBuffer ceiling.
struct TinyBufferResponseFilter;

#[async_trait::async_trait]
impl HttpFilter for TinyBufferResponseFilter {
    fn name(&self) -> &'static str {
        "test_tiny_buffer_response"
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(BodyRequirement::Optional)
    }

    fn response_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(8) }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

/// Request-body filter that errors on every chunk.
struct ErrorRequestBodyFilter;

#[async_trait::async_trait]
impl HttpFilter for ErrorRequestBodyFilter {
    fn name(&self) -> &'static str {
        "test_error_request_body"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(BodyRequirement::Optional)
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
        Err("test_error_request_body: body inspection failed".to_owned().into())
    }
}

/// Registry with builtins plus the failing body filters.
fn registry() -> FilterRegistry {
    registry_with_eos(true, Arc::new(AtomicBool::new(false)))
}

/// Registry with a selectable EOS outcome and observable hook invocation.
fn registry_with_eos(reject_at_eos: bool, eos_seen: Arc<AtomicBool>) -> FilterRegistry {
    let mut reg = FilterRegistry::with_builtins();
    reg.register(
        "test_reject_response_body",
        FilterFactory::Http(Arc::new(move |_| {
            Ok(Box::new(RejectResponseBodyFilter {
                reject_at_eos,
                eos_seen: Arc::clone(&eos_seen),
            }))
        })),
    )
    .unwrap();
    reg.register(
        "test_error_response_body",
        FilterFactory::Http(Arc::new(|_| Ok(Box::new(ErrorResponseBodyFilter)))),
    )
    .unwrap();
    reg.register(
        "test_error_at_response_eof",
        FilterFactory::Http(Arc::new(|_| {
            Ok(Box::new(ErrorAtResponseEofFilter {
                eof_seen: Arc::new(AtomicBool::new(false)),
                error_at_eof: true,
            }))
        })),
    )
    .unwrap();
    reg.register(
        "test_reject_response_phase",
        FilterFactory::Http(Arc::new(|_| Ok(Box::new(HeaderRejectResponseFilter)))),
    )
    .unwrap();
    reg.register(
        "test_tiny_buffer_response",
        FilterFactory::Http(Arc::new(|_| Ok(Box::new(TinyBufferResponseFilter)))),
    )
    .unwrap();
    reg.register(
        "test_error_request_body",
        FilterFactory::Http(Arc::new(|_| Ok(Box::new(ErrorRequestBodyFilter)))),
    )
    .unwrap();
    reg
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Proxy YAML with the given filter ahead of router + load balancer.
fn proxy_yaml(proxy_port: u16, backend_port: u16, filter_name: &str) -> String {
    format!(
        r#"
listeners:
  - name: web
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]

insecure_options:
  allow_private_endpoints: true
  allow_private_upstreams: true

filter_chains:
  - name: main
    filters:
      - filter: {filter_name}
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

/// Proxy YAML for a filter that exercises the HTTP/2 response-trailer path.
fn h2_proxy_yaml(proxy_port: u16, backend_port: u16, filter_name: &str) -> String {
    format!(
        r#"
listeners:
  - name: web
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]

insecure_options:
  allow_private_endpoints: true
  allow_private_upstreams: true

filter_chains:
  - name: main
    filters:
      - filter: {filter_name}
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
            http:
              version: h2
"#
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn response_body_eos_rejection_aborts_stream() {
    let spec = PayloadSpec::binary(16_384, 17);
    let expected = spec.chunk(0, 16_384);
    let (continued, continued_body, continued_eos) = observe_response_body_eos(false, spec.clone());
    assert!(continued_eos, "control EOS hook must run");
    assert_eq!(continued.status, Some(200), "{continued:?}");
    assert_eq!(continued_body, expected, "control must deliver the exact payload");
    assert_eq!(continued.body_bytes, spec.len(), "{continued:?}");
    assert_eq!(continued.completion, Some(H1Completion::Chunked), "{continued:?}");
    assert_eq!(continued.abort, None, "{continued:?}");

    let (rejected, rejected_body, rejected_eos) = observe_response_body_eos(true, spec);
    assert!(rejected_eos, "rejection EOS hook must run");
    assert_eq!(
        rejected.status,
        Some(200),
        "status must already be committed: {rejected:?}"
    );
    assert_eq!(rejected_body, expected, "accepted Stream bytes must remain observable");
    assert_eq!(rejected.body_bytes, 16_384, "{rejected:?}");
    assert_eq!(
        rejected.completion, None,
        "rejected stream must not complete: {rejected:?}"
    );
    assert!(
        rejected.abort.as_ref().is_some_and(|(kind, _)| matches!(
            kind,
            ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
        )),
        "rejected stream must end at the peer, not at a deadline: {rejected:?}"
    );
}

/// Gate the upstream terminator on complete client observation of its content.
fn observe_response_body_eos(reject_at_eos: bool, spec: PayloadSpec) -> (H1Response, Vec<u8>, bool) {
    let mut source = start_payload_response_backend(spec.clone(), PayloadResponseFraming::Chunked, Some(spec.len()));
    let proxy_port = free_port();
    let config = Config::from_yaml(&proxy_yaml(proxy_port, source.port, "test_reject_response_body")).unwrap();
    let eos_seen = Arc::new(AtomicBool::new(false));
    let reg = registry_with_eos(reject_at_eos, Arc::clone(&eos_seen));
    let _proxy = start_full_proxy_with_registry(&config, &reg);
    let address = format!("127.0.0.1:{proxy_port}");
    wait_for_tcp(&address);
    let (observed_tx, observed_rx) = mpsc::channel();
    let client = std::thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(address).expect("connect EOS client");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read deadline");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set write deadline");
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .expect("send EOS request");
        let mut body = Vec::new();
        let mut acknowledged = false;
        let response = read_h1_response(&mut BufReader::new(stream), false, spec.len(), |part| {
            body.extend_from_slice(part);
            if body.len() == 16_384 && !acknowledged {
                acknowledged = true;
                observed_tx.send(()).expect("acknowledge client-observed payload");
            }
            Ok(())
        });
        (response, body)
    });
    let paused = source.prefix_written.recv_timeout(Duration::from_secs(5));
    let observed = observed_rx.recv_timeout(Duration::from_secs(5));
    source.resume();
    let (response, body) = client.join().expect("EOS client thread");
    source.join();
    assert_eq!(
        paused.expect("source pause before terminating chunk"),
        16_384,
        "the backend must pause after sending the complete accepted prefix"
    );
    observed.expect("client must observe accepted content before EOS release");
    (response, body, eos_seen.load(Ordering::SeqCst))
}

#[test]
fn response_phase_rejection_delivers_headers_and_body() {
    let backend_port = Backend::fixed("upstream-content").start();
    let proxy_port = free_port();
    let config = Config::from_yaml(&proxy_yaml(proxy_port, backend_port, "test_reject_response_phase")).unwrap();
    let reg = registry();
    let _proxy = start_full_proxy_with_registry(&config, &reg);

    let raw = http_send(
        &format!("127.0.0.1:{proxy_port}"),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 429, "rejection status must reach the client");
    assert_eq!(
        parse_header(&raw, "Retry-After").as_deref(),
        Some("7"),
        "rejection headers must survive the response-phase error boundary: {raw}"
    );
    let body = parse_body(&raw);
    assert_eq!(body, "slow down", "rejection body must reach the client");
    assert!(
        !raw.contains("upstream-content"),
        "rejected upstream content must not leak: {raw}"
    );
}

#[test]
fn response_body_filter_error_does_not_deliver_body() {
    let backend_port = Backend::fixed("confidential-payload").start();
    let proxy_port = free_port();
    let config = Config::from_yaml(&proxy_yaml(proxy_port, backend_port, "test_error_response_body")).unwrap();
    let reg = registry();
    let _proxy = start_full_proxy_with_registry(&config, &reg);

    let (_status, body) = http_get(&format!("127.0.0.1:{proxy_port}"), "/", None);
    assert!(
        !body.contains("confidential-payload"),
        "an errored response body must not reach the client: {body:?}"
    );
}

#[test]
fn synthetic_eof_filter_error_aborts_h2_trailer_delivery() {
    let prefix = Bytes::from_static(b"\x00\x00\x00\x00\x02hi");
    for error_at_eof in [false, true] {
        let (response, body, eof_seen) = observe_synthetic_response_eof(error_at_eof, &prefix);
        assert!(eof_seen, "the synthetic EOF hook must run: {response:?}");
        assert_eq!(response.status, Some(200), "the client observed the head before EOF");
        assert_eq!(body, prefix, "accepted bytes must survive the final hook");
        if error_at_eof {
            assert_eq!(response.completion, None, "failed EOF must not complete: {response:?}");
            assert!(
                response.abort.as_ref().is_some_and(|(kind, _)| matches!(
                    kind,
                    ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
                )),
                "EOF failure must produce a peer abort, not a read deadline: {response:?}"
            );
        } else {
            assert_eq!(response.completion, Some(H1Completion::Chunked), "{response:?}");
            assert_eq!(response.abort, None, "successful EOF must complete: {response:?}");
        }
    }
}

/// Release upstream trailers only after the H1 client observes every accepted byte.
fn observe_synthetic_response_eof(error_at_eof: bool, prefix: &Bytes) -> (H1Response, Vec<u8>, bool) {
    let backend = PausedH2EofBackend::start(prefix.clone());
    let proxy_port = free_port();
    let config = Config::from_yaml(&h2_proxy_yaml(proxy_port, backend.port, "test_error_at_response_eof"))
        .expect("HTTP/2 proxy config should parse");
    let eof_seen = Arc::new(AtomicBool::new(false));
    let filter_eof_seen = Arc::clone(&eof_seen);
    let mut reg = FilterRegistry::with_builtins();
    reg.register(
        "test_error_at_response_eof",
        FilterFactory::Http(Arc::new(move |_| {
            Ok(Box::new(ErrorAtResponseEofFilter {
                eof_seen: Arc::clone(&filter_eof_seen),
                error_at_eof,
            }))
        })),
    )
    .expect("register EOF probe");
    let proxy = start_full_proxy_with_registry(&config, &reg);
    wait_for_tcp(proxy.addr());
    let mut stream = std::net::TcpStream::connect(proxy.addr()).expect("connect synthetic EOF client");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    stream
        .write_all(
            b"POST /pkg.Svc/Method HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/grpc\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .expect("send synthetic EOF request");
    let mut body = Vec::new();
    let mut observed = false;
    let response = read_h1_response(
        &mut BufReader::new(stream),
        false,
        u64::try_from(prefix.len()).unwrap(),
        |part| {
            body.extend_from_slice(part);
            if !observed && body.as_slice() == prefix.as_ref() {
                observed = true;
                backend.release.notify_one();
            }
            Ok(())
        },
    );
    assert!(
        observed,
        "the client must observe the exact prefix before trailer release: {response:?}"
    );
    (response, body, eof_seen.load(Ordering::SeqCst))
}

/// Own the H2 backend runtime and a client-observation gate for its trailers.
struct PausedH2EofBackend {
    /// Bound backend port.
    port: u16,
    /// Permit sent only after the client observes the expected response prefix.
    release: Arc<tokio::sync::Notify>,
    /// Stop the accept loop and all connection tasks during cleanup.
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    /// Backend thread joined before its guard is released.
    worker: Option<std::thread::JoinHandle<()>>,
}

impl PausedH2EofBackend {
    /// Bind before returning, and keep every async task inside the owned runtime.
    fn start(prefix: Bytes) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind paused H2 backend");
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let release = Arc::new(tokio::sync::Notify::new());
        let server_release = Arc::clone(&release);
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let worker = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("paused H2 backend runtime");
            runtime.block_on(run_paused_h2_backend(listener, prefix, server_release, shutdown_rx));
        });
        Self {
            port,
            release,
            shutdown: Some(shutdown),
            worker: Some(worker),
        }
    }
}

impl Drop for PausedH2EofBackend {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _sent = shutdown.send(());
        }
        if let Some(worker) = self.worker.take() {
            let joined = worker.join();
            if !std::thread::panicking() {
                joined.expect("paused H2 backend thread");
            }
        }
    }
}

/// Accept connections while retaining cancellation ownership of their tasks.
async fn run_paused_h2_backend(
    listener: std::net::TcpListener,
    prefix: Bytes,
    release: Arc<tokio::sync::Notify>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) {
    let listener = tokio::net::TcpListener::from_std(listener).expect("adopt H2 listener");
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted.expect("accept H2 connection");
                connections.spawn(serve_paused_h2_connection(stream, prefix.clone(), Arc::clone(&release)));
            },
            Some(joined) = connections.join_next(), if !connections.is_empty() => {
                joined.expect("paused H2 connection task");
            },
        }
    }
    connections.shutdown().await;
}

/// Drive H2 I/O while the response waits for the client's observation permit.
async fn serve_paused_h2_connection(stream: tokio::net::TcpStream, prefix: Bytes, release: Arc<tokio::sync::Notify>) {
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    let Some(Ok((request, respond))) = connection.accept().await else {
        return;
    };
    let drive = async {
        if let Some(Ok(_)) = connection.accept().await {
            panic!("unexpected second request to the paused H2 backend");
        }
    };
    tokio::pin!(drive);
    tokio::select! {
        () = serve_paused_h2_response(request, respond, prefix, release) => drive.await,
        () = &mut drive => {},
    }
}

/// Emit trailers only after exact downstream prefix observation, with a bounded wait.
async fn serve_paused_h2_response(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    prefix: Bytes,
    release: Arc<tokio::sync::Notify>,
) {
    let mut request_body = request.into_body();
    while let Some(chunk) = request_body.data().await {
        let chunk = chunk.expect("read H2 request body");
        request_body.flow_control().release_capacity(chunk.len()).unwrap();
    }
    let response = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(())
        .unwrap();
    let mut send = respond.send_response(response, false).expect("send H2 response head");
    send.send_data(prefix, false).expect("send accepted H2 prefix");
    tokio::time::timeout(Duration::from_secs(5), release.notified())
        .await
        .expect("client must observe prefix before trailers");
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
    send.send_trailers(trailers).expect("release H2 response trailers");
}

#[test]
fn response_over_stream_buffer_ceiling_is_not_delivered() {
    let big_body = "x".repeat(64);
    let backend_port = Backend::fixed(&big_body).start();
    let proxy_port = free_port();
    let config = Config::from_yaml(&proxy_yaml(proxy_port, backend_port, "test_tiny_buffer_response")).unwrap();
    let reg = registry();
    let _proxy = start_full_proxy_with_registry(&config, &reg);

    use std::io::{BufReader, Write as _};
    let address = format!("127.0.0.1:{proxy_port}");
    wait_for_tcp(&address);
    let mut stream = std::net::TcpStream::connect(&address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut body = Vec::new();
    let result = read_h1_response(&mut BufReader::new(stream), false, 4096, |part| {
        body.extend_from_slice(part);
        Ok(())
    });
    praxis_test_utils::assert_buffered_response_rejected(&result, &body);
}

#[test]
fn head_rejection_sends_no_body() {
    let backend_port = Backend::fixed("should-not-be-reached").start();
    let proxy_port = free_port();
    let config = Config::from_yaml(&proxy_yaml(proxy_port, backend_port, "test_reject_response_phase")).unwrap();
    let reg = registry();
    let _proxy = start_full_proxy_with_registry(&config, &reg);

    use std::io::{BufReader, Read as _, Write as _};
    let address = format!("127.0.0.1:{proxy_port}");
    wait_for_tcp(&address);
    let mut stream = std::net::TcpStream::connect(&address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream
        .write_all(b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut body = Vec::new();
    let response = read_h1_response(&mut reader, true, 4096, |part| {
        body.extend_from_slice(part);
        Ok(())
    });
    assert_eq!(
        response.status,
        Some(429),
        "a HEAD rejection must keep its status: {response:?}"
    );
    assert_eq!(
        response.completion,
        Some(H1Completion::Headers),
        "a HEAD response completes at its header terminator, whatever Content-Length it \
         advertises: {response:?}"
    );
    assert!(body.is_empty(), "a HEAD rejection must not send a body, got {body:?}");
    assert!(
        response
            .headers
            .iter()
            .any(|(name, value)| name == "retry-after" && value == "7"),
        "a HEAD rejection must keep its response headers: {response:?}"
    );
    // HEAD reading stops at the header terminator, so drain the rest of the
    // connection: the rejection must send no trailing bytes and must close
    // (the stream's read timeout bounds the wait).
    let mut trailing = Vec::new();
    reader
        .read_to_end(&mut trailing)
        .expect("the connection must close after the HEAD response");
    assert!(
        trailing.is_empty(),
        "a HEAD rejection must not send trailing bytes after the headers, got {trailing:?}"
    );
}

#[test]
fn request_body_filter_error_rejects_request() {
    let backend_port = Backend::fixed("should-not-be-reached").start();
    let proxy_port = free_port();
    let config = Config::from_yaml(&proxy_yaml(proxy_port, backend_port, "test_error_request_body")).unwrap();
    let reg = registry();
    let _proxy = start_full_proxy_with_registry(&config, &reg);

    let raw = http_send(
        &format!("127.0.0.1:{proxy_port}"),
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
    );
    assert_eq!(
        parse_status(&raw),
        500,
        "a body-filter failure must still deliver its 500 response"
    );
    assert!(
        !raw.contains("should-not-be-reached"),
        "an errored request body must not be forwarded: {raw:?}"
    );
}
