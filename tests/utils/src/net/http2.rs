// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! HTTP/2 streaming helpers with explicit completion and reset observations.

use std::io;

use bytes::Bytes;

use crate::payload::PayloadSpec;

/// Maximum generated chunk size accepted by the H2 sender.
const MAX_H2_CHUNK: usize = 65_536; // 64 KiB

/// Outcome of streaming a request body to an HTTP/2 send stream.
#[derive(Debug, Default)]
pub struct H2Upload {
    /// Bytes successfully queued to the H2 library, not proof of peer receipt.
    pub queued_bytes: u64,
    /// Whether an `END_STREAM` was successfully queued.
    pub end_stream: bool,
    /// Reset reason reported by h2, when available.
    pub reset: Option<h2::Reason>,
    /// Error or reset observed while sending.
    pub abort: Option<String>,
}

/// Outcome of receiving an HTTP/2 response body.
#[derive(Debug, Default)]
pub struct H2Response {
    /// Final status, absent if response headers failed.
    pub status: Option<u16>,
    /// Response headers, absent if response headers failed.
    pub headers: Option<http::HeaderMap>,
    /// Body bytes successfully passed to the sink.
    pub body_bytes: u64,
    /// Whether the stream reached `END_STREAM` without error.
    pub end_stream: bool,
    /// Received trailers, if any.
    pub trailers: Option<http::HeaderMap>,
    /// Reset reason reported by h2, when available.
    pub reset: Option<h2::Reason>,
    /// Error describing failure or observation-limit exhaustion.
    pub abort: Option<String>,
}

/// Queue a generated request body while respecting HTTP/2 flow control.
///
/// This function does not create or drive a connection. Callers may use h2's
/// handshake on an existing plain TCP or TLS stream, drive the connection in
/// a task, and apply their own deadline. A successful send only means h2
/// accepted the bytes; use a backend receipt to prove delivery.
pub async fn send_h2_payload(stream: &mut h2::SendStream<Bytes>, spec: &PayloadSpec, chunk_size: usize) -> H2Upload {
    let mut result = H2Upload::default();
    if chunk_size == 0 {
        result.abort = Some("chunk size must be nonzero".to_owned());
        return result;
    }
    while !result.end_stream {
        if let Err(error) = queue_payload_chunk(stream, spec, chunk_size.min(MAX_H2_CHUNK), &mut result).await {
            result.abort = Some(error);
            break;
        }
    }
    result
}

/// Queue one bounded chunk, including an empty final frame for an empty body.
async fn queue_payload_chunk(
    stream: &mut h2::SendStream<Bytes>,
    spec: &PayloadSpec,
    chunk_size: usize,
    result: &mut H2Upload,
) -> Result<(), String> {
    let remaining = spec.len().saturating_sub(result.queued_bytes);
    let desired = usize::try_from(remaining).unwrap_or(usize::MAX).min(chunk_size);
    let capacity = if desired == 0 {
        0
    } else {
        available_capacity(stream, desired).await?
    };
    let bytes = spec.chunk(result.queued_bytes, desired.min(capacity));
    let length = u64::try_from(bytes.len()).expect("bounded chunk length");
    let last = result.queued_bytes + length == spec.len();
    stream
        .send_data(Bytes::from(bytes), last)
        .map_err(|error| error.to_string())?;
    result.queued_bytes += length;
    result.end_stream = last;
    Ok(())
}

/// Wait for positive flow-control capacity or a terminal stream outcome.
async fn available_capacity(stream: &mut h2::SendStream<Bytes>, desired: usize) -> Result<usize, String> {
    stream.reserve_capacity(desired);
    if stream.capacity() > 0 {
        return Ok(stream.capacity());
    }
    loop {
        match std::future::poll_fn(|cx| stream.poll_capacity(cx)).await {
            Some(Ok(0)) => {},
            Some(Ok(capacity)) => return Ok(capacity),
            Some(Err(error)) => return Err(error.to_string()),
            None => return Err("HTTP/2 stream closed before upload completed".to_owned()),
        }
    }
}

/// Stream a response to `sink`, recording `END_STREAM` separately from status.
///
/// Apply a deadline around this future and drive the h2 connection separately.
/// The body limit applies to bytes delivered to the sink, not to frame syntax.
pub async fn read_h2_response<F>(
    response: Result<http::Response<h2::RecvStream>, h2::Error>,
    max_body: u64,
    mut sink: F,
) -> H2Response
where
    F: FnMut(&[u8]) -> io::Result<()>,
{
    let mut result = H2Response::default();
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            record_error(&mut result, &error);
            return result;
        },
    };
    let (parts, mut body) = response.into_parts();
    result.status = Some(parts.status.as_u16());
    result.headers = Some(parts.headers);
    if !receive_h2_data(&mut body, max_body, &mut sink, &mut result).await {
        return result;
    }
    match body.trailers().await {
        Ok(trailers) => {
            result.trailers = trailers;
            result.end_stream = true;
        },
        Err(error) => record_error(&mut result, &error),
    }
    result
}

/// Receive content frames while returning capacity only after their observation.
async fn receive_h2_data<F>(body: &mut h2::RecvStream, max: u64, sink: &mut F, result: &mut H2Response) -> bool
where
    F: FnMut(&[u8]) -> io::Result<()>,
{
    while let Some(frame) = body.data().await {
        let bytes = match frame {
            Ok(bytes) => bytes,
            Err(error) => {
                record_error(result, &error);
                return false;
            },
        };
        if !deliver_h2_data(&bytes, max, sink, result) {
            return false;
        }
        if let Err(error) = body.flow_control().release_capacity(bytes.len()) {
            record_error(result, &error);
            return false;
        }
    }
    true
}

/// Deliver a content prefix within the observation cap and preserve its count.
fn deliver_h2_data<F>(bytes: &[u8], max: u64, sink: &mut F, result: &mut H2Response) -> bool
where
    F: FnMut(&[u8]) -> io::Result<()>,
{
    let remaining = usize::try_from(max.saturating_sub(result.body_bytes)).unwrap_or(usize::MAX);
    let accepted = bytes.len().min(remaining);
    if let Err(error) = sink(&bytes[..accepted]) {
        result.abort = Some(error.to_string());
        return false;
    }
    result.body_bytes += u64::try_from(accepted).expect("observed frame length");
    if accepted < bytes.len() {
        result.abort = Some("body exceeds observation limit".to_owned());
        return false;
    }
    true
}

/// Preserve an h2 error's reset reason and diagnostic.
fn record_error(result: &mut H2Response, error: &h2::Error) {
    result.reset = error.reason();
    result.abort = Some(error.to_string());
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use bytes::Bytes;
    use tokio::{
        io::{DuplexStream, duplex},
        sync::oneshot,
        task::JoinHandle,
        time::timeout,
    };

    use super::{H2Response, read_h2_response, send_h2_payload};
    use crate::payload::PayloadSpec;

    /// Validate an uploaded binary body before returning a small response.
    fn binary_server(server_io: DuplexStream, expected: PayloadSpec) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            tokio::spawn(async move {
                let mut body = request.into_body();
                let mut offset = 0;
                while let Some(frame) = body.data().await {
                    let bytes = frame.unwrap();
                    assert_eq!(expected.mismatch(offset, &bytes), None);
                    offset += bytes.len() as u64;
                    body.flow_control().release_capacity(bytes.len()).unwrap();
                }
                assert_eq!(offset, expected.len());
                let mut send = respond.send_response(http::Response::new(()), false).unwrap();
                send.send_data(Bytes::from_static(b"a\0b"), true).unwrap();
            });
            while connection.accept().await.is_some() {}
        })
    }

    /// Collect only the small, bounded response used in these helper self-checks.
    async fn collect_response(response: h2::client::ResponseFuture, maximum: u64) -> (H2Response, Vec<u8>) {
        let mut received = Vec::new();
        let outcome = timeout(Duration::from_secs(5), async {
            read_h2_response(response.await, maximum, |part| {
                received.extend_from_slice(part);
                Ok(())
            })
            .await
        })
        .await
        .unwrap();
        (outcome, received)
    }

    #[tokio::test]
    async fn h2_streams_binary_payload_under_flow_control() {
        let (client_io, server_io) = duplex(131_072);
        let spec = PayloadSpec::binary(200_000, 81);
        let server = binary_server(server_io, spec.clone());
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(connection);
        let request = http::Request::post("http://localhost/upload").body(()).unwrap();
        let (response, mut send) = client.send_request(request, false).unwrap();
        let upload = timeout(Duration::from_secs(5), send_h2_payload(&mut send, &spec, 4096))
            .await
            .unwrap();
        assert_eq!(upload.queued_bytes, spec.len());
        assert!(upload.end_stream);
        assert_eq!(upload.abort, None);
        let (outcome, received) = collect_response(response, 3).await;
        assert_eq!(outcome.status, Some(200));
        assert_eq!(outcome.body_bytes, 3);
        assert!(outcome.end_stream);
        assert_eq!(outcome.abort, None);
        assert_eq!(received, b"a\0b");
        drop(client);
        driver.abort();
        server.abort();
    }

    /// Reset after the client explicitly acknowledges observing the prefix.
    fn reset_server(server_io: DuplexStream, observed_rx: oneshot::Receiver<()>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (_, mut respond) = connection.accept().await.unwrap().unwrap();
            tokio::spawn(async move {
                let mut stream = respond.send_response(http::Response::new(()), false).unwrap();
                stream.send_data(Bytes::from_static(b"abc"), false).unwrap();
                observed_rx.await.unwrap();
                stream.send_reset(h2::Reason::CANCEL);
            });
            while connection.accept().await.is_some() {}
        })
    }

    #[tokio::test]
    async fn reset_after_headers_and_data_is_not_completion() {
        let (client_io, server_io) = duplex(8192);
        let (observed_tx, observed_rx) = oneshot::channel();
        let server = reset_server(server_io, observed_rx);
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(connection);
        let request = http::Request::get("http://localhost/").body(()).unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let mut observed = Some(observed_tx);
        let outcome = timeout(Duration::from_secs(5), async {
            read_h2_response(response.await, 10, |_| {
                if let Some(sender) = observed.take() {
                    sender.send(()).unwrap();
                }
                Ok(())
            })
            .await
        })
        .await
        .unwrap();
        assert_eq!(outcome.status, Some(200));
        assert_eq!(outcome.body_bytes, 3);
        assert!(!outcome.end_stream);
        assert_eq!(outcome.reset, Some(h2::Reason::CANCEL));
        assert!(outcome.abort.is_some());
        drop(client);
        driver.abort();
        server.abort();
    }

    /// Create a trusted TLS pair advertising H2 for the transport self-check.
    fn tls_configs() -> (rustls::ServerConfig, rustls::ClientConfig) {
        use crate::net::{TestCertificates, ensure_crypto_provider, parse_cert_chain_and_key};
        ensure_crypto_provider();
        let certs = TestCertificates::generate();
        let (chain, key) = parse_cert_chain_and_key(
            &std::fs::read(&certs.cert_path).unwrap(),
            &std::fs::read(&certs.key_path).unwrap(),
        );
        let mut server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        server.alpn_protocols = vec![b"h2".to_vec()];
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certs.ca_cert_der.clone().into()).unwrap();
        let mut client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"h2".to_vec()];
        (server, client)
    }

    /// Drive an H2 server over an authenticated TLS transport.
    fn tls_server(server_io: DuplexStream, config: rustls::ServerConfig) -> JoinHandle<()> {
        tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let tls = acceptor.accept(server_io).await.unwrap();
            let mut connection = h2::server::handshake(tls).await.unwrap();
            let (_, mut respond) = connection.accept().await.unwrap().unwrap();
            let mut send = respond.send_response(http::Response::new(()), false).unwrap();
            send.send_data(Bytes::from_static(b"a\0b"), true).unwrap();
            while connection.accept().await.is_some() {}
        })
    }

    /// Perform the bounded client TLS handshake and verify negotiated H2.
    async fn tls_client(
        client_io: DuplexStream,
        config: rustls::ClientConfig,
    ) -> tokio_rustls::client::TlsStream<DuplexStream> {
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tls = timeout(
            Duration::from_secs(5),
            connector.connect("localhost".try_into().unwrap(), client_io),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        tls
    }

    #[tokio::test]
    async fn h2_tls_negotiates_and_completes_binary_response() {
        let (server_config, client_config) = tls_configs();
        let (client_io, server_io) = duplex(8192);
        let server = tls_server(server_io, server_config);
        let tls = tls_client(client_io, client_config).await;
        let (mut client, connection) = h2::client::handshake(tls).await.unwrap();
        let driver = tokio::spawn(connection);
        let request = http::Request::get("https://localhost/").body(()).unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let (result, received) = collect_response(response, 3).await;
        assert_eq!(result.status, Some(200));
        assert!(result.end_stream);
        assert_eq!(result.abort, None);
        assert_eq!(received, b"a\0b");
        drop(client);
        driver.abort();
        server.abort();
    }
}

/// A group of HTTP/2 uploads paused immediately before their final byte.
///
/// The worker owns and drives one HTTP/2 connection. Dropping the handle
/// cancels pending flow-control waits and joins the worker.
pub struct H2PausedUploads {
    /// All prefix bytes have been queued to the H2 library, or setup failed.
    pub ready: std::sync::mpsc::Receiver<Result<u64, String>>,
    /// Completed response observations, or a transport/setup error.
    pub result: std::sync::mpsc::Receiver<Result<H2PausedResult, String>>,
    /// Releases the final content byte and `END_STREAM` for every upload.
    resume: Option<tokio::sync::oneshot::Sender<()>>,
    /// Interrupts any pending network or flow-control operation on drop.
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
    /// The owned connection-driving thread.
    worker: Option<std::thread::JoinHandle<()>>,
}

impl H2PausedUploads {
    /// Release all pending final bytes. Subsequent calls are harmless.
    pub fn resume(&mut self) {
        if let Some(sender) = self.resume.take() {
            let _sent = sender.send(());
        }
    }
}

impl Drop for H2PausedUploads {
    fn drop(&mut self) {
        if let Some(sender) = self.cancel.take() {
            let _sent = sender.send(());
        }
        if let Some(worker) = self.worker.take()
            && let Err(error) = worker.join()
            && !std::thread::panicking()
        {
            std::panic::resume_unwind(error);
        }
    }
}

/// Completed H2 responses and DATA frames actually written to the socket.
#[derive(Debug)]
pub struct H2PausedResult {
    /// One fully observed response per bulk stream.
    pub responses: Vec<H2Response>,
    /// Complete DATA frame headers observed in the outgoing byte stream.
    pub data_frames: u64,
    /// DATA frames with zero payload bytes.
    pub empty_data_frames: u64,
}

/// Start multiple bounded HTTP/2 uploads on one connection, with alternating
/// `x-resource-tenant` values. The ready notification reports queued bytes,
/// which are not evidence of backend receipt. Each stream also emits a legal
/// zero-length non-final DATA frame before its generated prefix. When
/// `pace_small` is set, small chunks are paced so the peer can consume them.
///
/// # Panics
///
/// Panics if `streams` or `chunk_size` is zero, or if the payload is empty.
pub fn start_h2_paused_uploads(
    addr: &str,
    spec: PayloadSpec,
    streams: usize,
    chunk_size: usize,
    pace_small: bool,
) -> H2PausedUploads {
    assert!(streams > 0 && chunk_size > 0 && !spec.is_empty());
    let addr = addr.to_owned();
    let (ready_tx, ready) = std::sync::mpsc::channel();
    let (result_tx, result) = std::sync::mpsc::channel();
    let (resume, resume_rx) = tokio::sync::oneshot::channel();
    let (cancel, cancel_rx) = tokio::sync::oneshot::channel();
    let worker = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("H2 test runtime");
        let outcome = runtime.block_on(async {
            tokio::select! {
                result = Box::pin(paused_uploads(&addr, &spec, streams, chunk_size, pace_small, &ready_tx, resume_rx)) => result,
                _ = cancel_rx => Err("H2 campaign cancelled".to_owned()),
            }
        });
        if let Err(error) = &outcome {
            let _sent = ready_tx.send(Err(error.clone()));
        }
        let _sent = result_tx.send(outcome);
    });
    H2PausedUploads {
        ready,
        result,
        resume: Some(resume),
        cancel: Some(cancel),
        worker: Some(worker),
    }
}

/// Drive one connection and retain every stream until the parent releases it.
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::large_stack_frames,
    reason = "the coordinated H2 exchange keeps its stream handles together; its future is boxed by the caller"
)]
async fn paused_uploads(
    addr: &str,
    spec: &PayloadSpec,
    streams: usize,
    chunk_size: usize,
    pace_small: bool,
    ready: &std::sync::mpsc::Sender<Result<u64, String>>,
    resume: tokio::sync::oneshot::Receiver<()>,
) -> Result<H2PausedResult, String> {
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|error| error.to_string())?;
    let frames = std::sync::Arc::new(std::sync::Mutex::new(OutgoingFrames::default()));
    let io = CountH2Frames {
        inner: tcp,
        frames: std::sync::Arc::clone(&frames),
    };
    let (mut client, connection) = h2::client::handshake(io).await.map_err(|error| error.to_string())?;
    let mut driver = tokio::spawn(connection);
    let mut pending = Vec::new();
    for index in 0..streams {
        client = client.ready().await.map_err(|error| error.to_string())?;
        let request = http::Request::post("/bulk")
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header("content-length", spec.len().to_string())
            .header("x-resource-tenant", format!("tenant-{}", index % 2))
            .body(())
            .map_err(|error| error.to_string())?;
        let (response, mut upload) = client.send_request(request, false).map_err(|error| error.to_string())?;
        upload
            .send_data(Bytes::new(), false)
            .map_err(|error| error.to_string())?;
        if let Err(error) = queue_prefix(&mut upload, spec, chunk_size, pace_small).await {
            let response = tokio::time::timeout(std::time::Duration::from_secs(2), response).await;
            let driver = tokio::time::timeout(std::time::Duration::from_secs(2), &mut driver).await;
            return Err(format!("{error}; response={response:?}; driver={driver:?}"));
        }
        pending.push((response, upload));
    }
    client = client.ready().await.map_err(|error| error.to_string())?;
    let probe = http::Request::get("/probe")
        .header("host", "localhost")
        .body(())
        .map_err(|error| error.to_string())?;
    let (probe_response, mut probe_upload) = client.send_request(probe, false).map_err(|error| error.to_string())?;
    probe_upload
        .send_data(Bytes::new(), true)
        .map_err(|error| error.to_string())?;
    let probe = read_h2_response(probe_response.await, 0, |_| Ok(())).await;
    if probe.status != Some(200) || !probe.end_stream || probe.abort.is_some() {
        return Err(format!("independent H2 probe failed: {probe:?}"));
    }
    let queued = (spec.len() - 1).saturating_mul(u64::try_from(streams).map_err(|error| error.to_string())?);
    ready.send(Ok(queued)).map_err(|error| error.to_string())?;
    resume.await.map_err(|error| error.to_string())?;
    for (_, upload) in &mut pending {
        let capacity = available_capacity(upload, 1).await?;
        if capacity == 0 {
            return Err("no capacity for final byte".to_owned());
        }
        upload
            .send_data(Bytes::from(spec.chunk(spec.len() - 1, 1)), true)
            .map_err(|error| error.to_string())?;
    }
    let mut responses = Vec::new();
    for (response, _) in pending {
        let mut body = Vec::new();
        let observed = read_h2_response(response.await, 8192, |chunk| {
            body.extend_from_slice(chunk);
            Ok(())
        })
        .await;
        if body != b"ok" {
            return Err(format!("unexpected H2 response body: {body:?}, {observed:?}"));
        }
        responses.push(observed);
    }
    driver.abort();
    let counts = frames.lock().map_err(|error| error.to_string())?;
    Ok(H2PausedResult {
        responses,
        data_frames: counts.data_frames,
        empty_data_frames: counts.empty_data_frames,
    })
}

/// Counts complete outgoing frame headers after the client preface.
#[derive(Default)]
struct OutgoingFrames {
    /// Number of preface bytes consumed so far.
    preface: usize,
    /// Partial nine-byte frame header.
    header: [u8; 9],
    /// Number of header bytes collected.
    header_len: usize,
    /// Remaining bytes in the current frame payload.
    payload_remaining: usize,
    /// Number of DATA frames physically written.
    data_frames: u64,
    /// Number of empty DATA frames physically written.
    empty_data_frames: u64,
}

impl OutgoingFrames {
    /// Account only for bytes accepted by the socket, including partial writes.
    fn observe(&mut self, bytes: &[u8]) {
        for byte in bytes {
            if self.preface < 24 {
                self.preface += 1;
                continue;
            }
            if self.payload_remaining > 0 {
                self.payload_remaining -= 1;
                continue;
            }
            self.header[self.header_len] = *byte;
            self.header_len += 1;
            if self.header_len == 9 {
                self.payload_remaining = (usize::from(self.header[0]) << 16)
                    | (usize::from(self.header[1]) << 8)
                    | usize::from(self.header[2]);
                if self.header[3] == 0 {
                    self.data_frames += 1;
                    if self.payload_remaining == 0 {
                        self.empty_data_frames += 1;
                    }
                }
                self.header_len = 0;
            }
        }
    }
}

/// H2 client I/O that records written DATA frame boundaries without buffering.
struct CountH2Frames<T> {
    /// Underlying transport.
    inner: T,
    /// Shared parser for outgoing frame bytes.
    frames: std::sync::Arc<std::sync::Mutex<OutgoingFrames>>,
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for CountH2Frames<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for CountH2Frames<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match std::pin::Pin::new(&mut self.inner).poll_write(cx, buf) {
            std::task::Poll::Ready(Ok(count)) => {
                self.frames
                    .lock()
                    .expect("H2 frame counter lock")
                    .observe(&buf[..count]);
                std::task::Poll::Ready(Ok(count))
            },
            other => other,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Queue all but the final byte, respecting per-stream H2 flow control.
async fn queue_prefix(
    stream: &mut h2::SendStream<Bytes>,
    spec: &PayloadSpec,
    chunk_size: usize,
    pace_small: bool,
) -> Result<(), String> {
    let target = spec.len() - 1;
    let mut offset = 0;
    while offset < target {
        let desired = usize::try_from(target - offset)
            .unwrap_or(usize::MAX)
            .min(chunk_size)
            .min(MAX_H2_CHUNK);
        let capacity = available_capacity(stream, desired)
            .await
            .map_err(|error| format!("H2 prefix offset {offset}: {error}"))?;
        let bytes = spec.chunk(offset, desired.min(capacity));
        offset += bytes.len() as u64;
        stream
            .send_data(Bytes::from(bytes), false)
            .map_err(|error| error.to_string())?;
        if pace_small && chunk_size < 1024 {
            tokio::time::sleep(std::time::Duration::from_micros(100)).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod resource_tests {
    use std::time::{Duration, Instant};

    use super::{OutgoingFrames, start_h2_paused_uploads};
    use crate::PayloadSpec;

    /// Frame headers split across socket writes and header-like payload bytes
    /// must not be mistaken for additional DATA frames.
    #[test]
    fn counts_fragmented_data_frames_without_scanning_payload() {
        let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        wire.extend_from_slice(&[0, 0, 4, 0, 0, 0, 0, 0, 1]);
        wire.extend_from_slice(&[0, 0, 0, 0]);
        wire.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0, 3]);
        let mut parser = OutgoingFrames::default();
        for part in wire.chunks(2) {
            parser.observe(part);
        }
        assert_eq!(parser.data_frames, 2, "two DATA headers must be counted");
        assert_eq!(parser.empty_data_frames, 1, "only the last DATA frame is empty");
        assert_eq!(parser.payload_remaining, 0, "last frame must be complete");
    }

    /// Dropping a campaign must interrupt an unresponsive H2 peer.
    #[test]
    fn dropping_paused_upload_interrupts_a_stalled_peer() {
        let (listener, port) = crate::net::port::bind_unique_port();
        let addr = format!("127.0.0.1:{port}");
        let client = start_h2_paused_uploads(&addr, PayloadSpec::binary(1024, 1), 1, 16, true);
        let (_peer, _) = listener.accept().unwrap();
        let start = Instant::now();
        drop(client);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "worker did not cancel promptly"
        );
    }
}
