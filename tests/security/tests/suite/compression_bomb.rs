// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Highly compressed upstream bodies remain encoded during pass-through.

use std::{
    io::{self, BufReader, Read as _, Write as _},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    H1Completion, free_port, http_send, parse_body, parse_header, parse_status, read_h1_response,
    start_backend_with_shutdown, start_full_proxy, start_gzip_encoded_backend, start_proxy, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Gzip of 1,000,000 zero bytes, stored in 1,003 compressed bytes.
const GZIP_1MB_ZEROS: &[u8] = include_bytes!("../../fixtures/gzip_1mb_zeros.gz");

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn highly_compressed_upstream_body_passes_through_unchanged() {
    let backend = start_gzip_encoded_backend(GZIP_1MB_ZEROS.to_vec());
    let proxy_port = free_port();
    let yaml = compression_proxy_yaml(proxy_port, backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = super::test_utils::send_bytes(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Accept-Encoding: identity\r\n\
         Connection: close\r\n\
         \r\n",
    );
    let header_end = raw
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .expect("response headers")
        + 4;
    let headers = std::str::from_utf8(&raw[..header_end]).expect("headers must be UTF-8");
    assert_eq!(parse_status(headers), 200, "encoded upstream response must succeed");
    assert_eq!(
        parse_header(headers, "content-encoding").as_deref(),
        Some("gzip"),
        "gzip must not be decoded"
    );
    assert_eq!(
        parse_header(headers, "content-length"),
        Some(GZIP_1MB_ZEROS.len().to_string()),
        "length must describe compressed bytes"
    );
    assert_eq!(
        &raw[header_end..],
        GZIP_1MB_ZEROS,
        "binary gzip payload must be forwarded unchanged"
    );
}

#[test]
fn encoded_response_ceiling_counts_gzip_bytes_not_decompressed_bytes() {
    let backend = start_gzip_encoded_backend(GZIP_1MB_ZEROS.to_vec());
    for limit in [GZIP_1MB_ZEROS.len(), GZIP_1MB_ZEROS.len() - 1] {
        let proxy_port = free_port();
        let yaml = compression_proxy_yaml(proxy_port, backend.port()).replace(
            "      - filter: router\n",
            "      - filter: static_response\n        conditions:\n          - when:\n              path: /probe\n        status: 200\n        body: ok\n      - filter: router\n",
        );
        let mut config = Config::from_yaml(&yaml).unwrap();
        config.body_limits.max_response_bytes = Some(limit);
        let proxy = start_full_proxy(&config);
        wait_for_tcp(proxy.addr());
        let mut socket = TcpStream::connect(proxy.addr()).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        socket
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut received = Vec::new();
        let response = read_h1_response(
            &mut BufReader::new(socket),
            false,
            u64::try_from(limit).unwrap(),
            |part| {
                received.extend_from_slice(part);
                Ok(())
            },
        );
        if limit == GZIP_1MB_ZEROS.len() {
            assert_eq!(response.status, Some(200));
            assert_eq!(response.completion, Some(H1Completion::ContentLength));
            assert_eq!(received, GZIP_1MB_ZEROS);
        } else {
            assert_eq!(
                response.status,
                Some(500),
                "the upstream body failed before committing headers"
            );
            assert_eq!(response.completion, Some(H1Completion::ContentLength));
            assert!(response.headers.iter().all(|(name, _)| name != "content-encoding"));
            assert!(!received.starts_with(&GZIP_1MB_ZEROS[..2]));
            assert!(received.len() <= limit);
        }
        let probe = http_send(
            proxy.addr(),
            "GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(parse_status(&probe), 200);
        assert_eq!(parse_body(&probe), "ok");
    }
}

#[test]
fn encoded_requests_remain_opaque_and_cannot_promote_json_fields() {
    let backend = recording_backend(2);
    let promoted = start_backend_with_shutdown("unexpected-promoted-route");
    let proxy_port = free_port();
    let yaml = opaque_request_yaml(proxy_port, backend.port, promoted.port());
    let proxy = start_full_proxy(&Config::from_yaml(&yaml).unwrap());
    wait_for_tcp(proxy.addr());
    for body in [GZIP_1MB_ZEROS, b"\x1f\x8b{\"model\":\"guarded\"}".as_slice()] {
        assert_eq!(post(proxy.addr(), "Content-Encoding: gzip\r\n", body), 200);
        backend.accepted.recv_timeout(Duration::from_secs(5)).unwrap();
        let (headers, received) = backend.receipts.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(received, body, "neither valid gzip nor invalid gzip is decoded");
        assert!(headers.to_ascii_lowercase().contains("content-encoding: gzip"));
    }
    backend.join();
}

#[test]
fn protected_inspection_explicitly_rejects_non_identity_encodings() {
    let backend = recording_backend(1);
    let proxy_port = free_port();
    let yaml = protected_request_yaml(proxy_port, backend.port);
    let proxy = start_full_proxy(&Config::from_yaml(&yaml).unwrap());
    wait_for_tcp(proxy.addr());

    for headers in [
        "Content-Encoding: gzip\r\n",
        "Content-Encoding: br\r\n",
        "",
        "Content-Encoding: identity\r\nContent-Encoding: gzip\r\n",
    ] {
        assert_eq!(
            post(proxy.addr(), headers, GZIP_1MB_ZEROS),
            403,
            "unsupported or missing encoding is denied"
        );
    }
    assert_eq!(
        post(
            proxy.addr(),
            "Content-Encoding: identity\r\n",
            br#"{"text":"123-45-6789"}"#
        ),
        403,
        "identity content is actually inspected"
    );
    assert!(
        matches!(
            backend.accepted.recv_timeout(Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "rejected requests must not open an upstream connection"
    );
    assert!(
        backend.receipts.try_recv().is_err(),
        "rejected requests must not reach the backend"
    );
    let clean = br#"{"text":"hello"}"#;
    assert_eq!(post(proxy.addr(), "Content-Encoding: identity\r\n", clean), 200);
    backend.accepted.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(backend.receipts.recv_timeout(Duration::from_secs(5)).unwrap().1, clean);
    backend.join();
}

#[test]
fn recording_backend_cancels_idle_and_incomplete_requests() {
    let backend = recording_backend(1);
    let started = Instant::now();
    backend.join();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "idle listener must stop promptly"
    );

    for request in [
        b"POST / HTTP/1.1\r\nHost: localhost\r\n".as_slice(),
        b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nx".as_slice(),
    ] {
        let backend = recording_backend(1);
        let mut socket = TcpStream::connect(("127.0.0.1", backend.port)).unwrap();
        socket.write_all(request).unwrap();
        backend.accepted.recv_timeout(Duration::from_secs(5)).unwrap();
        thread::sleep(Duration::from_millis(20));
        let started = Instant::now();
        backend.join();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "active read must stop promptly"
        );
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Enable compression while testing preservation of an already encoded response.
fn compression_proxy_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: compression
        min_size_bytes: 1
        gzip:
          enabled: true
          level: 1
        content_types:
          - "text/"
          - "application/"
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

/// Maximum request header bytes retained by the recording backend.
const RECORDING_HEADER_LIMIT: usize = 16_384; // 16 KiB
/// Maximum encoded request body retained by the recording backend.
const RECORDING_BODY_LIMIT: usize = 1_048_576; // 1 MiB

/// Exact header and body observations from a complete request.
type RecordedRequest = (String, Vec<u8>);

/// Backend with separate accept and completed-body observations.
struct RecordingBackend {
    /// Listener port used in proxy configuration.
    port: u16,
    /// Signals a connection even when its request never completes.
    accepted: Receiver<()>,
    /// Fully received requests, in order.
    receipts: Receiver<RecordedRequest>,
    /// Stop an idle listener during teardown.
    stop: Arc<AtomicBool>,
    /// Interrupt an active socket during teardown.
    active: Arc<Mutex<Option<TcpStream>>>,
    /// Worker owns the listener and is always joined.
    worker: Option<JoinHandle<()>>,
}

impl RecordingBackend {
    /// Cancel the listener or the active read before waiting for the worker.
    fn cancel(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let active = self.active.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(socket) = active.as_ref() {
            let _result = socket.shutdown(Shutdown::Both);
        }
    }

    /// Check that the worker terminated without errors.
    fn join(mut self) {
        self.cancel();
        if let Some(worker) = self.worker.take() {
            worker.join().expect("recording backend worker");
        }
    }
}

impl Drop for RecordingBackend {
    fn drop(&mut self) {
        self.cancel();
        if let Some(worker) = self.worker.take()
            && let Err(error) = worker.join()
            && !thread::panicking()
        {
            std::panic::resume_unwind(error);
        }
    }
}

/// Start a bounded backend that acknowledges only complete bodies.
fn recording_backend(count: usize) -> RecordingBackend {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let (accepted_tx, accepted) = mpsc::channel();
    let (receipt_tx, receipts) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let active = Arc::new(Mutex::new(None));
    let worker_stop = Arc::clone(&stop);
    let worker_active = Arc::clone(&active);
    let worker = thread::spawn(move || {
        for _ in 0..count {
            let Some(socket) = accept_recording_socket(&listener, &worker_stop, &worker_active) else {
                return;
            };
            if accepted_tx.send(()).is_err() {
                return;
            }
            let result = record_request(socket, &receipt_tx);
            drop(worker_active.lock().unwrap().take());
            if let Err(error) = result
                && !worker_stop.load(Ordering::SeqCst)
            {
                panic!("recording backend request: {error}");
            }
        }
    });
    RecordingBackend {
        port,
        accepted,
        receipts,
        stop,
        active,
        worker: Some(worker),
    }
}

/// Accept and arm cancellation before publishing an upstream connection.
fn accept_recording_socket(
    listener: &TcpListener,
    stop: &AtomicBool,
    active: &Mutex<Option<TcpStream>>,
) -> Option<TcpStream> {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((socket, _)) => {
                let mut current = active.lock().unwrap();
                if stop.load(Ordering::SeqCst) {
                    return None;
                }
                *current = Some(socket.try_clone().unwrap());
                drop(current);
                return Some(socket);
            },
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            },
            Err(error) => panic!("recording backend accept: {error}"),
        }
    }
    None
}

/// Capture a bounded request and reply only after its complete body arrives.
fn record_request(socket: TcpStream, receipts: &Sender<RecordedRequest>) -> io::Result<()> {
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(socket);
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        if headers.len() == RECORDING_HEADER_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request headers exceed test bound",
            ));
        }
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        headers.push(byte[0]);
    }
    let headers = String::from_utf8(headers).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let size: usize = parse_header(&headers, "content-length")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing content-length"))?
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if size > RECORDING_BODY_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request body exceeds test bound",
        ));
    }
    let mut body = vec![0; size];
    reader.read_exact(&mut body)?;
    receipts
        .send((headers, body))
        .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error))?;
    reader
        .get_mut()
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
}

/// Send a binary request and parse its response status.
fn post(addr: &str, headers: &str, body: &[u8]) -> u16 {
    let mut socket = super::test_utils::connect(addr);
    write!(socket, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
    let _sent = socket.write_all(body);
    let response = super::test_utils::read_closed(&mut socket);
    let head = response.windows(4).position(|window| window == b"\r\n\r\n").unwrap();
    let headers = std::str::from_utf8(&response[..head + 4]).unwrap();
    let status = parse_status(headers);
    if status == 200 {
        assert_eq!(
            parse_header(headers, "content-length").as_deref(),
            Some("2"),
            "backend reply must declare its exact length"
        );
        assert_eq!(
            &response[head + 4..],
            b"ok",
            "only the complete intended backend reply counts"
        );
    }
    status
}

/// Route only a genuinely promoted `model` to the alternate backend.
fn opaque_request_yaml(proxy_port: u16, backend_port: u16, promoted_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: main
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: json_body_field
        field: model
        header: x-praxis-model
      - filter: router
        routes:
          - path_prefix: "/"
            headers: {{x-praxis-model: guarded}}
            cluster: promoted
          - path_prefix: "/"
            cluster: opaque
      - filter: load_balancer
        clusters:
          - name: promoted
            endpoints: ["127.0.0.1:{promoted_port}"]
          - name: opaque
            endpoints: ["127.0.0.1:{backend_port}"]
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// Require explicit identity before applying the body PII rule.
fn protected_request_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: main
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: guardrails
        rules:
          - target: header
            name: Content-Encoding
            pattern: "(?i)^identity$"
            negate: true
          - target: body
            contains: [ssn]
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:{backend_port}"]
insecure_options:
  allow_private_endpoints: true
"#
    )
}
