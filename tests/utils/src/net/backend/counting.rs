// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Binary-safe one-request backend for payload tests.

use std::{
    io::{self, BufReader, Write as _},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{
    net::{
        http1::{H1Completion, framing, read_body_with_trailers, read_head},
        port::bind_unique_port,
    },
    payload::PayloadSpec,
};

/// Observations from one request received by a counting backend.
#[derive(Debug)]
pub struct BackendReceipt {
    /// Configured identity of this backend.
    pub backend_id: String,
    /// Request identifier from the `x-request-id` header, when supplied.
    pub request_id: Option<String>,
    /// Attempt identifier from the `x-attempt-id` header, when supplied.
    pub attempt_id: Option<String>,
    /// Request line and headers, with lowercase header names.
    pub request_line: String,
    /// Received headers in wire order.
    pub headers: Vec<(String, String)>,
    /// Validated request trailer fields in wire order, excluding framing bytes.
    pub trailers: Vec<(String, String)>,
    /// Number of content bytes received.
    pub bytes: u64,
    /// Number of matching bytes before the first mismatch.
    pub verified_bytes: u64,
    /// Absolute position of the first byte mismatch, if any.
    pub mismatch: Option<u64>,
    /// Time at which the first content byte was observed.
    pub first_byte: Option<Instant>,
    /// Completed request framing, or `None` after a failure.
    pub completion: Option<H1Completion>,
    /// Error describing an incomplete or invalid request.
    pub abort: Option<String>,
}

/// One-request backend with separate first-byte and completion notifications.
pub struct CountingBackend {
    /// Listener port.
    pub port: u16,
    /// Notification as soon as the backend accepts a connection.
    pub accepted: Receiver<Instant>,
    /// Notification when the first body byte reaches this backend.
    pub first_byte: Receiver<Instant>,
    /// Completed or aborted request observation.
    pub receipt: Receiver<BackendReceipt>,
    /// Cancellation flag for a listener that receives no connection.
    stop: Arc<AtomicBool>,
    /// Connected socket clone used to interrupt active reads during teardown.
    active: Arc<Mutex<Option<TcpStream>>>,
    /// Worker that owns the listener.
    thread: Option<JoinHandle<()>>,
}

impl CountingBackend {
    /// Stop the listener, interrupt an active request, and join its worker.
    ///
    /// # Panics
    ///
    /// Panics if the backend worker panicked.
    pub fn join(mut self) {
        self.cancel();
        if let Some(thread) = self.thread.take() {
            thread.join().expect("counting backend thread");
        }
    }

    /// Interrupt the listener or a connected peer before waiting for its worker.
    fn cancel(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(stream) = self.active.lock().expect("active counting socket lock").as_ref() {
            let _result = stream.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for CountingBackend {
    fn drop(&mut self) {
        self.cancel();
        if let Some(thread) = self.thread.take()
            && let Err(error) = thread.join()
            && !thread::panicking()
        {
            std::panic::resume_unwind(error);
        }
    }
}

/// Spawn a backend that verifies an HTTP/1 body against `spec` incrementally.
///
/// The backend reads at most `max_body` content bytes and sends a small 200
/// receipt only after complete framing and exact byte verification. Otherwise
/// it sends 422 after a complete but mismatched body, or closes on a framing
/// failure. Set a read timeout on the test client separately.
///
/// # Panics
///
/// Panics if the listener cannot be bound or configured.
pub fn start_counting_backend(spec: PayloadSpec, backend_id: &str, max_body: u64) -> CountingBackend {
    let (listener, port) = bind_unique_port();
    listener.set_nonblocking(true).expect("set listener nonblocking");
    let (accepted_tx, accepted) = mpsc::channel();
    let (first_tx, first_byte) = mpsc::channel();
    let (receipt_tx, receipt) = mpsc::channel();
    let backend_id = backend_id.to_owned();
    let stop = Arc::new(AtomicBool::new(false));
    let active = Arc::new(Mutex::new(None));
    let worker_stop = Arc::clone(&stop);
    let worker_active = Arc::clone(&active);
    let thread = thread::spawn(move || {
        let Some(stream) = accept_counting_socket(&listener, &worker_stop, &worker_active, &accepted_tx) else {
            return;
        };
        let observation = observe_request(stream, &spec, backend_id, max_body, &first_tx);
        drop(worker_active.lock().expect("active counting socket lock").take());
        let _sent = receipt_tx.send(observation);
    });
    CountingBackend {
        port,
        accepted,
        first_byte,
        receipt,
        stop,
        active,
        thread: Some(thread),
    }
}

/// Accept a connection and arm cancellation before announcing its arrival.
fn accept_counting_socket(
    listener: &TcpListener,
    stop: &AtomicBool,
    active: &Mutex<Option<TcpStream>>,
    accepted: &Sender<Instant>,
) -> Option<TcpStream> {
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if stop.load(Ordering::Relaxed) {
                    return None;
                }
                thread::sleep(Duration::from_millis(5));
            },
            Err(error) => panic!("accept counting backend request: {error}"),
        }
    };
    let mut socket = active.lock().expect("active counting socket lock");
    if stop.load(Ordering::Relaxed) {
        return None;
    }
    *socket = Some(stream.try_clone().expect("clone counting backend socket"));
    drop(socket);
    let _sent = accepted.send(Instant::now());
    Some(stream)
}

/// Verify one request and send success only after complete, matching framing.
fn observe_request(
    stream: TcpStream,
    spec: &PayloadSpec,
    backend_id: String,
    max_body: u64,
    first_byte: &Sender<Instant>,
) -> BackendReceipt {
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("set backend read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(15)))
        .expect("set backend write timeout");
    let mut reader = BufReader::new(stream);
    let mut observation = empty_receipt(backend_id);
    if let Err(error) = verify_request(&mut reader, spec, max_body, first_byte, &mut observation) {
        observation.abort = Some(error.to_string());
    } else {
        let matches = observation.mismatch.is_none() && observation.bytes == spec.len();
        let status = if matches { "200 OK" } else { "422 Unprocessable Content" };
        let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let _sent = reader.get_mut().write_all(response.as_bytes());
    }
    observation
}

/// Create a receipt before any request bytes have been observed.
fn empty_receipt(backend_id: String) -> BackendReceipt {
    BackendReceipt {
        backend_id,
        request_id: None,
        attempt_id: None,
        request_line: String::new(),
        headers: Vec::new(),
        trailers: Vec::new(),
        bytes: 0,
        verified_bytes: 0,
        mismatch: None,
        first_byte: None,
        completion: None,
        abort: None,
    }
}

/// Parse bounded request framing and validate each body chunk incrementally.
fn verify_request(
    reader: &mut BufReader<TcpStream>,
    spec: &PayloadSpec,
    max_body: u64,
    first_byte: &Sender<Instant>,
    observation: &mut BackendReceipt,
) -> io::Result<()> {
    let head = read_head(reader)?;
    observation.request_id = header(&head.headers, "x-request-id");
    observation.attempt_id = header(&head.headers, "x-attempt-id");
    let mode = framing(&head.headers, false)?;
    observation.request_line = head.start;
    observation.headers = head.headers;
    let mut count = 0;
    let mut sink = |chunk: &[u8]| {
        if observation.first_byte.is_none() {
            let instant = Instant::now();
            observation.first_byte = Some(instant);
            let _sent = first_byte.send(instant);
        }
        if observation.mismatch.is_none() {
            observation.mismatch = spec.mismatch(observation.bytes, chunk);
            observation.verified_bytes = observation.mismatch.unwrap_or(observation.bytes + chunk.len() as u64);
        }
        observation.bytes += chunk.len() as u64;
        Ok(())
    };
    let end = read_body_with_trailers(reader, mode, max_body, &mut sink, &mut count)?;
    observation.completion = Some(end.completion);
    observation.trailers = end.trailers;
    Ok(())
}

/// Return the first value of a named header.
fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufReader, Read as _, Write as _},
        net::TcpStream,
        time::{Duration, Instant},
    };

    use super::start_counting_backend;
    use crate::{
        net::http1::{H1Completion, read_h1_response},
        payload::PayloadSpec,
    };

    #[test]
    fn teardown_interrupts_a_peer_stalled_inside_headers() {
        let backend = start_counting_backend(PayloadSpec::binary(1, 7), "cancel", 1);
        let mut stream = TcpStream::connect(("127.0.0.1", backend.port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        stream.write_all(b"POST / HTTP/1.1\r\nHost: ").unwrap();
        backend.accepted.recv_timeout(Duration::from_secs(2)).unwrap();
        let started = Instant::now();
        backend.join();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn binary_receipt_records_body_and_request_identity() {
        let spec = PayloadSpec::binary(257, 91);
        let backend = start_counting_backend(spec.clone(), "blue", 300);
        let mut stream = TcpStream::connect(("127.0.0.1", backend.port)).unwrap();
        backend.accepted.recv_timeout(Duration::from_secs(2)).unwrap();
        stream.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 257\r\nX-Request-Id: req-1\r\nX-Attempt-Id: 2\r\n\r\n").unwrap();
        stream.write_all(&spec.chunk(0, 7)).unwrap();
        backend.first_byte.recv_timeout(Duration::from_secs(2)).unwrap();
        stream.write_all(&spec.chunk(7, 250)).unwrap();
        let response = read_h1_response(&mut BufReader::new(stream), false, 0, |_| Ok(()));
        let receipt = backend.receipt.recv_timeout(Duration::from_secs(2)).unwrap();
        backend.join();
        assert_eq!(response.status, Some(200));
        assert_eq!(response.completion, Some(H1Completion::ContentLength));
        assert_eq!(receipt.backend_id, "blue");
        assert_eq!(receipt.request_id.as_deref(), Some("req-1"));
        assert_eq!(receipt.attempt_id.as_deref(), Some("2"));
        assert_eq!(receipt.bytes, 257);
        assert_eq!(receipt.verified_bytes, 257);
        assert_eq!(receipt.mismatch, None);
        assert_eq!(receipt.completion, Some(H1Completion::ContentLength));
        assert_eq!(receipt.abort, None);
    }

    #[test]
    fn chunked_receipt_retains_validated_trailers() {
        let spec = PayloadSpec::padded(3, b"abc", b"", b'x').unwrap();
        let backend = start_counting_backend(spec, "trailer", 3);
        let mut stream = TcpStream::connect(("127.0.0.1", backend.port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        stream.write_all(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Trailer: done\r\nX-Trailer: second\r\n\r\n").unwrap();
        let result = read_h1_response(&mut BufReader::new(stream), false, 0, |_| Ok(()));
        let receipt = backend.receipt.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(result.status, Some(200));
        assert_eq!(receipt.completion, Some(H1Completion::Chunked));
        assert_eq!(receipt.bytes, 3);
        assert_eq!(
            receipt.trailers,
            vec![
                ("x-trailer".to_owned(), "done".to_owned()),
                ("x-trailer".to_owned(), "second".to_owned())
            ]
        );
        backend.join();
    }

    #[test]
    fn mismatch_and_truncated_framing_are_not_success() {
        let spec = PayloadSpec::binary(3, 1);
        let backend = start_counting_backend(spec.clone(), "red", 10);
        let mut stream = TcpStream::connect(("127.0.0.1", backend.port)).unwrap();
        stream
            .write_all(b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nxyz")
            .unwrap();
        let result = read_h1_response(&mut BufReader::new(stream), false, 0, |_| Ok(()));
        let receipt = backend.receipt.recv_timeout(Duration::from_secs(2)).unwrap();
        backend.join();
        assert_eq!(result.status, Some(422));
        assert!(receipt.mismatch.is_some());
        let backend = start_counting_backend(spec, "red", 10);
        let mut stream = TcpStream::connect(("127.0.0.1", backend.port)).unwrap();
        stream
            .write_all(b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nx")
            .unwrap();
        drop(stream);
        let receipt = backend.receipt.recv_timeout(Duration::from_secs(2)).unwrap();
        backend.join();
        assert_eq!(receipt.bytes, 1);
        assert_eq!(receipt.completion, None);
        assert!(receipt.abort.is_some());
    }

    #[test]
    fn unselected_backend_can_be_joined() {
        let backend = start_counting_backend(PayloadSpec::binary(1, 0), "unused", 1);
        assert_eq!(
            backend.accepted.try_recv().unwrap_err(),
            std::sync::mpsc::TryRecvError::Empty
        );
        backend.join();
    }
}
