// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Generated response source with bounded chunks and an optional acknowledged pause.

use std::{
    io::{self, Read as _, Write as _},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::payload::PayloadSpec;

/// Framing used for a generated HTTP/1 response.
#[derive(Clone, Copy, Debug)]
pub enum PayloadResponseFraming {
    /// Send a Content-Length matching the generated content.
    Fixed,
    /// Send content using chunked transfer encoding.
    Chunked,
    /// End the response by closing the connection.
    Close,
}

/// Bytes accepted by socket writes and whether final framing was written.
/// Socket writes do not prove that the proxy or client received the bytes.
#[derive(Debug)]
pub struct PayloadResponseReceipt {
    /// Payload bytes accepted by the socket, excluding HTTP framing.
    pub written_bytes: u64,
    /// Whether all content and its terminating framing were written.
    pub complete: bool,
    /// Write, read, or pause error, if the response could not be completed.
    pub error: Option<String>,
}

/// A one-request generated response source with bounded memory use.
pub struct PayloadResponseBackend {
    /// Bound listener port.
    pub port: u16,
    /// Notification after a connection is accepted and cancellation is armed.
    pub accepted: Receiver<()>,
    /// Notification after the requested prefix has been written and flushed.
    pub prefix_written: Receiver<u64>,
    /// Completed write-side observation.
    pub receipt: Receiver<PayloadResponseReceipt>,
    /// Resumes the producer after the optional prefix pause.
    resume: Option<Sender<()>>,
    /// Stop an unselected listener.
    stop: Arc<AtomicBool>,
    /// Clone of the connected socket, allowing teardown to interrupt I/O.
    active: Arc<Mutex<Option<TcpStream>>>,
    /// Listener and producer worker.
    thread: Option<JoinHandle<()>>,
}

impl PayloadResponseBackend {
    /// Resume an optionally paused source. Calling this once when there is no
    /// pause is harmless.
    pub fn resume(&mut self) {
        if let Some(resume) = self.resume.take() {
            let _sent = resume.send(());
        }
    }

    /// Stop the listener or connected socket and wait for the worker to exit.
    ///
    /// # Panics
    ///
    /// Panics if the worker panicked.
    pub fn join(mut self) {
        self.cancel();
        if let Some(thread) = self.thread.take() {
            thread.join().expect("payload response backend thread");
        }
    }

    /// Interrupt active I/O as well as an optional producer pause.
    fn cancel(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.resume();
        if let Some(stream) = self.active.lock().expect("active socket lock").as_ref() {
            let _result = stream.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for PayloadResponseBackend {
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

/// Configuration and coordination owned by the producer worker.
struct Producer {
    /// Expected content.
    spec: PayloadSpec,
    /// Wire response framing.
    framing: PayloadResponseFraming,
    /// Optional byte count at which the source pauses.
    pause_after: Option<u64>,
    /// Signals that the prefix was handed to the socket.
    prefix_tx: Sender<u64>,
    /// Waits for the caller to resume production.
    resume_rx: Receiver<()>,
}

/// Spawn a single-request response source. `pause_after` stops after exactly
/// that many content bytes until `resume` is called, including at zero or EOS.
/// Chunks are at most 16 KiB; dropping the handle interrupts connected I/O.
///
/// # Panics
///
/// Panics if the prefix exceeds the payload length or the listener cannot be configured.
pub fn start_payload_response_backend(
    spec: PayloadSpec,
    framing: PayloadResponseFraming,
    pause_after: Option<u64>,
) -> PayloadResponseBackend {
    assert!(pause_after.is_none_or(|prefix| prefix <= spec.len()));
    let (listener, port) = crate::net::port::bind_unique_port();
    listener.set_nonblocking(true).expect("set listener nonblocking");
    let (accepted_tx, accepted) = mpsc::channel();
    let (prefix_tx, prefix_written) = mpsc::channel();
    let (resume, resume_rx) = mpsc::channel();
    let (receipt_tx, receipt) = mpsc::channel();
    let producer = Producer {
        spec,
        framing,
        pause_after,
        prefix_tx,
        resume_rx,
    };
    let worker = Worker::spawn(listener, producer, accepted_tx, receipt_tx);
    PayloadResponseBackend {
        port,
        accepted,
        prefix_written,
        receipt,
        resume: Some(resume),
        stop: worker.stop,
        active: worker.active,
        thread: Some(worker.thread),
    }
}

/// Resources needed to cancel and join the response worker.
struct WorkerHandle {
    /// Stop an unselected listener.
    stop: Arc<AtomicBool>,
    /// Interrupt a connected socket.
    active: Arc<Mutex<Option<TcpStream>>>,
    /// Producer thread.
    thread: JoinHandle<()>,
}

/// State owned by the response producer thread.
struct Worker {
    /// Listening socket.
    listener: TcpListener,
    /// Cancellation flag shared with the caller.
    stop: Arc<AtomicBool>,
    /// Socket clone used for cancellation.
    active: Arc<Mutex<Option<TcpStream>>>,
    /// Generated response and pause state.
    producer: Producer,
    /// Connection acceptance notification.
    accepted: Sender<()>,
    /// Completed socket-write observation.
    receipt: Sender<PayloadResponseReceipt>,
}

impl Worker {
    /// Spawn the worker and return its cancellation resources.
    fn spawn(
        listener: TcpListener,
        producer: Producer,
        accepted: Sender<()>,
        receipt: Sender<PayloadResponseReceipt>,
    ) -> WorkerHandle {
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(Mutex::new(None));
        let worker = Self {
            listener,
            stop: Arc::clone(&stop),
            active: Arc::clone(&active),
            producer,
            accepted,
            receipt,
        };
        let thread = thread::spawn(move || worker.serve());
        WorkerHandle { stop, active, thread }
    }

    /// Accept one connection and run the generator with interruptible I/O.
    fn serve(&self) {
        let Some(mut stream) = accept(&self.listener, &self.stop) else {
            return;
        };
        {
            let mut socket = self.active.lock().expect("active socket lock");
            if self.stop.load(Ordering::Relaxed) {
                return;
            }
            *socket = Some(stream.try_clone().expect("clone response socket"));
        }
        let _sent = self.accepted.send(());
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("response request timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .expect("response write timeout");
        let mut observation = PayloadResponseReceipt {
            written_bytes: 0,
            complete: false,
            error: None,
        };
        match self.producer.write_response(&mut stream, &mut observation) {
            Ok(()) => observation.complete = true,
            Err(error) => observation.error = Some(error.to_string()),
        }
        drop(self.active.lock().expect("active socket lock").take());
        let _sent = self.receipt.send(observation);
    }
}

/// Poll a listener until connected or stopped.
fn accept(listener: &TcpListener, stop: &AtomicBool) -> Option<TcpStream> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Some(stream),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if stop.load(Ordering::Relaxed) {
                    return None;
                }
                thread::sleep(Duration::from_millis(5));
            },
            Err(error) => panic!("accept generated response: {error}"),
        }
    }
}

impl Producer {
    /// Consume the request head, then stream the generated response.
    fn write_response(&self, stream: &mut TcpStream, receipt: &mut PayloadResponseReceipt) -> io::Result<()> {
        read_request_head(stream)?;
        let length_header = match self.framing {
            PayloadResponseFraming::Fixed => format!("Content-Length: {}\r\n", self.spec.len()),
            PayloadResponseFraming::Chunked => "Transfer-Encoding: chunked\r\n".to_owned(),
            PayloadResponseFraming::Close => String::new(),
        };
        write!(stream, "HTTP/1.1 200 OK\r\n{length_header}Connection: close\r\n\r\n")?;
        let mut paused = false;
        while receipt.written_bytes < self.spec.len() {
            self.pause_if_due(stream, receipt.written_bytes, &mut paused)?;
            let next_pause = if paused {
                u64::MAX
            } else {
                self.pause_after.unwrap_or(u64::MAX)
            };
            let size = next_pause.saturating_sub(receipt.written_bytes).min(16_384) as usize;
            self.write_chunk(stream, receipt, size)?;
        }
        self.pause_if_due(stream, receipt.written_bytes, &mut paused)?;
        if matches!(self.framing, PayloadResponseFraming::Chunked) {
            stream.write_all(b"0\r\n\r\n")?;
        }
        stream.flush()
    }

    /// Acknowledge an exact prefix and wait for permission to produce the tail.
    fn pause_if_due(&self, stream: &mut TcpStream, written: u64, paused: &mut bool) -> io::Result<()> {
        if !*paused && self.pause_after == Some(written) {
            stream.flush()?;
            let _sent = self.prefix_tx.send(written);
            self.resume_rx
                .recv_timeout(Duration::from_secs(15))
                .map_err(io::Error::other)?;
            *paused = true;
        }
        Ok(())
    }

    /// Write one generated content chunk, accounting for partial writes.
    fn write_chunk(&self, stream: &mut TcpStream, receipt: &mut PayloadResponseReceipt, size: usize) -> io::Result<()> {
        let chunk = self.spec.chunk(receipt.written_bytes, size);
        if matches!(self.framing, PayloadResponseFraming::Chunked) {
            write!(stream, "{:x}\r\n", chunk.len())?;
        }
        let mut offset = 0;
        while offset < chunk.len() {
            let count = stream.write(&chunk[offset..])?;
            if count == 0 {
                return Err(io::Error::from(io::ErrorKind::WriteZero));
            }
            offset += count;
            receipt.written_bytes += count as u64;
        }
        if matches!(self.framing, PayloadResponseFraming::Chunked) {
            stream.write_all(b"\r\n")?;
        }
        Ok(())
    }
}

/// Read one bounded header block without consuming data from another request.
fn read_request_head(stream: &mut TcpStream) -> io::Result<()> {
    let mut headers = Vec::new();
    let mut byte = [0_u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte)?;
        headers.push(byte[0]);
        if headers.len() > 65_536 {
            return Err(io::Error::other("request header too large"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufReader, Write as _},
        net::TcpStream,
        time::{Duration, Instant},
    };

    use super::{PayloadResponseFraming, start_payload_response_backend};
    use crate::{PayloadSpec, read_h1_response};

    #[test]
    fn generated_framing_and_prefix_pause_are_byte_exact() {
        for framing in [
            PayloadResponseFraming::Fixed,
            PayloadResponseFraming::Chunked,
            PayloadResponseFraming::Close,
        ] {
            assert_generated_response(framing);
        }
    }

    /// Verify one framing with an acknowledged initial prefix.
    fn assert_generated_response(framing: PayloadResponseFraming) {
        let spec = PayloadSpec::binary(20_000, 42);
        let mut source = start_payload_response_backend(spec.clone(), framing, Some(1024));
        let mut stream = TcpStream::connect(("127.0.0.1", source.port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut count = 0;
        let mut resumed = false;
        let result = read_h1_response(&mut BufReader::new(stream), false, spec.len(), |chunk| {
            assert_eq!(spec.mismatch(count, chunk), None);
            count += chunk.len() as u64;
            if count >= 1024 && !resumed {
                assert_eq!(
                    source.prefix_written.recv_timeout(Duration::from_secs(5)).unwrap(),
                    1024
                );
                source.resume();
                resumed = true;
            }
            Ok(())
        });
        assert!(resumed);
        assert_eq!(count, spec.len());
        assert!(result.completion.is_some(), "{result:?}");
        let receipt = source.receipt.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(receipt.written_bytes, spec.len());
        assert!(receipt.complete, "{receipt:?}");
        source.join();
    }

    #[test]
    fn zero_and_end_boundary_pauses_signal_before_completion() {
        for length in [0, 8] {
            let mut source = start_payload_response_backend(
                PayloadSpec::binary(length, 1),
                PayloadResponseFraming::Chunked,
                Some(length),
            );
            let mut stream = TcpStream::connect(("127.0.0.1", source.port)).unwrap();
            stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            assert_eq!(
                source.prefix_written.recv_timeout(Duration::from_secs(5)).unwrap(),
                length
            );
            assert_eq!(
                source.receipt.try_recv().unwrap_err(),
                std::sync::mpsc::TryRecvError::Empty
            );
            source.resume();
            let result = read_h1_response(&mut BufReader::new(stream), false, length, |_| Ok(()));
            assert!(result.completion.is_some(), "{result:?}");
            assert!(source.receipt.recv_timeout(Duration::from_secs(5)).unwrap().complete);
            source.join();
        }
    }

    #[test]
    fn dropping_active_trickling_peer_interrupts_worker() {
        let source = start_payload_response_backend(PayloadSpec::binary(1, 1), PayloadResponseFraming::Fixed, None);
        let mut stream = TcpStream::connect(("127.0.0.1", source.port)).unwrap();
        source.accepted.recv_timeout(Duration::from_secs(5)).unwrap();
        stream.write_all(b"G").unwrap();
        let started = Instant::now();
        drop(source);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
