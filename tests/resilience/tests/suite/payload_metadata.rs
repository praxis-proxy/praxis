// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Isolated request-metadata and sustained event-stream resource tests.
//! RSS and virtual-memory peaks are process measurements, not live-object counts.

use std::{
    io::{self, BufRead as _, BufReader, Write as _},
    net::{Shutdown, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use praxis_test_utils::{
    H1Completion, PayloadSpec, PraxisProcess, free_port, read_h1_response, sample_process, start_counting_backend,
    start_echo_backend,
};

use super::payload_resources::{config, probe, serialized, stop};

/// Per-I/O and synchronization deadline.
const WAIT: Duration = Duration::from_secs(10);
/// One mebibyte.
const MIB: u64 = 1_048_576;
/// Real child address-space limit, below the smaller advertised length.
const ADDRESS_LIMIT: u64 = 1_006_632_960; // 960 MiB
/// An allowed body prefix with position-dependent contents.
const SEED: u64 = 0x4729;
/// A large, representable Content-Length and a much larger one.
const DECLARED: [u64; 2] = [1_073_741_824, 9_223_372_036_854_775_807];
/// Header-only filter; request body is deliberately not inspected.
const HEADER_GUARD: &str = "      - filter: guardrails\n        rules:\n          - target: header\n            name: X-Bad\n            contains: evil\n";

/// Start a real proxy with both address-space containment and startup headroom.
fn contained_proxy(yaml: &str, addr: &str) -> (PraxisProcess, u64) {
    let process = PraxisProcess::spawn_with_ulimit(yaml, addr, Some("-S -v 983040"));
    let limits = std::fs::read_to_string(format!("/proc/{}/limits", process.pid())).unwrap();
    let soft = limits
        .lines()
        .find_map(|line| line.strip_prefix("Max address space"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert_eq!(soft, ADDRESS_LIMIT, "the proxy must inherit the address-space limit");
    let startup_peak = proc_bytes(process.pid(), "VmPeak:");
    assert!(
        startup_peak <= ADDRESS_LIMIT - 64 * MIB,
        "the real proxy needs startup headroom: {startup_peak}"
    );
    (process, startup_peak)
}

/// Read a Linux procfs status size in bytes.
fn proc_bytes(pid: u32, field: &str) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let mut fields = status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .unwrap()
        .split_whitespace();
    let kib = fields.next().unwrap().parse::<u64>().unwrap();
    assert_eq!(
        fields.next(),
        Some("kB"),
        "procfs memory observations must use KiB units"
    );
    kib * 1024
}

/// Background RSS samples, stopped and joined even on panic.
struct Sampler {
    /// Request termination of the sampling thread.
    stop: Arc<AtomicBool>,
    /// Worker producing its maximum observed RSS.
    worker: Option<JoinHandle<u64>>,
}

impl Sampler {
    /// Sample the child while the workload is active.
    fn start(pid: u32) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut peak = 0;
            while !flag.load(Ordering::Relaxed) {
                peak = peak.max(sample_process(pid).expect("proxy must remain alive").rss_bytes.unwrap());
                thread::sleep(Duration::from_millis(10));
            }
            peak.max(
                sample_process(pid)
                    .expect("proxy must remain alive after workload")
                    .rss_bytes
                    .unwrap(),
            )
        });
        Self {
            stop,
            worker: Some(worker),
        }
    }

    /// Stop the worker and return its observed peak RSS.
    fn finish(mut self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap()
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}

/// Assert RSS and virtual-space growth against the warmed child, not the test runner.
fn check_memory(
    process: &PraxisProcess,
    initial: &praxis_test_utils::ProcessSample,
    initial_vm_peak: u64,
    peak_rss: u64,
    budget: u64,
) {
    let initial_rss = initial.rss_bytes.unwrap();
    let high_water_limit = initial.peak_rss_bytes.unwrap().max(initial_rss + budget);
    let peak_vm = proc_bytes(process.pid(), "VmPeak:");
    let peak_hwm = proc_bytes(process.pid(), "VmHWM:");
    eprintln!(
        "metadata/stream child: rss_before={initial_rss} sampled_peak={peak_rss} vm_start={initial_vm_peak} vm_peak={peak_vm} rss_hwm={peak_hwm}"
    );
    assert!(
        peak_rss.saturating_sub(initial_rss) <= budget,
        "proxy RSS exceeded the workload budget"
    );
    assert!(
        peak_vm.saturating_sub(initial_vm_peak) <= 256 * MIB,
        "virtual address growth exceeded the metadata budget"
    );
    assert!(
        peak_hwm <= high_water_limit,
        "proxy RSS high-water exceeded the workload budget"
    );
    assert!(peak_vm < ADDRESS_LIMIT, "proxy reached its address-space cap");
}

/// Connect with a finite deadline and a fresh HTTP/1 connection.
fn connect(addr: &str) -> TcpStream {
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    stream
}

/// A completed local response, with bounded capture.
fn complete_status(stream: TcpStream) -> u16 {
    let result = read_h1_response(&mut BufReader::new(stream), false, 8192, |_| Ok(()));
    assert!(result.completion.is_some() && result.abort.is_none(), "{result:?}");
    result.status.unwrap()
}

/// The declared huge body is withheld until a header-only guard rejects it.
#[test]
fn huge_denied_headers_do_not_allocate_or_dispatch() {
    let _guard = serialized();
    let spec = PayloadSpec::binary(4, SEED);
    let backend = start_counting_backend(spec.clone(), "guard", spec.len());
    let health = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let yaml = config(port, backend.port, health.port(), HEADER_GUARD, "")
        .replace("max_request_bytes: 67108864", "max_request_bytes: null")
        .replace("max_response_bytes: null", "max_response_bytes: 1024");
    let (mut process, initial_vm_peak) = contained_proxy(&yaml, &addr);
    probe(&addr);
    let initial = sample_process(process.pid()).unwrap();
    let sampler = Sampler::start(process.pid());

    for length in DECLARED {
        let mut stream = connect(&addr);
        let started = Instant::now();
        write!(stream, "POST /bulk HTTP/1.1\r\nHost: localhost\r\nX-Bad: evil\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n").unwrap();
        assert_eq!(
            complete_status(stream),
            403,
            "header guard must reject before any upload"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "header rejection must be prompt"
        );
        assert!(
            matches!(
                backend.accepted.recv_timeout(Duration::from_millis(250)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "denied header must never select the backend"
        );
    }
    let mut allowed = connect(&addr);
    write!(
        allowed,
        "POST /bulk HTTP/1.1\r\nHost: localhost\r\nX-Bad: safe\r\nContent-Length: 4\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    allowed.write_all(&spec.chunk(0, 4)).unwrap();
    assert_eq!(
        complete_status(allowed),
        200,
        "positive control must reach the selected backend"
    );
    let receipt = backend.receipt.recv_timeout(WAIT).unwrap();
    assert_eq!(
        receipt.request_line, "POST /bulk HTTP/1.1",
        "the allowed request must reach the chosen bulk route"
    );
    assert_eq!(receipt.bytes, 4);
    assert_eq!(
        receipt.verified_bytes, 4,
        "all four prefix bytes must match independently"
    );
    assert_eq!(receipt.completion, Some(H1Completion::ContentLength));
    assert!(receipt.abort.is_none() && receipt.mismatch.is_none(), "{receipt:?}");
    probe(&addr);
    let peak = sampler.finish();
    check_memory(&process, &initial, initial_vm_peak, peak, 64 * MIB);
    stop(&mut process);
    backend.join();
}

/// How the incomplete upload is terminated after its tiny prefix.
#[derive(Clone, Copy, Debug)]
enum UploadEnd {
    ClientClose,
    ReadTimeout,
}

/// A tiny, validated prefix reaches the backend, which must never complete it.
fn truncated_metadata_case(length: u64, ending: UploadEnd) {
    let spec = PayloadSpec::binary(length, SEED);
    let backend = start_counting_backend(spec.clone(), "truncated", 64);
    let health = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let listener = match ending {
        UploadEnd::ClientClose => "",
        UploadEnd::ReadTimeout => "    downstream_read_timeout_ms: 500\n",
    };
    let yaml = config(port, backend.port, health.port(), "", listener)
        .replace("max_request_bytes: 67108864", "max_request_bytes: null")
        .replace("max_response_bytes: null", "max_response_bytes: 1024");
    let (mut process, initial_vm_peak) = contained_proxy(&yaml, &addr);
    probe(&addr);
    let initial = sample_process(process.pid()).unwrap();
    let sampler = Sampler::start(process.pid());
    let mut stream = connect(&addr);
    write!(
        stream,
        "POST /bulk HTTP/1.1\r\nHost: localhost\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    stream.write_all(&spec.chunk(0, 4)).unwrap();
    backend
        .accepted
        .recv_timeout(WAIT)
        .expect("allowed request must select backend");
    backend
        .first_byte
        .recv_timeout(WAIT)
        .expect("backend must observe the exact prefix before termination");
    match ending {
        UploadEnd::ClientClose => {
            assert!(
                matches!(
                    backend.receipt.recv_timeout(Duration::from_millis(200)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ),
                "the backend must still be waiting for the rest of the request before client close"
            );
            stream.shutdown(Shutdown::Both).unwrap();
            drop(stream);
        },
        UploadEnd::ReadTimeout => {
            let start = Instant::now();
            let result = read_h1_response(&mut BufReader::new(stream), false, 8192, |_| Ok(()));
            assert!(
                start.elapsed() < WAIT,
                "downstream read timeout must end the stalled upload"
            );
            assert_ne!(
                result.status,
                Some(200),
                "truncated input cannot produce a successful response: {result:?}"
            );
            assert!(
                !result
                    .abort
                    .as_ref()
                    .is_some_and(|(kind, _)| matches!(*kind, io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)),
                "the client must not time out waiting for the proxy: {result:?}"
            );
        },
    }
    let receipt = backend
        .receipt
        .recv_timeout(WAIT)
        .expect("backend must finish observing the interrupted request");
    assert_eq!(
        receipt.request_line, "POST /bulk HTTP/1.1",
        "the allowed request must reach the chosen bulk route"
    );
    assert_eq!(receipt.bytes, 4, "exact prefix only: {receipt:?}");
    assert_eq!(
        receipt.verified_bytes, 4,
        "all four prefix bytes must match independently"
    );
    assert!(
        receipt.completion.is_none() && receipt.abort.is_some() && receipt.mismatch.is_none(),
        "truncated request must not complete: {receipt:?}"
    );
    assert!(
        receipt
            .headers
            .iter()
            .any(|(name, value)| name == "content-length" && value == &length.to_string()),
        "backend must observe the actual declared length: {receipt:?}"
    );
    probe(&addr);
    let peak = sampler.finish();
    check_memory(&process, &initial, initial_vm_peak, peak, 64 * MIB);
    stop(&mut process);
    backend.join();
}

#[test]
fn huge_allowed_lengths_keep_only_a_tiny_prefix_on_close_and_timeout() {
    let _guard = serialized();
    for length in DECLARED {
        for ending in [UploadEnd::ClientClose, UploadEnd::ReadTimeout] {
            truncated_metadata_case(length, ending);
        }
    }
}

/// Number of ordered SSE messages; total content is just over 64 MiB.
const EVENT_COUNT: usize = 4097;
/// Each message is large enough to exercise streaming without a large fixture.
const EVENT_BYTES: usize = 16_384;
/// First and middle barriers include a genuine upstream idle interval.
const EVENT_GAP: Duration = Duration::from_millis(75);

/// An exact, position-sensitive SSE message; only one is materialized at once.
fn event(index: usize) -> Vec<u8> {
    let head = format!("id: {index:06}\ndata: ");
    let mut event: Vec<u8> = (0..EVENT_BYTES)
        .map(|offset| b'a' + u8::try_from((index + offset) % 26).unwrap())
        .collect();
    event[..head.len()].copy_from_slice(head.as_bytes());
    event[EVENT_BYTES - 2..].copy_from_slice(b"\n\n");
    event
}

/// Whether the source waits for proof the client received this message.
fn event_barrier(completed: usize) -> bool {
    matches!(completed, 1 | EVENT_COUNT) || completed == EVENT_COUNT / 2
}

/// A cancellable one-request SSE peer whose barriers force incremental delivery.
struct EventPeer {
    /// Listener port.
    port: u16,
    /// Client acknowledgments of fully observed barrier messages.
    acknowledgments: Sender<usize>,
    /// Stop the listener when no connection is selected.
    stop: Arc<AtomicBool>,
    /// Socket clone for interrupting a blocked write on teardown.
    active: Arc<Mutex<Option<TcpStream>>>,
    /// Joined producer; returns its exact sent content count.
    worker: Option<JoinHandle<io::Result<u64>>>,
}

impl EventPeer {
    /// Stop a listening or connected peer.
    fn cancel(&self) {
        self.stop.store(true, Ordering::Relaxed);
        let _sent = self.acknowledgments.send(0);
        if let Some(stream) = self.active.lock().unwrap().as_ref() {
            let _shutdown = stream.shutdown(Shutdown::Both);
        }
    }

    /// Wait for successful terminal framing, returning sent content bytes.
    fn finish(mut self) -> u64 {
        self.worker
            .take()
            .unwrap()
            .join()
            .unwrap()
            .expect("SSE source must complete")
    }
}

impl Drop for EventPeer {
    fn drop(&mut self) {
        self.cancel();
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                let _result = result.unwrap();
            }
        }
    }
}

/// Serve one request and stop promptly when the peer handle is dropped.
fn event_peer() -> EventPeer {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let active = Arc::new(Mutex::new(None::<TcpStream>));
    let flag = Arc::clone(&stop);
    let socket = Arc::clone(&active);
    let (acknowledgments, receive) = mpsc::channel();
    let worker = thread::spawn(move || {
        let stream = loop {
            if flag.load(Ordering::Relaxed) {
                return Err(io::Error::other("SSE source cancelled before accept"));
            }
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                Err(error) => return Err(error),
            }
        };
        {
            let mut active = socket.lock().unwrap();
            if flag.load(Ordering::Relaxed) {
                return Err(io::Error::other("SSE source cancelled"));
            }
            *active = Some(stream.try_clone()?);
        }
        let result = serve_events(stream, &receive);
        drop(socket.lock().unwrap().take());
        result
    });
    EventPeer {
        port,
        acknowledgments,
        stop,
        active,
        worker: Some(worker),
    }
}

/// Send chunk-framed SSE messages, pausing until observed at three checkpoints.
fn serve_events(stream: TcpStream, acknowledgments: &Receiver<usize>) -> io::Result<u64> {
    stream.set_read_timeout(Some(WAIT))?;
    stream.set_write_timeout(Some(WAIT))?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line != "GET /bulk HTTP/1.1\r\n" {
        return Err(io::Error::other("unexpected SSE upstream request"));
    }
    let mut header_bytes = line.len();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        header_bytes += line.len();
        if header_bytes > 65_536 {
            return Err(io::Error::other("SSE request headers exceed the fixture budget"));
        }
        if line == "\r\n" {
            break;
        }
    }
    let mut stream = reader.into_inner();
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")?;
    let mut sent = 0;
    for index in 0..EVENT_COUNT {
        let body = event(index);
        write!(stream, "{:x}\r\n", body.len())?;
        stream.write_all(&body)?;
        stream.write_all(b"\r\n")?;
        stream.flush()?;
        sent += body.len() as u64;
        let completed = index + 1;
        if event_barrier(completed) {
            let observed = acknowledgments.recv_timeout(WAIT).map_err(io::Error::other)?;
            if observed != completed {
                return Err(io::Error::other("event observation was cancelled or out of order"));
            }
            if completed != EVENT_COUNT {
                thread::sleep(EVENT_GAP);
            }
        }
    }
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()?;
    Ok(sent)
}

/// The proxy delivers every ordered event before source completion with bounded RSS.
#[test]
fn sustained_unbounded_sse_is_incremental_and_memory_bounded() {
    let _guard = serialized();
    let peer = event_peer();
    let health = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let yaml = config(port, peer.port, health.port(), "", "").replace(
        "          - name: bulk\n            endpoints:",
        "          - name: bulk\n            read_timeout_ms: 5000\n            endpoints:",
    );
    let (mut process, initial_vm_peak) = contained_proxy(&yaml, &addr);
    probe(&addr);
    let initial = sample_process(process.pid()).unwrap();
    let sampler = Sampler::start(process.pid());
    let mut stream = connect(&addr);
    stream
        .write_all(b"GET /bulk HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let expected_total = u64::try_from(EVENT_COUNT * EVENT_BYTES).unwrap();
    assert!(
        expected_total > 64 * MIB,
        "unbounded direction must exceed the finite maximum"
    );
    let mut current = event(0);
    let mut index = 0;
    let mut offset = 0;
    let mut received = 0_u64;
    let mut gaps = 0;
    let mut gap_started = None::<Instant>;
    let response = read_h1_response(&mut BufReader::new(stream), false, expected_total, |mut bytes| {
        while !bytes.is_empty() {
            assert!(index < EVENT_COUNT, "unexpected extra event bytes");
            let take = bytes.len().min(EVENT_BYTES - offset);
            assert_eq!(
                &bytes[..take],
                &current[offset..offset + take],
                "event {index}, offset {offset}"
            );
            offset += take;
            received += take as u64;
            bytes = &bytes[take..];
            if offset == EVENT_BYTES {
                index += 1;
                offset = 0;
                if let Some(started) = gap_started.take() {
                    assert!(
                        started.elapsed() >= Duration::from_millis(50),
                        "next event must follow the deliberate idle gap"
                    );
                    gaps += 1;
                }
                if event_barrier(index) {
                    // The source cannot write its next event or terminal framing
                    // until the client confirms this complete message arrived.
                    if index != EVENT_COUNT {
                        probe(&addr);
                    }
                    let gate_started = Instant::now();
                    peer.acknowledgments.send(index).unwrap();
                    if index != EVENT_COUNT {
                        gap_started = Some(gate_started);
                    }
                }
                if index < EVENT_COUNT {
                    current = event(index);
                }
            }
        }
        Ok(())
    });
    assert_eq!(response.status, Some(200), "{response:?}");
    assert!(
        response
            .headers
            .iter()
            .any(|(name, value)| name == "content-type" && value == "text/event-stream"),
        "SSE content type must survive forwarding: {response:?}"
    );
    assert_eq!(
        response.completion,
        Some(H1Completion::Chunked),
        "complete stream framing: {response:?}"
    );
    assert!(response.abort.is_none(), "{response:?}");
    assert_eq!((index, offset, received), (EVENT_COUNT, 0, expected_total));
    assert_eq!(gaps, 2, "both idle intervals must be observed");
    assert_eq!(
        peer.finish(),
        expected_total,
        "source completed every event and terminal framing"
    );
    probe(&addr);
    let peak = sampler.finish();
    check_memory(&process, &initial, initial_vm_peak, peak, 48 * MIB);
    stop(&mut process);
}

/// Counts request-state owners and actual body-hook bytes in an in-process proxy.
#[derive(Default)]
struct OwnerCounters {
    /// Number of tracked request states created.
    created: AtomicUsize,
    /// Number of tracked states still alive.
    live: AtomicUsize,
    /// Number of tracked states dropped.
    dropped: AtomicUsize,
    /// Number of dropped states that actually retained body bytes.
    bodies_dropped: AtomicUsize,
    /// Sum of bytes offered to the custom body hook, including EOS aggregates.
    observed: AtomicUsize,
}

/// Request-scoped state which retains a cloned body chunk until it is dropped.
struct RequestOwner {
    /// Shared counters for this test.
    counters: Arc<OwnerCounters>,
    /// A real incoming body chunk, or the frozen EOS body, held by this state.
    body: Option<bytes::Bytes>,
}

impl Drop for RequestOwner {
    fn drop(&mut self) {
        let body = self.body.take();
        if body.is_some() {
            self.counters.bodies_dropped.fetch_add(1, Ordering::SeqCst);
        }
        drop(body);
        self.counters.live.fetch_sub(1, Ordering::SeqCst);
        self.counters.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

/// Test-only filter that tracks request-scoped ownership through real hooks.
struct OwnerFilter {
    /// Counters shared with the test controller.
    counters: Arc<OwnerCounters>,
}

#[async_trait::async_trait]
impl praxis_filter::HttpFilter for OwnerFilter {
    fn name(&self) -> &'static str {
        "lifecycle_owner"
    }

    fn runs_request_head(&self) -> bool {
        true
    }

    async fn on_request_head(
        &self,
        ctx: &mut praxis_filter::HttpFilterContext<'_>,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        if ctx.request.uri.path() == "/bulk" {
            let id = ctx
                .current_filter_id
                .ok_or_else(|| praxis_filter::FilterError::from("missing filter id"))?;
            self.counters.created.fetch_add(1, Ordering::SeqCst);
            self.counters.live.fetch_add(1, Ordering::SeqCst);
            let previous = ctx.filter_state.insert(
                id,
                Box::new(RequestOwner {
                    counters: Arc::clone(&self.counters),
                    body: None,
                }),
            );
            assert!(previous.is_none(), "the request head must create its state once");
        }
        Ok(praxis_filter::FilterAction::Continue)
    }

    async fn on_request(
        &self,
        _: &mut praxis_filter::HttpFilterContext<'_>,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        Ok(praxis_filter::FilterAction::Continue)
    }

    fn request_body_access(&self) -> praxis_filter::BodyAccess {
        praxis_filter::BodyAccess::ReadOnly(praxis_filter::BodyRequirement::Optional)
    }

    fn request_body_mode(&self) -> praxis_filter::BodyMode {
        praxis_filter::BodyMode::StreamBuffer {
            max_bytes: Some(2_097_152),
        }
    }

    async fn on_request_body(
        &self,
        ctx: &mut praxis_filter::HttpFilterContext<'_>,
        body: &mut Option<bytes::Bytes>,
        _: bool,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        if ctx.request.uri.path() == "/bulk" {
            let id = ctx
                .current_filter_id
                .ok_or_else(|| praxis_filter::FilterError::from("missing filter id"))?;
            let owner = ctx
                .filter_state
                .get_mut(&id)
                .and_then(|state| state.downcast_mut::<RequestOwner>())
                .ok_or_else(|| praxis_filter::FilterError::from("missing request owner"))?;
            if let Some(chunk) = body {
                self.counters.observed.fetch_add(chunk.len(), Ordering::SeqCst);
                owner.body = Some(chunk.clone());
            }
        }
        Ok(praxis_filter::FilterAction::Continue)
    }
}

/// Wait for all observed request-state owners to be dropped, within a deadline.
fn assert_owners_dropped(counters: &OwnerCounters, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let created = counters.created.load(Ordering::SeqCst);
        let dropped = counters.dropped.load(Ordering::SeqCst);
        let live = counters.live.load(Ordering::SeqCst);
        if (created, dropped, live) == (expected, expected, 0) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "owners not released: created={created}, dropped={dropped}, live={live}, expected={expected}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// Submit a complete body and require exact echoed bytes on success.
fn submit_tracked(addr: &str, bytes: &[u8], expected_status: u16) {
    let mut stream = connect(addr);
    write!(
        stream,
        "POST /bulk HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    )
    .unwrap();
    stream.write_all(bytes).unwrap();
    let mut output = Vec::new();
    let response = read_h1_response(&mut BufReader::new(stream), false, 2_097_152, |part| {
        output.extend_from_slice(part);
        Ok(())
    });
    assert_eq!(response.status, Some(expected_status), "{response:?}");
    assert!(
        response.completion.is_some() && response.abort.is_none(),
        "{response:?}"
    );
    if expected_status == 200 {
        assert_eq!(output, bytes, "success must echo the actual complete body");
    }
}

/// Test-owned state and cloned input Bytes are dropped after real request cycles.
/// This does not count all proxy allocations or Tokio tasks.
#[test]
fn repeated_request_cycles_drop_tracked_body_owners() {
    let _guard = serialized();
    let backend = start_echo_backend();
    let health = start_echo_backend();
    let port = free_port();
    let filters = "      - filter: lifecycle_owner\n      - filter: json_body\n        conditions:\n          - when:\n              path_prefix: /bulk\n        max_body_bytes: 2097152\n        on_invalid: reject\n        request_extract:\n          - pointer: /model\n            metadata: model\n";
    let yaml = config(port, backend.port(), health.port(), filters, "")
        .replace("max_request_bytes: 67108864", "max_request_bytes: 2097152");
    let config = praxis_core::config::Config::from_yaml(&yaml).unwrap();
    let counters = Arc::new(OwnerCounters::default());
    let captured = Arc::clone(&counters);
    let mut registry = praxis_filter::FilterRegistry::with_builtins();
    registry
        .register(
            "lifecycle_owner",
            praxis_filter::FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(OwnerFilter {
                    counters: Arc::clone(&captured),
                }))
            })),
        )
        .unwrap();
    let proxy = praxis_test_utils::start_full_proxy_with_registry(&config, &registry);
    let payload = PayloadSpec::padded(131_072, br#"{"model":"unit","data":""#, br#""}"#, b'x').unwrap();
    let valid = payload.chunk(0, 131_072);
    let mut expected = 0;

    for _cycle in 0..4 {
        submit_tracked(proxy.addr(), &valid, 200);
        expected += 1;
        assert_owners_dropped(&counters, expected);

        let mut oversized = connect(proxy.addr());
        oversized
            .write_all(
                b"POST /bulk HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2097153\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        assert_eq!(complete_status(oversized), 413);
        expected += 1;
        assert_owners_dropped(&counters, expected);

        submit_tracked(proxy.addr(), br#"{"model":"#, 400);
        expected += 1;
        assert_owners_dropped(&counters, expected);

        let seen = counters.observed.load(Ordering::SeqCst);
        let mut aborted = connect(proxy.addr());
        write!(
            aborted,
            "POST /bulk HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            valid.len()
        )
        .unwrap();
        aborted.write_all(&valid[..16_384]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while counters.observed.load(Ordering::SeqCst) == seen {
            assert!(
                Instant::now() < deadline,
                "body hook must receive the prefix before cancellation"
            );
            thread::sleep(Duration::from_millis(10));
        }
        aborted.shutdown(Shutdown::Both).unwrap();
        drop(aborted);
        expected += 1;
        assert_owners_dropped(&counters, expected);
        probe(proxy.addr());
    }
    assert_eq!(counters.created.load(Ordering::SeqCst), 16);
    assert_eq!(counters.dropped.load(Ordering::SeqCst), 16);
    assert_eq!(counters.live.load(Ordering::SeqCst), 0);
    assert_eq!(
        counters.bodies_dropped.load(Ordering::SeqCst),
        12,
        "each success, malformed body, and cancellation retained an observed chunk"
    );
}
