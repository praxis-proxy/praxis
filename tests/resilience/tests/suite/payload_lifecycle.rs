// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Payload lifecycle and failure containment against actual proxy processes.

#![cfg(target_os = "linux")]

use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{Shutdown, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use praxis_test_utils::{
    PayloadResponseFraming, PayloadSpec, PraxisProcess, ProcessLogCursor, free_port, http_get, read_h1_response,
    sample_process, start_backend_with_shutdown, start_counting_backend, start_echo_backend,
    start_payload_response_backend, start_reloadable_proxy,
};

use super::payload_resources::{config, probe, serialized, sink, status, stop, upload};

/// Deadline for peer receipts and individual socket operations.
const WAIT: Duration = Duration::from_secs(20);
/// Bounded built-in preread filter used by lifecycle tests.
const INSPECT: &str = "      - filter: json_body_field\n        field: model\n        header: x-praxis-model\n        max_body_bytes: 262144\n";

/// An idle timeout is not a total upload deadline: a slow but active request
/// lasts longer than the timeout and must still arrive intact.
#[test]
fn idle_timeout_closes_silent_upload_but_allows_long_trickle() {
    let _guard = serialized();
    for filters in ["", INSPECT] {
        let clean = start_echo_backend();
        let backend = start_echo_backend();
        let port = free_port();
        let addr = format!("127.0.0.1:{port}");
        let yaml = config(
            port,
            backend.port(),
            clean.port(),
            filters,
            "    downstream_read_timeout_ms: 500\n",
        );
        let mut process = PraxisProcess::spawn(&yaml, &addr);
        let mut silent = upload(&addr, 262_144);
        silent.write_all(br#"{"model":"old","pad":"#).unwrap();
        silent.write_all(&vec![b'x'; 240_000]).unwrap();
        let started = Instant::now();
        let expected = if filters.is_empty() { 400 } else { 408 };
        assert_eq!(
            status(silent),
            expected,
            "timeout phase preread={}",
            !filters.is_empty()
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        probe(&addr);

        let body = br#"{"model":"old"}"#;
        let mut trickle = upload(&addr, body.len());
        let started = Instant::now();
        for byte in body {
            trickle.write_all(&[*byte]).unwrap();
            thread::sleep(Duration::from_millis(100));
        }
        let mut echoed = Vec::new();
        let response = read_h1_response(&mut BufReader::new(trickle), false, 1024, |chunk| {
            echoed.extend_from_slice(chunk);
            Ok(())
        });
        assert!(started.elapsed() > Duration::from_millis(500));
        assert_eq!(response.status, Some(200), "{response:?}");
        assert!(
            response.completion.is_some() && response.abort.is_none(),
            "{response:?}"
        );
        assert_eq!(echoed, body);
        probe(&addr);
        stop(&mut process);
    }
}

/// A paused request retains its pipeline generation across a valid and then an
/// invalid reload; the new body cap applies only to requests started later.
#[test]
fn reload_pins_inflight_body_and_rejects_invalid_generation() {
    let _guard = serialized();
    let old_body = PayloadSpec::padded(
        1_048_576,
        br#"{"model":"old","pad":""#,
        br#"","ssn":"123-45-6789"}"#,
        b'x',
    )
    .unwrap();
    let new_body = PayloadSpec::padded(32_768, br#"{"model":"old","pad":""#, br#""}"#, b'x').unwrap();
    let old_backend = start_counting_backend(old_body.clone(), "old", old_body.len());
    let new_backend = start_counting_backend(new_body.clone(), "new", new_body.len());
    let old_probe = start_backend_with_shutdown("generation-a");
    let new_probe = start_backend_with_shutdown("generation-b");
    let port = free_port();
    let old_inspect = INSPECT.replace("262144", "2097152");
    let old_yaml = config(port, old_backend.port, old_probe.port(), &old_inspect, "");
    let proxy = start_reloadable_proxy(&old_yaml);
    let mut old = upload(proxy.addr(), old_body.len() as usize);
    old.write_all(&old_body.chunk(0, old_body.len() as usize - 1)).unwrap();
    thread::sleep(Duration::from_millis(100));
    assert!(
        old_backend.accepted.try_recv() == Err(mpsc::TryRecvError::Empty),
        "old request must still be held in preread"
    );
    let new_filters = format!(
        "{INSPECT}      - filter: guardrails\n        rules:\n          - target: body\n            contains: [ssn]\n"
    );
    let new_yaml = config(port, new_backend.port, new_probe.port(), &new_filters, "")
        .replace("max_request_bytes: 67108864", "max_request_bytes: 65536");
    let seen = proxy.reload_until(
        &new_yaml,
        || http_get(proxy.addr(), "/probe", None),
        |(_, body)| body == "generation-b",
    );
    assert_eq!((seen.0, seen.1.as_str()), (200, "generation-b"));
    old.write_all(&old_body.chunk(old_body.len() - 1, 1)).unwrap();
    assert_eq!(status(old), 200);
    let receipt = old_backend.receipt.recv_timeout(WAIT).unwrap();
    assert_eq!(
        (receipt.bytes, receipt.mismatch, receipt.completion.is_some()),
        (old_body.len(), None, true)
    );

    let over = upload(proxy.addr(), 131_072);
    assert_eq!(status(over), 413);
    let forbidden_body =
        PayloadSpec::padded(32_768, br#"{"model":"old","pad":""#, br#"","ssn":"123-45-6789"}"#, b'x').unwrap();
    let mut forbidden = upload(proxy.addr(), forbidden_body.len() as usize);
    forbidden
        .write_all(&forbidden_body.chunk(0, forbidden_body.len() as usize))
        .unwrap();
    assert_eq!(status(forbidden), 403);
    let mut new = upload(proxy.addr(), new_body.len() as usize);
    new.write_all(&new_body.chunk(0, new_body.len() as usize)).unwrap();
    assert_eq!(status(new), 200);
    let receipt = new_backend.receipt.recv_timeout(WAIT).unwrap();
    assert_eq!(
        (receipt.bytes, receipt.mismatch, receipt.completion.is_some()),
        (new_body.len(), None, true)
    );
    proxy.reload(&new_yaml.replace("max_request_bytes: 65536", "max_request_bytes: invalid"));
    assert_eq!(http_get(proxy.addr(), "/probe", None), (200, "generation-b".to_owned()));
    old_backend.join();
    new_backend.join();
}

/// SIGTERM while buffering, streaming upload, or blocked on a response must
/// finish within the configured grace period and cancel incomplete peers.
#[test]
fn shutdown_cancels_inflight_body_phases_and_reaps_peers() {
    let _guard = serialized();
    shutdown_acknowledged_preread();
    for phase in ["upload", "response"] {
        let spec = PayloadSpec::binary(8_388_608, 22);
        let bulk = start_counting_backend(spec.clone(), "shutdown", spec.len());
        let mut source = start_payload_response_backend(spec.clone(), PayloadResponseFraming::Fixed, Some(8192));
        let clean = start_echo_backend();
        let port = free_port();
        let addr = format!("127.0.0.1:{port}");
        let backend_port = if phase == "response" { source.port } else { bulk.port };
        let mut process = PraxisProcess::spawn(&config(port, backend_port, clean.port(), "", ""), &addr);
        probe(&addr);
        let client = if phase == "response" {
            let mut stream = TcpStream::connect(&addr).unwrap();
            stream.set_read_timeout(Some(WAIT)).unwrap();
            stream
                .write_all(b"GET /bulk HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            assert_eq!(source.prefix_written.recv_timeout(WAIT).unwrap(), 8192);
            stream
        } else {
            let mut stream = upload(&addr, spec.len() as usize);
            stream.write_all(&spec.chunk(0, 65_536)).unwrap();
            bulk.first_byte.recv_timeout(WAIT).unwrap();
            stream
        };
        let mut client = BufReader::new(client);
        let mut observed = 0_u64;
        if phase == "response" {
            let mut line = String::new();
            client.read_line(&mut line).unwrap();
            assert!(line.starts_with("HTTP/1.1 200"), "{line:?}");
            let mut declared = None;
            loop {
                line.clear();
                assert_ne!(client.read_line(&mut line).unwrap(), 0);
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    declared = Some(value.trim().parse::<u64>().unwrap());
                }
            }
            assert_eq!(declared, Some(spec.len()));
            let mut prefix = vec![0; 8192];
            client.read_exact(&mut prefix).unwrap();
            assert_eq!(spec.mismatch(0, &prefix), None);
            observed = prefix.len() as u64;
        }
        let started = Instant::now();
        process.signal("TERM");
        let (exit, killed) = process.wait_or_kill(Duration::from_secs(12));
        assert!(!killed && exit.success(), "{phase}: {exit}, killed={killed}");
        assert!(
            started.elapsed() < Duration::from_secs(12),
            "shutdown must finish within the runner deadline"
        );
        if phase == "response" {
            let mut chunk = [0_u8; 8192];
            loop {
                match client.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(count) => {
                        assert_eq!(spec.mismatch(observed, &chunk[..count]), None);
                        observed += count as u64;
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                    Err(error) => panic!("{phase}: unexpected read error: {error}"),
                }
            }
            assert!(observed < spec.len(), "incomplete response falsely completed");
        } else {
            let response = read_h1_response(&mut client, false, 8192, |_| Ok(()));
            assert!(
                response.status != Some(200) || response.completion.is_none(),
                "{phase} falsely completed: {response:?}"
            );
        }
        if phase == "upload" {
            let receipt = bulk.receipt.recv_timeout(WAIT).unwrap();
            assert!(
                receipt.bytes < spec.len() && receipt.completion.is_none(),
                "{receipt:?}"
            );
        }
        if phase == "response" {
            source.resume();
            let receipt = source.receipt.recv_timeout(WAIT).unwrap();
            assert!(!receipt.complete && receipt.written_bytes < spec.len(), "{receipt:?}");
        }
        bulk.join();
        source.join();
    }
}

/// The child test registry acknowledges a real pre-read body prefix and keeps
/// an incoming chunk in request state until shutdown cancels the upload.
fn shutdown_acknowledged_preread() {
    let spec = PayloadSpec::binary(262_144, 22);
    let bulk = start_counting_backend(spec.clone(), "shutdown-preread", spec.len());
    let clean = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let filters = "      - filter: w7_generation\n        generation: shutdown\n        ack_bytes: 200000\n";
    let yaml = config(port, bulk.port, clean.port(), filters, "");
    let dir = std::env::temp_dir().join(format!("praxis-w7-shutdown-{}-{port}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let files = GenerationFiles(dir);
    let config_path = files.0.join("config.yaml");
    let events = files.0.join("events");
    std::fs::write(&config_path, yaml).unwrap();
    let mut child = ReleaseChild::spawn_reload(&config_path, &events);
    praxis_test_utils::wait_for_tcp(&addr);
    probe(&addr);

    let mut client = upload(&addr, spec.len() as usize);
    client.write_all(&spec.chunk(0, 240_000)).unwrap();
    let held = wait_generation_event(&events, "prefix-held shutdown ");
    let id: usize = held.split_whitespace().last().unwrap().parse().unwrap();
    let snapshot = std::fs::read_to_string(&events).unwrap();
    assert!(
        snapshot.lines().any(|line| line == format!("body-held shutdown {id}")),
        "the acknowledged prefix must retain an actual body owner"
    );
    assert!(
        !snapshot.lines().any(|line| line == format!("body-drop shutdown {id}")),
        "the body owner must remain held until shutdown"
    );
    assert_eq!(
        bulk.accepted.try_recv(),
        Err(mpsc::TryRecvError::Empty),
        "incomplete pre-read must not dispatch upstream"
    );
    let started = Instant::now();
    child.shutdown();
    assert!(
        started.elapsed() < Duration::from_secs(12),
        "shutdown must finish within the runner deadline"
    );
    let response = read_h1_response(&mut BufReader::new(client), false, 8192, |_| Ok(()));
    assert!(
        response.status != Some(200) || response.completion.is_none(),
        "incomplete preread must not succeed: {response:?}"
    );
    bulk.join();
}

/// Send a body and require a completely framed response.
fn send_body(addr: &str, body: &[u8]) -> u16 {
    let mut request = upload(addr, body.len());
    request.write_all(body).unwrap();
    status(request)
}

/// Bounded hostile batches include successes, over-limit headers, late parse
/// errors, and cancellation. RSS and descriptor trends are separate from live
/// allocations, which this test cannot measure.
#[test]
fn repeated_failures_and_cancellation_leave_proxy_available() {
    let _guard = serialized();
    let body = PayloadSpec::padded(
        1_048_576,
        br#"{"model":"old","canary":"CANARY_PAYLOAD_SECRET_77412","pad":""#,
        br#""}"#,
        b'x',
    )
    .unwrap()
    .chunk(0, 1_048_576);
    let backend = sink(body.clone(), 18);
    let clean = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let filters = "      - filter: json_body\n        conditions:\n          - when:\n              path_prefix: /bulk\n        max_body_bytes: 2097152\n        on_invalid: reject\n        request_extract:\n          - pointer: /model\n            metadata: model\n";
    let admin_port = free_port();
    let admin = format!("127.0.0.1:{admin_port}");
    let yaml = config(port, backend.port, clean.port(), filters, "")
        .replace("max_request_bytes: 67108864", "max_request_bytes: 2097152");
    let yaml = format!("{yaml}\nadmin:\n  metrics_address: \"{admin}\"\n");
    let mut process = PraxisProcess::spawn_with_ulimit(&yaml, &addr, Some("-S -v 2097152"));
    praxis_test_utils::wait_for_tcp(&admin);
    let mut invalid = body.clone();
    *invalid.last_mut().unwrap() = b'!';
    for _ in 0..2 {
        assert_eq!(send_body(&addr, &body), 200);
    }
    wait_active_requests(&admin, 0);
    let before = sample_process(process.pid()).unwrap();
    let mut rss = Vec::new();
    for batch in 0..4 {
        for _ in 0..4 {
            assert_eq!(send_body(&addr, &body), 200);
            let over = upload(&addr, 2_097_153);
            assert_eq!(status(over), 413);
            let mut malformed = upload(&addr, invalid.len());
            malformed.write_all(&invalid).unwrap();
            assert_eq!(status(malformed), 400);
            let mut abandoned = upload(&addr, body.len());
            abandoned.write_all(&body[..body.len() / 2]).unwrap();
            wait_active_requests(&admin, 1);
            drop(abandoned);
            wait_active_requests(&admin, 0);
        }
        probe(&addr);
        wait_active_requests(&admin, 0);
        let ceiling = before.open_fds.unwrap() + 12;
        assert!(
            process.wait_open_fds_at_most(ceiling, Duration::from_secs(5)) <= ceiling,
            "descriptors did not settle"
        );
        let sample = sample_process(process.pid()).expect("proxy survived hostile traffic");
        eprintln!(
            "failure batch={batch} rss={:?} anon={:?} fds={:?}",
            sample.rss_bytes, sample.anonymous_rss_bytes, sample.open_fds
        );
        rss.push(sample.rss_bytes.unwrap());
        assert!(
            sample.open_fds.unwrap() <= before.open_fds.unwrap() + 12,
            "open descriptors did not settle"
        );
    }
    assert!(
        rss.last().unwrap().saturating_sub(rss[0]) < 64 * 1_048_576,
        "steady RSS grew beyond runner budget: {rss:?}"
    );
    for _ in 0..18 {
        assert_eq!(backend.receipt.recv_timeout(WAIT).unwrap().unwrap(), body.len() as u64);
    }
    stop(&mut process);
    let mut cursor = ProcessLogCursor::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    loop {
        let chunk = process.logs_since(&mut cursor, 65_536).unwrap();
        if chunk.stdout.is_empty() && chunk.stderr.is_empty() {
            break;
        }
        stdout.extend(chunk.stdout);
        stderr.extend(chunk.stderr);
        assert!(stdout.len() + stderr.len() < 1_048_576, "log capture budget exhausted");
    }
    for logs in [&stdout, &stderr] {
        assert!(
            !logs
                .windows(b"CANARY_PAYLOAD_SECRET_77412".len())
                .any(|part| part == b"CANARY_PAYLOAD_SECRET_77412")
        );
        assert!(!logs.windows(32).any(|window| window.iter().all(|byte| *byte == b'x')));
    }
}

/// A backend that aborts after a complete upload must not poison later traffic.
/// A distinct early reply is observed without requiring the proxy to read or
/// reject bytes that the client never sent after the reply.
#[test]
fn complete_upload_reset_and_early_backend_reply_preserve_availability() {
    let _guard = serialized();
    for early in [false, true] {
        let body = PayloadSpec::binary(131_072, 49);
        let backend = aborting_upload_peer(body.clone(), early);
        let clean = start_echo_backend();
        let port = free_port();
        let addr = format!("127.0.0.1:{port}");
        let mut process = PraxisProcess::spawn(&config(port, backend.port, clean.port(), "", ""), &addr);
        let mut request = upload(&addr, body.len() as usize);
        let sent = if early { 8192 } else { body.len() as usize };
        request.write_all(&body.chunk(0, sent)).unwrap();
        let status = status(request);
        let receipt = backend.receipt.recv_timeout(WAIT).unwrap().unwrap();
        assert_eq!(status, if early { 200 } else { 502 }, "{receipt:?}");
        assert_eq!(receipt.request_line, "POST /bulk HTTP/1.1");
        assert_eq!(receipt.declared, body.len());
        assert_eq!(receipt.mismatch, None, "{receipt:?}");
        if early {
            assert!(
                sent < body.len() as usize,
                "client intentionally leaves the upload incomplete"
            );
            assert!(
                receipt.bytes <= sent as u64 && !receipt.complete && !matches!(receipt.terminal, UploadTerminal::Reset),
                "{receipt:?}"
            );
            assert!(
                matches!(receipt.terminal, UploadTerminal::EarlyReply),
                "backend must actually write its early reply"
            );
        } else {
            assert_eq!(receipt.bytes, body.len(), "the reset follows the full verified upload");
            assert!(
                receipt.complete
                    && matches!(receipt.terminal, UploadTerminal::Reset)
                    && !matches!(receipt.terminal, UploadTerminal::EarlyReply),
                "{receipt:?}"
            );
        }
        probe(&addr);
        stop(&mut process);
        drop(backend);
    }
}

/// Mutually exclusive terminal actions of the aborting upload peer.
#[derive(Debug)]
enum UploadTerminal {
    /// Request observation is still in progress.
    Pending,
    /// The peer wrote its early response.
    EarlyReply,
    /// The peer reset after consuming the complete request.
    Reset,
}

/// Independent upstream observation for the reset and early-reply cases.
#[derive(Debug)]
struct UploadPeerReceipt {
    /// Complete upstream request line.
    request_line: String,
    /// Declared fixed content length from the request head.
    declared: u64,
    /// Body bytes observed by this peer; early reply only counts prefetched bytes.
    bytes: u64,
    /// First body mismatch, if any.
    mismatch: Option<u64>,
    /// The complete declared body was consumed; mismatch is reported separately.
    complete: bool,
    /// The peer action after observing the request.
    terminal: UploadTerminal,
}

/// One-request peer that can interrupt accept or an active socket and join.
struct AbortingUploadPeer {
    /// Upstream listening port.
    port: u16,
    /// Parsed request and terminal action, or an explicit fixture I/O failure.
    receipt: mpsc::Receiver<std::io::Result<UploadPeerReceipt>>,
    /// Interrupt an outstanding accept.
    stopping: Arc<AtomicBool>,
    /// Interrupt active reads and writes on teardown.
    active: Arc<Mutex<Option<TcpStream>>>,
    /// The owned listener and request worker.
    worker: Option<JoinHandle<()>>,
}

impl Drop for AbortingUploadPeer {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Relaxed);
        if let Some(stream) = self.active.lock().unwrap().as_ref() {
            let _result = stream.shutdown(Shutdown::Both);
        }
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}

/// Accept one upstream request with cancellation armed before consuming it.
fn aborting_upload_peer(spec: PayloadSpec, early: bool) -> AbortingUploadPeer {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    listener.set_nonblocking(true).unwrap();
    let stopping = Arc::new(AtomicBool::new(false));
    let active = Arc::new(Mutex::new(None::<TcpStream>));
    let flag = Arc::clone(&stopping);
    let socket = Arc::clone(&active);
    let (tx, receipt) = mpsc::channel();
    let worker = thread::spawn(move || {
        while !flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let mut slot = socket.lock().unwrap();
                    if flag.load(Ordering::Relaxed) {
                        break;
                    }
                    *slot = Some(stream.try_clone().unwrap());
                    drop(slot);
                    let outcome = serve_aborting_upload(stream, &spec, early, &socket);
                    drop(socket.lock().unwrap().take());
                    let _sent = tx.send(outcome);
                    break;
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                Err(error) => panic!("upload peer accept: {error}"),
            }
        }
    });
    AbortingUploadPeer {
        port,
        receipt,
        stopping,
        active,
        worker: Some(worker),
    }
}

/// Verify the request, then either answer early or reset after the full upload.
fn serve_aborting_upload(
    stream: TcpStream,
    spec: &PayloadSpec,
    early: bool,
    active: &Mutex<Option<TcpStream>>,
) -> std::io::Result<UploadPeerReceipt> {
    stream.set_read_timeout(Some(WAIT))?;
    stream.set_write_timeout(Some(WAIT))?;
    let mut reader = BufReader::new(stream);
    let mut receipt = upload_peer_head(&mut reader)?;
    if early {
        // BufReader may have prefetched body bytes while reading the headers;
        // record only those actually observed, never assume the rest arrived.
        let prefix = reader.buffer();
        receipt.bytes = prefix.len() as u64;
        receipt.mismatch = spec.mismatch(0, prefix);
        reader
            .get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")?;
        reader.get_mut().flush()?;
        receipt.terminal = UploadTerminal::EarlyReply;
    } else {
        verify_upload_body(&mut reader, spec, &mut receipt)?;
        // The cancellation clone must close before SO_LINGER can produce RST.
        drop(active.lock().unwrap().take());
        reset_upload_socket(reader.into_inner())?;
        receipt.terminal = UploadTerminal::Reset;
    }
    Ok(receipt)
}

/// Read a bounded fixed-length HTTP request head without assuming framing.
fn upload_peer_head(reader: &mut BufReader<TcpStream>) -> std::io::Result<UploadPeerReceipt> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(std::io::Error::other("upstream request line missing"));
    }
    let request_line = line.trim_end_matches("\r\n").to_owned();
    let mut total = line.len();
    let mut declared = None;
    loop {
        line.clear();
        let count = reader.read_line(&mut line)?;
        total += count;
        if count == 0 || total > 65_536 {
            return Err(std::io::Error::other("incomplete or oversized upstream request head"));
        }
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                if declared.is_some() {
                    return Err(std::io::Error::other("duplicate content length"));
                }
                declared = Some(value.trim().parse::<u64>().map_err(std::io::Error::other)?);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err(std::io::Error::other("unexpected transfer encoding"));
            }
        }
    }
    Ok(UploadPeerReceipt {
        request_line,
        declared: declared.ok_or_else(|| std::io::Error::other("missing content length"))?,
        bytes: 0,
        mismatch: None,
        complete: false,
        terminal: UploadTerminal::Pending,
    })
}

/// Consume and compare the entire bounded body before allowing the reset.
fn verify_upload_body(
    reader: &mut BufReader<TcpStream>,
    spec: &PayloadSpec,
    receipt: &mut UploadPeerReceipt,
) -> std::io::Result<()> {
    if receipt.declared != spec.len() {
        return Err(std::io::Error::other("incorrect upstream declared length"));
    }
    let mut chunk = [0_u8; 8192];
    while receipt.bytes < receipt.declared {
        let remaining = usize::try_from(receipt.declared - receipt.bytes)
            .unwrap()
            .min(chunk.len());
        let count = reader.read(&mut chunk[..remaining])?;
        if count == 0 {
            return Err(std::io::Error::other("upstream body ended before declared length"));
        }
        if receipt.mismatch.is_none() {
            receipt.mismatch = spec.mismatch(receipt.bytes, &chunk[..count]);
        }
        receipt.bytes += count as u64;
    }
    receipt.complete = true;
    Ok(())
}

/// Drop the last socket handle with zero linger to send an actual TCP RST.
fn reset_upload_socket(stream: TcpStream) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_io().build()?;
    let _entered = runtime.enter();
    stream.set_nonblocking(true)?;
    let socket = tokio::net::TcpStream::from_std(stream)?;
    socket.set_zero_linger()?;
    drop(socket);
    Ok(())
}

/// A reusable slow response peer. Dropping it interrupts both accept and an
/// active socket so a failed assertion cannot strand a test worker.
struct SlowPeer {
    /// Port exposed to the proxy.
    port: u16,
    /// Per-response socket byte and error observations.
    receipts: mpsc::Receiver<(u64, std::io::ErrorKind)>,
    /// Request termination of the accept loop.
    stopping: Arc<AtomicBool>,
    /// Socket clone for interrupting an active response.
    active: Arc<Mutex<Option<TcpStream>>>,
    /// Owned accept and response thread.
    worker: Option<JoinHandle<()>>,
}

impl Drop for SlowPeer {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Relaxed);
        if let Some(stream) = self.active.lock().unwrap().as_ref() {
            let _result = stream.shutdown(Shutdown::Both);
        }
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}

/// Start a response peer whose worker can be interrupted and joined.
fn slow_peer() -> SlowPeer {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    listener.set_nonblocking(true).unwrap();
    let stopping = Arc::new(AtomicBool::new(false));
    let active = Arc::new(Mutex::new(None::<TcpStream>));
    let flag = Arc::clone(&stopping);
    let socket = Arc::clone(&active);
    let (tx, receipts) = mpsc::channel();
    let worker = thread::spawn(move || {
        while !flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let mut slot = socket.lock().unwrap();
                    if flag.load(Ordering::Relaxed) {
                        break;
                    }
                    *slot = Some(stream.try_clone().unwrap());
                    drop(slot);
                    let outcome = slow_response(stream);
                    drop(socket.lock().unwrap().take());
                    let _sent = tx.send(outcome);
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                Err(error) => panic!("slow peer accept: {error}"),
            }
        }
    });
    SlowPeer {
        port,
        receipts,
        stopping,
        active,
        worker: Some(worker),
    }
}

/// Report content bytes accepted by the socket and the terminal write error.
fn slow_response(stream: TcpStream) -> (u64, std::io::ErrorKind) {
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0, "request headers must complete");
        if line == "\r\n" {
            break;
        }
    }
    let stream = reader.get_mut();
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16777216\r\nConnection: close\r\n\r\n")
        .unwrap();
    let chunk = vec![b'x'; 16_384];
    let mut bytes = 0;
    loop {
        match stream.write(&chunk) {
            Ok(0) => return (bytes, std::io::ErrorKind::WriteZero),
            Ok(count) => bytes += count as u64,
            Err(error) => return (bytes, error.kind()),
        }
        // Keep the peer alive long enough for downstream cancellation to reach it.
        thread::sleep(Duration::from_millis(2));
        assert!(bytes < 16_777_216, "cancelled client did not stop the response");
    }
}

#[test]
fn repeated_slow_response_cancellations_leave_process_available() {
    let _guard = serialized();
    let slow = slow_peer();
    let clean = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let admin = format!("127.0.0.1:{}", free_port());
    let yaml = format!(
        "{}\nadmin:\n  metrics_address: \"{admin}\"\n",
        config(port, slow.port, clean.port(), "", "")
    );
    let mut process = PraxisProcess::spawn_with_ulimit(&yaml, &addr, Some("-S -v 2097152"));
    praxis_test_utils::wait_for_tcp(&admin);
    let before = sample_process(process.pid()).unwrap();
    for iteration in 0..8 {
        let mut client = TcpStream::connect(&addr).unwrap();
        client.set_read_timeout(Some(WAIT)).unwrap();
        client
            .write_all(b"GET /bulk HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.starts_with("HTTP/1.1 200"), "{line:?}");
        loop {
            line.clear();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0, "request headers must complete");
            if line == "\r\n" {
                break;
            }
        }
        let mut prefix = [0; 1024];
        reader.read_exact(&mut prefix).unwrap();
        assert!(prefix.iter().all(|byte| *byte == b'x'));
        wait_active_requests(&admin, 1);
        drop(reader);
        let (written, reason) = slow.receipts.recv_timeout(WAIT).unwrap();
        assert!(
            written < 16_777_216
                && matches!(
                    reason,
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ),
            "iteration={iteration} bytes={written} error={reason:?}"
        );
        probe(&addr);
        wait_active_requests(&admin, 0);
    }
    let ceiling = before.open_fds.unwrap() + 12;
    assert!(
        process.wait_open_fds_at_most(ceiling, Duration::from_secs(5)) <= ceiling,
        "descriptors did not settle"
    );
    let after = sample_process(process.pid()).expect("proxy survived repeated slow peers");
    eprintln!("slow response batches: before={before:?} after={after:?}");
    assert!(after.open_fds.unwrap() <= before.open_fds.unwrap() + 12);
    assert!(after.rss_bytes.unwrap().saturating_sub(before.rss_bytes.unwrap()) < 64 * 1_048_576);
    stop(&mut process);
}

/// Test-only filter that switches from stream buffering to pass-through in a
/// normal body callback. It is registered only in the dedicated child below.
struct ReleaseOnChunk;

#[async_trait::async_trait]
impl praxis_filter::HttpFilter for ReleaseOnChunk {
    fn name(&self) -> &'static str {
        "w7_release"
    }

    fn request_body_access(&self) -> praxis_filter::BodyAccess {
        praxis_filter::BodyAccess::ReadOnly
    }

    async fn on_request(
        &self,
        ctx: &mut praxis_filter::HttpFilterContext<'_>,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        ctx.set_request_body_mode(praxis_filter::BodyMode::StreamBuffer { max_bytes: Some(4096) });
        Ok(praxis_filter::FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        _context: &mut praxis_filter::HttpFilterContext<'_>,
        _body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        Ok(praxis_filter::FilterAction::Release)
    }
}

/// Internal test-binary entry point. The parent supplies its complete config;
/// the production registry is extended only in this isolated child process.
#[test]
#[ignore = "internal subprocess entry, invoked only by release lifecycle test"]
fn release_child_server() {
    let yaml = std::env::var("PRAXIS_W7_RELEASE_CONFIG").expect("parent must provide child config");
    let config = praxis_core::config::Config::from_yaml(&yaml).unwrap();
    let registry = praxis_test_utils::registry_with("w7_release", || Box::new(ReleaseOnChunk));
    praxis::run_server_with_registry(config, registry, None, None);
}

/// Reap the test-server process on all paths, including assertion failures.
struct ReleaseChild(Option<std::process::Child>);

impl ReleaseChild {
    /// Start the exact ignored child entry with an isolated custom registry.
    fn spawn(yaml: &str) -> Self {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "payload_lifecycle::release_child_server",
                "--ignored",
                "--nocapture",
            ])
            .env("PRAXIS_W7_RELEASE_CONFIG", yaml)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        Self(Some(child))
    }

    /// Start the separately registered reload fixture with a watched file.
    fn spawn_reload(config: &std::path::Path, events: &std::path::Path) -> Self {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "payload_lifecycle::generation_child_server",
                "--ignored",
                "--nocapture",
            ])
            .env("PRAXIS_W7_GENERATION_CONFIG", config)
            .env("PRAXIS_W7_GENERATION_EVENTS", events)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        Self(Some(child))
    }

    /// Signal graceful shutdown and bound the wait for the process to exit.
    fn shutdown(&mut self) {
        let child = self.0.as_mut().unwrap();
        let result = std::process::Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap();
        assert!(result.success(), "SIGTERM must reach the child server");
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "release child exited with {status}");
                drop(self.0.take());
                return;
            }
            assert!(
                Instant::now() < deadline,
                "release child failed to exit within shutdown budget"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for ReleaseChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _result = child.kill();
            let _result = child.wait();
        }
    }
}

/// Append a short lifecycle event from the isolated server process.
fn generation_event(path: &std::path::Path, event: &str, generation: &str, id: usize) {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    file.write_all(format!("{event} {generation} {id}\n").as_bytes())
        .unwrap();
}

/// A reference to an actual incoming chunk, kept in request-scoped filter state.
struct GenerationBodyOwner {
    /// This clone retains the received chunk's allocation until request teardown.
    _body: bytes::Bytes,
    /// Event destination shared with the parent process.
    events: std::path::PathBuf,
    /// Owning filter generation.
    generation: String,
    /// Unique filter instance identifier.
    id: usize,
    /// Sum of non-EOS body bytes received by this request's hook.
    observed: usize,
    /// Whether the optional prefix acknowledgment has been emitted.
    acknowledged: bool,
}

impl Drop for GenerationBodyOwner {
    fn drop(&mut self) {
        generation_event(&self.events, "body-drop", &self.generation, self.id);
    }
}

/// A generation-tagged response hook with separately observed filter ownership.
struct GenerationFilter {
    /// Event destination shared with the parent process.
    events: std::path::PathBuf,
    /// Configuration generation installed by the file watcher.
    generation: String,
    /// Unique instance identifier, including discarded validation instances.
    id: usize,
    /// Optional minimum non-EOS bytes required before acknowledging progress.
    ack_bytes: Option<usize>,
}

impl Drop for GenerationFilter {
    fn drop(&mut self) {
        generation_event(&self.events, "filter-drop", &self.generation, self.id);
    }
}

#[async_trait::async_trait]
impl praxis_filter::HttpFilter for GenerationFilter {
    fn name(&self) -> &'static str {
        "w7_generation"
    }

    async fn on_request(
        &self,
        _ctx: &mut praxis_filter::HttpFilterContext<'_>,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        Ok(praxis_filter::FilterAction::Continue)
    }

    fn request_body_access(&self) -> praxis_filter::BodyAccess {
        praxis_filter::BodyAccess::ReadOnly
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
        end_of_stream: bool,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        if !end_of_stream && let Some(chunk) = body.as_ref().filter(|chunk| !chunk.is_empty()) {
            if ctx.get_filter_state::<GenerationBodyOwner>().is_none() {
                ctx.insert_filter_state(GenerationBodyOwner {
                    _body: chunk.clone(),
                    events: self.events.clone(),
                    generation: self.generation.clone(),
                    id: self.id,
                    observed: 0,
                    acknowledged: false,
                });
                generation_event(&self.events, "body-held", &self.generation, self.id);
            }
            let owner = ctx.get_filter_state_mut::<GenerationBodyOwner>().unwrap();
            owner.observed += chunk.len();
            if !owner.acknowledged && self.ack_bytes.is_some_and(|minimum| owner.observed >= minimum) {
                owner.acknowledged = true;
                generation_event(&self.events, "prefix-held", &self.generation, self.id);
            }
        }
        Ok(praxis_filter::FilterAction::Continue)
    }

    async fn on_response(
        &self,
        ctx: &mut praxis_filter::HttpFilterContext<'_>,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        if let Some(response) = ctx.response_header.as_mut() {
            response
                .headers
                .insert("x-w7-generation", self.generation.parse().unwrap());
            ctx.response_headers_modified = true;
        }
        Ok(praxis_filter::FilterAction::Continue)
    }
}

/// Run the actual watcher in an isolated process with a test-only registry.
#[test]
#[ignore = "internal subprocess entry, invoked only by reload ownership test"]
fn generation_child_server() {
    let path = std::path::PathBuf::from(std::env::var_os("PRAXIS_W7_GENERATION_CONFIG").unwrap());
    let events = std::path::PathBuf::from(std::env::var_os("PRAXIS_W7_GENERATION_EVENTS").unwrap());
    let config = praxis_core::config::Config::from_yaml(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let next = AtomicUsize::new(0);
    let mut registry = praxis_filter::FilterRegistry::with_builtins();
    registry
        .register(
            "w7_generation",
            praxis_filter::FilterFactory::Http(Arc::new(move |value| {
                let generation = value
                    .get("generation")
                    .and_then(serde_yaml::Value::as_str)
                    .unwrap()
                    .to_owned();
                Ok(Box::new(GenerationFilter {
                    events: events.clone(),
                    generation,
                    id: next.fetch_add(1, Ordering::Relaxed),
                    ack_bytes: value
                        .get("ack_bytes")
                        .map(|value| usize::try_from(value.as_u64().unwrap()).unwrap()),
                }))
            })),
        )
        .unwrap();
    praxis::run_server_with_registry(config, registry, Some(path), None);
}

/// Delete the watched config and event log after the child is reaped.
struct GenerationFiles(std::path::PathBuf);

impl Drop for GenerationFiles {
    fn drop(&mut self) {
        let _result = std::fs::remove_dir_all(&self.0);
    }
}

/// Poll a bounded event log for a particular event, allowing asynchronous teardown.
fn wait_generation_event(path: &std::path::Path, prefix: &str) -> String {
    let deadline = Instant::now() + WAIT;
    loop {
        let events = std::fs::read_to_string(path).unwrap_or_default();
        if let Some(line) = events
            .lines()
            .find(|line| *line == prefix || (prefix.ends_with(' ') && line.starts_with(prefix)))
        {
            return line.to_owned();
        }
        assert!(Instant::now() < deadline, "missing event {prefix:?}: {events}");
        thread::sleep(Duration::from_millis(20));
    }
}

/// Read a completed response and its generation-tagged response hook.
fn generation_response(stream: TcpStream) -> (u16, Option<String>) {
    let response = read_h1_response(&mut BufReader::new(stream), false, 8192, |_| Ok(()));
    assert!(
        response.completion.is_some() && response.abort.is_none(),
        "{response:?}"
    );
    let generation = response
        .headers
        .iter()
        .find(|(name, _)| name == "x-w7-generation")
        .map(|(_, value)| value.clone());
    (response.status.unwrap(), generation)
}

/// The watcher swaps new response hooks while a pre-read request pins the old
/// filter and a real body-chunk owner until the old request drains.
#[test]
fn reload_drains_old_response_hook_and_body_owner() {
    let _guard = serialized();
    let body = PayloadSpec::binary(1_048_576, 73);
    let old_backend = start_counting_backend(body.clone(), "old", body.len());
    let new_backend = start_echo_backend();
    let old_probe = start_backend_with_shutdown("old");
    let new_probe = start_backend_with_shutdown("new");
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let old_filter = "      - filter: w7_generation\n        generation: old\n";
    let new_filter = "      - filter: w7_generation\n        generation: new\n";
    let old_yaml = config(port, old_backend.port, old_probe.port(), old_filter, "");
    let new_yaml = config(port, new_backend.port(), new_probe.port(), new_filter, "");
    let dir = std::env::temp_dir().join(format!("praxis-w7-reload-{}-{port}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let files = GenerationFiles(dir);
    let config_path = files.0.join("config.yaml");
    let events = files.0.join("events");
    std::fs::write(&config_path, old_yaml).unwrap();
    let mut child = ReleaseChild::spawn_reload(&config_path, &events);
    praxis_test_utils::wait_for_tcp(&addr);
    assert_eq!(http_get(&addr, "/probe", None), (200, "old".to_owned()));

    let mut old = upload(&addr, body.len() as usize);
    old.write_all(&body.chunk(0, body.len() as usize - 1)).unwrap();
    let held = wait_generation_event(&events, "body-held old ");
    let id: usize = held.split_whitespace().last().unwrap().parse().unwrap();
    assert_eq!(old_backend.accepted.try_recv(), Err(mpsc::TryRecvError::Empty));
    std::fs::write(&config_path, new_yaml).unwrap();
    let deadline = Instant::now() + WAIT;
    loop {
        if http_get(&addr, "/probe", None) == (200, "new".to_owned()) {
            break;
        }
        assert!(Instant::now() < deadline, "new generation did not load");
        thread::sleep(Duration::from_millis(50));
    }
    let snapshot = std::fs::read_to_string(&events).unwrap();
    assert!(
        !snapshot
            .lines()
            .any(|line| line == format!("body-drop old {id}") || line == format!("filter-drop old {id}")),
        "old request lost its owners while held: {snapshot}"
    );
    let mut new = TcpStream::connect(&addr).unwrap();
    new.set_read_timeout(Some(WAIT)).unwrap();
    new.write_all(b"GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    assert_eq!(generation_response(new), (200, Some("new".to_owned())));

    old.write_all(&body.chunk(body.len() - 1, 1)).unwrap();
    assert_eq!(generation_response(old), (200, Some("old".to_owned())));
    let receipt = old_backend.receipt.recv_timeout(WAIT).unwrap();
    assert_eq!(
        (receipt.bytes, receipt.mismatch, receipt.completion.is_some()),
        (body.len(), None, true)
    );
    wait_generation_event(&events, &format!("body-drop old {id}"));
    wait_generation_event(&events, &format!("filter-drop old {id}"));
    child.shutdown();
    old_backend.join();
}

/// Once a normal body callback has released its buffer, an idle upload must
/// time out and shutdown must cancel an incomplete upstream exchange.
#[test]
fn released_upload_times_out_or_cancels_during_shutdown() {
    let _guard = serialized();
    for shutdown in [false, true] {
        let spec = PayloadSpec::binary(1_048_576, 27);
        let backend = start_counting_backend(spec.clone(), "released", spec.len());
        let clean = start_echo_backend();
        let port = free_port();
        let addr = format!("127.0.0.1:{port}");
        let listener = if shutdown {
            ""
        } else {
            "    downstream_read_timeout_ms: 500\n"
        };
        let yaml = config(
            port,
            backend.port,
            clean.port(),
            "      - filter: w7_release\n",
            listener,
        );
        let mut child = ReleaseChild::spawn(&yaml);
        praxis_test_utils::wait_for_tcp(&addr);
        let mut client = upload(&addr, spec.len() as usize);
        client.write_all(&spec.chunk(0, 2048)).unwrap();
        // A dynamically enabled buffer with this filter cannot forward its
        // first byte until the callback has returned Release.
        backend.first_byte.recv_timeout(WAIT).unwrap();
        probe(&addr);
        if shutdown {
            child.shutdown();
            let response = read_h1_response(&mut BufReader::new(client), false, 8192, |_| Ok(()));
            assert!(
                response.status != Some(200) || response.completion.is_none(),
                "{response:?}"
            );
        } else {
            assert_eq!(status(client), 400);
            probe(&addr);
        }
        let receipt = backend.receipt.recv_timeout(WAIT).unwrap();
        assert!(receipt.bytes > 0 && receipt.bytes < spec.len(), "{receipt:?}");
        assert_eq!(receipt.mismatch, None);
        assert!(receipt.completion.is_none() && receipt.abort.is_some(), "{receipt:?}");
        if !shutdown {
            child.shutdown();
        }
        backend.join();
    }
}

/// Observe the request-context lifetime gauge, not an inferred Tokio task count.
fn wait_active_requests(admin: &str, expected: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut socket = TcpStream::connect(admin).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        socket
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut text = Vec::new();
        let response = read_h1_response(&mut BufReader::new(socket), false, 262_144, |chunk| {
            text.extend_from_slice(chunk);
            Ok(())
        });
        assert_eq!(response.status, Some(200), "{response:?}");
        assert!(
            response.completion.is_some() && response.abort.is_none(),
            "{response:?}"
        );
        let text = std::str::from_utf8(&text).unwrap();
        let value = text.lines().find_map(|line| {
            line.strip_prefix("praxis_http_active_requests{listener=\"default\"} ")
                .map(|value| value.parse::<u64>().unwrap())
        });
        if value == Some(expected) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "active requests must settle at {expected}, got {value:?}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}
