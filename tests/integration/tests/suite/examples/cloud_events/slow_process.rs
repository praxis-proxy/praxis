// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Isolated CloudEvents backpressure and payload-retention observations.

use std::{
    collections::{HashMap, HashSet},
    io::{BufReader, Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use praxis_test_utils::{
    H1Completion, PayloadSpec, PraxisProcess, ProcessLogCursor, ProcessSample, free_port, read_h1_response,
    sample_process, start_backend_with_shutdown,
};

/// Bytes in each streamed response, equal to the default response limit.
const RESPONSE_BYTES: usize = 10_485_760;
/// Request buffer ceiling used for malformed and oversized inputs.
const REQUEST_LIMIT: usize = 1_048_576;
/// The documented process-wide CloudEvents delivery permit count.
const DELIVERY_LIMIT: usize = 64;
/// Synthetic content that must not appear in telemetry.
const CANARY: &[u8] = b"W6_CLOUD_BODY_CANARY_49d1";
/// Socket and fixture deadlines, separate from the proxy's policy.
const WAIT: Duration = Duration::from_secs(15);
/// Each resource needs its own `ulimit` invocation for shells such as dash.
const PROCESS_LIMITS: &str = "-v 4194304 && ulimit -t 120 && ulimit -f 2048 && export RUST_LOG=info";

#[test]
#[cfg_attr(coverage, ignore = "spawns an isolated praxis process")]
fn slow_cloud_events_survive_large_cycles_failures_and_recover() {
    let receiver = SlowEvents::start();
    let mut bulk = LargeBackend::start();
    let probe = start_backend_with_shutdown("probe-ok");
    let port = free_port();
    let admin_port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let admin = format!("127.0.0.1:{admin_port}");
    let yaml = process_config(port, admin_port, bulk.port, probe.port(), receiver.port);
    let mut process = PraxisProcess::spawn_with_ulimit(&yaml, &addr, Some(PROCESS_LIMITS));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        exercise(&process, &mut bulk, &receiver, &addr, &admin)
    }));
    let (mut logs, expected) = match outcome {
        Ok(result) => result,
        Err(failure) => {
            let (status, forced) = process.wait_or_kill(Duration::from_secs(1));
            eprintln!("proxy exit after failed workload: {status}; runner_forced={forced}");
            std::panic::resume_unwind(failure);
        },
    };
    if let Some(status) = process.wait_for_exit(Duration::from_millis(1)) {
        panic!("proxy exited before shutdown, possibly due to a runner resource limit: {status}");
    }
    process.signal("TERM");
    let (status, forced) = process.wait_or_kill(Duration::from_secs(10));
    assert!(
        !forced && status.success(),
        "proxy must not be killed or hang: {status}"
    );
    logs.drain(&process);
    logs.assert_private();
    logs.assert_records(&expected);
}

#[test]
#[ignore = "scheduled: isolated large CloudEvents streaming RSS profile"]
fn scheduled_cloud_events_streaming_rss_plateau_through_one_gib() {
    let mut growth = Vec::new();
    let mut steady_growths = Vec::new();
    for length in [10_485_760_usize, 67_108_864, 268_435_456, 1_073_741_824] {
        let (baseline, peak, steady) = profile_cloud_events_response(length);
        let increase = peak.saturating_sub(baseline);
        let steady_increase = steady.saturating_sub(baseline);
        eprintln!(
            "CloudEvents response bytes={length} baseline_rss={baseline} peak_rss={peak} steady_rss={steady} peak_growth={increase} steady_growth={steady_increase}"
        );
        assert!(
            increase <= 134_217_728,
            "sampled RSS exceeded the 128 MiB runner envelope at {length} bytes"
        );
        assert!(
            steady_increase <= 67_108_864,
            "post-transfer RSS exceeded the 64 MiB runner envelope at {length} bytes"
        );
        growth.push(increase);
        steady_growths.push(steady_increase);
    }
    assert!(
        growth
            .iter()
            .all(|increase| *increase <= growth[0].saturating_add(67_108_864)),
        "peak RSS growth must remain within 64 MiB across response sizes: {growth:?}"
    );
    assert!(
        steady_growths
            .iter()
            .all(|increase| *increase <= steady_growths[0].saturating_add(33_554_432)),
        "post-transfer RSS growth must remain within 32 MiB across response sizes: {steady_growths:?}"
    );
}

/// Profile a single response in a fresh child with bounded receiver and logs.
fn profile_cloud_events_response(length: usize) -> (u64, u64, u64) {
    let receiver = SlowEvents::start();
    receiver.release.store(true, Ordering::SeqCst);
    let mut bulk = LargeBackend::with_length(length);
    let probe = start_backend_with_shutdown("probe-ok");
    let port = free_port();
    let admin_port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let admin = format!("127.0.0.1:{admin_port}");
    let original = process_config(port, admin_port, bulk.port, probe.port(), receiver.port);
    let finite = format!("  max_response_bytes: {RESPONSE_BYTES}\n");
    let json_filter = "      - filter: json_body\n        content_types: [application/json]\n        request_remove: [/unused]\n        max_body_bytes: 1048576\n        on_invalid: reject\n";
    assert!(
        original.contains(&finite),
        "profile must replace the finite response limit"
    );
    assert!(
        original.contains(json_filter),
        "profile must remove the request JSON filter"
    );
    // Keep the stepped sizes explicit in policy as well as in the generator.
    let yaml = original
        .replacen(
            "body_limits:\n",
            &format!("body_limits:\n  max_buffer_bytes: {}\n", length.max(67_108_864)),
            1,
        )
        .replace(&finite, "  max_response_bytes: null\n")
        .replace(json_filter, "")
        .replace(
            "  allow_private_endpoints: true\n",
            "  allow_private_endpoints: true\n  allow_unbounded_body: true\n",
        );
    let mut process = PraxisProcess::spawn_with_ulimit(&yaml, &addr, Some(PROCESS_LIMITS));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        profile_workload(&process, &mut bulk, &receiver, (&addr, &admin), length)
    }));
    let (baseline, peak, steady, mut logs, expected) = match outcome {
        Ok(result) => result,
        Err(failure) => {
            let (status, forced) = process.wait_or_kill(Duration::from_secs(1));
            eprintln!("profile child exit after failure: {status}; runner_forced={forced}");
            std::panic::resume_unwind(failure);
        },
    };
    if let Some(status) = process.wait_for_exit(Duration::from_millis(1)) {
        panic!("profile child exited before shutdown, possibly due to runner limits: {status}");
    }
    process.signal("TERM");
    let (status, forced) = process.wait_or_kill(Duration::from_secs(10));
    assert!(
        !forced && status.success(),
        "profile child did not exit cleanly: {status}"
    );
    logs.drain(&process);
    logs.assert_private();
    logs.assert_records(&expected);
    (baseline, peak, steady)
}

/// Exercise a paused large transfer while measuring the child only.
fn profile_workload(
    process: &PraxisProcess,
    bulk: &mut LargeBackend,
    receiver: &SlowEvents,
    addresses: (&str, &str),
    length: usize,
) -> (u64, u64, u64, BoundedLogs, HashMap<String, u16>) {
    let (addr, admin) = addresses;
    praxis_test_utils::wait_for_tcp(admin);
    let expected = HashMap::from([
        ("profile-warmup".to_owned(), 200),
        ("profile-large".to_owned(), 200),
        ("profile-during".to_owned(), 200),
        ("profile-after".to_owned(), 200),
    ]);
    probe_request(addr, "profile-warmup");
    wait_for(
        Duration::from_secs(15),
        || {
            receiver
                .events()
                .iter()
                .any(|event| event.request_id == "profile-warmup")
                && metric(
                    &scrape(admin),
                    "praxis_cloud_events_publish_total",
                    Some("outcome=\"success\""),
                ) == 1
        },
        "warmup event",
    );
    let baseline = sample_process(process.pid()).unwrap();
    let sampler = ResponseSampler::start(process.pid());
    let (delivered, delivered_rx) = mpsc::channel();
    let client_addr = addr.to_owned();
    let client = thread::spawn(move || large_request_sized(&client_addr, "profile-large", length, Some(delivered)));
    bulk.prefix.recv_timeout(WAIT).unwrap();
    delivered_rx
        .recv_timeout(WAIT)
        .expect("large response prefix must reach the client");
    probe_request(addr, "profile-during");
    assert!(
        receiver
            .events()
            .iter()
            .all(|event| event.request_id != "profile-large"),
        "a response-complete event must not precede the large response"
    );
    bulk.resume.take().unwrap().send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(240);
    while !client.is_finished() {
        assert!(Instant::now() < deadline, "large transfer exceeded the runner deadline");
        thread::sleep(Duration::from_millis(20));
    }
    client.join().unwrap();
    assert_eq!(
        bulk.completed.recv_timeout(WAIT).unwrap(),
        length,
        "source must finish the entire response"
    );
    assert_eq!(
        bulk.accepted.load(Ordering::SeqCst),
        1,
        "source must receive exactly one request"
    );
    probe_request(addr, "profile-after");
    wait_for(
        Duration::from_secs(15),
        || {
            let metrics = scrape(admin);
            receiver.events().len() == 4
                && metric(&metrics, "praxis_cloud_events_attempts_total", None) == 4
                && metric(
                    &metrics,
                    "praxis_cloud_events_publish_total",
                    Some("outcome=\"success\""),
                ) == 4
        },
        "four complete best-effort events",
    );
    verify_events(&receiver.events(), &expected);
    let samples = sampler.finish();
    let peak = samples
        .iter()
        .map(|sample| sample.peak_rss_bytes.unwrap())
        .max()
        .unwrap();
    thread::sleep(Duration::from_millis(100));
    let steady = sample_process(process.pid()).unwrap();
    let mut logs = BoundedLogs::default();
    wait_for(
        Duration::from_secs(10),
        || {
            logs.drain(process);
            logs.has_records(&expected)
        },
        "one access record per profile request",
    );
    logs.assert_records(&expected);
    logs.assert_private();
    assert!(
        receiver.events().iter().all(|event| event.body_bytes <= 1_024),
        "every event must respect the configured size limit"
    );
    eprintln!(
        "CloudEvents profile bytes={length} samples={} peak_fds={:?} steady_fds={:?}",
        samples.len(),
        samples.iter().filter_map(|sample| sample.open_fds).max(),
        steady.open_fds
    );
    (
        baseline.rss_bytes.unwrap(),
        peak,
        steady.rss_bytes.unwrap(),
        logs,
        expected,
    )
}

/// A bounded sampler reads only the child process's procfs statistics.
struct ResponseSampler {
    /// Stops periodic samples.
    stop: Arc<AtomicBool>,
    /// Sampling thread and its bounded observations.
    worker: Option<JoinHandle<Vec<ProcessSample>>>,
}

impl ResponseSampler {
    /// Begin sampling until stopped or the runner's sample bound is reached.
    fn start(pid: u32) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut samples = Vec::new();
            while !flag.load(Ordering::SeqCst) {
                assert!(samples.len() < 20_000, "response sampler exceeded its bound");
                samples.push(sample_process(pid).expect("sample live proxy during response"));
                thread::sleep(Duration::from_millis(25));
            }
            samples.push(sample_process(pid).expect("sample live proxy after response"));
            samples
        });
        Self {
            stop,
            worker: Some(worker),
        }
    }

    /// Stop and join the sampler, retaining its observations.
    fn finish(mut self) -> Vec<ProcessSample> {
        self.stop.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap()
    }
}

impl Drop for ResponseSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}

/// Run the bounded workload while the measured child remains alive.
fn exercise(
    process: &PraxisProcess,
    bulk: &mut LargeBackend,
    receiver: &SlowEvents,
    addr: &str,
    admin: &str,
) -> (BoundedLogs, HashMap<String, u16>) {
    praxis_test_utils::wait_for_tcp(admin);
    let started = Instant::now();
    let deadline = started + Duration::from_secs(45);
    let baseline = sample_process(process.pid()).unwrap();
    let mut samples = vec![baseline.clone()];
    let mut logs = BoundedLogs::default();
    let mut expected = HashMap::new();

    expected.insert("warmup".to_owned(), 200);
    probe_request(addr, "warmup");
    wait_for(
        Duration::from_secs(10),
        || receiver.held.load(Ordering::SeqCst) == 1,
        "warmup event",
    );
    assert_eq!(
        receiver.held.load(Ordering::SeqCst),
        1,
        "the receiver is actively stalled"
    );

    expected.insert("large-0".to_owned(), 200);
    expected.insert("during".to_owned(), 200);
    let (delivered, delivered_rx) = mpsc::channel();
    thread::scope(|scope| {
        let response = scope.spawn(|| large_request(addr, "large-0", Some(delivered)));
        bulk.prefix.recv_timeout(WAIT).unwrap();
        delivered_rx
            .recv_timeout(WAIT)
            .expect("client must receive the prefix before the producer resumes");
        probe_request(addr, "during");
        assert!(
            receiver.events().iter().all(|event| event.request_id != "large-0"),
            "response-complete event must wait for the paused response"
        );
        bulk.resume.take().unwrap().send(()).unwrap();
        response.join().unwrap();
    });
    for batch in 0..4 {
        if batch > 0 {
            let id = format!("large-{batch}");
            expected.insert(id.clone(), 200);
            large_request(addr, &id, None);
        }
        let invalid = format!("invalid-{batch}");
        expected.insert(invalid.clone(), 400);
        malformed_request(addr, &invalid);
        let over = format!("oversized-{batch}");
        expected.insert(over.clone(), 413);
        oversized_request(addr, &over);
        let probe_id = format!("batch-{batch}");
        expected.insert(probe_id.clone(), 200);
        probe_request(addr, &probe_id);
        samples.push(sample_process(process.pid()).unwrap());
        logs.drain(process);
        assert!(Instant::now() < deadline, "workload exceeded its test deadline");
    }
    assert_eq!(
        bulk.accepted.load(Ordering::SeqCst),
        4,
        "rejected uploads must not reach the bulk backend"
    );

    for index in 0..80 {
        let id = format!("burst-{index}");
        expected.insert(id.clone(), 200);
        probe_request(addr, &id);
        if index % 10 == 0 {
            logs.drain(process);
            samples.push(sample_process(process.pid()).unwrap());
        }
        assert!(Instant::now() < deadline, "burst exceeded its test deadline");
    }
    wait_for(
        Duration::from_secs(10),
        || {
            let metrics = scrape(admin);
            metric(&metrics, "praxis_cloud_events_attempts_total", None) == 64
                && metric(
                    &metrics,
                    "praxis_cloud_events_skipped_total",
                    Some("reason=\"backpressure\""),
                ) >= 26
                && receiver.held.load(Ordering::SeqCst) == DELIVERY_LIMIT
        },
        "64 held deliveries and at least 26 best-effort drops",
    );
    assert!(
        Instant::now() < deadline,
        "delivery saturation exceeded its test deadline"
    );
    verify_events(&receiver.events(), &expected);
    samples.push(sample_process(process.pid()).unwrap());

    receiver.release.store(true, Ordering::SeqCst);
    wait_for(
        Duration::from_secs(10),
        || {
            let metrics = scrape(admin);
            metric(
                &metrics,
                "praxis_cloud_events_publish_total",
                Some("outcome=\"success\""),
            ) == 32
                && metric(
                    &metrics,
                    "praxis_cloud_events_publish_total",
                    Some("failure_class=\"http_status\""),
                ) == 32
        },
        "all held 204/503 responses accounted for",
    );
    expected.insert("recovery".to_owned(), 200);
    probe_request(addr, "recovery");
    wait_for(
        Duration::from_secs(10),
        || receiver.events().iter().any(|event| event.request_id == "recovery"),
        "recovery event",
    );
    wait_for(
        Duration::from_secs(10),
        || {
            let metrics = scrape(admin);
            metric(
                &metrics,
                "praxis_cloud_events_publish_total",
                Some("outcome=\"success\""),
            ) == 33
        },
        "recovery publication",
    );
    wait_for(
        Duration::from_secs(10),
        || sample_process(process.pid()).unwrap().open_fds.unwrap() <= baseline.open_fds.unwrap() + 16,
        "delivery descriptors released",
    );
    samples.push(sample_process(process.pid()).unwrap());
    verify_events(&receiver.events(), &expected);
    assert_eq!(
        receiver.events().len(),
        65,
        "64 held deliveries and the one recovered delivery"
    );
    assert_eq!(
        receiver.held.load(Ordering::SeqCst),
        0,
        "receiver must release every held delivery"
    );
    wait_for(
        Duration::from_secs(10),
        || {
            logs.drain(process);
            logs.has_records(&expected)
        },
        "one access record for every request",
    );
    logs.assert_records(&expected);
    logs.assert_private();
    assert_resource_samples(&samples);
    let log_bytes = logs.stdout.len() + logs.stderr.len();
    let elapsed = started.elapsed();
    eprintln!(
        "slow CloudEvents: {} requests, {} event bytes, {log_bytes} log bytes, elapsed {elapsed:?}, {:.0} log bytes/s",
        expected.len(),
        receiver.events().iter().map(|event| event.body_bytes).sum::<usize>(),
        log_bytes as f64 / elapsed.as_secs_f64().max(0.001)
    );
    (logs, expected)
}

/// Configure a bounded JSON request pipeline and independent response/probe routes.
fn process_config(port: u16, admin_port: u16, bulk_port: u16, probe_port: u16, event_port: u16) -> String {
    format!(
        r#"
shutdown_timeout_secs: 1
runtime:
  threads: 2
  subrequest_max_connections: 128
admin:
  metrics_address: "127.0.0.1:{admin_port}"
body_limits:
  max_request_bytes: {REQUEST_LIMIT}
  max_response_bytes: {RESPONSE_BYTES}
listeners:
  - name: web
    address: "127.0.0.1:{port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: access_log
        sample_rate: 1.0
        fields: [request_id, status, request_body_bytes, response_body_bytes]
        sink: {{type: stdout}}
      - filter: json_body
        content_types: [application/json]
        request_remove: [/unused]
        max_body_bytes: {REQUEST_LIMIT}
        on_invalid: reject
      - filter: cloud_events
        on: response_complete
        destination: "http://127.0.0.1:{event_port}/events"
        source: urn:praxis:test
        type: gateway.completed
        size_limit_bytes: 1024
        delivery_timeout_ms: 60000
        request_headers: [x-request-id]
        data:
          request_id: {{value: request_header.x-request-id, type: string, required: true}}
          status: {{value: response.status, type: integer, required: true}}
      - filter: router
        routes:
          - path_prefix: /large
            cluster: bulk
          - path_prefix: /
            cluster: probe
      - filter: load_balancer
        clusters:
          - name: bulk
            endpoints: ["127.0.0.1:{bulk_port}"]
          - name: probe
            endpoints: ["127.0.0.1:{probe_port}"]
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// A response source which pauses its first stream before writing its tail.
struct LargeBackend {
    /// Listening port.
    port: u16,
    /// Acknowledges that the first prefix was handed to the socket.
    prefix: Receiver<()>,
    /// Resumes the held response.
    resume: Option<Sender<()>>,
    /// Lengths of responses written completely by the source.
    completed: Receiver<usize>,
    /// Number of request heads received by the bulk backend.
    accepted: Arc<AtomicUsize>,
    /// Cancels the listener.
    stop: Arc<AtomicBool>,
    /// Listener and response worker.
    worker: Option<JoinHandle<()>>,
}

impl LargeBackend {
    /// Serve sequential responses without retaining a complete response body.
    fn start() -> Self {
        Self::with_length(RESPONSE_BYTES)
    }

    /// Start the same bounded source with a caller-selected response length.
    fn with_length(length: usize) -> Self {
        assert!(
            length >= 65_536 + CANARY.len(),
            "response must contain a full prefix and canary"
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let (prefix_tx, prefix) = mpsc::channel();
        let (resume, resume_rx) = mpsc::channel();
        let (completed_tx, completed) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::clone(&stop);
        let count = Arc::clone(&accepted);
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        socket.set_read_timeout(Some(WAIT)).unwrap();
                        socket.set_write_timeout(Some(WAIT)).unwrap();
                        let head = read_head(&mut socket);
                        assert!(
                            head.starts_with("GET /large HTTP/1.1"),
                            "unexpected bulk request: {head}"
                        );
                        let first = count.fetch_add(1, Ordering::SeqCst) == 0;
                        write!(
                            socket,
                            "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
                        )
                        .unwrap();
                        send_repeated(&mut socket, 65_536);
                        if first {
                            prefix_tx.send(()).unwrap();
                            resume_rx.recv_timeout(WAIT).unwrap();
                        }
                        send_repeated(&mut socket, length - CANARY.len() - 65_536);
                        socket.write_all(CANARY).unwrap();
                        completed_tx.send(length).unwrap();
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    },
                    Err(error) => panic!("bulk listener: {error}"),
                }
            }
        });
        Self {
            port,
            prefix,
            resume: Some(resume),
            completed,
            accepted,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for LargeBackend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(resume) = self.resume.take() {
            let _sent = resume.send(());
        }
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}

/// Write a fixed fill byte using only a small working buffer.
fn send_repeated(socket: &mut TcpStream, mut remaining: usize) {
    let buffer = [b'x'; 4_096];
    while remaining > 0 {
        let size = remaining.min(buffer.len());
        socket.write_all(&buffer[..size]).unwrap();
        remaining -= size;
    }
}

/// Connect with bounded read and write deadlines.
fn connect(addr: &str) -> TcpStream {
    let socket = TcpStream::connect(addr).unwrap();
    socket.set_read_timeout(Some(WAIT)).unwrap();
    socket.set_write_timeout(Some(WAIT)).unwrap();
    socket
}

/// Observe all response content without retaining the large body in the runner.
fn large_request(addr: &str, request_id: &str, delivered: Option<Sender<()>>) {
    large_request_sized(addr, request_id, RESPONSE_BYTES, delivered);
}

/// Verify a generated response of `length` bytes with constant controller memory.
fn large_request_sized(addr: &str, request_id: &str, length: usize, mut delivered: Option<Sender<()>>) {
    let mut socket = connect(addr);
    write!(
        socket,
        "GET /large HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: {request_id}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut offset = 0_usize;
    let fill_end = length - CANARY.len();
    let response = read_h1_response(&mut BufReader::new(socket), false, length as u64, |bytes| {
        let fill = fill_end.saturating_sub(offset).min(bytes.len());
        assert!(
            bytes[..fill].iter().all(|byte| *byte == b'x'),
            "response fill mismatch at {offset}"
        );
        if fill < bytes.len() {
            let canary_offset = offset + fill - fill_end;
            assert_eq!(
                &bytes[fill..],
                &CANARY[canary_offset..canary_offset + bytes.len() - fill],
                "response canary differs at byte {canary_offset}"
            );
        }
        offset += bytes.len();
        if offset >= 65_536
            && let Some(sender) = delivered.take()
        {
            sender.send(()).unwrap();
        }
        Ok(())
    });
    assert_eq!(response.status, Some(200), "{response:?}");
    assert_eq!(response.completion, Some(H1Completion::ContentLength), "{response:?}");
    assert_eq!(offset, length, "client must observe the complete generated response");
}

/// Send an independent short request and require its complete expected body.
fn probe_request(addr: &str, request_id: &str) {
    let mut socket = connect(addr);
    write!(
        socket,
        "GET /probe HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: {request_id}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let (response, body) = small_response(socket);
    assert_eq!(response.status, Some(200), "{response:?}");
    assert_eq!(body, b"probe-ok", "control request must return the probe body");
}

/// A late invalid escape forces JSON parsing to inspect nearly the entire input.
fn malformed_request(addr: &str, request_id: &str) {
    let body = PayloadSpec::padded(1_048_500, b"{\"payload\":\"W6_CLOUD_BODY_CANARY_49d1", br#"\q"}"#, b'x').unwrap();
    let mut socket = connect(addr);
    write!(socket, "POST /large HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: {request_id}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
    let mut offset = 0;
    while offset < body.len() {
        let chunk = body.chunk(offset, 16_384);
        socket.write_all(&chunk).unwrap();
        offset += chunk.len() as u64;
    }
    let (response, received) = small_response(socket);
    assert_eq!(response.status, Some(400), "{response:?}");
    assert!(received.is_empty(), "invalid JSON rejection must have an empty body");
    assert!(
        !received.windows(CANARY.len()).any(|window| window == CANARY),
        "invalid-input response must not reflect the body canary"
    );
}

/// Cross the input cap with unknown-length chunked content, not just a declaration.
fn oversized_request(addr: &str, request_id: &str) {
    let mut socket = connect(addr);
    write!(socket, "POST /large HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: {request_id}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").unwrap();
    let mut first = [b'x'; 8_192];
    first[..CANARY.len()].copy_from_slice(CANARY);
    let mut sent = 0;
    while sent <= REQUEST_LIMIT {
        let size = (REQUEST_LIMIT + 1 - sent).min(first.len());
        if write!(socket, "{size:x}\r\n").is_err()
            || socket.write_all(&first[..size]).is_err()
            || socket.write_all(b"\r\n").is_err()
        {
            break;
        }
        sent += size;
    }
    let (response, received) = small_response(socket);
    assert_eq!(response.status, Some(413), "sent={sent}: {response:?}");
    assert_eq!(
        received.as_slice(),
        br#"{"error":"request body too large"}"#,
        "oversized input must return the exact bounded error body"
    );
    assert!(
        !received.windows(CANARY.len()).any(|window| window == CANARY),
        "oversize response must not reflect the body canary"
    );
}

/// Collect only a bounded small response and insist on complete framing.
fn small_response(socket: TcpStream) -> (praxis_test_utils::H1Response, Vec<u8>) {
    let mut body = Vec::new();
    let response = read_h1_response(&mut BufReader::new(socket), false, 8_192, |bytes| {
        body.extend_from_slice(bytes);
        Ok(())
    });
    // Error responses may complete by closing the connection. Each caller
    // separately checks the status and the expected body contents.
    assert!(
        response.completion.is_some() && response.abort.is_none(),
        "{response:?}"
    );
    (response, body)
}

/// Read one small request head without allocating an unbounded line.
fn read_head(socket: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 16_384, "request head exceeded test bound");
        socket.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
    }
    String::from_utf8(head).unwrap()
}

/// One bounded event observed by the deliberately slow receiver.
#[derive(Clone)]
struct ObservedEvent {
    /// Request identifier selected by the explicit event mapping.
    request_id: String,
    /// Mapped response status.
    status: u16,
    /// Serialized event size, excluding HTTP framing.
    body_bytes: usize,
}

/// A receiver which holds accepted calls, then returns alternating 204 and 503.
struct SlowEvents {
    /// Receiver port.
    port: u16,
    /// All bounded event observations.
    observed: Arc<Mutex<Vec<ObservedEvent>>>,
    /// Number of sockets currently held without a response.
    held: Arc<AtomicUsize>,
    /// Release all held sockets and acknowledge future events.
    release: Arc<AtomicBool>,
    /// Stop the listener on teardown.
    stop: Arc<AtomicBool>,
    /// Listener worker.
    worker: Option<JoinHandle<()>>,
}

impl SlowEvents {
    /// Start an event receiver with a strict cap on retained sockets and bytes.
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let held = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_observed = Arc::clone(&observed);
        let worker_held = Arc::clone(&held);
        let worker_release = Arc::clone(&release);
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut sockets: Vec<TcpStream> = Vec::new();
            while !worker_stop.load(Ordering::SeqCst) {
                if worker_release.load(Ordering::SeqCst) && !sockets.is_empty() {
                    for (index, mut socket) in sockets.drain(..).enumerate() {
                        let status = if index % 2 == 0 { 204 } else { 503 };
                        acknowledge(&mut socket, status);
                    }
                    worker_held.store(0, Ordering::SeqCst);
                }
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        socket.set_read_timeout(Some(WAIT)).unwrap();
                        socket.set_write_timeout(Some(WAIT)).unwrap();
                        let event = read_cloud_event(&mut socket);
                        let mut entries = worker_observed.lock().unwrap();
                        assert!(entries.len() < 128, "receiver event ledger exceeded its bound");
                        entries.push(event);
                        drop(entries);
                        if worker_release.load(Ordering::SeqCst) {
                            acknowledge(&mut socket, 204);
                        } else {
                            assert!(
                                sockets.len() < DELIVERY_LIMIT,
                                "more than 64 deliveries reached the stalled receiver"
                            );
                            sockets.push(socket);
                            worker_held.store(sockets.len(), Ordering::SeqCst);
                        }
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    },
                    Err(error) => panic!("event listener: {error}"),
                }
            }
        });
        Self {
            port,
            observed,
            held,
            release,
            stop,
            worker: Some(worker),
        }
    }

    /// Snapshot the bounded event ledger.
    fn events(&self) -> Vec<ObservedEvent> {
        self.observed.lock().unwrap().clone()
    }
}

impl Drop for SlowEvents {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}

/// Read one complete event with explicit header and body ceilings.
fn read_cloud_event(socket: &mut TcpStream) -> ObservedEvent {
    let head = read_head(socket);
    assert!(
        head.starts_with("POST /events HTTP/1.1\r\n"),
        "receiver must observe a CloudEvents POST: {head}"
    );
    let header = |name: &str| {
        head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then_some(value.trim())
        })
    };
    assert_eq!(
        header("content-type"),
        Some("application/cloudevents+json"),
        "event must use the CloudEvents JSON content type"
    );
    let size: usize = header("content-length").unwrap().parse().unwrap();
    assert!(size <= 1_024, "event exceeds configured size limit");
    let mut body = vec![0; size];
    socket.read_exact(&mut body).unwrap();
    assert!(
        !body.windows(CANARY.len()).any(|window| window == CANARY),
        "payload leaked into event"
    );
    let event: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(event["specversion"], "1.0", "event must use CloudEvents version 1.0");
    let request_id = event["data"]["request_id"].as_str().unwrap().to_owned();
    assert!(request_id.len() <= 32, "request ID must fit the bounded event ledger");
    let status = u16::try_from(event["data"]["status"].as_u64().unwrap()).unwrap();
    ObservedEvent {
        request_id,
        status,
        body_bytes: size,
    }
}

/// Return one fixed, bodyless receiver response.
fn acknowledge(socket: &mut TcpStream, status: u16) {
    let response = if status == 204 {
        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice()
    } else {
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice()
    };
    socket.write_all(response).unwrap();
}

/// Require unique, bounded events with statuses matching their originating requests.
fn verify_events(events: &[ObservedEvent], expected: &HashMap<String, u16>) {
    let mut seen = HashSet::new();
    for event in events {
        assert!(
            event.body_bytes <= 1_024,
            "event must respect the configured size limit"
        );
        assert!(
            seen.insert(event.request_id.as_str()),
            "duplicate event: {}",
            event.request_id
        );
        assert_eq!(
            expected.get(&event.request_id),
            Some(&event.status),
            "unrecognized event {}",
            event.request_id
        );
    }
}

/// Collect at most a fixed amount of stdout and stderr through incremental cursors.
#[derive(Default)]
struct BoundedLogs {
    /// Read positions for the child's two log files.
    cursor: ProcessLogCursor,
    /// Captured stdout, kept separate from stderr to preserve line boundaries.
    stdout: Vec<u8>,
    /// Captured stderr.
    stderr: Vec<u8>,
}

impl BoundedLogs {
    /// Drain currently available bytes, enforcing the runner's log budget.
    fn drain(&mut self, process: &PraxisProcess) {
        loop {
            let chunk = process.logs_since(&mut self.cursor, 4_096).unwrap();
            if chunk.stdout.is_empty() && chunk.stderr.is_empty() {
                break;
            }
            self.stdout.extend(chunk.stdout);
            self.stderr.extend(chunk.stderr);
            assert!(
                self.stdout.len() + self.stderr.len() <= 262_144,
                "test log budget exceeded"
            );
        }
        self.assert_private();
    }

    /// Check both streams for the synthetic request/response secret.
    fn assert_private(&self) {
        assert!(
            !self.stdout.windows(CANARY.len()).any(|window| window == CANARY),
            "stdout leaked the body canary"
        );
        assert!(
            !self.stderr.windows(CANARY.len()).any(|window| window == CANARY),
            "stderr leaked the body canary"
        );
    }

    /// Count JSON access records by their explicitly configured request ID.
    fn records(&self) -> HashMap<String, Vec<String>> {
        let mut records = HashMap::<String, Vec<String>>::new();
        for line in String::from_utf8_lossy(&self.stdout).lines() {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(id) = value.get("request_id").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let Some(status) = value.get("status").and_then(serde_json::Value::as_str) else {
                continue;
            };
            records.entry(id.to_owned()).or_default().push(status.to_owned());
        }
        records
    }

    /// Whether all expected IDs have appeared in the bounded log snapshot.
    fn has_records(&self, expected: &HashMap<String, u16>) -> bool {
        let records = self.records();
        expected.keys().all(|id| records.contains_key(id))
    }

    /// Require exactly one record with the actual response status for each request.
    fn assert_records(&self, expected: &HashMap<String, u16>) {
        let records = self.records();
        assert_eq!(records.len(), expected.len(), "unexpected access record IDs");
        for (id, status) in expected {
            let entries = records.get(id).expect("missing access record");
            assert_eq!(entries.len(), 1, "access record count for {id}");
            assert_eq!(entries[0], status.to_string(), "access status for {id}");
        }
    }
}

/// Scrape the process's private metrics listener.
fn scrape(admin: &str) -> String {
    let mut socket = connect(admin);
    socket
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut bytes = Vec::new();
    let response = read_h1_response(&mut BufReader::new(socket), false, 131_072, |part| {
        bytes.extend_from_slice(part);
        Ok(())
    });
    assert_eq!(response.status, Some(200), "{response:?}");
    // The admin listener may use connection-close framing for its finite scrape.
    assert!(response.completion.is_some(), "{response:?}");
    assert!(response.abort.is_none(), "{response:?}");
    let body = String::from_utf8(bytes).unwrap();
    assert!(
        !body.contains(std::str::from_utf8(CANARY).unwrap()),
        "metrics must not expose the body canary"
    );
    body
}

/// Sum counter samples with an optional bounded-label predicate.
fn metric(scrape: &str, name: &str, label: Option<&str>) -> u64 {
    scrape
        .lines()
        .filter(|line| {
            line.strip_prefix(name)
                .is_some_and(|tail| tail.starts_with('{') || tail.starts_with(' '))
                && label.is_none_or(|label| line.contains(label))
        })
        .map(|line| line.rsplit_once(' ').unwrap().1.parse::<u64>().unwrap())
        .sum()
}

/// Poll a condition under an explicit test deadline.
fn wait_for(timeout: Duration, mut condition: impl FnMut() -> bool, description: &str) {
    let deadline = Instant::now() + timeout;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {description}");
        thread::sleep(Duration::from_millis(20));
    }
}

/// Record raw RSS/FD samples and enforce only a generous runner safety envelope.
fn assert_resource_samples(samples: &[ProcessSample]) {
    let baseline = samples[0].rss_bytes.unwrap();
    let rss: Vec<_> = samples.iter().map(|sample| sample.rss_bytes.unwrap()).collect();
    let fds: Vec<_> = samples.iter().map(|sample| sample.open_fds.unwrap()).collect();
    let max_rss = *rss.iter().max().unwrap();
    let high_water = samples.last().unwrap().peak_rss_bytes.unwrap();
    let high_water_limit = samples[0].peak_rss_bytes.unwrap().max(baseline + 536_870_912);
    assert!(
        max_rss.saturating_sub(baseline) <= 536_870_912,
        "runner RSS safety envelope exceeded"
    );
    assert!(
        high_water <= high_water_limit,
        "runner RSS high-water envelope exceeded"
    );
    assert!(
        *fds.iter().max().unwrap() <= fds[0] + 80,
        "descriptor safety envelope exceeded"
    );
    eprintln!("slow CloudEvents sampled RSS bytes: {rss:?}; descriptors: {fds:?}");
}
