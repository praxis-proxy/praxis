// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Isolated-process payload resource profiles. RSS is not a live-allocation count.

#![cfg(target_os = "linux")]

use std::{
    collections::HashMap,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{Shutdown, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use praxis_test_utils::{
    PayloadResponseFraming, PayloadSpec, PraxisProcess, ProcessLogCursor, ProcessSample, free_port, http_get,
    read_h1_response, sample_process, start_backend_with_shutdown, start_counting_backend, start_echo_backend,
    start_h2_paused_uploads, start_payload_response_backend,
};

/// One mebibyte.
const MIB: u64 = 1_048_576;
/// Deadline for an individual socket or backend receipt.
const WAIT: Duration = Duration::from_secs(30);

/// Prevent resource tests in this binary from perturbing each other's samples.
static RESOURCE_LOCK: Mutex<()> = Mutex::new(());

/// Hold the shared lock through a complete measured workload.
pub(super) fn serialized() -> std::sync::MutexGuard<'static, ()> {
    RESOURCE_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Configures independent bulk and health routes, with a bounded read timeout.
pub(super) fn config(port: u16, bulk: u16, probe: u16, filters: &str, listener: &str) -> String {
    format!(
        r#"
shutdown_timeout_secs: 1
runtime:
  threads: 2
body_limits:
  max_request_bytes: 67108864
  max_response_bytes: null
insecure_options:
  allow_private_endpoints: true
  allow_unbounded_body: true
listeners:
  - name: default
    address: "127.0.0.1:{port}"
{listener}    filter_chains: [main]
filter_chains:
  - name: main
    filters:
{filters}      - filter: router
        routes:
          - path_prefix: /bulk
            cluster: bulk
          - path_prefix: /
            cluster: probe
      - filter: load_balancer
        clusters:
          - name: bulk
            endpoints: ["127.0.0.1:{bulk}"]
          - name: probe
            endpoints: ["127.0.0.1:{probe}"]
"#
    )
}

/// An independent request tests that the proxy remains available.
pub(super) fn probe(addr: &str) {
    let (status, body) = http_get(addr, "/probe", None);
    assert_eq!((status, body.as_str()), (200, ""), "clean probe must succeed");
}

/// Start a request whose body can be written in controlled pieces.
pub(super) fn upload(addr: &str, len: usize) -> TcpStream {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    write!(stream, "POST /bulk HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n").unwrap();
    stream
}

/// Read the entire framed response while imposing a small response body ceiling.
pub(super) fn status(stream: TcpStream) -> u16 {
    let result = read_h1_response(&mut BufReader::new(stream), false, 8192, |_| Ok(()));
    assert!(result.completion.is_some() && result.abort.is_none(), "{result:?}");
    result.status.unwrap()
}

/// A sampling thread which is stopped and reaped even if the workload panics.
struct Sampler {
    /// Request termination of the sampler.
    stop: Arc<AtomicBool>,
    /// Samples collected by the background thread.
    worker: Option<JoinHandle<Vec<ProcessSample>>>,
}

impl Sampler {
    /// Begin polling a process until the sampler is stopped.
    fn start(pid: u32) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut samples = Vec::new();
            while !flag.load(Ordering::Relaxed) {
                samples.push(sample_process(pid).expect("sample live proxy"));
                thread::sleep(Duration::from_millis(10));
            }
            samples.push(sample_process(pid).expect("sample live proxy after workload"));
            samples
        });
        Self {
            stop,
            worker: Some(worker),
        }
    }

    /// Stop the thread and return its samples.
    fn finish(mut self) -> Vec<ProcessSample> {
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

/// Poll the child during a workload; failure to sample the child is a test error.
fn measure<T>(pid: u32, operation: impl FnOnce() -> T) -> (T, Vec<ProcessSample>) {
    let sampler = Sampler::start(pid);
    let result = operation();
    (result, sampler.finish())
}

/// Log raw counters and assert only a generous runner safety envelope.
fn report(label: &str, before: &ProcessSample, samples: &[ProcessSample], budget: u64) {
    let baseline = before.rss_bytes.expect("Linux VmRSS");
    let peak = samples
        .iter()
        .map(|sample| sample.rss_bytes.expect("Linux VmRSS"))
        .max()
        .unwrap();
    let last = samples.last().unwrap();
    let high_water = last.peak_rss_bytes.expect("Linux VmHWM");
    let high_water_limit = before.peak_rss_bytes.expect("Linux VmHWM").max(baseline + budget);
    let cpu = last.cpu_ticks.unwrap().saturating_sub(before.cpu_ticks.unwrap());
    let anon = samples.iter().filter_map(|sample| sample.anonymous_rss_bytes).max();
    let fds = samples.iter().filter_map(|sample| sample.open_fds).max();
    eprintln!(
        "{label}: baseline_rss={baseline} sampled_peak_rss={peak} high_water_rss={high_water} after_rss={:?} peak_anon={anon:?} cpu_ticks={cpu} peak_fds={fds:?}",
        last.rss_bytes
    );
    assert!(
        peak.saturating_sub(baseline) <= budget,
        "{label}: RSS safety envelope exceeded"
    );
    assert!(
        high_water <= high_water_limit,
        "{label}: RSS high-water envelope exceeded"
    );
}

/// Stop a process with a bounded wait and distinguish an OS kill from success.
pub(super) fn stop(process: &mut PraxisProcess) {
    process.signal("TERM");
    let (status, killed) = process.wait_or_kill(Duration::from_secs(12));
    assert!(
        !killed && status.success(),
        "proxy did not exit cleanly: {status}, forced={killed}"
    );
}

/// Stream and check a generated response with constant test-harness memory.
fn opaque_response(length: u64, access_log: bool) -> (u64, u64) {
    let spec = PayloadSpec::binary(length, 9);
    let mut backend = start_payload_response_backend(spec.clone(), PayloadResponseFraming::Fixed, Some(0));
    let clean = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let filters = if access_log {
        "      - filter: access_log\n        sample_rate: 1.0\n        fields: [path, status, response_body_bytes]\n        sink: {type: stdout}\n"
    } else {
        ""
    };
    // Large scheduled profiles explicitly opt into their payload-sized cap.
    // Other resource fixtures retain the ordinary 64 MiB buffering default.
    let yaml = config(port, backend.port, clean.port(), filters, "").replacen(
        "body_limits:\n",
        &format!("body_limits:\n  max_buffer_bytes: {}\n", length.max(67_108_864)),
        1,
    );
    let mut process = PraxisProcess::spawn(&yaml, &addr);
    let before = sample_process(process.pid()).unwrap();
    let (_, samples) = measure(process.pid(), || {
        thread::scope(|scope| {
            let reader = scope.spawn(|| {
                let mut client = TcpStream::connect(&addr).unwrap();
                client.set_read_timeout(Some(WAIT)).unwrap();
                client
                    .write_all(b"GET /bulk HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .unwrap();
                let mut count = 0;
                let response = read_h1_response(&mut BufReader::new(client), false, length, |bytes| {
                    assert_eq!(spec.mismatch(count, bytes), None, "opaque bytes must match at {count}");
                    count += bytes.len() as u64;
                    Ok(())
                });
                assert_eq!(response.status, Some(200), "{response:?}");
                assert!(
                    response.completion.is_some() && response.abort.is_none(),
                    "{response:?}"
                );
                assert_eq!(count, length, "complete response length");
            });
            assert_eq!(
                backend.prefix_written.recv_timeout(WAIT).unwrap(),
                0,
                "source must pause before response data"
            );
            probe(&addr);
            backend.resume();
            while !reader.is_finished() {
                probe(&addr);
                thread::sleep(Duration::from_millis(100));
            }
            reader.join().unwrap();
        });
    });
    let receipt = backend.receipt.recv_timeout(WAIT).unwrap();
    assert!(receipt.complete && receipt.written_bytes == length, "{receipt:?}");
    report(
        &format!("opaque bytes={length} access_log={access_log}"),
        &before,
        &samples,
        128 * MIB,
    );
    probe(&addr);
    let peak = samples.iter().filter_map(|sample| sample.rss_bytes).max().unwrap();
    stop(&mut process);
    if access_log {
        let mut cursor = ProcessLogCursor::default();
        let mut captured = Vec::new();
        loop {
            let logs = process.logs_since(&mut cursor, 65_536).unwrap();
            if logs.stdout.is_empty() && logs.stderr.is_empty() {
                break;
            }
            captured.extend(logs.stdout);
            assert!(captured.len() < 1_048_576, "access logs exceed capture budget");
        }
        let records: Vec<serde_json::Value> = captured
            .split(|byte| *byte == b'\n')
            .filter_map(|line| serde_json::from_slice(line).ok())
            .filter(|record: &serde_json::Value| {
                record.get("path").and_then(serde_json::Value::as_str) == Some("/bulk")
            })
            .collect();
        assert_eq!(records.len(), 1, "completion must log exactly once: {records:?}");
        assert_eq!(
            records[0].get("status").and_then(serde_json::Value::as_str),
            Some("200"),
            "completion record must retain the response status"
        );
        assert_eq!(
            records[0]
                .get("response_body_bytes")
                .and_then(serde_json::Value::as_str),
            Some(length.to_string().as_str()),
            "completion record must count all response bytes"
        );
    }
    backend.join();
    (before.rss_bytes.unwrap(), peak)
}

#[test]
fn opaque_ten_mib_with_and_without_access_log_stays_bounded() {
    let _guard = serialized();
    for access_log in [false, true] {
        opaque_response(10 * MIB, access_log);
    }
}

#[test]
#[ignore = "scheduled: serialized release-build resource profile"]
fn scheduled_opaque_streaming_plateau_through_one_gib() {
    let _guard = serialized();
    for length in [10 * MIB, 64 * MIB, 256 * MIB, 1024 * MIB] {
        for access_log in [false, true] {
            let (base, peak) = opaque_response(length, access_log);
            eprintln!("opaque size={length} rss_growth={}", peak.saturating_sub(base));
        }
    }
}

/// A one-connection sink validates a generated, possibly rewritten JSON body
/// incrementally. It never reflects the body or retains a second copy.
pub(super) struct Sink {
    /// Listening port for generated requests.
    pub(super) port: u16,
    /// Complete exact-body observations, one per request.
    pub(super) receipt: Receiver<Result<u64, String>>,
    /// Notification when the listener accepts each upstream connection.
    accepted: Receiver<()>,
    /// Ask the accept loop to acknowledge after draining the listener backlog.
    fence: mpsc::Sender<mpsc::Sender<()>>,
    /// Tenant header recorded with each complete request.
    tenants: Receiver<Option<String>>,
    /// Interrupt the accept loop when the test ends.
    stop: Arc<AtomicBool>,
    /// Socket clones used to interrupt active reads.
    active: Arc<Mutex<HashMap<usize, TcpStream>>>,
    /// Accept loop and its joined request handlers.
    worker: Option<JoinHandle<()>>,
}

impl Drop for Sink {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for stream in self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
        {
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

/// Remove a connection's cancellation handle as soon as its handler exits.
struct SinkSocket {
    /// Stable identifier assigned by the accept loop.
    id: usize,
    /// Currently active upstream connections.
    active: Arc<Mutex<HashMap<usize, TcpStream>>>,
}

impl Drop for SinkSocket {
    fn drop(&mut self) {
        let _removed = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
    }
}

/// Start a bounded concurrent sink accepting exactly `count` requests.
pub(super) fn sink(expected: Vec<u8>, count: usize) -> Sink {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let active = Arc::new(Mutex::new(HashMap::new()));
    let flag = Arc::clone(&stop);
    let sockets = Arc::clone(&active);
    let expected = Arc::new(expected);
    let (tx, receipt) = mpsc::channel();
    let (accepted_tx, accepted) = mpsc::channel();
    let (fence, fences) = mpsc::channel::<mpsc::Sender<()>>();
    let (tenant_tx, tenants) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut handlers = Vec::new();
        while !flag.load(Ordering::Relaxed) && handlers.len() < count {
            match listener.accept() {
                Ok((stream, _)) => {
                    let mut active_sockets = sockets.lock().unwrap();
                    if flag.load(Ordering::Relaxed) {
                        break;
                    }
                    let id = handlers.len();
                    let previous = active_sockets.insert(id, stream.try_clone().unwrap());
                    drop(active_sockets);
                    assert!(previous.is_none(), "each sink connection has a unique id");
                    let _sent = accepted_tx.send(());
                    let expected = Arc::clone(&expected);
                    let tx = tx.clone();
                    let tenant_tx = tenant_tx.clone();
                    let active = Arc::clone(&sockets);
                    handlers.push(thread::spawn(move || {
                        let handle = SinkSocket { id, active };
                        let observation = receive_body(stream, &expected, &tenant_tx);
                        drop(handle);
                        let _sent = tx.send(observation);
                    }));
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    while let Ok(acknowledge) = fences.try_recv() {
                        let _sent = acknowledge.send(());
                    }
                    thread::sleep(Duration::from_millis(5));
                },
                Err(error) => panic!("sink accept: {error}"),
            }
        }
        for handler in handlers {
            handler.join().unwrap();
        }
    });
    Sink {
        port,
        receipt,
        accepted,
        fence,
        tenants,
        stop,
        active,
        worker: Some(worker),
    }
}

/// Verify request framing and bytes incrementally before replying.
fn receive_body(stream: TcpStream, expected: &[u8], tenants: &mpsc::Sender<Option<String>>) -> Result<u64, String> {
    stream.set_read_timeout(Some(WAIT)).map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut length = None;
    let mut tenant = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).map_err(|error| error.to_string())? == 0 {
            return Err("EOF in request headers".into());
        }
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = Some(value.trim().parse::<usize>().map_err(|error| error.to_string())?);
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("x-resource-tenant")
        {
            tenant = Some(value.trim().to_owned());
        }
    }
    if length != Some(expected.len()) {
        return Err(format!("incorrect content length: {length:?}"));
    }
    let mut received = 0;
    let mut chunk = vec![0_u8; 16_384];
    while received < expected.len() {
        let size = (expected.len() - received).min(chunk.len());
        reader
            .read_exact(&mut chunk[..size])
            .map_err(|error| error.to_string())?;
        if chunk[..size] != expected[received..received + size] {
            return Err(format!("mismatch at {received}"));
        }
        received += size;
    }
    tenants.send(tenant).map_err(|error| error.to_string())?;
    reader
        .get_mut()
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .map_err(|error| error.to_string())?;
    Ok(received as u64)
}

/// The backend reports an accepted connection before its body completes and
/// releases its cancellation socket on both complete and truncated requests.
#[test]
fn sink_releases_completed_and_interrupted_connections() {
    let _guard = serialized();
    let backend = sink(b"ok".to_vec(), 2);
    let addr = format!("127.0.0.1:{}", backend.port);
    assert_sink_not_selected(&backend);

    let mut complete = TcpStream::connect(&addr).unwrap();
    complete.set_read_timeout(Some(WAIT)).unwrap();
    complete
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\nok")
        .unwrap();
    backend.accepted.recv_timeout(WAIT).unwrap();
    let response = read_h1_response(&mut BufReader::new(complete), false, 2, |_| Ok(()));
    assert_eq!(response.status, Some(200));
    assert!(
        response.completion.is_some() && response.abort.is_none(),
        "{response:?}"
    );
    assert_eq!(backend.receipt.recv_timeout(WAIT).unwrap().unwrap(), 2);
    assert!(
        backend.active.lock().unwrap().is_empty(),
        "completed handler drops its socket clone"
    );
    assert_sink_not_selected(&backend);

    let mut partial = TcpStream::connect(&addr).unwrap();
    partial
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\no")
        .unwrap();
    backend.accepted.recv_timeout(WAIT).unwrap();
    assert_eq!(
        backend.active.lock().unwrap().len(),
        1,
        "interrupted handler is actively tracked"
    );
    assert!(
        matches!(backend.receipt.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "acceptance is observable before a request has completed"
    );
    partial.shutdown(Shutdown::Write).unwrap();
    assert!(
        backend.receipt.recv_timeout(WAIT).unwrap().is_err(),
        "truncated request must fail"
    );
    assert!(
        backend.active.lock().unwrap().is_empty(),
        "interrupted handler drops its socket clone"
    );
}

/// Generate distinct inspection shapes without allocating in the proxy fixture.
fn json_body(size: usize, shape: &str) -> Vec<u8> {
    use std::fmt::Write as _;
    let mut body = String::with_capacity(size);
    body.push_str("{\"model\":\"old\",\"pad\":\"");
    if shape == "fields" || shape == "fields_wide" {
        body.push('"');
        let value = if shape == "fields" {
            "x"
        } else {
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        };
        let mut field = 0;
        loop {
            let member = format!(",\"k{field}\":\"{value}\"");
            if body.len() + member.len() + 1 > size {
                break;
            }
            write!(body, "{member}").unwrap();
            field += 1;
        }
        body.push('}');
    } else {
        let atom = match shape {
            "long" => "x",
            "escaped" => "\\u0078",
            "unicode" => "İ",
            _ => panic!("unknown shape"),
        };
        let repeats = (size - body.len() - 2) / atom.len();
        for _ in 0..repeats {
            body.push_str(atom);
        }
        body.push_str("\"}");
    }
    body.into_bytes()
}

/// Run one complete request without buffering the response in the harness.
fn post_json(addr: &str, input: &[u8]) -> u16 {
    let mut stream = upload(addr, input.len());
    for chunk in input.chunks(16_384) {
        stream.write_all(chunk).unwrap();
    }
    status(stream)
}

/// Repeat smaller profiles enough to overcome coarse Linux CPU tick counters.
fn cpu_iterations(size: usize) -> usize {
    (134_217_728 / size).clamp(2, 128)
}

/// Verify a shaped body while sampling one built-in inspection pipeline.
fn profile_inspection(size: usize, shape: &str, mode: &str, iterations: usize) -> u64 {
    let input = json_body(size, shape);
    let mut expected = input.clone();
    let filters = match mode {
        "field" => {
            "      - filter: json_body_field\n        field: model\n        header: x-praxis-model\n        max_body_bytes: 67108864\n"
        },
        "pii" => {
            "      - filter: json_body_field\n        field: model\n        header: x-praxis-model\n        max_body_bytes: 67108864\n      - filter: guardrails\n        action: reject\n        rules:\n          - target: body\n            contains: [email, phone, ssn, credit_card]\n"
        },
        "rewrite" => {
            drop(expected.splice(10..13, b"new".iter().copied()));
            "      - filter: json_body\n        conditions:\n          - when:\n              path_prefix: /bulk\n        max_body_bytes: 67108864\n        on_invalid: reject\n        request_replace:\n          - pointer: /model\n            value: new\n"
        },
        _ => panic!("unknown mode"),
    };
    let backend = sink(expected, iterations + 1);
    let clean = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut process = PraxisProcess::spawn(&config(port, backend.port, clean.port(), filters, ""), &addr);
    let cold = sample_process(process.pid()).unwrap();
    let (_, mut warm_samples) = measure(process.pid(), || {
        assert_eq!(post_json(&addr, &input), 200, "warmup {mode}/{shape}");
        assert_eq!(
            backend.receipt.recv_timeout(WAIT).unwrap().unwrap(),
            input.len() as u64,
            "backend must receive the complete expected body"
        );
    });
    let before = sample_process(process.pid()).unwrap();
    let (_, samples) = measure(process.pid(), || {
        for _ in 0..iterations {
            assert_eq!(post_json(&addr, &input), 200, "{mode}/{shape}");
            assert_eq!(
                backend.receipt.recv_timeout(WAIT).unwrap().unwrap(),
                input.len() as u64,
                "backend must receive the complete expected body"
            );
        }
    });
    let ticks = samples
        .last()
        .unwrap()
        .cpu_ticks
        .unwrap()
        .saturating_sub(before.cpu_ticks.unwrap());
    warm_samples.extend(samples);
    report(
        &format!("inspect mode={mode} shape={shape} size={size}"),
        &cold,
        &warm_samples,
        768 * MIB,
    );
    probe(&addr);
    stop(&mut process);
    ticks
}

#[test]
fn inspect_one_mib_shapes_and_consumers() {
    let _guard = serialized();
    for mode in ["field", "pii", "rewrite"] {
        for shape in ["long", "fields", "escaped", "unicode"] {
            profile_inspection(MIB as usize, shape, mode, 1);
        }
    }
}

#[test]
#[ignore = "scheduled: serialized release-build inspection allocation profile"]
fn scheduled_inspection_memory_shapes_and_cpu_scaling() {
    let _guard = serialized();
    for mode in ["field", "pii", "rewrite"] {
        for shape in ["long", "fields", "fields_wide", "escaped", "unicode"] {
            let mut scaling = Vec::new();
            for size in [MIB, 2 * MIB, 4 * MIB, 8 * MIB, 10 * MIB, 64 * MIB] {
                // Keep the field-count workload contained at 64 MiB.
                if shape == "fields" && size > 10 * MIB {
                    continue;
                }
                if shape == "fields_wide" && size != 64 * MIB {
                    continue;
                }
                let iterations = cpu_iterations(size as usize);
                let ticks = profile_inspection(size as usize, shape, mode, iterations);
                eprintln!(
                    "cpu observation mode={mode} shape={shape} size={size} iterations={iterations} ticks={ticks} insufficient_tick_resolution={}",
                    ticks < 5
                );
                if size <= 8 * MIB {
                    scaling.push((size / MIB, ticks, iterations));
                }
            }
            if scaling.len() == 4 && scaling.iter().all(|(_, ticks, _)| *ticks >= 5) {
                // Fit per-operation tick counts only when each aggregate
                // spans several kernel ticks; retain raw coarse samples.
                let points: Vec<(f64, f64)> = scaling
                    .iter()
                    .map(|(size, ticks, runs)| (*size as f64, *ticks as f64 / *runs as f64))
                    .collect();
                let x_sum: f64 = points.iter().map(|(x, _)| x).sum();
                let y_sum: f64 = points.iter().map(|(_, y)| y).sum();
                let xy_sum: f64 = points.iter().map(|(x, y)| x * y).sum();
                let xx_sum: f64 = points.iter().map(|(x, _)| x * x).sum();
                let slope = (4.0 * xy_sum - x_sum * y_sum) / (4.0 * xx_sum - x_sum * x_sum);
                let ratio = points[3].1 / points[0].1;
                eprintln!(
                    "cpu scaling mode={mode} shape={shape} samples={scaling:?} ticks_per_operation_mib_slope={slope:.3} endpoint_ratio={ratio:.3}"
                );
            } else if scaling.len() == 4 {
                eprintln!("cpu scaling mode={mode} shape={shape} insufficient_tick_resolution samples={scaling:?}");
            }
        }
    }
}

/// Exercise the same bytes with different HTTP/1 chunk counts and both
/// pre-read inspection and ordinary streaming.
#[test]
fn tiny_chunks_keep_content_exact_with_and_without_preread() {
    let _guard = serialized();
    for filters in [
        "",
        "      - filter: json_body_field\n        field: model\n        header: x-praxis-model\n",
    ] {
        for chunk_len in [16_384_usize, 128, 16] {
            let spec = PayloadSpec::padded(262_144, br#"{"model":"old","pad":""#, br#""}"#, b'x').unwrap();
            let backend = start_counting_backend(spec.clone(), "bulk", spec.len());
            let clean = start_echo_backend();
            let port = free_port();
            let addr = format!("127.0.0.1:{port}");
            let mut process = PraxisProcess::spawn(&config(port, backend.port, clean.port(), filters, ""), &addr);
            let before = sample_process(process.pid()).unwrap();
            let (_, samples) = measure(process.pid(), || {
                let mut stream = TcpStream::connect(&addr).unwrap();
                stream.set_read_timeout(Some(WAIT)).unwrap();
                stream.set_write_timeout(Some(WAIT)).unwrap();
                stream.write_all(b"POST /bulk HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").unwrap();
                let mut offset = 0;
                while offset < spec.len() {
                    let bytes = spec.chunk(offset, chunk_len);
                    write!(stream, "{:x}\r\n", bytes.len()).unwrap();
                    stream.write_all(&bytes).unwrap();
                    stream.write_all(b"\r\n").unwrap();
                    offset += bytes.len() as u64;
                }
                stream.write_all(b"0\r\n\r\n").unwrap();
                assert_eq!(status(stream), 200, "upload must complete successfully");
            });
            let receipt = backend.receipt.recv_timeout(WAIT).unwrap();
            assert_eq!(receipt.bytes, spec.len());
            assert_eq!(receipt.mismatch, None);
            assert!(receipt.completion.is_some());
            report(
                &format!("frames chunk={chunk_len} preread={}", !filters.is_empty()),
                &before,
                &samples,
                128 * MIB,
            );
            probe(&addr);
            stop(&mut process);
            backend.join();
        }
    }
}

/// Measure how quickly the same proxy and generator reach the progress
/// barrier with an actively reading client. This prevents a slow generator
/// from masquerading as successful backpressure.
fn response_progress_control() -> Duration {
    let length = 16 * MIB;
    let spec = PayloadSpec::binary(length, 91);
    let mut backend = start_payload_response_backend(spec.clone(), PayloadResponseFraming::Fixed, Some(length));
    let clean = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut process = PraxisProcess::spawn(&config(port, backend.port, clean.port(), "", ""), &addr);
    let started = Instant::now();
    let mut client = TcpStream::connect(&addr).unwrap();
    client.set_read_timeout(Some(WAIT)).unwrap();
    client
        .write_all(b"GET /bulk HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut count = 0;
    let mut reached = None;
    let result = read_h1_response(&mut BufReader::new(client), false, length, |chunk| {
        assert_eq!(
            spec.mismatch(count, chunk),
            None,
            "control response bytes must match at {count}"
        );
        count += chunk.len() as u64;
        if count == length {
            reached = Some(started.elapsed());
            backend.resume();
        }
        Ok(())
    });
    assert_eq!(result.status, Some(200), "control response must succeed");
    assert!(result.completion.is_some() && result.abort.is_none(), "{result:?}");
    assert_eq!(
        backend.prefix_written.recv_timeout(WAIT).unwrap(),
        length,
        "control source must reach the full prefix"
    );
    assert!(
        backend.receipt.recv_timeout(WAIT).unwrap().complete,
        "control source must complete"
    );
    probe(&addr);
    stop(&mut process);
    backend.join();
    reached.unwrap()
}

/// A stalled downstream cannot cause a complete large response to be spooled;
/// once it reads again both the generated body and framing must finish exactly.
#[test]
fn stalled_download_resumes_and_client_cancellation_stops_producer() {
    let _guard = serialized();
    let control = response_progress_control();
    let stall = (control * 2 + Duration::from_millis(500)).max(Duration::from_secs(1));
    assert!(
        stall < Duration::from_secs(12),
        "producer control is too slow to establish backpressure: {control:?}"
    );
    eprintln!("producer progress control={control:?} stalled_duration={stall:?}");
    for cancel in [false, true] {
        let length = 64 * MIB;
        let spec = PayloadSpec::binary(length, 91);
        let mut backend = start_payload_response_backend(spec.clone(), PayloadResponseFraming::Fixed, Some(16 * MIB));
        let clean = start_echo_backend();
        let port = free_port();
        let addr = format!("127.0.0.1:{port}");
        let mut process = PraxisProcess::spawn(&config(port, backend.port, clean.port(), "", ""), &addr);
        let before = sample_process(process.pid()).unwrap();
        let (_, samples) = measure(process.pid(), || {
            let mut stream = TcpStream::connect(&addr).unwrap();
            stream.set_read_timeout(Some(WAIT)).unwrap();
            stream
                .write_all(b"GET /bulk HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            backend.accepted.recv_timeout(WAIT).unwrap();
            thread::sleep(stall);
            assert_eq!(
                backend.prefix_written.try_recv().unwrap_err(),
                mpsc::TryRecvError::Empty,
                "producer reached 16 MiB or terminated while client did not read"
            );
            probe(&addr);
            if cancel {
                drop(stream);
                // The producer may be blocked in a write; a cancellation must
                // ultimately interrupt it rather than complete the response.
                backend.resume();
                let receipt = backend.receipt.recv_timeout(WAIT).unwrap();
                assert!(!receipt.complete && receipt.written_bytes < length, "{receipt:?}");
            } else {
                let mut received = 0;
                let response = read_h1_response(&mut BufReader::new(stream), false, length, |chunk| {
                    assert_eq!(spec.mismatch(received, chunk), None);
                    received += chunk.len() as u64;
                    if received >= 16 * MIB {
                        backend.resume();
                    }
                    Ok(())
                });
                assert_eq!(response.status, Some(200));
                assert!(
                    response.completion.is_some() && response.abort.is_none(),
                    "{response:?}"
                );
                assert_eq!(received, length);
                assert_eq!(backend.prefix_written.recv_timeout(WAIT).unwrap(), 16 * MIB);
                let receipt = backend.receipt.recv_timeout(WAIT).unwrap();
                assert!(receipt.complete && receipt.written_bytes == length, "{receipt:?}");
            }
        });
        report(&format!("slow receiver cancel={cancel}"), &before, &samples, 128 * MIB);
        probe(&addr);
        stop(&mut process);
        backend.join();
    }
}

/// Keep uploads just short of EOS while independent small requests run, then
/// verify every response and the proxy's peak resident memory.
fn concurrent_uploads(concurrency: usize) {
    let body = json_body(1_048_576, "long");
    let backend = sink(body.clone(), concurrency);
    let clean = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let filters = "      - filter: json_body_field\n        field: model\n        header: x-praxis-model\n        max_body_bytes: 1048576\n";
    let yaml = config(port, backend.port, clean.port(), filters, "    max_connections: 40\n")
        .replace(
            "  threads: 2\n",
            "  threads: 2\n  max_connections: 48\n  max_memory_bytes: 536870912\n",
        )
        .replace("max_request_bytes: 67108864", "max_request_bytes: 1048576");
    let mut process = PraxisProcess::spawn(&yaml, &addr);
    let mut baseline = Vec::new();
    for _ in 0..20 {
        let started = Instant::now();
        probe(&addr);
        baseline.push(started.elapsed());
    }
    baseline.sort();
    let baseline_p95 = baseline[18];
    let baseline_p99 = baseline[19];
    let before = sample_process(process.pid()).unwrap();
    let (_, samples) = measure(process.pid(), || {
        let mut streams = Vec::new();
        for _ in 0..concurrency {
            let mut stream = upload(&addr, body.len());
            stream.write_all(&body[..body.len() - 1]).unwrap();
            streams.push(stream);
        }
        let mut latencies = Vec::new();
        for _ in 0..20 {
            let started = Instant::now();
            probe(&addr);
            latencies.push(started.elapsed());
        }
        latencies.sort();
        let p95 = latencies[18];
        let p99 = latencies[19];
        eprintln!(
            "concurrency={concurrency} baseline_p95={baseline_p95:?} baseline_p99={baseline_p99:?} p95={p95:?} p99={p99:?}"
        );
        assert!(
            p95 < baseline_p95 * 20 + Duration::from_secs(2)
                && p99 < Duration::from_secs(5)
                && p99 < baseline_p99 * 20 + Duration::from_secs(2),
            "probe latency budget exceeded: {p99:?}"
        );
        for stream in &mut streams {
            stream.write_all(&body[body.len() - 1..]).unwrap();
        }
        for stream in streams {
            assert_eq!(status(stream), 200, "upload must complete successfully");
        }
        for _ in 0..concurrency {
            assert_eq!(
                backend.receipt.recv_timeout(WAIT).unwrap().unwrap(),
                body.len() as u64,
                "backend must receive every upload byte"
            );
        }
    });
    report(&format!("concurrency={concurrency}"), &before, &samples, 256 * MIB);
    probe(&addr);
    stop(&mut process);
}

#[test]
fn small_probes_succeed_during_paused_uploads() {
    let _guard = serialized();
    for count in [1, 4] {
        concurrent_uploads(count);
    }
}

#[test]
#[ignore = "scheduled: serialized concurrency and process resource profile"]
fn scheduled_small_probes_during_16_and_32_paused_uploads() {
    let _guard = serialized();
    for count in [16, 32] {
        concurrent_uploads(count);
    }
}

/// Build separate routes for one-shot download sources and independent tenants.
fn download_config(port: u16, sources: &[u16], tenant_a: u16, tenant_b: u16) -> String {
    let mut routes = String::new();
    let mut clusters = String::new();
    for (index, source) in sources.iter().enumerate() {
        routes.push_str(&format!(
            "          - path_prefix: /bulk/{index:03}/\n            cluster: bulk{index}\n"
        ));
        clusters.push_str(&format!(
            "          - name: bulk{index}\n            endpoints: [\"127.0.0.1:{source}\"]\n"
        ));
    }
    format!(
        r#"
shutdown_timeout_secs: 1
runtime:
  threads: 2
  max_memory_bytes: 536870912
body_limits:
  max_response_bytes: null
insecure_options:
  allow_private_endpoints: true
  allow_unbounded_body: true
listeners:
  - name: default
    address: "127.0.0.1:{port}"
    max_connections: 48
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
{routes}          - path_prefix: /tenant/a
            cluster: tenant_a
          - path_prefix: /tenant/b
            cluster: tenant_b
      - filter: load_balancer
        clusters:
{clusters}          - name: tenant_a
            endpoints: ["127.0.0.1:{tenant_a}"]
          - name: tenant_b
            endpoints: ["127.0.0.1:{tenant_b}"]
"#
    )
}

/// Independent tenant probe with an exact response and bounded framing.
fn download_tenant_probe(addr: &str, tenant: &str) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    write!(
        stream,
        "GET /tenant/{tenant} HTTP/1.1\r\nHost: localhost\r\nX-Resource-Tenant: {tenant}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut body = Vec::new();
    let response = read_h1_response(&mut BufReader::new(stream), false, 128, |chunk| {
        body.extend_from_slice(chunk);
        Ok(())
    });
    assert_eq!(response.status, Some(200), "{response:?}");
    assert!(
        response.completion.is_some() && response.abort.is_none(),
        "{response:?}"
    );
    assert_eq!(
        body,
        format!("tenant-{tenant}").as_bytes(),
        "probe must retain tenant routing while downloads are active"
    );
}

/// Collect comparable samples per tenant, checking loaded work is in flight.
fn download_probe_samples(addr: &str, workers: Option<&[JoinHandle<()>]>) -> [Vec<Duration>; 2] {
    let mut durations = [Vec::new(), Vec::new()];
    for _ in 0..20 {
        for (index, tenant) in ["a", "b"].into_iter().enumerate() {
            if let Some(workers) = workers {
                assert!(
                    workers.iter().any(|worker| !worker.is_finished()),
                    "downloads ended before probes finished"
                );
            }
            let start = Instant::now();
            download_tenant_probe(addr, tenant);
            durations[index].push(start.elapsed());
        }
    }
    for samples in &mut durations {
        samples.sort();
    }
    durations
}

/// Pause each one-shot source after 64 KiB, then resume concurrent 10 MiB
/// downloads while comparing independent per-tenant probe latency to baseline.
fn concurrent_downloads(concurrency: usize) {
    const LENGTH: u64 = 10 * MIB;
    const PREFIX: u64 = 65_536;
    let specs: Vec<_> = (0..concurrency)
        .map(|index| PayloadSpec::binary(LENGTH, index as u64 + 500))
        .collect();
    let mut sources: Vec<_> = specs
        .iter()
        .map(|spec| start_payload_response_backend(spec.clone(), PayloadResponseFraming::Fixed, Some(PREFIX)))
        .collect();
    let tenant_a = start_backend_with_shutdown("tenant-a");
    let tenant_b = start_backend_with_shutdown("tenant-b");
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let ports: Vec<_> = sources.iter().map(|source| source.port).collect();
    let mut process = PraxisProcess::spawn(&download_config(port, &ports, tenant_a.port(), tenant_b.port()), &addr);
    let baseline = download_probe_samples(&addr, None);
    let before = sample_process(process.pid()).unwrap();
    let (_, samples) = measure(process.pid(), || {
        let (ready_tx, ready_rx) = mpsc::channel();
        let mut resumes = Vec::new();
        let mut workers = Vec::new();
        for (index, spec) in specs.iter().cloned().enumerate() {
            let addr = addr.clone();
            let ready = ready_tx.clone();
            let (resume, resumed) = mpsc::channel();
            resumes.push(resume);
            workers.push(thread::spawn(move || {
                let mut stream = TcpStream::connect(&addr).unwrap();
                stream.set_read_timeout(Some(WAIT)).unwrap();
                let tenant = if index % 2 == 0 { "a" } else { "b" };
                write!(stream, "GET /bulk/{index:03}/ HTTP/1.1\r\nHost: localhost\r\nX-Resource-Tenant: {tenant}\r\nConnection: close\r\n\r\n").unwrap();
                let mut received = 0;
                let mut announced = false;
                let response = read_h1_response(&mut BufReader::new(stream), false, LENGTH, |chunk| {
                    assert_eq!(spec.mismatch(received, chunk), None, "download {index} at {received}");
                    received += chunk.len() as u64;
                    if received >= PREFIX && !announced {
                        announced = true;
                        ready.send(index).unwrap();
                        resumed.recv_timeout(WAIT).map_err(|error| std::io::Error::other(error.to_string()))?;
                    }
                    // Keep actual response transfers concurrent long enough to sample probes.
                    thread::sleep(Duration::from_millis(1));
                    Ok(())
                });
                assert_eq!(response.status, Some(200), "{response:?}");
                assert!(response.completion.is_some() && response.abort.is_none(), "{response:?}");
                assert_eq!(received, LENGTH, "download {index} length");
            }));
        }
        drop(ready_tx);
        let mut ready = Vec::new();
        for source in &sources {
            assert_eq!(
                source.prefix_written.recv_timeout(WAIT).unwrap(),
                PREFIX,
                "every source must pause at the configured prefix"
            );
            ready.push(ready_rx.recv_timeout(WAIT).unwrap());
        }
        ready.sort_unstable();
        assert_eq!(
            ready,
            (0..concurrency).collect::<Vec<_>>(),
            "every response must reach its client"
        );
        for tenant in ["a", "b"] {
            download_tenant_probe(&addr, tenant);
        }
        for source in &mut sources {
            source.resume();
        }
        for resume in resumes {
            resume.send(()).unwrap();
        }
        let loaded = download_probe_samples(&addr, Some(&workers));
        for (index, tenant) in ["a", "b"].into_iter().enumerate() {
            let p95 = loaded[index][18];
            let p99 = loaded[index][19];
            eprintln!(
                "downloads={concurrency} tenant={tenant} baseline_p95={:?} baseline_p99={:?} p95={p95:?} p99={p99:?}",
                baseline[index][18], baseline[index][19]
            );
            assert!(
                p95 < baseline[index][18] * 20 + Duration::from_secs(2)
                    && p99 < baseline[index][19] * 20 + Duration::from_secs(2)
                    && p99 < Duration::from_secs(5),
                "tenant {tenant} probe budget exceeded"
            );
        }
        for worker in workers {
            worker.join().unwrap();
        }
        for source in &sources {
            let receipt = source.receipt.recv_timeout(WAIT).unwrap();
            assert!(receipt.complete && receipt.written_bytes == LENGTH, "{receipt:?}");
        }
    });
    report(&format!("downloads={concurrency}"), &before, &samples, 256 * MIB);
    for tenant in ["a", "b"] {
        download_tenant_probe(&addr, tenant);
    }
    stop(&mut process);
    for source in sources {
        source.join();
    }
}

#[test]
fn small_probes_during_concurrent_downloads() {
    let _guard = serialized();
    for count in [1, 4] {
        concurrent_downloads(count);
    }
}

#[test]
#[ignore = "scheduled: serialized 16 and 32 response concurrency profile"]
fn scheduled_small_probes_during_16_and_32_downloads() {
    let _guard = serialized();
    for count in [16, 32] {
        concurrent_downloads(count);
    }
}

/// Profile invalid JSON without dispatch, or several configured guardrail
/// rules over a long near-match. A separate positive proves the last byte can
/// trigger the rule, rather than merely exercising a permissive path.
fn cpu_variant(size: usize, variant: &str, count: usize) -> u64 {
    let mut input = if variant == "operations" {
        let mut prefix = String::from("{\"model\":\"old\",");
        for index in 0..7 {
            prefix.push_str(&format!("\"m{index}\":\"old\","));
        }
        prefix.push_str("\"pad\":\"");
        let mut body = prefix.into_bytes();
        body.resize(size - 2, b'x');
        body.extend_from_slice(b"\"}");
        body
    } else {
        json_body(size, "long")
    };
    let mut expected_status = 200;
    let mut expected = input.clone();
    let filters = if variant == "invalid_early" || variant == "invalid_late" {
        if variant == "invalid_early" {
            input[0] = b'!';
        } else {
            *input.last_mut().unwrap() = b'!';
        }
        expected_status = 400;
        "      - filter: json_body\n        conditions:\n          - when:\n              path_prefix: /bulk\n        max_body_bytes: 67108864\n        on_invalid: reject\n        request_extract:\n          - pointer: /model\n            metadata: model\n".to_owned()
    } else if variant == "operations" {
        let mut filters = "      - filter: json_body\n        conditions:\n          - when:\n              path_prefix: /bulk\n        max_body_bytes: 67108864\n        on_invalid: reject\n        request_replace:\n".to_owned();
        let mut search_from = 0;
        for index in 0..count {
            let offset = search_from
                + expected[search_from..]
                    .windows(3)
                    .position(|value| value == b"old")
                    .unwrap();
            expected[offset..offset + 3].copy_from_slice(b"new");
            search_from = offset + 3;
            let pointer = if index == 0 {
                "model".to_owned()
            } else {
                format!("m{}", index - 1)
            };
            filters.push_str(&format!("          - pointer: /{pointer}\n            value: new\n"));
        }
        filters
    } else {
        if variant == "near_match_positive" {
            let last_content = input.len() - 3;
            input[last_content] = b'y';
            expected_status = 403;
        }
        let mut filters = "      - filter: json_body_field\n        field: model\n        header: x-praxis-model\n        max_body_bytes: 67108864\n      - filter: guardrails\n        rules:\n".to_owned();
        for _ in 0..count {
            filters.push_str("          - target: body\n            contains: xxxxxxxxxxxxxxxxxxxxxxxxy\n");
        }
        filters
    };
    let iterations = if variant == "near_match_positive" {
        1
    } else {
        cpu_iterations(size)
    };
    let backend = sink(expected, iterations + 1);
    let clean = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut process = PraxisProcess::spawn(&config(port, backend.port, clean.port(), &filters, ""), &addr);
    assert_eq!(post_json(&addr, &input), expected_status, "warmup variant={variant}");
    if expected_status == 200 {
        assert_eq!(
            backend.receipt.recv_timeout(WAIT).unwrap().unwrap(),
            input.len() as u64,
            "backend must receive the complete expected body"
        );
    }
    let before = sample_process(process.pid()).unwrap();
    let (_, samples) = measure(process.pid(), || {
        for _ in 0..iterations {
            assert_eq!(
                post_json(&addr, &input),
                expected_status,
                "variant={variant} rules={count}"
            );
            if expected_status == 200 {
                assert_eq!(
                    backend.receipt.recv_timeout(WAIT).unwrap().unwrap(),
                    input.len() as u64,
                    "backend must receive the complete expected body"
                );
            }
        }
    });
    if expected_status != 200 {
        assert_sink_not_selected(&backend);
    }
    eprintln!("cpu variant={variant} rules={count} size={size} iterations={iterations}");
    report(
        &format!("cpu variant={variant} rules={count} size={size}"),
        &before,
        &samples,
        256 * MIB,
    );
    let ticks = samples
        .last()
        .unwrap()
        .cpu_ticks
        .unwrap()
        .saturating_sub(before.cpu_ticks.unwrap());
    probe(&addr);
    stop(&mut process);
    if expected_status != 200 {
        assert_sink_not_selected(&backend);
    }
    ticks
}

/// Observe backend accepts, including connections whose body never completed.
fn assert_sink_not_selected(backend: &Sink) {
    assert!(
        matches!(backend.accepted.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "rejected input must not select an upstream connection"
    );
    let (acknowledge, observed) = mpsc::channel();
    backend
        .fence
        .send(acknowledge)
        .expect("sink accept loop must remain live");
    observed
        .recv_timeout(WAIT)
        .expect("sink must drain its listener backlog");
    assert!(
        matches!(backend.accepted.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "rejected input must not select an upstream connection"
    );
}

#[test]
#[ignore = "scheduled: release-build CPU rule-count and invalid-input profiles"]
fn scheduled_cpu_rules_and_early_late_errors() {
    let _guard = serialized();
    for size in [MIB, 2 * MIB, 4 * MIB, 8 * MIB] {
        for variant in ["invalid_early", "invalid_late"] {
            let ticks = cpu_variant(size as usize, variant, 0);
            eprintln!("cpu-errors size={size} variant={variant} ticks={ticks}");
        }
        for count in [1, 4, 8] {
            let ticks = cpu_variant(size as usize, "near_match", count);
            eprintln!("cpu-rules size={size} rules={count} ticks={ticks}");
            let ticks = cpu_variant(size as usize, "operations", count);
            eprintln!("cpu-operations size={size} operations={count} ticks={ticks}");
        }
    }
    cpu_variant(MIB as usize, "near_match_positive", 1);
}

/// A full listener rejects new work and admits it again as soon as one
/// near-cap in-flight request finishes and releases its permit.
#[test]
fn near_cap_uploads_obey_listener_admission_and_release_permits() {
    let _guard = serialized();
    let body = json_body(1_048_576, "long");
    let backend = sink(body.clone(), 1);
    let clean = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let filters = "      - filter: json_body_field\n        field: model\n        header: x-praxis-model\n        max_body_bytes: 1048576\n";
    let yaml = config(port, backend.port, clean.port(), filters, "    max_connections: 1\n")
        .replace("max_request_bytes: 67108864", "max_request_bytes: 1048576");
    let mut process = PraxisProcess::spawn(&yaml, &addr);
    probe(&addr);
    thread::sleep(Duration::from_millis(300));
    let mut first = upload(&addr, body.len());
    first.write_all(&body[..body.len() - 1]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let response = http_get(&addr, "/probe", None).0;
        if response == 503 {
            break;
        }
        assert_eq!(response, 200);
        assert!(Instant::now() < deadline, "listener did not apply its admission limit");
        thread::sleep(Duration::from_millis(20));
    }
    first.write_all(&body[body.len() - 1..]).unwrap();
    assert_eq!(status(first), 200);
    assert_eq!(
        backend.receipt.recv_timeout(WAIT).unwrap().unwrap(),
        body.len() as u64,
        "backend must receive every upload byte"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let response = http_get(&addr, "/probe", None).0;
        if response == 200 {
            break;
        }
        assert_eq!(response, 503);
        assert!(Instant::now() < deadline, "listener did not release a completed permit");
        thread::sleep(Duration::from_millis(20));
    }
    stop(&mut process);
}

/// Count actual HTTP/2 DATA frames written while holding body bytes fixed.
#[test]
fn h2_frame_count_preserves_content_with_and_without_preread() {
    let _guard = serialized();
    for filters in [
        "",
        "      - filter: json_body_field\n        field: model\n        header: x-praxis-model\n",
    ] {
        let mut frame_counts = Vec::new();
        for chunk_size in [16_384, 128, 16] {
            let spec = PayloadSpec::padded(65_536, br#"{"model":"old","pad":""#, br#""}"#, b'x').unwrap();
            let backend = sink(spec.chunk(0, spec.len() as usize), 1);
            let clean = start_echo_backend();
            let port = free_port();
            let addr = format!("127.0.0.1:{port}");
            let mut process = PraxisProcess::spawn(&config(port, backend.port, clean.port(), filters, ""), &addr);
            let before = sample_process(process.pid()).unwrap();
            let (frames, samples) = measure(process.pid(), || {
                let mut client = start_h2_paused_uploads(&addr, spec.clone(), 1, chunk_size, true);
                assert_eq!(
                    client.ready.recv_timeout(WAIT).unwrap().unwrap_or_else(|error| panic!(
                        "H2 prefix failed: {error}; backend receipt: {:?}; proxy logs: {}",
                        backend.receipt.try_recv(),
                        process.logs()
                    )),
                    spec.len() - 1,
                    "prefix queued"
                );
                probe(&addr);
                client.resume();
                let result = client.result.recv_timeout(WAIT).unwrap().unwrap();
                assert_eq!(result.responses.len(), 1, "one complete stream");
                let response = &result.responses[0];
                assert_eq!(response.status, Some(200), "{response:?}");
                assert!(response.end_stream && response.abort.is_none(), "{response:?}");
                assert!(
                    result.empty_data_frames > 0,
                    "independent H2 probe must send empty END_STREAM DATA"
                );
                assert_eq!(
                    backend.receipt.recv_timeout(WAIT).unwrap().unwrap(),
                    spec.len(),
                    "all bytes must reach backend"
                );
                assert_eq!(
                    backend.tenants.recv_timeout(WAIT).unwrap().as_deref(),
                    Some("tenant-0"),
                    "tenant header must survive H2"
                );
                eprintln!(
                    "h2 chunk={chunk_size} data_frames={} empty_data_frames={}",
                    result.data_frames, result.empty_data_frames
                );
                result.data_frames
            });
            report(
                &format!("h2 frames chunk={chunk_size} preread={}", !filters.is_empty()),
                &before,
                &samples,
                128 * MIB,
            );
            frame_counts.push(frames);
            probe(&addr);
            stop(&mut process);
        }
        assert!(
            frame_counts[0] < frame_counts[1] && frame_counts[1] < frame_counts[2],
            "actual DATA frame counts must increase: {frame_counts:?}"
        );
    }
}

/// Open one H1 upload with an explicit tenant, keeping its final byte unsent.
fn tenant_upload(addr: &str, body: &[u8], tenant: &str) -> TcpStream {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    write!(stream, "POST /bulk HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nX-Resource-Tenant: {tenant}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
    stream.write_all(&body[..body.len() - 1]).unwrap();
    stream
}

/// Mix H1 connections and H2 streams while both protocols serve probes.
fn mixed_protocol_uploads(concurrency: usize) {
    let spec = PayloadSpec::padded(MIB, br#"{"model":"old","pad":""#, br#""}"#, b'x').unwrap();
    let body = spec.chunk(0, spec.len() as usize);
    let backend = sink(body.clone(), concurrency * 2);
    let clean = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let filters = "      - filter: json_body_field\n        field: model\n        header: x-praxis-model\n        max_body_bytes: 1048576\n";
    let listener = format!("    max_connections: {}\n", concurrency * 2 + 8);
    let yaml = config(port, backend.port, clean.port(), filters, &listener)
        .replace("  threads: 2\n", "  threads: 2\n  max_memory_bytes: 536870912\n")
        .replace("max_request_bytes: 67108864", "max_request_bytes: 1048576");
    let mut process = PraxisProcess::spawn(&yaml, &addr);
    let mut baseline = Vec::new();
    for _ in 0..20 {
        let start = Instant::now();
        probe(&addr);
        baseline.push(start.elapsed());
    }
    baseline.sort();
    let before = sample_process(process.pid()).unwrap();
    let (_, samples) = measure(process.pid(), || {
        let mut h1 = Vec::new();
        for index in 0..concurrency {
            h1.push(tenant_upload(&addr, &body, &format!("h1-{}", index % 2)));
        }
        let mut h2 = start_h2_paused_uploads(&addr, spec.clone(), concurrency, 16_384, true);
        let deadline = Instant::now() + WAIT;
        loop {
            match h2.ready.recv_timeout(Duration::from_millis(50)) {
                Ok(result) => {
                    assert_eq!(
                        result.unwrap(),
                        (spec.len() - 1) * concurrency as u64,
                        "all H2 prefixes queued"
                    );
                    break;
                },
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    probe(&addr);
                    assert!(Instant::now() < deadline, "H2 prefixes timed out");
                },
                Err(error) => panic!("H2 setup failed: {error}"),
            }
        }
        let mut latencies = Vec::new();
        for _ in 0..20 {
            let start = Instant::now();
            probe(&addr);
            latencies.push(start.elapsed());
        }
        latencies.sort();
        let p95 = latencies[18];
        let p99 = latencies[19];
        eprintln!(
            "mixed h1={concurrency} h2={concurrency} baseline_p95={:?} baseline_p99={:?} p95={p95:?} p99={p99:?}",
            baseline[18], baseline[19]
        );
        assert!(
            p95 < baseline[18] * 20 + Duration::from_secs(2)
                && p99 < baseline[19] * 20 + Duration::from_secs(2)
                && p99 < Duration::from_secs(5),
            "mixed probe budget exceeded"
        );
        h2.resume();
        for stream in &mut h1 {
            stream.write_all(&body[body.len() - 1..]).unwrap();
        }
        for stream in h1 {
            assert_eq!(status(stream), 200, "H1 upload must succeed");
        }
        let result = h2.result.recv_timeout(WAIT).unwrap().unwrap();
        assert_eq!(result.responses.len(), concurrency, "every H2 response must arrive");
        assert!(
            result
                .responses
                .iter()
                .all(|response| response.status == Some(200) && response.end_stream && response.abort.is_none()),
            "{:?}",
            result.responses
        );
        assert!(result.empty_data_frames > 0, "H2 control must include empty DATA");
        let mut tenants = Vec::new();
        for _ in 0..concurrency * 2 {
            assert_eq!(
                backend.receipt.recv_timeout(WAIT).unwrap().unwrap(),
                spec.len(),
                "all bytes must reach backend"
            );
            tenants.push(backend.tenants.recv_timeout(WAIT).unwrap().unwrap());
        }
        let mut expected = Vec::new();
        for index in 0..concurrency {
            expected.push(format!("h1-{}", index % 2));
            expected.push(format!("tenant-{}", index % 2));
        }
        tenants.sort();
        expected.sort();
        assert_eq!(
            tenants, expected,
            "each protocol and tenant must reach the selected backend"
        );
    });
    report(
        &format!("mixed protocols concurrency={concurrency}"),
        &before,
        &samples,
        256 * MIB,
    );
    probe(&addr);
    stop(&mut process);
}

#[test]
fn mixed_h1_h2_uploads_preserve_tenants_and_probe_progress() {
    let _guard = serialized();
    for count in [1, 4] {
        mixed_protocol_uploads(count);
    }
}

#[test]
#[ignore = "scheduled: serialized mixed-protocol concurrency profile"]
fn scheduled_mixed_h1_h2_16_and_32_uploads() {
    let _guard = serialized();
    for count in [16, 32] {
        mixed_protocol_uploads(count);
    }
}

/// A rapid tiny-frame flood is subject to the H2 transport's explicit
/// connection-level overhead guard; its failure must not poison a new client.
#[cfg(feature = "pingora")]
#[test]
fn h2_tiny_frame_flood_is_bounded_by_transport_guard() {
    let _guard = serialized();
    let spec = PayloadSpec::padded(262_144, br#"{"model":"old","pad":""#, br#""}"#, b'x').unwrap();
    let backend = start_counting_backend(spec.clone(), "flood", spec.len());
    let clean = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut process = PraxisProcess::spawn_with_env(
        &config(port, backend.port, clean.port(), "", ""),
        &addr,
        &[("RUST_LOG", "debug")],
    );
    let before = sample_process(process.pid()).unwrap();
    let (_, samples) = measure(process.pid(), || {
        let client = start_h2_paused_uploads(&addr, spec.clone(), 1, 128, false);
        let failure = client
            .ready
            .recv_timeout(WAIT)
            .unwrap()
            .expect_err("unpaced flood must hit the transport guard");
        eprintln!("H2 flood outcome: {failure}");
        assert!(
            failure.contains("BrokenPipe"),
            "affected stream must report its transport failure: {failure}"
        );
        let mut cursor = ProcessLogCursor::default();
        let mut logs = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let chunk = process.logs_since(&mut cursor, 65_536).unwrap();
            logs.extend(chunk.stdout);
            logs.extend(chunk.stderr);
            assert!(logs.len() < 1_048_576, "debug log budget exhausted");
            let text = String::from_utf8_lossy(&logs);
            if text.contains("too_many_data_frames") && text.contains("ENHANCE_YOUR_CALM") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "server did not report the expected H2 GOAWAY reason"
            );
            thread::sleep(Duration::from_millis(20));
        }
        let receipt = backend.receipt.recv_timeout(WAIT).unwrap();
        eprintln!(
            "H2 flood backend bytes={} verified={} completion={:?} abort={:?}",
            receipt.bytes, receipt.verified_bytes, receipt.completion, receipt.abort
        );
        assert!(
            receipt.bytes > 0 && receipt.bytes < spec.len(),
            "flood must not complete: {receipt:?}"
        );
        assert_eq!(receipt.verified_bytes, receipt.bytes, "all forwarded bytes must match");
        assert_eq!(receipt.mismatch, None, "no corrupted forwarded bytes");
        assert!(
            receipt.completion.is_none() && receipt.abort.is_some(),
            "upstream must see an incomplete upload: {receipt:?}"
        );
        let control = praxis_test_utils::h2c_get(&addr, "/probe", None);
        assert_eq!(
            (control.0, control.1.as_str()),
            (200, ""),
            "a new H2 connection must survive the flood"
        );
        probe(&addr);
    });
    report("h2 frame flood", &before, &samples, 128 * MIB);
    stop(&mut process);
    backend.join();
}

/// Read a Linux procfs status size in bytes, failing if it is unavailable.
fn proc_status_bytes(pid: u32, field: &str) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read live proxy status");
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .expect("required procfs field");
    let mut fields = value.split_whitespace();
    let kib = fields
        .next()
        .expect("procfs size")
        .parse::<u64>()
        .expect("numeric procfs size");
    assert_eq!(fields.next(), Some("kB"), "procfs size units");
    kib * 1024
}

/// Confirm the child actually has the requested address-space limit and
/// sufficient startup headroom; failed limits or an OS-killed proxy fail.
fn assert_metadata_limit(process: &PraxisProcess) -> u64 {
    const LIMIT: u64 = 1_006_632_960; // 960 MiB
    const HEADROOM: u64 = 67_108_864; // 64 MiB
    let limits = std::fs::read_to_string(format!("/proc/{}/limits", process.pid())).expect("read proxy limits");
    let row = limits
        .lines()
        .find_map(|line| line.strip_prefix("Max address space"))
        .expect("address-space limit row");
    let soft = row
        .split_whitespace()
        .next()
        .expect("soft address-space limit")
        .parse::<u64>()
        .expect("numeric address-space limit");
    assert_eq!(soft, LIMIT, "the proxy must run below the advertised 1 GiB body length");
    let peak = proc_status_bytes(process.pid(), "VmPeak:");
    assert!(
        peak <= LIMIT - HEADROOM,
        "proxy startup leaves insufficient address-space headroom: {peak}"
    );
    peak
}

/// One reusable bodyless upstream with observable requests and interruptible
/// accept/read operations, so failed assertions cannot leave a worker behind.
struct MetadataPeer {
    /// Listener port.
    port: u16,
    /// Request lines observed before each response.
    requests: Receiver<String>,
    /// Stop the accept loop.
    stop: Arc<AtomicBool>,
    /// Connected socket clone for interrupting a stalled request.
    active: Arc<Mutex<Option<TcpStream>>>,
    /// Listener and response worker.
    worker: Option<JoinHandle<()>>,
}

impl Drop for MetadataPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
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

/// Start a peer serving HEAD, 304 and deliberately invalid 204 responses.
fn metadata_peer() -> MetadataPeer {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let active = Arc::new(Mutex::new(None::<TcpStream>));
    let flag = Arc::clone(&stop);
    let socket = Arc::clone(&active);
    let (tx, requests) = mpsc::channel();
    let worker = thread::spawn(move || {
        while !flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let mut guard = socket.lock().unwrap();
                    if flag.load(Ordering::Relaxed) {
                        break;
                    }
                    *guard = Some(stream.try_clone().unwrap());
                    drop(guard);
                    let request = metadata_response(stream);
                    drop(socket.lock().unwrap().take());
                    let _sent = tx.send(request);
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                Err(error) => panic!("metadata peer accept: {error}"),
            }
        }
    });
    MetadataPeer {
        port,
        requests,
        stop,
        active,
        worker: Some(worker),
    }
}

/// Parse a bounded request head and respond without allocating its declared
/// representation length. The connection is closed after every response.
fn metadata_response(stream: TcpStream) -> String {
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reader = BufReader::new(stream);
    let mut request = String::new();
    assert_ne!(reader.read_line(&mut request).unwrap(), 0, "request line must arrive");
    let mut head_bytes = request.len();
    let mut conditional = false;
    loop {
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0, "request headers must finish");
        conditional |= line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("if-none-match") && value.trim() == "\"payload-metadata\""
        });
        head_bytes += line.len();
        assert!(head_bytes <= 65_536, "peer request headers are bounded");
        if line == "\r\n" {
            break;
        }
    }
    let status = if request.starts_with("HEAD /bulk/head ") {
        "200 OK"
    } else if request.starts_with("GET /bulk/not-modified ") {
        assert!(conditional, "304 fixture requires its matching request validator");
        "304 Not Modified"
    } else if request.starts_with("GET /bulk/no-content ") {
        "204 No Content"
    } else {
        panic!("unexpected metadata request: {request:?}");
    };
    let validator = if conditional {
        "ETag: \"payload-metadata\"\r\n"
    } else {
        ""
    };
    write!(reader.get_mut(), "HTTP/1.1 {status}\r\n{validator}Content-Type: text/event-stream\r\nContent-Length: 1073741824\r\nConnection: close\r\n\r\n").unwrap();
    request
}

/// Require EOF after the expected final response; no pipelined sentinel may
/// be interpreted as another response on the same connection.
fn assert_no_more_response(connection: &mut BufReader<TcpStream>) {
    let mut extra = [0_u8; 1];
    match connection.read(&mut extra) {
        Ok(0) => {},
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {},
        other => panic!("unexpected extra downstream response bytes: {other:?}"),
    }
}

/// HEAD/304 hypothetical sizes are metadata, not a 1 GiB response allocation;
/// an illegal 204 is either sanitized or rejected without desynchronization.
#[test]
fn bodyless_huge_lengths_stay_bounded_and_preserve_connection_framing() {
    let _guard = serialized();
    let peer = metadata_peer();
    let clean = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let yaml =
        config(port, peer.port, clean.port(), "", "").replace("max_response_bytes: null", "max_response_bytes: 1024");
    let mut process = PraxisProcess::spawn_with_ulimit(&yaml, &addr, Some("-S -v 983040"));
    let baseline_vm = assert_metadata_limit(&process);
    let before = sample_process(process.pid()).expect("proxy must survive startup");
    let (_, samples) = measure(process.pid(), || {
        for _ in 0..2 {
            for (method, path, expected) in [
                ("HEAD", "/bulk/head", 200),
                ("GET", "/bulk/not-modified", 304),
                ("GET", "/bulk/no-content", 204),
            ] {
                let mut stream = TcpStream::connect(&addr).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let close = if expected == 204 { "Connection: close\r\n" } else { "" };
                let conditional = if expected == 304 {
                    "If-None-Match: \"payload-metadata\"\r\n"
                } else {
                    ""
                };
                write!(
                    stream,
                    "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{conditional}{close}\r\n"
                )
                .unwrap();
                let mut connection = BufReader::new(stream);
                let response = read_h1_response(&mut connection, method == "HEAD", 4096, |_| Ok(()));
                if expected == 204 && response.status == Some(502) {
                    assert!(
                        response.completion.is_some() && response.abort.is_none(),
                        "invalid 204 rejection must complete: {response:?}"
                    );
                    assert_no_more_response(&mut connection);
                    probe(&addr);
                } else {
                    assert_eq!(response.status, Some(expected), "{response:?}");
                    assert_eq!(
                        response.completion,
                        Some(praxis_test_utils::H1Completion::Headers),
                        "bodyless framing: {response:?}"
                    );
                    assert_eq!(response.body_bytes, 0, "bodyless responses must deliver no body");
                    let length = response
                        .headers
                        .iter()
                        .find(|(name, _)| name == "content-length")
                        .map(|(_, value)| value.as_str());
                    if expected == 204 {
                        assert!(
                            length.is_none() && !response.headers.iter().any(|(name, _)| name == "transfer-encoding"),
                            "invalid 204 framing must be removed"
                        );
                        assert_no_more_response(&mut connection);
                        probe(&addr);
                    } else {
                        assert_eq!(length, Some("1073741824"), "hypothetical length must remain metadata");
                        connection
                            .get_mut()
                            .write_all(b"GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                            .unwrap();
                        let next = read_h1_response(&mut connection, false, 0, |_| Ok(()));
                        assert_eq!(next.status, Some(200), "following response: {next:?}");
                        assert!(
                            next.completion.is_some() && next.abort.is_none(),
                            "following response must complete: {next:?}"
                        );
                        assert_no_more_response(&mut connection);
                    }
                }
                let request = peer.requests.recv_timeout(WAIT).unwrap();
                assert!(
                    request.starts_with(&format!("{method} {path} ")),
                    "selected peer must receive the intended request: {request:?}"
                );
            }
        }
    });
    report("bodyless metadata", &before, &samples, 128 * MIB);
    let peak_vm = proc_status_bytes(process.pid(), "VmPeak:");
    eprintln!("bodyless virtual memory: startup_peak={baseline_vm} final_peak={peak_vm} limit=1006632960");
    assert!(peak_vm < 1_006_632_960, "address-space limit must not be exceeded");
    probe(&addr);
    stop(&mut process);
}

/// Exercise bounded oversized trailer metadata repeatedly while the actual
/// built-in pre-read filter prevents dispatch of incomplete requests.
#[cfg(feature = "pingora")]
#[test]
fn oversized_trailer_failures_preserve_resources_and_never_dispatch() {
    let _guard = serialized();
    let spec = PayloadSpec::padded(1, b"a", b"", b'x').unwrap();
    let backend = start_counting_backend(spec, "trailer", 1);
    let clean = start_echo_backend();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let filters = "      - filter: json_body_field\n        field: model\n        header: x-praxis-model\n";
    let yaml = config(port, backend.port, clean.port(), filters, "")
        .replace("max_request_bytes: 67108864", "max_request_bytes: 16")
        .replace("max_response_bytes: null", "max_response_bytes: 1024");
    let mut process = PraxisProcess::spawn_with_ulimit(&yaml, &addr, Some("-S -v 983040"));
    let baseline_vm = assert_metadata_limit(&process);
    let before = sample_process(process.pid()).expect("proxy must survive startup");
    let (_, samples) = measure(process.pid(), || {
        for _ in 0..4 {
            let mut stream = TcpStream::connect(&addr).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            stream.write_all(b"POST /bulk HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\na\r\n0\r\nX-Large: ").unwrap();
            let mut trailer = vec![b'x'; 65_537];
            trailer.extend_from_slice(b"\r\n\r\nGET /probe HTTP/1.1\r\nHost: localhost\r\n\r\n");
            stream
                .write_all(&trailer)
                .expect("oversized trailer and pipelined sentinel must be accepted by the socket");
            let mut connection = BufReader::new(stream);
            let response = read_h1_response(&mut connection, false, 4096, |_| Ok(()));
            assert_eq!(
                response.status,
                Some(500),
                "Pingora trailer parser failure: {response:?}"
            );
            assert!(
                response.completion.is_some() && response.abort.is_none(),
                "rejection must complete: {response:?}"
            );
            assert_no_more_response(&mut connection);
            assert_eq!(
                backend.accepted.try_recv().unwrap_err(),
                mpsc::TryRecvError::Empty,
                "incomplete metadata must not dispatch upstream"
            );
            probe(&addr);
        }
    });
    report("oversized trailer failures", &before, &samples, 128 * MIB);
    let peak_vm = proc_status_bytes(process.pid(), "VmPeak:");
    eprintln!("oversized trailer virtual memory: startup_peak={baseline_vm} final_peak={peak_vm} limit=1006632960");
    assert!(peak_vm < 1_006_632_960, "address-space limit must not be exceeded");
    let ceiling = before.open_fds.unwrap() + 12;
    assert!(
        process.wait_open_fds_at_most(ceiling, Duration::from_secs(5)) <= ceiling,
        "descriptors must settle"
    );
    probe(&addr);
    stop(&mut process);
    backend.join();
}
