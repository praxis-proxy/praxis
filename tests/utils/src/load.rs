// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Test utilities for driving concurrent HTTP/1.1 load at a proxy.
//!
//! Clients are plain threads over raw sockets so every connection, reuse,
//! and close is explicit, which descriptor accounting tests depend on.

use std::{
    collections::BTreeMap,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::TcpStream,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Per-socket read and write timeout for load clients.
const IO_TIMEOUT: Duration = Duration::from_secs(20);

/// Read timeout for requests held in flight by [`open_requests`], whose
/// backends answer within seconds when the proxy admits them at all.
const IN_FLIGHT_TIMEOUT: Duration = Duration::from_secs(5);

// -----------------------------------------------------------------------------
// LoadReport
// -----------------------------------------------------------------------------

/// Outcome counts for a batch of requests.
#[derive(Debug, Default)]
pub struct LoadReport {
    /// Transport failures (refused, reset, timed out, or malformed), with the
    /// error text.
    pub failures: Vec<String>,

    /// Response count by status code.
    pub statuses: BTreeMap<u16, usize>,
}

impl LoadReport {
    /// Responses with `status`.
    pub fn count(&self, status: u16) -> usize {
        self.statuses.get(&status).copied().unwrap_or(0)
    }

    /// Total requests attempted.
    pub fn total(&self) -> usize {
        self.statuses.values().sum::<usize>() + self.failures.len()
    }

    /// Whether every request got a response with one of `allowed`.
    pub fn only(&self, allowed: &[u16]) -> bool {
        self.failures.is_empty() && self.statuses.keys().all(|status| allowed.contains(status))
    }

    /// Merge another report into this one.
    fn absorb(&mut self, other: Self) {
        self.failures.extend(other.failures);
        for (status, count) in other.statuses {
            *self.statuses.entry(status).or_default() += count;
        }
    }
}

// -----------------------------------------------------------------------------
// Load
// -----------------------------------------------------------------------------

/// Run `clients` concurrent clients against `addr`, each sending
/// `requests_per_client` `GET path` requests, starting together.
///
/// With `keep_alive`, a client reuses its connection until the proxy closes
/// it and then reconnects; otherwise every request uses a new connection.
///
/// # Panics
///
/// Panics if a client thread panics.
pub fn concurrent_gets(
    addr: &str,
    path: &str,
    clients: usize,
    requests_per_client: usize,
    keep_alive: bool,
) -> LoadReport {
    let barrier = Arc::new(Barrier::new(clients));
    let handles: Vec<_> = std::iter::repeat_with(|| {
        let barrier = Arc::clone(&barrier);
        let addr = addr.to_owned();
        let path = path.to_owned();
        std::thread::spawn(move || {
            barrier.wait();
            run_client(&addr, &path, requests_per_client, keep_alive)
        })
    })
    .take(clients)
    .collect();

    let mut report = LoadReport::default();
    for handle in handles {
        report.absorb(handle.join().expect("load client thread"));
    }
    report
}

// -----------------------------------------------------------------------------
// Continuous load
// -----------------------------------------------------------------------------

/// Continuous HTTP/1.1 and HTTP/2 load driver.
pub struct ContinuousLoadDriver {
    /// Signal that tells workers to stop.
    stop: Arc<AtomicBool>,
    /// Worker join handles.
    handles: Vec<std::thread::JoinHandle<()>>,
    /// Counters shared with workers.
    report: Arc<ContinuousLoadReport>,
}

/// Mutable request counters shared by continuous load workers.
#[derive(Default)]
pub struct ContinuousLoadReport {
    /// Successful HTTP/1.1 responses.
    pub http1: AtomicU64,
    /// Successful HTTP/2 responses.
    pub http2: AtomicU64,
    /// Successful HTTPS responses.
    pub https: AtomicU64,
    /// Failed requests.
    pub failures: AtomicU64,
    /// First failure message.
    pub first_failure: std::sync::Mutex<Option<String>>,
}

/// Immutable result returned when continuous load stops.
#[derive(Debug)]
pub struct ContinuousLoadSnapshot {
    /// Successful HTTP/1.1 responses.
    pub http1: u64,
    /// Successful HTTP/2 responses.
    pub http2: u64,
    /// Successful HTTPS responses.
    pub https: u64,
    /// Failed requests.
    pub failures: u64,
    /// First failure message.
    pub first_failure: Option<String>,
}

impl ContinuousLoadSnapshot {
    /// Total requests attempted.
    pub fn total(&self) -> u64 {
        self.http1 + self.http2 + self.https + self.failures
    }
}

impl ContinuousLoadDriver {
    /// Starts two keep-alive HTTP/1.1 workers and one HTTP/2 worker.
    ///
    /// Every failed exchange is counted, including connection-close races.
    pub fn start(endpoint: &str) -> Self {
        Self::start_workers(endpoint, None)
    }

    /// Starts HTTP/1.1, HTTP/2, and HTTPS keep-alive load workers.
    pub fn start_with_https(
        http_endpoint: &str,
        https_endpoint: &str,
        client_config: Arc<rustls::ClientConfig>,
    ) -> Self {
        Self::start_workers(http_endpoint, Some((https_endpoint.to_owned(), client_config)))
    }

    /// Spawns the selected continuous-load workers.
    fn start_workers(endpoint: &str, https: Option<(String, Arc<rustls::ClientConfig>)>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let report = Arc::new(ContinuousLoadReport::default());
        let mut handles = std::iter::repeat_with(|| spawn_worker(&stop, &report, endpoint, http1_worker))
            .take(2)
            .chain(std::iter::once(spawn_worker(&stop, &report, endpoint, http2_worker)))
            .collect::<Vec<_>>();
        if let Some((https_endpoint, client_config)) = https {
            let stop = Arc::clone(&stop);
            let report = Arc::clone(&report);
            handles.push(std::thread::spawn(move || {
                https_worker(&stop, &report, &https_endpoint, &client_config);
            }));
        }
        Self { stop, handles, report }
    }

    /// Stops workers and returns their final counters.
    ///
    /// # Panics
    ///
    /// Panics if the report mutex is poisoned.
    pub fn stop(mut self) -> ContinuousLoadSnapshot {
        self.join_workers();
        self.snapshot()
    }

    /// Returns the current counters without stopping the workers.
    ///
    /// # Panics
    ///
    /// Panics if the report mutex is poisoned.
    pub fn snapshot(&self) -> ContinuousLoadSnapshot {
        ContinuousLoadSnapshot {
            http1: self.report.http1.load(Ordering::SeqCst),
            http2: self.report.http2.load(Ordering::SeqCst),
            https: self.report.https.load(Ordering::SeqCst),
            failures: self.report.failures.load(Ordering::SeqCst),
            first_failure: self.report.first_failure.lock().expect("load report").clone(),
        }
    }

    /// Stops and joins every worker, counting unexpected worker panics.
    fn join_workers(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for handle in self.handles.drain(..) {
            if handle.join().is_err() {
                self.report.failure("load worker panicked".to_owned());
            }
        }
    }
}

impl Drop for ContinuousLoadDriver {
    fn drop(&mut self) {
        self.join_workers();
    }
}

/// Spawns a continuous worker with its owned copies of shared state.
fn spawn_worker(
    stop: &Arc<AtomicBool>,
    report: &Arc<ContinuousLoadReport>,
    endpoint: &str,
    worker: fn(&AtomicBool, &ContinuousLoadReport, &str),
) -> std::thread::JoinHandle<()> {
    let stop = Arc::clone(stop);
    let report = Arc::clone(report);
    let endpoint = endpoint.to_owned();
    std::thread::spawn(move || worker(&stop, &report, &endpoint))
}

/// Runs persistent HTTP/1.1 keepalive requests until stopped.
fn http1_worker(stop: &AtomicBool, report: &ContinuousLoadReport, endpoint: &str) {
    let mut stream = None;
    while !stop.load(Ordering::Relaxed) {
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| http1_request(endpoint, &mut stream)));
        match result {
            Ok(Ok(response)) if healthy_response(&response) => {
                report.http1.fetch_add(1, Ordering::Relaxed);
            },
            Ok(Ok(response)) => {
                report.failure(format!("HTTP/1.1 returned {response}"));
                stream = None;
            },
            Ok(Err(error)) => {
                report.failure(format!("HTTP/1.1 transport: {error}"));
                stream = None;
            },
            Err(_) => {
                report.failure("HTTP/1.1 client panicked".to_owned());
                stream = None;
            },
        }
    }
}

/// Sends one persistent HTTP/1.1 request, reconnecting when `stream` is unset.
fn http1_request(endpoint: &str, stream: &mut Option<TcpStream>) -> Result<String, String> {
    if stream.is_none() {
        let address = endpoint.parse().map_err(|error| format!("invalid endpoint: {error}"))?;
        *stream = Some(TcpStream::connect_timeout(&address, IO_TIMEOUT).map_err(|error| error.to_string())?);
    }
    let stream = stream.as_mut().expect("connected stream");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| error.to_string())?;
    Ok(crate::net::http_send_on_connection(
        stream,
        "GET /healthy HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
    ))
}

/// Checks status and the complete fixed-length health response body.
fn healthy_response(response: &str) -> bool {
    response.split_once("\r\n\r\n").is_some_and(|(headers, body)| {
        headers
            .lines()
            .next()
            .is_some_and(|status| status.starts_with("HTTP/1.1 200 "))
            && body.trim() == "ok"
            && headers.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            }) == Some(body.len())
    })
}

/// Runs prior-knowledge HTTP/2 requests until stopped.
fn http2_worker(stop: &AtomicBool, report: &ContinuousLoadReport, endpoint: &str) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("HTTP/2 load runtime");
    while !stop.load(Ordering::Relaxed) {
        let result = runtime.block_on(async { tokio::time::timeout(IO_TIMEOUT, http2_request(endpoint)).await });
        match result {
            Ok(Ok(())) => {
                report.http2.fetch_add(1, Ordering::Relaxed);
            },
            Ok(Err(error)) => report.failure(format!("HTTP/2 transport: {error}")),
            Err(error) => report.failure(format!("HTTP/2 timeout: {error}")),
        }
    }
}

/// Runs HTTPS health requests until stopped.
fn https_worker(
    stop: &AtomicBool,
    report: &ContinuousLoadReport,
    endpoint: &str,
    client_config: &Arc<rustls::ClientConfig>,
) {
    while !stop.load(Ordering::Relaxed) {
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            crate::net::https_get(endpoint, "/healthy", client_config)
        }));
        match result {
            Ok((status, body)) if status == 200 && body.trim() == "ok" => {
                report.https.fetch_add(1, Ordering::Relaxed);
            },
            Ok((status, body)) => {
                report.failure(format!("HTTPS returned {status} {body}"));
            },
            Err(_) => report.failure("HTTPS client panicked".to_owned()),
        }
    }
}

/// Makes one HTTP/2 exchange, polling the connection alongside the request.
async fn http2_request(endpoint: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let stream = tokio::net::TcpStream::connect(endpoint).await?;
    let (mut client, connection) = h2::client::handshake(stream).await?;
    let exchange = async move {
        let request = http::Request::get("/healthy").header("host", "localhost").body(())?;
        let (response, _) = client.send_request(request, true)?;
        let response = response.await?;
        let status = response.status();
        let mut stream = response.into_body();
        let mut body = Vec::new();
        while let Some(chunk) = stream.data().await {
            let chunk = chunk?;
            body.extend_from_slice(&chunk);
            stream.flow_control().release_capacity(chunk.len())?;
        }
        if status != http::StatusCode::OK || body != b"ok" {
            return Err(format!("unexpected health response: {status} {body:?}").into());
        }
        Ok(())
    };
    tokio::pin!(connection, exchange);
    tokio::select! {
        result = &mut exchange => result,
        result = &mut connection => {
            result?;
            exchange.await
        },
    }
}

impl ContinuousLoadReport {
    /// Records a failed request and retains the first failure message.
    fn failure(&self, message: String) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        let mut first = self.first_failure.lock().expect("load report");
        if first.is_none() {
            *first = Some(message);
        }
    }
}

#[cfg(test)]
mod continuous_tests {
    use super::*;

    #[test]
    fn health_response_requires_complete_success_body() {
        assert!(healthy_response("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
        for response in [
            "",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\no",
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nok",
            "HTTP/1.1 500 Error\r\n\r\nok",
        ] {
            assert!(!healthy_response(response), "accepted {response:?}");
        }
    }

    #[test]
    fn total_includes_failed_requests() {
        let snapshot = ContinuousLoadSnapshot {
            http1: 2,
            http2: 3,
            https: 4,
            failures: 1,
            first_failure: None,
        };
        assert_eq!(snapshot.total(), 10);
    }

    #[test]
    fn connection_closure_is_counted_without_retry() {
        for worker in [http1_worker, http2_worker] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
            let endpoint = listener.local_addr().expect("address").to_string();
            let stop = Arc::new(AtomicBool::new(false));
            let server_stop = Arc::clone(&stop);
            let server = std::thread::spawn(move || {
                let (stream, _) = listener.accept().expect("accept");
                server_stop.store(true, Ordering::SeqCst);
                drop(stream);
            });
            let report = ContinuousLoadReport::default();
            worker(&stop, &report, &endpoint);
            server.join().expect("server");
            assert_eq!(report.failures.load(Ordering::SeqCst), 1);
        }
    }
}

/// Open `count` connections to `addr` and send one `GET path` on each
/// without reading the responses, so every exchange stays in flight.
///
/// # Panics
///
/// Panics if a connection cannot be opened or written.
pub fn open_requests(addr: &str, path: &str, count: usize) -> Vec<TcpStream> {
    std::iter::repeat_with(|| {
        let mut stream = TcpStream::connect(addr).expect("connect");
        stream.set_read_timeout(Some(IN_FLIGHT_TIMEOUT)).expect("read timeout");
        stream.write_all(request(path, true).as_bytes()).expect("write request");
        stream
    })
    .take(count)
    .collect()
}

/// Open `count` keep-alive connections to `addr`, complete one `GET path` on
/// each, and return them still open and idle.
///
/// # Panics
///
/// Panics if a connection cannot be opened or its request fails.
pub fn idle_keepalive_connections(addr: &str, path: &str, count: usize) -> Vec<TcpStream> {
    std::iter::repeat_with(|| {
        let mut conn = None;
        let status = send(addr, path, true, &mut conn).expect("keep-alive request");
        assert_eq!(status, 200, "warm-up request on an idle keep-alive connection");
        conn.expect("the proxy kept the connection alive").into_inner()
    })
    .take(count)
    .collect()
}

/// Whether the peer has closed `stream`, without blocking.
///
/// # Panics
///
/// Panics if the socket mode cannot be changed.
pub fn is_closed_by_peer(stream: &TcpStream) -> bool {
    stream.set_nonblocking(true).expect("nonblocking");
    let mut probe = [0_u8; 1];
    let closed = match stream.peek(&mut probe) {
        Ok(read) => read == 0,
        Err(err) => err.kind() != std::io::ErrorKind::WouldBlock,
    };
    stream.set_nonblocking(false).expect("blocking");
    closed
}

/// Read each of `streams` to its end, returning the raw response text and
/// whether the peer closed the connection (rather than the read timing out).
pub fn read_raw_responses(streams: Vec<TcpStream>) -> Vec<(String, bool)> {
    streams
        .into_iter()
        .map(|mut stream| {
            let mut raw = Vec::new();
            let closed = stream.read_to_end(&mut raw).is_ok();
            (String::from_utf8_lossy(&raw).into_owned(), closed)
        })
        .collect()
}

/// Read one response from each of `streams` into a report.
pub fn collect_responses(streams: Vec<TcpStream>) -> LoadReport {
    let mut report = LoadReport::default();
    for stream in streams {
        match read_response(&mut BufReader::new(stream)) {
            Ok((status, _)) => *report.statuses.entry(status).or_default() += 1,
            Err(err) => report.failures.push(err),
        }
    }
    report
}

// -----------------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------------

/// One client's sequential requests.
fn run_client(addr: &str, path: &str, requests: usize, keep_alive: bool) -> LoadReport {
    let mut report = LoadReport::default();
    let mut conn: Option<BufReader<TcpStream>> = None;
    for _ in 0..requests {
        let outcome = send(addr, path, keep_alive, &mut conn);
        match outcome {
            Ok(status) => *report.statuses.entry(status).or_default() += 1,
            Err(err) => {
                conn = None;
                report.failures.push(err);
            },
        }
    }
    report
}

/// Send one request, reusing `conn` when open, and keep it open only when
/// both sides allow reuse.
fn send(addr: &str, path: &str, keep_alive: bool, conn: &mut Option<BufReader<TcpStream>>) -> Result<u16, String> {
    let mut reader = if let Some(reader) = conn.take() {
        reader
    } else {
        let stream = TcpStream::connect(addr).map_err(|err| format!("connect: {err}"))?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|err| err.to_string())?;
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(|err| err.to_string())?;
        BufReader::new(stream)
    };
    reader
        .get_mut()
        .write_all(request(path, !keep_alive).as_bytes())
        .map_err(|err| format!("write: {err}"))?;
    let (status, reusable) = read_response(&mut reader)?;
    if keep_alive && reusable {
        *conn = Some(reader);
    }
    Ok(status)
}

/// An HTTP/1.1 `GET` for `path`, asking to close when `close` is set.
fn request(path: &str, close: bool) -> String {
    let connection = if close { "close" } else { "keep-alive" };
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: {connection}\r\n\r\n")
}

/// Read one response, returning its status and whether the connection may
/// carry another request.
fn read_response(reader: &mut BufReader<TcpStream>) -> Result<(u16, bool), String> {
    let status = read_status(reader)?;
    let framing = read_headers(reader)?;
    if framing.chunked {
        read_chunked(reader)?;
        Ok((status, !framing.close))
    } else if let Some(length) = framing.content_length {
        let mut body = vec![0_u8; length];
        reader
            .read_exact(&mut body)
            .map_err(|err| format!("read body: {err}"))?;
        Ok((status, !framing.close))
    } else {
        let mut body = Vec::new();
        reader
            .read_to_end(&mut body)
            .map_err(|err| format!("read body: {err}"))?;
        Ok((status, false))
    }
}

/// How a response body is delimited and whether the connection closes.
#[derive(Default)]
struct Framing {
    /// `Transfer-Encoding: chunked`.
    chunked: bool,

    /// `Connection: close`.
    close: bool,

    /// `Content-Length`, when present.
    content_length: Option<usize>,
}

/// Read the status line and return the status code.
fn read_status(reader: &mut BufReader<TcpStream>) -> Result<u16, String> {
    let mut status_line = String::new();
    let read = reader
        .read_line(&mut status_line)
        .map_err(|err| format!("read status: {err}"))?;
    if read == 0 {
        return Err("connection closed before a response".to_owned());
    }
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("malformed status line: {status_line:?}"))
}

/// Read headers through the blank line, keeping only framing.
fn read_headers(reader: &mut BufReader<TcpStream>) -> Result<Framing, String> {
    let mut framing = Framing::default();
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|err| format!("read header: {err}"))?;
        let Some((name, value)) = line.trim_end().split_once(':') else {
            return Ok(framing);
        };
        let value = value.trim().to_ascii_lowercase();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => framing.content_length = value.parse::<usize>().ok(),
            "transfer-encoding" => framing.chunked = value.contains("chunked"),
            "connection" => framing.close = value.contains("close"),
            _ => {},
        }
    }
}

/// Consume a chunked body up to and including its terminating chunk.
fn read_chunked(reader: &mut BufReader<TcpStream>) -> Result<(), String> {
    loop {
        let mut size_line = String::new();
        reader
            .read_line(&mut size_line)
            .map_err(|err| format!("read chunk size: {err}"))?;
        let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or(""), 16)
            .map_err(|err| format!("malformed chunk size {size_line:?}: {err}"))?;
        let mut chunk = vec![0_u8; size + 2];
        reader
            .read_exact(&mut chunk)
            .map_err(|err| format!("read chunk: {err}"))?;
        if size == 0 {
            return Ok(());
        }
    }
}
