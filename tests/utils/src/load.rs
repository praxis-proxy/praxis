// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Test utilities for driving concurrent HTTP/1.1 load at a proxy.
//!
//! Clients are plain threads over raw sockets so every connection, reuse,
//! and close is explicit, which descriptor accounting tests depend on.

use std::{
    collections::BTreeMap,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{TcpStream, ToSocketAddrs as _},
    panic::AssertUnwindSafe,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Per-socket read and write timeout for load clients.
const IO_TIMEOUT: Duration = Duration::from_secs(20);

/// Read timeout for requests held in flight by [`open_requests`], whose
/// backends answer within seconds when the proxy admits them at all.
const IN_FLIGHT_TIMEOUT: Duration = Duration::from_secs(5);

/// Pause after a failed exchange so a persistent outage cannot spin the loop.
const RECONNECT_BACKOFF: Duration = Duration::from_millis(50);

/// Longest single sleep while waiting out [`RECONNECT_BACKOFF`].
const RECONNECT_POLL: Duration = Duration::from_millis(10);

/// Largest health response body a load worker retains.
const HEALTH_BODY_LIMIT: usize = 64;

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
    /// One-shot replays after an idle, reused HTTP/1.1 connection closes.
    pub http1_replays: AtomicU64,
    /// Successful HTTP/2 responses.
    pub http2: AtomicU64,
    /// Replay attempts begun after a clean, unprocessed remote GOAWAY.
    pub http2_replays: AtomicU64,
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
    /// One-shot replays after an idle, reused HTTP/1.1 connection closes.
    pub http1_replays: u64,
    /// Successful HTTP/2 responses.
    pub http2: u64,
    /// Replay attempts begun after a clean, unprocessed remote GOAWAY.
    pub http2_replays: u64,
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
    /// Reports logical health requests with one-shot recovery for stale
    /// HTTP/1.1 sockets and clean, unprocessed HTTP/2 GOAWAY. Fresh-connection
    /// failures, timeouts, and incomplete responses remain failures.
    pub fn start(endpoint: &str) -> Self {
        Self::start_workers(endpoint, None)
    }

    /// Starts HTTP/1.1, HTTP/2, and HTTPS load workers.
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
            http1_replays: self.report.http1_replays.load(Ordering::SeqCst),
            http2: self.report.http2.load(Ordering::SeqCst),
            http2_replays: self.report.http2_replays.load(Ordering::SeqCst),
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
    let mut replay_pending = false;
    while !stop.load(Ordering::Relaxed) {
        let reused = stream.is_some();
        if replay_pending {
            report.http1_replays.fetch_add(1, Ordering::Relaxed);
            replay_pending = false;
        }
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| http1_request(endpoint, &mut stream)));
        match result {
            Ok(result) if reused && stale_http1_connection(&result) => {
                stream = None;
                replay_pending = true;
            },
            Ok(Ok(response)) => record_http1_response(report, &response, &mut stream),
            Ok(Err(error)) => {
                report.failure(format!("HTTP/1.1 transport: {error}"));
                stream = None;
                std::thread::sleep(Duration::from_millis(50));
            },
            Err(_) => {
                report.failure("HTTP/1.1 client panicked".to_owned());
                stream = None;
            },
        }
    }
}

/// Identifies an idle close before a response to an idempotent health GET.
///
/// Only a reused socket can be replayed. Its fresh replacement is not eligible,
/// bounding replay to one attempt per [RFC 9112 Section 9.3.1].
///
/// [RFC 9112 Section 9.3.1]: https://datatracker.ietf.org/doc/html/rfc9112#section-9.3.1
fn stale_http1_connection(result: &std::io::Result<String>) -> bool {
    match result {
        Ok(response) => response.is_empty(),
        Err(error) => matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
        ),
    }
}

/// Records the exchange and honors announced HTTP/1.1 connection closure.
fn record_http1_response(report: &ContinuousLoadReport, response: &str, stream: &mut Option<TcpStream>) {
    if let Some(failure) = http1_failure(response) {
        report.failure(failure);
        *stream = None;
    } else {
        report.http1.fetch_add(1, Ordering::Relaxed);
        *stream = stream.take().filter(|_| !http1_closes(response));
    }
}

/// Returns whether headers prohibit connection reuse per [RFC 9112 Section 9.6].
///
/// [RFC 9112 Section 9.6]: https://datatracker.ietf.org/doc/html/rfc9112#section-9.6
fn http1_closes(response: &str) -> bool {
    response.split_once("\r\n\r\n").is_some_and(|(headers, _)| {
        headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .any(|(name, value)| {
                name.eq_ignore_ascii_case("connection")
                    && value.split(',').any(|token| token.trim().eq_ignore_ascii_case("close"))
            })
    })
}

/// Returns the failure message for an unhealthy HTTP/1.1 response.
fn http1_failure(response: &str) -> Option<String> {
    if healthy_response(response) {
        return None;
    }
    Some(if response.is_empty() {
        "HTTP/1.1 keepalive closed without a response".to_owned()
    } else {
        format!("HTTP/1.1 returned {response}")
    })
}

/// Sends one persistent HTTP/1.1 request, reconnecting when `stream` is unset.
fn http1_request(endpoint: &str, stream: &mut Option<TcpStream>) -> std::io::Result<String> {
    if stream.is_none() {
        *stream = Some(connect_endpoint(endpoint)?);
    }
    let stream = stream.as_mut().expect("connected stream");
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let deadline = Instant::now()
        .checked_add(IO_TIMEOUT)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "exchange deadline overflows"))?;
    crate::net::try_http_send_on_connection_until(
        stream,
        "GET /healthy HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
        deadline,
        HEALTH_BODY_LIMIT,
    )
}

/// Resolves every address for the endpoint and connects to the first that answers.
fn connect_endpoint(endpoint: &str) -> std::io::Result<TcpStream> {
    let mut last_error = None;
    for address in endpoint.to_socket_addrs()? {
        match TcpStream::connect_timeout(&address, IO_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{endpoint} resolved to no addresses"),
        )
    }))
}

/// Checks status and the complete fixed-length health response body.
fn healthy_response(response: &str) -> bool {
    response.split_once("\r\n\r\n").is_some_and(|(headers, body)| {
        headers
            .lines()
            .next()
            .is_some_and(|status| status.starts_with("HTTP/1.1 200 "))
            && body == "ok"
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
    let runtime = worker_runtime();
    let mut client = None;
    let mut replayed = false;
    let mut replay_pending = false;
    while !stop.load(Ordering::Relaxed) {
        let Some(request_client) = client.take().or_else(|| load_http2_client(&runtime, report, endpoint)) else {
            continue;
        };
        if std::mem::take(&mut replay_pending) {
            report.http2_replays.fetch_add(1, Ordering::Relaxed);
        }
        let result = runtime.block_on(async { tokio::time::timeout(IO_TIMEOUT, http2_request(request_client)).await });
        match result {
            Ok(Ok(returned_client)) => {
                client = Some(returned_client);
                report.http2.fetch_add(1, Ordering::Relaxed);
                replayed = false;
            },
            Ok(Err(error)) if !replayed && unprocessed_http2_goaway(error.as_ref()) => {
                replayed = true;
                replay_pending = true;
            },
            Ok(Err(error)) => record_http2_failure(report, stop, &mut replayed, format!("HTTP/2 transport: {error}")),
            Err(error) => record_http2_failure(report, stop, &mut replayed, format!("HTTP/2 timeout: {error}")),
        }
    }
}

/// Counts a failed exchange and pauses before the worker reconnects.
fn record_http2_failure(report: &ContinuousLoadReport, stop: &AtomicBool, replayed: &mut bool, message: String) {
    *replayed = false;
    report.failure(message);
    reconnect_backoff(stop);
}

/// Waits out [`RECONNECT_BACKOFF`], returning early once `stop` is set.
fn reconnect_backoff(stop: &AtomicBool) {
    reconnect_backoff_with(stop, std::thread::sleep);
}

/// Waits out [`RECONNECT_BACKOFF`] through `sleep`, returning early once stopped.
fn reconnect_backoff_with(stop: &AtomicBool, mut sleep: impl FnMut(Duration)) {
    let mut remaining = RECONNECT_BACKOFF;
    while !remaining.is_zero() && !stop.load(Ordering::Relaxed) {
        let slice = remaining.min(RECONNECT_POLL);
        sleep(slice);
        remaining = remaining.saturating_sub(slice);
    }
}

/// Connects a worker, counting failures without a refused-connection busy loop.
fn load_http2_client(
    runtime: &tokio::runtime::Runtime,
    report: &ContinuousLoadReport,
    endpoint: &str,
) -> Option<h2::client::SendRequest<bytes::Bytes>> {
    match connect_http2(runtime, endpoint) {
        Ok(client) => Some(client),
        Err(error) => {
            report.failure(format!("HTTP/2 connect: {error}"));
            std::thread::sleep(Duration::from_millis(50));
            None
        },
    }
}

/// Recognizes h2's clean remote GOAWAY for streams the peer did not process.
///
/// h2 reports this on streams above the peer's last-stream ID; retrying those
/// streams is permitted by [RFC 9113 Section 6.8]. I/O errors remain failures.
///
/// [RFC 9113 Section 6.8]: https://datatracker.ietf.org/doc/html/rfc9113#section-6.8
fn unprocessed_http2_goaway(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    error
        .downcast_ref::<h2::Error>()
        .is_some_and(|error| error.is_remote() && error.is_go_away() && error.reason() == Some(h2::Reason::NO_ERROR))
}

/// Builds the single-threaded runtime shared by a continuous-load worker.
fn worker_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("HTTP/2 load runtime")
}

/// Connects once and keeps the HTTP/2 connection task running.
fn connect_http2(
    runtime: &tokio::runtime::Runtime,
    endpoint: &str,
) -> Result<h2::client::SendRequest<bytes::Bytes>, Box<dyn std::error::Error + Send + Sync>> {
    let (client, connection) = runtime.block_on(async {
        type ConnectError = Box<dyn std::error::Error + Send + Sync>;
        let connect = async {
            let stream = tokio::net::TcpStream::connect(endpoint)
                .await
                .map_err(|error| -> ConnectError { Box::new(error) })?;
            h2::client::handshake(stream)
                .await
                .map_err(|error| -> ConnectError { Box::new(error) })
        };
        tokio::time::timeout(IO_TIMEOUT, connect)
            .await
            .map_err(|error| -> ConnectError { format!("HTTP/2 connect timed out: {error}").into() })?
    })?;
    runtime.spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

/// Runs HTTPS health requests until stopped.
fn https_worker(
    stop: &AtomicBool,
    report: &ContinuousLoadReport,
    endpoint: &str,
    client_config: &Arc<rustls::ClientConfig>,
) {
    let runtime = worker_runtime();
    while !stop.load(Ordering::Relaxed) {
        let result = crate::net::https_get_attempt_on(&runtime, endpoint, "/healthy", client_config);
        match result {
            Ok((status, body)) if status == 200 && body == "ok" => {
                report.https.fetch_add(1, Ordering::Relaxed);
            },
            Ok((status, body)) => {
                report.failure(format!("HTTPS returned {status} {body}"));
            },
            Err(error) => {
                report.failure(format!("HTTPS transport: {error}"));
            },
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Makes one HTTP/2 exchange, polling the connection alongside the request.
async fn http2_request(
    client: h2::client::SendRequest<bytes::Bytes>,
) -> Result<h2::client::SendRequest<bytes::Bytes>, Box<dyn std::error::Error + Send + Sync>> {
    let mut client = client.ready().await?;
    let exchange = async {
        let request = http::Request::get("/healthy").header("host", "localhost").body(())?;
        let (response, _) = client.send_request(request, true)?;
        let response = response.await?;
        let status = response.status();
        let mut stream = response.into_body();
        let mut body = Vec::with_capacity(2);
        while body.len() < 2 {
            let Some(chunk) = stream.data().await else { break };
            let chunk = chunk?;
            let keep = (2 - body.len()).min(chunk.len());
            body.extend_from_slice(&chunk[..keep]);
            stream.flow_control().release_capacity(chunk.len())?;
        }
        if status != http::StatusCode::OK || body != b"ok" {
            return Err(format!("unexpected health response: {status} {body:?}").into());
        }
        Ok(())
    };
    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = exchange.await;
    result?;
    Ok(client)
}

impl ContinuousLoadReport {
    /// Records a failed request and retains the first failure message.
    #[expect(clippy::print_stderr, reason = "bounded samples diagnose disruption failures")]
    fn failure(&self, message: String) {
        if self.failures.fetch_add(1, Ordering::Relaxed) < 8 {
            eprintln!("continuous load failure: {message}");
        }
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
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok ",
        ] {
            assert!(!healthy_response(response), "accepted {response:?}");
        }
    }

    #[test]
    fn total_includes_failed_requests() {
        let snapshot = ContinuousLoadSnapshot {
            http1: 2,
            http1_replays: 5,
            http2: 3,
            http2_replays: 7,
            https: 4,
            failures: 1,
            first_failure: None,
        };
        assert_eq!(snapshot.total(), 10);
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "persistent HTTP/1.1 server and worker assertion")]
    fn http1_load_reuses_one_connection_for_multiple_exchanges() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
        let endpoint = listener.local_addr().expect("address").to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read timeout");
            for index in 0..3 {
                let mut request =
                    [0; b"GET /healthy HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n".len()];
                stream.read_exact(&mut request).expect("request on same connection");
                if index == 2 {
                    server_stop.store(true, Ordering::SeqCst);
                }
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .expect("response");
            }
        });
        let report = ContinuousLoadReport::default();
        http1_worker(&stop, &report, &endpoint);
        server.join().expect("server");
        assert_eq!(
            report.http1.load(Ordering::SeqCst),
            3,
            "three successes must share the one accepted connection"
        );
        assert_eq!(
            report.failures.load(Ordering::SeqCst),
            0,
            "persistent exchanges must succeed"
        );
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "persistent HTTP/2 server and worker assertion")]
    fn http2_load_reuses_one_connection_for_multiple_exchanges() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
        let endpoint = listener.local_addr().expect("address").to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_nonblocking(true).expect("nonblocking socket");
            worker_runtime().block_on(async {
                let stream = tokio::net::TcpStream::from_std(stream).expect("Tokio socket");
                let mut connection = h2::server::handshake(stream).await.expect("handshake");
                for index in 0..3 {
                    let (_, mut respond) = connection.accept().await.expect("stream").expect("request");
                    let response = http::Response::builder().status(200).body(()).expect("response");
                    let mut send = respond.send_response(response, false).expect("response headers");
                    send.send_data(bytes::Bytes::from_static(b"ok"), true)
                        .expect("response body");
                    if index == 2 {
                        server_stop.store(true, Ordering::SeqCst);
                    }
                }
                let _ = connection.accept().await;
            });
        });
        let report = ContinuousLoadReport::default();
        http2_worker(&stop, &report, &endpoint);
        server.join().expect("server");
        assert_eq!(
            report.http2.load(Ordering::SeqCst),
            3,
            "three streams must share the one accepted connection"
        );
        assert_eq!(
            report.failures.load(Ordering::SeqCst),
            0,
            "persistent exchanges must succeed"
        );
    }

    /// A client must stop reuse after `Connection: close` per [RFC 9112 Section 9.6].
    ///
    /// [RFC 9112 Section 9.6]: https://datatracker.ietf.org/doc/html/rfc9112#section-9.6
    #[test]
    #[expect(clippy::too_many_lines, reason = "two accepted connections and worker assertions")]
    fn http1_load_reconnects_after_announced_or_stale_close() {
        for announced in [true, false] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
            let endpoint = listener.local_addr().expect("address").to_string();
            let stop = Arc::new(AtomicBool::new(false));
            let server_stop = Arc::clone(&stop);
            let server = std::thread::spawn(move || {
                for index in 0..2 {
                    let (mut stream, _) = listener.accept().expect("accept replacement connection");
                    let mut request =
                        [0; b"GET /healthy HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n".len()];
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .expect("read timeout");
                    stream.read_exact(&mut request).expect("health request");
                    if index == 1 {
                        server_stop.store(true, Ordering::SeqCst);
                    }
                    let response: &[u8] = if announced {
                        b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok"
                    } else {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                    };
                    stream.write_all(response).expect("health response");
                    if !announced && index == 0 {
                        stream.read_exact(&mut request).expect("request on stale socket");
                    }
                }
            });
            let report = ContinuousLoadReport::default();
            http1_worker(&stop, &report, &endpoint);
            server.join().expect("server");
            assert_eq!(report.http1.load(Ordering::SeqCst), 2, "both logical requests complete");
            assert_eq!(
                report.failures.load(Ordering::SeqCst),
                0,
                "idle closure is recovered once"
            );
            assert_eq!(
                report.http1_replays.load(Ordering::SeqCst),
                u64::from(!announced),
                "only the reused, stale connection needs a safe replay"
            );
        }
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "real HTTP/1.1 peer and failure accounting assertions"
    )]
    fn unhealthy_announced_close_is_counted() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
        let endpoint = listener.local_addr().expect("address").to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read timeout");
            let mut request = [0; b"GET /healthy HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n".len()];
            stream.read_exact(&mut request).expect("health request");
            server_stop.store(true, Ordering::SeqCst);
            stream
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok")
                .expect("unhealthy response");
        });
        let report = ContinuousLoadReport::default();
        http1_worker(&stop, &report, &endpoint);
        server.join().expect("server");
        assert_eq!(
            report.failures.load(Ordering::SeqCst),
            1,
            "503 must count as one failure"
        );
        assert_eq!(
            report.http1.load(Ordering::SeqCst),
            0,
            "503 must not count as a success"
        );
        assert_eq!(
            report.http1_replays.load(Ordering::SeqCst),
            0,
            "an unhealthy response must not be replayed"
        );
    }

    #[test]
    fn stale_replay_does_not_mask_timeouts_or_incomplete_responses() {
        for result in [
            Ok("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\no".to_owned()),
            Err(std::io::Error::from(std::io::ErrorKind::TimedOut)),
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
            Err(std::io::Error::other("incomplete HTTP response")),
        ] {
            assert!(
                !stale_http1_connection(&result),
                "timeouts and response bytes must remain failures"
            );
        }
    }

    #[test]
    fn connection_close_headers_are_honored_without_hiding_failed_responses() {
        assert!(
            http1_closes("HTTP/1.1 200 OK\r\ncOnNeCtIoN: keep-alive, CLOSE\r\n\r\nok"),
            "close is a case-insensitive connection option"
        );
        assert!(
            !http1_closes("HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\nConnection: close"),
            "body text must not control connection reuse"
        );
        assert!(
            http1_failure("").is_some(),
            "unannounced closure still fails the request"
        );
    }

    /// Unprocessed streams may be replayed per [RFC 9113 Section 6.8].
    ///
    /// [RFC 9113 Section 6.8]: https://datatracker.ietf.org/doc/html/rfc9113#section-6.8
    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "real HTTP/2 GOAWAY peers and bounded replay assertions"
    )]
    fn http2_replays_one_unprocessed_goaway_and_counts_repeated_rejection() {
        for (rejections, successes, failures) in [(1, 1, 0), (2, 0, 1)] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
            let endpoint = listener.local_addr().expect("address").to_string();
            let stop = Arc::new(AtomicBool::new(false));
            let server_stop = Arc::clone(&stop);
            let server = std::thread::spawn(move || {
                worker_runtime().block_on(async {
                    for index in 1..=rejections {
                        let (stream, _) = listener.accept().expect("accept GOAWAY connection");
                        stream.set_nonblocking(true).expect("nonblocking stream");
                        let stream = tokio::net::TcpStream::from_std(stream).expect("Tokio stream");
                        let mut connection = h2::server::handshake(stream).await.expect("handshake");
                        connection.abrupt_shutdown(h2::Reason::NO_ERROR);
                        if index == 2 {
                            server_stop.store(true, Ordering::SeqCst);
                        }
                        let _ = connection.accept().await;
                    }
                    if rejections == 1 {
                        let (stream, _) = listener.accept().expect("accept replay");
                        stream.set_nonblocking(true).expect("nonblocking stream");
                        let stream = tokio::net::TcpStream::from_std(stream).expect("Tokio stream");
                        let mut connection = h2::server::handshake(stream).await.expect("handshake");
                        let (request, mut respond) = connection.accept().await.expect("stream").expect("request");
                        assert_eq!(request.uri(), "/healthy", "the unprocessed health request is replayed");
                        let response = http::Response::builder().status(200).body(()).expect("response");
                        let mut body = respond.send_response(response, false).expect("headers");
                        body.send_data(bytes::Bytes::from_static(b"ok"), true).expect("body");
                        server_stop.store(true, Ordering::SeqCst);
                        let _ = connection.accept().await;
                    }
                });
            });
            let report = ContinuousLoadReport::default();
            http2_worker(&stop, &report, &endpoint);
            server.join().expect("server");
            assert_eq!(
                report.http2.load(Ordering::SeqCst),
                successes,
                "one safe replay may complete"
            );
            assert_eq!(
                report.failures.load(Ordering::SeqCst),
                failures,
                "repeated GOAWAY must not hide an outage"
            );
            assert_eq!(
                report.http2_replays.load(Ordering::SeqCst),
                1,
                "each logical request permits only one safe replay"
            );
        }
    }

    #[test]
    fn stopping_after_goaway_does_not_count_an_unstarted_replay() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
        let endpoint = listener.local_addr().expect("address").to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            worker_runtime().block_on(async {
                let (stream, _) = listener.accept().expect("accept");
                stream.set_nonblocking(true).expect("nonblocking stream");
                let stream = tokio::net::TcpStream::from_std(stream).expect("Tokio stream");
                let mut connection = h2::server::handshake(stream).await.expect("handshake");
                server_stop.store(true, Ordering::SeqCst);
                connection.abrupt_shutdown(h2::Reason::NO_ERROR);
                let _ = connection.accept().await;
            });
        });
        let report = ContinuousLoadReport::default();
        http2_worker(&stop, &report, &endpoint);
        server.join().expect("server");
        assert_eq!(
            report.http2_replays.load(Ordering::SeqCst),
            0,
            "stopping before replay must not count an attempt"
        );
        assert_eq!(
            report.failures.load(Ordering::SeqCst),
            0,
            "an unprocessed GOAWAY is not an application failure"
        );
    }

    #[test]
    fn connection_closure_is_counted() {
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

    #[test]
    fn reconnect_backoff_requests_no_sleep_when_stopped() {
        let stopped = AtomicBool::new(true);
        let mut sleeps = Vec::new();
        reconnect_backoff_with(&stopped, |duration| sleeps.push(duration));
        assert!(sleeps.is_empty(), "a stopped worker must not request a backoff sleep");

        let running = AtomicBool::new(false);
        let mut total = Duration::ZERO;
        reconnect_backoff_with(&running, |duration| total = total.saturating_add(duration));
        assert_eq!(
            total, RECONNECT_BACKOFF,
            "a running worker must request the full backoff"
        );
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
