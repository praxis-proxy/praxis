// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Runtime release transitions and the separate request pre-read contract.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext,
};
use praxis_test_utils::{
    custom_filter_yaml, free_port, http_get, parse_status, read_http_request, spawn_raw_http_backend,
    start_echo_backend, start_full_proxy_with_registry, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn request_release_exposes_stream_and_preserves_tail() {
    let backend = start_echo_backend();
    let observations = Arc::new(Mutex::new(Vec::new()));
    let config = release_config(backend.port(), 16);
    let registry = release_registry(Direction::Request, &observations);
    let proxy = start_full_proxy_with_registry(&config, &registry);
    wait_for_tcp(proxy.addr());
    let raw = send_split_request(proxy.addr(), &observations, false);

    assert_eq!(parse_status(&raw), 200, "released request reaches the backend");
    assert!(
        raw.ends_with("abcdef"),
        "the prefix and tail must arrive exactly once: {raw}"
    );
    assert_stream_tail(&observations);
}

#[test]
fn response_release_exposes_stream_on_nonempty_eos() {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let backend_observations = Arc::clone(&observations);
    let (backend_port, backend_thread) = spawn_raw_http_backend(move |mut stream| {
        read_http_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nab")
            .unwrap();
        stream.flush().unwrap();
        wait_for_prefix(&backend_observations);
        stream.write_all(b"cdef").unwrap();
    });
    let config = release_config(backend_port, 16);
    let registry = release_registry(Direction::Response, &observations);
    let proxy = start_full_proxy_with_registry(&config, &registry);
    wait_for_tcp(proxy.addr());
    let (status, body) = http_get(proxy.addr(), "/", None);
    backend_thread.join().unwrap();

    assert_eq!(status, 200, "released response is delivered");
    assert_eq!(body, "abcdef", "repeated Release must preserve the tail");
    assert_stream_tail(&observations);
    let observations = observations.lock().unwrap().clone();
    assert!(
        observations
            .iter()
            .any(|observation| observation.end_of_stream && observation.bytes > 0),
        "the streamed final callback carries a nonempty final chunk"
    );
}

#[test]
fn request_release_still_enforces_global_ceiling() {
    let backend = start_echo_backend();
    let observations = Arc::new(Mutex::new(Vec::new()));
    let config = release_config(backend.port(), 5);
    let registry = release_registry(Direction::Request, &observations);
    let proxy = start_full_proxy_with_registry(&config, &registry);
    wait_for_tcp(proxy.addr());
    let raw = send_split_request(proxy.addr(), &observations, true);

    assert_eq!(parse_status(&raw), 413, "a released tail cannot lift the global limit");
    assert!(
        observations
            .lock()
            .unwrap()
            .iter()
            .map(|observation| observation.bytes)
            .sum::<usize>()
            <= 2,
        "the oversized tail is rejected before its hook"
    );
}

#[test]
fn preread_release_keeps_buffered_eos_for_body_writer() {
    let backend = start_echo_backend();
    let observations = Arc::new(Mutex::new(Vec::new()));
    let config = release_config(backend.port(), 16);
    let registry = release_registry(Direction::PreRead, &observations);
    let proxy = start_full_proxy_with_registry(&config, &registry);
    wait_for_tcp(proxy.addr());
    let raw = send_split_request(proxy.addr(), &observations, false);

    assert_eq!(parse_status(&raw), 200, "pre-read body writer reaches the backend");
    assert!(
        raw.ends_with("ABCDEF"),
        "pre-read EOS receives and transforms the complete body: {raw}"
    );
    let observations = observations.lock().unwrap().clone();
    assert!(
        observations
            .iter()
            .all(|observation| matches!(observation.mode, BodyMode::StreamBuffer { .. })),
        "pre-read continues buffering until EOS"
    );
    assert!(
        observations
            .iter()
            .any(|observation| observation.end_of_stream && observation.bytes == 6),
        "pre-read writer receives the full aggregate after Release"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// The delivery path exercised by the probe.
#[derive(Clone, Copy)]
enum Direction {
    PreRead,
    Request,
    Response,
}

/// Delivery observed by one body callback.
#[derive(Clone, Copy)]
struct Observation {
    /// Number of bytes offered to the hook.
    bytes: usize,
    /// Whether the callback finishes the body.
    end_of_stream: bool,
    /// Runtime delivery mode visible to the hook.
    mode: BodyMode,
}

/// Records body delivery and returns Release on every callback.
struct ReleaseProbe {
    /// Path selected for this test.
    direction: Direction,
    /// Calls recorded for test synchronization and assertions.
    observations: Arc<Mutex<Vec<Observation>>>,
}

#[async_trait::async_trait]
impl HttpFilter for ReleaseProbe {
    fn name(&self) -> &'static str {
        "release_probe"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if matches!(self.direction, Direction::Request) {
            ctx.set_request_body_mode(BodyMode::StreamBuffer { max_bytes: Some(2) });
        }
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if matches!(self.direction, Direction::Response) {
            ctx.set_response_body_mode(BodyMode::StreamBuffer { max_bytes: Some(2) });
        }
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        match self.direction {
            Direction::PreRead => BodyAccess::ReadWrite,
            Direction::Request => BodyAccess::ReadOnly,
            Direction::Response => BodyAccess::None,
        }
    }

    fn request_body_mode(&self) -> BodyMode {
        match self.direction {
            Direction::PreRead => BodyMode::StreamBuffer { max_bytes: Some(16) },
            Direction::Request | Direction::Response => BodyMode::Stream,
        }
    }

    fn response_body_access(&self) -> BodyAccess {
        match self.direction {
            Direction::Response => BodyAccess::ReadOnly,
            Direction::PreRead | Direction::Request => BodyAccess::None,
        }
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        self.observe(ctx.request_body_mode, body.as_ref(), end_of_stream);
        if matches!(self.direction, Direction::PreRead) && end_of_stream {
            *body = body.as_ref().map(|bytes| Bytes::from(bytes.to_ascii_uppercase()));
        }
        Ok(FilterAction::Release)
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        self.observe(ctx.response_body_mode, body.as_ref(), end_of_stream);
        Ok(FilterAction::Release)
    }
}

impl ReleaseProbe {
    /// Record one callback before allowing the sender to send the tail.
    fn observe(&self, mode: BodyMode, body: Option<&Bytes>, end_of_stream: bool) {
        self.observations.lock().unwrap().push(Observation {
            bytes: body.map_or(0, Bytes::len),
            end_of_stream,
            mode,
        });
    }
}

/// Build a proxy config with independent buffer and global ceilings.
fn release_config(backend_port: u16, ceiling: usize) -> Config {
    let yaml = custom_filter_yaml(free_port(), backend_port, "release_probe");
    Config::from_yaml(&format!(
        "{yaml}\nbody_limits:\n  max_request_bytes: {ceiling}\n  max_response_bytes: {ceiling}\n"
    ))
    .unwrap()
}

/// Register a probe with test-local observations.
fn release_registry(direction: Direction, observations: &Arc<Mutex<Vec<Observation>>>) -> FilterRegistry {
    let observations = Arc::clone(observations);
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "release_probe",
            FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(ReleaseProbe {
                    direction,
                    observations: Arc::clone(&observations),
                }))
            })),
        )
        .unwrap();
    registry
}

/// Send a request whose tail follows Release using either HTTP framing mode.
fn send_split_request(address: &str, observations: &Arc<Mutex<Vec<Observation>>>, chunked: bool) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (prefix, tail): (&[u8], &[u8]) = if chunked {
        (b"POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nab\r\n", b"4\r\ncdef\r\n0\r\n\r\n")
    } else {
        (
            b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 6\r\nConnection: close\r\n\r\nab",
            b"cdef",
        )
    };
    stream.write_all(prefix).unwrap();
    stream.flush().unwrap();
    wait_for_prefix(observations);
    stream.write_all(tail).unwrap();
    let mut raw = String::new();
    drop(stream.read_to_string(&mut raw));
    raw
}

/// Wait until the first callback has run before sending any tail bytes.
fn wait_for_prefix(observations: &Arc<Mutex<Vec<Observation>>>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while observations.lock().unwrap().is_empty() {
        assert!(
            Instant::now() < deadline,
            "the first hook must run before the tail is sent"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Check the transition without assuming TCP preserves chunk boundaries.
fn assert_stream_tail(observations: &Arc<Mutex<Vec<Observation>>>) {
    let observations = observations.lock().unwrap().clone();
    assert!(
        matches!(observations.first().unwrap().mode, BodyMode::StreamBuffer { .. }),
        "the initial callback sees buffered delivery"
    );
    assert!(observations.len() >= 2, "the hook must observe a tail after Release");
    assert!(
        observations
            .iter()
            .skip(1)
            .all(|observation| observation.mode == BodyMode::Stream),
        "every callback after Release sees Stream"
    );
    assert_eq!(
        observations.iter().map(|observation| observation.bytes).sum::<usize>(),
        6,
        "the callbacks observe every wire byte exactly once"
    );
}
