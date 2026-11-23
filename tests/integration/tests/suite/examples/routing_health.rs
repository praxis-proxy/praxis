// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Controllable health probes for routing example tests.

use std::{
    collections::HashSet,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use praxis_test_utils::{bind_unique_port, http_get};

// -----------------------------------------------------------------------------
// Test Health Backend
// -----------------------------------------------------------------------------

/// Backend with an independently switchable `/healthz` probe.
pub(super) struct TestHealthBackend {
    /// Bound port shared by normal traffic and active probes.
    port: u16,
    /// Probe result to return on `/healthz`.
    healthy: Arc<AtomicBool>,
    /// Number of completed active probe responses.
    probes: Arc<AtomicUsize>,
    /// Controls the listener loop.
    running: Arc<AtomicBool>,
    /// Listener worker joined when this guard drops.
    thread: Option<JoinHandle<()>>,
}

impl TestHealthBackend {
    /// Start a backend that returns `identity` on ordinary requests.
    pub(super) fn start(identity: &'static str) -> Self {
        let (listener, port) = bind_unique_port();
        listener.set_nonblocking(true).expect("set routing health nonblocking");
        let healthy = Arc::new(AtomicBool::new(true));
        let probes = Arc::new(AtomicUsize::new(0));
        let running = Arc::new(AtomicBool::new(true));
        let probe_healthy = Arc::clone(&healthy);
        let probe_count = Arc::clone(&probes);
        let serve_running = Arc::clone(&running);
        let thread = thread::spawn(move || serve(&listener, identity, &probe_healthy, &probe_count, &serve_running));
        Self {
            port,
            healthy,
            probes,
            running,
            thread: Some(thread),
        }
    }

    /// Port to use in the example config.
    pub(super) fn port(&self) -> u16 {
        self.port
    }

    /// Change only the probe result; ordinary requests still return 200.
    pub(super) fn set_healthy(&self, healthy: bool) {
        self.healthy.store(healthy, Ordering::Release);
    }

    /// Current number of completed probe responses.
    pub(super) fn probe_count(&self) -> usize {
        self.probes.load(Ordering::Acquire)
    }

    /// Wait until a fresh active probe has received this backend's response.
    pub(super) fn wait_for_probe_after(&self, previous: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.probe_count() <= previous {
            assert!(
                Instant::now() < deadline,
                "no fresh health probe for port {}",
                self.port
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for TestHealthBackend {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("join routing health backend");
        }
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Serve probe and identity responses until the backend guard is dropped.
fn serve(listener: &TcpListener, identity: &str, healthy: &AtomicBool, probes: &AtomicUsize, running: &AtomicBool) {
    while running.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => respond(stream, identity, healthy, probes),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            },
            Err(error) => panic!("routing health backend accept failed: {error}"),
        }
    }
}

/// Respond to one complete HTTP request.
fn respond(mut stream: TcpStream, identity: &str, healthy: &AtomicBool, probes: &AtomicUsize) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set routing health read timeout");
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).expect("read routing health request");
        if read == 0 {
            return;
        }
        request.extend_from_slice(&buffer[..read]);
    }
    let is_probe = request.starts_with(b"GET /healthz ");
    let (status, body) = if is_probe && !healthy.load(Ordering::Acquire) {
        ("503 Service Unavailable", "unhealthy")
    } else if is_probe {
        ("200 OK", "healthy")
    } else {
        ("200 OK", identity)
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("write routing health response");
    if is_probe {
        probes.fetch_add(1, Ordering::Release);
    }
}

/// Wait for a complete bounded response cycle matching `accept`.
pub(super) fn wait_for_routing_phase<F>(proxy_addr: &str, accept: F) -> HashSet<String>
where
    F: Fn(&HashSet<String>) -> bool,
{
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut seen = HashSet::new();
        for _ in 0..8 {
            let (status, body) = http_get(proxy_addr, "/", None);
            assert_eq!(status, 200, "routing request returned status {status}: {body}");
            seen.insert(body);
        }
        if accept(&seen) {
            return seen;
        }
        assert!(
            Instant::now() < deadline,
            "routing phase did not appear; last bodies: {seen:?}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}
