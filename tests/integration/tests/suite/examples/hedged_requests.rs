// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the hedged-requests example configuration.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use praxis_test_utils::{
    free_port, http_get, start_backend_with_shutdown, start_full_proxy, start_slow_backend, wait_for_tcp,
};

#[test]
fn hedged_request_returns_the_faster_endpoint() {
    let slow_port = start_slow_backend("slow", Duration::from_millis(800));
    let fast = start_backend_with_shutdown("fast");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/hedged-requests.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", slow_port), ("127.0.0.1:3002", fast.port())]),
    );
    let proxy = start_full_proxy(&config);

    for _ in 0..2 {
        let started = Instant::now();
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "the hedged request should succeed");
        assert_eq!(
            body, "fast",
            "the faster endpoint should win whichever endpoint is primary"
        );
        assert!(
            started.elapsed() < Duration::from_millis(700),
            "the copy should answer before the slow primary"
        );
    }
}

#[test]
fn hedged_sse_in_second_accept_header_streams_first_event() {
    let first = SseBackend::start();
    let second = SseBackend::start();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/hedged-requests.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", first.port), ("127.0.0.1:3002", second.port)]),
    );
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    let mut stream = TcpStream::connect(proxy.addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nAccept: text/event-stream\r\n\r\n",
        )
        .unwrap();

    let started = Instant::now();
    let mut received = Vec::new();
    let mut chunk = [0_u8; 512];
    while started.elapsed() < Duration::from_secs(2)
        && !received
            .windows(b"data: hi\n\n".len())
            .any(|part| part == b"data: hi\n\n")
    {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(size) => received.extend_from_slice(&chunk[..size]),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock || error.kind() == std::io::ErrorKind::TimedOut => {},
            Err(error) => panic!("SSE read failed: {error}"),
        }
    }
    assert!(
        received
            .windows(b"data: hi\n\n".len())
            .any(|part| part == b"data: hi\n\n"),
        "the first SSE event must arrive before upstream EOS: {received:?}"
    );
    thread::sleep(Duration::from_millis(120));
    assert_eq!(
        first.starts.load(Ordering::SeqCst) + second.starts.load(Ordering::SeqCst),
        1,
        "an SSE request must not start a hedged copy"
    );
}

struct SseBackend {
    port: u16,
    running: Arc<AtomicBool>,
    starts: Arc<AtomicUsize>,
    worker: Option<thread::JoinHandle<()>>,
}

impl SseBackend {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let starts = Arc::new(AtomicUsize::new(0));
        let worker_running = Arc::clone(&running);
        let worker_starts = Arc::clone(&starts);
        let worker = thread::spawn(move || {
            while worker_running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                        let mut request = [0_u8; 1024];
                        if stream.read(&mut request).is_ok_and(|size| size > 0) {
                            worker_starts.fetch_add(1, Ordering::SeqCst);
                            let _sent = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\na\r\ndata: hi\n\n\r\n");
                            while worker_running.load(Ordering::SeqCst) {
                                thread::sleep(Duration::from_millis(10));
                            }
                        }
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    },
                    Err(error) => panic!("SSE backend accept failed: {error}"),
                }
            }
        });
        Self {
            port,
            running,
            starts,
            worker: Some(worker),
        }
    }
}

impl Drop for SseBackend {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}
