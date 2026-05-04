// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! TCP proxy throughput benchmarks.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, wait_for_tcp};

use crate::throughput_utils::{BenchResult, assert_performance, report_results};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn bench_tcp_proxy_serial() {
    let backend_port = start_tcp_echo_backend();
    let proxy_port = free_port();
    let addr = start_tcp_proxy(proxy_port, backend_port);

    let result = run_tcp_benchmark(&addr, b"hello", 1000, 1, 50);
    assert_eq!(result.errors, 0, "all requests should succeed");
    report_results(&result);
    assert_performance(&result, 100.0, 500.0);
}

#[test]
fn bench_tcp_proxy_concurrent() {
    let backend_port = start_tcp_echo_backend();
    let proxy_port = free_port();
    let addr = start_tcp_proxy(proxy_port, backend_port);

    let result = run_tcp_benchmark(&addr, b"hello world", 2000, 8, 50);
    assert_eq!(result.errors, 0, "all requests should succeed");
    report_results(&result);
    assert_performance(&result, 500.0, 500.0);
}

#[test]
fn bench_tcp_proxy_large_payload() {
    let backend_port = start_tcp_echo_backend();
    let proxy_port = free_port();
    let addr = start_tcp_proxy(proxy_port, backend_port);

    let message = vec![b'x'; 4096];
    let result = run_tcp_benchmark(&addr, &message, 1000, 4, 50);
    assert_eq!(result.errors, 0, "all requests should succeed");
    report_results(&result);
    assert_performance(&result, 200.0, 500.0);
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Start a Praxis TCP proxy.
fn start_tcp_proxy(proxy_port: u16, backend_port: u16) -> String {
    let yaml = tcp_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    std::thread::spawn(move || {
        praxis::run_server(config, None);
    });
    let addr = format!("127.0.0.1:{proxy_port}");
    wait_for_tcp(&addr);
    addr
}

/// Start a TCP echo server on a free port.
fn start_tcp_echo_backend() -> u16 {
    let port = free_port();
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        },
                    }
                }
            });
        }
    });
    port
}

/// Send a message through the proxy and verify the echo.
fn tcp_echo_roundtrip(addr: &str, message: &[u8]) -> bool {
    let mut stream = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(_) => return false,
    };
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    if stream.write_all(message).is_err() {
        return false;
    }
    let mut buf = vec![0u8; message.len()];
    match stream.read_exact(&mut buf) {
        Ok(()) => buf == message,
        Err(_) => false,
    }
}

/// Run a TCP echo benchmark.
fn run_tcp_benchmark(
    addr: &str,
    message: &[u8],
    total_requests: usize,
    concurrency: usize,
    warmup: usize,
) -> BenchResult {
    for _ in 0..warmup {
        tcp_echo_roundtrip(addr, message);
    }

    let addr_owned = addr.to_owned();
    let message = Arc::new(message.to_vec());
    let per_thread = total_requests / concurrency;
    let remainder = total_requests % concurrency;
    let wall_start = Instant::now();

    let handles: Vec<_> = (0..concurrency)
        .map(|i| {
            let addr = addr_owned.clone();
            let msg = Arc::clone(&message);
            let count = per_thread + if i < remainder { 1 } else { 0 };
            std::thread::spawn(move || {
                let mut latencies = Vec::with_capacity(count);
                let mut errors = 0usize;
                for _ in 0..count {
                    let start = Instant::now();
                    if tcp_echo_roundtrip(&addr, &msg) {
                        latencies.push(start.elapsed());
                    } else {
                        errors += 1;
                    }
                }
                (latencies, errors)
            })
        })
        .collect();

    let mut all_latencies = Vec::with_capacity(total_requests);
    let mut total_errors = 0usize;
    for handle in handles {
        let (latencies, errors) = handle.join().expect("worker panicked");
        all_latencies.extend(latencies);
        total_errors += errors;
    }
    let elapsed = wall_start.elapsed();
    all_latencies.sort();

    BenchResult {
        label: "tcp_proxy".into(),
        total_requests: all_latencies.len(),
        concurrency,
        elapsed,
        latencies: all_latencies,
        errors: total_errors,
    }
}

/// Generate a minimal TCP proxy YAML config.
fn tcp_proxy_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"listeners:
  - name: tcp_proxy
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    upstream: "127.0.0.1:{backend_port}"
"#
    )
}
