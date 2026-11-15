// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional test for the bandwidth-limiting example.
//!
//! The example paces HTTP bodies per source address and TCP payloads per
//! connection. Both listeners run from the example file.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    net::TcpStream,
    time::{Duration, Instant},
};

use praxis_test_utils::{
    free_port, http_get, start_backend_with_shutdown, start_full_proxy, start_tcp_echo_backend, wait_for_tcp,
};

/// Example burst plus half a second at 1_000_000 bytes per second.
const PACED_BYTES: usize = 65_536 + 500_000;

/// Lower bound for the half-second pace, with room for scheduling noise.
const MIN_PACE: Duration = Duration::from_millis(400);

#[test]
fn bandwidth_limiting_example_paces_http_and_tcp() {
    let body = "x".repeat(PACED_BYTES);
    let http_backend = start_backend_with_shutdown(&body);
    let tcp_backend = start_tcp_echo_backend();
    let http_port = free_port();
    let tcp_port = free_port();
    let config = super::load_example_config(
        "traffic-management/bandwidth-limiting.yaml",
        http_port,
        HashMap::from([
            ("127.0.0.1:8082", tcp_port),
            ("127.0.0.1:3000", http_backend.port()),
            ("127.0.0.1:3001", tcp_backend),
        ]),
    );

    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{http_port}"));
    wait_for_tcp(&format!("127.0.0.1:{tcp_port}"));

    let started = Instant::now();
    let (status, response) = http_get(&format!("127.0.0.1:{http_port}"), "/", None);
    let http_elapsed = started.elapsed();
    assert_eq!(status, 200, "paced HTTP download should succeed");
    assert_eq!(response.len(), PACED_BYTES, "the full HTTP body should arrive");
    assert!(
        http_elapsed >= MIN_PACE,
        "HTTP per_ip download of {PACED_BYTES} bytes at 1000000 bytes/sec with a 65536 byte burst \
         should take about half a second, elapsed {http_elapsed:?}"
    );

    let payload = vec![7_u8; PACED_BYTES];
    let started = Instant::now();
    let echoed = exchange(tcp_port, &payload);
    let tcp_elapsed = started.elapsed();
    assert_eq!(echoed, payload, "the TCP payload should be echoed");
    assert!(
        tcp_elapsed >= MIN_PACE,
        "TCP per_connection transfer of {PACED_BYTES} bytes at 1000000 bytes/sec with a 65536 byte burst \
         should take about half a second, elapsed {tcp_elapsed:?}"
    );
}

/// Write `payload` while reading the echo, so neither direction fills the socket.
fn exchange(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("TCP connect");
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut reader = stream.try_clone().expect("clone TCP stream");
    let expected = payload.len();
    let handle = std::thread::spawn(move || {
        let mut got = vec![0_u8; expected];
        reader.read_exact(&mut got).expect("TCP read");
        got
    });
    stream.write_all(payload).expect("TCP write");
    stream.shutdown(std::net::Shutdown::Write).expect("shutdown write");
    handle.join().expect("reader thread")
}
