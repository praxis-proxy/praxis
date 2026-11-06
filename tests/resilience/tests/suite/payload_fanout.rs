// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Attempt and byte accounting for payload fan-out in an isolated proxy.

#![cfg(any(feature = "pingora", feature = "iterative-request-router"))]

use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

#[cfg(feature = "pingora")]
use praxis_test_utils::start_echo_backend;
use praxis_test_utils::{PraxisProcess, free_port, http_send, parse_body, parse_status, read_h1_response};

/// One fully read request and the observed cancellation of a held response.
#[cfg(feature = "pingora")]
struct Attempt {
    body: Vec<u8>,
    cancelled: bool,
}

/// Backend which reads each request before responding or waiting.
#[cfg(feature = "pingora")]
struct AttemptBackend {
    port: u16,
    /// Signal that a connection was opened, even if its body never completes.
    accepted: mpsc::Receiver<()>,
    /// Signal that the complete request arrived, before the response.
    arrived: mpsc::Receiver<()>,
    attempts: mpsc::Receiver<Attempt>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

#[cfg(feature = "pingora")]
impl Drop for AttemptBackend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take()
            && let Err(error) = worker.join()
            && !thread::panicking()
        {
            std::panic::resume_unwind(error);
        }
    }
}

/// Start a backend returning `status`, or holding the response until cancelled.
#[cfg(feature = "pingora")]
fn attempt_backend(status: Option<u16>) -> AttemptBackend {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (accepted_tx, accepted) = mpsc::channel();
    let (sender, attempts) = mpsc::channel();
    let (arrival_sender, arrived) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = Arc::clone(&stop);
    let worker = thread::spawn(move || {
        while !stopping.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    accepted_tx.send(()).unwrap();
                    receive_attempt(stream, status, &sender, &arrival_sender);
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                Err(error) => panic!("backend accept: {error}"),
            }
        }
    });
    AttemptBackend {
        port,
        accepted,
        arrived,
        attempts,
        stop,
        worker: Some(worker),
    }
}

/// Read fixed-length request content to completion before producing a result.
#[cfg(feature = "pingora")]
fn receive_attempt(stream: TcpStream, status: Option<u16>, sender: &mpsc::Sender<Attempt>, arrived: &mpsc::Sender<()>) {
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut reader = BufReader::new(stream);
    let mut length = None;
    loop {
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0, "complete request headers");
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = Some(value.trim().parse::<usize>().unwrap());
        }
    }
    let mut body = vec![0; length.expect("request must have fixed-length framing")];
    reader.read_exact(&mut body).unwrap();
    arrived.send(()).unwrap();
    let cancelled = if let Some(status) = status {
        write!(
            reader.get_mut(),
            "HTTP/1.1 {status} result\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        )
        .unwrap();
        false
    } else {
        let mut byte = [0];
        match reader.read(&mut byte) {
            Ok(0) => true,
            Err(error) => matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ),
            Ok(_) => false,
        }
    };
    sender.send(Attempt { body, cancelled }).unwrap();
}

/// Send an idempotent request and require a fully framed response.
#[cfg(feature = "pingora")]
fn send_request(addr: &str, body: &[u8]) -> (Option<u16>, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    write!(
        stream,
        "GET /api/upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body).unwrap();
    let mut output = Vec::new();
    let response = read_h1_response(&mut BufReader::new(stream), false, 1024, |chunk| {
        output.extend_from_slice(chunk);
        Ok(())
    });
    assert!(
        response.completion.is_some() && response.abort.is_none(),
        "response must complete: {response:?}"
    );
    (response.status, output)
}

/// Common routing with a separate clean-probe backend.
#[cfg(feature = "pingora")]
fn config(proxy: u16, probe: u16, endpoints: &[u16], route_policy: &str, cluster_policy: &str) -> String {
    let endpoints = endpoints
        .iter()
        .map(|port| format!("              - \"127.0.0.1:{port}\"\n"))
        .collect::<String>();
    format!(
        r#"
runtime:
  threads: 2
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: backend
{route_policy}
          - path_prefix: "/"
            cluster: probe
      - filter: load_balancer
        clusters:
          - name: backend
            load_balancer_strategy: round_robin
            endpoints:
{endpoints}{cluster_policy}
          - name: probe
            endpoints: ["127.0.0.1:{probe}"]
"#
    )
}

/// Verify a separate request remains usable after a fan-out.
fn probe(addr: &str, expected: &str) {
    let response = http_send(
        addr,
        "GET /echo HTTP/1.1\r\nHost: localhost\r\nX-Probe: yes\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&response), 200, "independent probe must succeed");
    assert_eq!(parse_body(&response), expected, "probe reaches its intended route");
}

#[cfg(feature = "pingora")]
#[test]
fn retry_attempts_and_forwarded_bytes_obey_the_replay_limit() {
    #[cfg(target_os = "linux")]
    let _guard = crate::payload_resources::serialized();
    for (length, expected_attempts) in [(65_536, 3), (65_537, 1)] {
        let backends = [
            attempt_backend(Some(503)),
            attempt_backend(Some(503)),
            attempt_backend(Some(503)),
        ];
        let clean = start_echo_backend();
        let port = free_port();
        let endpoints: Vec<u16> = backends.iter().map(|backend| backend.port).collect();
        let policy = "            retry_policy:\n              max_retries: 2\n              retriable_conditions: [status_5xx]\n              backoff:\n                base_interval_ms: 1\n                max_interval_ms: 5\n";
        let yaml = config(port, clean.port(), &endpoints, "", policy);
        let addr = format!("127.0.0.1:{port}");
        let mut process = PraxisProcess::spawn(&yaml, &addr);
        #[cfg(target_os = "linux")]
        let before = praxis_test_utils::sample_process(process.pid()).unwrap();
        let body: Vec<u8> = (0..length).map(|offset| u8::try_from(offset % 251).unwrap()).collect();
        let (status, output) = send_request(&addr, &body);
        assert_eq!(status, Some(503));
        assert_eq!(output, b"ok");
        let mut attempts = 0;
        for backend in &backends {
            while backend.accepted.try_recv().is_ok() {
                backend.arrived.recv_timeout(Duration::from_secs(3)).unwrap();
                let attempt = backend.attempts.recv_timeout(Duration::from_secs(3)).unwrap();
                assert_eq!(attempt.body, body);
                assert!(!attempt.cancelled, "a completed retry attempt was not cancelled");
                attempts += 1;
            }
            assert!(
                matches!(
                    backend.accepted.recv_timeout(Duration::from_millis(200)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ),
                "no attempt may start after the response completes"
            );
        }
        assert_eq!(attempts, expected_attempts, "attempt cap and replay threshold");
        probe(&addr, "");
        #[cfg(target_os = "linux")]
        {
            let after = praxis_test_utils::sample_process(process.pid()).unwrap();
            assert!(before.rss_bytes.is_some_and(|value| value > 0));
            assert!(after.rss_bytes.is_some_and(|value| value > 0));
        }
        process.signal("TERM");
        let (status, killed) = process.wait_or_kill(Duration::from_secs(10));
        assert!(!killed && status.success(), "proxy must exit cleanly");
    }
}

#[cfg(all(feature = "pingora", feature = "hedged-requests"))]
#[test]
fn hedge_cancels_loser_after_two_complete_payload_attempts() {
    #[cfg(target_os = "linux")]
    let _guard = crate::payload_resources::serialized();
    let slow = attempt_backend(None);
    let fast = attempt_backend(Some(200));
    let clean = start_echo_backend();
    let port = free_port();
    let policy = "            hedge_policy:\n              initial_requests: 1\n              max_attempts: 2\n              per_try_timeout_ms: 400\n              budget_percent: 100";
    let yaml = config(port, clean.port(), &[slow.port, fast.port], policy, "");
    let addr = format!("127.0.0.1:{port}");
    let mut process = PraxisProcess::spawn(&yaml, &addr);
    let body: Vec<u8> = (0..65_536).map(|offset| u8::try_from(offset % 251).unwrap()).collect();
    let request_addr = addr.clone();
    let request_body = body.clone();
    let client = thread::spawn(move || send_request(&request_addr, &request_body));
    slow.accepted.recv_timeout(Duration::from_secs(5)).unwrap();
    slow.arrived.recv_timeout(Duration::from_secs(5)).unwrap();
    #[cfg(target_os = "linux")]
    {
        let in_flight = praxis_test_utils::sample_process(process.pid()).unwrap();
        assert!(in_flight.rss_bytes.is_some_and(|value| value > 0));
    }
    let (status, output) = client.join().unwrap();
    assert_eq!((status, output.as_slice()), (Some(200), b"ok".as_slice()));
    fast.accepted.recv_timeout(Duration::from_secs(3)).unwrap();
    let winner = fast.attempts.recv_timeout(Duration::from_secs(3)).unwrap();
    let loser = slow.attempts.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(winner.body, body);
    assert_eq!(loser.body, body);
    assert!(loser.cancelled, "losing upstream exchange must be cancelled");
    probe(&addr, "");
    process.signal("TERM");
    let (status, killed) = process.wait_or_kill(Duration::from_secs(10));
    assert!(!killed && status.success());
}

#[cfg(feature = "iterative-request-router")]
mod iterative {
    use super::*;

    /// A finite child server that records complete requests and serves fixed responses.
    struct RepeatingChild {
        port: u16,
        accepted: mpsc::Receiver<()>,
        received: mpsc::Receiver<Vec<u8>>,
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl Drop for RepeatingChild {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(worker) = self.worker.take()
                && let Err(error) = worker.join()
                && !thread::panicking()
            {
                std::panic::resume_unwind(error);
            }
        }
    }

    fn child(response_len: usize) -> RepeatingChild {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (accepted_tx, accepted) = mpsc::channel();
        let (sender, received) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        accepted_tx.send(()).unwrap();
                        stream.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
                        let mut reader = BufReader::new(stream);
                        let mut length = None;
                        loop {
                            let mut line = String::new();
                            assert_ne!(
                                reader.read_line(&mut line).unwrap(),
                                0,
                                "child request headers must complete before the body"
                            );
                            if line == "\r\n" {
                                break;
                            }
                            if let Some((name, value)) = line.split_once(':')
                                && name.eq_ignore_ascii_case("content-length")
                            {
                                length = Some(value.trim().parse::<usize>().unwrap());
                            }
                        }
                        let mut body = vec![0; length.unwrap()];
                        reader.read_exact(&mut body).unwrap();
                        sender.send(body).unwrap();
                        write!(
                            reader.get_mut(),
                            "HTTP/1.1 200 OK\r\nContent-Length: {response_len}\r\nConnection: close\r\n\r\n"
                        )
                        .unwrap();
                        reader.get_mut().write_all(&vec![b'r'; response_len]).unwrap();
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    },
                    Err(error) => panic!("child accept: {error}"),
                }
            }
        });
        RepeatingChild {
            port,
            accepted,
            received,
            stop,
            worker: Some(worker),
        }
    }

    fn yaml(proxy: u16, child: u16, max_state: usize) -> String {
        format!(
            r#"
runtime:
  threads: 2
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        conditions:
          - when:
              headers:
                x-probe: "yes"
        status: 200
        body: ok
      - filter: iterative_request_router
        conditions:
          - when:
              headers:
                x-iterate: yes
        initial_step: repeat
        max_iterations: 3
        max_response_bytes: 100000
        max_state_bytes: {max_state}
        steps:
          - name: repeat
            filters:
              - filter: router
                routes:
                  - path_prefix: /
                    cluster: child
              - filter: load_balancer
                clusters:
                  - name: child
                    endpoints: ["127.0.0.1:{child}"]
            on_result:
              - default: true
                next: repeat
"#
        )
    }

    fn send(addr: &str, bytes: &[u8]) -> (Option<u16>, bool) {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        write!(stream, "POST /echo HTTP/1.1\r\nHost: localhost\r\nX-Iterate: yes\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).unwrap();
        stream.write_all(bytes).unwrap();
        let response = read_h1_response(&mut BufReader::new(stream), false, 4096, |_| Ok(()));
        (
            response.status,
            response.completion.is_some() && response.abort.is_none(),
        )
    }

    #[test]
    fn iteration_and_history_budgets_bound_large_body_amplification() {
        #[cfg(target_os = "linux")]
        let _guard = crate::payload_resources::serialized();
        for (response_len, max_state, expected_status, expected_attempts) in
            [(16, 200_000, 508, 3), (70_000, 100_000, 413, 1)]
        {
            let child = child(response_len);
            let port = free_port();
            let addr = format!("127.0.0.1:{port}");
            let mut process = PraxisProcess::spawn(&yaml(port, child.port, max_state), &addr);
            #[cfg(target_os = "linux")]
            let before = praxis_test_utils::sample_process(process.pid()).unwrap();
            let body = vec![b'i'; 65_537];
            let (status, complete) = send(&addr, &body);
            assert_eq!(status, Some(expected_status));
            assert!(complete);
            for _ in 0..expected_attempts {
                child.accepted.recv_timeout(Duration::from_secs(3)).unwrap();
                assert_eq!(child.received.recv_timeout(Duration::from_secs(3)).unwrap(), body);
            }
            assert!(
                matches!(
                    child.accepted.recv_timeout(Duration::from_millis(200)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ),
                "no further iteration after the budget stops the request"
            );
            probe(&addr, "ok");
            #[cfg(target_os = "linux")]
            {
                let after = praxis_test_utils::sample_process(process.pid()).unwrap();
                assert!(before.rss_bytes.is_some_and(|value| value > 0));
                assert!(after.rss_bytes.is_some_and(|value| value > 0));
            }
            process.signal("TERM");
            let (status, killed) = process.wait_or_kill(Duration::from_secs(10));
            assert!(!killed && status.success());
        }
    }
}
