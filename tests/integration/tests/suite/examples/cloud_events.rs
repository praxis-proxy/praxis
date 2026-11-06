// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the CloudEvents publisher example.

#[cfg(target_os = "linux")]
mod slow_process;

use std::{
    collections::HashMap,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use praxis_test_utils::{
    H1Completion, free_port, http_send, parse_status, read_h1_response, start_backend, start_full_proxy, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn cloud_events_example_publishes_after_response_completion() {
    let receiver = TcpListener::bind("127.0.0.1:0").unwrap();
    let receiver_port = receiver.local_addr().unwrap().port();
    let (sender, received) = mpsc::channel();
    let receiver_thread = thread::spawn(move || {
        let (mut stream, _) = receiver.accept().unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 4096];
        let body_length = loop {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0, "event receiver connection must contain a request");
            request.extend_from_slice(&chunk[..read]);
            let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            break headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
        };
        let header_end = request.windows(4).position(|window| window == b"\r\n\r\n").unwrap() + 4;
        while request.len() < header_end + body_length {
            let read = stream.read(&mut chunk).unwrap();
            assert!(
                read > 0,
                "event receiver connection must contain the complete request body"
            );
            request.extend_from_slice(&chunk[..read]);
        }
        sender.send(request).unwrap();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });

    let backend_port = start_backend("cloud-events-backend");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "observability/cloud-events.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", receiver_port)]),
    );
    let proxy = start_full_proxy(&config);

    let response = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: example-client\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&response),
        200,
        "event publication must not change the client response"
    );

    let event = received
        .recv_timeout(Duration::from_secs(2))
        .expect("receiver must receive a CloudEvent");
    let event = String::from_utf8(event).expect("CloudEvent request must be UTF-8");
    assert!(
        event.starts_with("POST /events HTTP/1.1\r\n"),
        "receiver must get the configured path: {event}"
    );
    assert!(
        event
            .to_ascii_lowercase()
            .contains("content-type: application/cloudevents+json"),
        "receiver must get structured CloudEvents content type: {event}"
    );
    assert!(
        event.contains("\"specversion\":\"1.0\""),
        "event must use CloudEvents 1.0: {event}"
    );
    assert!(
        event.contains("\"status\":200"),
        "event must include mapped response status: {event}"
    );
    assert!(
        event.contains("\"user_agent\":\"unverified\""),
        "event must include configured provenance: {event}"
    );
    receiver_thread.join().unwrap();
}

#[test]
fn cloud_events_receiver_failure_does_not_change_client_response() {
    let backend_port = start_backend("cloud-events-backend");
    let proxy_port = free_port();
    let unavailable_receiver_port = free_port();
    let config = super::load_example_config(
        "observability/cloud-events.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3000", backend_port),
            ("127.0.0.1:3001", unavailable_receiver_port),
        ]),
    );
    let proxy = start_full_proxy(&config);

    let response = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(
        parse_status(&response),
        200,
        "receiver failure must not change the client response"
    );
}

#[test]
fn cloud_event_waits_for_stream_completion_and_excludes_payload() {
    let (event_port, events) = bounded_event_receiver();
    let (backend_port, resume) = paused_sse_backend();
    let proxy_port = free_port();
    let mut config = super::load_example_config(
        "observability/cloud-events.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", event_port)]),
    );
    config.filter_chains[0]
        .filters
        .insert(0, serde_yaml::from_str("filter: access_log").unwrap());
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    let mut socket = TcpStream::connect(proxy.addr()).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: safe-agent\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut received = Vec::new();
    let mut resumed = false;
    let result = read_h1_response(&mut BufReader::new(socket), false, 262_144, |chunk| {
        received.extend_from_slice(chunk);
        if !resumed {
            assert!(b"data: first\n\n".starts_with(&received));
            if received.len() == b"data: first\n\n".len() {
                assert!(events.try_recv().is_err(), "response-complete event must wait for EOS");
                resume.send(()).unwrap();
                resumed = true;
            }
        }
        Ok(())
    });
    assert!(resumed);
    assert_eq!(result.status, Some(200));
    assert_eq!(result.completion, Some(H1Completion::Chunked));
    let mut expected = b"data: first\n\n".to_vec();
    expected.extend_from_slice(b"data: CANARY_EVENT_BODY_SECRET\n\n");
    expected.extend(std::iter::repeat_n(b'x', 131_072));
    assert_eq!(received, expected);
    let event = events.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(event.len() <= 65_536, "event is bounded");
    assert!(event.contains("\"status\":200"));
    assert!(!event.contains("CANARY_EVENT_BODY_SECRET"));
    assert!(
        events.recv_timeout(Duration::from_millis(500)).is_err(),
        "one completed response emits one event"
    );
}

#[test]
fn cloud_event_does_not_hide_a_stream_response_limit() {
    let (event_port, events) = bounded_event_receiver();
    let (backend_port, resume) = paused_sse_backend();
    let proxy_port = free_port();
    let mut config = super::load_example_config(
        "observability/cloud-events.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", event_port)]),
    );
    config.body_limits.max_response_bytes = Some(16_384);
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    let mut socket = TcpStream::connect(proxy.addr()).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut received = Vec::new();
    let mut resumed = false;
    let result = read_h1_response(&mut BufReader::new(socket), false, 16_384, |chunk| {
        received.extend_from_slice(chunk);
        if !resumed && received.len() >= b"data: first\n\n".len() {
            resume.send(()).unwrap();
            resumed = true;
        }
        Ok(())
    });
    assert!(resumed, "prefix must arrive before the tail");
    assert_eq!(result.status, Some(200));
    assert!(
        result.completion.is_none(),
        "an over-limit response cannot complete: {result:?}"
    );
    assert!(received.starts_with(b"data: first\n\n"));
    assert_eq!(
        received
            .windows(b"data: first\n\n".len())
            .filter(|window| *window == b"data: first\n\n")
            .count(),
        1
    );
    assert!(
        events.recv_timeout(Duration::from_millis(500)).is_err(),
        "the response-complete example must not emit for an aborted stream"
    );
    let probe = http_send(
        proxy.addr(),
        "GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&probe), 200);
    assert_eq!(praxis_test_utils::parse_body(&probe), "ok");
    let event = events.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(event.len() <= 65_536);
    assert!(!event.contains("CANARY_EVENT_BODY_SECRET"));
    events.recv_timeout(Duration::from_millis(500)).unwrap_err();
}

/// Accept events under a strict body bound, and acknowledge each one.
fn bounded_event_receiver() -> (u16, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let (sender, events) = mpsc::channel();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((socket, _)) => {
                    if sender.send(read_event(socket)).is_err() {
                        break;
                    }
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                },
                Err(error) => panic!("event receiver: {error}"),
            }
        }
    });
    (port, events)
}

/// Read and acknowledge one event without retaining unbounded data.
fn read_event(mut socket: TcpStream) -> String {
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reader = BufReader::new(&mut socket);
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        assert_ne!(
            reader.read_line(&mut line).unwrap(),
            0,
            "event headers ended prematurely"
        );
        headers.push_str(&line);
        assert!(headers.len() <= 16_384, "event headers exceeded the observation bound");
        if line == "\r\n" {
            break;
        }
    }
    let length: usize = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap();
    assert!(length <= 65_536, "event body exceeded the observation bound");
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    socket
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .unwrap();
    String::from_utf8(body).unwrap()
}

/// Hold the second event until the client has observed the first one.
fn paused_sse_backend() -> (u16, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (resume, wait) = mpsc::channel();
    thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut reader = BufReader::new(&mut socket);
        loop {
            let mut line = String::new();
            assert_ne!(
                reader.read_line(&mut line).unwrap(),
                0,
                "SSE request headers ended prematurely"
            );
            if line == "\r\n" {
                break;
            }
        }
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nd\r\ndata: first\n\n\r\n").unwrap();
        socket.flush().unwrap();
        wait.recv_timeout(Duration::from_secs(8)).unwrap();
        let tail = format!("data: CANARY_EVENT_BODY_SECRET\n\n{}", "x".repeat(131_072));
        let _sent = write!(socket, "{:x}\r\n{}\r\n0\r\n\r\n", tail.len(), tail);
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut probe, _)) => {
                    let mut reader = BufReader::new(&mut probe);
                    loop {
                        let mut line = String::new();
                        assert_ne!(
                            reader.read_line(&mut line).unwrap(),
                            0,
                            "probe request headers ended prematurely"
                        );
                        if line == "\r\n" {
                            break;
                        }
                    }
                    let _sent = probe.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                    break;
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                },
                Err(error) => panic!("probe backend: {error}"),
            }
        }
    });
    (port, resume)
}
