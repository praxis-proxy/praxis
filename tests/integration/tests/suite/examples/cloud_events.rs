// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the CloudEvents publisher example.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    net::TcpListener,
    sync::mpsc,
    thread,
    time::Duration,
};

use praxis_test_utils::{free_port, http_send, parse_status, start_backend, start_full_proxy};

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
