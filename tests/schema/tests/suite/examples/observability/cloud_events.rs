// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! CloudEvents publisher example schema tests.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::Duration,
};

use praxis_test_utils::{free_port, http_send, parse_body, parse_status, start_backend, start_full_proxy};
use serde_json::Value;

// -----------------------------------------------------------------------------
// Test Receiver
// -----------------------------------------------------------------------------

fn start_event_receiver(response: &'static [u8]) -> (u16, Receiver<String>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, received) = mpsc::channel();
    let receiver_thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        sender.send(read_request(&mut stream)).unwrap();
        stream.write_all(response).unwrap();
    });

    (port, received, receiver_thread)
}

fn read_request(stream: &mut TcpStream) -> String {
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    let mut request = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0, "event receiver connection must contain a request");
        request.extend_from_slice(&chunk[..read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break header_end + 4;
        }
    };
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
        })
        .flatten()
        .unwrap_or(0);
    while request.len() < header_end + content_length {
        let read = stream.read(&mut chunk).unwrap();
        assert!(
            read > 0,
            "event receiver connection must contain the complete request body"
        );
        request.extend_from_slice(&chunk[..read]);
    }

    String::from_utf8(request).unwrap()
}

fn event_json(request: &str) -> Value {
    let (_, body) = request
        .split_once("\r\n\r\n")
        .expect("event request must contain headers");
    serde_json::from_str(body).expect("event request body must be valid JSON")
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn cloud_events_example_parses() {
    let backend_port = start_backend("cloud-events");
    let proxy_port = free_port();
    let receiver_port = free_port();
    let config = crate::example_utils::load_example_config(
        "observability/cloud-events.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", receiver_port)]),
    );
    let _proxy = start_full_proxy(&config);
}

#[test]
fn cloud_events_example_forwards_requests_when_receiver_is_unavailable() {
    let backend_port = start_backend("cloud-events");
    let proxy_port = free_port();
    let unavailable_receiver_port = free_port();
    let config = crate::example_utils::load_example_config(
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
        "event delivery must not change the response"
    );
    assert_eq!(parse_body(&response), "cloud-events", "request must reach the backend");
}

#[test]
fn cloud_events_example_publishes_structured_event() {
    let (receiver_port, received, receiver_thread) =
        start_event_receiver(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
    let backend_port = start_backend("cloud-events");
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
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
        "event delivery must not change the response"
    );

    let request = received
        .recv_timeout(Duration::from_secs(2))
        .expect("receiver must receive a CloudEvent");
    assert!(request.starts_with("POST /events HTTP/1.1\r\n"));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("content-type: application/cloudevents+json")
    );
    let event = event_json(&request);
    assert_eq!(event["specversion"], "1.0");
    assert_eq!(event["source"], "urn:praxis:gateway");
    assert_eq!(event["type"], "gateway.response.completed");
    assert_eq!(event["data"]["status"], 200);
    assert_eq!(event["data"]["user_agent"], "example-client");
    assert_eq!(event["data"]["_praxis_provenance"]["user_agent"], "unverified");
    receiver_thread.join().unwrap();
}

#[test]
fn cloud_events_example_omits_optional_user_agent() {
    let (receiver_port, received, receiver_thread) =
        start_event_receiver(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
    let backend_port = start_backend("cloud-events");
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "observability/cloud-events.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", receiver_port)]),
    );
    let proxy = start_full_proxy(&config);

    let response = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&response),
        200,
        "event delivery must not change the response"
    );

    let request = received
        .recv_timeout(Duration::from_secs(2))
        .expect("receiver must receive a CloudEvent");
    let event = event_json(&request);
    assert_eq!(event["data"]["status"], 200);
    assert!(event["data"].get("user_agent").is_none());
    assert!(event["data"]["_praxis_provenance"].get("user_agent").is_none());
    receiver_thread.join().unwrap();
}

#[test]
fn cloud_events_example_ignores_receiver_http_failure() {
    let (receiver_port, received, receiver_thread) =
        start_event_receiver(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
    let backend_port = start_backend("cloud-events");
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "observability/cloud-events.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port), ("127.0.0.1:3001", receiver_port)]),
    );
    let proxy = start_full_proxy(&config);

    let response = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(
        parse_status(&response),
        200,
        "receiver failure must not change the response"
    );
    assert_eq!(parse_body(&response), "cloud-events", "request must reach the backend");
    received
        .recv_timeout(Duration::from_secs(2))
        .expect("receiver must receive the attempted CloudEvent");
    receiver_thread.join().unwrap();
}
