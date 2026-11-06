// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the gRPC-Web translation example configuration.
//!
//! The point of the filter is that a browser-shaped call reaches a
//! gRPC backend and gets its status back in the body, so these drive
//! it the way a browser would — over HTTP/1.1, with no access to
//! trailers — and read the status out of the response bytes.

use std::{
    collections::HashMap,
    io::{BufReader, Write as _},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
};

use base64::Engine as _;
use bytes::Bytes;
use praxis_core::config::Config;
use praxis_test_utils::{
    GrpcBackend, H1Completion, free_port, http_send, parse_body, parse_status, read_h1_response, start_full_proxy,
    start_grpc_backend, start_proxy, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn a_binary_grpc_web_call_gets_its_status_in_the_body() {
    let backend = start_grpc_backend(
        GrpcBackend::status(5)
            .message("no such user")
            .body(b"\x00\x00\x00\x00\x02hi".as_slice()),
    );
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));

    let raw = http_send(proxy.addr(), &grpc_web_request("application/grpc-web+proto", ""));

    assert_eq!(parse_status(&raw), 200, "the call should reach the backend: {raw}");
    assert_eq!(
        header_value(&raw, "content-type").as_deref(),
        Some("application/grpc-web+proto"),
        "the response should be typed as gRPC-Web, not native gRPC: {raw}"
    );
    let body = parse_body(&raw);
    assert!(
        body.contains("grpc-status: 5"),
        "the trailer must arrive in the body, since a browser cannot read HTTP trailers: {body:?}"
    );
    assert!(
        body.contains("grpc-message: no such user"),
        "the message should survive the translation: {body:?}"
    );
    assert!(
        !raw.to_ascii_lowercase().contains("\ngrpc-status:"),
        "the status must not also be left as an HTTP trailer: {raw}"
    );
}

#[test]
fn a_successful_call_carries_status_zero() {
    let backend = start_grpc_backend(GrpcBackend::ok().body(b"\x00\x00\x00\x00\x02hi".as_slice()));
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));

    let raw = http_send(proxy.addr(), &grpc_web_request("application/grpc-web+proto", ""));
    let body = parse_body(&raw);

    assert!(
        body.contains("hi"),
        "the message frame should be forwarded verbatim: {body:?}"
    );
    assert!(
        body.contains("grpc-status: 0"),
        "a successful call still needs its status frame: {body:?}"
    );
}

#[test]
fn a_text_call_is_decoded_upstream_and_re_encoded_downstream() {
    let backend = start_grpc_backend(GrpcBackend::ok().body(b"\x00\x00\x00\x00\x02hi".as_slice()));
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));

    let encoded_request = base64::engine::general_purpose::STANDARD.encode(b"\x00\x00\x00\x00\x00");
    let raw = http_send(
        proxy.addr(),
        &grpc_web_request("application/grpc-web-text", &encoded_request),
    );

    assert_eq!(parse_status(&raw), 200, "the call should succeed: {raw}");
    let body = parse_body(&raw);
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .unwrap_or_else(|error| panic!("the -text response must be valid base64 ({error}): {body:?}"));
    let text = String::from_utf8_lossy(&decoded);
    assert!(
        text.contains("grpc-status: 0"),
        "the decoded stream should carry the trailer frame: {text:?}"
    );
    assert!(text.contains("hi"), "and the message frame: {text:?}");
}

#[test]
fn a_trailers_only_error_keeps_its_status_in_the_headers() {
    // A single END_STREAM header block with the status and no body.
    // There is no body phase to append a frame to, and none is needed:
    // gRPC-Web clients read the status off the headers in this case.
    let backend = start_grpc_backend(GrpcBackend::status(7).message("denied").trailers_only());
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));

    let raw = http_send(proxy.addr(), &grpc_web_request("application/grpc-web+proto", ""));

    assert_eq!(
        header_value(&raw, "grpc-status").as_deref(),
        Some("7"),
        "the status must survive to the client: {raw}"
    );
    assert!(
        !parse_body(&raw).contains("grpc-status: 2"),
        "a real status must never be overwritten by the synthesized UNKNOWN: {raw}"
    );
}

#[test]
fn non_grpc_web_traffic_is_untouched() {
    let backend = start_grpc_backend(GrpcBackend::ok().body(b"\x00\x00\x00\x00\x02hi".as_slice()));
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));

    // A native gRPC client needs no translation and must not get a
    // trailer frame appended to its body.
    let raw = http_send(proxy.addr(), &grpc_web_request("application/grpc", ""));

    assert_eq!(parse_status(&raw), 200, "native gRPC should pass through: {raw}");
    assert!(
        !parse_body(&raw).contains("grpc-status:"),
        "a native gRPC client reads trailers itself: {raw}"
    );
}

#[test]
fn example_text_buffer_boundary_and_invalid_tail() {
    const LIMIT: usize = 10_485_760; // example's encoded request buffer
    let backend = recording_grpc_backend(grpc_frame(32_771));
    let proxy_port = free_port();
    let proxy = start_full_proxy(&example(proxy_port, backend.port));
    wait_for_tcp(proxy.addr());

    let request = grpc_frame(LIMIT / 4 * 3 - 5);
    let encoded = base64::engine::general_purpose::STANDARD.encode(&request);
    assert_eq!(encoded.len(), LIMIT);
    let (status, body) = send_binary_request(proxy.addr(), "application/grpc-web-text", encoded.as_bytes());
    assert_eq!(status, 200);
    assert_receipt(&backend, &request);
    assert_grpc_web_response(&body, true, &grpc_frame(32_771));

    let below = grpc_frame((LIMIT - 4) / 4 * 3 - 5);
    let below_encoded = base64::engine::general_purpose::STANDARD.encode(&below);
    assert_eq!(
        below_encoded.len(),
        LIMIT - 4,
        "the largest smaller valid base64 length"
    );
    let (status, body) = send_binary_request(proxy.addr(), "application/grpc-web-text", below_encoded.as_bytes());
    assert_eq!(status, 200);
    assert_receipt(&backend, &below);
    assert_grpc_web_response(&body, true, &grpc_frame(32_771));

    let mut invalid = encoded.clone().into_bytes();
    invalid.pop();
    assert_eq!(invalid.len(), LIMIT - 1);
    assert_eq!(
        send_binary_request(proxy.addr(), "application/grpc-web-text", &invalid).0,
        400
    );
    let mut over = encoded.into_bytes();
    over.push(b'!');
    assert_eq!(
        send_binary_request(proxy.addr(), "application/grpc-web-text", &over).0,
        413
    );
    assert!(
        backend.receipts.recv_timeout(Duration::from_millis(200)).is_err(),
        "rejected bodies must not reach gRPC"
    );

    let probe = grpc_frame(2);
    let encoded_probe = base64::engine::general_purpose::STANDARD.encode(&probe);
    let (status, body) = send_binary_request(proxy.addr(), "application/grpc-web-text", encoded_probe.as_bytes());
    assert_eq!(status, 200);
    assert_grpc_web_response(&body, true, &grpc_frame(32_771));
    assert_receipt(&backend, &probe);
}

#[test]
fn example_large_binary_and_text_translate_messages_and_status() {
    let response = grpc_frame(1_048_579);
    let backend = recording_grpc_backend(response.clone());
    let proxy_port = free_port();
    let mut config = example(proxy_port, backend.port);
    config.body_limits.max_response_bytes = Some(response.len());
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    let request = grpc_frame(65_537);
    for (content_type, text) in [
        ("application/grpc-web+proto", false),
        ("application/grpc-web-text", true),
    ] {
        let input = if text {
            base64::engine::general_purpose::STANDARD.encode(&request).into_bytes()
        } else {
            request.clone()
        };
        let (status, output) = send_binary_request(proxy.addr(), content_type, &input);
        assert_eq!(status, 200);
        assert_receipt(&backend, &request);
        assert!(
            output.len() > response.len(),
            "the response limit counts input before encoding and trailers"
        );
        assert_grpc_web_response(&output, text, &response);
    }
}

#[test]
fn text_filter_buffer_limit_is_on_encoded_input_even_with_larger_global_limit() {
    const LIMIT: usize = 65_536;
    let backend = recording_grpc_backend(grpc_frame(7));
    let proxy_port = free_port();
    let mut config = example(proxy_port, backend.port);
    config.body_limits.max_request_bytes = Some(LIMIT * 2);
    let grpc = &mut config.filter_chains[0].filters[0];
    assert_eq!(grpc.filter_type, "grpc_web");
    grpc.config.as_mapping_mut().unwrap().insert(
        serde_yaml::Value::from("max_buffer_bytes"),
        serde_yaml::Value::from(LIMIT),
    );
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    let request = grpc_frame(LIMIT / 4 * 3 - 5);
    let mut encoded = base64::engine::general_purpose::STANDARD.encode(&request).into_bytes();
    assert_eq!(encoded.len(), LIMIT);
    let (status, response) = send_binary_request(proxy.addr(), "application/grpc-web-text", &encoded);
    assert_eq!(status, 200);
    assert_grpc_web_response(&response, true, &grpc_frame(7));
    assert_receipt(&backend, &request);
    encoded.push(b'!');
    assert_eq!(
        send_binary_request(proxy.addr(), "application/grpc-web-text", &encoded).0,
        413
    );
    backend.receipts.recv_timeout(Duration::from_millis(200)).unwrap_err();
    let probe = grpc_frame(1);
    let encoded_probe = base64::engine::general_purpose::STANDARD.encode(&probe);
    let (status, response) = send_binary_request(proxy.addr(), "application/grpc-web-text", encoded_probe.as_bytes());
    assert_eq!(status, 200);
    assert_grpc_web_response(&response, true, &grpc_frame(7));
    assert_receipt(&backend, &probe);
}

#[test]
fn text_request_is_decoded_before_http2_forwarding() {
    let backend = recording_grpc_backend(grpc_frame(2));
    let proxy = start_full_proxy(&example(free_port(), backend.port));
    wait_for_tcp(proxy.addr());
    let request = grpc_frame(3);
    let encoded = base64::engine::general_purpose::STANDARD.encode(&request);
    let (status, body) = send_binary_request(proxy.addr(), "application/grpc-web-text", encoded.as_bytes());
    assert_eq!(status, 200);
    assert_receipt(&backend, &request);
    assert_grpc_web_response(&body, true, &grpc_frame(2));
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Load the example config, pointing it at `backend_port`.
fn example(proxy_port: u16, backend_port: u16) -> Config {
    super::load_example_config(
        "payload-processing/grpc-web.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:50051", backend_port)]),
    )
}

/// Build a gRPC-Web request with the given content type and body.
fn grpc_web_request(content_type: &str, body: &str) -> String {
    format!(
        "POST /pkg.Svc/Method HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        len = body.len(),
    )
}

/// A header value from a raw HTTP/1.1 response.
fn header_value(raw: &str, name: &str) -> Option<String> {
    raw.lines()
        .take_while(|line| !line.trim().is_empty())
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _value)| key.trim().eq_ignore_ascii_case(name))
        .map(|(_key, value)| value.trim().to_owned())
}

/// Generate a valid, deterministic length-prefixed gRPC message.
fn grpc_frame(payload_len: usize) -> Vec<u8> {
    let mut frame = vec![0];
    frame.extend_from_slice(&u32::try_from(payload_len).unwrap().to_be_bytes());
    frame.extend((0..payload_len).map(|index| u8::try_from(index % 251).unwrap()));
    frame
}

/// A bounded recording backend that shuts down when the test ends.
struct RecordingGrpcBackend {
    /// Listener port for the HTTP/2 upstream.
    port: u16,
    /// Complete request bodies, in acceptance order.
    receipts: Receiver<Vec<u8>>,
    /// Shutdown signal for the listener and active connections.
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    /// Backend runtime thread, joined at teardown.
    worker: Option<thread::JoinHandle<()>>,
}

/// Compare complete backend content without printing a potentially huge body on failure.
fn assert_receipt(backend: &RecordingGrpcBackend, expected: &[u8]) {
    let actual = backend.receipts.recv_timeout(Duration::from_secs(10)).unwrap();
    let mismatch = actual.iter().zip(expected).position(|(left, right)| left != right);
    assert!(
        actual == expected,
        "backend body differs: actual length {}, expected length {}, first mismatch {mismatch:?}",
        actual.len(),
        expected.len()
    );
}

impl Drop for RecordingGrpcBackend {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _sent = shutdown.send(());
        }
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

/// Observe the exact request, then send a gRPC message and status trailers over h2c.
fn recording_grpc_backend(response: Vec<u8>) -> RecordingGrpcBackend {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let (sender, receipts) = mpsc::channel();
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    let worker = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let server = async {
                loop {
                    let (socket, _) = listener.accept().await.unwrap();
                    let sender = sender.clone();
                    let response = Bytes::copy_from_slice(&response);
                    tokio::spawn(async move {
                        let mut connection = h2::server::handshake(socket).await.unwrap();
                        while let Some(Ok((request, mut respond))) = connection.accept().await {
                            let sender = sender.clone();
                            let response = response.clone();
                            tokio::spawn(async move {
                                assert_eq!(
                                    request.headers().get("content-type").unwrap(),
                                    "application/grpc+proto",
                                    "backend must receive native gRPC"
                                );
                                let mut body = request.into_body();
                                let mut received = Vec::new();
                                while let Some(chunk) = body.data().await {
                                    let chunk = chunk.unwrap();
                                    received.extend_from_slice(&chunk);
                                    body.flow_control().release_capacity(chunk.len()).unwrap();
                                }
                                sender.send(received).unwrap();
                                let headers = http::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/grpc")
                                    .body(())
                                    .unwrap();
                                let mut stream = respond.send_response(headers, false).unwrap();
                                stream.send_data(response, false).unwrap();
                                let mut trailers = http::HeaderMap::new();
                                let _previous = trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                                stream.send_trailers(trailers).unwrap();
                            });
                        }
                    });
                }
            };
            tokio::select! {
                () = server => {},
                _shutdown = shutdown_rx => {},
                () = tokio::time::sleep(Duration::from_secs(60)) => {},
            }
        });
    });
    RecordingGrpcBackend {
        port,
        receipts,
        shutdown: Some(shutdown),
        worker: Some(worker),
    }
}

/// Send content without interpreting binary data as HTTP framing.
fn send_binary_request(addr: &str, content_type: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut socket = TcpStream::connect(addr).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(socket, "POST /pkg.Svc/Method HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
    let _sent = socket.write_all(body); // A rejection may close before the client finishes writing.
    let mut received = Vec::new();
    let response = read_h1_response(&mut BufReader::new(socket), false, 16_777_216, |part| {
        received.extend_from_slice(part);
        Ok(())
    });
    assert!(
        matches!(
            response.completion,
            Some(H1Completion::Chunked | H1Completion::ContentLength)
        ),
        "response framing: {response:?}"
    );
    (response.status.unwrap(), received)
}

/// Check the complete message, final trailer frame and text expansion.
fn assert_grpc_web_response(wire: &[u8], text: bool, expected_message: &[u8]) {
    let decoded = if text {
        base64::engine::general_purpose::STANDARD.decode(wire).unwrap()
    } else {
        wire.to_vec()
    };
    assert!(
        decoded.starts_with(expected_message),
        "decoded message differs, length {} versus expected {}",
        decoded.len(),
        expected_message.len()
    );
    let trailer = &decoded[expected_message.len()..];
    assert_eq!(trailer[0], 0x80, "trailer frame must carry the gRPC-Web trailer flag");
    assert_eq!(
        usize::try_from(u32::from_be_bytes(trailer[1..5].try_into().unwrap())).unwrap(),
        trailer.len() - 5,
        "trailer frame must declare its exact payload length"
    );
    assert_eq!(
        &trailer[5..],
        b"grpc-status: 0\r\n",
        "trailer must carry the backend status"
    );
    if text {
        assert_eq!(
            wire.len(),
            decoded.len().div_ceil(3) * 4,
            "text response must have exact base64 expansion"
        );
    }
}
