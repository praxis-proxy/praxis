// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for the Responses to Chat Completions translation example.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Receiver},
    time::Duration,
};

use praxis_test_utils::{Backend, free_port, http_send, json_post, parse_body, parse_status, start_proxy};

use super::load_example_config;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const CHAT_COMPLETIONS_RESPONSE: &str = r#"{"id":"chatcmpl-responses-test","model":"gpt-4o-mini","choices":[{"message":{"role":"assistant","content":"Hello from chat."},"finish_reason":"stop","index":0}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}"#;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn openai_responses_to_chat_completions_transforms_response_body() {
    let (backend_port, backend_requests) = start_recording_chat_backend(CHAT_COMPLETIONS_RESPONSE);
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/to-chat-completions.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4o-mini","instructions":"Reply briefly.","input":"Hello","store":false,"max_output_tokens":32}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));
    let transformed: serde_json::Value = serde_json::from_str(&parse_body(&raw)).expect("response body should be JSON");
    let upstream_body = backend_requests
        .recv_timeout(Duration::from_secs(5))
        .expect("backend should receive exactly one transformed request");
    let upstream: serde_json::Value = serde_json::from_str(&upstream_body).expect("upstream body should be JSON");

    assert_eq!(parse_status(&raw), 200, "translation should return 200");
    assert_eq!(upstream["model"], "gpt-4o-mini", "model should be preserved upstream");
    assert_eq!(upstream["max_completion_tokens"], 32, "token limit should map upstream");
    assert_eq!(
        upstream["messages"][0],
        serde_json::json!({"role": "system", "content": "Reply briefly."}),
        "instructions should become a system message"
    );
    assert_eq!(
        upstream["messages"][1],
        serde_json::json!({"role": "user", "content": "Hello"}),
        "input should become a user message"
    );
    assert_eq!(transformed["object"], "response", "response object type");
    assert_eq!(transformed["status"], "completed", "response status");
    assert_eq!(transformed["instructions"], "Reply briefly.", "instructions echoed");
    assert_eq!(transformed["input"], "Hello", "input echoed");
    assert_eq!(
        transformed["output"][0]["content"][0]["text"], "Hello from chat.",
        "Chat Completions text should map to Responses output text"
    );
    assert_eq!(transformed["usage"]["input_tokens"], 7, "prompt tokens mapped");
    assert_eq!(transformed["usage"]["output_tokens"], 3, "completion tokens mapped");
}

#[test]
fn openai_responses_to_chat_completions_rejects_streaming_until_stream_filter_exists() {
    let backend_guard = Backend::fixed(CHAT_COMPLETIONS_RESPONSE)
        .header("content-type", "application/json")
        .start_with_shutdown();
    let proxy_port = free_port();

    let config = load_example_config(
        "ai/openai/responses/to-chat-completions.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let body = r#"{"model":"gpt-4o-mini","input":"Hello","stream":true,"store":false}"#;
    let raw = http_send(proxy.addr(), &json_post("/v1/responses", body));
    let parsed: serde_json::Value = serde_json::from_str(&parse_body(&raw)).expect("error body should be JSON");

    assert_eq!(
        parse_status(&raw),
        400,
        "streaming translation should be rejected clearly"
    );
    assert_eq!(
        parsed["error"]["type"].as_str(),
        Some("invalid_request_error"),
        "error type should be invalid_request_error"
    );
    assert!(
        parsed["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("streaming")),
        "error message should explain streaming is not supported yet"
    );
}

// -----------------------------------------------------------------------------
// Test Helpers
// -----------------------------------------------------------------------------

/// Start a one-shot backend that records the request body and returns a fixed
/// Chat Completions response.
fn start_recording_chat_backend(response_body: &'static str) -> (u16, Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("recording backend should bind");
    let port = listener
        .local_addr()
        .expect("recording backend should expose local addr")
        .port();
    let (sender, receiver) = mpsc::channel();

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("recording backend should set read timeout");
            let request = read_request(&mut stream);

            if !request.starts_with("POST ") {
                write_response(&mut stream, "ready", "text/plain");
                continue;
            }

            let body = request_body(&request);
            sender
                .send(body)
                .expect("recording backend request channel should be open");
            write_response(&mut stream, response_body, "application/json");
            break;
        }
    });

    (port, receiver)
}

/// Read a complete HTTP request using `Content-Length`.
fn read_request(stream: &mut TcpStream) -> String {
    let mut data = Vec::new();
    let mut buf = [0_u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }

        let raw = String::from_utf8_lossy(&data);
        if let Some(header_section) = raw.split("\r\n\r\n").next() {
            let content_length = parse_content_length(header_section);
            let header_len = header_section.len() + 4;
            if data.len() >= header_len + content_length {
                break;
            }
        }
    }

    String::from_utf8_lossy(&data).into_owned()
}

/// Extract the HTTP request body from a raw request string.
fn request_body(raw: &str) -> String {
    raw.split("\r\n\r\n").nth(1).unwrap_or("").to_owned()
}

/// Extract `Content-Length` from raw request headers.
fn parse_content_length(headers: &str) -> usize {
    headers
        .lines()
        .find(|line| line.to_lowercase().starts_with("content-length:"))
        .and_then(|line| line.split_once(':').map(|(_, value)| value))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
}

/// Write a simple HTTP response.
fn write_response(stream: &mut TcpStream, body: &str, content_type: &str) {
    let headers = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .expect("recording backend should write response headers");
    stream
        .write_all(body.as_bytes())
        .expect("recording backend should write response body");
}
