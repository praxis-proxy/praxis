// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Functional tests for the trace context example configuration.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_send, parse_body, parse_status, start_header_echo_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn trace_context_generates_traceparent_when_absent() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "observability/trace-context.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "proxy should return 200");

    let body = parse_body(&raw);
    let traceparent = extract_header_from_echo(&body, "traceparent");
    assert!(traceparent.is_some(), "upstream request should have traceparent header");

    let tp = traceparent.unwrap();
    assert!(tp.starts_with("00-"), "traceparent should start with version 00");
    assert_eq!(tp.len(), 55, "traceparent should be 55 characters");
}

#[test]
fn trace_context_joins_existing_trace() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "observability/trace-context.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "proxy should return 200");

    let body = parse_body(&raw);
    let traceparent = extract_header_from_echo(&body, "traceparent").expect("upstream should have traceparent");

    assert!(
        traceparent.contains("4bf92f3577b34da6a3ce929d0e0e4736"),
        "trace_id should be preserved from incoming request"
    );
    assert!(
        !traceparent.contains("00f067aa0ba902b7"),
        "parent_id should be updated to proxy's span"
    );
}

#[test]
fn trace_context_forwards_tracestate() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "observability/trace-context.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\
         tracestate: congo=t61rcWkgMzE,rojo=00f067aa0ba902b7\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "proxy should return 200");

    let body = parse_body(&raw);
    let tracestate = extract_header_from_echo(&body, "tracestate").expect("upstream should have tracestate");
    assert_eq!(
        tracestate, "congo=t61rcWkgMzE,rojo=00f067aa0ba902b7",
        "tracestate should be forwarded verbatim"
    );
}

#[test]
fn trace_context_ignores_malformed_traceparent() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "observability/trace-context.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         traceparent: not-a-valid-traceparent\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "proxy should return 200 even with bad traceparent"
    );

    let body = parse_body(&raw);
    let traceparent = extract_header_from_echo(&body, "traceparent").expect("upstream should have a new traceparent");

    assert!(
        traceparent.starts_with("00-"),
        "new traceparent should be generated when incoming is malformed"
    );
    assert_eq!(traceparent.len(), 55, "generated traceparent should be 55 characters");
}

#[test]
fn trace_context_strips_tracestate_when_traceparent_absent() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "observability/trace-context.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         tracestate: congo=t61rcWkgMzE\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "proxy should return 200");

    let body = parse_body(&raw);
    assert!(
        extract_header_from_echo(&body, "tracestate").is_none(),
        "tracestate should be stripped when traceparent is absent"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Extract a header value from the echo backend's response body.
///
/// The echo backend returns request headers as `name: value` lines.
fn extract_header_from_echo(body: &str, name: &str) -> Option<String> {
    let lower_name = name.to_lowercase();
    body.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim().to_lowercase() == lower_name).then(|| value.trim().to_owned())
    })
}
