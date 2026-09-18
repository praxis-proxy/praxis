// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the gRPC deadline example configuration.

use std::{collections::HashMap, time::Duration};

use praxis_core::config::Config;
use praxis_test_utils::{GrpcBackend, free_port, http_send, parse_status, start_grpc_backend, start_proxy};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Build a gRPC request, optionally carrying a `grpc-timeout`.
fn grpc_request(timeout: Option<&str>) -> String {
    let header = timeout.map_or_else(String::new, |value| format!("grpc-timeout: {value}\r\n"));
    format!(
        "POST /pkg.Svc/Method HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/grpc\r\n\
         Content-Length: 0\r\n\
         {header}\
         Connection: close\r\n\r\n"
    )
}

/// Load the example config, pointing it at `backend_port`.
fn example(proxy_port: u16, backend_port: u16) -> Config {
    super::load_example_config(
        "traffic-management/grpc-timeout.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:50051", backend_port)]),
    )
}

/// The value of a header in a raw HTTP/1.1 response, lowercased name match.
fn header_value(raw: &str, name: &str) -> Option<String> {
    raw.lines()
        .take_while(|line| !line.trim().is_empty())
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().to_owned())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn deadline_is_decremented_before_reaching_the_upstream() {
    let backend = start_grpc_backend(GrpcBackend::ok());
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));
    // The harness's readiness probe already reached the backend.
    let _probe = backend.drain_seen_timeouts();

    let raw = http_send(proxy.addr(), &grpc_request(Some("5S")));
    assert_eq!(parse_status(&raw), 200, "the call should reach the backend: {raw}");

    let seen = backend.seen_timeouts();
    let forwarded = seen.first().expect("the backend should have seen one request");
    assert!(
        !forwarded.is_empty(),
        "the deadline should be propagated upstream, not dropped"
    );
    // The example withholds 50ms of headroom, so a 5s ask can never
    // arrive upstream as 5s.
    assert_ne!(
        forwarded, "5S",
        "the upstream should be told the remaining budget, not the client's original ask"
    );
    let remaining = praxis_core::grpc::GrpcTimeout::parse(forwarded)
        .expect("the forwarded value should be a valid grpc-timeout")
        .as_duration();
    assert!(
        remaining < Duration::from_secs(5),
        "{forwarded} decodes to {remaining:?}, which is not less than the client's 5s"
    );
}

#[test]
fn a_slow_upstream_is_cancelled_with_deadline_exceeded() {
    // Slow enough that a 300ms deadline must fire first, but inside the
    // harness's readiness-probe budget: the probe goes to this backend too.
    let backend = start_grpc_backend(GrpcBackend::ok().delay(Duration::from_secs(2)));
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));
    let _probe = backend.drain_seen_timeouts();

    let started = std::time::Instant::now();
    let raw = http_send(proxy.addr(), &grpc_request(Some("300m")));
    let elapsed = started.elapsed();

    assert_eq!(
        parse_status(&raw),
        200,
        "gRPC reports failures as HTTP 200 with a grpc-status: {raw}"
    );
    assert_eq!(
        header_value(&raw, "grpc-status").as_deref(),
        Some("4"),
        "an expired deadline is DEADLINE_EXCEEDED: {raw}"
    );
    assert!(
        elapsed < Duration::from_millis(1_500),
        "the deadline should cancel the call in ~300ms, not wait out the 2s backend (took {elapsed:?})"
    );
}

#[test]
fn a_malformed_deadline_is_rejected_without_contacting_the_upstream() {
    let backend = start_grpc_backend(GrpcBackend::ok());
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));
    let _probe = backend.drain_seen_timeouts();

    let raw = http_send(proxy.addr(), &grpc_request(Some("ten seconds")));

    assert_eq!(
        header_value(&raw, "grpc-status").as_deref(),
        Some("13"),
        "a malformed grpc-timeout is INTERNAL: {raw}"
    );
    assert!(
        backend.seen_timeouts().is_empty(),
        "the upstream should never have been contacted"
    );
}

#[test]
fn a_header_less_call_gets_the_configured_default() {
    let backend = start_grpc_backend(GrpcBackend::ok());
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));
    let _probe = backend.drain_seen_timeouts();

    let raw = http_send(proxy.addr(), &grpc_request(None));
    assert_eq!(parse_status(&raw), 200, "the call should succeed: {raw}");

    let seen = backend.seen_timeouts();
    let forwarded = seen.first().expect("the backend should have seen one request");
    let remaining = praxis_core::grpc::GrpcTimeout::parse(forwarded)
        .expect("the default deadline should be propagated")
        .as_duration();
    assert!(
        remaining <= Duration::from_secs(10),
        "{forwarded} exceeds the example's 10s default"
    );
}

#[test]
fn non_grpc_traffic_is_unaffected() {
    let backend = start_grpc_backend(GrpcBackend::ok());
    let proxy_port = free_port();
    let proxy = start_proxy(&example(proxy_port, backend.port()));
    let _probe = backend.drain_seen_timeouts();

    // No gRPC content-type: the filter must not install a deadline, so
    // no grpc-timeout reaches the upstream.
    let raw = http_send(
        proxy.addr(),
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "plain HTTP should pass through: {raw}");
    assert_eq!(
        backend.seen_timeouts().first().map(String::as_str),
        Some(""),
        "a non-gRPC request should carry no grpc-timeout"
    );
}
