// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! HTTP QUERY forwarding and policy-driven request replay.

#[cfg(all(feature = "hedged-requests", feature = "pingora"))]
mod hedge;
mod http2;

use praxis_core::config::Config;
use praxis_test_utils::{
    ProxyGuard, RecordedRequest, RequestLog, free_port, http_send, parse_body, parse_header, parse_status,
    start_full_proxy, start_recording_backend, wait_for_tcp,
};

/// A query with non-ASCII content to expose lossy body handling.
pub(super) const QUERY_BODY: &str = r#"{"category":"café","limit":2}"#;
/// Both the target's query component and the QUERY body must survive forwarding.
pub(super) const TARGET: &str = "/products?sort=price&tag=a%2Fb";
/// Retry failures after the backend has had a chance to consume the body.
const RETRY_POLICY: &str = "max_retries: 1\n              retriable_conditions: [connect_failure, reset, status_5xx]";

#[test]
fn query_content_length_preserves_method_target_headers_and_body() {
    let (backend, log) = start_recording_backend(|_| response(202, "results"));
    let proxy = start(&yaml(&[backend.port()], "max_retries: 0"));

    let raw = http_send(proxy.addr(), &request("QUERY", QUERY_BODY));

    assert_eq!(parse_status(&raw), 202, "the origin's status must survive: {raw}");
    assert_eq!(parse_body(&raw), "results", "the origin's result must survive");
    assert_eq!(parse_header(&raw, "accept-query"), Some("application/json".to_owned()));
    assert_query(&observed(&log), QUERY_BODY);
}

#[test]
fn query_chunked_preserves_the_decoded_body() {
    let (backend, log) = start_recording_backend(|_| response(200, "results"));
    let proxy = start(&yaml(&[backend.port()], "max_retries: 0"));
    let mut wire = format!(
        "QUERY {TARGET} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    );
    for chunk in ["{\"category\":", "\"café\",", "\"limit\":2}"] {
        use std::fmt::Write as _;
        write!(wire, "{:x}\r\n{chunk}\r\n", chunk.len()).unwrap();
    }
    wire.push_str("0\r\n\r\n");

    let raw = http_send(proxy.addr(), &wire);

    assert_eq!(parse_status(&raw), 200, "chunked QUERY must reach the origin: {raw}");
    assert_query(&observed(&log), QUERY_BODY);
}

#[test]
fn query_status_retry_consumes_and_replays_the_complete_body() {
    let (failing, failed_log) = start_recording_backend(|_| response(503, "unavailable"));
    let (healthy, healthy_log) = start_recording_backend(|_| response(200, "results"));
    let proxy = start(&yaml(&[failing.port(), healthy.port()], RETRY_POLICY));

    let raw = http_send(proxy.addr(), &request("QUERY", QUERY_BODY));

    assert_eq!(parse_status(&raw), 200, "QUERY should retry the configured 503: {raw}");
    assert_query(&observed(&failed_log), QUERY_BODY);
    assert_query(&observed(&healthy_log), QUERY_BODY);
}

#[test]
fn query_connection_failure_retries_with_its_body() {
    let dead = free_port();
    let (healthy, log) = start_recording_backend(|_| response(200, "results"));
    let proxy = start(&yaml(&[dead, healthy.port()], RETRY_POLICY));

    let raw = http_send(proxy.addr(), &request("QUERY", QUERY_BODY));

    assert_eq!(
        parse_status(&raw),
        200,
        "QUERY should recover from a connection failure: {raw}"
    );
    assert_query(&observed(&log), QUERY_BODY);
}

#[cfg(feature = "pingora")]
#[test]
fn query_fresh_connection_eof_preserves_pingora_reuse_safety() {
    let (failing, failed_log) = start_recording_backend(|_| Vec::new());
    let (healthy, healthy_log) = start_recording_backend(|_| response(200, "results"));
    let proxy = start(&yaml(&[failing.port(), healthy.port()], RETRY_POLICY));

    let raw = http_send(proxy.addr(), &request("QUERY", QUERY_BODY));

    assert_eq!(
        parse_status(&raw),
        502,
        "a fresh-connection EOF must retain Pingora's reuse-only retry restriction: {raw}"
    );
    assert_query(&observed(&failed_log), QUERY_BODY);
    assert!(
        observed(&healthy_log).is_empty(),
        "QUERY must not bypass the transport's replay guard"
    );
}

#[test]
fn query_retry_replays_the_body_produced_by_a_buffered_filter() {
    let (failing, failed_log) = start_recording_backend(|_| response(503, "unavailable"));
    let (healthy, healthy_log) = start_recording_backend(|_| response(200, "results"));
    let config = yaml(&[failing.port(), healthy.port()], RETRY_POLICY).replace(
        "      - filter: router",
        "      - filter: json_body\n        request_add:\n          - pointer: /tenant\n            value: acme\n      - filter: router",
    );
    let proxy = start(&config);

    let raw = http_send(proxy.addr(), &request("QUERY", QUERY_BODY));

    assert_eq!(parse_status(&raw), 200, "a buffered QUERY should retry: {raw}");
    let first = observed(&failed_log);
    let replay = observed(&healthy_log);
    assert_eq!(first.len(), 1);
    assert_eq!(replay.len(), 1);
    assert_eq!(
        first[0].body, replay[0].body,
        "the replay must use the forwarded representation"
    );
    let body: serde_json::Value = serde_json::from_slice(&replay[0].body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"category": "café", "limit": 2, "tenant": "acme"})
    );
}

#[test]
fn query_retry_preserves_existing_policy_guards() {
    for policy in [
        "max_retries: 0\n              retriable_conditions: [status_5xx]",
        "max_retries: 1\n              retriable_conditions: [connect_failure]",
        "max_retries: 1\n              retriable_conditions: [status_5xx]\n              retry_body_limit_bytes: 4",
    ] {
        let (failing, failed_log) = start_recording_backend(|_| response(503, "unavailable"));
        let (healthy, healthy_log) = start_recording_backend(|_| response(200, "results"));
        let proxy = start(&yaml(&[failing.port(), healthy.port()], policy));

        let raw = http_send(proxy.addr(), &request("QUERY", QUERY_BODY));

        assert_eq!(
            parse_status(&raw),
            503,
            "the retry guard must still apply: {policy}\n{raw}"
        );
        assert_query(&observed(&failed_log), QUERY_BODY);
        assert!(
            observed(&healthy_log).is_empty(),
            "the guarded QUERY must not reach another endpoint"
        );
    }
}

#[test]
fn query_replay_buffer_boundary_never_replays_a_truncated_body() {
    for (length, retried) in [(65_536, true), (65_537, false)] {
        let body = format!("\"{}\"", "a".repeat(length - 2));
        let (failing, failed_log) = start_recording_backend(|_| response(503, "unavailable"));
        let (healthy, healthy_log) = start_recording_backend(|_| response(200, "results"));
        let proxy = start(&yaml(&[failing.port(), healthy.port()], RETRY_POLICY));

        let raw = http_send(proxy.addr(), &request("QUERY", &body));

        assert_eq!(
            parse_status(&raw),
            if retried { 200 } else { 503 },
            "replay size {length}: {raw}"
        );
        assert_query(&observed(&failed_log), &body);
        if retried {
            assert_query(&observed(&healthy_log), &body);
        } else {
            assert!(
                observed(&healthy_log).is_empty(),
                "an oversized body must never be partially replayed"
            );
        }
    }
}

#[test]
fn query_streams_to_the_origin_before_the_upload_finishes() {
    use std::{
        io::{BufReader, Write as _},
        net::TcpStream,
        time::Duration,
    };

    use praxis_test_utils::{PayloadSpec, read_h1_response, start_counting_backend};

    let payload = PayloadSpec::padded(4096, b"\"", b"\"", b'a').unwrap();
    let backend = start_counting_backend(payload.clone(), "query", 4096);
    let proxy = start(&yaml(&[backend.port], "max_retries: 0"));
    let mut client = TcpStream::connect(proxy.addr()).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    client.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(client, "QUERY {TARGET} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n").unwrap();
    client.write_all(&payload.chunk(0, 128)).unwrap();

    backend
        .first_byte
        .recv_timeout(Duration::from_secs(5))
        .expect("QUERY must reach the origin before the client sends its final bytes");
    client.write_all(&payload.chunk(128, 3968)).unwrap();
    let response = read_h1_response(&mut BufReader::new(client), false, 4096, |_| Ok(()));
    let receipt = backend.receipt.recv_timeout(Duration::from_secs(5)).unwrap();

    assert_eq!(response.status, Some(200), "{response:?}; backend: {receipt:?}");
    assert!(
        response.completion.is_some(),
        "the response must complete: {response:?}"
    );
    assert_eq!(receipt.request_line, format!("QUERY {TARGET} HTTP/1.1"));
    assert_eq!(receipt.bytes, 4096);
    assert_eq!(receipt.mismatch, None, "all streamed bytes must arrive intact");
    assert!(receipt.completion.is_some(), "the upload must complete: {receipt:?}");
}

#[test]
fn query_retries_stop_at_the_configured_attempt_limit() {
    let (backend, log) = start_recording_backend(|_| response(503, "unavailable"));
    let proxy = start(&yaml(&[backend.port()], RETRY_POLICY));

    let raw = http_send(proxy.addr(), &request("QUERY", QUERY_BODY));

    assert_eq!(
        parse_status(&raw),
        503,
        "exhausted retries must return the origin's failure: {raw}"
    );
    let attempts = observed(&log);
    assert_eq!(attempts.len(), 2, "one retry permits exactly two backend attempts");
    for attempt in attempts {
        assert_query(&[attempt], QUERY_BODY);
    }
}

#[test]
fn adding_query_does_not_enable_other_methods_for_automatic_status_retries() {
    for method in ["POST", "PUT", "DELETE", "PATCH", "TRACE", "CUSTOM"] {
        let (failing, failed_log) = start_recording_backend(|_| response(503, "unavailable"));
        let (healthy, healthy_log) = start_recording_backend(|_| response(200, "results"));
        let proxy = start(&yaml(&[failing.port(), healthy.port()], RETRY_POLICY));

        let raw = http_send(proxy.addr(), &request(method, QUERY_BODY));

        assert_eq!(parse_status(&raw), 503, "{method} still needs retry opt-in: {raw}");
        assert_eq!(observed(&failed_log).len(), 1, "{method} should have one attempt");
        assert!(
            observed(&healthy_log).is_empty(),
            "{method} must not retry onto the healthy endpoint"
        );
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a deterministic two-attempt proxy configuration.
pub(super) fn yaml(ports: &[u16], policy: &str) -> String {
    let endpoints = ports
        .iter()
        .map(|port| format!("              - \"127.0.0.1:{port}\"\n"))
        .collect::<String>();
    let port = free_port();
    format!(
        r#"
listeners:
  - name: query
    address: "127.0.0.1:{port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: /
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            load_balancer_strategy: round_robin
            endpoints:
{endpoints}            retry_policy:
              {policy}
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// Start without an HTTP readiness probe consuming the first endpoint.
pub(super) fn start(yaml: &str) -> ProxyGuard {
    let config = Config::from_yaml(yaml).unwrap();
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());
    proxy
}

/// A fixed-length request carrying the complete query representation.
pub(super) fn request(method: &str, body: &str) -> String {
    format!(
        "{method} {TARGET} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A response that advertises the resource's query format.
pub(super) fn response(status: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} Result\r\nContent-Length: {}\r\nContent-Type: application/json\r\nAccept-Query: application/json\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ).into_bytes()
}

/// Snapshot complete backend requests after receiving the client response.
pub(super) fn observed(log: &RequestLog) -> Vec<RecordedRequest> {
    log.lock().unwrap().clone()
}

/// Assert one backend attempt preserved the request's semantic content.
pub(super) fn assert_query(attempts: &[RecordedRequest], body: &str) {
    assert_eq!(attempts.len(), 1, "expected one complete request: {attempts:?}");
    let attempt = &attempts[0];
    assert_eq!(
        attempt.request_line,
        format!("QUERY {TARGET} HTTP/1.1"),
        "the origin must receive the QUERY method and complete request target"
    );
    assert_eq!(
        attempt.body,
        body.as_bytes(),
        "the origin must receive the complete body"
    );
    assert!(
        attempt
            .headers
            .iter()
            .any(|(name, value)| name == "content-type" && value == "application/json"),
        "the origin must receive the query representation's media type"
    );
}
