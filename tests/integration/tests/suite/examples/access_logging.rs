// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the access logging example configuration.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    net::TcpStream,
    time::{Duration, Instant},
};

use praxis_test_utils::{
    PraxisProcess, ProcessLogCursor, free_port, http_get, http_send, parse_body, parse_header, parse_status,
    start_backend_with_shutdown, start_full_proxy, start_proxy, start_tcp_tagged_backend, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn access_logging() {
    let backend_port_guard = start_backend_with_shutdown("logged");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "observability/access-logging.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "basic request should return 200");
    assert_eq!(parse_body(&raw), "logged", "response body should match backend");

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Request-Id: trace-abc\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "request with X-Request-Id should return 200");
    assert_eq!(
        parse_header(&raw, "x-request-id"),
        Some("trace-abc".to_owned()),
        "proxy should echo back the X-Request-Id"
    );
}

#[test]
#[cfg_attr(coverage, ignore = "spawns the praxis binary")]
fn failure_logs_and_metrics_exclude_body_canaries_and_count_rejection_once() {
    let backend = start_backend_with_shutdown("telemetry-ok");
    let port = free_port();
    let admin_port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let admin = format!("127.0.0.1:{admin_port}");
    let yaml = format!(
        r#"
shutdown_timeout_secs: 1
admin:
  metrics_address: "{admin}"
body_limits:
  max_request_bytes: 65536
listeners:
  - name: web
    address: "{addr}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: request_id
      - filter: access_log
        sample_rate: 1.0
        fields: [request_id, status, request_body_bytes, response_body_bytes]
        sink: {{type: stdout}}
      - filter: json_body_field
        field: model
        header: x-praxis-model
      - filter: guardrails
        rules:
          - target: body
            contains: [ssn]
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:{backend_port}"]
insecure_options:
  allow_private_endpoints: true
"#,
        backend_port = backend.port()
    );
    let mut proxy = PraxisProcess::spawn_with_env(&yaml, &addr, &[("RUST_LOG", "debug")]);
    wait_for_tcp(&admin);
    let secret = "CANARY_PAYLOAD_SECRET_77412";
    let pii = format!(
        r#"{{"model":"ok","padding":"{}","secret":"{secret}","ssn":"123-45-6789"}}"#,
        "x".repeat(50_000)
    );
    assert_telemetry_request(&addr, "w6-pii", &pii, 403, secret);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (_, metrics) = http_get(&admin, "/metrics", None);
        assert!(!metrics.contains(secret));
        if metrics.contains("praxis_errors_total{type=\"filter_reject\"} 1") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "one rejection must produce exactly one filter_reject counter: {metrics}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let invalid = format!(r#"{{"model":"{secret}\ninvalid","padding":"{}"}}"#, "y".repeat(40_000));
    assert_telemetry_request(&addr, "w6-invalid", &invalid, 200, secret);
    let overlong = format!(
        r#"{{"model":"{secret}{}","padding":"{}"}}"#,
        "v".repeat(300),
        "p".repeat(30_000)
    );
    assert_telemetry_request(&addr, "w6-long", &overlong, 200, secret);
    let promoted = format!(r#"{{"model":"{secret}","padding":"{}"}}"#, "q".repeat(30_000));
    assert_telemetry_request(&addr, "w6-promoted", &promoted, 200, secret);
    let oversized = format!(r#"{{"padding":"{secret}{}"}}"#, "z".repeat(65_536));
    assert_telemetry_request(&addr, "w6-over", &oversized, 413, secret);
    assert_telemetry_request(&addr, "w6-probe", r#"{"model":"safe"}"#, 200, secret);
    let (_, metrics) = http_get(&admin, "/metrics", None);
    assert!(!metrics.contains(secret), "payload data must not become a metric label");
    assert!(!metrics.contains("123-45-6789"));

    let mut cursor = ProcessLogCursor::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        while read_log_chunk(&proxy, &mut cursor, &mut stdout, &mut stderr) {}
        let logs = String::from_utf8_lossy(&stdout);
        if ["w6-pii", "w6-invalid", "w6-long", "w6-promoted", "w6-over", "w6-probe"]
            .iter()
            .all(|id| logs.contains(&format!("\"request_id\":\"{id}\"")))
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "every request must eventually emit an access record"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    proxy.signal("TERM");
    let (status, forced) = proxy.wait_or_kill(Duration::from_secs(10));
    assert!(!forced && status.success(), "proxy must flush logs and exit cleanly");
    while read_log_chunk(&proxy, &mut cursor, &mut stdout, &mut stderr) {}
    let logs = String::from_utf8_lossy(&stdout);
    let diagnostic_logs = String::from_utf8_lossy(&stderr);
    assert!(!logs.contains(secret));
    assert!(!logs.contains("123-45-6789"));
    assert!(!diagnostic_logs.contains(secret));
    assert!(!diagnostic_logs.contains("123-45-6789"));
    for (id, status) in [
        ("w6-pii", "403"),
        ("w6-invalid", "200"),
        ("w6-long", "200"),
        ("w6-promoted", "200"),
        ("w6-over", "413"),
        ("w6-probe", "200"),
    ] {
        let records: Vec<_> = logs
            .lines()
            .filter(|line| line.contains(&format!("\"request_id\":\"{id}\"")))
            .collect();
        assert_eq!(records.len(), 1, "{id} must have one access record: {logs}");
        let record: serde_json::Value = serde_json::from_str(records[0]).unwrap();
        assert_eq!(record["status"], status);
    }
}

/// Drain logs incrementally while imposing a total bound on the test controller.
fn read_log_chunk(
    proxy: &PraxisProcess,
    cursor: &mut ProcessLogCursor,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
) -> bool {
    let chunk = proxy.logs_since(cursor, 4096).unwrap();
    let read = !chunk.stdout.is_empty() || !chunk.stderr.is_empty();
    stdout.extend(chunk.stdout);
    stderr.extend(chunk.stderr);
    assert!(
        stdout.len() + stderr.len() <= 131_072,
        "six requests must not log their bodies"
    );
    read
}

/// Ensure neither an error nor a successful control reflects the body canary.
fn assert_telemetry_request(addr: &str, request_id: &str, body: &str, expected: u16, secret: &str) {
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: {request_id}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let response = http_send(addr, &request);
    assert_eq!(parse_status(&response), expected, "{request_id}: {response}");
    assert!(!response.contains(secret), "{request_id} reflected the body canary");
    assert!(
        !response.contains("123-45-6789"),
        "{request_id} reflected the PII canary"
    );
}

#[test]
fn tcp_access_log_example_forwards_tcp_traffic() {
    let backend_port = start_tcp_tagged_backend("db");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "observability/tcp-access-log.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:5432", proxy_port), ("127.0.0.1:15432", backend_port)]),
    );
    let _proxy = start_full_proxy(&config);
    let addr = format!("127.0.0.1:{proxy_port}");
    wait_for_tcp(&addr);

    // Exercise the logged connect/forward/disconnect lifecycle: the
    // tcp_access_log pipeline must forward payloads unchanged.
    let mut stream = TcpStream::connect(&addr).expect("TCP connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    stream.write_all(b"select 1").expect("TCP write");
    stream.shutdown(std::net::Shutdown::Write).expect("shutdown write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("TCP read");
    let text = String::from_utf8_lossy(&buf);

    assert!(
        text.contains("db"),
        "tcp-access-log example should forward to the tagged backend, got: {text}"
    );
    assert!(
        text.contains("select 1"),
        "tcp-access-log example should echo the payload, got: {text}"
    );
}
