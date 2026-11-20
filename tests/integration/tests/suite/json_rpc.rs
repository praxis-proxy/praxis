// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the `json_rpc` filter.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, json_post, parse_body, parse_status, start_backend_with_shutdown, start_header_echo_backend,
    start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn extracts_json_rpc_method_to_header() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/api", r#"{"jsonrpc":"2.0","method":"service/invoke","id":1}"#),
    );

    assert_eq!(parse_status(&raw), 200, "JSON-RPC request should return 200");
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-json-rpc-method: service/invoke"),
        "expected X-Json-Rpc-Method header echoed by backend, got:\n{body}"
    );
    assert!(
        body.to_lowercase().contains("x-json-rpc-id: 1"),
        "expected X-Json-Rpc-Id header echoed by backend, got:\n{body}"
    );
    assert!(
        body.to_lowercase().contains("x-json-rpc-kind: request"),
        "expected X-Json-Rpc-Kind header echoed by backend, got:\n{body}"
    );
}

#[test]
fn extracts_notification_without_id() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post(
            "/api",
            r#"{"jsonrpc":"2.0","method":"notifications/service/list_changed"}"#,
        ),
    );

    assert_eq!(parse_status(&raw), 200, "JSON-RPC notification should return 200");
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase()
            .contains("x-json-rpc-method: notifications/service/list_changed"),
        "expected method header for notification, got:\n{body}"
    );
    assert!(
        body.to_lowercase().contains("x-json-rpc-kind: notification"),
        "expected kind=notification header, got:\n{body}"
    );
    assert!(
        !body.to_lowercase().contains("x-json-rpc-id:"),
        "notifications should not have id header, got:\n{body}"
    );
}

#[test]
fn method_based_routing_different_clusters() {
    let backend1_guard = start_backend_with_shutdown("tools-backend");
    let backend1_port = backend1_guard.port();

    let backend2_guard = start_backend_with_shutdown("messaging-backend");
    let backend2_port = backend2_guard.port();

    let proxy_port = free_port();
    let yaml = routing_proxy_yaml(proxy_port, backend1_port, backend2_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw1 = http_send(
        proxy.addr(),
        &json_post(
            "/rpc-tools/",
            r#"{"jsonrpc":"2.0","id":"req-1","method":"service/invoke","params":{"name":"calculator"}}"#,
        ),
    );
    assert_eq!(parse_status(&raw1), 200, "service/invoke request should return 200");
    assert_eq!(
        parse_body(&raw1),
        "tools-backend",
        "service/invoke should route to tools backend"
    );

    let raw2 = http_send(
        proxy.addr(),
        &json_post(
            "/rpc-msg/",
            r#"{"jsonrpc":"2.0","id":"msg-123","method":"ProcessRequest","params":{"recipient":"agent-42"}}"#,
        ),
    );
    assert_eq!(parse_status(&raw2), 200, "ProcessRequest request should return 200");
    assert_eq!(
        parse_body(&raw2),
        "messaging-backend",
        "ProcessRequest should route to messaging backend"
    );
}

#[test]
fn non_json_rpc_passes_through() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/api", r#"{"message":"hello","user":"alice"}"#),
    );

    assert_eq!(parse_status(&raw), 200, "non-JSON-RPC request should pass through");
    let body = parse_body(&raw);
    assert!(
        !body.to_lowercase().contains("x-json-rpc"),
        "non-JSON-RPC should not add JSON-RPC headers, got:\n{body}"
    );
}

#[test]
fn invalid_json_passes_through() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/api", "not json at all"));

    assert_eq!(parse_status(&raw), 200, "invalid JSON should pass through by default");
    let body = parse_body(&raw);
    assert!(
        !body.to_lowercase().contains("x-json-rpc"),
        "invalid JSON should not add JSON-RPC headers, got:\n{body}"
    );
}

#[test]
fn string_and_numeric_ids_handled() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw1 = http_send(
        proxy.addr(),
        &json_post("/api", r#"{"jsonrpc":"2.0","method":"test","id":"req-abc"}"#),
    );
    assert_eq!(parse_status(&raw1), 200, "string ID should work");
    let body1 = parse_body(&raw1);
    assert!(
        body1.to_lowercase().contains("x-json-rpc-id: req-abc"),
        "expected string ID header, got:\n{body1}"
    );

    let raw2 = http_send(
        proxy.addr(),
        &json_post("/api", r#"{"jsonrpc":"2.0","method":"test","id":42}"#),
    );
    assert_eq!(parse_status(&raw2), 200, "numeric ID should work");
    let body2 = parse_body(&raw2);
    assert!(
        body2.to_lowercase().contains("x-json-rpc-id: 42"),
        "expected numeric ID header, got:\n{body2}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn simple_proxy_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: json_rpc
        max_body_bytes: 1048576
        batch_policy: reject
        on_invalid: continue
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

fn routing_proxy_yaml(proxy_port: u16, backend1_port: u16, backend2_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: json_rpc
        max_body_bytes: 1048576
        batch_policy: reject
        on_invalid: continue
        headers:
          method: X-Json-Rpc-Method
          id: X-Json-Rpc-Id
          kind: X-Json-Rpc-Kind
      - filter: router
        routes:
          - path_prefix: "/rpc-tools/"
            headers:
              x-json-rpc-method: "service/invoke"
            cluster: "tools"
          - path_prefix: "/rpc-tools/"
            headers:
              x-json-rpc-method: "service/list"
            cluster: "tools"
          - path_prefix: "/rpc-msg/"
            headers:
              x-json-rpc-method: "ProcessRequest"
            cluster: "messaging"
          - path_prefix: "/rpc-msg/"
            headers:
              x-json-rpc-method: "StreamRequest"
            cluster: "messaging"
          - path_prefix: "/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "tools"
            endpoints:
              - "127.0.0.1:{backend1_port}"
          - name: "messaging"
            endpoints:
              - "127.0.0.1:{backend2_port}"
          - name: "default"
            endpoints:
              - "127.0.0.1:{backend1_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

#[test]
fn large_malformed_json_rpc_respects_invalid_and_failure_modes() {
    use std::{sync::mpsc::TryRecvError, time::Duration};

    use praxis_test_utils::{PayloadSpec, start_counting_backend};

    let spec = PayloadSpec::padded(
        1_048_576,
        br#"{"jsonrpc":"2.0","method":"safe","params":""#,
        br#""}garbage"#,
        b'x',
    )
    .unwrap();
    for (invalid, failure, status) in [
        ("continue", "closed", 200),
        ("reject", "open", 400),
        ("error", "closed", 500),
        ("error", "open", 200),
    ] {
        let backend = start_counting_backend(spec.clone(), "rpc", spec.len());
        let port = free_port();
        let yaml = invalid_rpc_yaml(port, backend.port, invalid, failure);
        let proxy = praxis_test_utils::start_full_proxy(&Config::from_yaml(&yaml).unwrap());
        praxis_test_utils::wait_for_tcp(proxy.addr());
        let body = String::from_utf8(spec.chunk(0, usize::try_from(spec.len()).unwrap())).unwrap();
        let request = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Json-Rpc-Method: forged\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        assert_eq!(
            parse_status(&http_send(proxy.addr(), &request)),
            status,
            "on_invalid={invalid}, failure_mode={failure}"
        );
        if status == 200 {
            let receipt = backend.receipt.recv_timeout(Duration::from_secs(10)).unwrap();
            assert_eq!(receipt.verified_bytes, spec.len());
            assert_eq!(receipt.mismatch, None);
            assert!(receipt.completion.is_some());
            assert!(
                receipt.headers.iter().all(|(name, _)| !name.starts_with("x-json-rpc-")),
                "configured classifier headers are stripped even on invalid input"
            );
        } else {
            assert!(matches!(backend.accepted.try_recv(), Err(TryRecvError::Empty)));
        }
        backend.join();
    }
}

#[test]
fn large_json_rpc_batch_rejection_overrides_continue_and_fail_open() {
    use std::sync::mpsc::TryRecvError;

    use praxis_test_utils::{PayloadSpec, start_counting_backend};

    let spec = PayloadSpec::padded(
        1_048_576,
        br#"[{"jsonrpc":"2.0","method":"safe","params":""#,
        br#""}]"#,
        b'x',
    )
    .unwrap();
    let backend = start_counting_backend(spec.clone(), "rpc", spec.len());
    let port = free_port();
    let yaml = invalid_rpc_yaml(port, backend.port, "continue", "open");
    let proxy = praxis_test_utils::start_full_proxy(&Config::from_yaml(&yaml).unwrap());
    praxis_test_utils::wait_for_tcp(proxy.addr());
    let body = String::from_utf8(spec.chunk(0, usize::try_from(spec.len()).unwrap())).unwrap();
    assert_eq!(parse_status(&http_send(proxy.addr(), &json_post("/", &body))), 400);
    assert!(matches!(backend.accepted.try_recv(), Err(TryRecvError::Empty)));
    backend.join();
}

/// Configure the registered JSON-RPC filter and one byte-verifying backend.
fn invalid_rpc_yaml(proxy_port: u16, backend_port: u16, invalid: &str, failure: &str) -> String {
    format!(
        r#"
listeners:
  - name: gateway
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: json_rpc
        max_body_bytes: 2097152
        on_invalid: {invalid}
        failure_mode: {failure}
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
"#
    )
}

#[test]
fn large_json_rpc_late_methods_route_only_after_eos_and_reset_per_request() {
    use std::{
        io::{BufReader, Write as _},
        net::TcpStream,
        sync::mpsc::{RecvTimeoutError, TryRecvError},
        time::Duration,
    };

    use praxis_test_utils::{PayloadSpec, read_h1_response, start_counting_backend, start_full_proxy, wait_for_tcp};

    let methods = ["service/invoke", "ProcessRequest", "unknown/method"];
    let specs: Vec<PayloadSpec> = methods
        .iter()
        .map(|method| {
            let suffix = format!(r#"","method":"{method}","id":7}}"#);
            PayloadSpec::padded(1_048_576, br#"{"jsonrpc":"2.0","params":""#, suffix.as_bytes(), b'x').unwrap()
        })
        .collect();
    let backends: Vec<_> = specs
        .iter()
        .zip(["tools", "messaging", "fallback"])
        .map(|(spec, name)| start_counting_backend(spec.clone(), name, spec.len()))
        .collect();
    let proxy_port = free_port();
    let yaml = large_method_routing_yaml(proxy_port, backends[0].port, backends[1].port, backends[2].port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_full_proxy(&config);
    wait_for_tcp(proxy.addr());

    for (index, spec) in specs.iter().enumerate() {
        let mut stream = TcpStream::connect(proxy.addr()).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
        write!(
            stream,
            "POST /rpc HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Json-Rpc-Method: forged\r\nConnection: close\r\n\r\n",
            spec.len()
        )
        .unwrap();
        let mut offset = 0;
        while offset < spec.len() - 1 {
            let remaining = usize::try_from(spec.len() - 1 - offset).unwrap();
            let chunk = spec.chunk(offset, remaining.min(65_536));
            stream.write_all(&chunk).unwrap();
            offset += u64::try_from(chunk.len()).unwrap();
        }
        stream.flush().unwrap();
        assert!(
            matches!(
                backends[index].accepted.recv_timeout(Duration::from_millis(200)),
                Err(RecvTimeoutError::Timeout)
            ),
            "the selected backend must not be contacted before the JSON document ends"
        );
        for backend in &backends[index + 1..] {
            assert!(matches!(backend.accepted.try_recv(), Err(TryRecvError::Empty)));
        }
        stream.write_all(&spec.chunk(offset, 1)).unwrap();
        let response = read_h1_response(&mut BufReader::new(stream), false, 0, |_| Ok(()));
        assert_eq!(response.status, Some(200), "method {}", methods[index]);
        assert!(response.completion.is_some(), "response must complete: {response:?}");
        let receipt = backends[index].receipt.recv_timeout(Duration::from_secs(20)).unwrap();
        assert_eq!(receipt.backend_id, ["tools", "messaging", "fallback"][index]);
        assert_eq!(receipt.bytes, spec.len());
        assert_eq!(receipt.verified_bytes, spec.len());
        assert_eq!(receipt.mismatch, None);
        assert!(receipt.completion.is_some());
        assert_eq!(receipt.abort, None);
        let promoted: Vec<_> = receipt
            .headers
            .iter()
            .filter(|(name, _)| name == "x-json-rpc-method")
            .collect();
        assert_eq!(promoted.len(), 1, "client-supplied classifier must be replaced");
        assert_eq!(promoted[0].1, methods[index]);
        for backend in &backends[index + 1..] {
            assert!(
                matches!(backend.accepted.try_recv(), Err(TryRecvError::Empty)),
                "wrong backend must not be selected"
            );
        }
    }
    for backend in backends {
        backend.join();
    }
}

/// Route the same path using a promoted JSON-RPC method and an explicit fallback.
fn large_method_routing_yaml(proxy_port: u16, tools_port: u16, messaging_port: u16, fallback_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: gateway
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: json_rpc
        max_body_bytes: 2097152
      - filter: router
        routes:
          - path_prefix: "/"
            headers:
              x-json-rpc-method: service/invoke
            cluster: tools
          - path_prefix: "/"
            headers:
              x-json-rpc-method: ProcessRequest
            cluster: messaging
          - path_prefix: "/"
            cluster: fallback
      - filter: load_balancer
        clusters:
          - name: tools
            endpoints: ["127.0.0.1:{tools_port}"]
          - name: messaging
            endpoints: ["127.0.0.1:{messaging_port}"]
          - name: fallback
            endpoints: ["127.0.0.1:{fallback_port}"]
insecure_options:
  allow_private_endpoints: true
"#
    )
}

#[test]
fn large_json_rpc_adversaries_follow_method_and_invalid_document_policy() {
    use praxis_test_utils::PayloadSpec;

    let size = 1_048_576;
    let prefix = br#"{"jsonrpc":"2.0","method":"service/invoke","pad":""#;
    let middle = format!(
        r#"{{"jsonrpc":"2.0","method":"service/invoke","pad":"{}","bad":!,"tail":""#,
        "x".repeat(524_288)
    );
    let early = br#"{"jsonrpc":"2.0","method":"service/invoke",!,"pad":""#;
    let mut cases = vec![
        (
            "early syntax",
            PayloadSpec::padded(size, early, br#""}"#, b'x').unwrap(),
            None,
        ),
        (
            "middle syntax",
            PayloadSpec::padded(size, middle.as_bytes(), br#""}"#, b'x').unwrap(),
            None,
        ),
        (
            "late syntax",
            PayloadSpec::padded(size, prefix, br#"",}"#, b'x').unwrap(),
            None,
        ),
        (
            "second document",
            PayloadSpec::padded(size, prefix, br#""}{}"#, b'x').unwrap(),
            None,
        ),
        (
            "trailing garbage",
            PayloadSpec::padded(size, prefix, br#""}junk"#, b'x').unwrap(),
            None,
        ),
    ];
    let document = br#"{"jsonrpc":"2.0","method":"service/invoke","id":7}"#;
    cases.push((
        "HTTP-looking suffix",
        PayloadSpec::padded(size, document, b"GET /other HTTP/1.1\r\nHost: localhost\r\n\r\n", b' ').unwrap(),
        None,
    ));
    cases.push((
        "whitespace control",
        PayloadSpec::padded(size, document, b"", b' ').unwrap(),
        Some("service/invoke"),
    ));
    cases.push((
        "duplicate late method",
        PayloadSpec::padded(
            size,
            prefix,
            br#"","nested":{"method":"decoy"},"\u006dethod":"ProcessRequest","id":7}"#,
            b'x',
        )
        .unwrap(),
        Some("ProcessRequest"),
    ));
    cases.push((
        "duplicate reverse control",
        PayloadSpec::padded(
            size,
            br#"{"jsonrpc":"2.0","method":"ProcessRequest","pad":""#,
            br#"","nested":{"method":"decoy"},"\u006dethod":"service/invoke","id":7}"#,
            b'x',
        )
        .unwrap(),
        Some("service/invoke"),
    ));

    for depth in [70, 129] {
        let suffix = format!(r#"","params":{}0{},"id":7}}"#, "[".repeat(depth), "]".repeat(depth));
        let spec = PayloadSpec::padded(size, prefix, suffix.as_bytes(), b'x').unwrap();
        cases.push(("nested params", spec, (depth == 70).then_some("service/invoke")));
    }
    let wide = format!(r#"","params":[{}],"id":7}}"#, vec!["0"; 12_000].join(","));
    cases.push((
        "wide valid params",
        PayloadSpec::padded(size, prefix, wide.as_bytes(), b'x').unwrap(),
        Some("service/invoke"),
    ));

    for (name, spec, expected_method) in cases {
        assert_rpc_route_case(name, &spec, expected_method, None);
    }
}

#[test]
fn large_json_rpc_encoding_faults_do_not_authorize_method_route() {
    use praxis_test_utils::PayloadSpec;

    let size = 1_048_576;
    let prefix = br#"{"jsonrpc":"2.0","method":"service/invoke","params":""#;
    let suffix = br#"","id":7}"#;
    for (name, byte) in [("invalid UTF-8", 0xFF), ("raw NUL", 0)] {
        let spec = PayloadSpec::padded(size, prefix, suffix, b'x')
            .unwrap()
            .with_fault(size - u64::try_from(suffix.len()).unwrap() - 1, byte)
            .unwrap();
        assert_rpc_route_case(name, &spec, None, None);
    }
    let surrogate = PayloadSpec::padded(size, prefix, br#"\ud800","id":7}"#, b'x').unwrap();
    assert_rpc_route_case("unpaired surrogate", &surrogate, None, None);

    let valid_suffix = "café\",\"id\":7}".as_bytes();
    let split = size - u64::try_from(valid_suffix.len()).unwrap()
        + u64::try_from(valid_suffix.iter().position(|byte| *byte == 0xC3).unwrap()).unwrap()
        + 1;
    let valid = PayloadSpec::padded(size, prefix, valid_suffix, b'x').unwrap();
    assert_rpc_route_case("split Unicode control", &valid, Some("service/invoke"), Some(split));
}

#[test]
fn large_json_rpc_first_batch_policy_routes_first_valid_method() {
    use praxis_test_utils::PayloadSpec;

    let first = PayloadSpec::padded(
        1_048_576,
        br#"[{"jsonrpc":"2.0","params":""#,
        br#"","method":"service/invoke","id":1},{"jsonrpc":"2.0","method":"ProcessRequest","id":2}]"#,
        b'x',
    )
    .unwrap();
    assert_rpc_route_case("first batch method", &first, Some("service/invoke"), None);
    let skipped = PayloadSpec::padded(
        1_048_576,
        br#"[{"jsonrpc":"2.0","method":42},{"jsonrpc":"2.0","params":""#,
        br#"","method":"ProcessRequest","id":2}]"#,
        b'x',
    )
    .unwrap();
    assert_rpc_route_case("first valid batch method", &skipped, Some("ProcessRequest"), None);
}

/// Check an entire JSON-RPC request against an independent serde parser and byte-verifying backends.
fn assert_rpc_route_case(
    name: &str,
    spec: &praxis_test_utils::PayloadSpec,
    expected_method: Option<&str>,
    split: Option<u64>,
) {
    use std::{
        io::{BufReader, Write as _},
        net::TcpStream,
        sync::mpsc::{RecvTimeoutError, TryRecvError},
        time::Duration,
    };

    use praxis_test_utils::{read_h1_response, start_counting_backend, start_full_proxy, wait_for_tcp};

    let reference = serde_json::from_slice::<serde_json::Value>(&spec.chunk(0, usize::try_from(spec.len()).unwrap()));
    let batch = reference.as_ref().is_ok_and(serde_json::Value::is_array);
    match expected_method {
        Some(method) => {
            let document = reference.as_ref().unwrap();
            let actual = if batch {
                document.as_array().unwrap().iter().find_map(|item| {
                    (item.get("jsonrpc").and_then(serde_json::Value::as_str) == Some("2.0"))
                        .then(|| item.get("method").and_then(serde_json::Value::as_str))
                        .flatten()
                })
            } else {
                document.get("method").and_then(serde_json::Value::as_str)
            };
            assert_eq!(actual, Some(method), "case={name}");
        },
        None => {
            reference.expect_err("the JSON reference must reject the invalid routing case");
        },
    }
    let backends: Vec<_> = ["tools", "messaging", "fallback"]
        .iter()
        .map(|id| start_counting_backend(spec.clone(), id, spec.len()))
        .collect();
    let port = free_port();
    let yaml = large_method_routing_yaml(port, backends[0].port, backends[1].port, backends[2].port);
    let yaml = if batch {
        yaml.replace(
            "        max_body_bytes: 2097152\n",
            "        max_body_bytes: 2097152\n        batch_policy: first\n        max_batch_size: 2\n",
        )
    } else {
        yaml
    };
    let proxy = start_full_proxy(&Config::from_yaml(&yaml).unwrap());
    wait_for_tcp(proxy.addr());
    let mut stream = TcpStream::connect(proxy.addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
    write!(stream, "POST /rpc HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Json-Rpc-Method: forged\r\nConnection: close\r\n\r\n", spec.len()).unwrap();
    let split = split.unwrap_or(spec.len() - 1);
    let mut offset = 0;
    while offset < split {
        let remaining = usize::try_from(split - offset).unwrap();
        let chunk = spec.chunk(offset, remaining.min(65_536));
        stream.write_all(&chunk).unwrap();
        offset += u64::try_from(chunk.len()).unwrap();
    }
    stream.flush().unwrap();
    assert!(
        matches!(
            backends[0].accepted.recv_timeout(Duration::from_millis(200)),
            Err(RecvTimeoutError::Timeout)
        ),
        "early protected dispatch case={name}"
    );
    assert!(
        matches!(backends[1].accepted.try_recv(), Err(TryRecvError::Empty)),
        "early alternate dispatch case={name}"
    );
    assert!(
        matches!(backends[2].accepted.try_recv(), Err(TryRecvError::Empty)),
        "early fallback dispatch case={name}"
    );
    while offset < spec.len() {
        let chunk = spec.chunk(offset, 65_536);
        stream.write_all(&chunk).unwrap();
        offset += u64::try_from(chunk.len()).unwrap();
    }
    let response = read_h1_response(&mut BufReader::new(stream), false, 0, |_| Ok(()));
    assert_eq!(response.status, Some(200), "case={name}");
    assert!(response.completion.is_some(), "case={name} response={response:?}");
    let selected = match expected_method {
        Some("service/invoke") => 0,
        Some("ProcessRequest") => 1,
        Some(other) => panic!("unexpected method {other}"),
        None => 2,
    };
    let receipt = backends[selected]
        .receipt
        .recv_timeout(Duration::from_secs(20))
        .unwrap();
    assert_eq!(
        receipt.backend_id,
        ["tools", "messaging", "fallback"][selected],
        "case={name}"
    );
    assert_eq!(receipt.bytes, spec.len(), "case={name}");
    assert_eq!(receipt.verified_bytes, spec.len(), "case={name}");
    assert_eq!(receipt.mismatch, None, "case={name}");
    assert!(receipt.completion.is_some(), "case={name}");
    assert_eq!(receipt.abort, None, "case={name}");
    let methods: Vec<_> = receipt
        .headers
        .iter()
        .filter(|(key, _)| key == "x-json-rpc-method")
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(methods, expected_method.into_iter().collect::<Vec<_>>(), "case={name}");
    if batch {
        assert!(
            receipt
                .headers
                .iter()
                .any(|(key, value)| key == "x-json-rpc-kind" && value == "batch"),
            "case={name}"
        );
    }
    for (index, backend) in backends.iter().enumerate() {
        if index != selected {
            assert!(
                matches!(backend.accepted.try_recv(), Err(TryRecvError::Empty)),
                "wrong backend case={name}"
            );
        }
    }
    for backend in backends {
        backend.join();
    }
}

#[test]
fn truncated_large_json_rpc_never_routes_prefix_and_next_request_is_clean() {
    use std::{
        io::{BufReader, Write as _},
        net::TcpStream,
        sync::mpsc::{RecvTimeoutError, TryRecvError},
        time::Duration,
    };

    use praxis_test_utils::{PayloadSpec, read_h1_response, start_counting_backend, start_full_proxy, wait_for_tcp};

    let spec = PayloadSpec::padded(
        1_048_576,
        br#"{"jsonrpc":"2.0","method":"service/invoke","params":""#,
        br#"","id":7}"#,
        b'x',
    )
    .unwrap();
    let backends: Vec<_> = ["tools", "messaging", "fallback"]
        .iter()
        .map(|id| start_counting_backend(spec.clone(), id, spec.len()))
        .collect();
    let port = free_port();
    let yaml = large_method_routing_yaml(port, backends[0].port, backends[1].port, backends[2].port);
    let proxy = start_full_proxy(&Config::from_yaml(&yaml).unwrap());
    wait_for_tcp(proxy.addr());
    let mut truncated = TcpStream::connect(proxy.addr()).unwrap();
    truncated.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        truncated,
        "POST /rpc HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        spec.len()
    )
    .unwrap();
    truncated.write_all(&spec.chunk(0, 524_288)).unwrap();
    drop(truncated);
    assert!(matches!(
        backends[0].accepted.recv_timeout(Duration::from_millis(300)),
        Err(RecvTimeoutError::Timeout)
    ));
    assert!(matches!(backends[1].accepted.try_recv(), Err(TryRecvError::Empty)));
    assert!(matches!(backends[2].accepted.try_recv(), Err(TryRecvError::Empty)));

    let mut clean = TcpStream::connect(proxy.addr()).unwrap();
    clean.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    clean.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
    write!(
        clean,
        "POST /rpc HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        spec.len()
    )
    .unwrap();
    let mut offset = 0;
    while offset < spec.len() {
        let chunk = spec.chunk(offset, 65_536);
        clean.write_all(&chunk).unwrap();
        offset += u64::try_from(chunk.len()).unwrap();
    }
    let response = read_h1_response(&mut BufReader::new(clean), false, 0, |_| Ok(()));
    assert_eq!(response.status, Some(200));
    assert!(response.completion.is_some());
    let receipt = backends[0].receipt.recv_timeout(Duration::from_secs(20)).unwrap();
    assert_eq!(receipt.backend_id, "tools");
    assert_eq!(receipt.verified_bytes, spec.len());
    assert_eq!(receipt.mismatch, None);
    assert!(receipt.completion.is_some());
    assert_eq!(receipt.abort, None);
    assert!(matches!(backends[1].accepted.try_recv(), Err(TryRecvError::Empty)));
    assert!(matches!(backends[2].accepted.try_recv(), Err(TryRecvError::Empty)));
    for backend in backends {
        backend.join();
    }
}

#[test]
fn large_json_rpc_rewrite_order_controls_route_and_later_extraction() {
    use std::{
        io::{BufReader, Write as _},
        net::TcpStream,
        sync::mpsc::{RecvTimeoutError, TryRecvError},
        time::Duration,
    };

    use praxis_test_utils::{PayloadSpec, read_h1_response, start_counting_backend, start_full_proxy, wait_for_tcp};

    let input = PayloadSpec::padded(
        1_048_576,
        br#"{"jsonrpc":"2.0","method":"service/invoke","params":""#,
        br#"","id":7}"#,
        b'x',
    )
    .unwrap();
    let output = PayloadSpec::padded(
        1_048_576,
        br#"{"jsonrpc":"2.0","method":"ProcessRequest","params":""#,
        br#"","id":7}"#,
        b'x',
    )
    .unwrap();
    let rpc = "      - filter: json_rpc\n        max_body_bytes: 2097152\n";
    let rewrite = "      - filter: json_body\n        max_body_bytes: 2097152\n        request_replace:\n          - pointer: /method\n            value: ProcessRequest\n";
    let extract = "      - filter: json_body\n        max_body_bytes: 2097152\n        request_extract:\n          - pointer: /method\n            header: X-After\n";
    for (filters, protected, promoted) in [
        (format!("{rpc}{rewrite}{extract}"), true, "service/invoke"),
        (format!("{rewrite}{rpc}{extract}"), false, "ProcessRequest"),
    ] {
        let backends: Vec<_> = ["protected", "fallback"]
            .iter()
            .map(|id| start_counting_backend(output.clone(), id, output.len()))
            .collect();
        let port = free_port();
        let yaml = large_rpc_rewrite_yaml(port, backends[0].port, backends[1].port, &filters);
        let proxy = start_full_proxy(&Config::from_yaml(&yaml).unwrap());
        wait_for_tcp(proxy.addr());
        let mut stream = TcpStream::connect(proxy.addr()).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
        write!(
            stream,
            "POST /rpc HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            input.len()
        )
        .unwrap();
        let mut offset = 0;
        while offset < input.len() - 1 {
            let remaining = usize::try_from(input.len() - 1 - offset).unwrap();
            let chunk = input.chunk(offset, remaining.min(65_536));
            stream.write_all(&chunk).unwrap();
            offset += u64::try_from(chunk.len()).unwrap();
        }
        stream.flush().unwrap();
        assert!(matches!(
            backends[0].accepted.recv_timeout(Duration::from_millis(200)),
            Err(RecvTimeoutError::Timeout)
        ));
        assert!(matches!(backends[1].accepted.try_recv(), Err(TryRecvError::Empty)));
        stream.write_all(&input.chunk(offset, 1)).unwrap();
        let response = read_h1_response(&mut BufReader::new(stream), false, 0, |_| Ok(()));
        assert_eq!(response.status, Some(200));
        assert!(response.completion.is_some());
        let selected = usize::from(!protected);
        let receipt = backends[selected]
            .receipt
            .recv_timeout(Duration::from_secs(20))
            .unwrap();
        assert_eq!(receipt.backend_id, if protected { "protected" } else { "fallback" });
        assert_eq!(receipt.bytes, output.len());
        assert_eq!(receipt.verified_bytes, output.len());
        assert_eq!(receipt.mismatch, None);
        assert!(receipt.completion.is_some());
        assert_eq!(receipt.abort, None);
        assert!(
            receipt
                .headers
                .iter()
                .any(|(name, value)| name == "x-json-rpc-method" && value == promoted)
        );
        assert!(
            receipt
                .headers
                .iter()
                .any(|(name, value)| name == "x-after" && value == "ProcessRequest")
        );
        assert!(matches!(
            backends[1 - selected].accepted.try_recv(),
            Err(TryRecvError::Empty)
        ));
        for backend in backends {
            backend.join();
        }
    }
}

/// Configure route conditions over metadata captured before and after a rewrite.
fn large_rpc_rewrite_yaml(proxy_port: u16, protected_port: u16, fallback_port: u16, filters: &str) -> String {
    format!(
        r#"
listeners:
  - name: gateway
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
{filters}      - filter: router
        routes:
          - path_prefix: "/"
            headers:
              x-json-rpc-method: service/invoke
              x-after: ProcessRequest
            cluster: protected
          - path_prefix: "/"
            cluster: fallback
      - filter: load_balancer
        clusters:
          - name: protected
            endpoints: ["127.0.0.1:{protected_port}"]
          - name: fallback
            endpoints: ["127.0.0.1:{fallback_port}"]
insecure_options:
  allow_private_endpoints: true
"#
    )
}

#[test]
fn large_json_rpc_filter_error_fail_open_uses_explicit_fallback() {
    use std::{
        io::{BufReader, Write as _},
        net::TcpStream,
        sync::mpsc::TryRecvError,
        time::Duration,
    };

    use praxis_test_utils::{PayloadSpec, read_h1_response, start_counting_backend, start_full_proxy, wait_for_tcp};

    let spec = PayloadSpec::padded(
        1_048_576,
        br#"{"jsonrpc":"2.0","method":"service/invoke","params":""#,
        br#"","id":7}garbage"#,
        b'x',
    )
    .unwrap();
    for (mode, status) in [("open", 200), ("closed", 500)] {
        let backends: Vec<_> = ["protected", "alternate", "fallback"]
            .iter()
            .map(|id| start_counting_backend(spec.clone(), id, spec.len()))
            .collect();
        let port = free_port();
        let yaml = large_method_routing_yaml(port, backends[0].port, backends[1].port, backends[2].port).replace(
            "        max_body_bytes: 2097152\n",
            &format!("        max_body_bytes: 2097152\n        on_invalid: error\n        failure_mode: {mode}\n"),
        );
        let proxy = start_full_proxy(&Config::from_yaml(&yaml).unwrap());
        wait_for_tcp(proxy.addr());
        let mut stream = TcpStream::connect(proxy.addr()).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
        write!(stream, "POST /rpc HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nX-Json-Rpc-Method: service/invoke\r\nConnection: close\r\n\r\n", spec.len()).unwrap();
        let mut offset = 0;
        while offset < spec.len() {
            let chunk = spec.chunk(offset, 65_536);
            stream.write_all(&chunk).unwrap();
            offset += u64::try_from(chunk.len()).unwrap();
        }
        let response = read_h1_response(&mut BufReader::new(stream), false, 65_536, |_| Ok(()));
        assert_eq!(response.status, Some(status), "failure_mode={mode}");
        assert!(
            response.completion.is_some(),
            "failure_mode={mode} response={response:?}"
        );
        assert!(
            matches!(backends[0].accepted.try_recv(), Err(TryRecvError::Empty)),
            "protected route must not receive an invalid request"
        );
        assert!(matches!(backends[1].accepted.try_recv(), Err(TryRecvError::Empty)));
        if mode == "open" {
            let receipt = backends[2].receipt.recv_timeout(Duration::from_secs(20)).unwrap();
            assert_eq!(receipt.backend_id, "fallback");
            assert_eq!(receipt.bytes, spec.len());
            assert_eq!(receipt.verified_bytes, spec.len());
            assert_eq!(receipt.mismatch, None);
            assert!(receipt.completion.is_some());
            assert_eq!(receipt.abort, None);
            assert!(
                receipt.headers.iter().all(|(name, _)| !name.starts_with("x-json-rpc-")),
                "classifier headers are stripped even after a filter error"
            );
        } else {
            assert!(
                matches!(backends[2].accepted.try_recv(), Err(TryRecvError::Empty)),
                "closed failure must not dispatch"
            );
        }
        for backend in backends {
            backend.join();
        }
    }
}
