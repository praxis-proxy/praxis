// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for payload-processing example configurations.

use std::collections::HashMap;

use praxis_core::config::Config;
use praxis_test_utils::{
    BackendReceipt, PayloadSpec, free_port, http_send, json_post, load_example_config, parse_body, parse_status,
    patch_yaml, start_backend_with_shutdown, start_counting_backend, start_full_proxy, start_header_echo_backend,
    start_proxy, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn multi_field_extraction_extracts_both_fields() {
    // alpha_cluster lists two distinct endpoints (10.0.1.1, 10.0.1.2); give
    // each its own header-echo backend rather than collapsing them onto one
    // address (a duplicate endpoint address is rejected by config validation).
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let backend_guard_2 = start_header_echo_backend();
    let backend_port_2 = backend_guard_2.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/multi-field-extraction.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", backend_port),
            ("10.0.1.2:8080", backend_port_2),
            ("10.0.2.1:8080", backend_port),
            ("10.0.3.1:8080", backend_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/chat/completions", r#"{"model":"model-alpha-1","user_id":"u-42"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "multi-field extraction should return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-model: model-alpha-1"),
        "expected X-Model header echoed by backend, got:\n{body}"
    );
    assert!(
        lower.contains("x-user-id: u-42"),
        "expected X-User-Id header echoed by backend, got:\n{body}"
    );
}

#[test]
fn multi_field_extraction_routes_by_model() {
    // alpha_cluster lists two distinct endpoints (10.0.1.1, 10.0.1.2); give
    // each its own backend rather than collapsing them onto one address (a
    // duplicate endpoint address is rejected by config validation). Both share
    // the "alpha-backend" body so the routing assertion holds either way.
    let alpha_port_guard = start_backend_with_shutdown("alpha-backend");
    let alpha_port = alpha_port_guard.port();
    let alpha_port_guard_2 = start_backend_with_shutdown("alpha-backend");
    let alpha_port_2 = alpha_port_guard_2.port();
    let default_port_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/multi-field-extraction.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", alpha_port),
            ("10.0.1.2:8080", alpha_port_2),
            ("10.0.2.1:8080", default_port),
            ("10.0.3.1:8080", default_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/chat/completions", r#"{"model":"model-alpha-1","user_id":"u-42"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "model-alpha-1 routing should return 200");
    assert_eq!(
        parse_body(&raw),
        "alpha-backend",
        "model=model-alpha-1 should route to alpha_cluster cluster"
    );
}

#[test]
fn conditional_field_extraction_fires_on_v1_path() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/conditional-field-extraction.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", backend_port),
            ("10.0.2.1:8080", backend_port),
            ("10.0.3.1:8080", backend_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/chat/completions", r#"{"model":"model-beta-1","messages":[]}"#),
    );
    assert_eq!(parse_status(&raw), 200, "v1 path extraction should return 200");
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-model: model-beta-1"),
        "X-Model should be extracted on /v1/ path, got:\n{body}"
    );
}

#[test]
fn conditional_field_extraction_skips_on_non_v1_path() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/conditional-field-extraction.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", backend_port),
            ("10.0.2.1:8080", backend_port),
            ("10.0.3.1:8080", backend_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/healthz", r#"{"model":"model-beta-1","messages":[]}"#),
    );
    assert_eq!(parse_status(&raw), 200, "non-v1 path should return 200");
    let body = parse_body(&raw);
    assert!(
        !body.to_lowercase().contains("x-model"),
        "X-Model should NOT be extracted on non-/v1/ path, got:\n{body}"
    );
}

#[test]
fn field_extraction_access_control_routes_acme() {
    let acme_port_guard = start_backend_with_shutdown("acme-backend");
    let acme_port = acme_port_guard.port();
    // acme lists two distinct endpoints (10.0.1.1, 10.0.1.2); give each its own
    // backend rather than collapsing them onto one address (a duplicate
    // endpoint address is rejected by config validation).
    let acme_port_guard_2 = start_backend_with_shutdown("acme-backend");
    let acme_port_2 = acme_port_guard_2.port();
    let globex_port_guard = start_backend_with_shutdown("globex-backend");
    let globex_port = globex_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/field-extraction-access-control.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", acme_port),
            ("10.0.1.2:8080", acme_port_2),
            ("10.0.2.1:8080", globex_port),
            ("10.0.3.1:8080", default_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/api/data", r#"{"tenant_id":"acme","query":"SELECT *"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "acme tenant should return 200");
    assert_eq!(
        parse_body(&raw),
        "acme-backend",
        "tenant_id=acme should route to acme cluster"
    );
}

#[test]
fn field_extraction_access_control_routes_globex() {
    let acme_port_guard = start_backend_with_shutdown("acme-backend");
    let acme_port = acme_port_guard.port();
    // acme lists two distinct endpoints (10.0.1.1, 10.0.1.2); give each its own
    // backend rather than collapsing them onto one address (a duplicate
    // endpoint address is rejected by config validation).
    let acme_port_guard_2 = start_backend_with_shutdown("acme-backend");
    let acme_port_2 = acme_port_guard_2.port();
    let globex_port_guard = start_backend_with_shutdown("globex-backend");
    let globex_port = globex_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/field-extraction-access-control.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", acme_port),
            ("10.0.1.2:8080", acme_port_2),
            ("10.0.2.1:8080", globex_port),
            ("10.0.3.1:8080", default_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/api/data", r#"{"tenant_id":"globex","query":"SELECT *"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "globex tenant should return 200");
    assert_eq!(
        parse_body(&raw),
        "globex-backend",
        "tenant_id=globex should route to globex cluster"
    );
}

#[test]
fn field_extraction_access_control_unknown_tenant_to_default() {
    let acme_port_guard = start_backend_with_shutdown("acme-backend");
    let acme_port = acme_port_guard.port();
    // acme lists two distinct endpoints (10.0.1.1, 10.0.1.2); give each its own
    // backend rather than collapsing them onto one address (a duplicate
    // endpoint address is rejected by config validation).
    let acme_port_guard_2 = start_backend_with_shutdown("acme-backend");
    let acme_port_2 = acme_port_guard_2.port();
    let globex_port_guard = start_backend_with_shutdown("globex-backend");
    let globex_port = globex_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/field-extraction-access-control.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", acme_port),
            ("10.0.1.2:8080", acme_port_2),
            ("10.0.2.1:8080", globex_port),
            ("10.0.3.1:8080", default_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/api/data", r#"{"tenant_id":"unknown","query":"SELECT *"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "unknown tenant should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "unknown tenant should route to default cluster"
    );
}

#[test]
fn field_extraction_example_body_routing_ignores_client_tenant_headers() {
    let acme_guard = start_backend_with_shutdown("acme-backend");
    let acme_second_guard = start_backend_with_shutdown("acme-backend");
    let globex_guard = start_backend_with_shutdown("globex-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
    let config = load_example_config(
        "payload-processing/field-extraction-access-control.yaml",
        free_port(),
        HashMap::from([
            ("10.0.1.1:8080", acme_guard.port()),
            ("10.0.1.2:8080", acme_second_guard.port()),
            ("10.0.2.1:8080", globex_guard.port()),
            ("10.0.3.1:8080", default_guard.port()),
        ]),
    );
    let proxy = start_proxy(&config);
    let send = |body: &str, extra_headers: &str| {
        let request = format!(
            "POST /api/data HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             {extra_headers}Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {body}",
            body.len()
        );
        http_send(proxy.addr(), &request)
    };

    for (body, extra_headers, backend) in [
        ("{}", "X-Tenant-Id: acme\r\n", "default-backend"),
        ("{bad", "X-Tenant-Id: acme\r\n", "default-backend"),
        (r#"{"tenant_id":"globex"}"#, "X-Tenant-Id: acme\r\n", "globex-backend"),
        (r#"{"tenant_id":"acme"}"#, "", "acme-backend"),
        (r#"{"tenant_id":"globex"}"#, "", "globex-backend"),
        (r#"{"tenant_id":"unknown"}"#, "", "default-backend"),
    ] {
        let response = send(body, extra_headers);
        assert_eq!(parse_status(&response), 200, "body: {body}");
        assert_eq!(parse_body(&response), backend, "body: {body}");
    }

    let spoofed = send("{}", "X-Praxis-Tenant-Id: acme\r\n");
    assert_eq!(parse_status(&spoofed), 400, "reserved client header must be rejected");
}

#[test]
fn body_size_limit_allows_small_body() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/body-size-limit-with-extraction.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/chat", r#"{"model":"model-alpha-1","prompt":"hello"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "small body under 1024 limit should return 200");
}

#[test]
fn body_size_limit_rejects_oversized_body() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/body-size-limit-with-extraction.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let large_body = format!(r#"{{"model":"model-alpha-1","prompt":"{}"}}"#, "x".repeat(2000));
    let raw = http_send(proxy.addr(), &json_post("/v1/chat", &large_body));
    assert_eq!(parse_status(&raw), 413, "oversized body should be rejected with 413");
}

#[test]
fn multi_listener_body_pipeline_passthrough() {
    let payload = r#"{"model":"model-alpha-1","user_id":"u-1"}"#;
    assert_multi_listener_example_request("passthrough", payload, None);
}

#[test]
fn multi_listener_body_pipeline_buffered_listener() {
    assert_multi_listener_example_request(
        "buffered",
        r#"{"model":"model-alpha-1","user_id":"u-1"}"#,
        Some("model-alpha-1"),
    );
    assert_multi_listener_example_request("buffered", "{}", None);
}

/// Exercise one measured request against the shipped three-listener YAML.
fn assert_multi_listener_example_request(listener: &str, payload: &str, expected_model: Option<&str>) {
    use std::{sync::mpsc::TryRecvError, time::Duration};

    let spec = PayloadSpec::padded(payload.len() as u64, payload.as_bytes(), b"", b'x').unwrap();
    let default = start_counting_backend(spec.clone(), "default", spec.len());
    let alpha = start_counting_backend(spec.clone(), "alpha", spec.len());
    let stream_port = free_port();
    let buffer_port = free_port();
    let passthrough_port = free_port();
    let config = multi_listener_example_config(stream_port, buffer_port, passthrough_port, default.port, alpha.port);
    let _proxy = start_full_proxy(&config);
    let listener_port = match listener {
        "buffered" => buffer_port,
        "passthrough" => passthrough_port,
        _ => panic!("unsupported example listener: {listener}"),
    };
    let address = format!("127.0.0.1:{listener_port}");
    wait_for_tcp(&address);
    let request_path = format!("/v1/chat/{listener}/{}", payload.len());
    let raw = http_send(&address, &json_post(&request_path, payload));
    assert_eq!(parse_status(&raw), 200, "{listener}: {raw}");
    let receipt = default.receipt.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(receipt.backend_id, "default", "{listener} must use default routing");
    assert_eq!(
        receipt.request_line,
        format!("POST {request_path} HTTP/1.1"),
        "receipt must belong to the measured POST"
    );
    assert_exact_example_body(&receipt, &spec);
    assert_eq!(
        example_header(&receipt, "x-model"),
        expected_model,
        "{listener} must promote only its configured model value"
    );
    assert_eq!(
        example_header(&receipt, "x-user-id"),
        None,
        "{listener} must not promote the user_id field"
    );
    assert!(
        matches!(alpha.accepted.try_recv(), Err(TryRecvError::Empty)),
        "{listener} request must not reach the alpha backend"
    );
    default.join();
    alpha.join();
}

/// Load the actual multi-listener example with local measured endpoints.
fn multi_listener_example_config(
    stream_port: u16,
    buffer_port: u16,
    passthrough_port: u16,
    default_port: u16,
    alpha_port: u16,
) -> Config {
    let path = praxis_test_utils::example_config_path("payload-processing/multi-listener-body-pipeline.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    let patched = patch_yaml(&yaml, stream_port, &HashMap::new());
    let patched = patched
        .replace("0.0.0.0:8081", &format!("127.0.0.1:{buffer_port}"))
        .replace("0.0.0.0:8082", &format!("127.0.0.1:{passthrough_port}"))
        .replace("127.0.0.1:3000", &format!("127.0.0.1:{default_port}"))
        .replace("127.0.0.1:3001", &format!("127.0.0.1:{alpha_port}"));
    Config::from_yaml(&patched).unwrap()
}

/// Verify byte-for-byte request delivery to the selected backend.
fn assert_exact_example_body(receipt: &BackendReceipt, spec: &PayloadSpec) {
    assert_eq!(receipt.bytes, spec.len(), "{receipt:?}");
    assert_eq!(receipt.verified_bytes, spec.len(), "{receipt:?}");
    assert_eq!(receipt.mismatch, None, "{receipt:?}");
    assert!(receipt.completion.is_some(), "{receipt:?}");
    assert_eq!(receipt.abort, None, "{receipt:?}");
}

/// Return one promoted header observed by the backend.
fn example_header<'a>(receipt: &'a BackendReceipt, name: &str) -> Option<&'a str> {
    receipt
        .headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.as_str())
}

#[test]
fn multi_listener_body_pipeline_stream_buffer_routes() {
    let default_port_guard = start_backend_with_shutdown("default-response");
    let default_port = default_port_guard.port();
    let alpha_port_guard = start_backend_with_shutdown("alpha-response");
    let alpha_port = alpha_port_guard.port();
    let proxy_streambuf = free_port();
    let proxy_buffered = free_port();
    let proxy_passthrough = free_port();

    let path = praxis_test_utils::example_config_path("payload-processing/multi-listener-body-pipeline.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let patched = patch_yaml(&yaml, proxy_streambuf, &HashMap::new());
    let patched = patched
        .replace("0.0.0.0:8081", &format!("127.0.0.1:{proxy_buffered}"))
        .replace("0.0.0.0:8082", &format!("127.0.0.1:{proxy_passthrough}"))
        .replace("127.0.0.1:3000", &format!("127.0.0.1:{default_port}"))
        .replace("127.0.0.1:3001", &format!("127.0.0.1:{alpha_port}"));
    let config = Config::from_yaml(&patched).unwrap();

    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/chat", r#"{"model":"model-alpha-1","user_id":"u-1"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "stream-buffer listener should return 200");
    assert_eq!(
        parse_body(&raw),
        "alpha-response",
        "model=model-alpha-1 should route to alpha_cluster cluster on stream-buffer listener"
    );
}

#[test]
fn body_size_example_routes_late_selector_at_limit_and_rejects_one_over() {
    use std::{sync::mpsc::TryRecvError, time::Duration};

    for size in [1024, 1025] {
        let spec = PayloadSpec::padded(size, br#"{"prompt":""#, br#"","model":"model-alpha-1"}"#, b'x').unwrap();
        let backend = start_counting_backend(spec.clone(), "example", size);
        let proxy_port = free_port();
        let config = load_example_config(
            "payload-processing/body-size-limit-with-extraction.yaml",
            proxy_port,
            HashMap::from([("127.0.0.1:3000", backend.port)]),
        );
        let proxy = start_full_proxy(&config);
        wait_for_tcp(proxy.addr());
        let body = String::from_utf8(spec.chunk(0, usize::try_from(size).unwrap())).unwrap();
        let response = http_send(proxy.addr(), &json_post("/v1/chat", &body));
        if size == 1024 {
            assert_eq!(parse_status(&response), 200);
            let receipt = backend.receipt.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(receipt.bytes, size);
            assert_eq!(receipt.verified_bytes, size);
            assert_eq!(receipt.mismatch, None);
            assert!(receipt.completion.is_some());
            assert!(
                receipt
                    .headers
                    .iter()
                    .any(|(name, value)| name == "x-model" && value == "model-alpha-1")
            );
        } else {
            assert_eq!(parse_status(&response), 413);
            assert!(matches!(backend.accepted.try_recv(), Err(TryRecvError::Empty)));
        }
        backend.join();
    }
}
