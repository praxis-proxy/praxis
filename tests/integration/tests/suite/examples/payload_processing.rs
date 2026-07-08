// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for payload-processing example configurations.

use std::collections::HashMap;

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_send, json_post, load_example_config, parse_body, parse_status, patch_yaml,
    start_backend_with_shutdown, start_header_echo_backend, start_proxy, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------


#[test]
fn multi_field_extraction_extracts_both_fields() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/multi-field-extraction.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", backend_port),
            ("10.0.1.2:8080", backend_port),
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
    let alpha_port_guard = start_backend_with_shutdown("alpha-backend");
    let alpha_port = alpha_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let config = load_example_config(
        "payload-processing/multi-field-extraction.yaml",
        proxy_port,
        HashMap::from([
            ("10.0.1.1:8080", alpha_port),
            ("10.0.1.2:8080", alpha_port),
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
            ("10.0.1.2:8080", acme_port),
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
            ("10.0.1.2:8080", acme_port),
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
            ("10.0.1.2:8080", acme_port),
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
    let default_port_guard = start_backend_with_shutdown("passthrough-ok");
    let default_port = default_port_guard.port();
    let alpha_port_guard = start_backend_with_shutdown("alpha-response");
    let alpha_port = alpha_port_guard.port();
    let proxy_passthrough = free_port();
    let proxy_streambuf = free_port();
    let proxy_buffered = free_port();

    let path = praxis_test_utils::example_config_path("payload-processing/multi-listener-body-pipeline.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let patched = patch_yaml(&yaml, proxy_streambuf, &HashMap::new());
    let patched = patched
        .replace("0.0.0.0:8081", &format!("127.0.0.1:{proxy_buffered}"))
        .replace("0.0.0.0:8082", &format!("127.0.0.1:{proxy_passthrough}"))
        .replace("127.0.0.1:3000", &format!("127.0.0.1:{default_port}"))
        .replace("127.0.0.1:3001", &format!("127.0.0.1:{alpha_port}"));
    let config = Config::from_yaml(&patched).unwrap();

    let _proxy = start_proxy(&config);
    let passthrough_addr = format!("127.0.0.1:{proxy_passthrough}");
    wait_for_tcp(&passthrough_addr);

    let (status, body) = http_get(&passthrough_addr, "/anything", None);
    assert_eq!(status, 200, "passthrough listener should return 200");
    assert_eq!(
        body, "passthrough-ok",
        "passthrough listener should route to default backend"
    );
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
