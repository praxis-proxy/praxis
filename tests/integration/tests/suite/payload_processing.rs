// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for payload processing example configurations.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, json_post, parse_body, parse_status, start_backend_with_shutdown, start_header_echo_backend,
    start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn stream_buffer_routes_by_extracted_action() {
    let process_port_guard = start_backend_with_shutdown("process-backend");
    let process_port = process_port_guard.port();
    let validate_port_guard = start_backend_with_shutdown("validate-backend");
    let validate_port = validate_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let yaml = action_routing_yaml(proxy_port, process_port, validate_port, default_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/tasks", r#"{"action":"process","payload":"data"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "process action should return 200");
    assert_eq!(
        parse_body(&raw),
        "process-backend",
        "action=process should route to processor cluster"
    );

    let raw = http_send(
        proxy.addr(),
        &json_post("/tasks", r#"{"action":"validate","payload":"data"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "validate action should return 200");
    assert_eq!(
        parse_body(&raw),
        "validate-backend",
        "action=validate should route to validator cluster"
    );
}

#[test]
fn stream_buffer_unknown_action_routes_to_default() {
    let process_port_guard = start_backend_with_shutdown("process-backend");
    let process_port = process_port_guard.port();
    let validate_port_guard = start_backend_with_shutdown("validate-backend");
    let validate_port = validate_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let yaml = action_routing_yaml(proxy_port, process_port, validate_port, default_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/tasks", r#"{"action":"unknown","payload":"data"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "unknown action should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "unknown action should route to default cluster"
    );
}

#[test]
fn stream_buffer_missing_action_routes_to_default() {
    let process_port_guard = start_backend_with_shutdown("process-backend");
    let process_port = process_port_guard.port();
    let validate_port_guard = start_backend_with_shutdown("validate-backend");
    let validate_port = validate_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let yaml = action_routing_yaml(proxy_port, process_port, validate_port, default_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/tasks", r#"{"payload":"data"}"#));
    assert_eq!(parse_status(&raw), 200, "missing action should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "missing action field should route to default cluster"
    );
}

#[test]
fn multi_field_extracts_both_fields() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let yaml = multi_field_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/chat", r#"{"model":"model-alpha-1","user_id":"u-42"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "multi-field extraction should return 200");
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("x-model: model-alpha-1"),
        "expected X-Model header echoed by backend, got:\n{body}"
    );
    assert!(
        body_lower.contains("x-user-id: u-42"),
        "expected X-User-Id header echoed by backend, got:\n{body}"
    );
}

#[test]
fn multi_field_missing_one_still_extracts_other() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let yaml = multi_field_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/chat", r#"{"model":"model-alpha-1"}"#));
    assert_eq!(parse_status(&raw), 200, "single-field present should return 200");
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("x-model: model-alpha-1"),
        "expected X-Model header when only model is present, got:\n{body}"
    );
    assert!(
        !body_lower.contains("x-user-id"),
        "X-User-Id should not be present when user_id field is missing, got:\n{body}"
    );
}

#[test]
fn multi_field_routes_by_extracted_model() {
    let alpha_port_guard = start_backend_with_shutdown("alpha-backend");
    let alpha_port = alpha_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let yaml = multi_field_routing_yaml(proxy_port, alpha_port, default_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/chat", r#"{"model":"model-alpha-1","user_id":"u-42"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "model-alpha-1 model routing should return 200");
    assert_eq!(
        parse_body(&raw),
        "alpha-backend",
        "model=model-alpha-1 should route to alpha_cluster cluster"
    );

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/chat", r#"{"model":"unknown","user_id":"u-42"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "unknown model routing should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "unknown model should route to default cluster"
    );
}

#[test]
fn conditional_extraction_fires_on_matching_path() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let yaml = conditional_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/chat/completions", r#"{"model":"model-alpha-1","prompt":"hi"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "matching path extraction should return 200");
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-model: model-alpha-1"),
        "X-Model should be extracted on /v1/ path, got:\n{body}"
    );
}

#[test]
fn conditional_extraction_skips_on_non_matching_path() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let yaml = conditional_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/other/endpoint", r#"{"model":"model-alpha-1","prompt":"hi"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "non-matching path should return 200");
    let body = parse_body(&raw);
    assert!(
        !body.to_lowercase().contains("x-model"),
        "X-Model should NOT be extracted on /other/ path, got:\n{body}"
    );
}

#[test]
fn body_limit_allows_small_body_with_extraction() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let yaml = body_limit_extraction_yaml(proxy_port, backend_port, 4096);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/v1/chat", r#"{"model":"model-alpha-1","prompt":"hello"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "small body under limit should return 200");
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-model: model-alpha-1"),
        "field should be extracted from small body, got:\n{body}"
    );
}

#[test]
fn body_limit_rejects_oversized_body() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let yaml = body_limit_extraction_yaml(proxy_port, backend_port, 32);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let large_body = format!(r#"{{"model":"model-alpha-1","prompt":"{}"}}"#, "x".repeat(100));
    let raw = http_send(proxy.addr(), &json_post("/v1/chat", &large_body));
    assert_eq!(parse_status(&raw), 413, "oversized body should be rejected with 413");
}

#[test]
fn body_limit_exact_boundary_succeeds() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let small_json = r#"{"model":"model-alpha-1"}"#;
    let limit = small_json.len();
    let yaml = body_limit_extraction_yaml(proxy_port, backend_port, limit);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/v1/chat", small_json));
    assert_eq!(
        parse_status(&raw),
        200,
        "body at exact limit boundary should return 200"
    );
    let body = parse_body(&raw);
    assert!(
        body.to_lowercase().contains("x-model: model-alpha-1"),
        "field should be extracted at exact boundary, got:\n{body}"
    );
}

#[test]
fn tenant_extraction_routes_to_correct_backend() {
    let acme_port_guard = start_backend_with_shutdown("acme-backend");
    let acme_port = acme_port_guard.port();
    let globex_port_guard = start_backend_with_shutdown("globex-backend");
    let globex_port = globex_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let yaml = tenant_routing_yaml(proxy_port, acme_port, globex_port, default_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/api/data", r#"{"tenant_id":"acme","query":"SELECT *"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "acme tenant routing should return 200");
    assert_eq!(
        parse_body(&raw),
        "acme-backend",
        "tenant_id=acme should route to acme cluster"
    );

    let raw = http_send(
        proxy.addr(),
        &json_post("/api/data", r#"{"tenant_id":"globex","query":"SELECT *"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "globex tenant routing should return 200");
    assert_eq!(
        parse_body(&raw),
        "globex-backend",
        "tenant_id=globex should route to globex cluster"
    );
}

#[test]
fn tenant_extraction_unknown_tenant_routes_to_default() {
    let acme_port_guard = start_backend_with_shutdown("acme-backend");
    let acme_port = acme_port_guard.port();
    let globex_port_guard = start_backend_with_shutdown("globex-backend");
    let globex_port = globex_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let yaml = tenant_routing_yaml(proxy_port, acme_port, globex_port, default_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &json_post("/api/data", r#"{"tenant_id":"unknown","query":"SELECT *"}"#),
    );
    assert_eq!(parse_status(&raw), 200, "unknown tenant should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "unknown tenant_id should route to default cluster"
    );
}

#[test]
fn tenant_extraction_missing_tenant_routes_to_default() {
    let acme_port_guard = start_backend_with_shutdown("acme-backend");
    let acme_port = acme_port_guard.port();
    let globex_port_guard = start_backend_with_shutdown("globex-backend");
    let globex_port = globex_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-backend");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();

    let yaml = tenant_routing_yaml(proxy_port, acme_port, globex_port, default_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(proxy.addr(), &json_post("/api/data", r#"{"query":"SELECT *"}"#));
    assert_eq!(parse_status(&raw), 200, "missing tenant should return 200");
    assert_eq!(
        parse_body(&raw),
        "default-backend",
        "missing tenant_id should route to default cluster"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// YAML config for action-based routing via stream-buffer extraction.
fn action_routing_yaml(proxy_port: u16, process_port: u16, validate_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - body-inspection
      - routing
filter_chains:
  - name: body-inspection
    filters:
      - filter: json_body_field
        field: action
        header: X-Action
  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            headers:
              x-action: "process"
            cluster: processor
          - path_prefix: "/"
            headers:
              x-action: "validate"
            cluster: validator
          - path_prefix: "/"
            cluster: default
      - filter: load_balancer
        clusters:
          - name: processor
            endpoints:
              - "127.0.0.1:{process_port}"
          - name: validator
            endpoints:
              - "127.0.0.1:{validate_port}"
          - name: default
            endpoints:
              - "127.0.0.1:{default_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// YAML config for multi-field extraction echoing headers back.
fn multi_field_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: json_body_field
        fields:
          - field: model
            header: X-Model
          - field: user_id
            header: X-User-Id
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// YAML config for multi-field extraction with model-based routing.
fn multi_field_routing_yaml(proxy_port: u16, alpha_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: json_body_field
        fields:
          - field: model
            header: X-Model
          - field: user_id
            header: X-User-Id
      - filter: router
        routes:
          - path_prefix: "/"
            headers:
              x-model: "model-alpha-1"
            cluster: alpha_cluster
          - path_prefix: "/"
            cluster: default
      - filter: load_balancer
        clusters:
          - name: alpha_cluster
            endpoints:
              - "127.0.0.1:{alpha_port}"
          - name: default
            endpoints:
              - "127.0.0.1:{default_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// YAML config for conditional field extraction on /v1/ paths.
fn conditional_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: json_body_field
        conditions:
          - when:
              path_prefix: "/v1/"
        field: model
        header: X-Model
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// YAML config for body size limit combined with field extraction.
fn body_limit_extraction_yaml(proxy_port: u16, backend_port: u16, limit: usize) -> String {
    format!(
        r#"
body_limits:
  max_request_bytes: {limit}
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: json_body_field
        field: model
        header: X-Model
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// YAML config for tenant-based access control routing.
fn tenant_routing_yaml(proxy_port: u16, acme_port: u16, globex_port: u16, default_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - extract-tenant
      - routing
filter_chains:
  - name: extract-tenant
    filters:
      - filter: json_body_field
        field: tenant_id
        header: X-Tenant-Id
  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            headers:
              x-tenant-id: "acme"
            cluster: acme
          - path_prefix: "/"
            headers:
              x-tenant-id: "globex"
            cluster: globex
          - path_prefix: "/"
            cluster: default
      - filter: load_balancer
        clusters:
          - name: acme
            endpoints:
              - "127.0.0.1:{acme_port}"
          - name: globex
            endpoints:
              - "127.0.0.1:{globex_port}"
          - name: default
            endpoints:
              - "127.0.0.1:{default_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

#[test]
fn large_json_routes_only_after_eos_and_preserves_original_bytes() {
    for (size, position) in [
        (1_048_576, "early"),
        (1_048_576, "middle"),
        (1_048_576, "late"),
        (10_485_760, "late"),
    ] {
        let (prefix, suffix) = routing_document_parts(size, position);
        let spec = praxis_test_utils::PayloadSpec::padded(size, &prefix, &suffix, b'x').unwrap();
        assert_large_body_route(&spec, true);
    }
}

#[test]
#[ignore = "64 MiB scheduled payload test"]
fn large_json_routes_at_64_mib() {
    let size = 67_108_864;
    let (prefix, suffix) = routing_document_parts(size, "late");
    let spec = praxis_test_utils::PayloadSpec::padded(size, &prefix, &suffix, b'x').unwrap();
    assert_large_body_route(&spec, true);
}

#[test]
fn large_invalid_or_unsafe_selectors_use_quarantine_route() {
    let size = 1_048_576;
    let cases: Vec<(Vec<u8>, Vec<u8>, bool)> = vec![
        (br#"{"model":"blue","pad":""#.to_vec(), br#""}garbage"#.to_vec(), false),
        (br#"{"model":"blue","pad":""#.to_vec(), br#""}{}"#.to_vec(), false),
        (br#"{"model":"blue","pad":""#.to_vec(), br#"""#.to_vec(), false),
        (br#"{"pad":""#.to_vec(), br#""}"#.to_vec(), false),
        (br#"{"model":"bad\r\nvalue","pad":""#.to_vec(), br#""}"#.to_vec(), false),
        (
            br#"{"model":"bad\u0000value","pad":""#.to_vec(),
            br#""}"#.to_vec(),
            false,
        ),
        (
            br#"{"model":"bad\u007fvalue","pad":""#.to_vec(),
            br#""}"#.to_vec(),
            false,
        ),
        (
            br#"{"model":"blue","pad":""#.to_vec(),
            br#"","\u006dodel":"other"}"#.to_vec(),
            false,
        ),
        (
            br#"{"model":"other","pad":""#.to_vec(),
            br#"","nested":{"model":"other"},"\u006dodel":"blue"}"#.to_vec(),
            true,
        ),
        (
            format!(r#"{{"model":"{}","pad":""#, "x".repeat(257)).into_bytes(),
            br#""}"#.to_vec(),
            false,
        ),
        (
            br#"{"model":{"tier":"blue"},"pad":""#.to_vec(),
            br#""}"#.to_vec(),
            false,
        ),
    ];
    for (prefix, suffix, protected) in cases {
        let spec = praxis_test_utils::PayloadSpec::padded(size, &prefix, &suffix, b'x').unwrap();
        assert_large_body_route(&spec, protected);
    }
    let invalid_utf8 = praxis_test_utils::PayloadSpec::padded(size, br#"{"model":"blue","pad":""#, br#""}"#, b'x')
        .unwrap()
        .with_fault(size - 3, 0xFF)
        .unwrap();
    assert_large_body_route(&invalid_utf8, false);
}

#[test]
fn deep_hidden_subtrees_follow_each_consumers_depth_policy() {
    let filters = "      - filter: json_body\n        max_body_bytes: 2097152\n        on_invalid: reject\n        request_extract:\n          - pointer: /model\n            header: X-Model\n";
    for (depth, walker_status) in [(90, 200), (129, 400)] {
        let suffix = format!(r#"","nested":{}1{}}}"#, "[".repeat(depth), "]".repeat(depth));
        let spec =
            praxis_test_utils::PayloadSpec::padded(1_048_576, br#"{"model":"blue","pad":""#, suffix.as_bytes(), b'x')
                .unwrap();
        let body = spec.chunk(0, usize::try_from(spec.len()).unwrap());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).is_ok(),
            depth == 90,
            "serde DOM depth control"
        );
        assert_large_body_route(&spec, true);
        assert_single_backend_payload(filters, 2_097_152, &spec, &spec, walker_status);
    }
}

#[test]
fn complete_json_prefix_requires_the_entire_suffix_before_routing() {
    let prefix = br#"{"model":"blue"}"#;
    for (suffix, protected) in [
        (b"".as_slice(), true),
        (b"{}".as_slice(), false),
        (b"GET /protected HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(), false),
    ] {
        let spec = praxis_test_utils::PayloadSpec::padded(1_048_576, prefix, suffix, b' ').unwrap();
        assert_large_body_route(&spec, protected);
    }
}

#[test]
fn content_type_exclusion_does_not_unlock_protected_route() {
    let spec =
        praxis_test_utils::PayloadSpec::padded(1_048_576, br#"{"model":"blue","pad":""#, br#""}"#, b'x').unwrap();
    assert_large_body_route_with_options(&spec, false, RouteCriteria::ContentTypeExcluded);
}

#[test]
fn large_json_unicode_spanning_writes_preserves_routing_and_original_bytes() {
    for token in ["🌳".as_bytes(), br"\ud83c\udf33".as_slice()] {
        let mut prefix = br#"{"ignored":""#.to_vec();
        prefix.resize(65_535, b'x');
        prefix.extend_from_slice(token);
        prefix.extend_from_slice(br#"","model":"blue","pad":""#);
        let spec = praxis_test_utils::PayloadSpec::padded(1_048_576, &prefix, br#""}"#, b'x').unwrap();
        assert_large_body_route(&spec, true);
    }
}

#[test]
fn distant_multi_field_route_requires_both_values() {
    let prefix = br#"{"model":"blue","pad":""#;
    for (suffix, protected) in [
        (br#"","tenant":"acme"}"#.as_slice(), true),
        (br#"","tenant":"unknown"}"#.as_slice(), false),
        (br#"","tenant":42}"#.as_slice(), false),
        (br#""}"#.as_slice(), false),
    ] {
        let spec = praxis_test_utils::PayloadSpec::padded(1_048_576, prefix, suffix, b'x').unwrap();
        assert_large_body_route_with_options(&spec, protected, RouteCriteria::RequireTenant);
    }
}

/// Construct a large object with a selector at a specified position.
fn routing_document_parts(size: u64, position: &str) -> (Vec<u8>, Vec<u8>) {
    match position {
        "early" => (br#"{"model":"blue","pad":""#.to_vec(), br#""}"#.to_vec()),
        "middle" => {
            let half = usize::try_from(size / 2).unwrap();
            let mut prefix = br#"{"first":""#.to_vec();
            prefix.extend(std::iter::repeat_n(b'x', half));
            prefix.extend_from_slice(br#"","model":"blue","pad":""#);
            (prefix, br#""}"#.to_vec())
        },
        "late" => (br#"{"pad":""#.to_vec(), br#"","model":"blue"}"#.to_vec()),
        _ => panic!("unknown selector position"),
    }
}

/// Classifier options exercised by the large-route fixture.
#[derive(Clone, Copy)]
enum RouteCriteria {
    /// Require only the model field.
    ModelOnly,
    /// Require both model and tenant fields.
    RequireTenant,
    /// Skip classification for an excluded request content type.
    ContentTypeExcluded,
}

/// Assert pre-EOS isolation, route choice, byte integrity, and reserved-header stripping.
fn assert_large_body_route(spec: &praxis_test_utils::PayloadSpec, protected: bool) {
    assert_large_body_route_with_options(spec, protected, RouteCriteria::ModelOnly);
}

/// Exercise a classifier with explicit route and content-type options.
fn assert_large_body_route_with_options(
    spec: &praxis_test_utils::PayloadSpec,
    protected: bool,
    criteria: RouteCriteria,
) {
    use std::{
        io::{BufReader, Write as _},
        net::TcpStream,
        time::Duration,
    };

    use praxis_test_utils::{H1Completion, read_h1_response, start_counting_backend};

    let protected_backend = start_counting_backend(spec.clone(), "protected", spec.len());
    let quarantine_backend = start_counting_backend(spec.clone(), "quarantine", spec.len());
    let proxy_port = free_port();
    let yaml = large_routing_yaml(
        proxy_port,
        protected_backend.port,
        quarantine_backend.port,
        matches!(criteria, RouteCriteria::RequireTenant),
    );
    let yaml = if matches!(criteria, RouteCriteria::ContentTypeExcluded) {
        yaml.replace("      - filter: json_body_field\n", "      - filter: json_body_field\n        conditions:\n          - when:\n              headers:\n                content-type: application/json\n")
    } else {
        yaml
    };
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = praxis_test_utils::start_full_proxy(&config);
    praxis_test_utils::wait_for_tcp(proxy.addr());
    let mut stream = TcpStream::connect(proxy.addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
    let content_type = if matches!(criteria, RouteCriteria::ContentTypeExcluded) {
        "text/plain"
    } else {
        "application/json"
    };
    write!(stream, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nX-Route: blue\r\nConnection: close\r\n\r\n", spec.len()).unwrap();
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
            protected_backend.accepted.recv_timeout(Duration::from_millis(200)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ),
        "protected backend must not receive a connection before EOS"
    );
    assert!(
        matches!(
            quarantine_backend.accepted.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ),
        "fallback must not receive a connection before EOS"
    );
    stream.write_all(&spec.chunk(offset, 1)).unwrap();
    let response = read_h1_response(&mut BufReader::new(stream), false, 0, |_| Ok(()));
    assert_eq!(response.status, Some(200), "backend verifies the entire request");
    assert!(
        response.completion.is_some(),
        "response framing must complete: {response:?}"
    );
    assert_eq!(response.abort, None, "response must not abort");
    let (selected, other) = if protected {
        (&protected_backend, &quarantine_backend)
    } else {
        (&quarantine_backend, &protected_backend)
    };
    let receipt = selected.receipt.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(
        receipt.backend_id,
        if protected { "protected" } else { "quarantine" },
        "selected route must match classifier result"
    );
    assert_eq!(
        receipt.bytes,
        spec.len(),
        "selected backend must receive the complete body"
    );
    assert_eq!(
        receipt.verified_bytes,
        spec.len(),
        "selected backend must verify every body byte"
    );
    assert_eq!(receipt.mismatch, None, "backend body bytes must match");
    assert!(
        matches!(
            receipt.completion,
            Some(H1Completion::ContentLength | H1Completion::Chunked)
        ),
        "selected request must complete with valid framing"
    );
    assert_eq!(receipt.abort, None, "backend request must not abort");
    assert!(
        receipt.headers.iter().all(|(name, _)| name != "x-praxis-route"),
        "trusted promotion must not reach backend"
    );
    assert!(
        matches!(other.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
        "unselected backend must receive no request"
    );
    protected_backend.join();
    quarantine_backend.join();
}

/// Two routes with an explicit quarantine fallback and reserved classifier header.
fn large_routing_yaml(proxy_port: u16, protected_port: u16, quarantine_port: u16, require_tenant: bool) -> String {
    let tenant_match = if require_tenant {
        "              x-praxis-tenant: acme\n"
    } else {
        ""
    };
    format!(
        r#"
body_limits:
  max_request_bytes: 67108864
listeners:
  - name: gateway
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: json_body_field
        max_body_bytes: 67108864
        fields:
          - field: model
            header: x-praxis-route
          - field: tenant
            header: x-praxis-tenant
      - filter: router
        routes:
          - path_prefix: "/"
            headers:
              x-praxis-route: blue
{tenant_match}            cluster: protected
          - path_prefix: "/"
            cluster: quarantine
      - filter: load_balancer
        clusters:
          - name: protected
            endpoints: ["127.0.0.1:{protected_port}"]
          - name: quarantine
            endpoints: ["127.0.0.1:{quarantine_port}"]
insecure_options:
  allow_private_endpoints: true
"#
    )
}

#[test]
fn competing_json_limits_merge_then_global_ceiling_clamps_both_orders() {
    let spec = praxis_test_utils::PayloadSpec::padded(16_384, br#"{"model":"blue","pad":""#, br#""}"#, b'x').unwrap();
    let field = "      - filter: json_body_field\n        field: model\n        header: X-Model\n        max_body_bytes: 8192\n";
    let extractor = "      - filter: json_body\n        max_body_bytes: 32768\n        request_extract:\n          - pointer: /model\n            metadata: chosen\n";
    for filters in [format!("{field}{extractor}"), format!("{extractor}{field}")] {
        assert_single_backend_payload(&filters, 32_768, &spec, &spec, 200);
        assert_single_backend_payload(&filters, 8_192, &spec, &spec, 413);
    }
}

#[test]
fn large_request_rewrites_set_authoritative_length_and_preserve_tail() {
    let size = 1_048_576;
    let input_prefix = br#"{"model":"old","secret":"remove","pad":""#;
    let input_suffix = br#""}"#;
    let input = praxis_test_utils::PayloadSpec::padded(size, input_prefix, input_suffix, b'x').unwrap();
    let rewrite_cases = [
        (
            "request_add:\n          - pointer: /added\n            value: more",
            br#"{"model":"old","secret":"remove","pad":""#.as_slice(),
            br#"","added":"more"}"#.as_slice(),
        ),
        (
            "request_remove:\n          - /secret",
            br#"{"model":"old","pad":""#.as_slice(),
            br#""}"#.as_slice(),
        ),
        (
            "request_replace:\n          - pointer: /model\n            value: new",
            br#"{"model":"new","secret":"remove","pad":""#.as_slice(),
            br#""}"#.as_slice(),
        ),
    ];
    for (operation, prefix, suffix) in rewrite_cases {
        let new_size = size - u64::try_from(input_prefix.len() + input_suffix.len()).unwrap()
            + u64::try_from(prefix.len() + suffix.len()).unwrap();
        let expected = praxis_test_utils::PayloadSpec::padded(new_size, prefix, suffix, b'x').unwrap();
        let filters = format!(
            "      - filter: json_body\n        max_body_bytes: 2097152\n        on_invalid: reject\n        {operation}\n"
        );
        assert_single_backend_payload(&filters, 2_097_152, &input, &expected, 200);
    }
    let filters =
        "      - filter: json_body\n        request_replace:\n          - pointer: ''\n            value: {}\n";
    let empty = praxis_test_utils::PayloadSpec::padded(2, b"{}", b"", b' ').unwrap();
    assert_single_backend_payload(filters, 2_097_152, &input, &empty, 200);
}

#[test]
fn content_type_skip_preserves_bytes_without_bypassing_global_limit() {
    let spec = praxis_test_utils::PayloadSpec::padded(16_384, br#"{"model":"old","pad":""#, br#""}"#, b'x').unwrap();
    let skipped = "      - filter: json_body\n        max_body_bytes: 32768\n        content_types: [application/not-json]\n        request_replace:\n          - pointer: /model\n            value: new\n";
    assert_single_backend_payload(skipped, 32_768, &spec, &spec, 200);
    assert_single_backend_payload(skipped, 8_192, &spec, &spec, 413);
    let active = skipped.replace("application/not-json", "application/json");
    let expected =
        praxis_test_utils::PayloadSpec::padded(16_384, br#"{"model":"new","pad":""#, br#""}"#, b'x').unwrap();
    assert_single_backend_payload(&active, 32_768, &spec, &expected, 200);
}

/// Run a built-in JSON pipeline against a byte-verifying backend.
fn assert_single_backend_payload(
    filters: &str,
    limit: u64,
    input: &praxis_test_utils::PayloadSpec,
    expected: &praxis_test_utils::PayloadSpec,
    status: u16,
) {
    use std::{
        io::{BufReader, Write as _},
        net::TcpStream,
        sync::mpsc::TryRecvError,
        time::Duration,
    };

    use praxis_test_utils::{H1Completion, read_h1_response, start_counting_backend};

    let backend = start_counting_backend(expected.clone(), "backend", expected.len());
    let proxy_port = free_port();
    let yaml = single_backend_payload_yaml(proxy_port, backend.port, limit, filters);
    let proxy = praxis_test_utils::start_full_proxy(&Config::from_yaml(&yaml).unwrap());
    praxis_test_utils::wait_for_tcp(proxy.addr());
    let mut stream = TcpStream::connect(proxy.addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(stream, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n", input.len()).unwrap();
    let mut offset = 0;
    while offset < input.len() {
        let chunk = input.chunk(offset, 65_536);
        stream.write_all(&chunk).unwrap();
        offset += u64::try_from(chunk.len()).unwrap();
    }
    let response = read_h1_response(&mut BufReader::new(stream), false, 65_536, |_| Ok(()));
    assert_eq!(
        response.status,
        Some(status),
        "response status must match configured limit behavior"
    );
    assert!(response.completion.is_some(), "response must complete: {response:?}");
    if status == 200 {
        let receipt = backend.receipt.recv_timeout(Duration::from_secs(30)).unwrap();
        assert_eq!(
            receipt.bytes,
            expected.len(),
            "backend must receive the expected rewritten length"
        );
        assert_eq!(
            receipt.verified_bytes,
            expected.len(),
            "backend must verify every rewritten byte"
        );
        assert_eq!(receipt.mismatch, None, "backend body bytes must match");
        assert_eq!(receipt.abort, None, "backend request must not abort");
        assert_eq!(
            receipt.completion,
            Some(H1Completion::ContentLength),
            "rewritten request framing must complete"
        );
        assert_eq!(
            receipt
                .headers
                .iter()
                .filter(|(name, _)| name == "content-length")
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            vec![expected.len().to_string()],
            "rewritten Content-Length must match the expected body"
        );
        assert!(
            receipt.headers.iter().all(|(name, _)| name != "transfer-encoding"),
            "fixed-length rewrite must not use transfer encoding"
        );
    } else {
        assert!(
            matches!(backend.accepted.try_recv(), Err(TryRecvError::Empty)),
            "oversized input must not reach backend"
        );
    }
    backend.join();
}

/// Configure a body pipeline with an explicit global request ceiling.
fn single_backend_payload_yaml(proxy_port: u16, backend_port: u16, limit: u64, filters: &str) -> String {
    format!(
        r#"
body_limits:
  max_request_bytes: {limit}
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
fn large_response_redaction_waits_for_eos_and_preserves_committed_length() {
    use praxis_test_utils::PayloadResponseFraming;

    for framing in [
        PayloadResponseFraming::Fixed,
        PayloadResponseFraming::Chunked,
        PayloadResponseFraming::Close,
    ] {
        for http2 in [false, true] {
            assert_redacted_response(framing, http2);
        }
    }
}

/// Status, completion and bytes are independent observations of a response.
struct JsonResponseObservation {
    status: Option<u16>,
    complete: bool,
    abort: Option<String>,
    body: Vec<u8>,
}

/// Read through either downstream protocol, preserving incomplete responses.
fn observe_json_response(address: &str, http2: bool, seen: &std::sync::mpsc::Sender<()>) -> JsonResponseObservation {
    use std::{
        io::{BufReader, Write as _},
        net::TcpStream,
        time::Duration,
    };

    let mut body = Vec::new();
    if http2 {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            tokio::time::timeout(Duration::from_secs(20), async {
                let stream = tokio::net::TcpStream::connect(address).await.unwrap();
                let (mut sender, connection) = h2::client::handshake(stream).await.unwrap();
                let driver = tokio::spawn(connection);
                let request = http::Request::builder()
                    .uri(format!("http://{address}/"))
                    .body(())
                    .unwrap();
                let (response, _) = sender.send_request(request, true).unwrap();
                let observed = praxis_test_utils::read_h2_response(response.await, 2_097_152, |chunk| {
                    let _sent = seen.send(());
                    body.extend_from_slice(chunk);
                    Ok(())
                })
                .await;
                driver.abort();
                JsonResponseObservation {
                    status: observed.status,
                    complete: observed.end_stream,
                    abort: observed.abort,
                    body,
                }
            })
            .await
            .unwrap()
        })
    } else {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let response = praxis_test_utils::read_h1_response(&mut BufReader::new(stream), false, 2_097_152, |chunk| {
            let _sent = seen.send(());
            body.extend_from_slice(chunk);
            Ok(())
        });
        JsonResponseObservation {
            status: response.status,
            complete: response.completion.is_some(),
            abort: response.abort.map(|error| format!("{error:?}")),
            body,
        }
    }
}

/// A successful response must finish its framing without a reset or read error.
fn collect_json_response(address: &str, http2: bool, seen: &std::sync::mpsc::Sender<()>) -> (u16, Vec<u8>) {
    let result = observe_json_response(address, http2, seen);
    assert!(result.complete, "response did not complete: {:?}", result.abort);
    assert_eq!(result.abort, None, "response must not abort");
    (result.status.unwrap(), result.body)
}

/// Gate the upstream final byte and check that no original data leaks early.
fn assert_redacted_response(framing: praxis_test_utils::PayloadResponseFraming, http2: bool) {
    use std::{sync::mpsc, thread, time::Duration};

    use praxis_test_utils::{PayloadSpec, start_payload_response_backend};

    let original_len = 1_048_576;
    let original = PayloadSpec::padded(
        original_len,
        br#"{"keep":"safe","secret":""#,
        br#"","tail":"end"}"#,
        b's',
    )
    .unwrap();
    let mut backend = start_payload_response_backend(original, framing, Some(original_len - 1));
    let filters = "      - filter: json_body\n        max_body_bytes: 2097152\n        on_invalid: reject\n        response_remove:\n          - /secret\n";
    let config = Config::from_yaml(&single_backend_payload_yaml(
        free_port(),
        backend.port,
        2_097_152,
        filters,
    ))
    .unwrap();
    let proxy = praxis_test_utils::start_full_proxy(&config);
    praxis_test_utils::wait_for_tcp(proxy.addr());
    let address = proxy.addr().to_owned();
    let (seen, observed) = mpsc::channel();
    let reader = thread::spawn(move || collect_json_response(&address, http2, &seen));
    assert_eq!(
        backend.prefix_written.recv_timeout(Duration::from_secs(10)).unwrap(),
        original_len - 1,
        "source must pause before its final response byte"
    );
    assert!(
        matches!(
            observed.recv_timeout(Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "buffered response must not release data before validation"
    );
    backend.resume();
    let (status, body) = reader.join().unwrap();
    assert_eq!(status, 200, "response status must be successful");
    assert_eq!(
        u64::try_from(body.len()).unwrap(),
        original_len,
        "redaction must preserve committed response length"
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"keep":"safe","tail":"end"}),
        "redacted JSON must retain only the allowed fields"
    );
    assert!(
        !body.windows(64).any(|window| window == [b's'; 64]),
        "removed secret bytes must not reach client"
    );
    let json_end = body.iter().rposition(|byte| *byte != b' ').unwrap() + 1;
    assert!(
        body[json_end..].iter().all(|byte| *byte == b' '),
        "redacted length padding must consist of spaces"
    );
    let receipt = backend.receipt.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(receipt.complete, "{receipt:?}");
    assert_eq!(
        receipt.written_bytes, original_len,
        "source must write the entire original response"
    );
    backend.join();
}

#[test]
fn malformed_large_response_does_not_release_sensitive_original_body() {
    for chunked in [false, true] {
        for http2 in [false, true] {
            assert_invalid_json_response(chunked, http2, InvalidResponse::RejectMalformed);
            assert_invalid_json_response(chunked, http2, InvalidResponse::RejectTruncated);
            assert_invalid_json_response(chunked, http2, InvalidResponse::ContinueMalformed);
        }
    }
}

/// Invalid response shape and configured failure policy.
#[derive(Clone, Copy)]
enum InvalidResponse {
    /// Reject a complete malformed JSON response.
    RejectMalformed,
    /// Reject an incomplete transport response.
    RejectTruncated,
    /// Explicitly preserve a complete malformed JSON response.
    ContinueMalformed,
}

/// Separate parser rejection, transport truncation and explicit passthrough.
fn assert_invalid_json_response(chunked: bool, http2: bool, scenario: InvalidResponse) {
    let truncated = matches!(scenario, InvalidResponse::RejectTruncated);
    let passthrough = matches!(scenario, InvalidResponse::ContinueMalformed);
    use std::{io::Write as _, sync::mpsc, time::Duration};

    use praxis_test_utils::{read_http_request, spawn_raw_http_backend};

    let mut upstream = format!(r#"{{"secret":"CANARY-SECRET","padding":"{}"}}"#, "x".repeat(1_048_576)).into_bytes();
    if !truncated {
        upstream.extend_from_slice(b"garbage");
    }
    let expected = upstream.clone();
    let (backend_port, backend_thread) = spawn_raw_http_backend(move |mut stream| {
        stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
        read_http_request(&mut stream);
        let framing = if chunked {
            "Transfer-Encoding: chunked".to_owned()
        } else {
            format!("Content-Length: {}", upstream.len() + usize::from(truncated))
        };
        write!(stream, "HTTP/1.1 200 OK\r\n{framing}\r\nConnection: close\r\n\r\n").unwrap();
        for part in upstream.chunks(16_384) {
            if chunked {
                write!(stream, "{:x}\r\n", part.len()).unwrap();
            }
            stream.write_all(part).unwrap();
            if chunked {
                stream.write_all(b"\r\n").unwrap();
            }
        }
        if chunked && !truncated {
            stream.write_all(b"0\r\n\r\n").unwrap();
        }
    });
    let clean = start_backend_with_shutdown("{}");
    let behavior = if passthrough { "continue" } else { "reject" };
    let filters = format!(
        "      - filter: json_body\n        max_body_bytes: 2097152\n        on_invalid: {behavior}\n        response_remove:\n          - /secret\n"
    );
    let yaml = single_backend_payload_yaml(free_port(), backend_port, 2_097_152, &filters)
        .replace(
            "        routes:\n",
            "        routes:\n          - path_prefix: /probe\n            cluster: probe\n",
        )
        .replace(
            "        clusters:\n",
            &format!(
                "        clusters:\n          - name: probe\n            endpoints: [\"127.0.0.1:{}\"]\n",
                clean.port()
            ),
        );
    let proxy = praxis_test_utils::start_full_proxy(&Config::from_yaml(&yaml).unwrap());
    praxis_test_utils::wait_for_tcp(proxy.addr());
    let (seen, _observed) = mpsc::channel();
    let result = observe_json_response(proxy.addr(), http2, &seen);
    backend_thread.join().unwrap();
    if passthrough {
        assert_eq!(
            result.status,
            Some(200),
            "passthrough response status must remain successful"
        );
        assert!(result.complete, "passthrough response must complete");
        assert_eq!(result.abort, None, "response must not abort");
        assert_eq!(result.body, expected, "continue preserves the complete invalid input");
    } else {
        assert!(
            !result.body.windows(13).any(|part| part == b"CANARY-SECRET"),
            "rejected response must not leak its secret"
        );
        assert!(
            !result.body.windows(64).any(|part| part == [b'x'; 64]),
            "rejected response must not leak padding"
        );
        // A failure can precede header commitment or abort an already committed
        // response. Neither a missing response nor a completed 200 is accepted.
        match result.status {
            Some(200) => {
                assert!(!result.complete, "rejected response must be incomplete");
                assert!(
                    result.abort.is_some(),
                    "a committed rejection requires a transport failure"
                );
            },
            Some(status) => {
                assert_eq!(
                    status,
                    if truncated { 502 } else { 500 },
                    "local failure status must distinguish transport and parse failure"
                );
                assert!(result.complete, "local failure response must complete");
                assert_eq!(result.abort, None, "response must not abort");
            },
            None => panic!("proxy emitted no response headers: {:?}", result.abort),
        }
    }
    assert_eq!(
        praxis_test_utils::http_get(proxy.addr(), "/probe", None),
        (200, "{}".to_owned()),
        "independent probe must succeed after response failure"
    );
}

#[test]
fn large_multi_field_metadata_does_not_leak_between_requests() {
    use std::time::Duration;

    use praxis_test_utils::{PayloadSpec, start_counting_backend};

    let valid = PayloadSpec::padded(1_048_576, br#"{"model":"blue","pad":""#, br#"","tenant":"acme"}"#, b'x').unwrap();
    let missing = PayloadSpec::padded(1_048_576, br#"{"model":"blue","pad":""#, br#""}"#, b'x').unwrap();
    let protected = start_counting_backend(valid.clone(), "protected", valid.len());
    let quarantine = start_counting_backend(missing.clone(), "quarantine", missing.len());
    let proxy_port = free_port();
    let yaml = large_routing_yaml(proxy_port, protected.port, quarantine.port, true);
    let proxy = praxis_test_utils::start_full_proxy(&Config::from_yaml(&yaml).unwrap());
    praxis_test_utils::wait_for_tcp(proxy.addr());
    for (spec, expected) in [(valid, &protected), (missing, &quarantine)] {
        let body = String::from_utf8(spec.chunk(0, usize::try_from(spec.len()).unwrap())).unwrap();
        let response = http_send(proxy.addr(), &json_post("/", &body));
        assert_eq!(parse_status(&response), 200);
        let receipt = expected.receipt.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(
            receipt.verified_bytes,
            spec.len(),
            "selected backend must verify every body byte"
        );
        assert_eq!(receipt.mismatch, None, "backend body bytes must match");
        assert!(receipt.completion.is_some());
        assert!(receipt.headers.iter().all(|(name, _)| !name.starts_with("x-praxis-")));
    }
    protected.join();
    quarantine.join();
}

#[test]
fn truncated_large_upload_does_not_dispatch_and_next_request_is_clean() {
    use std::{io::Write as _, net::TcpStream, sync::mpsc::RecvTimeoutError, time::Duration};

    use praxis_test_utils::{PayloadSpec, start_counting_backend};

    let valid = PayloadSpec::padded(1_048_576, br#"{"pad":""#, br#"","model":"blue"}"#, b'x').unwrap();
    let protected = start_counting_backend(valid.clone(), "protected", valid.len());
    let quarantine = start_counting_backend(valid.clone(), "quarantine", valid.len());
    let proxy_port = free_port();
    let yaml = large_routing_yaml(proxy_port, protected.port, quarantine.port, false);
    let proxy = praxis_test_utils::start_full_proxy(&Config::from_yaml(&yaml).unwrap());
    praxis_test_utils::wait_for_tcp(proxy.addr());
    let partial = PayloadSpec::padded(1_048_576, br#"{"model":"blue","pad":""#, b"", b'x').unwrap();
    let mut stream = TcpStream::connect(proxy.addr()).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    stream
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2097152\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut offset = 0;
    while offset < partial.len() {
        let chunk = partial.chunk(offset, 65_536);
        stream.write_all(&chunk).unwrap();
        offset += u64::try_from(chunk.len()).unwrap();
    }
    drop(stream);
    assert!(matches!(
        protected.accepted.recv_timeout(Duration::from_millis(300)),
        Err(RecvTimeoutError::Timeout)
    ));
    assert!(matches!(
        quarantine.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    let body = String::from_utf8(valid.chunk(0, usize::try_from(valid.len()).unwrap())).unwrap();
    assert_eq!(parse_status(&http_send(proxy.addr(), &json_post("/", &body))), 200);
    let receipt = protected.receipt.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(receipt.verified_bytes, valid.len());
    assert_eq!(receipt.mismatch, None, "backend body bytes must match");
    assert!(receipt.completion.is_some());
    assert!(matches!(
        quarantine.accepted.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    protected.join();
    quarantine.join();
}

#[test]
fn large_body_processors_observe_declared_order_once() {
    use std::time::Duration;

    use praxis_test_utils::{PayloadSpec, start_counting_backend};

    let input = PayloadSpec::padded(1_048_576, br#"{"model":"blue","pad":""#, br#""}"#, b'x').unwrap();
    let output = PayloadSpec::padded(1_048_575, br#"{"model":"new","pad":""#, br#""}"#, b'x').unwrap();
    let extract = "      - filter: json_body_field\n        field: model\n        header: x-praxis-before\n";
    let rewrite =
        "      - filter: json_body\n        request_replace:\n          - pointer: /model\n            value: new\n";
    let after = "      - filter: json_body\n        request_extract:\n          - pointer: /model\n            header: x-praxis-after\n";
    for (filters, expected_protected) in [
        (format!("{extract}{rewrite}{after}"), true),
        (format!("{rewrite}{extract}{after}"), false),
    ] {
        let protected = start_counting_backend(output.clone(), "protected", output.len());
        let quarantine = start_counting_backend(output.clone(), "quarantine", output.len());
        let proxy_port = free_port();
        let yaml = format!(
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
              x-praxis-before: blue
              x-praxis-after: new
            cluster: protected
          - path_prefix: "/"
            cluster: quarantine
      - filter: load_balancer
        clusters:
          - name: protected
            endpoints: ["127.0.0.1:{protected_port}"]
          - name: quarantine
            endpoints: ["127.0.0.1:{quarantine_port}"]
insecure_options:
  allow_private_endpoints: true
"#,
            protected_port = protected.port,
            quarantine_port = quarantine.port
        );
        let proxy = praxis_test_utils::start_full_proxy(&Config::from_yaml(&yaml).unwrap());
        praxis_test_utils::wait_for_tcp(proxy.addr());
        let body = String::from_utf8(input.chunk(0, usize::try_from(input.len()).unwrap())).unwrap();
        assert_eq!(parse_status(&http_send(proxy.addr(), &json_post("/", &body))), 200);
        let (selected, other) = if expected_protected {
            (&protected, &quarantine)
        } else {
            (&quarantine, &protected)
        };
        let receipt = selected.receipt.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(receipt.verified_bytes, output.len());
        assert_eq!(receipt.mismatch, None, "backend body bytes must match");
        assert!(receipt.completion.is_some());
        assert!(receipt.headers.iter().all(|(name, _)| !name.starts_with("x-praxis-")));
        assert!(matches!(
            other.accepted.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        protected.join();
        quarantine.join();
    }
}

#[test]
fn large_carrier_promotes_only_safe_decoded_header_values() {
    use std::time::Duration;

    use praxis_test_utils::{PayloadSpec, start_counting_backend};

    let cases = [
        ("x".repeat(255), Some("x".repeat(255))),
        ("\\u0078".repeat(256), Some("x".repeat(256))),
        ("\\u0078".repeat(257), None),
        ("\\u00e9".repeat(128), Some("é".repeat(128))),
        ("\\u00e9".repeat(129), None),
        ("bad\\r\\nInjected: yes".to_owned(), None),
        ("bad\\u0000value".to_owned(), None),
        ("bad\\u007fvalue".to_owned(), None),
    ];
    let filters = "      - filter: json_body_field\n        max_body_bytes: 2097152\n        field: model\n        header: X-Model\n";
    for (token, expected) in cases {
        let prefix = format!(r#"{{"model":"{token}","pad":""#);
        let spec = PayloadSpec::padded(1_048_576, prefix.as_bytes(), br#""}"#, b'x').unwrap();
        let backend = start_counting_backend(spec.clone(), "header", spec.len());
        let port = free_port();
        let yaml = single_backend_payload_yaml(port, backend.port, 2_097_152, filters);
        let proxy = praxis_test_utils::start_full_proxy(&Config::from_yaml(&yaml).unwrap());
        praxis_test_utils::wait_for_tcp(proxy.addr());
        let body = String::from_utf8(spec.chunk(0, usize::try_from(spec.len()).unwrap())).unwrap();
        assert_eq!(parse_status(&http_send(proxy.addr(), &json_post("/", &body))), 200);
        let receipt = backend.receipt.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(
            receipt.verified_bytes,
            spec.len(),
            "selected backend must verify every body byte"
        );
        assert_eq!(receipt.mismatch, None, "backend body bytes must match");
        assert!(receipt.completion.is_some());
        let promoted: Vec<&str> = receipt
            .headers
            .iter()
            .filter(|(name, _)| name == "x-model")
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(promoted, expected.as_deref().into_iter().collect::<Vec<_>>());
        assert!(receipt.headers.iter().all(|(name, _)| name != "injected"));
        backend.join();
    }
}

#[test]
fn malformed_json_rewrite_modes_and_fail_open_do_not_bypass_limits() {
    let spec =
        praxis_test_utils::PayloadSpec::padded(16_384, br#"{"model":"blue","pad":""#, br#""}garbage"#, b'x').unwrap();
    for (invalid, failure, status) in [
        ("continue", "closed", 200),
        ("reject", "open", 400),
        ("error", "closed", 500),
        ("error", "open", 200),
    ] {
        let filters = format!(
            "      - filter: json_body\n        max_body_bytes: 32768\n        on_invalid: {invalid}\n        failure_mode: {failure}\n        request_remove:\n          - /model\n"
        );
        assert_single_backend_payload(&filters, 32_768, &spec, &spec, status);
    }
    let filters = "      - filter: json_body\n        max_body_bytes: 32768\n        on_invalid: error\n        failure_mode: open\n        request_remove:\n          - /model\n";
    assert_single_backend_payload(filters, 8_192, &spec, &spec, 413);
}

#[test]
fn large_response_processors_run_in_reverse_order_and_preserve_length() {
    use std::{
        sync::{Arc, mpsc},
        thread,
        time::Duration,
    };

    use praxis_filter::{FilterFactory, FilterRegistry};
    use praxis_test_utils::{
        PayloadResponseFraming, PayloadSpec, start_full_proxy_with_registry, start_payload_response_backend,
        wait_for_tcp,
    };

    let length = 1_048_576;
    let prefix = br#"{"secret":"private","other":42,"pad":""#;
    let suffix = br#""}"#;
    let original = PayloadSpec::padded(length, prefix, suffix, b'x').unwrap();
    let secret = "      - filter: json_body\n        max_body_bytes: 1048576\n        response_remove: [/secret]\n";
    let extract = "      - filter: json_body\n        max_body_bytes: 1048576\n        response_remove: [/other]\n        response_extract:\n          - pointer: /secret\n            metadata: response.secret\n";
    for (filters, captured) in [
        (format!("{secret}{extract}"), Some("private")),
        (format!("{extract}{secret}"), None),
    ] {
        let mut backend =
            start_payload_response_backend(original.clone(), PayloadResponseFraming::Fixed, Some(length - 1));
        let filters = format!("      - filter: response_metadata_observer\n{filters}");
        let yaml = single_backend_payload_yaml(free_port(), backend.port, 2_097_152, &filters);
        let config = Config::from_yaml(&yaml).unwrap();
        let (events, observations) = mpsc::channel();
        let mut registry = FilterRegistry::with_builtins();
        registry
            .register(
                "response_metadata_observer",
                FilterFactory::Http(Arc::new(move |_| {
                    let filter: Box<dyn praxis_filter::HttpFilter> =
                        Box::new(ResponseMetadataObserver { events: events.clone() });
                    Ok(filter)
                })),
            )
            .unwrap();
        let proxy = start_full_proxy_with_registry(&config, &registry);
        wait_for_tcp(proxy.addr());
        let address = proxy.addr().to_owned();
        let (seen, body_observations) = mpsc::channel();
        let reader = thread::spawn(move || collect_json_response(&address, false, &seen));
        assert_eq!(
            backend.prefix_written.recv_timeout(Duration::from_secs(10)).unwrap(),
            length - 1
        );
        assert!(matches!(
            body_observations.recv_timeout(Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        backend.resume();
        let (status, body) = reader.join().unwrap();
        assert_eq!(status, 200, "response status must be successful");
        let padding_len = usize::try_from(length).unwrap() - prefix.len() - suffix.len();
        let mut expected = format!(r#"{{"pad":"{}"}}"#, "x".repeat(padding_len)).into_bytes();
        expected.resize(usize::try_from(length).unwrap(), b' ');
        assert_eq!(
            body, expected,
            "both real response processors must rewrite exactly once and fit the original length"
        );
        assert_eq!(
            observations.recv_timeout(Duration::from_secs(10)).unwrap().as_deref(),
            captured,
            "the extractor must see the preceding response processor's output"
        );
        assert!(
            matches!(observations.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "one final observer callback"
        );
        let receipt = backend.receipt.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(receipt.complete, "{receipt:?}");
        assert_eq!(receipt.written_bytes, length);
        backend.join();
    }
}

/// Observe response metadata after the real body processors complete.
struct ResponseMetadataObserver {
    /// Captured response metadata sent to the test.
    events: std::sync::mpsc::Sender<Option<String>>,
}

#[async_trait::async_trait]
impl praxis_filter::HttpFilter for ResponseMetadataObserver {
    fn name(&self) -> &'static str {
        "response_metadata_observer"
    }

    fn response_body_access(&self) -> praxis_filter::BodyAccess {
        praxis_filter::BodyAccess::ReadOnly
    }

    fn response_body_mode(&self) -> praxis_filter::BodyMode {
        praxis_filter::BodyMode::StreamBuffer {
            max_bytes: Some(1_048_576),
        }
    }

    async fn on_request(
        &self,
        _ctx: &mut praxis_filter::HttpFilterContext<'_>,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        Ok(praxis_filter::FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        ctx: &mut praxis_filter::HttpFilterContext<'_>,
        _body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        if !end_of_stream {
            return Ok(praxis_filter::FilterAction::Continue);
        }
        self.events
            .send(ctx.get_metadata("response.secret").map(str::to_owned))
            .unwrap();
        Ok(praxis_filter::FilterAction::BodyDone)
    }
}
