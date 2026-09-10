// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Praxis Contributors

//! Functional integration tests for traffic-management example configurations.

use std::collections::HashMap;

use praxis_core::config::{Cluster, Config};
use praxis_test_utils::{
    free_port, http_get, http_send, parse_header, parse_status, start_backend_with_shutdown, start_proxy,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn timeout_example_fast_request_succeeds() {
    let backend_guard = start_backend_with_shutdown("fast");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/timeout.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "fast request should succeed within 5s timeout");
    assert_eq!(body, "fast", "response body should match backend");
}

#[test]
fn redirect_example_returns_301_with_location() {
    let proxy_port = free_port();
    let migration_port = free_port();
    let config = super::load_example_config(
        "traffic-management/redirect.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:8081", migration_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /old-page HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 301, "redirect example should return 301");
    assert_eq!(
        parse_header(&raw, "Location").as_deref(),
        Some("https://example.com/old-page"),
        "redirect Location should expand path template"
    );
}

#[test]
fn rate_limiting_example_allows_then_rejects() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let global_port = free_port();
    let config = super::load_example_config(
        "traffic-management/rate-limiting.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3000", backend_guard.port()),
            ("127.0.0.1:8081", global_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let (first_status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(first_status, 200, "first request within burst should succeed");

    let mut got_429 = false;
    for _ in 0..50 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        if status == 429 {
            got_429 = true;
            break;
        }
    }
    assert!(got_429, "rate limiter should return 429 after exhausting burst");
}

#[test]
fn rate_limiting_example_returns_rate_limit_headers() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let global_port = free_port();
    let config = super::load_example_config(
        "traffic-management/rate-limiting.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3000", backend_guard.port()),
            ("127.0.0.1:8081", global_port),
        ]),
    );
    let proxy = start_proxy(&config);

    for _ in 0..50 {
        let raw = http_send(
            proxy.addr(),
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        if parse_status(&raw) == 429 {
            assert!(
                parse_header(&raw, "Retry-After").is_some(),
                "429 response should include Retry-After header"
            );
            return;
        }
    }
    panic!("rate limiter should have returned 429 within 50 requests");
}

#[test]
fn cluster_application_metadata_example_proxies_request() {
    let backend_guard = start_backend_with_shutdown("llm");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/cluster-application-metadata.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", backend_guard.port())]),
    );

    // Both identifiers survive parsing and validation on the cluster that
    // declared them, not merely somewhere in the config as a whole.
    let clusters = inline_clusters(&config, "main", "load_balancer");
    let cluster = clusters
        .iter()
        .find(|c| &*c.name == "llm_backend")
        .expect("example should define the llm_backend cluster");
    assert_eq!(
        cluster.http.application_protocol.as_deref(),
        Some("openai_chat_completions"),
        "application_protocol should survive parsing"
    );
    assert_eq!(
        cluster.http.application_provider.as_deref(),
        Some("vllm"),
        "application_provider should survive parsing"
    );

    let proxy = start_proxy(&config);

    // A cluster tagged with opaque application metadata is accepted and still
    // proxies traffic normally — the metadata rides along with the cluster.
    let (status, body) = http_get(proxy.addr(), "/v1/chat/completions", None);
    assert_eq!(status, 200, "request to the tagged cluster should be proxied");
    assert_eq!(body, "llm", "response body should come from the tagged backend");
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

/// Read back the inline `clusters:` list of one filter entry.
///
/// Example clusters are declared inside the load balancer's opaque filter
/// config rather than the top-level `clusters:` block, so recovering the
/// typed [`Cluster`] means re-deserializing that YAML value — the same way
/// `validate_inline_clusters` reaches them.
fn inline_clusters(config: &Config, chain_name: &str, filter_type: &str) -> Vec<Cluster> {
    let chain = config
        .filter_chains
        .iter()
        .find(|c| c.name == chain_name)
        .unwrap_or_else(|| panic!("chain '{chain_name}' not found"));
    let entry = chain
        .filters
        .iter()
        .find(|f| f.filter_type == filter_type)
        .unwrap_or_else(|| panic!("filter '{filter_type}' not found in chain '{chain_name}'"));
    let serde_yaml::Value::Mapping(mapping) = &entry.config else {
        panic!("filter '{filter_type}' config should be a mapping");
    };
    let clusters = mapping
        .get("clusters")
        .unwrap_or_else(|| panic!("filter '{filter_type}' should declare inline clusters"));
    serde_yaml::from_value(clusters.clone()).expect("inline clusters should deserialize")
}
