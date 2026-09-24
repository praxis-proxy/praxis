// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for `selected_upstream` conditions when `endpoint_selector`
//! presets the endpoint before the load balancer runs.
//!
//! The pipeline is the shipped endpoint-selector shape (`endpoint_selector` ->
//! `router` -> `load_balancer`) followed by a `path_rewrite` gated on the
//! routed cluster's provider. A `headers` filter stands in for the trusted
//! external source and presets the destination, so the load balancer never
//! selects an endpoint; it must still publish the routed cluster's metadata
//! for the gate to fire.

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_proxy, start_uri_echo_backend};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn preset_endpoint_publishes_routed_cluster_metadata() {
    let preset_backend = start_uri_echo_backend();
    let cluster_backend = start_backend_with_shutdown("cluster-backend");
    let proxy_port = free_port();
    let config = Config::from_yaml(&preset_endpoint_yaml(
        proxy_port,
        preset_backend.port(),
        cluster_backend.port(),
    ))
    .unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/chat", None);

    assert_eq!(status, 200, "the request through the preset endpoint should succeed");
    assert_eq!(
        body, "/selected/chat",
        "the preset endpoint must serve the request and the selected_upstream gate must fire on the routed \
         cluster's provider"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// The shipped endpoint-selector shape with a trusted preset destination and a
/// `path_rewrite` gated on the routed cluster's provider.
fn preset_endpoint_yaml(proxy_port: u16, preset_port: u16, cluster_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main

filter_chains:
  - name: main
    filters:
      - filter: headers
        request_set:
          - name: x-gateway-destination
            value: "127.0.0.1:{preset_port}"

      - filter: endpoint_selector
        source_header: x-gateway-destination
        strip_header: true
        required: true

      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend

      - filter: load_balancer
        clusters:
          - name: backend
            http:
              application_protocol: openai_chat_completions
              application_provider: vllm
            endpoints:
              - "127.0.0.1:{cluster_port}"

      - filter: path_rewrite
        add_prefix: "/selected"
        conditions:
          - when:
              selected_upstream:
                application_provider: vllm

insecure_options:
  allow_private_endpoints: true
"#
    )
}
