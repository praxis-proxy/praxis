// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for the per-cluster authority override example configuration.

use std::collections::HashMap;

use praxis_core::config::Config;
use praxis_test_utils::{free_port, h2c_get, http_get, start_header_echo_backend};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn authority_override_replaces_host() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/authority-override.yaml",
        proxy_port,
        HashMap::from([("localhost:9000", backend.port())]),
    );
    let proxy = praxis_test_utils::start_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", Some("anything.example.com"));
    assert_eq!(status, 200, "authority override example should return 200");
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("host: api.example.com"),
        "upstream should receive the configured authority, not the downstream Host; got:\n{body}"
    );
}

#[test]
fn authority_override_does_not_leak_downstream_host() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/authority-override.yaml",
        proxy_port,
        HashMap::from([("localhost:9000", backend.port())]),
    );
    let proxy = praxis_test_utils::start_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/test", Some("attacker.evil.com"));
    assert_eq!(status, 200);
    let body_lower = body.to_lowercase();
    assert!(
        !body_lower.contains("attacker.evil.com"),
        "downstream Host must not leak to upstream when authority override is set; got:\n{body}"
    );
    assert!(
        body_lower.contains("host: api.example.com"),
        "upstream should receive the configured authority; got:\n{body}"
    );
}

#[test]
fn authority_override_works_over_h2c_downstream() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/authority-override.yaml",
        proxy_port,
        HashMap::from([("localhost:9000", backend.port())]),
    );
    let proxy = praxis_test_utils::start_proxy(&config);
    let (status, body) = h2c_get(proxy.addr(), "/", Some("anything.example.com"));
    assert_eq!(status, 200, "H2 request through authority override should return 200");
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("host: api.example.com"),
        "upstream should receive the configured authority when client connects via H2; got:\n{body}"
    );
}

#[test]
fn two_clusters_authority_isolation() {
    let override_backend = start_header_echo_backend();
    let passthrough_backend = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/override/"
            cluster: with-authority
          - path_prefix: "/passthrough/"
            cluster: without-authority
      - filter: load_balancer
        clusters:
          - name: with-authority
            endpoints:
              - "127.0.0.1:{override_port}"
            http:
              authority: "api.example.com"
          - name: without-authority
            endpoints:
              - "127.0.0.1:{passthrough_port}"
"#,
        override_port = override_backend.port(),
        passthrough_port = passthrough_backend.port(),
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = praxis_test_utils::start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/override/test", Some("client.example.com"));
    assert_eq!(status, 200);
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("host: api.example.com"),
        "override cluster should replace Host; got:\n{body}"
    );

    let (status, body) = http_get(proxy.addr(), "/passthrough/test", Some("client.example.com"));
    assert_eq!(status, 200);
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("host: client.example.com"),
        "passthrough cluster should forward original Host; got:\n{body}"
    );
    assert!(
        !body_lower.contains("host: api.example.com"),
        "passthrough cluster must not receive the other cluster's authority; got:\n{body}"
    );
}

#[test]
fn authority_override_stable_across_sequential_requests() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/authority-override.yaml",
        proxy_port,
        HashMap::from([("localhost:9000", backend.port())]),
    );
    let proxy = praxis_test_utils::start_proxy(&config);

    for i in 0..5 {
        let (status, body) = http_get(proxy.addr(), &format!("/req-{i}"), Some("varying-host.example.com"));
        assert_eq!(status, 200, "request {i} should succeed");
        let body_lower = body.to_lowercase();
        assert!(
            body_lower.contains("host: api.example.com"),
            "request {i}: authority override should be stable across requests; got:\n{body}"
        );
    }
}

/// An h2c request with an absolute URI (explicit `:scheme` and
/// `:authority` pseudo-headers) names an authority in the request itself;
/// the configured override must still win over it.
#[test]
fn authority_override_wins_over_h2c_absolute_uri() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/authority-override.yaml",
        proxy_port,
        HashMap::from([("localhost:9000", backend.port())]),
    );
    let proxy = praxis_test_utils::start_proxy(&config);

    let (status, body) =
        praxis_test_utils::h2c_get_absolute(proxy.addr(), &format!("http://{}/", "absolute.example.com"));
    assert_eq!(status, 200, "absolute-URI h2c request should be proxied");
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("host: api.example.com"),
        "configured authority must replace the request URI's authority; got:\n{body}"
    );
    assert!(
        !body_lower.contains("absolute.example.com"),
        "the client-supplied authority must not leak upstream; got:\n{body}"
    );
}
