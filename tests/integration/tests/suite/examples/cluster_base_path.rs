// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the per-cluster upstream base path example configuration.

use praxis_core::config::Config;
use praxis_test_utils::{
    BackendGuard, GrpcBackend, ProxyGuard, example_config_path, free_port, h2c_get_authority_only, http_send,
    parse_body, parse_status, start_grpc_backend, start_proxy, start_uri_echo_backend,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn base_path_prefixes_the_upstream_path_per_cluster() {
    let example = ExampleProxy::start();

    for (path, model, want, expectation) in [
        (
            "/v1/completions",
            "model-a",
            "/grid-models/model-a/v1/completions",
            "each cluster should receive its own prefix",
        ),
        (
            "/v1/completions",
            "model-b",
            "/grid-models/model-b/v1/completions",
            "each cluster should receive its own prefix",
        ),
        (
            "/v1/models?limit=2&page=1",
            "model-a",
            "/grid-models/model-a/v1/models?limit=2&page=1",
            "the query should survive the prefix",
        ),
        (
            "/grid-models/model-a/v1/completions",
            "model-a",
            "/grid-models/model-a/grid-models/model-a/v1/completions",
            "a client path resembling the prefix should still be prefixed, or a client could reach the upstream root",
        ),
    ] {
        let target = example.get(path, model);
        assert_eq!(target, want, "{model} requesting {path}: {expectation}");
    }
}

#[test]
fn base_path_is_applied_once_on_a_retried_attempt() {
    let live = start_uri_echo_backend();
    let dead_port = free_port();
    let path = example_config_path("traffic-management/cluster-base-path.yaml");
    let yaml = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .replace(
            "              - \"127.0.0.1:9000\"\n",
            &format!(
                "              - \"127.0.0.1:{dead_port}\"\n              - \"127.0.0.1:{}\"\n",
                live.port()
            ),
        )
        .replace(
            "              base_path: \"/grid-models/model-a\"\n",
            "              base_path: \"/grid-models/model-a\"\n            retry_policy:\n              max_retries: 2\n              retriable_conditions: [connect_failure]\n",
        )
        .replace("0.0.0.0:8080", &format!("127.0.0.1:{}", free_port()));
    assert!(
        yaml.contains("retry_policy:"),
        "test setup: the retry policy should have been added"
    );
    let config = Config::from_yaml(&yaml).expect("example with a retry policy should parse");
    let proxy = start_proxy(&config);

    for i in 0..4 {
        let (status, body) = get_for_model(proxy.addr(), "/v1/completions", "model-a");
        assert_eq!(
            status, 200,
            "request {i} should fail over to the live endpoint; got {body}"
        );
        assert_eq!(
            body, "/grid-models/model-a/v1/completions",
            "request {i}: a retried attempt must carry the prefix exactly once"
        );
    }
}

#[test]
fn the_base_path_lands_on_the_rewritten_path_not_the_original() {
    let backend = start_uri_echo_backend();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: model-a
      - filter: path_rewrite
        strip_prefix: "/api/v1"
      - filter: load_balancer
        clusters:
          - name: model-a
            endpoints:
              - "127.0.0.1:{backend_port}"
            http:
              base_path: "/grid-models/model-a"
insecure_options:
  allow_private_endpoints: true
"#,
        backend_port = backend.port()
    );
    let config = Config::from_yaml(&yaml).expect("rewrite plus base path should parse");
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api/v1/completions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let (status, body) = (parse_status(&raw), parse_body(&raw));

    assert_eq!(status, 200, "request should succeed; got {body}");
    assert_eq!(
        body, "/grid-models/model-a/completions",
        "the prefix belongs on the rewritten path, not on the path the rewrite replaced"
    );
}

#[test]
fn a_preset_endpoint_is_reached_under_the_routed_clusters_base_path() {
    let backend = start_uri_echo_backend();
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
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
            cluster: model-a
      - filter: load_balancer
        clusters:
          - name: model-a
            endpoints:
              - "127.0.0.1:{dead_port}"
            http:
              base_path: "/grid-models/model-a"
insecure_options:
  allow_private_endpoints: true
"#,
        preset_port = backend.port()
    );
    let config = Config::from_yaml(&yaml).expect("preset plus base path should parse");
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /v1/completions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let (status, body) = (parse_status(&raw), parse_body(&raw));

    assert_eq!(
        status, 200,
        "only the preset endpoint is alive, so a non-200 means the preset path did not run; got {body}"
    );
    assert_eq!(
        body, "/grid-models/model-a/v1/completions",
        "a preset endpoint should still be reached under the cluster's base path"
    );
}

/// A proxy with one prefixed cluster whose upstream leg is HTTP/2.
///
/// The backend reports the `:path` it received, so these assert what the
/// proxy actually sent on the h2 leg rather than what it holds in its URI.
fn h2_upstream_proxy(backend_port: u16) -> (ProxyGuard, String) {
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: model-a
      - filter: load_balancer
        clusters:
          - name: model-a
            endpoints:
              - "127.0.0.1:{backend_port}"
            http:
              version: h2
              base_path: "/grid-models/model-a"
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = Config::from_yaml(&yaml).expect("h2 upstream with a base path should parse");
    let proxy = start_proxy(&config);
    let addr = proxy.addr().to_owned();
    (proxy, addr)
}

#[test]
fn an_h1_request_reaches_an_h2_upstream_under_the_base_path() {
    let backend = start_grpc_backend(GrpcBackend::ok());
    let (_proxy, addr) = h2_upstream_proxy(backend.port());

    let raw = http_send(
        &addr,
        "POST /v1/completions HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/grpc\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(
        parse_status(&raw),
        200,
        "the h2 upstream should be reachable; got {raw}"
    );
    assert!(
        backend
            .seen_paths()
            .contains(&"/grid-models/model-a/v1/completions".to_owned()),
        "the h2 upstream should have seen the prefixed path, saw {:?}",
        backend.seen_paths()
    );
}

#[test]
fn an_h2_request_reaches_an_h2_upstream_under_the_base_path() {
    let backend = start_grpc_backend(GrpcBackend::ok());
    let (_proxy, addr) = h2_upstream_proxy(backend.port());

    let (status, body) = h2c_get_authority_only(&addr, "/v1/completions", "gateway.example.test");

    assert_eq!(status, 200, "an h2 client should reach the h2 upstream; got {body}");
    assert!(
        backend
            .seen_paths()
            .contains(&"/grid-models/model-a/v1/completions".to_owned()),
        "the h2 upstream should have seen the prefixed path, saw {:?}",
        backend.seen_paths()
    );
}

#[test]
fn a_selector_after_the_balancer_keeps_the_base_path() {
    let backend = start_uri_echo_backend();
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        request_set:
          - name: x-gateway-destination
            value: "127.0.0.1:{preset_port}"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: model-a
      - filter: load_balancer
        clusters:
          - name: model-a
            endpoints:
              - "127.0.0.1:{dead_port}"
            http:
              base_path: "/grid-models/model-a"
      - filter: endpoint_selector
        source_header: x-gateway-destination
        strip_header: true
        required: true
insecure_options:
  allow_private_endpoints: true
"#,
        preset_port = backend.port()
    );
    let config = Config::from_yaml(&yaml).expect("selector after balancer should parse");
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /v1/completions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let (status, body) = (parse_status(&raw), parse_body(&raw));

    assert_eq!(status, 200, "only the preset endpoint is alive; got {body}");
    assert_eq!(
        body, "/grid-models/model-a/v1/completions",
        "a selector ordered after the balancer must keep the cluster's prefix"
    );
}

#[test]
fn an_unprefixed_cluster_is_unchanged() {
    let backend = start_uri_echo_backend();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: plain
      - filter: load_balancer
        clusters:
          - name: plain
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        backend_port = backend.port()
    );
    let config = Config::from_yaml(&yaml).expect("config without a base path should parse");
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /v1/completions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let (status, body) = (parse_status(&raw), parse_body(&raw));

    assert_eq!(status, 200, "request should succeed; got {body}");
    assert_eq!(
        body, "/v1/completions",
        "a cluster with no base path must forward the client path unchanged"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Send a GET for `model` and return `(status, body)`. The example's routes
/// match on `X-Model`, which `http_get` cannot send.
fn get_for_model(addr: &str, path: &str, model: &str) -> (u16, String) {
    let raw = http_send(
        addr,
        &format!(
            "GET {path} HTTP/1.1\r\n\
             Host: gateway.example.test\r\n\
             X-Model: {model}\r\n\
             Connection: close\r\n\r\n"
        ),
    );
    (parse_status(&raw), parse_body(&raw))
}

/// The example config running against two URI-echo backends.
///
/// Shared by every assertion in one test rather than started per assertion,
/// so the suite binds three ports for the whole set instead of three per
/// case.
struct ExampleProxy {
    /// Answers for the example's `127.0.0.1:9000` endpoint (model-a).
    _model_a: BackendGuard,

    /// Answers for the example's `127.0.0.1:9001` endpoint (model-b).
    _model_b: BackendGuard,

    /// The running proxy.
    proxy: ProxyGuard,
}

impl ExampleProxy {
    /// Load the example with test ports for both model backends.
    fn start() -> Self {
        let model_a = start_uri_echo_backend();
        let model_b = start_uri_echo_backend();
        let path = example_config_path("traffic-management/cluster-base-path.yaml");
        let yaml = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {path}: {e}"))
            .replace("127.0.0.1:9000", &format!("127.0.0.1:{}", model_a.port()))
            .replace("127.0.0.1:9001", &format!("127.0.0.1:{}", model_b.port()))
            .replace("0.0.0.0:8080", &format!("127.0.0.1:{}", free_port()));
        let config = Config::from_yaml(&yaml).expect("cluster-base-path example should parse");
        let proxy = start_proxy(&config);
        Self {
            _model_a: model_a,
            _model_b: model_b,
            proxy,
        }
    }

    /// Send `path` for `model` and return the request target the upstream saw.
    fn get(&self, path: &str, model: &str) -> String {
        let (status, body) = get_for_model(self.proxy.addr(), path, model);
        assert_eq!(status, 200, "request for {model} {path} should succeed; got {body}");
        body
    }
}
