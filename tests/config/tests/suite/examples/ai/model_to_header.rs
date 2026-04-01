use praxis_core::config::Config;

use crate::common::{free_port, http_post, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn model_to_header_routes_by_model_field() {
    let port_a = start_backend("model-a-response");
    let port_default = start_backend("default-response");
    let proxy_port = free_port();
    let yaml = make_yaml(proxy_port, "mistral-large-latest", port_a, port_default);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let (status, body) = http_post(&addr, "/v1/chat", r#"{"model":"mistral-large-latest","messages":[]}"#);
    assert_eq!(status, 200, "matching model should return 200");
    assert_eq!(
        body, "model-a-response",
        "matching model should route to model-a backend"
    );
}

#[test]
fn model_to_header_falls_through_on_unknown_model() {
    let port_a = start_backend("model-a-response");
    let port_default = start_backend("default-response");
    let proxy_port = free_port();
    let yaml = make_yaml(proxy_port, "mistral-large-latest", port_a, port_default);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let (status, body) = http_post(&addr, "/v1/chat", r#"{"model":"unknown","messages":[]}"#);
    assert_eq!(status, 200, "unknown model should return 200");
    assert_eq!(body, "default-response", "unknown model should fall through to default");
}

#[test]
fn model_to_header_continues_without_model_field() {
    let port_a = start_backend("model-a-response");
    let port_default = start_backend("default-response");
    let proxy_port = free_port();
    let yaml = make_yaml(proxy_port, "mistral-large-latest", port_a, port_default);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let (status, body) = http_post(&addr, "/v1/chat", r#"{"messages":[]}"#);
    assert_eq!(status, 200, "missing model field should return 200");
    assert_eq!(body, "default-response", "missing model should fall through to default");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build YAML config for model-based routing with two named clusters
/// plus a default fallback.
fn make_yaml(proxy_port: u16, model_a: &str, port_a: u16, port_default: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
pipeline:
  - filter: model_to_header
  - filter: router
    routes:
      - path_prefix: "/"
        headers:
          x-model: "{model_a}"
        cluster: model_a
      - path_prefix: "/"
        cluster: fallback
  - filter: load_balancer
    clusters:
      - name: model_a
        endpoints:
          - "127.0.0.1:{port_a}"
      - name: fallback
        endpoints:
          - "127.0.0.1:{port_default}"
"#
    )
}
