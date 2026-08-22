// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Regression coverage for the StreamBuffer adapter contract that
//! protocol-specific body mutators rely on.

use praxis_core::config::Config;
use praxis_test_utils::{
    filters::BodyMutatingStreamBufferFilter, free_port, http_send, parse_body, parse_status, start_echo_backend,
    start_header_echo_backend, start_proxy_with_registry, start_uri_echo_backend,
};

#[test]
fn stream_buffer_readwrite_mutated_body_reaches_backend() {
    let backend_guard = start_echo_backend();
    let proxy_port = free_port();

    let yaml = mutator_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with_mutator();
    let proxy = start_proxy_with_registry(&config, &registry);

    let request = format!(
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: 20\r\n\
         \r\n\
         original-body-here!!"
    );
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    assert_eq!(
        parse_body(&raw),
        "mutated",
        "backend should receive the mutated body, not the original"
    );
}

#[test]
fn stream_buffer_readwrite_rewritten_path_reaches_backend() {
    let backend_guard = start_uri_echo_backend();
    let proxy_port = free_port();

    let yaml = mutator_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with_mutator();
    let proxy = start_proxy_with_registry(&config, &registry);

    let request = format!(
        "POST /original HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: 4\r\n\
         \r\n\
         test"
    );
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    let echoed_path = parse_body(&raw);
    assert_eq!(
        echoed_path, "/rewritten/path",
        "backend should receive the rewritten path set during body-phase pre-read"
    );
}

#[test]
fn stream_buffer_readwrite_content_length_repaired() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = mutator_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with_mutator();
    let proxy = start_proxy_with_registry(&config, &registry);

    let original = "this-is-a-longer-original-body-that-will-be-replaced";
    let request = format!(
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {original}",
        original.len(),
    );
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    let echoed_headers = parse_body(&raw);
    let echoed_lower = echoed_headers.to_lowercase();
    assert!(
        echoed_lower.contains("content-length: 7"),
        "backend should receive repaired Content-Length for mutated body: {echoed_headers}"
    );
    assert!(
        !echoed_lower.contains(&format!("content-length: {}", original.len())),
        "backend should not receive original Content-Length after body mutation: {echoed_headers}"
    );
}

// -----------------------------------------------------------------------------
// Body-phase Header Writeback Tests
// -----------------------------------------------------------------------------

#[test]
fn stream_buffer_body_phase_headers_to_set_reach_backend() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = header_mutator_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with_header_mutator();
    let proxy = start_proxy_with_registry(&config, &registry);

    let request = format!(
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: 4\r\n\
         x-client-remove-me: present\r\n\
         \r\n\
         test"
    );
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    let headers = parse_body(&raw);
    assert!(
        headers.contains("x-body-phase-set: from-body-filter"),
        "body-phase headers_to_set should reach backend: {headers}"
    );
}

#[test]
fn stream_buffer_body_phase_headers_to_remove_reach_backend() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = header_mutator_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with_header_mutator();
    let proxy = start_proxy_with_registry(&config, &registry);

    let request = format!(
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: 4\r\n\
         x-client-remove-me: present\r\n\
         \r\n\
         test"
    );
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    let headers = parse_body(&raw);
    assert!(
        !headers.contains("x-client-remove-me"),
        "body-phase headers_to_remove should strip client header: {headers}"
    );
}

#[test]
fn stream_buffer_body_phase_reserved_header_stripped_before_upstream() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();

    let yaml = header_mutator_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with_header_mutator();
    let proxy = start_proxy_with_registry(&config, &registry);

    let request = format!(
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: 4\r\n\
         \r\n\
         test"
    );
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(parse_status(&raw), 200);
    let headers = parse_body(&raw);
    assert!(
        !headers.contains("x-praxis-internal-leak"),
        "reserved x-praxis-* headers set during body phase must be stripped before upstream: {headers}"
    );
}

// -----------------------------------------------------------------------------
// Registries
// -----------------------------------------------------------------------------

fn registry_with_mutator() -> praxis_filter::FilterRegistry {
    let mut registry = praxis_filter::FilterRegistry::with_builtins();
    registry
        .register(
            "test_body_mutator",
            praxis_filter::FilterFactory::Http(std::sync::Arc::new(|_| {
                Ok(Box::new(BodyMutatingStreamBufferFilter::default_test()))
            })),
        )
        .expect("duplicate filter name");
    registry
}

fn registry_with_header_mutator() -> praxis_filter::FilterRegistry {
    let mut registry = praxis_filter::FilterRegistry::with_builtins();
    registry
        .register(
            "test_header_mutator",
            praxis_filter::FilterFactory::Http(std::sync::Arc::new(|_| {
                Ok(Box::new(praxis_test_utils::filters::HeaderMutatingStreamBufferFilter))
            })),
        )
        .expect("duplicate filter name");
    registry
}

// -----------------------------------------------------------------------------
// YAML Utilities
// -----------------------------------------------------------------------------

fn mutator_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: test_body_mutator
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
    )
}

fn header_mutator_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: test_header_mutator
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#,
    )
}
