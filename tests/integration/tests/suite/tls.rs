//! TLS integration tests: listener termination, upstream origination,
//! TCP TLS forwarding, and SNI fallback behavior.

use praxis_core::config::Config;

use crate::common::{
    TestCertificates, free_port, https_get, start_backend, start_full_proxy, start_tcp_echo_backend, start_tls_proxy,
    tls_send_recv, wait_for_tls,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn listener_tls_termination_end_to_end() {
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();

    let backend_port = start_backend("tls-terminated");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      cert_path: "{cert}"
      key_path: "{key}"
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_tls_proxy(&config, &client_config);

    let (status, body) = https_get(&addr, "/", &client_config);
    assert_eq!(status, 200, "TLS-terminated proxy should return 200");
    assert_eq!(
        body, "tls-terminated",
        "TLS-terminated proxy should forward backend body"
    );
}

#[test]
fn tls_listener_routing_works() {
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();

    let api_port = start_backend("api-response");
    let web_port = start_backend("web-response");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      cert_path: "{cert}"
      key_path: "{key}"
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: api
          - path_prefix: "/"
            cluster: web
      - filter: load_balancer
        clusters:
          - name: api
            endpoints:
              - "127.0.0.1:{api_port}"
          - name: web
            endpoints:
              - "127.0.0.1:{web_port}"
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_tls_proxy(&config, &client_config);

    let (_, api_body) = https_get(&addr, "/api/users", &client_config);
    assert_eq!(api_body, "api-response", "TLS proxy should route /api/ to api backend");

    let (_, web_body) = https_get(&addr, "/index.html", &client_config);
    assert_eq!(web_body, "web-response", "TLS proxy should route / to web backend");
}

#[test]
fn tcp_listener_tls_end_to_end() {
    let certs = TestCertificates::generate();
    let raw_config = certs.raw_tls_client_config();

    let echo_port = start_tcp_echo_backend();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure-tcp
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    upstream: "127.0.0.1:{echo_port}"
    tls:
      cert_path: "{cert}"
      key_path: "{key}"
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    start_full_proxy(config);

    let addr = format!("127.0.0.1:{proxy_port}");
    wait_for_tls(&addr, &raw_config);

    let payload = b"hello from TLS TCP client";
    let response = tls_send_recv(&addr, payload, &raw_config);
    assert_eq!(
        response,
        payload,
        "TCP TLS proxy should echo data bidirectionally, got: {:?}",
        String::from_utf8_lossy(&response)
    );
}

#[test]
fn sni_fallback_to_host_header() {
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();

    let backend_port = start_backend("sni-fallback-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      cert_path: "{cert}"
      key_path: "{key}"
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            upstream_tls: false
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_tls_proxy(&config, &client_config);

    let (status, body) = https_get(&addr, "/", &client_config);
    assert_eq!(
        status, 200,
        "proxy with no upstream_sni should still route via Host header fallback"
    );
    assert_eq!(body, "sni-fallback-ok", "response body should match backend");
}
