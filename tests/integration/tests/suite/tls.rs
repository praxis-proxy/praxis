// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! TLS integration tests: listener termination, upstream origination,
//! TCP TLS forwarding, mTLS, and SNI behavior.

use std::sync::Arc;

use praxis_core::config::Config;
use praxis_test_utils::{
    TestCertificates, free_port, http_get, https_get, start_backend_with_shutdown, start_full_proxy,
    start_mtls_backend, start_proxy, start_tcp_echo_backend, start_tls_backend, start_tls_proxy,
    start_tls_proxy_no_wait, tls_connection_rejected, tls_send_recv, wait_for_https, wait_for_tls,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn listener_tls_termination_end_to_end() {
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("tls-terminated");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
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
    let proxy = start_tls_proxy(&config, &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(status, 200, "TLS-terminated proxy should return 200");
    assert_eq!(
        body, "tls-terminated",
        "TLS-terminated proxy should forward backend body"
    );

    let peer_der = get_peer_cert_der(proxy.addr(), &client_config, "localhost");
    assert_eq!(
        peer_der, certs.server_cert_der,
        "listener should present the configured server certificate"
    );
}

#[test]
fn tls_listener_routing_works() {
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();

    let api_port_guard = start_backend_with_shutdown("api-response");
    let api_port = api_port_guard.port();
    let web_port_guard = start_backend_with_shutdown("web-response");
    let web_port = web_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
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
    let proxy = start_tls_proxy(&config, &client_config);

    let (_, api_body) = https_get(proxy.addr(), "/api/users", &client_config);
    assert_eq!(api_body, "api-response", "TLS proxy should route /api/ to api backend");

    let (_, web_body) = https_get(proxy.addr(), "/index.html", &client_config);
    assert_eq!(web_body, "web-response", "TLS proxy should route / to web backend");

    let peer_der = get_peer_cert_der(proxy.addr(), &client_config, "localhost");
    assert_eq!(
        peer_der, certs.server_cert_der,
        "listener should present the configured server certificate"
    );
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
      certificates:
        - cert_path: "{cert}"
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

    let backend_port_guard = start_backend_with_shutdown("sni-fallback-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
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
    let proxy = start_tls_proxy(&config, &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(
        status, 200,
        "proxy with no upstream_sni should still route via Host header fallback"
    );
    assert_eq!(body, "sni-fallback-ok", "response body should match backend");
}

#[test]
fn upstream_tls_origination_end_to_end() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "tls-upstream-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
            tls:
              verify: false
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 200,
        "upstream TLS origination should return 200 (status-only: upstream cert not observable from client)"
    );
    assert_eq!(body, "tls-upstream-ok", "response body should come from TLS backend");
}

#[test]
fn both_side_tls_end_to_end() {
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();

    let backend_port = start_tls_backend(&certs, "both-tls-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
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
            tls:
              verify: false
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy(&config, &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(status, 200, "both-side TLS proxy should return 200");
    assert_eq!(body, "both-tls-ok", "both-side TLS should forward backend body");

    let peer_der = get_peer_cert_der(proxy.addr(), &client_config, "localhost");
    assert_eq!(
        peer_der, certs.server_cert_der,
        "listener should present the configured server certificate"
    );
}

#[test]
fn listener_mtls_require_valid_client_cert_succeeds() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert();
    let client_config = certs.client_config_with_cert(&client_cert);

    let backend_port_guard = start_backend_with_shutdown("mtls-require-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
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
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(status, 200, "mTLS require with valid client cert should return 200");
    assert_eq!(body, "mtls-require-ok", "mTLS require should forward backend body");

    let peer_der = get_peer_cert_der(proxy.addr(), &client_config, "localhost");
    assert_eq!(
        peer_der, certs.server_cert_der,
        "mTLS listener should present the configured server certificate"
    );
}

#[test]
fn listener_mtls_require_no_client_cert_fails() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert();
    let mtls_client_config = certs.client_config_with_cert(&client_cert);
    let no_cert_config = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("mtls-no-cert");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
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
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &mtls_client_config);

    let no_cert_ref = &no_cert_config;
    let addr_ref = proxy.addr();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| https_get(addr_ref, "/", no_cert_ref)));

    assert!(
        result.is_err(),
        "mTLS require without client cert should reject the connection"
    );
}

#[test]
fn listener_mtls_request_mode_without_cert_succeeds() {
    let certs = TestCertificates::generate();
    let no_cert_config = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("mtls-request-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: request
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
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy(&config, &no_cert_config);

    let (status, body) = https_get(proxy.addr(), "/", &no_cert_config);
    assert_eq!(status, 200, "mTLS request mode without cert should succeed");
    assert_eq!(body, "mtls-request-ok", "mTLS request mode should forward backend body");

    let peer_der = get_peer_cert_der(proxy.addr(), &no_cert_config, "localhost");
    assert_eq!(
        peer_der, certs.server_cert_der,
        "mTLS request-mode listener should present the configured server certificate"
    );
}

#[test]
fn upstream_mtls_proxy_presents_client_cert() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert();

    let backend_port = start_mtls_backend(&certs, "upstream-mtls-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
            tls:
              verify: false
              client_cert:
                cert_path: "{client_cert}"
                key_path: "{client_key}"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
        client_cert = client_cert.cert_path.display(),
        client_key = client_cert.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 200,
        "upstream mTLS should return 200 (status-only: proxy's client cert not observable from test client)"
    );
    assert_eq!(body, "upstream-mtls-ok", "upstream mTLS should forward backend body");
}

#[test]
fn upstream_tls_verify_disabled_with_self_signed() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "verify-disabled-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
            tls:
              verify: false
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 200,
        "upstream TLS with verify disabled should return 200 (status-only: upstream cert not observable from client)"
    );
    assert_eq!(
        body, "verify-disabled-ok",
        "verify disabled should forward backend body"
    );
}

#[test]
fn upstream_tls_verify_enabled_wrong_cert_returns_502() {
    let proxy_certs = TestCertificates::generate();
    let backend_certs = TestCertificates::generate();

    let backend_port = start_tls_backend(&backend_certs, "should-not-reach");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
insecure_options:
  allow_tls_without_sni: true
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
            tls:
              verify: true
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    );

    drop(proxy_certs);
    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 502, "upstream TLS verify with untrusted cert should return 502");
}

#[test]
fn sni_derived_from_hostname_address() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "sni-hostname-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
            tls:
              sni: "localhost"
              verify: false
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 200,
        "upstream TLS with explicit SNI should return 200 (status-only: SNI sent to upstream not observable)"
    );
    assert_eq!(body, "sni-hostname-ok", "explicit SNI should reach backend");
}

#[test]
fn sni_ip_address_leaves_sni_empty() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "sni-ip-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
            tls:
              verify: false
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 200,
        "upstream TLS with IP address should return 200 (status-only: empty SNI not observable from client)"
    );
    assert_eq!(body, "sni-ip-ok", "IP-based upstream should reach backend");
}

#[test]
fn tcp_listener_mtls_require_valid_client_cert_succeeds() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert();
    let mtls_config = certs.raw_tls_client_config_with_cert(&client_cert);

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
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    start_full_proxy(config);

    let addr = format!("127.0.0.1:{proxy_port}");
    wait_for_tls(&addr, &mtls_config);

    let payload = b"hello from mTLS TCP client";
    let response = tls_send_recv(&addr, payload, &mtls_config);
    assert_eq!(
        response,
        payload,
        "TCP mTLS proxy with valid client cert should echo data, got: {:?}",
        String::from_utf8_lossy(&response)
    );
}

#[test]
fn tcp_listener_mtls_require_no_cert_fails() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert();
    let mtls_config = certs.raw_tls_client_config_with_cert(&client_cert);
    let no_cert_config = certs.raw_tls_client_config();

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
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    start_full_proxy(config);

    let addr = format!("127.0.0.1:{proxy_port}");
    wait_for_tls(&addr, &mtls_config);

    let failed = tls_connection_rejected(&addr, b"should not echo", &no_cert_config);
    assert!(
        failed,
        "TCP mTLS require without client cert should reject the connection"
    );
}

#[test]
fn upstream_tls_verify_with_ca_file() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "ca-file-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
runtime:
  upstream_ca_file: "{ca}"
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
            tls:
              sni: "localhost"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    start_full_proxy(config);

    let addr = format!("127.0.0.1:{proxy_port}");
    praxis_test_utils::wait_for_http(&addr);

    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(
        status, 200,
        "upstream TLS with CA file should return 200 (paired with ca_file_without_ca_fails)"
    );
    assert_eq!(
        body, "ca-file-ok",
        "response body should come from verified TLS backend"
    );
}

#[test]
fn upstream_tls_verify_without_ca_file_fails() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "should-not-reach");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
            tls:
              sni: "localhost"
              verify: true
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 502,
        "upstream TLS verify without CA file should fail with 502 (proves CA file config matters)"
    );
}

#[test]
fn multi_cert_config_parses_and_serves_with_primary_cert() {
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("multi-cert-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
          server_names:
            - localhost
        - cert_path: "{cert}"
          key_path: "{key}"
          server_names:
            - api.example.com
        - cert_path: "{cert}"
          key_path: "{key}"
          default: true
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
    assert_eq!(
        config.listeners[0].tls.as_ref().unwrap().certificates.len(),
        3,
        "config should parse all three certificate entries"
    );
    assert_eq!(
        config.listeners[0].tls.as_ref().unwrap().certificates[0].server_names,
        vec!["localhost"],
        "first cert should have server_names set"
    );
    assert!(
        config.listeners[0].tls.as_ref().unwrap().certificates[2]
            .server_names
            .is_empty(),
        "last cert (default) should have no server_names"
    );
    assert!(
        config.listeners[0].tls.as_ref().unwrap().certificates[2].default,
        "last cert should be marked as default"
    );

    let proxy = start_tls_proxy(&config, &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(
        status, 200,
        "multi-cert proxy should serve traffic via primary certificate"
    );
    assert_eq!(body, "multi-cert-ok", "multi-cert proxy should forward backend body");

    let peer_der = get_peer_cert_der(proxy.addr(), &client_config, "localhost");
    assert_eq!(
        peer_der, certs.server_cert_der,
        "multi-cert listener should present the configured server certificate"
    );
}

#[test]
fn listener_min_version_tls13_rejects_tls12() {
    let certs = TestCertificates::generate();
    let tls13_client = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("tls13-only-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      min_version: tls13
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
    let proxy = start_tls_proxy(&config, &tls13_client);

    let (status, _) = https_get(proxy.addr(), "/", &tls13_client);
    assert_eq!(status, 200, "TLS 1.3 client should succeed against tls13-only listener");

    let tls12_client = build_tls12_only_client(&certs);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        https_get(proxy.addr(), "/", &tls12_client)
    }));
    assert!(
        result.is_err(),
        "TLS 1.2-only client should be rejected by tls13-only listener"
    );
}

#[test]
fn upstream_mtls_missing_client_cert_returns_502() {
    let certs = TestCertificates::generate();

    let backend_port = start_mtls_backend(&certs, "should-not-reach");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
            tls:
              verify: false
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 502,
        "proxy without client cert should get 502 from mTLS backend"
    );
}

#[test]
fn per_cluster_ca_verifies_upstream() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "per-cluster-ca-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
            tls:
              sni: "localhost"
              ca:
                ca_path: "{ca}"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "per-cluster CA should verify upstream and return 200");
    assert_eq!(body, "per-cluster-ca-ok", "per-cluster CA should forward backend body");
}

#[test]
fn per_cluster_ca_without_ca_fails_verification() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "should-not-reach");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
            tls:
              sni: "localhost"
              verify: true
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 502,
        "upstream TLS verify without per-cluster CA should fail with 502 (proves CA config matters)"
    );
}

#[test]
fn multi_cert_sni_selects_correct_certificate() {
    let alpha_certs = TestCertificates::generate_for_san("alpha.localhost");
    let beta_certs = TestCertificates::generate_for_san("beta.localhost");

    let backend_port_guard = start_backend_with_shutdown("sni-select-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{alpha_cert}"
          key_path: "{alpha_key}"
          server_names:
            - alpha.localhost
        - cert_path: "{beta_cert}"
          key_path: "{beta_key}"
          default: true
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
        alpha_cert = alpha_certs.cert_path.display(),
        alpha_key = alpha_certs.key_path.display(),
        beta_cert = beta_certs.cert_path.display(),
        beta_key = beta_certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();

    let dual_trust = dual_ca_client_config(&alpha_certs, &beta_certs);
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_sni_tls(proxy.addr(), &dual_trust, "alpha.localhost");

    let alpha_peer_der = get_peer_cert_der(proxy.addr(), &dual_trust, "alpha.localhost");
    assert_eq!(
        alpha_peer_der, alpha_certs.server_cert_der,
        "SNI alpha.localhost should select the alpha certificate"
    );

    let beta_peer_der = get_peer_cert_der(proxy.addr(), &dual_trust, "beta.localhost");
    assert_eq!(
        beta_peer_der, beta_certs.server_cert_der,
        "SNI beta.localhost (unmatched) should select the default (beta) certificate"
    );

    assert_ne!(
        alpha_certs.server_cert_der, beta_certs.server_cert_der,
        "alpha and beta certificates must be distinct for this test to be valid"
    );
}

#[test]
fn listener_min_version_tls12_accepts_both_versions() {
    let certs = TestCertificates::generate();
    let tls13_client = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("tls12-min-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      min_version: tls12
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
    let proxy = start_tls_proxy(&config, &tls13_client);

    let (status, body) = https_get(proxy.addr(), "/", &tls13_client);
    assert_eq!(status, 200, "TLS 1.3 client should succeed against tls12-min listener");
    assert_eq!(body, "tls12-min-ok", "TLS 1.3 should forward backend body");

    let tls12_client = build_tls12_only_client(&certs);
    let (status12, body12) = https_get(proxy.addr(), "/", &tls12_client);
    assert_eq!(
        status12, 200,
        "TLS 1.2 client should succeed against tls12-min listener"
    );
    assert_eq!(body12, "tls12-min-ok", "TLS 1.2 should forward backend body");

    let peer_der = get_peer_cert_der(proxy.addr(), &tls13_client, "localhost");
    assert_eq!(
        peer_der, certs.server_cert_der,
        "tls12-min listener should present the configured server certificate"
    );
}

#[test]
fn upstream_tls_verify_enabled_with_valid_cert_succeeds() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "verify-valid-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
runtime:
  upstream_ca_file: "{ca}"
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
            tls:
              sni: "localhost"
              verify: true
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).expect("valid YAML config");
    start_full_proxy(config);

    let addr = format!("127.0.0.1:{proxy_port}");
    praxis_test_utils::wait_for_http(&addr);

    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(
        status, 200,
        "upstream TLS verify with valid cert should return 200 (paired with wrong_cert_returns_502)"
    );
    assert_eq!(body, "verify-valid-ok", "verified upstream should forward backend body");
}

#[test]
fn full_mtls_listener_and_upstream_end_to_end() {
    let listener_certs = TestCertificates::generate();
    let upstream_certs = TestCertificates::generate();

    let proxy_client_cert = upstream_certs.generate_client_cert();
    let listener_client_cert = listener_certs.generate_client_cert();
    let client_config = listener_certs.client_config_with_cert(&listener_client_cert);

    let backend_port = start_mtls_backend(&upstream_certs, "full-mtls-ok");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{listener_cert}"
          key_path: "{listener_key}"
      client_ca:
        ca_path: "{listener_ca}"
      client_cert_mode: require
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
            tls:
              verify: false
              client_cert:
                cert_path: "{proxy_client_cert}"
                key_path: "{proxy_client_key}"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
        listener_cert = listener_certs.cert_path.display(),
        listener_key = listener_certs.key_path.display(),
        listener_ca = listener_certs.ca_cert_path.display(),
        proxy_client_cert = proxy_client_cert.cert_path.display(),
        proxy_client_key = proxy_client_cert.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(status, 200, "full mTLS end-to-end should return 200");
    assert_eq!(body, "full-mtls-ok", "full mTLS should forward backend body");

    let peer_der = get_peer_cert_der(proxy.addr(), &client_config, "localhost");
    assert_eq!(
        peer_der, listener_certs.server_cert_der,
        "full mTLS listener should present the listener certificate, not the upstream certificate"
    );
}

#[test]
fn multi_cert_sni_returns_correct_certificate_subject() {
    let alpha_certs = TestCertificates::generate_for_san("alpha.test");
    let beta_certs = TestCertificates::generate_for_san("beta.test");
    let default_certs = TestCertificates::generate_for_san("default.test");

    let backend_port_guard = start_backend_with_shutdown("sni-subject-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{alpha_cert}"
          key_path: "{alpha_key}"
          server_names:
            - alpha.test
        - cert_path: "{beta_cert}"
          key_path: "{beta_key}"
          server_names:
            - beta.test
        - cert_path: "{default_cert}"
          key_path: "{default_key}"
          default: true
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
        alpha_cert = alpha_certs.cert_path.display(),
        alpha_key = alpha_certs.key_path.display(),
        beta_cert = beta_certs.cert_path.display(),
        beta_key = beta_certs.key_path.display(),
        default_cert = default_certs.cert_path.display(),
        default_key = default_certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();

    let triple_trust = triple_ca_client_config(&alpha_certs, &beta_certs, &default_certs);
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_sni_tls(proxy.addr(), &triple_trust, "alpha.test");

    let alpha_peer_der = get_peer_cert_der(proxy.addr(), &triple_trust, "alpha.test");
    assert_eq!(
        alpha_peer_der, alpha_certs.server_cert_der,
        "SNI alpha.test should present the alpha certificate"
    );

    let beta_peer_der = get_peer_cert_der(proxy.addr(), &triple_trust, "beta.test");
    assert_eq!(
        beta_peer_der, beta_certs.server_cert_der,
        "SNI beta.test should present the beta certificate"
    );

    let fallback_peer_der = get_peer_cert_der(proxy.addr(), &triple_trust, "default.test");
    assert_eq!(
        fallback_peer_der, default_certs.server_cert_der,
        "fallback SNI should present the default certificate"
    );

    assert_ne!(
        alpha_certs.server_cert_der, beta_certs.server_cert_der,
        "alpha and beta certificates must be distinct"
    );
    assert_ne!(
        beta_certs.server_cert_der, default_certs.server_cert_der,
        "beta and default certificates must be distinct"
    );
}

#[test]
fn multi_cert_unknown_sni_returns_default_certificate() {
    let alpha_certs = TestCertificates::generate_for_san("alpha.test");
    let default_certs = TestCertificates::generate_for_san("default.test");

    let backend_port_guard = start_backend_with_shutdown("fallback-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{alpha_cert}"
          key_path: "{alpha_key}"
          server_names:
            - alpha.test
        - cert_path: "{default_cert}"
          key_path: "{default_key}"
          default: true
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
        alpha_cert = alpha_certs.cert_path.display(),
        alpha_key = alpha_certs.key_path.display(),
        default_cert = default_certs.cert_path.display(),
        default_key = default_certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();

    let no_verify_trust = no_hostname_verify_client_config(&[&alpha_certs.ca_cert_der, &default_certs.ca_cert_der]);
    let alpha_trust = dual_ca_client_config(&alpha_certs, &default_certs);
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_sni_tls(proxy.addr(), &alpha_trust, "alpha.test");

    let alpha_der = get_peer_cert_der(proxy.addr(), &alpha_trust, "alpha.test");
    assert_eq!(
        alpha_der, alpha_certs.server_cert_der,
        "SNI alpha.test should present the alpha certificate"
    );

    let unknown_der = get_peer_cert_der(proxy.addr(), &no_verify_trust, "unknown.test");
    assert_eq!(
        unknown_der, default_certs.server_cert_der,
        "unknown SNI should fall back to the default certificate"
    );

    assert_ne!(
        alpha_certs.server_cert_der, default_certs.server_cert_der,
        "alpha and default certificates must be distinct"
    );
}

#[test]
fn mtls_require_rejects_client_cert_from_wrong_ca() {
    let server_certs = TestCertificates::generate();
    let wrong_ca_certs = TestCertificates::generate();

    let wrong_client_cert = wrong_ca_certs.generate_client_cert();

    let valid_client_cert = server_certs.generate_client_cert();
    let valid_client_config = server_certs.client_config_with_cert(&valid_client_cert);

    let wrong_ca_client_config = build_cross_ca_client_config(&server_certs, &wrong_ca_certs, &wrong_client_cert);

    let backend_port_guard = start_backend_with_shutdown("wrong-ca-should-not-reach");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
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
        cert = server_certs.cert_path.display(),
        key = server_certs.key_path.display(),
        ca = server_certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &valid_client_config);

    let wrong_ref = &wrong_ca_client_config;
    let addr_ref = proxy.addr();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| https_get(addr_ref, "/", wrong_ref)));
    assert!(
        result.is_err(),
        "mTLS require should reject client cert signed by wrong CA"
    );
}

#[test]
fn multi_cert_sni_with_mtls_require() {
    let alpha_certs = TestCertificates::generate_for_san("alpha.mtls");
    let beta_certs = TestCertificates::generate_for_san("beta.mtls");

    let client_cert = alpha_certs.generate_client_cert();
    let client_config = build_sni_mtls_client_config(&alpha_certs, &beta_certs, &client_cert);

    let backend_port_guard = start_backend_with_shutdown("sni-mtls-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{alpha_cert}"
          key_path: "{alpha_key}"
          server_names:
            - alpha.mtls
        - cert_path: "{beta_cert}"
          key_path: "{beta_key}"
          default: true
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
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
        alpha_cert = alpha_certs.cert_path.display(),
        alpha_key = alpha_certs.key_path.display(),
        beta_cert = beta_certs.cert_path.display(),
        beta_key = beta_certs.key_path.display(),
        ca = alpha_certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_sni_tls(proxy.addr(), &client_config, "alpha.mtls");

    let alpha_peer_der = get_peer_cert_der(proxy.addr(), &client_config, "alpha.mtls");
    assert_eq!(
        alpha_peer_der, alpha_certs.server_cert_der,
        "SNI alpha.mtls should present the alpha cert even with mTLS"
    );
}

#[test]
fn multi_cert_sni_with_tls13_only() {
    let alpha_certs = TestCertificates::generate_for_san("alpha.tls13");
    let beta_certs = TestCertificates::generate_for_san("beta.tls13");

    let backend_port_guard = start_backend_with_shutdown("sni-tls13-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{alpha_cert}"
          key_path: "{alpha_key}"
          server_names:
            - alpha.tls13
        - cert_path: "{beta_cert}"
          key_path: "{beta_key}"
          default: true
      min_version: tls13
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
        alpha_cert = alpha_certs.cert_path.display(),
        alpha_key = alpha_certs.key_path.display(),
        beta_cert = beta_certs.cert_path.display(),
        beta_key = beta_certs.key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();

    let dual_trust = dual_ca_client_config(&alpha_certs, &beta_certs);
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_sni_tls(proxy.addr(), &dual_trust, "alpha.tls13");

    let alpha_peer_der = get_peer_cert_der(proxy.addr(), &dual_trust, "alpha.tls13");
    assert_eq!(
        alpha_peer_der, alpha_certs.server_cert_der,
        "SNI alpha.tls13 over TLS 1.3 should present the alpha cert"
    );

    let beta_peer_der = get_peer_cert_der(proxy.addr(), &dual_trust, "beta.tls13");
    assert_eq!(
        beta_peer_der, beta_certs.server_cert_der,
        "SNI beta.tls13 (unmatched) over TLS 1.3 should present the default cert"
    );
}

#[test]
fn mtls_require_with_tls13_only() {
    let certs = TestCertificates::generate();
    let client_cert = certs.generate_client_cert();
    let client_config = certs.client_config_with_cert(&client_cert);

    let backend_port_guard = start_backend_with_shutdown("mtls-tls13-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
      min_version: tls13
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
        ca = certs.ca_cert_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(status, 200, "mTLS require with TLS 1.3 should return 200");
    assert_eq!(body, "mtls-tls13-ok", "mTLS + TLS 1.3 should forward backend body");

    let peer_der = get_peer_cert_der(proxy.addr(), &client_config, "localhost");
    assert_eq!(
        peer_der, certs.server_cert_der,
        "mTLS + TLS 1.3 listener should present the configured server certificate"
    );
}

#[cfg(any(not(target_os = "macos"), feature = "no-mac-cert-rotation-tests"))]
#[test]
fn hot_reload_serves_rotated_certificate() {
    let original = TestCertificates::generate();
    let client_config = original.client_config();

    let backend_port_guard = start_backend_with_shutdown("hot-reload-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let cert_dir = tempfile::TempDir::new().unwrap();
    let cert_path = cert_dir.path().join("server.pem");
    let key_path = cert_dir.path().join("server-key.pem");
    std::fs::copy(&original.cert_path, &cert_path).unwrap();
    std::fs::copy(&original.key_path, &key_path).unwrap();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      hot_reload: true
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
        cert = cert_path.display(),
        key = key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    start_full_proxy(config);

    let addr = format!("127.0.0.1:{proxy_port}");
    wait_for_https(&addr, &client_config);

    let initial_der = get_peer_cert_der(&addr, &client_config, "localhost");
    assert_eq!(
        initial_der, original.server_cert_der,
        "initial cert should match the original"
    );

    let rotated = TestCertificates::generate();
    let rotated_key_pem = std::fs::read(&rotated.key_path).unwrap();
    let rotated_cert_pem = std::fs::read(&rotated.cert_path).unwrap();
    std::fs::write(&key_path, &rotated_key_pem).unwrap();
    std::fs::write(&cert_path, &rotated_cert_pem).unwrap();

    std::thread::sleep(std::time::Duration::from_secs(3));

    let rotated_client = rotated.client_config();
    let rotated_der = get_peer_cert_der(&addr, &rotated_client, "localhost");
    assert_eq!(
        rotated_der, rotated.server_cert_der,
        "after rotation the proxy should serve the new certificate"
    );

    assert_ne!(
        original.server_cert_der, rotated.server_cert_der,
        "original and rotated certs must be distinct for this test to be valid"
    );
}

#[test]
fn hot_reload_invalid_cert_keeps_old() {
    let original = TestCertificates::generate();
    let client_config = original.client_config();

    let backend_port_guard = start_backend_with_shutdown("hot-reload-invalid-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let cert_dir = tempfile::TempDir::new().unwrap();
    let cert_path = cert_dir.path().join("server.pem");
    let key_path = cert_dir.path().join("server-key.pem");
    std::fs::copy(&original.cert_path, &cert_path).unwrap();
    std::fs::copy(&original.key_path, &key_path).unwrap();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      hot_reload: true
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
        cert = cert_path.display(),
        key = key_path.display(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    start_full_proxy(config);

    let addr = format!("127.0.0.1:{proxy_port}");
    wait_for_https(&addr, &client_config);

    let initial_der = get_peer_cert_der(&addr, &client_config, "localhost");
    assert_eq!(
        initial_der, original.server_cert_der,
        "initial cert should match the original"
    );

    std::fs::write(&cert_path, b"not a valid cert").unwrap();
    std::fs::write(&key_path, b"not a valid key").unwrap();

    std::thread::sleep(std::time::Duration::from_secs(2));

    let after_der = get_peer_cert_der(&addr, &client_config, "localhost");
    assert_eq!(
        after_der, original.server_cert_der,
        "after invalid rotation the proxy should still serve the original certificate"
    );

    let (status, body) = https_get(&addr, "/", &client_config);
    assert_eq!(
        status, 200,
        "proxy should still serve traffic after invalid cert rotation"
    );
    assert_eq!(body, "hot-reload-invalid-ok", "response body should match backend");
}

#[test]
fn listener_cipher_suite_restriction_accepts_matching_client() {
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("cipher-suite-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      cipher_suites:
        - tls13_aes_256_gcm_sha384
        - tls13_aes_128_gcm_sha256
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
    let proxy = start_tls_proxy(&config, &client_config);

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(
        status, 200,
        "cipher-suite-restricted proxy should accept TLS 1.3 client"
    );
    assert_eq!(
        body, "cipher-suite-ok",
        "cipher-suite-restricted proxy should forward backend body"
    );
}

#[test]
fn listener_cipher_suite_restriction_rejects_excluded_suite() {
    let certs = TestCertificates::generate();
    let client_config = certs.client_config();

    let backend_port_guard = start_backend_with_shutdown("cipher-rejected");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      cipher_suites:
        - tls13_aes_256_gcm_sha384
        - tls13_aes_128_gcm_sha256
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
    let proxy = start_tls_proxy(&config, &client_config);

    let tls12_only = build_tls12_only_client(&certs);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        https_get(proxy.addr(), "/", &tls12_only)
    }));
    assert!(
        result.is_err(),
        "TLS 1.2-only client should be rejected when only TLS 1.3 suites are configured"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn build_tls12_only_client(certs: &TestCertificates) -> Arc<rustls::ClientConfig> {
    let ca = rustls::pki_types::CertificateDer::from(certs.ca_cert_der.clone());
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca).expect("add CA to root store");

    let versions = vec![&rustls::version::TLS12];
    let mut config = rustls::ClientConfig::builder_with_protocol_versions(&versions)
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    Arc::new(config)
}

fn dual_ca_client_config(a: &TestCertificates, b: &TestCertificates) -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(rustls::pki_types::CertificateDer::from(a.ca_cert_der.clone()))
        .expect("add CA A to root store");
    root_store
        .add(rustls::pki_types::CertificateDer::from(b.ca_cert_der.clone()))
        .expect("add CA B to root store");

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    Arc::new(config)
}

fn get_peer_cert_der(addr: &str, client_config: &Arc<rustls::ClientConfig>, sni: &str) -> Vec<u8> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
        let server_name = rustls::pki_types::ServerName::try_from(sni.to_owned()).expect("valid SNI");
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("TCP connect");
        let tls = connector.connect(server_name, tcp).await.expect("TLS handshake");
        let (_, conn) = tls.get_ref();
        let certs = conn.peer_certificates().expect("peer certificates present");
        certs[0].as_ref().to_vec()
    })
}

fn wait_for_sni_tls(addr: &str, client_config: &Arc<rustls::ClientConfig>, sni: &str) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    for _ in 0..500 {
        let result = rt.block_on(async {
            let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
            let server_name = rustls::pki_types::ServerName::try_from(sni.to_owned()).ok()?;
            let tcp = tokio::net::TcpStream::connect(addr).await.ok()?;
            connector.connect(server_name, tcp).await.ok().map(|_| ())
        });
        if result.is_some() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("TLS server at {addr} with SNI {sni} did not become ready within 5s");
}

fn triple_ca_client_config(
    a: &TestCertificates,
    b: &TestCertificates,
    c: &TestCertificates,
) -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(rustls::pki_types::CertificateDer::from(a.ca_cert_der.clone()))
        .expect("add CA A to root store");
    root_store
        .add(rustls::pki_types::CertificateDer::from(b.ca_cert_der.clone()))
        .expect("add CA B to root store");
    root_store
        .add(rustls::pki_types::CertificateDer::from(c.ca_cert_der.clone()))
        .expect("add CA C to root store");

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    Arc::new(config)
}

fn build_cross_ca_client_config(
    server_certs: &TestCertificates,
    wrong_ca_certs: &TestCertificates,
    wrong_client_cert: &praxis_test_utils::ClientCert,
) -> Arc<rustls::ClientConfig> {
    let ca = rustls::pki_types::CertificateDer::from(server_certs.ca_cert_der.clone());
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca).expect("add server CA to root store");

    let cert_pem = std::fs::read(&wrong_client_cert.cert_path).expect("read wrong client cert PEM");
    let key_pem = std::fs::read(&wrong_client_cert.key_path).expect("read wrong client key PEM");

    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .expect("parse wrong client cert PEM");
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .expect("parse wrong client key PEM")
        .expect("no wrong client private key found");

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .expect("build cross-CA client config");
    config.alpn_protocols = vec![b"h2".to_vec()];

    let _ = wrong_ca_certs;
    Arc::new(config)
}

fn build_sni_mtls_client_config(
    a: &TestCertificates,
    b: &TestCertificates,
    client_cert: &praxis_test_utils::ClientCert,
) -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(rustls::pki_types::CertificateDer::from(a.ca_cert_der.clone()))
        .expect("add CA A to root store");
    root_store
        .add(rustls::pki_types::CertificateDer::from(b.ca_cert_der.clone()))
        .expect("add CA B to root store");

    let cert_pem = std::fs::read(&client_cert.cert_path).expect("read client cert PEM");
    let key_pem = std::fs::read(&client_cert.key_path).expect("read client key PEM");

    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .expect("parse client cert PEM");
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .expect("parse client key PEM")
        .expect("no client private key found");

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .expect("build SNI mTLS client config");
    config.alpn_protocols = vec![b"h2".to_vec()];

    Arc::new(config)
}

/// Build a client config that trusts the given CAs but does NOT
/// verify the server hostname. Used to test SNI fallback behavior
/// where the presented cert's subject won't match the SNI sent.
fn no_hostname_verify_client_config(ca_ders: &[&Vec<u8>]) -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    for der in ca_ders {
        root_store
            .add(rustls::pki_types::CertificateDer::from((*der).clone()))
            .expect("add CA to root store");
    }

    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .expect("build WebPki verifier");

    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoHostnameVerifier(verifier)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    Arc::new(config)
}

/// Wrapper that validates the certificate chain against trusted CAs
/// but accepts any hostname. Only for testing SNI fallback.
#[derive(Debug)]
struct NoHostnameVerifier(Arc<dyn rustls::client::danger::ServerCertVerifier>);

impl rustls::client::danger::ServerCertVerifier for NoHostnameVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}
