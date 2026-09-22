// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! TLS attack-vector tests (weak ciphers, ALPN mismatch).

use std::sync::Arc;

use praxis_core::config::Config;
use praxis_test_utils::{
    TestCertificates, free_port, https_get, start_backend_with_shutdown, start_tls_proxy, tls_connection_rejected,
};
use rustls::ClientConfig;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn weak_cipher_suite_client_rejected() {
    let certs = TestCertificates::generate();
    let backend = start_backend_with_shutdown("cipher-ok");
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
              - "127.0.0.1:{backend}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        backend = backend.port(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let matching_client = certs.client_config();
    let proxy = start_tls_proxy(&config, &matching_client);

    // Sanity: matching TLS 1.3 client works.
    let (status, _) = https_get(proxy.addr(), "/", &matching_client);
    assert_eq!(status, 200, "matching cipher client should succeed");

    // TLS 1.2-only client is rejected when only TLS 1.3 suites are configured.
    let weak_client = build_tls12_only_client(&certs);
    let rejected = tls_connection_rejected(
        proxy.addr(),
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        &weak_client,
    );
    assert!(
        rejected,
        "TLS 1.2-only / weak-suite client must be rejected by cipher restriction"
    );
}

#[test]
fn alpn_mismatch_between_client_and_listener_fails_closed() {
    let certs = TestCertificates::generate();
    let backend = start_backend_with_shutdown("alpn-ok");
    let proxy_port = free_port();

    // Listener does not advertise h2; HTTP/1.1 only.
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
              - "127.0.0.1:{backend}"
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        backend = backend.port(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let ready_client = certs.client_config();
    let proxy = start_tls_proxy(&config, &ready_client);

    // Client that *only* offers h2 must not silently speak the wrong protocol.
    let h2_only = build_h2_only_client(&certs);
    let rejected = tls_connection_rejected(
        proxy.addr(),
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        &h2_only,
    );
    assert!(
        rejected,
        "ALPN mismatch (client h2-only vs HTTP/1.1 listener) must fail closed"
    );
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn build_tls12_only_client(certs: &TestCertificates) -> Arc<ClientConfig> {
    let ca = rustls::pki_types::CertificateDer::from(certs.ca_cert_der.clone());
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca).expect("add CA to root store");

    let versions = vec![&rustls::version::TLS12];
    let mut config = ClientConfig::builder_with_protocol_versions(&versions)
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

fn build_h2_only_client(certs: &TestCertificates) -> Arc<ClientConfig> {
    let ca = rustls::pki_types::CertificateDer::from(certs.ca_cert_der.clone());
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca).expect("add CA to root store");

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}
