// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Protocol and TLS example configuration tests.

use praxis_core::config::{Config, ProtocolKind};
use praxis_tls::ClientCertMode;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn tcp_proxy_protocol_and_upstream() {
    let config = Config::from_yaml(
        r#"
listeners:
  - name: postgres
    address: "127.0.0.1:5432"
    protocol: tcp
    upstream: "127.0.0.1:15432"
"#,
    )
    .unwrap();

    assert_eq!(config.listeners.len(), 1, "should have exactly one listener");
    let listener = &config.listeners[0];
    assert_eq!(listener.name, "postgres", "listener name mismatch");
    assert_eq!(listener.address, "127.0.0.1:5432", "bind address mismatch");
    assert_eq!(listener.protocol, ProtocolKind::Tcp, "protocol should be TCP");
    assert_eq!(
        listener.upstream.as_deref(),
        Some("127.0.0.1:15432"),
        "upstream address mismatch"
    );
    assert!(listener.tls.is_none(), "TCP proxy should have no TLS");
    assert!(
        listener.filter_chains.is_empty(),
        "TCP proxy should have no filter chains"
    );
}

#[test]
fn tls_termination_listener_tls() {
    let tmp = TempCerts::new("tls-term");
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:8443"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: {cert}
          key_path: {key}

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
              - "127.0.0.1:3000"
"#,
        cert = tmp.cert,
        key = tmp.key,
    );
    let config = Config::from_yaml(&yaml).unwrap();

    let listener = &config.listeners[0];
    assert_eq!(listener.name, "default", "listener name mismatch");
    assert_eq!(listener.address, "127.0.0.1:8443", "bind address mismatch");
    assert_eq!(listener.protocol, ProtocolKind::Http, "protocol should default to HTTP");
    let tls = listener.tls.as_ref().expect("TLS should be configured");
    assert_eq!(tls.certificates.len(), 1, "should have exactly one certificate");
    assert_eq!(tls.certificates[0].cert_path, tmp.cert, "cert_path mismatch");
    assert_eq!(tls.certificates[0].key_path, tmp.key, "key_path mismatch");
    assert_eq!(
        tls.client_cert_mode,
        ClientCertMode::None,
        "client_cert_mode should default to None"
    );
    assert!(
        tls.client_ca.is_none(),
        "client_ca should be None for simple termination"
    );
}

#[test]
fn tls_multi_cert_sni_entries() {
    let api = TempCerts::new("multi-api");
    let web = TempCerts::new("multi-web");
    let fallback = TempCerts::new("multi-default");
    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:8443"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: {api_cert}
          key_path: {api_key}
          server_names:
            - api.example.com
        - cert_path: {web_cert}
          key_path: {web_key}
          server_names:
            - web.example.com
            - www.example.com
        - cert_path: {fb_cert}
          key_path: {fb_key}
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
              - "127.0.0.1:3000"
"#,
        api_cert = api.cert,
        api_key = api.key,
        web_cert = web.cert,
        web_key = web.key,
        fb_cert = fallback.cert,
        fb_key = fallback.key,
    );
    let config = Config::from_yaml(&yaml).unwrap();

    let tls = config.listeners[0].tls.as_ref().expect("TLS should be configured");
    assert_eq!(tls.certificates.len(), 3, "should have three certificates");
    assert_eq!(
        tls.certificates[0].server_names,
        vec!["api.example.com"],
        "first cert server_names mismatch"
    );
    assert_eq!(
        tls.certificates[1].server_names,
        vec!["web.example.com", "www.example.com"],
        "second cert server_names mismatch"
    );
    assert!(
        tls.certificates[2].server_names.is_empty(),
        "fallback cert should have no server_names"
    );
    assert!(tls.certificates[2].default, "fallback cert should be marked as default");
}

#[test]
fn tls_mtls_listener_client_ca_and_mode() {
    let tmp = TempCerts::with_ca("mtls-listener");
    let yaml = format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:8443"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: {cert}
          key_path: {key}
      client_ca:
        ca_path: {ca}
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
              - "127.0.0.1:3000"
"#,
        cert = tmp.cert,
        key = tmp.key,
        ca = tmp.ca.as_ref().unwrap(),
    );
    let config = Config::from_yaml(&yaml).unwrap();

    let tls = config.listeners[0].tls.as_ref().expect("TLS should be configured");
    let client_ca = tls.client_ca.as_ref().expect("client_ca should be set");
    assert_eq!(
        client_ca.ca_path,
        tmp.ca.as_ref().unwrap().as_str(),
        "client_ca path mismatch"
    );
    assert_eq!(
        tls.client_cert_mode,
        ClientCertMode::Require,
        "client_cert_mode should be Require"
    );
}

#[test]
fn tls_version_constraint_min_version() {
    let tmp = TempCerts::new("tls-ver");
    let yaml = format!(
        r#"
listeners:
  - name: tls13-only
    address: "127.0.0.1:8443"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: {cert}
          key_path: {key}
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
              - "127.0.0.1:3000"
"#,
        cert = tmp.cert,
        key = tmp.key,
    );
    let config = Config::from_yaml(&yaml).unwrap();

    let listener = &config.listeners[0];
    assert_eq!(listener.name, "tls13-only", "listener name mismatch");
    let tls = listener.tls.as_ref().expect("TLS should be configured");
    assert_eq!(
        tls.min_version,
        Some(praxis_tls::TlsVersion::Tls13),
        "min_version should be Tls13"
    );
}

#[test]
fn mixed_protocol_http_and_tcp_listeners() {
    let config = Config::from_yaml(
        r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains:
      - observability
      - routing

  - name: db
    address: "127.0.0.1:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"

filter_chains:
  - name: observability
    filters:
      - filter: request_id
      - filter: access_log

  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "10.0.0.1:8080"
"#,
    )
    .unwrap();

    assert_eq!(config.listeners.len(), 2, "should have two listeners");

    let http = &config.listeners[0];
    assert_eq!(http.name, "web", "HTTP listener name mismatch");
    assert_eq!(http.protocol, ProtocolKind::Http, "first listener should be HTTP");
    assert_eq!(
        http.filter_chains,
        vec!["observability", "routing"],
        "HTTP listener filter chain references mismatch"
    );
    assert!(http.tls.is_none(), "HTTP listener should have no TLS");
    assert!(http.upstream.is_none(), "HTTP listener should have no upstream");

    let tcp = &config.listeners[1];
    assert_eq!(tcp.name, "db", "TCP listener name mismatch");
    assert_eq!(tcp.protocol, ProtocolKind::Tcp, "second listener should be TCP");
    assert_eq!(
        tcp.upstream.as_deref(),
        Some("10.0.0.1:5432"),
        "TCP upstream address mismatch"
    );
    assert!(
        tcp.filter_chains.is_empty(),
        "TCP listener should have no filter chains"
    );

    assert_eq!(config.filter_chains.len(), 2, "should have two filter chains");
    assert_eq!(
        config.filter_chains[0].name, "observability",
        "first chain name mismatch"
    );
    assert_eq!(config.filter_chains[1].name, "routing", "second chain name mismatch");
}

#[test]
fn tcp_round_robin_config() {
    let config = Config::from_yaml(
        r#"
listeners:
  - name: postgres
    address: "127.0.0.1:5432"
    protocol: tcp
    cluster: db_pool
    filter_chains: [tcp_lb]

clusters:
  - name: db_pool
    endpoints:
      - "127.0.0.1:15432"
      - "127.0.0.1:15433"

filter_chains:
  - name: tcp_lb
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: db_pool
            endpoints:
              - "127.0.0.1:15432"
              - "127.0.0.1:15433"
"#,
    )
    .unwrap();

    let listener = &config.listeners[0];
    assert_eq!(listener.protocol, ProtocolKind::Tcp, "protocol should be TCP");
    assert_eq!(
        listener.cluster.as_deref(),
        Some("db_pool"),
        "cluster should be db_pool"
    );
    assert!(
        listener.upstream.is_none(),
        "upstream should be None for cluster-backed listener"
    );
    assert_eq!(listener.filter_chains, vec!["tcp_lb"], "filter chain mismatch");
}

#[test]
fn tcp_least_connections_config() {
    let config = Config::from_yaml(
        r#"
listeners:
  - name: postgres
    address: "127.0.0.1:5432"
    protocol: tcp
    cluster: db_pool
    filter_chains: [tcp_lb]

clusters:
  - name: db_pool
    endpoints:
      - "127.0.0.1:15432"
      - "127.0.0.1:15433"
      - "127.0.0.1:15434"
    load_balancer_strategy:
      least_connections: ~

filter_chains:
  - name: tcp_lb
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: db_pool
            endpoints:
              - "127.0.0.1:15432"
              - "127.0.0.1:15433"
              - "127.0.0.1:15434"
            load_balancer_strategy:
              least_connections: ~
"#,
    )
    .unwrap();

    assert_eq!(
        config.listeners[0].cluster.as_deref(),
        Some("db_pool"),
        "cluster should be db_pool"
    );
}

#[test]
fn tcp_consistent_hash_config() {
    let config = Config::from_yaml(
        r#"
listeners:
  - name: cache
    address: "127.0.0.1:6379"
    protocol: tcp
    cluster: cache_pool
    filter_chains: [tcp_lb]

clusters:
  - name: cache_pool
    endpoints:
      - "127.0.0.1:16379"
      - "127.0.0.1:16380"
      - "127.0.0.1:16381"
    load_balancer_strategy:
      consistent_hash: {}

filter_chains:
  - name: tcp_lb
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: cache_pool
            endpoints:
              - "127.0.0.1:16379"
              - "127.0.0.1:16380"
              - "127.0.0.1:16381"
            load_balancer_strategy:
              consistent_hash: {}
"#,
    )
    .unwrap();

    assert_eq!(
        config.listeners[0].cluster.as_deref(),
        Some("cache_pool"),
        "cluster should be cache_pool"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Temporary cert and key files that exist on disk for TLS config parsing.
struct TempCerts {
    /// Absolute path to the cert file.
    cert: String,
    /// Absolute path to the key file.
    key: String,
    /// Absolute path to the CA file (when created).
    ca: Option<String>,
    /// Directory path; cleaned up on drop.
    dir: std::path::PathBuf,
}

impl TempCerts {
    /// Create temporary empty cert and key files under a unique subdirectory.
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("praxis-proto-cfg-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, b"").expect("write temp cert");
        std::fs::write(&key, b"").expect("write temp key");
        Self {
            cert: cert.to_str().unwrap().to_owned(),
            key: key.to_str().unwrap().to_owned(),
            ca: None,
            dir,
        }
    }

    /// Create temporary cert, key, and CA files under a unique subdirectory.
    fn with_ca(label: &str) -> Self {
        let mut tmp = Self::new(label);
        let ca = tmp.dir.join("ca.pem");
        std::fs::write(&ca, b"").expect("write temp ca");
        tmp.ca = Some(ca.to_str().unwrap().to_owned());
        tmp
    }
}

impl Drop for TempCerts {
    /// Clean up temporary directory.
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.dir));
    }
}
