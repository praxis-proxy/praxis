// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Listener metadata snapshot for `GET /api/pipelines`.

use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use praxis_core::config::{Config, ProtocolKind};
use serde::Serialize;

// -----------------------------------------------------------------------------
// ListenerMeta
// -----------------------------------------------------------------------------

/// Transport and chain metadata for one configured listener.
#[derive(Clone, Debug, Serialize)]
pub struct ListenerMeta {
    /// Listener name.
    pub name: String,
    /// Bind address.
    pub address: String,
    /// Protocol kind (`http` / `tcp`).
    pub protocol: ProtocolKind,
    /// Whether listener TLS is configured.
    pub tls: bool,
    /// Named filter chains attached to this listener.
    pub chain_names: Vec<String>,
}

/// Hot-swappable listener metadata for the admin pipelines API.
pub type ListenerMetaStore = Arc<ArcSwap<HashMap<String, ListenerMeta>>>;

/// Build listener metadata from configuration.
pub fn listener_meta_from_config(config: &Config) -> HashMap<String, ListenerMeta> {
    config
        .listeners
        .iter()
        .map(|listener| {
            (
                listener.name.clone(),
                ListenerMeta {
                    name: listener.name.clone(),
                    address: listener.address.clone(),
                    protocol: listener.protocol.clone(),
                    tls: listener.tls.is_some(),
                    chain_names: listener.filter_chains.clone(),
                },
            )
        })
        .collect()
}

/// Wrap a metadata map in an [`ArcSwap`] store.
pub fn new_listener_meta_store(meta: HashMap<String, ListenerMeta>) -> ListenerMetaStore {
    Arc::new(ArcSwap::from_pointee(meta))
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    fn sample_config() -> Config {
        Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main, edge]
  - name: plain_tcp
    address: "127.0.0.1:9000"
    protocol: tcp
    filter_chains: [tcp_main]
  - name: secure
    address: "127.0.0.1:8443"
    tls:
      certificates:
        - cert_path: "/tmp/praxis-test.pem"
          key_path: "/tmp/praxis-test-key.pem"
    filter_chains: [main]
filter_chains:
  - name: main
    filters: [{ filter: static_response, status: 200 }]
  - name: edge
    filters: [{ filter: static_response, status: 204 }]
  - name: tcp_main
    filters: []
"#,
        )
        .expect("config should parse")
    }

    #[test]
    fn http_listener_meta_includes_chain_names() {
        let meta = listener_meta_from_config(&sample_config());
        let web = meta.get("web").expect("web listener");
        assert_eq!(web.address, "127.0.0.1:8080", "web address should match config");
        assert_eq!(web.protocol, ProtocolKind::Http, "web should be HTTP");
        assert!(!web.tls, "web listener should not enable TLS");
        assert_eq!(web.chain_names, ["main", "edge"], "web chain_names should match config");
    }

    #[test]
    fn tcp_listener_meta_sets_protocol() {
        let meta = listener_meta_from_config(&sample_config());
        let tcp = meta.get("plain_tcp").expect("tcp listener");
        assert_eq!(tcp.protocol, ProtocolKind::Tcp, "plain_tcp should be TCP");
        assert!(!tcp.tls, "plain_tcp should not enable TLS");
        assert_eq!(tcp.chain_names, ["tcp_main"], "tcp chain_names should match config");
    }

    #[test]
    fn tls_listener_meta_sets_tls_flag() {
        let meta = listener_meta_from_config(&sample_config());
        assert_eq!(meta.len(), 3, "sample config has three listeners");
        let secure = meta.get("secure").expect("tls listener");
        assert!(secure.tls, "secure listener should enable TLS");
        assert_eq!(secure.protocol, ProtocolKind::Http, "secure should be HTTP");
        assert_eq!(secure.chain_names, ["main"], "secure chain_names should match config");
    }
}
