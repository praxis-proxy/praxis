// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for embedder-registered KV stores served by `/api/kv/*`.

use std::sync::Arc;

use praxis_core::{
    config::Config,
    kv::{KvBackend, KvEntry, KvLookup, KvStoreRegistry, MatchType, memory::InMemoryKvBackend},
};
use praxis_test_utils::{
    ProxyGuard, free_port, http_get, http_put_json, start_backend, start_full_proxy_with_kv_stores, wait_for_tcp,
};

/// Read-only backend with one fixed entry, standing in for an embedder's
/// external store.
#[derive(Debug)]
struct FixedBackend;

impl KvBackend for FixedBackend {
    fn get(&self, key: &str) -> Option<Arc<str>> {
        (key == "color").then(|| Arc::from("from-custom-backend"))
    }

    fn set(&self, _key: &str, _value: Arc<str>) -> bool {
        false
    }

    fn delete(&self, _key: &str) -> bool {
        false
    }

    fn entries(&self) -> Vec<KvEntry> {
        vec![(Arc::from("color"), Arc::from("from-custom-backend"))]
    }

    fn lookup(&self, _pattern: &str, _match_type: MatchType) -> Result<Option<KvEntry>, String> {
        Ok(None)
    }

    fn len(&self) -> usize {
        1
    }
}

/// One listener plus the admin API on `admin_port`.
fn kv_config_yaml(proxy_port: u16, admin_port: u16, backend_port: u16) -> String {
    format!(
        r#"
insecure_options:
  allow_private_endpoints: true

admin:
  address: "127.0.0.1:{admin_port}"

listeners:
  - name: web
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]

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
    )
}

/// Start a full proxy sharing `kv_stores`; returns the admin address and guard.
fn start_with(kv_stores: &KvStoreRegistry) -> (String, ProxyGuard) {
    let backend_port = start_backend("kv-admin");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = Config::from_yaml(&kv_config_yaml(proxy_port, admin_port, backend_port)).expect("config should parse");
    let proxy = start_full_proxy_with_kv_stores(&config, kv_stores);
    let admin_addr = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin_addr);
    (admin_addr, proxy)
}

#[test]
fn admin_api_serves_registered_backend() {
    let kv_stores = KvStoreRegistry::new();
    kv_stores.register("flags", Arc::new(FixedBackend)).unwrap();
    let (admin_addr, _proxy) = start_with(&kv_stores);

    let (status, body) = http_get(&admin_addr, "/api/kv/flags/color", None);
    assert_eq!(status, 200, "registered store must be served: {body}");
    assert!(
        body.contains(r#""value":"from-custom-backend""#),
        "value must come from the registered backend, not a memory store: {body}"
    );

    // A memory store would accept this; FixedBackend refuses, so the write
    // provably reached the registered backend.
    let (status, body) = http_put_json(&admin_addr, "/api/kv/flags/color", "red");
    assert_eq!(status, 507, "writes must reach the registered backend: {body}");
}

#[test]
fn admin_api_never_creates_unknown_store() {
    let kv_stores = KvStoreRegistry::new();
    kv_stores
        .register("routing_overrides", Arc::new(InMemoryKvBackend::new()))
        .unwrap();
    let (admin_addr, _proxy) = start_with(&kv_stores);

    let (status, body) = http_put_json(&admin_addr, "/api/kv/routing_overides/k", "v");
    assert_eq!(status, 404, "PUT to a misspelled store must 404: {body}");
    let (status, _) = http_get(&admin_addr, "/api/kv/routing_overides", None);
    assert_eq!(status, 404, "the misspelled store must still be missing");
    assert!(
        kv_stores.get("routing_overides").is_none(),
        "admin requests must never add a store"
    );
    assert_eq!(kv_stores.len(), 1, "registry must be unchanged");
}

#[test]
fn store_registered_after_startup_is_served() {
    let kv_stores = KvStoreRegistry::new();
    let (admin_addr, _proxy) = start_with(&kv_stores);

    let (status, _) = http_get(&admin_addr, "/api/kv/late", None);
    assert_eq!(status, 404, "store must not exist before registration");

    kv_stores.register("late", Arc::new(InMemoryKvBackend::new())).unwrap();
    let (status, body) = http_put_json(&admin_addr, "/api/kv/late/k", "v");
    assert_eq!(
        status, 200,
        "a store registered after startup must accept writes: {body}"
    );
    assert_eq!(
        kv_stores.lookup("late", "k"),
        KvLookup::Value(Arc::from("v")),
        "the write must land in the embedder's registry"
    );
}
