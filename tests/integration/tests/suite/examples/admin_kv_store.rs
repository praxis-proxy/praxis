// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the admin-kv-store example configuration.

use std::{collections::HashMap, sync::Arc};

use praxis_core::{
    config::Config,
    kv::{KvBackend, KvEntry, KvRegistryError, KvStoreRegistry, MatchType, memory::InMemoryKvBackend},
};
use praxis_test_utils::{free_port, http_get, http_put_json, start_full_proxy_with_kv_stores, wait_for_tcp};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn admin_kv_store_config_parses() {
    let (config, _admin_addr) = load_config();
    assert_eq!(config.listeners.len(), 1, "expected one listener");
    assert!(config.admin.address.is_some(), "admin address should be set");
}

#[test]
fn admin_kv_store_serves_registered_backend() {
    let (config, admin_addr) = load_config();
    let kv_stores = KvStoreRegistry::new();
    kv_stores
        .register("routing_overrides", Arc::new(ReadOnlyBackend))
        .expect("first registration should succeed");
    kv_stores
        .register("flags", Arc::new(InMemoryKvBackend::new()))
        .expect("first registration should succeed");

    let _proxy = start_full_proxy_with_kv_stores(&config, &kv_stores);
    wait_for_tcp(&admin_addr);

    let (status, body) = http_get(&admin_addr, "/api/kv/routing_overrides/preferred_cluster", None);
    assert_eq!(status, 200, "registered store should serve its value: {body}");
    assert!(
        body.contains(r#""value":"canary""#),
        "value should come from the registered backend: {body}"
    );

    let (status, body) = http_put_json(&admin_addr, "/api/kv/routing_overrides/preferred_cluster", "stable");
    assert_eq!(
        status, 507,
        "the read-only backend, not a memory store, should handle the write: {body}"
    );

    let (status, body) = http_put_json(&admin_addr, "/api/kv/flags/dark_mode", "true");
    assert_eq!(status, 200, "writable registered store should accept PUT: {body}");
    let (status, body) = http_get(&admin_addr, "/api/kv/flags/dark_mode", None);
    assert_eq!(status, 200, "written key should be readable: {body}");
    assert!(
        body.contains(r#""value":"true""#),
        "GET should return the written value: {body}"
    );

    assert_eq!(
        kv_stores.register("routing_overrides", Arc::new(InMemoryKvBackend::new())),
        Err(KvRegistryError::AlreadyRegistered(Arc::from("routing_overrides"))),
        "a served store must not be replaceable"
    );
    let (status, body) = http_get(&admin_addr, "/api/kv/routing_overrides/preferred_cluster", None);
    assert_eq!(status, 200, "original store should keep serving: {body}");
    assert!(
        body.contains(r#""value":"canary""#),
        "original backend should survive: {body}"
    );
}

#[test]
fn admin_kv_store_never_creates_missing_store() {
    let (config, admin_addr) = load_config();
    let kv_stores = KvStoreRegistry::new();
    kv_stores
        .register("routing_overrides", Arc::new(ReadOnlyBackend))
        .expect("first registration should succeed");

    let _proxy = start_full_proxy_with_kv_stores(&config, &kv_stores);
    wait_for_tcp(&admin_addr);

    let (status, body) = http_put_json(&admin_addr, "/api/kv/routing_overides/preferred_cluster", "stable");
    assert_eq!(status, 404, "PUT to a misspelled store should be 404: {body}");
    let (status, body) = http_get(&admin_addr, "/api/kv/routing_overides", None);
    assert_eq!(status, 404, "misspelled store should still be missing: {body}");

    assert!(
        kv_stores.get("routing_overides").is_none(),
        "the admin API must not create a store"
    );
    assert_eq!(kv_stores.len(), 1, "only the registered store should exist");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Load the example with free ports, returning the config and the admin address.
fn load_config() -> (Config, String) {
    let admin_port = free_port();
    let config = super::load_example_config(
        "operations/admin-kv-store.yaml",
        free_port(),
        HashMap::from([("127.0.0.1:3000", free_port()), ("127.0.0.1:9901", admin_port)]),
    );
    (config, format!("127.0.0.1:{admin_port}"))
}

/// Read-only backend with one fixed entry, standing in for an
/// embedder-supplied store such as Redis. It refuses every write, so a
/// successful PUT would prove a memory store answered instead.
#[derive(Debug)]
struct ReadOnlyBackend;

impl KvBackend for ReadOnlyBackend {
    fn get(&self, key: &str) -> Option<Arc<str>> {
        (key == "preferred_cluster").then(|| Arc::from("canary"))
    }

    fn set(&self, _key: &str, _value: Arc<str>) -> bool {
        false
    }

    fn delete(&self, _key: &str) -> bool {
        false
    }

    fn entries(&self) -> Vec<KvEntry> {
        vec![(Arc::from("preferred_cluster"), Arc::from("canary"))]
    }

    fn lookup(&self, _pattern: &str, _match_type: MatchType) -> Result<Option<KvEntry>, String> {
        Ok(None)
    }

    fn len(&self) -> usize {
        1
    }
}
