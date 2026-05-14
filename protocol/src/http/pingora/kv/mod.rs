// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Admin HTTP endpoints for runtime key-value store CRUD.

use std::sync::Arc;

use async_trait::async_trait;
use http::Response;
use pingora_core::{
    apps::http_app::ServeHttp, protocols::http::ServerSession, server::Server, services::listening::Service,
};
use praxis_core::kv::KvStoreRegistry;
use tracing::{info, warn};

use crate::http::pingora::{health::escape_json_string, json::json_response};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum request body size for KV admin API operations (1 MiB).
///
/// Prevents unbounded memory allocation from oversized PUT requests.
const MAX_BODY_BYTES: usize = 1_048_576; // 1 MiB

// ---------------------------------------------------------------------------
// PingoraKvService
// ---------------------------------------------------------------------------

/// HTTP service for KV store admin endpoints.
///
/// Routes:
/// - `GET /api/kv/{store}`: list all entries in a store
/// - `GET /api/kv/{store}/{key}`: get a value
/// - `PUT /api/kv/{store}/{key}`: set a value (body is the value)
/// - `DELETE /api/kv/{store}/{key}`: delete a key
pub struct PingoraKvService {
    /// Shared KV store registry.
    registry: KvStoreRegistry,
}

impl PingoraKvService {
    /// Create a new KV admin service.
    pub fn new(registry: KvStoreRegistry) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl ServeHttp for PingoraKvService {
    async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
        let path = http_session.req_header().uri.path().to_owned();
        let method = http_session.req_header().method.clone();

        let segments: Vec<&str> = path
            .strip_prefix("/api/kv/")
            .unwrap_or("")
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        match (method.as_str(), segments.as_slice()) {
            ("GET", [store]) => handle_list(&self.registry, store),
            ("GET", [store, key]) => handle_get(&self.registry, store, key),
            ("PUT", [store, key]) => match read_body(http_session).await {
                Ok(body) => handle_set(&self.registry, store, key, &body),
                Err(resp) => resp,
            },
            ("DELETE", [store, key]) => handle_delete(&self.registry, store, key),
            _ => json_response(404, br#"{"error":"not found"}"#),
        }
    }
}

// ---------------------------------------------------------------------------
// Request Body
// ---------------------------------------------------------------------------

/// Read the request body as a UTF-8 string, up to [`MAX_BODY_BYTES`].
///
/// Returns an error response if the body exceeds the limit or is not
/// valid UTF-8.
async fn read_body(session: &mut ServerSession) -> Result<String, Response<Vec<u8>>> {
    let mut buf = Vec::new();
    while let Some(chunk) = session.read_request_body().await.ok().flatten() {
        if buf.len() + chunk.len() > MAX_BODY_BYTES {
            warn!(limit = MAX_BODY_BYTES, "KV admin request body exceeded size limit");
            return Err(json_response(413, br#"{"error":"request body too large"}"#));
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).map_err(|e| {
        warn!(error = %e, "KV admin request body is not valid UTF-8");
        json_response(400, br#"{"error":"request body is not valid UTF-8"}"#)
    })
}

// ---------------------------------------------------------------------------
// Route Handlers
// ---------------------------------------------------------------------------

/// `GET /api/kv/{store}/{key}`: retrieve a single value.
fn handle_get(registry: &KvStoreRegistry, store: &str, key: &str) -> Response<Vec<u8>> {
    let Some(backend) = registry.get(store) else {
        return json_response(404, br#"{"error":"store not found"}"#);
    };
    match backend.get(key) {
        Some(val) => {
            let ek = escape_json_string(key);
            let ev = escape_json_string(&val);
            let body = format!(r#"{{"key":"{ek}","value":"{ev}"}}"#);
            json_response(200, body.as_bytes())
        },
        None => json_response(404, br#"{"error":"key not found"}"#),
    }
}

/// `PUT /api/kv/{store}/{key}`: insert or update a value.
fn handle_set(registry: &KvStoreRegistry, store: &str, key: &str, value: &str) -> Response<Vec<u8>> {
    let Some(backend) = registry.get(store) else {
        return json_response(404, br#"{"error":"store not found"}"#);
    };
    backend.set(key, Arc::from(value));
    json_response(200, br#"{"status":"ok"}"#)
}

/// `DELETE /api/kv/{store}/{key}`: remove a key.
fn handle_delete(registry: &KvStoreRegistry, store: &str, key: &str) -> Response<Vec<u8>> {
    let Some(backend) = registry.get(store) else {
        return json_response(404, br#"{"error":"store not found"}"#);
    };
    if backend.delete(key) {
        json_response(200, br#"{"status":"ok"}"#)
    } else {
        json_response(404, br#"{"error":"key not found"}"#)
    }
}

/// `GET /api/kv/{store}`: list all entries in a store.
fn handle_list(registry: &KvStoreRegistry, store: &str) -> Response<Vec<u8>> {
    let Some(backend) = registry.get(store) else {
        return json_response(404, br#"{"error":"store not found"}"#);
    };

    let entries = backend.entries();
    let pairs: Vec<String> = entries
        .iter()
        .map(|(k, v)| {
            let ek = escape_json_string(k);
            let ev = escape_json_string(v);
            format!(r#""{ek}":"{ev}""#)
        })
        .collect();
    let es = escape_json_string(store);
    let joined = pairs.join(",");
    let body = format!(r#"{{"store":"{es}","entries":{{{joined}}}}}"#);
    json_response(200, body.as_bytes())
}

// ---------------------------------------------------------------------------
// Server Registration
// ---------------------------------------------------------------------------

/// Register KV admin endpoints on the admin listener.
///
/// Binds to the same admin address as health endpoints.
pub fn add_kv_endpoint_to_pingora_server(server: &mut Server, admin_addr: &str, registry: KvStoreRegistry) {
    let mut service = Service::new("kv-admin".to_owned(), PingoraKvService::new(registry));
    service.add_tcp(admin_addr);
    info!(address = %admin_addr, "kv admin endpoints enabled");
    server.add_service(service);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use std::sync::Arc;

    use praxis_core::kv::KvStoreRegistry;

    use super::*;

    #[test]
    fn handle_get_returns_value() {
        let registry = make_registry_with("test", &[("color", "blue")]);
        let resp = handle_get(&registry, "test", "color");
        assert_eq!(resp.status().as_u16(), 200, "should return 200");
        let body = String::from_utf8_lossy(resp.body());
        assert!(
            body.contains(r#""value":"blue""#),
            "body should contain the value: {body}"
        );
    }

    #[test]
    fn handle_get_missing_key_returns_404() {
        let registry = make_registry_with("test", &[]);
        let resp = handle_get(&registry, "test", "missing");
        assert_eq!(resp.status().as_u16(), 404, "missing key should return 404");
    }

    #[test]
    fn handle_get_missing_store_returns_404() {
        let registry = make_empty_registry();
        let resp = handle_get(&registry, "nope", "key");
        assert_eq!(resp.status().as_u16(), 404, "missing store should return 404");
    }

    #[test]
    fn handle_set_creates_key() {
        let registry = make_registry_with("test", &[]);
        let resp = handle_set(&registry, "test", "color", "red");
        assert_eq!(resp.status().as_u16(), 200, "set should return 200");

        let store = registry.get("test").unwrap();
        assert_eq!(
            store.get("color").as_deref(),
            Some("red"),
            "key should be set after PUT"
        );
    }

    #[test]
    fn handle_set_missing_store_returns_404() {
        let registry = make_empty_registry();
        let resp = handle_set(&registry, "nope", "k", "v");
        assert_eq!(resp.status().as_u16(), 404, "missing store should return 404");
    }

    #[test]
    fn handle_delete_existing_key() {
        let registry = make_registry_with("test", &[("temp", "val")]);
        let resp = handle_delete(&registry, "test", "temp");
        assert_eq!(resp.status().as_u16(), 200, "delete should return 200");

        let store = registry.get("test").unwrap();
        assert!(store.get("temp").is_none(), "key should be gone after DELETE");
    }

    #[test]
    fn handle_delete_missing_key_returns_404() {
        let registry = make_registry_with("test", &[]);
        let resp = handle_delete(&registry, "test", "missing");
        assert_eq!(resp.status().as_u16(), 404, "deleting missing key should return 404");
    }

    #[test]
    fn handle_delete_missing_store_returns_404() {
        let registry = make_empty_registry();
        let resp = handle_delete(&registry, "nope", "key");
        assert_eq!(resp.status().as_u16(), 404, "missing store should return 404");
    }

    #[test]
    fn handle_list_returns_entries() {
        let registry = make_registry_with("test", &[("a", "1"), ("b", "2")]);
        let resp = handle_list(&registry, "test");
        assert_eq!(resp.status().as_u16(), 200, "list should return 200");
        let body = String::from_utf8_lossy(resp.body());
        assert!(
            body.contains(r#""store":"test""#),
            "body should contain store name: {body}"
        );
        assert!(
            body.contains(r#""entries":"#),
            "body should contain entries key: {body}"
        );
    }

    #[test]
    fn handle_list_empty_store() {
        let registry = make_registry_with("empty", &[]);
        let resp = handle_list(&registry, "empty");
        assert_eq!(resp.status().as_u16(), 200, "list empty store should return 200");
        let body = String::from_utf8_lossy(resp.body());
        assert!(
            body.contains(r#""entries":{}"#),
            "empty store should have empty entries: {body}"
        );
    }

    #[test]
    fn handle_list_missing_store_returns_404() {
        let registry = make_empty_registry();
        let resp = handle_list(&registry, "nope");
        assert_eq!(resp.status().as_u16(), 404, "missing store should return 404");
    }

    #[test]
    fn handle_get_escapes_json_in_values() {
        let registry = make_registry_with("test", &[("key", r#"val"ue"#)]);
        let resp = handle_get(&registry, "test", "key");
        let body = String::from_utf8_lossy(resp.body());
        assert!(
            body.contains(r#"val\"ue"#),
            "value with quotes should be escaped: {body}"
        );
        let parsed: Result<serde_json::Value, _> = serde_json::from_slice(resp.body());
        assert!(parsed.is_ok(), "response should be valid JSON: {body}");
    }

    #[test]
    fn handle_list_escapes_json_in_keys_and_values() {
        let registry = make_registry_with("test", &[(r#"k"ey"#, r#"v"al"#)]);
        let resp = handle_list(&registry, "test");
        let body = String::from_utf8_lossy(resp.body());
        let parsed: Result<serde_json::Value, _> = serde_json::from_slice(resp.body());
        assert!(parsed.is_ok(), "response should be valid JSON: {body}");
    }

    // -----------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------

    /// Build a registry with a single store pre-populated with pairs.
    fn make_registry_with(name: &str, pairs: &[(&str, &str)]) -> KvStoreRegistry {
        let registry = KvStoreRegistry::new();
        let store = registry.get_or_create(name);
        for (k, v) in pairs {
            store.set(k, Arc::from(*v));
        }
        registry
    }

    /// Build an empty registry.
    fn make_empty_registry() -> KvStoreRegistry {
        KvStoreRegistry::new()
    }
}
