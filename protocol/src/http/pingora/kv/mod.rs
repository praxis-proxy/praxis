// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

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

/// Dispatch a KV admin request and return the response.
///
/// Routes `GET`, `PUT`, and `DELETE` under `/api/kv/{store}[/{key}]`.
/// Returns a 404 JSON response for unrecognised paths or methods.
///
/// Used by [`PingoraAdminService`] to handle KV requests on the shared
/// admin port, and by [`PingoraKvService`] for backward compatibility.
///
/// [`PingoraAdminService`]: crate::http::pingora::health::PingoraAdminService
/// [`PingoraKvService`]: PingoraKvService
pub(crate) async fn dispatch_kv_request(registry: &KvStoreRegistry, session: &mut ServerSession) -> Response<Vec<u8>> {
    let path = session.req_header().uri.path().to_owned();
    let method = session.req_header().method.clone();

    match resolve_kv_route(method.as_str(), &path) {
        KvRoute::List(store) => handle_list(registry, &store),
        KvRoute::Get(store, key) => handle_get(registry, &store, &key),
        KvRoute::Set(store, key) => match read_body(session).await {
            Ok(body) => handle_set(registry, &store, &key, &body),
            Err(resp) => resp,
        },
        KvRoute::Delete(store, key) => handle_delete(registry, &store, &key),
        KvRoute::NotFound => json_response(404, br#"{"error":"not found"}"#),
    }
}

/// Resolved KV API route from method + path.
#[derive(Debug, PartialEq, Eq)]
enum KvRoute {
    /// `GET /api/kv/{store}`
    List(String),
    /// `GET /api/kv/{store}/{key}`
    Get(String, String),
    /// `PUT /api/kv/{store}/{key}`
    Set(String, String),
    /// `DELETE /api/kv/{store}/{key}`
    Delete(String, String),
    /// Unrecognised method or path.
    NotFound,
}

/// Parse a KV admin route from method and path.
fn resolve_kv_route(method: &str, path: &str) -> KvRoute {
    let segments: Vec<&str> = path
        .strip_prefix("/api/kv/")
        .unwrap_or("")
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    match (method, segments.as_slice()) {
        ("GET", [store]) => KvRoute::List((*store).to_owned()),
        ("GET", [store, key]) => KvRoute::Get((*store).to_owned(), (*key).to_owned()),
        ("PUT", [store, key]) => KvRoute::Set((*store).to_owned(), (*key).to_owned()),
        ("DELETE", [store, key]) => KvRoute::Delete((*store).to_owned(), (*key).to_owned()),
        _ => KvRoute::NotFound,
    }
}

#[async_trait]
impl ServeHttp for PingoraKvService {
    async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
        dispatch_kv_request(&self.registry, http_session).await
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
    loop {
        match session.read_request_body().await {
            Ok(Some(chunk)) => {
                if buf.len() + chunk.len() > MAX_BODY_BYTES {
                    warn!(limit = MAX_BODY_BYTES, "KV admin request body exceeded size limit");
                    return Err(json_response(413, br#"{"error":"request body too large"}"#));
                }
                buf.extend_from_slice(&chunk);
            },
            Ok(None) => break,
            Err(e) => {
                warn!(error = %e, "KV admin request body read failed");
                return Err(json_response(502, br#"{"error":"request body read failed"}"#));
            },
        }
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
    if backend.set(key, Arc::from(value)) {
        json_response(200, br#"{"status":"ok"}"#)
    } else {
        json_response(507, br#"{"error":"store capacity reached"}"#)
    }
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
///
/// # Deprecation
///
/// Prefer passing `kv_registry` to [`add_admin_endpoints_to_pingora_server`]
/// instead. This function creates a separate Pingora `Service` that
/// binds to the same port via `SO_REUSEPORT`, causing non-deterministic
/// connection routing that breaks health probes.
///
/// [`add_admin_endpoints_to_pingora_server`]: crate::http::pingora::health::add_admin_endpoints_to_pingora_server
#[deprecated(note = "pass KvStoreRegistry to add_admin_endpoints_to_pingora_server instead")]
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
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
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
    fn route_get_single_segment_is_list() {
        assert_eq!(
            resolve_kv_route("GET", "/api/kv/mystore"),
            KvRoute::List("mystore".to_owned()),
            "GET with one segment should route to List"
        );
    }

    #[test]
    fn route_get_two_segments_is_get() {
        assert_eq!(
            resolve_kv_route("GET", "/api/kv/mystore/mykey"),
            KvRoute::Get("mystore".to_owned(), "mykey".to_owned()),
            "GET with two segments should route to Get"
        );
    }

    #[test]
    fn route_put_two_segments_is_set() {
        assert_eq!(
            resolve_kv_route("PUT", "/api/kv/mystore/mykey"),
            KvRoute::Set("mystore".to_owned(), "mykey".to_owned()),
            "PUT with two segments should route to Set"
        );
    }

    #[test]
    fn route_delete_two_segments_is_delete() {
        assert_eq!(
            resolve_kv_route("DELETE", "/api/kv/mystore/mykey"),
            KvRoute::Delete("mystore".to_owned(), "mykey".to_owned()),
            "DELETE with two segments should route to Delete"
        );
    }

    #[test]
    fn route_unknown_method_is_not_found() {
        assert_eq!(
            resolve_kv_route("PATCH", "/api/kv/mystore/mykey"),
            KvRoute::NotFound,
            "PATCH should route to NotFound"
        );
    }

    #[test]
    fn route_extra_segments_is_not_found() {
        assert_eq!(
            resolve_kv_route("GET", "/api/kv/store/key/extra"),
            KvRoute::NotFound,
            "extra path segments should route to NotFound"
        );
    }

    #[test]
    fn route_no_segments_is_not_found() {
        assert_eq!(
            resolve_kv_route("GET", "/api/kv/"),
            KvRoute::NotFound,
            "bare /api/kv/ should route to NotFound"
        );
    }

    #[test]
    fn route_wrong_prefix_is_not_found() {
        assert_eq!(
            resolve_kv_route("GET", "/api/other/store"),
            KvRoute::NotFound,
            "wrong path prefix should route to NotFound"
        );
    }

    #[test]
    fn route_trailing_slash_ignored() {
        assert_eq!(
            resolve_kv_route("GET", "/api/kv/store/"),
            KvRoute::List("store".to_owned()),
            "trailing slash should be filtered and match List"
        );
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
