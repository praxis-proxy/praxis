// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Transport-agnostic HTTP request/response metadata and per-request filter context.

use std::{any::Any, borrow::Cow, collections::HashMap, net::IpAddr, sync::Arc, time::Instant};

use http::{HeaderMap, Method, StatusCode, Uri};
use praxis_core::{
    connectivity::Upstream, health::HealthRegistry, id::IdGenerator, kv::KvStoreRegistry, time::TimeSource,
};

use crate::{body::BodyMode, extensions::RequestExtensions, pipeline::body::merge_body_mode, results::FilterResultSet};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum entries allowed in the general `filter_metadata` map.
///
/// Individual keys and values are already size-bounded (64 / 256
/// bytes), but without an entry count cap a filter chain could
/// insert thousands of unique keys per request.
const MAX_METADATA_ENTRIES: usize = 128;

// -----------------------------------------------------------------------------
// HttpFilterContext
// -----------------------------------------------------------------------------

/// Per-request mutable state shared across all HTTP filters.
///
/// Created by the protocol layer for each incoming request. Filters read
/// and mutate it to select clusters, choose upstreams, and inject headers.
pub struct HttpFilterContext<'a> {
    /// Per-filter body-done tracking. When `true` at index `i`,
    /// filter `i` is skipped for remaining body chunks.
    pub body_done_indices: Vec<bool>,

    /// Iteration counters for re-entrant branches.
    /// Branch name -> current iteration count.
    pub branch_iterations: HashMap<Arc<str>, u32>,

    /// Downstream client IP address (from the TCP connection).
    pub client_addr: Option<IpAddr>,

    /// The cluster name selected by the router filter.
    pub cluster: Option<Arc<str>>,

    /// Stable invocation ID of the filter currently executing.
    ///
    /// Assigned at pipeline build time and unique within the
    /// request's pinned [`FilterPipeline`]. Set by the pipeline
    /// executor before each filter hook call and cleared after.
    /// Filter state accessors use this as the storage key so
    /// that multiple instances of the same filter type — including
    /// filters in branch chains — get independent state.
    ///
    /// [`FilterPipeline`]: crate::FilterPipeline
    pub current_filter_id: Option<usize>,

    /// Whether the downstream connection uses TLS.
    ///
    /// Set by the protocol layer from the connection's SSL
    /// digest. Used by the forwarded headers filter to derive
    /// `X-Forwarded-Proto` from the actual connection state
    /// rather than the request URI scheme (which is absent
    /// in HTTP/1.1).
    pub downstream_tls: bool,

    /// Type-safe request-scoped extension container.
    ///
    /// Filters store and retrieve arbitrary typed values that
    /// persist across all Pingora lifecycle phases (request,
    /// request body, response, response body, logging). Keyed
    /// by [`TypeId`], so only one value per concrete type. Use
    /// private newtypes to avoid collisions between independent
    /// filters.
    ///
    /// [`TypeId`]: std::any::TypeId
    pub extensions: RequestExtensions,

    /// Tracks which pipeline filter indices actually executed
    /// during the request phase. The response phase skips
    /// filters that did not run (e.g. due to `SkipTo`).
    pub executed_filter_indices: Vec<bool>,

    /// Extra headers to inject into the upstream request.
    pub extra_request_headers: Vec<(Cow<'static, str>, String)>,

    /// Headers to remove from the upstream request.
    pub request_headers_to_remove: Vec<http::header::HeaderName>,

    /// Headers to set (overwrite) on the upstream request.
    pub request_headers_to_set: Vec<(http::header::HeaderName, http::header::HeaderValue)>,

    /// Durable per-request metadata that persists across all
    /// Pingora lifecycle phases (request, request-body, response,
    /// response-body, logging). Unlike [`filter_results`] which
    /// are cleared after branch evaluation, metadata survives
    /// for the entire request lifetime.
    ///
    /// Keys use dot-prefix namespacing by convention
    /// (e.g. `json_rpc.kind`, `classifier.label`).
    ///
    /// [`filter_results`]: Self::filter_results
    pub filter_metadata: HashMap<String, String>,

    /// Filter result map: `filter_name` -> result entries.
    ///
    /// Filters write string key-value pairs here during
    /// `on_request` or `on_response`. The pipeline executor
    /// reads these to evaluate branch conditions. Cleared
    /// after branch evaluation at each filter.
    pub filter_results: HashMap<&'static str, FilterResultSet>,

    /// Typed per-filter state that persists across all lifecycle
    /// phases (request, request-body, response, response-body).
    ///
    /// Keyed by stable filter invocation ID, unique within the
    /// request's pinned [`FilterPipeline`]. Swapped into each
    /// `HttpFilterContext` from the protocol-layer request context
    /// and written back after filter execution, following the same
    /// pattern as [`filter_metadata`].
    ///
    /// [`FilterPipeline`]: crate::FilterPipeline
    /// [`filter_metadata`]: Self::filter_metadata
    pub filter_state: HashMap<usize, Box<dyn Any + Send + Sync>>,

    /// Shared health registry for endpoint health lookups.
    pub health_registry: Option<&'a HealthRegistry>,

    /// Shared request ID generator.
    pub id_generator: &'a IdGenerator,

    /// Named key-value stores for runtime mappings.
    pub kv_stores: Option<&'a KvStoreRegistry>,

    /// Transport-agnostic request headers, URI, and method.
    pub request: &'a Request,

    /// Accumulated request body bytes seen so far.
    pub request_body_bytes: u64,

    /// Per-request body delivery mode for the request direction.
    /// Defaults to [`BodyMode::Stream`]; filters may upgrade it
    /// via [`set_request_body_mode`].
    ///
    /// [`set_request_body_mode`]: Self::set_request_body_mode
    pub request_body_mode: BodyMode,

    /// When the request was received; available in all phases.
    pub request_start: Instant,

    /// Accumulated response body bytes seen so far.
    pub response_body_bytes: u64,

    /// Per-request body delivery mode for the response direction.
    /// Defaults to [`BodyMode::Stream`]; filters may upgrade it
    /// via [`set_response_body_mode`].
    ///
    /// [`set_response_body_mode`]: Self::set_response_body_mode
    pub response_body_mode: BodyMode,

    /// The upstream response headers, available during `on_response`.
    /// `None` during the request phase.
    pub response_header: Option<&'a mut Response>,

    /// Whether any filter modified the response headers during
    /// `on_response`. Used to skip unnecessary work.
    pub response_headers_modified: bool,

    /// Index of the selected endpoint in the cluster's
    /// endpoint list. Set by the load balancer filter
    /// for use by passive health checking in the
    /// protocol layer.
    pub selected_endpoint_index: Option<usize>,

    /// Wall-clock time source for timestamp generation.
    pub time_source: &'a dyn TimeSource,

    /// Rewritten URI path for the upstream request.
    ///
    /// Set by the `path_rewrite` or `url_rewrite` filter during
    /// `on_request`. Applied to the upstream `RequestHeader` in the
    /// protocol layer.
    ///
    /// The router checks this field before the original request URI.
    /// If a preceding filter sets `rewritten_path`, the router
    /// matches against it, enabling "rewrite then route" pipelines.
    ///
    /// If both `path_rewrite` and `url_rewrite` appear in the same
    /// pipeline, only the last writer's value takes effect.
    /// Pipeline validation rejects this by default; set
    /// `allow_rewrite_override: true` on the later filter to
    /// permit it. Or, better yet, don't.
    pub rewritten_path: Option<String>,

    /// The upstream peer selected by the load balancer filter.
    pub upstream: Option<Upstream>,
}

impl HttpFilterContext<'_> {
    /// Selected cluster name, if any.
    pub fn cluster_name(&self) -> Option<&str> {
        self.cluster.as_deref()
    }

    /// Upstream peer address, if selected.
    pub fn upstream_addr(&self) -> Option<&str> {
        self.upstream.as_ref().map(|u| &*u.address)
    }

    /// Read a durable metadata value by key.
    pub fn get_metadata(&self, key: &str) -> Option<&str> {
        self.filter_metadata.get(key).map(String::as_str)
    }

    /// X-Request-ID header value, if present and valid UTF-8.
    pub fn request_id(&self) -> Option<&str> {
        self.request.headers.get("x-request-id").and_then(|v| v.to_str().ok())
    }

    /// Write a durable metadata value that persists across all phases.
    ///
    /// Keys should use dot-prefix namespacing
    /// (e.g. `json_rpc.kind`, `classifier.label`). Keys are limited to
    /// 64 bytes and values to 256 bytes to bound per-request
    /// memory growth.
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        if key.is_empty() || key.len() > 64 {
            tracing::warn!(key_len = key.len(), "metadata key rejected (must be 1-64 bytes)");
            return;
        }
        if value.len() > 256 {
            tracing::warn!(key = %key, value_len = value.len(), "metadata value rejected (max 256 bytes)");
            return;
        }
        if !self.filter_metadata.contains_key(&key) && self.filter_metadata.len() >= MAX_METADATA_ENTRIES {
            tracing::warn!(
                key = %key,
                entries = self.filter_metadata.len(),
                "metadata entry rejected (max {MAX_METADATA_ENTRIES} entries)"
            );
            return;
        }
        self.filter_metadata.insert(key, value);
    }

    /// Upgrade the request body delivery mode for this request.
    ///
    /// Merges `mode` into the current mode using ratchet-up
    /// semantics: `StreamBuffer > SizeLimit > Stream`. A mode
    /// can only be upgraded, never downgraded.
    pub fn set_request_body_mode(&mut self, mode: BodyMode) {
        merge_body_mode(&mut self.request_body_mode, mode);
    }

    /// Upgrade the response body delivery mode for this request.
    ///
    /// Same ratchet-up semantics as [`set_request_body_mode`].
    ///
    /// [`set_request_body_mode`]: Self::set_request_body_mode
    pub fn set_response_body_mode(&mut self, mode: BodyMode) {
        merge_body_mode(&mut self.response_body_mode, mode);
    }

    /// Store typed per-request state for the currently executing filter.
    ///
    /// Uses [`current_filter_id`] as the storage key, so multiple
    /// instances of the same filter type get independent state.
    ///
    /// No-op if called outside of pipeline execution (when
    /// [`current_filter_id`] is `None`).
    ///
    /// [`current_filter_id`]: Self::current_filter_id
    pub fn insert_filter_state<T: Any + Send + Sync>(&mut self, state: T) {
        let Some(idx) = self.current_filter_id else {
            tracing::warn!("insert_filter_state called outside pipeline execution");
            return;
        };
        self.filter_state.insert(idx, Box::new(state));
    }

    /// Retrieve a shared reference to the typed state stored by the
    /// currently executing filter.
    ///
    /// Returns `None` when no state is stored, when the stored type
    /// does not match `T`, or when called outside pipeline execution.
    pub fn get_filter_state<T: Any + Send + Sync>(&self) -> Option<&T> {
        let idx = self.current_filter_id?;
        self.filter_state.get(&idx)?.downcast_ref()
    }

    /// Retrieve a mutable reference to the typed state stored by the
    /// currently executing filter.
    ///
    /// Returns `None` under the same conditions as
    /// [`get_filter_state`].
    ///
    /// [`get_filter_state`]: Self::get_filter_state
    pub fn get_filter_state_mut<T: Any + Send + Sync>(&mut self) -> Option<&mut T> {
        let idx = self.current_filter_id?;
        self.filter_state.get_mut(&idx)?.downcast_mut()
    }

    /// Remove and return the typed state stored by the currently
    /// executing filter.
    ///
    /// Returns `None` when no state is stored, when the stored type
    /// does not match `T`, or when called outside pipeline execution.
    /// A type mismatch does not destroy the stored entry.
    pub fn remove_filter_state<T: Any + Send + Sync>(&mut self) -> Option<T> {
        let idx = self.current_filter_id?;
        if !self.filter_state.get(&idx)?.as_ref().is::<T>() {
            return None;
        }
        let boxed = self.filter_state.remove(&idx)?;
        Some(*boxed.downcast::<T>().ok()?)
    }
}

// -----------------------------------------------------------------------------
// Request
// -----------------------------------------------------------------------------

/// HTTP request metadata.
///
/// ```
/// use http::{HeaderMap, Method, Uri};
/// use praxis_filter::Request;
///
/// let req = Request {
///     method: Method::GET,
///     uri: Uri::from_static("/api/users"),
///     headers: HeaderMap::new(),
/// };
/// assert_eq!(req.uri.path(), "/api/users");
/// ```
#[derive(Debug, Clone)]
pub struct Request {
    /// HTTP header map.
    pub headers: HeaderMap,

    /// HTTP method.
    pub method: Method,

    /// Request URI.
    pub uri: Uri,
}

// -----------------------------------------------------------------------------
// Response
// -----------------------------------------------------------------------------

/// HTTP response metadata.
///
/// ```
/// use http::{HeaderMap, StatusCode};
/// use praxis_filter::Response;
///
/// let mut resp = Response {
///     status: StatusCode::OK,
///     headers: HeaderMap::new(),
/// };
/// resp.headers.insert("x-custom", "value".parse().unwrap());
/// assert_eq!(resp.status, StatusCode::OK);
/// ```
#[derive(Debug)]
pub struct Response {
    /// HTTP header map.
    pub headers: HeaderMap,

    /// HTTP status code.
    pub status: StatusCode,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn request_fields_are_accessible() {
        let req = Request {
            method: Method::POST,
            uri: "/submit".parse().unwrap(),
            headers: HeaderMap::new(),
        };
        assert_eq!(req.method, Method::POST);
        assert_eq!(req.uri.path(), "/submit");
        assert!(req.headers.is_empty(), "new request should have no headers");
    }

    #[test]
    fn response_header_mutation() {
        let mut resp = Response {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        };
        resp.headers.insert("x-powered-by", "praxis".parse().unwrap());
        assert_eq!(resp.headers["x-powered-by"], "praxis");
    }

    #[test]
    fn response_status_codes() {
        for code in [200_u16, 404, 500] {
            let resp = Response {
                status: StatusCode::from_u16(code).unwrap(),
                headers: HeaderMap::new(),
            };
            assert_eq!(resp.status.as_u16(), code);
        }
    }

    #[test]
    fn cluster_name_returns_none_when_unset() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(ctx.cluster_name().is_none(), "cluster name should be None when unset");
    }

    #[test]
    fn cluster_name_returns_value_when_set() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some(Arc::from("backend"));
        assert_eq!(
            ctx.cluster_name(),
            Some("backend"),
            "cluster name should return set value"
        );
    }

    #[test]
    fn upstream_addr_returns_none_when_unset() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(ctx.upstream_addr().is_none(), "upstream addr should be None when unset");
    }

    #[test]
    fn upstream_addr_returns_value_when_set() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.upstream = Some(Upstream {
            address: Arc::from("10.0.0.1:8080"),
            tls: None,
            connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
        });
        assert_eq!(
            ctx.upstream_addr(),
            Some("10.0.0.1:8080"),
            "upstream addr should return set address"
        );
    }

    #[test]
    fn request_id_returns_none_when_absent() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(
            ctx.request_id().is_none(),
            "request ID should be None when header absent"
        );
    }

    #[test]
    fn request_id_returns_value_when_present() {
        let mut req = crate::test_utils::make_request(Method::GET, "/");
        req.headers.insert("x-request-id", "abc-123".parse().unwrap());
        let ctx = crate::test_utils::make_filter_context(&req);
        assert_eq!(
            ctx.request_id(),
            Some("abc-123"),
            "request ID should return header value"
        );
    }

    #[test]
    fn set_request_body_mode_upgrades_stream_to_stream_buffer() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        assert_eq!(ctx.request_body_mode, BodyMode::Stream, "should start as Stream");
        ctx.set_request_body_mode(BodyMode::StreamBuffer { max_bytes: Some(4096) });
        assert_eq!(
            ctx.request_body_mode,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
            "Stream should upgrade to StreamBuffer"
        );
    }

    #[test]
    fn set_request_body_mode_cannot_downgrade() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_request_body_mode(BodyMode::StreamBuffer { max_bytes: Some(2048) });
        ctx.set_request_body_mode(BodyMode::Stream);
        assert_eq!(
            ctx.request_body_mode,
            BodyMode::StreamBuffer { max_bytes: Some(2048) },
            "StreamBuffer should not downgrade to Stream"
        );
    }

    #[test]
    fn set_response_body_mode_upgrades_stream_to_stream_buffer() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        assert_eq!(ctx.response_body_mode, BodyMode::Stream, "should start as Stream");
        ctx.set_response_body_mode(BodyMode::StreamBuffer { max_bytes: Some(8192) });
        assert_eq!(
            ctx.response_body_mode,
            BodyMode::StreamBuffer { max_bytes: Some(8192) },
            "Stream should upgrade to StreamBuffer"
        );
    }

    #[test]
    fn set_request_body_mode_stream_buffer_then_stream_buffer_merges_limits() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_request_body_mode(BodyMode::StreamBuffer { max_bytes: Some(2048) });
        ctx.set_request_body_mode(BodyMode::StreamBuffer { max_bytes: Some(1024) });
        assert_eq!(
            ctx.request_body_mode,
            BodyMode::StreamBuffer { max_bytes: Some(2048) },
            "larger StreamBuffer limit should win when merging"
        );
    }

    #[test]
    fn get_metadata_returns_none_when_empty() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(
            ctx.get_metadata("json_rpc.method").is_none(),
            "get_metadata should return None for absent key"
        );
    }

    #[test]
    fn set_metadata_then_get_returns_value() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("json_rpc.method", "service/invoke");
        assert_eq!(
            ctx.get_metadata("json_rpc.method"),
            Some("service/invoke"),
            "get_metadata should return the set value"
        );
    }

    #[test]
    fn set_metadata_overwrites_existing() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("classifier.label", "ProcessRequest");
        ctx.set_metadata("classifier.label", "GetTask");
        assert_eq!(
            ctx.get_metadata("classifier.label"),
            Some("GetTask"),
            "set_metadata should overwrite previous value"
        );
    }

    #[test]
    fn metadata_independent_of_filter_results() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("request.session_id", "gw-123");
        ctx.filter_results.clear();
        assert_eq!(
            ctx.get_metadata("request.session_id"),
            Some("gw-123"),
            "clearing filter_results should not affect metadata"
        );
    }

    #[test]
    fn set_metadata_accepts_owned_strings() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let key = "request.task_id".to_owned();
        let value = "task-456".to_owned();
        ctx.set_metadata(key, value);
        assert_eq!(
            ctx.get_metadata("request.task_id"),
            Some("task-456"),
            "set_metadata should accept owned Strings"
        );
    }

    #[test]
    fn kv_stores_returns_none_when_unset() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(ctx.kv_stores.is_none(), "kv_stores should be None when unset");
    }

    #[test]
    fn kv_stores_returns_registry_when_set() {
        let registry = KvStoreRegistry::new();
        let store = registry.get_or_create("routing");
        store.set("model", Arc::from("model-gamma-1"));

        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.kv_stores = Some(&registry);

        let store = ctx.kv_stores.unwrap().get("routing").unwrap();
        assert_eq!(
            store.get("model").as_deref(),
            Some("model-gamma-1"),
            "filter should read KV store via context"
        );
    }

    #[test]
    fn kv_stores_write_from_context_is_visible() {
        let registry = KvStoreRegistry::new();
        let store = registry.get_or_create("flags");

        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.kv_stores = Some(&registry);

        ctx.kv_stores
            .unwrap()
            .get("flags")
            .unwrap()
            .set("dark_mode", Arc::from("true"));
        assert_eq!(
            store.get("dark_mode").as_deref(),
            Some("true"),
            "write through context should be visible on the original store"
        );
    }

    #[test]
    fn kv_stores_missing_store_returns_none() {
        let registry = KvStoreRegistry::new();

        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.kv_stores = Some(&registry);

        assert!(
            ctx.kv_stores.unwrap().get("nonexistent").is_none(),
            "missing store name should return None"
        );
    }

    #[test]
    fn set_metadata_rejects_empty_key() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("", "val");
        assert!(ctx.get_metadata("").is_none(), "empty key should be silently rejected");
    }

    #[test]
    fn set_metadata_rejects_long_key() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let long_key = "k".repeat(65);
        ctx.set_metadata(long_key.as_str(), "val");
        assert!(
            ctx.get_metadata(long_key.as_str()).is_none(),
            "65-byte key should be rejected"
        );
    }

    #[test]
    fn set_metadata_accepts_max_length_key() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let max_key = "k".repeat(64);
        ctx.set_metadata(max_key.as_str(), "val");
        assert_eq!(
            ctx.get_metadata(max_key.as_str()),
            Some("val"),
            "64-byte key should be accepted"
        );
    }

    #[test]
    fn set_metadata_rejects_long_value() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let long_value = "v".repeat(257);
        ctx.set_metadata("key", long_value.as_str());
        assert!(ctx.get_metadata("key").is_none(), "257-byte value should be rejected");
    }

    #[test]
    fn set_metadata_rejects_when_entry_limit_reached() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        for i in 0..MAX_METADATA_ENTRIES {
            ctx.set_metadata(format!("key.{i}"), "value");
        }
        assert_eq!(
            ctx.filter_metadata.len(),
            MAX_METADATA_ENTRIES,
            "should accept exactly {MAX_METADATA_ENTRIES} entries"
        );

        ctx.set_metadata("overflow", "value");
        assert!(
            ctx.get_metadata("overflow").is_none(),
            "entry beyond limit should be rejected"
        );
    }

    #[test]
    fn set_metadata_allows_overwrite_at_limit() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        for i in 0..MAX_METADATA_ENTRIES {
            ctx.set_metadata(format!("key.{i}"), "old");
        }

        ctx.set_metadata("key.0", "new");
        assert_eq!(
            ctx.get_metadata("key.0"),
            Some("new"),
            "overwriting existing key at limit should succeed"
        );
        assert_eq!(
            ctx.filter_metadata.len(),
            MAX_METADATA_ENTRIES,
            "overwrite should not increase entry count"
        );
    }

    #[test]
    fn kv_stores_lookup_with_match_types() {
        use praxis_core::kv::MatchType;

        let registry = KvStoreRegistry::new();
        let store = registry.get_or_create("routes");
        store.set("route.api.v1", Arc::from("api_cluster"));
        store.set("route.web.main", Arc::from("web_cluster"));

        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.kv_stores = Some(&registry);

        let store = ctx.kv_stores.unwrap().get("routes").unwrap();
        assert!(
            store.lookup("route.api", MatchType::Prefix).unwrap().is_some(),
            "prefix lookup should match route.api.v1"
        );
        assert!(
            store.lookup(".main", MatchType::Suffix).unwrap().is_some(),
            "suffix lookup should match route.web.main"
        );
    }

    // -------------------------------------------------------------------------
    // Filter State Tests
    // -------------------------------------------------------------------------

    #[test]
    fn insert_and_get_filter_state_returns_typed_value() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        ctx.insert_filter_state(42_u64);
        assert_eq!(
            ctx.get_filter_state::<u64>(),
            Some(&42_u64),
            "should return the inserted value"
        );
    }

    #[test]
    fn get_filter_state_returns_none_when_empty() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        assert!(
            ctx.get_filter_state::<u64>().is_none(),
            "should return None when no state stored"
        );
    }

    #[test]
    fn get_filter_state_returns_none_for_wrong_type() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        ctx.insert_filter_state(42_u64);
        assert!(
            ctx.get_filter_state::<String>().is_none(),
            "should return None for type mismatch"
        );
    }

    #[test]
    fn get_filter_state_returns_none_when_no_index() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.filter_state.insert(0, Box::new(42_u64));
        assert!(
            ctx.get_filter_state::<u64>().is_none(),
            "should return None when current_filter_id is None"
        );
    }

    #[test]
    fn get_filter_state_mut_allows_mutation() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        ctx.insert_filter_state(10_u64);
        *ctx.get_filter_state_mut::<u64>().unwrap() += 5;
        assert_eq!(
            ctx.get_filter_state::<u64>(),
            Some(&15_u64),
            "mutation through get_mut should be visible"
        );
    }

    #[test]
    fn remove_filter_state_takes_ownership() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        ctx.insert_filter_state("hello".to_owned());
        let removed = ctx.remove_filter_state::<String>();
        assert_eq!(removed.as_deref(), Some("hello"), "should return the stored value");
        assert!(
            ctx.get_filter_state::<String>().is_none(),
            "state should be gone after remove"
        );
    }

    #[test]
    fn remove_filter_state_returns_none_for_wrong_type() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        ctx.insert_filter_state(42_u64);
        assert!(
            ctx.remove_filter_state::<String>().is_none(),
            "type mismatch should return None"
        );
        assert!(
            ctx.get_filter_state::<u64>().is_some(),
            "type mismatch remove should not destroy the entry"
        );
    }

    #[test]
    fn different_indices_do_not_collide() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        ctx.insert_filter_state(100_u64);
        ctx.current_filter_id = Some(1);
        ctx.insert_filter_state(200_u64);

        ctx.current_filter_id = Some(0);
        assert_eq!(ctx.get_filter_state::<u64>(), Some(&100_u64), "index 0 state");

        ctx.current_filter_id = Some(1);
        assert_eq!(ctx.get_filter_state::<u64>(), Some(&200_u64), "index 1 state");
    }

    #[test]
    fn insert_filter_state_is_noop_without_index() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.insert_filter_state(42_u64);
        assert!(ctx.filter_state.is_empty(), "state map should remain empty");
    }
}
