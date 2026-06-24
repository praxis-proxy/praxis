// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Per-request context that carries filter pipeline results through Pingora's request/response lifecycle hooks.

use std::{collections::VecDeque, net::IpAddr, sync::Arc, time::Instant};

use bytes::Bytes;
use praxis_core::connectivity::Upstream;
use praxis_filter::{BodyBuffer, BodyMode, FilterPipeline, Request};
use tokio::sync::OwnedSemaphorePermit;

// -----------------------------------------------------------------------------
// PingoraRequestCtx
// -----------------------------------------------------------------------------

/// Per-request context carrying filter pipeline results through Pingora hooks.
///
/// ```
/// use std::sync::Arc;
///
/// use praxis_protocol::http::pingora::context::PingoraRequestCtx;
///
/// let mut ctx = PingoraRequestCtx::default();
/// ctx.cluster = Some(Arc::from("api-cluster"));
/// assert_eq!(ctx.cluster.as_deref(), Some("api-cluster"));
/// ```
#[expect(clippy::struct_excessive_bools, reason = "lifecycle flags")]
pub struct PingoraRequestCtx {
    /// Connection permit from the per-listener semaphore.
    ///
    /// Held for the lifetime of the request. RAII drop
    /// releases the permit when the context is dropped,
    /// including error and timeout paths.
    pub _connection_permit: Option<OwnedSemaphorePermit>,

    /// Permit from the process-wide connection semaphore.
    ///
    /// Present only when `runtime.max_connections` is configured.
    pub _global_connection_permit: Option<OwnedSemaphorePermit>,

    /// Downstream client IP address.
    pub client_addr: Option<IpAddr>,

    /// HTTP version of the downstream client request.
    ///
    /// Captured during `request_filter` so the response-phase Via
    /// header can reflect the protocol the client used.
    pub client_http_version: Option<http::Version>,

    /// Name of the cluster selected by a cluster-selecting filter.
    pub cluster: Option<Arc<str>>,

    /// Whether the downstream connection uses TLS.
    ///
    /// Derived from the Pingora session's SSL digest during
    /// `request_filter`. Used by the forwarded headers filter
    /// to set `X-Forwarded-Proto` correctly for HTTP/1.1
    /// connections where the URI lacks a scheme.
    pub downstream_tls: bool,

    /// Whether the connection was upgraded via 101 Switching Protocols.
    ///
    /// Set during `response_filter` when the upstream returns 101.
    /// Body filter hooks skip processing when true, since post-upgrade
    /// bytes are raw protocol frames (e.g. `WebSocket`), not HTTP bodies.
    pub connection_upgraded: bool,

    /// Type-safe request-scoped extension container. Swapped into each
    /// [`HttpFilterContext`] and written back after filter execution,
    /// following the same lifecycle as [`filter_metadata`].
    ///
    /// [`HttpFilterContext`]: praxis_filter::HttpFilterContext
    /// [`filter_metadata`]: PingoraRequestCtx::filter_metadata
    pub extensions: praxis_filter::RequestExtensions,

    /// Durable per-request metadata that persists across all lifecycle
    /// phases. Swapped into each [`HttpFilterContext`] and written back
    /// after filter execution.
    ///
    /// [`HttpFilterContext`]: praxis_filter::HttpFilterContext
    pub filter_metadata: std::collections::HashMap<String, String>,

    /// Post-mutation request body length produced during `StreamBuffer`
    /// pre-read.
    ///
    /// Stored so `upstream_request_filter` can repair request framing
    /// before Pingora sends headers to the backend.
    pub mutated_request_body_len: Option<usize>,

    /// Pipeline pinned for this request's entire lifecycle.
    ///
    /// Set once during `request_filter` by cloning the [`Arc`] from the
    /// listener's [`ArcSwap`]. All subsequent hooks (request body, response,
    /// response body, logging) use this reference instead of re-loading
    /// from the [`ArcSwap`], ensuring that a hot configuration reload
    /// cannot change the pipeline mid-request.
    ///
    /// [`ArcSwap`]: arc_swap::ArcSwap
    pub pinned_pipeline: Option<Arc<FilterPipeline>>,

    /// Filter results from body pre-read. Carried into the next
    /// [`HttpFilterContext`] so that branch chains attached to the
    /// first `on_request` filter can evaluate body-derived results.
    ///
    /// [`HttpFilterContext`]: praxis_filter::HttpFilterContext
    pub filter_results: std::collections::HashMap<&'static str, praxis_filter::FilterResultSet>,

    /// Typed per-filter state that persists across all lifecycle
    /// phases. Keyed by stable filter invocation ID, unique within
    /// the request's pinned [`FilterPipeline`]. Swapped into each
    /// [`HttpFilterContext`] and written back after filter execution,
    /// following the same pattern as [`filter_metadata`].
    ///
    /// [`FilterPipeline`]: praxis_filter::FilterPipeline
    /// [`HttpFilterContext`]: praxis_filter::HttpFilterContext
    /// [`filter_metadata`]: Self::filter_metadata
    pub filter_state: std::collections::HashMap<usize, Box<dyn std::any::Any + Send + Sync>>,

    /// Cluster name snapshot retained for metrics emission in the
    /// `logging()` hook, after `cluster` has been consumed by filter
    /// context construction.
    pub metrics_cluster: Option<Arc<str>>,

    /// Pre-built [`SharedString`] for the metrics cluster label.
    ///
    /// Cached when `metrics_cluster` is set so that
    /// `emit_request_metrics` avoids an `Arc` clone per request.
    ///
    /// [`SharedString`]: ::metrics::SharedString
    pub metrics_cluster_shared: Option<::metrics::SharedString>,

    /// Pre-read body chunks (`StreamBuffer` mode). When `StreamBuffer` is
    /// active, the body is read during `request_filter` (before upstream
    /// selection) so that body-based routing can influence `upstream_peer`.
    /// The `request_body_filter` hook then forwards these stored chunks
    /// instead of reading from the session.
    ///
    /// Uses `VecDeque` so that draining from the front is O(1).
    pub pre_read_body: Option<VecDeque<Bytes>>,

    /// Buffer for request body accumulation in [`StreamBuffer`] mode.
    ///
    /// [`StreamBuffer`]: praxis_filter::BodyMode::StreamBuffer
    pub request_body_buffer: Option<BodyBuffer>,

    /// Accumulated request body bytes seen so far.
    pub request_body_bytes: u64,

    /// Per-request body delivery mode for the request direction.
    /// Seeded from static pipeline capabilities, then potentially
    /// upgraded by filters during `on_request`.
    pub request_body_mode: BodyMode,

    /// Whether the request body has been released (`StreamBuffer` mode).
    /// Once true, remaining chunks bypass buffering and stream through.
    pub request_body_released: bool,

    /// Whether the request method is idempotent (GET, HEAD, OPTIONS).
    pub request_is_idempotent: bool,

    /// Snapshot of the original request for body/response body phases.
    pub request_snapshot: Option<Request>,

    /// When this request was received.
    pub request_start: Instant,

    /// Buffer for response body accumulation in [`StreamBuffer`] mode.
    ///
    /// [`StreamBuffer`]: praxis_filter::BodyMode::StreamBuffer
    pub response_body_buffer: Option<BodyBuffer>,

    /// Accumulated response body bytes seen so far.
    pub response_body_bytes: u64,

    /// Per-request body delivery mode for the response direction.
    /// Seeded from static pipeline capabilities, then potentially
    /// upgraded by filters during `on_response`.
    pub response_body_mode: BodyMode,

    /// Whether the response body has been released (`StreamBuffer` mode).
    pub response_body_released: bool,

    /// Upstream response status code, captured during `response_filter`
    /// for passive health recording in the `logging` hook.
    pub upstream_response_status: Option<u16>,

    /// Whether the response phase has been executed. Used to ensure
    /// cleanup (e.g. least-connections counter release) in the
    /// `logging()` hook when errors bypass `response_filter`.
    pub response_phase_done: bool,

    /// Number of upstream connection retries attempted.
    pub retries: u32,

    /// Index of the selected endpoint in the cluster's
    /// endpoint list. Set during load balancing; used
    /// for passive health recording in the logging hook.
    pub selected_endpoint_index: Option<usize>,

    /// Rewritten URI path for the upstream request.
    ///
    /// Set by the `path_rewrite` filter via [`HttpFilterContext`] and
    /// applied in `upstream_request_filter`.
    ///
    /// [`HttpFilterContext`]: praxis_filter::HttpFilterContext
    pub rewritten_path: Option<String>,

    /// Upstream endpoint selected by the load balancer filter.
    pub upstream: Option<Upstream>,

    /// Saved upstream for retry (cloned before first use).
    pub upstream_for_retry: Option<Upstream>,
}

/// Build an [`HttpFilterContext`] from a `PingoraRequestCtx`.
///
/// Macro (not a function) so Rust's disjoint field borrowing
/// works: `filter_context_for` borrows `self.request_snapshot`
/// immutably while `cluster`, `upstream`, and `rewritten_path`
/// are taken mutably. A function call with `&mut self` would
/// collapse these into a single mutable borrow.
///
/// [`HttpFilterContext`]: praxis_filter::HttpFilterContext
macro_rules! filter_context {
    ($ctx:expr, $pipeline:expr, $request:expr, $response_header:expr) => {{
        #[cfg(feature = "response-store")]
        if let Some(stores) = $pipeline.response_stores() {
            $ctx.extensions.insert(stores.clone());
        }
        praxis_filter::HttpFilterContext {
            body_done_indices: Vec::new(),
            branch_iterations: std::collections::HashMap::new(),
            client_addr: $ctx.client_addr,
            cluster: $ctx.cluster.take(),
            current_filter_id: None,
            downstream_tls: $ctx.downstream_tls,
            extensions: std::mem::take(&mut $ctx.extensions),
            executed_filter_indices: Vec::new(),
            extra_request_headers: Vec::new(),
            request_headers_to_remove: Vec::new(),
            request_headers_to_set: Vec::new(),
            filter_metadata: std::mem::take(&mut $ctx.filter_metadata),
            filter_results: std::mem::take(&mut $ctx.filter_results),
            filter_state: std::mem::take(&mut $ctx.filter_state),
            health_registry: $pipeline.health_registry(),
            id_generator: $pipeline.id_generator(),
            kv_stores: $pipeline.kv_stores(),
            request: $request,
            request_body_bytes: $ctx.request_body_bytes,
            request_body_mode: $ctx.request_body_mode,
            request_start: $ctx.request_start,
            response_body_bytes: $ctx.response_body_bytes,
            response_body_mode: $ctx.response_body_mode,
            response_header: $response_header,
            response_headers_modified: false,
            rewritten_path: $ctx.rewritten_path.take(),
            selected_endpoint_index: $ctx.selected_endpoint_index,
            time_source: $pipeline.time_source(),
            upstream: $ctx.upstream.take(),
        }
    }};
}

impl PingoraRequestCtx {
    /// Build an [`HttpFilterContext`] using an external request reference.
    ///
    /// Takes `cluster` and `upstream` from `self` (leaving `None`
    /// behind) so that filters can reassign them. The caller must
    /// write those fields back after filter execution.
    ///
    /// ```
    /// use praxis_filter::{FilterPipeline, FilterRegistry, Request};
    /// use praxis_protocol::http::pingora::context::PingoraRequestCtx;
    ///
    /// let registry = FilterRegistry::with_builtins();
    /// let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
    /// let request = Request {
    ///     method: http::Method::GET,
    ///     uri: http::Uri::from_static("/"),
    ///     headers: http::HeaderMap::new(),
    /// };
    /// let mut ctx = PingoraRequestCtx::default();
    /// let filter_ctx = ctx.build_filter_context(&pipeline, &request, None);
    /// assert!(filter_ctx.cluster.is_none());
    /// ```
    ///
    /// [`HttpFilterContext`]: praxis_filter::HttpFilterContext
    pub fn build_filter_context<'a>(
        &mut self,
        pipeline: &'a FilterPipeline,
        request: &'a Request,
        response_header: Option<&'a mut praxis_filter::Response>,
    ) -> praxis_filter::HttpFilterContext<'a> {
        filter_context!(self, pipeline, request, response_header)
    }

    /// Build an [`HttpFilterContext`] from the stored [`request_snapshot`].
    ///
    /// Uses disjoint field borrowing so that `request_snapshot` is
    /// borrowed immutably while `cluster` and `upstream` are taken
    /// mutably.
    ///
    /// Returns `None` when `request_snapshot` is not set.
    ///
    /// ```
    /// use praxis_filter::{FilterPipeline, FilterRegistry, Request};
    /// use praxis_protocol::http::pingora::context::PingoraRequestCtx;
    ///
    /// let registry = FilterRegistry::with_builtins();
    /// let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
    /// let mut ctx = PingoraRequestCtx::default();
    /// ctx.request_snapshot = Some(Request {
    ///     method: http::Method::GET,
    ///     uri: http::Uri::from_static("/"),
    ///     headers: http::HeaderMap::new(),
    /// });
    /// let filter_ctx = ctx.filter_context_for(&pipeline, None);
    /// assert!(filter_ctx.is_some());
    /// ```
    ///
    /// [`HttpFilterContext`]: praxis_filter::HttpFilterContext
    /// [`request_snapshot`]: PingoraRequestCtx::request_snapshot
    pub fn filter_context_for<'a>(
        &'a mut self,
        pipeline: &'a FilterPipeline,
        response_header: Option<&'a mut praxis_filter::Response>,
    ) -> Option<praxis_filter::HttpFilterContext<'a>> {
        let request = self.request_snapshot.as_ref()?;
        Some(filter_context!(self, pipeline, request, response_header))
    }

    /// Pin the current pipeline for this request's entire lifecycle.
    ///
    /// Clones the [`Arc`] from the [`ArcSwap`] and stores it in
    /// [`pinned_pipeline`]. All subsequent hooks should call
    /// [`pipeline`] instead of re-loading from the [`ArcSwap`].
    ///
    /// Called once by `request_filter` in both body-capable and
    /// no-body handlers.
    ///
    /// [`ArcSwap`]: arc_swap::ArcSwap
    /// [`pinned_pipeline`]: Self::pinned_pipeline
    /// [`pipeline`]: Self::pipeline
    pub fn pin_pipeline(&mut self, swap: &arc_swap::ArcSwap<FilterPipeline>) -> Arc<FilterPipeline> {
        if let Some(existing) = &self.pinned_pipeline {
            return Arc::clone(existing);
        }
        let pipeline = swap.load_full();
        self.pinned_pipeline = Some(Arc::clone(&pipeline));
        pipeline
    }

    /// Return the pinned pipeline, falling back to a fresh
    /// [`ArcSwap`] load when no pipeline was pinned.
    ///
    /// The fallback covers early-failure paths where a lifecycle
    /// hook runs before `request_filter` (e.g. after
    /// `early_request_filter` rejection triggers `logging`).
    ///
    /// Per-body-chunk hooks (`request_body_filter`,
    /// `response_body_filter`) call this on every chunk,
    /// incurring one [`Arc::clone`] per invocation.
    ///
    /// [`ArcSwap`]: arc_swap::ArcSwap
    pub fn pipeline(&self, swap: &arc_swap::ArcSwap<FilterPipeline>) -> Arc<FilterPipeline> {
        self.pinned_pipeline
            .as_ref()
            .map_or_else(|| swap.load_full(), Arc::clone)
    }
}

impl Default for PingoraRequestCtx {
    #[expect(
        clippy::too_many_lines,
        reason = "context default enumerates all lifecycle fields explicitly"
    )]
    fn default() -> Self {
        Self {
            _connection_permit: None,
            _global_connection_permit: None,
            client_addr: None,
            client_http_version: None,
            cluster: None,
            connection_upgraded: false,
            downstream_tls: false,
            extensions: praxis_filter::RequestExtensions::new(),
            filter_metadata: std::collections::HashMap::new(),
            mutated_request_body_len: None,
            pinned_pipeline: None,
            filter_results: std::collections::HashMap::new(),
            filter_state: std::collections::HashMap::new(),
            metrics_cluster: None,
            metrics_cluster_shared: None,
            pre_read_body: None,
            request_body_buffer: None,
            request_body_bytes: 0,
            request_body_mode: BodyMode::Stream,
            request_body_released: false,
            request_is_idempotent: false,
            request_snapshot: None,
            request_start: Instant::now(),
            response_body_buffer: None,
            response_body_bytes: 0,
            response_body_mode: BodyMode::Stream,
            response_body_released: false,
            upstream_response_status: None,
            response_phase_done: false,
            retries: 0,
            rewritten_path: None,
            selected_endpoint_index: None,
            upstream: None,
            upstream_for_retry: None,
        }
    }
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
    clippy::significant_drop_tightening,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use std::{
        collections::VecDeque,
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
    };

    use bytes::Bytes;
    use http::{HeaderMap, Method, Uri};
    use praxis_core::connectivity::Upstream;
    use praxis_filter::{BodyBuffer, BodyMode, FilterPipeline, FilterRegistry};

    use super::*;

    #[test]
    fn default_state_has_no_client_addr() {
        let ctx = default_ctx();
        assert!(ctx.client_addr.is_none(), "default client_addr should be None");
    }

    #[test]
    fn default_state_has_no_cluster() {
        let ctx = default_ctx();
        assert!(ctx.cluster.is_none(), "default cluster should be None");
    }

    #[test]
    fn default_state_has_zero_retries() {
        let ctx = default_ctx();
        assert_eq!(ctx.retries, 0, "default retries should be zero");
    }

    #[test]
    fn default_state_flags_are_false() {
        let ctx = default_ctx();
        assert!(
            !ctx.request_body_released,
            "default request_body_released should be false"
        );
        assert!(
            !ctx.response_body_released,
            "default response_body_released should be false"
        );
        assert!(
            !ctx.request_is_idempotent,
            "default request_is_idempotent should be false"
        );
        assert!(!ctx.response_phase_done, "default response_phase_done should be false");
    }

    #[test]
    fn default_state_buffers_are_none() {
        let ctx = default_ctx();
        assert!(
            ctx.request_body_buffer.is_none(),
            "default request_body_buffer should be None"
        );
        assert!(
            ctx.response_body_buffer.is_none(),
            "default response_body_buffer should be None"
        );
        assert!(ctx.pre_read_body.is_none(), "default pre_read_body should be None");
    }

    #[test]
    fn default_state_snapshots_are_none() {
        let ctx = default_ctx();
        assert!(
            ctx.request_snapshot.is_none(),
            "default request_snapshot should be None"
        );
        assert!(ctx.upstream.is_none(), "default upstream should be None");
        assert!(
            ctx.upstream_for_retry.is_none(),
            "default upstream_for_retry should be None"
        );
    }

    #[test]
    fn set_client_addr() {
        let mut ctx = default_ctx();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        ctx.client_addr = Some(addr);
        assert_eq!(
            ctx.client_addr.unwrap(),
            addr,
            "client_addr should match assigned value"
        );
    }

    #[test]
    fn set_cluster() {
        let mut ctx = default_ctx();
        ctx.cluster = Some(Arc::from("api-cluster"));
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("api-cluster"),
            "cluster should match assigned value"
        );
    }

    #[test]
    fn set_upstream() {
        let mut ctx = default_ctx();
        let upstream = Upstream {
            address: Arc::from("10.0.0.1:80"),
            tls: None,
            connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
        };
        ctx.upstream = Some(upstream.clone());
        assert_eq!(
            &*ctx.upstream.as_ref().unwrap().address,
            "10.0.0.1:80",
            "upstream address should match assigned value"
        );
    }

    #[test]
    fn increment_retries() {
        let mut ctx = default_ctx();
        ctx.retries += 1;
        ctx.retries += 1;
        assert_eq!(ctx.retries, 2, "retries should be 2 after two increments");
    }

    #[test]
    fn release_request_body_flag() {
        let mut ctx = default_ctx();
        assert!(!ctx.request_body_released, "request_body_released should start false");
        ctx.request_body_released = true;
        assert!(
            ctx.request_body_released,
            "request_body_released should be true after setting"
        );
    }

    #[test]
    fn release_response_body_flag() {
        let mut ctx = default_ctx();
        assert!(!ctx.response_body_released, "response_body_released should start false");
        ctx.response_body_released = true;
        assert!(
            ctx.response_body_released,
            "response_body_released should be true after setting"
        );
    }

    #[test]
    fn response_phase_done_flag() {
        let mut ctx = default_ctx();
        assert!(!ctx.response_phase_done, "response_phase_done should start false");
        ctx.response_phase_done = true;
        assert!(
            ctx.response_phase_done,
            "response_phase_done should be true after setting"
        );
    }

    #[test]
    fn set_pre_read_body() {
        let mut ctx = default_ctx();
        let chunks = VecDeque::from([Bytes::from_static(b"chunk1"), Bytes::from_static(b"chunk2")]);
        ctx.pre_read_body = Some(chunks);
        let body = ctx.pre_read_body.as_ref().unwrap();
        assert_eq!(body.len(), 2, "pre_read_body should contain 2 chunks");
        assert_eq!(body[0], Bytes::from_static(b"chunk1"), "first chunk should be 'chunk1'");
        assert_eq!(
            body[1],
            Bytes::from_static(b"chunk2"),
            "second chunk should be 'chunk2'"
        );
    }

    #[test]
    fn set_request_snapshot() {
        let mut ctx = default_ctx();
        let snapshot = Request {
            method: Method::POST,
            uri: "/api/data".parse::<Uri>().unwrap(),
            headers: HeaderMap::new(),
        };
        ctx.request_snapshot = Some(snapshot);
        let snap = ctx.request_snapshot.as_ref().unwrap();
        assert_eq!(snap.method, Method::POST, "snapshot method should be POST");
        assert_eq!(snap.uri.path(), "/api/data", "snapshot URI path should be /api/data");
    }

    #[test]
    fn request_body_buffer_lifecycle() {
        let mut ctx = default_ctx();
        let mut buf = BodyBuffer::new(100);
        buf.push(Bytes::from_static(b"data")).unwrap();
        ctx.request_body_buffer = Some(buf);

        assert!(
            ctx.request_body_buffer.is_some(),
            "buffer should be present after assignment"
        );
        let taken = ctx.request_body_buffer.take().unwrap();
        assert_eq!(
            taken.freeze(),
            Bytes::from_static(b"data"),
            "frozen buffer should contain pushed data"
        );
        assert!(ctx.request_body_buffer.is_none(), "buffer should be None after take");
    }

    #[test]
    fn default_request_body_mode_is_stream() {
        let ctx = default_ctx();
        assert_eq!(
            ctx.request_body_mode,
            BodyMode::Stream,
            "default request_body_mode should be Stream"
        );
    }

    #[test]
    fn default_response_body_mode_is_stream() {
        let ctx = default_ctx();
        assert_eq!(
            ctx.response_body_mode,
            BodyMode::Stream,
            "default response_body_mode should be Stream"
        );
    }

    #[test]
    fn set_request_body_mode() {
        let mut ctx = default_ctx();
        ctx.request_body_mode = BodyMode::StreamBuffer { max_bytes: Some(4096) };
        assert_eq!(
            ctx.request_body_mode,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
            "request_body_mode should match assigned value"
        );
    }

    #[test]
    fn set_response_body_mode() {
        let mut ctx = default_ctx();
        ctx.response_body_mode = BodyMode::StreamBuffer { max_bytes: Some(8192) };
        assert_eq!(
            ctx.response_body_mode,
            BodyMode::StreamBuffer { max_bytes: Some(8192) },
            "response_body_mode should match assigned value"
        );
    }

    // -------------------------------------------------------------------------
    // Metadata Roundtrip Tests
    // -------------------------------------------------------------------------

    #[test]
    fn metadata_roundtrip_through_filter_context() {
        let registry = FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        let request = Request {
            method: Method::GET,
            uri: "/".parse::<Uri>().unwrap(),
            headers: HeaderMap::new(),
        };

        let mut ctx = default_ctx();
        ctx.filter_metadata.insert("rpc.method".to_owned(), "echo".to_owned());
        ctx.filter_metadata.insert("rpc.status".to_owned(), "ok".to_owned());

        let fctx = ctx.build_filter_context(&pipeline, &request, None);
        assert_eq!(
            fctx.get_metadata("rpc.method"),
            Some("echo"),
            "metadata written before build should survive into filter context"
        );
        assert_eq!(
            fctx.get_metadata("rpc.status"),
            Some("ok"),
            "multiple metadata keys should round-trip"
        );
    }

    #[test]
    fn metadata_written_in_filter_context_persists_back() {
        let registry = FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        let request = Request {
            method: Method::GET,
            uri: "/".parse::<Uri>().unwrap(),
            headers: HeaderMap::new(),
        };

        let mut ctx = default_ctx();
        let mut fctx = ctx.build_filter_context(&pipeline, &request, None);
        fctx.set_metadata("trace.id", "abc-123");
        fctx.set_metadata("trace.span", "42");

        ctx.filter_metadata = fctx.filter_metadata;
        assert_eq!(
            ctx.filter_metadata.get("trace.id").map(String::as_str),
            Some("abc-123"),
            "metadata set in filter context should persist back to protocol context"
        );
        assert_eq!(
            ctx.filter_metadata.get("trace.span").map(String::as_str),
            Some("42"),
            "multiple metadata keys should persist back"
        );
    }

    // -------------------------------------------------------------------------
    // Hot-Reload Pipeline Pinning (via production helpers)
    // -------------------------------------------------------------------------

    #[test]
    fn pin_pipeline_captures_current_arc() {
        let registry = FilterRegistry::with_builtins();
        let pipeline_a = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
        let swap = arc_swap::ArcSwap::from(Arc::clone(&pipeline_a));

        let mut ctx = default_ctx();
        let pinned = ctx.pin_pipeline(&swap);
        assert!(
            Arc::ptr_eq(&pinned, &pipeline_a),
            "pin_pipeline should return the current pipeline"
        );
        assert!(
            Arc::ptr_eq(ctx.pinned_pipeline.as_ref().unwrap(), &pipeline_a),
            "pinned_pipeline should be stored in ctx"
        );
    }

    #[test]
    fn pipeline_returns_pinned_after_reload() {
        let registry = FilterRegistry::with_builtins();
        let pipeline_a = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
        let swap = arc_swap::ArcSwap::from(Arc::clone(&pipeline_a));

        let mut ctx = default_ctx();
        ctx.pin_pipeline(&swap);

        let pipeline_b = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
        swap.store(pipeline_b);

        let later = ctx.pipeline(&swap);
        assert!(
            Arc::ptr_eq(&later, &pipeline_a),
            "later hooks should still return pipeline A after reload"
        );
    }

    #[test]
    fn new_request_after_reload_pins_new_pipeline() {
        let registry = FilterRegistry::with_builtins();
        let pipeline_a = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
        let swap = arc_swap::ArcSwap::from(Arc::clone(&pipeline_a));

        let mut ctx_a = default_ctx();
        ctx_a.pin_pipeline(&swap);

        let pipeline_b = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
        swap.store(Arc::clone(&pipeline_b));

        let mut ctx_b = default_ctx();
        ctx_b.pin_pipeline(&swap);

        assert!(
            Arc::ptr_eq(&ctx_a.pipeline(&swap), &pipeline_a),
            "request A should use old pipeline"
        );
        assert!(
            Arc::ptr_eq(&ctx_b.pipeline(&swap), &pipeline_b),
            "request B should use new pipeline"
        );
    }

    #[test]
    fn old_pipeline_drops_after_ctx_drops() {
        let registry = FilterRegistry::with_builtins();
        let pipeline_a = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
        let weak_a = Arc::downgrade(&pipeline_a);
        let swap = arc_swap::ArcSwap::from(pipeline_a);

        let mut ctx = default_ctx();
        ctx.pin_pipeline(&swap);

        swap.store(Arc::new(FilterPipeline::build(&mut [], &registry).unwrap()));

        assert!(weak_a.upgrade().is_some(), "old pipeline alive while ctx exists");

        drop(ctx);

        assert!(weak_a.upgrade().is_none(), "old pipeline drops with ctx");
    }

    #[test]
    fn pipeline_helper_returns_pinned_for_every_phase() {
        let registry = FilterRegistry::with_builtins();
        let pipeline_a = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
        let swap = arc_swap::ArcSwap::from(Arc::clone(&pipeline_a));

        let mut ctx = default_ctx();
        ctx.pin_pipeline(&swap);

        swap.store(Arc::new(FilterPipeline::build(&mut [], &registry).unwrap()));

        for phase in ["request_body", "response", "response_body", "logging"] {
            let p = ctx.pipeline(&swap);
            assert!(
                Arc::ptr_eq(&p, &pipeline_a),
                "{phase}: should still return pinned pipeline A"
            );
        }
    }

    #[test]
    fn pipeline_fallback_when_not_pinned() {
        let registry = FilterRegistry::with_builtins();
        let pipeline_a = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
        let swap = arc_swap::ArcSwap::from(Arc::clone(&pipeline_a));

        let ctx = default_ctx();

        let loaded = ctx.pipeline(&swap);
        assert!(
            Arc::ptr_eq(&loaded, &pipeline_a),
            "unpinned ctx should fall back to current ArcSwap value"
        );
    }

    #[test]
    fn pin_pipeline_is_idempotent_after_reload() {
        let registry = FilterRegistry::with_builtins();
        let pipeline_a = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
        let swap = arc_swap::ArcSwap::from(Arc::clone(&pipeline_a));

        let mut ctx = default_ctx();
        ctx.pin_pipeline(&swap);

        let pipeline_b = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
        swap.store(pipeline_b);

        let second_pin = ctx.pin_pipeline(&swap);
        assert!(
            Arc::ptr_eq(&second_pin, &pipeline_a),
            "repeated pin_pipeline after reload should return the original pin"
        );
    }

    #[test]
    fn filter_state_isolated_across_pipelines_with_same_ids() {
        let registry = FilterRegistry::with_builtins();
        let pipeline_a = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
        let pipeline_b = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());

        let request = Request {
            method: Method::GET,
            uri: "/".parse::<Uri>().unwrap(),
            headers: HeaderMap::new(),
        };

        let mut ctx_a = default_ctx();
        ctx_a.pinned_pipeline = Some(Arc::clone(&pipeline_a));
        ctx_a.request_snapshot = Some(request.clone());
        let mut fctx_a = ctx_a.build_filter_context(&pipeline_a, &request, None);
        fctx_a.current_filter_id = Some(0);
        fctx_a.insert_filter_state(String::from("from_pipeline_a"));
        ctx_a.filter_state = fctx_a.filter_state;

        let mut ctx_b = default_ctx();
        ctx_b.pinned_pipeline = Some(Arc::clone(&pipeline_b));
        ctx_b.request_snapshot = Some(request.clone());
        let fctx_b = ctx_b.build_filter_context(&pipeline_b, &request, None);

        assert!(
            fctx_b.filter_state.is_empty(),
            "request B should have its own empty state map"
        );

        let fctx_a2 = ctx_a.filter_context_for(&pipeline_a, None).unwrap();
        assert_eq!(
            fctx_a2.filter_state.get(&0).and_then(|v| v.downcast_ref::<String>()),
            Some(&String::from("from_pipeline_a")),
            "request A should still see its own state in a later phase"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Create a default request context for tests.
    fn default_ctx() -> PingoraRequestCtx {
        PingoraRequestCtx::default()
    }
}
