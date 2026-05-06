// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

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
#[allow(clippy::struct_excessive_bools, reason = "lifecycle flags")]
pub struct PingoraRequestCtx {
    /// Connection permit from the per-listener semaphore.
    ///
    /// Held for the lifetime of the request. RAII drop
    /// releases the permit when the context is dropped,
    /// including error and timeout paths.
    pub _connection_permit: Option<OwnedSemaphorePermit>,

    /// Downstream client IP address.
    pub client_addr: Option<IpAddr>,

    /// HTTP version of the downstream client request.
    ///
    /// Captured during `request_filter` so the response-phase Via
    /// header can reflect the protocol the client used.
    pub client_http_version: Option<http::Version>,

    /// Name of the cluster selected by the router filter.
    pub cluster: Option<Arc<str>>,

    /// Whether the connection was upgraded via 101 Switching Protocols.
    ///
    /// Set during `response_filter` when the upstream returns 101.
    /// Body filter hooks skip processing when true, since post-upgrade
    /// bytes are raw protocol frames (e.g. `WebSocket`), not HTTP bodies.
    pub connection_upgraded: bool,

    /// Durable per-request metadata that persists across all lifecycle
    /// phases. Swapped into each [`HttpFilterContext`] and written back
    /// after filter execution.
    ///
    /// [`HttpFilterContext`]: praxis_filter::HttpFilterContext
    pub filter_metadata: std::collections::HashMap<String, String>,

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
    ($ctx:expr, $pipeline:expr, $request:expr, $response_header:expr) => {
        praxis_filter::HttpFilterContext {
            body_done_indices: Vec::new(),
            branch_iterations: std::collections::HashMap::new(),
            client_addr: $ctx.client_addr,
            cluster: $ctx.cluster.take(),
            executed_filter_indices: Vec::new(),
            extra_request_headers: Vec::new(),
            filter_metadata: std::mem::take(&mut $ctx.filter_metadata),
            filter_results: std::collections::HashMap::new(),
            health_registry: $pipeline.health_registry(),
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
            upstream: $ctx.upstream.take(),
        }
    };
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
}

impl Default for PingoraRequestCtx {
    fn default() -> Self {
        Self {
            _connection_permit: None,
            client_addr: None,
            client_http_version: None,
            cluster: None,
            connection_upgraded: false,
            filter_metadata: std::collections::HashMap::new(),
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::significant_drop_tightening,
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
    use praxis_filter::{BodyBuffer, BodyMode};

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
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Create a default request context for tests.
    fn default_ctx() -> PingoraRequestCtx {
        PingoraRequestCtx::default()
    }
}
