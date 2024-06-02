//! Per-request context that carries filter pipeline results through
//! Pingora's request/response lifecycle hooks.

use std::{collections::VecDeque, net::IpAddr, time::Instant};

use bytes::Bytes;
use praxis_core::connectivity::Upstream;
use praxis_filter::{BodyBuffer, Request};

// -----------------------------------------------------------------------------
// RequestCtx
// -----------------------------------------------------------------------------

/// Per-request context carrying filter pipeline results through Pingora hooks.
///
/// Created fresh for each request by `HTTPHandler::new_ctx()`. Accumulates
/// state (cluster, upstream, body buffers) as the request flows through
/// the filter pipeline phases.
pub struct RequestCtx {
    /// Downstream client IP address.
    pub client_addr: Option<IpAddr>,

    /// Name of the cluster selected by the router filter.
    pub cluster: Option<String>,

    /// Buffer for request body accumulation in buffer mode.
    pub request_body_buffer: Option<BodyBuffer>,

    /// Whether the request method is idempotent (GET, HEAD, OPTIONS).
    pub request_is_idempotent: bool,

    /// Snapshot of the original request for body/response body phases.
    pub request_snapshot: Option<Request>,

    /// Buffer for response body accumulation in buffer mode.
    pub response_body_buffer: Option<BodyBuffer>,

    /// When this request was received.
    pub request_start: Instant,

    /// Number of upstream connection retries attempted.
    pub retries: u32,

    /// Upstream endpoint selected by the load balancer filter.
    pub upstream: Option<Upstream>,

    /// Saved upstream for retry (cloned before first use).
    pub upstream_for_retry: Option<Upstream>,

    /// Whether the request body has been released (`StreamBuffer` mode).
    /// Once true, remaining chunks bypass buffering and stream through.
    pub request_body_released: bool,

    /// Pre-read body chunks (`StreamBuffer` mode). When `StreamBuffer` is
    /// active, the body is read during `request_filter` (before upstream
    /// selection) so that body-based routing can influence `upstream_peer`.
    /// The `request_body_filter` hook then forwards these stored chunks
    /// instead of reading from the session.
    ///
    /// Uses `VecDeque` so that draining from the front is O(1).
    pub pre_read_body: Option<VecDeque<Bytes>>,

    /// Whether the response body has been released (`StreamBuffer` mode).
    pub response_body_released: bool,

    /// Accumulated request body bytes seen so far.
    pub request_body_bytes: u64,

    /// Accumulated response body bytes seen so far.
    pub response_body_bytes: u64,

    /// Whether the response phase has been executed. Used to ensure
    /// cleanup (e.g. least-connections counter release) in the
    /// `logging()` hook when errors bypass `response_filter`.
    pub response_phase_done: bool,
}

impl Default for RequestCtx {
    fn default() -> Self {
        Self {
            client_addr: None,
            cluster: None,
            request_body_buffer: None,
            request_body_released: false,
            request_is_idempotent: false,
            request_snapshot: None,
            request_start: Instant::now(),
            response_body_buffer: None,
            response_body_released: false,
            retries: 0,
            upstream: None,
            upstream_for_retry: None,
            request_body_bytes: 0,
            response_body_bytes: 0,
            response_phase_done: false,
            pre_read_body: None,
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        net::{IpAddr, Ipv4Addr},
    };

    use bytes::Bytes;
    use http::{HeaderMap, Method, Uri};
    use praxis_core::connectivity::Upstream;
    use praxis_filter::BodyBuffer;

    use super::*;

    fn default_ctx() -> RequestCtx {
        RequestCtx::default()
    }

    // ---------------------------------------------------------
    // Default State
    // ---------------------------------------------------------

    #[test]
    fn default_state_has_no_client_addr() {
        let ctx = default_ctx();
        assert!(ctx.client_addr.is_none());
    }

    #[test]
    fn default_state_has_no_cluster() {
        let ctx = default_ctx();
        assert!(ctx.cluster.is_none());
    }

    #[test]
    fn default_state_has_zero_retries() {
        let ctx = default_ctx();
        assert_eq!(ctx.retries, 0);
    }

    #[test]
    fn default_state_flags_are_false() {
        let ctx = default_ctx();
        assert!(!ctx.request_body_released);
        assert!(!ctx.response_body_released);
        assert!(!ctx.request_is_idempotent);
        assert!(!ctx.response_phase_done);
    }

    #[test]
    fn default_state_buffers_are_none() {
        let ctx = default_ctx();
        assert!(ctx.request_body_buffer.is_none());
        assert!(ctx.response_body_buffer.is_none());
        assert!(ctx.pre_read_body.is_none());
    }

    #[test]
    fn default_state_snapshots_are_none() {
        let ctx = default_ctx();
        assert!(ctx.request_snapshot.is_none());
        assert!(ctx.upstream.is_none());
        assert!(ctx.upstream_for_retry.is_none());
    }

    // ---------------------------------------------------------
    // Field Mutations
    // ---------------------------------------------------------

    #[test]
    fn set_client_addr() {
        let mut ctx = default_ctx();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        ctx.client_addr = Some(addr);
        assert_eq!(ctx.client_addr.unwrap(), addr);
    }

    #[test]
    fn set_cluster() {
        let mut ctx = default_ctx();
        ctx.cluster = Some("api-cluster".to_string());
        assert_eq!(ctx.cluster.as_deref(), Some("api-cluster"));
    }

    #[test]
    fn set_upstream() {
        let mut ctx = default_ctx();
        let upstream = Upstream {
            address: "10.0.0.1:80".into(),
            tls: false,
            sni: String::new(),
            connection: praxis_core::connectivity::ConnectionOptions::default(),
        };
        ctx.upstream = Some(upstream.clone());
        assert_eq!(ctx.upstream.as_ref().unwrap().address, "10.0.0.1:80");
    }

    #[test]
    fn increment_retries() {
        let mut ctx = default_ctx();
        ctx.retries += 1;
        ctx.retries += 1;
        assert_eq!(ctx.retries, 2);
    }

    // ---------------------------------------------------------
    // State Transitions
    // ---------------------------------------------------------

    #[test]
    fn release_request_body_flag() {
        let mut ctx = default_ctx();
        assert!(!ctx.request_body_released);
        ctx.request_body_released = true;
        assert!(ctx.request_body_released);
    }

    #[test]
    fn release_response_body_flag() {
        let mut ctx = default_ctx();
        assert!(!ctx.response_body_released);
        ctx.response_body_released = true;
        assert!(ctx.response_body_released);
    }

    #[test]
    fn response_phase_done_flag() {
        let mut ctx = default_ctx();
        assert!(!ctx.response_phase_done);
        ctx.response_phase_done = true;
        assert!(ctx.response_phase_done);
    }

    #[test]
    fn set_pre_read_body() {
        let mut ctx = default_ctx();
        let chunks = VecDeque::from([Bytes::from_static(b"chunk1"), Bytes::from_static(b"chunk2")]);
        ctx.pre_read_body = Some(chunks);
        let body = ctx.pre_read_body.as_ref().unwrap();
        assert_eq!(body.len(), 2);
        assert_eq!(body[0], Bytes::from_static(b"chunk1"));
        assert_eq!(body[1], Bytes::from_static(b"chunk2"));
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
        assert_eq!(snap.method, Method::POST);
        assert_eq!(snap.uri.path(), "/api/data");
    }

    #[test]
    fn request_body_buffer_lifecycle() {
        let mut ctx = default_ctx();
        let mut buf = BodyBuffer::new(100);
        buf.push(Bytes::from_static(b"data")).unwrap();
        ctx.request_body_buffer = Some(buf);

        assert!(ctx.request_body_buffer.is_some());
        let taken = ctx.request_body_buffer.take().unwrap();
        assert_eq!(taken.freeze(), Bytes::from_static(b"data"));
        assert!(ctx.request_body_buffer.is_none());
    }
}
