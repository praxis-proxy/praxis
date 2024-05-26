//! The [`HttpFilter`] trait and per-request [`HttpFilterContext`].
//!
//! Every HTTP filter implements this trait. The context carries mutable
//! state (cluster selection, upstream, extra headers) across filter phases.

use std::{net::IpAddr, time::Instant};

use async_trait::async_trait;
use bytes::Bytes;
use praxis_core::connectivity::Upstream;

use crate::{
    actions::FilterAction,
    body::{BodyAccess, BodyMode},
    context::{Request, Response},
};

// -----------------------------------------------------------------------------
// Backward-compatible Aliases
// -----------------------------------------------------------------------------

/// Backward-compatible alias for [`HttpFilter`].
pub type Filter = dyn HttpFilter;

/// Backward-compatible alias for [`HttpFilterContext`].
pub type FilterContext<'a> = HttpFilterContext<'a>;

// -----------------------------------------------------------------------------
// HttpFilter Trait
// -----------------------------------------------------------------------------

/// A filter that participates in HTTP request/response processing.
///
/// # Example
///
/// ```
/// use async_trait::async_trait;
/// use praxis_filter::{FilterAction, FilterError, HttpFilter, HttpFilterContext};
///
/// struct NoopFilter;
///
/// #[async_trait]
/// impl HttpFilter for NoopFilter {
///     fn name(&self) -> &'static str { "noop" }
///     async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
///         Ok(FilterAction::Continue)
///     }
/// }
///
/// let filter = NoopFilter;
/// assert_eq!(filter.name(), "noop");
/// ```
#[async_trait]
pub trait HttpFilter: Send + Sync {
    /// Unique name identifying this filter type (e.g. `"router"`, `"rate_limiter"`).
    fn name(&self) -> &'static str;

    /// Called for each incoming request, in pipeline order.
    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError>;

    /// Called for each response, in reverse pipeline order.
    ///
    /// Default: [`FilterAction::Continue`]
    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let _ = ctx;
        Ok(FilterAction::Continue)
    }

    // ---------------------------------------------------------
    // Body Access Declarations
    // ---------------------------------------------------------

    /// Declares what access this filter needs to request bodies.
    ///
    /// Default: [`BodyAccess::None`]
    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::None
    }

    /// Declares what access this filter needs to response bodies.
    ///
    /// Default: [`BodyAccess::None`]
    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::None
    }

    /// Declares the delivery mode for request body chunks.
    ///
    /// Default: [`BodyMode::Stream`]
    fn request_body_mode(&self) -> BodyMode {
        BodyMode::Stream
    }

    /// Declares the delivery mode for response body chunks.
    ///
    /// Default: [`BodyMode::Stream`]
    fn response_body_mode(&self) -> BodyMode {
        BodyMode::Stream
    }

    /// Whether this filter needs the original request context during body phases.
    ///
    /// Default: `false`
    fn needs_request_context(&self) -> bool {
        false
    }

    // ---------------------------------------------------------
    // Body Hooks
    // ---------------------------------------------------------

    /// Called for each chunk of request body data, in pipeline order.
    ///
    /// Default: Passthrough
    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        let _ = (ctx, body, end_of_stream);
        Ok(FilterAction::Continue)
    }

    /// Called for each chunk of response body data, in reverse pipeline order.
    ///
    /// Default: passthrough, returns [`FilterAction::Continue`]
    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        let _ = (ctx, body, end_of_stream);
        Ok(FilterAction::Continue)
    }
}

/// Boxed error type for filter results.
pub type FilterError = Box<dyn std::error::Error + Send + Sync>;

// -----------------------------------------------------------------------------
// HttpFilterContext
// -----------------------------------------------------------------------------

/// Per-request mutable state shared across all HTTP filters.
///
/// Created by the protocol layer for each incoming request. Filters read
/// and mutate it to select clusters, choose upstreams, and inject headers.
pub struct HttpFilterContext<'a> {
    /// Downstream client IP address (from the TCP connection).
    pub client_addr: Option<IpAddr>,

    /// The cluster name selected by the router filter.
    pub cluster: Option<String>,

    /// Extra headers to inject into the upstream request.
    pub extra_request_headers: Vec<(String, String)>,

    /// Transport-agnostic request headers, URI, and method.
    pub request: &'a Request,

    /// When the request was received; available in all phases.
    pub request_start: Instant,

    /// The upstream response headers, available during `on_response`.
    /// `None` during the request phase.
    pub response_header: Option<&'a mut Response>,

    /// Accumulated request body bytes seen so far.
    pub request_body_bytes: u64,

    /// Accumulated response body bytes seen so far.
    pub response_body_bytes: u64,

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
        self.upstream.as_ref().map(|u| u.address.as_str())
    }

    /// X-Request-ID header value, if present and valid UTF-8.
    pub fn request_id(&self) -> Option<&str> {
        self.request.headers.get("x-request-id").and_then(|v| v.to_str().ok())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::{FilterAction, FilterError, filter::HttpFilterContext};

    struct MinimalFilter;

    #[async_trait]
    impl HttpFilter for MinimalFilter {
        fn name(&self) -> &'static str {
            "minimal"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }

    #[tokio::test]
    async fn default_on_response_returns_continue() {
        let filter = MinimalFilter;
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_response(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue));
    }

    #[test]
    fn cluster_name_returns_none_when_unset() {
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(ctx.cluster_name().is_none());
    }

    #[test]
    fn cluster_name_returns_value_when_set() {
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some("backend".to_string());
        assert_eq!(ctx.cluster_name(), Some("backend"));
    }

    #[test]
    fn upstream_addr_returns_none_when_unset() {
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(ctx.upstream_addr().is_none());
    }

    #[test]
    fn upstream_addr_returns_value_when_set() {
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.upstream = Some(praxis_core::connectivity::Upstream {
            address: "10.0.0.1:8080".into(),
            tls: false,
            sni: String::new(),
            connection: Default::default(),
        });
        assert_eq!(ctx.upstream_addr(), Some("10.0.0.1:8080"));
    }

    #[test]
    fn request_id_returns_none_when_absent() {
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(ctx.request_id().is_none());
    }

    #[test]
    fn default_body_access_is_none() {
        let filter = MinimalFilter;
        assert_eq!(filter.request_body_access(), BodyAccess::None);
        assert_eq!(filter.response_body_access(), BodyAccess::None);
        assert_eq!(filter.request_body_mode(), BodyMode::Stream);
        assert_eq!(filter.response_body_mode(), BodyMode::Stream);
        assert!(!filter.needs_request_context());
    }

    #[test]
    fn request_id_returns_value_when_present() {
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert("x-request-id", "abc-123".parse().unwrap());
        let ctx = crate::test_utils::make_filter_context(&req);
        assert_eq!(ctx.request_id(), Some("abc-123"));
    }
}
