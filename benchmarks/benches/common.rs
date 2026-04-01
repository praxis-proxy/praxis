//! Shared utility functions for Criterion benchmarks.

use http::{HeaderMap, Method, Uri};
use praxis_filter::{HttpFilterContext, Request};

// -----------------------------------------------------------------------------
// Request & Context Builders
// -----------------------------------------------------------------------------

/// Build a GET request targeting the given path.
pub(crate) fn make_request(path: &str) -> Request {
    Request {
        method: Method::GET,
        uri: path.parse::<Uri>().expect("invalid URI"),
        headers: HeaderMap::new(),
    }
}

/// Build an [`HttpFilterContext`] with no cluster, upstream,
/// or response header set.
pub(crate) fn make_ctx(req: &Request) -> HttpFilterContext<'_> {
    HttpFilterContext {
        client_addr: None,
        cluster: None,
        extra_request_headers: Vec::new(),
        request: req,
        request_body_bytes: 0,
        request_start: std::time::Instant::now(),
        response_body_bytes: 0,
        response_header: None,
        response_headers_modified: false,
        upstream: None,
    }
}

// -----------------------------------------------------------------------------
// Tokio Runtime
// -----------------------------------------------------------------------------

/// Build a single-threaded tokio runtime for async benchmarks.
pub(crate) fn bench_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
