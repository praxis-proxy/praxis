// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! Conversions between Pingora types and Praxis transport-agnostic types.

use std::time::Duration;

use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::Session;
use praxis_core::connectivity::ConnectionOptions;
use praxis_filter::{Rejection, Request, Response};
use tracing::{debug, warn};

// -----------------------------------------------------------------------------
// Pingora - Request / Response Conversion
// -----------------------------------------------------------------------------

/// Build a transport-agnostic [`Request`] from a Pingora session.
///
/// ```ignore
/// // Requires a `pingora_proxy::Session` which cannot be constructed
/// // outside of a Pingora request lifecycle.
/// use praxis_protocol::http::pingora::convert::request_header_from_session;
///
/// let req = request_header_from_session(&mut session);
/// assert!(!req.method.is_safe());
/// ```
///
/// [`Request`]: praxis_filter::Request
// Hot path: called per-request, cross-crate boundary.
#[inline]
pub(crate) fn request_header_from_session(session: &mut Session) -> Request {
    let req = session.req_header_mut();
    let method = req.method.clone();
    let uri = req.uri.clone();
    let headers = req.headers.clone();

    Request { method, uri, headers }
}

/// Build a transport-agnostic [`Response`] by taking headers from a Pingora response.
///
/// Uses [`std::mem::take`] to move the [`HeaderMap`] out of the Pingora
/// response, avoiding a deep clone. The caller must move the headers
/// back (or assign modified headers) before Pingora sends the response
/// downstream.
///
/// ```ignore
/// // Requires `pingora_http::ResponseHeader` from Pingora internals.
/// use praxis_protocol::http::pingora::convert::response_header_from_pingora;
///
/// let mut upstream = pingora_http::ResponseHeader::build(200, None).unwrap();
/// let resp = response_header_from_pingora(&mut upstream);
/// assert_eq!(resp.status.as_u16(), 200);
/// ```
///
/// [`Response`]: praxis_filter::Response
/// [`HeaderMap`]: http::HeaderMap
// Hot path: called per-request, cross-crate boundary.
#[inline]
pub(crate) fn response_header_from_pingora(upstream: &mut pingora_http::ResponseHeader) -> Response {
    Response {
        status: upstream.status,
        headers: std::mem::take(&mut upstream.headers),
    }
}

// -----------------------------------------------------------------------------
// Pingora - Rejection
// -----------------------------------------------------------------------------

/// Send a rejection response to the client, including any headers and body from the [`Rejection`].
///
/// Disables downstream keep-alive so the connection closes after the
/// response.
///
/// ```ignore
/// // Requires an active `pingora_proxy::Session` from a live request.
/// use praxis_protocol::http::pingora::convert::send_rejection;
///
/// let rejection = praxis_filter::Rejection::status(403);
/// send_rejection(&mut session, rejection).await;
/// ```
///
/// [`Rejection`]: praxis_filter::Rejection
#[allow(clippy::expect_used, reason = "status codes are valid")]
pub(crate) async fn send_rejection(session: &mut Session, rejection: Rejection) {
    debug!(status = rejection.status, "sending rejection response");

    session.set_keepalive(None);

    let mut header = pingora_http::ResponseHeader::build(rejection.status, Some(rejection.headers.len()))
        .expect("valid rejection status");

    for (name, value) in &rejection.headers {
        let _insert = header.insert_header(name.clone(), value.clone());
    }

    let has_body = rejection.body.is_some();

    if let Some(ref body) = rejection.body {
        let _insert = header.insert_header("content-length", body.len().to_string());
    }

    let _write = session.write_response_header(Box::new(header), !has_body).await;

    if let Some(body) = rejection.body {
        let _write = session.write_response_body(Some(body), true).await;
    }
}

// -----------------------------------------------------------------------------
// Pingora - Connection Options
// -----------------------------------------------------------------------------

/// Apply [`ConnectionOptions`] timeouts to a Pingora [`HttpPeer`].
///
/// ```ignore
/// // Requires `pingora_core::upstreams::peer::HttpPeer` from Pingora.
/// use praxis_protocol::http::pingora::convert::apply_connection_options;
///
/// let opts = praxis_core::connectivity::ConnectionOptions::default();
/// let mut peer = HttpPeer::new("10.0.0.1:80", false, String::new());
/// apply_connection_options(&mut peer, &opts);
/// ```
///
/// [`ConnectionOptions`]: praxis_core::connectivity::ConnectionOptions
/// [`HttpPeer`]: pingora_core::upstreams::peer::HttpPeer
// Hot path: called per upstream_peer, cross-crate boundary.
#[inline]
pub(crate) fn apply_connection_options(peer: &mut HttpPeer, opts: &ConnectionOptions) {
    if opts.connection_timeout == Some(Duration::ZERO) {
        warn!("connection_timeout is zero, upstream connections will fail immediately");
    }
    if opts.read_timeout == Some(Duration::ZERO) {
        warn!("read_timeout is zero, upstream reads will fail immediately");
    }
    if opts.write_timeout == Some(Duration::ZERO) {
        warn!("write_timeout is zero, upstream writes will fail immediately");
    }

    peer.options.connection_timeout = opts.connection_timeout;
    peer.options.total_connection_timeout = opts.total_connection_timeout;
    peer.options.idle_timeout = opts.idle_timeout;
    peer.options.read_timeout = opts.read_timeout;
    peer.options.write_timeout = opts.write_timeout;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use http::StatusCode;
    use praxis_core::connectivity::ConnectionOptions;

    use super::*;

    #[test]
    fn response_header_preserves_status() {
        let mut upstream = pingora_http::ResponseHeader::build(200, None).unwrap();
        let resp = response_header_from_pingora(&mut upstream);
        assert_eq!(resp.status, StatusCode::OK, "status should be 200 OK");
    }

    #[test]
    fn response_header_preserves_headers() {
        let mut upstream = pingora_http::ResponseHeader::build(200, Some(2)).unwrap();
        let _insert1 = upstream.insert_header("x-custom", "value");
        let _insert2 = upstream.insert_header("content-type", "text/plain");

        let resp = response_header_from_pingora(&mut upstream);
        assert_eq!(
            resp.headers.get("x-custom").unwrap(),
            "value",
            "x-custom header should be preserved"
        );
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/plain",
            "content-type header should be preserved"
        );
    }

    #[test]
    fn response_header_takes_headers_from_upstream() {
        let mut upstream = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
        let _insert = upstream.insert_header("x-test", "taken");

        let resp = response_header_from_pingora(&mut upstream);
        assert_eq!(
            resp.headers.get("x-test").unwrap(),
            "taken",
            "header should be in response"
        );
        assert!(
            upstream.headers.is_empty(),
            "upstream headers should be empty after take"
        );
    }

    #[test]
    fn response_header_empty_headers() {
        let mut upstream = pingora_http::ResponseHeader::build(404, None).unwrap();
        let resp = response_header_from_pingora(&mut upstream);
        assert_eq!(resp.status, StatusCode::NOT_FOUND, "status should be 404 Not Found");
        assert!(
            resp.headers.is_empty(),
            "headers should be empty when upstream has none"
        );
    }

    #[test]
    fn apply_connection_options_sets_timeouts() {
        let opts = ConnectionOptions {
            connection_timeout: Some(Duration::from_secs(5)),
            total_connection_timeout: Some(Duration::from_secs(10)),
            idle_timeout: Some(Duration::from_secs(60)),
            read_timeout: Some(Duration::from_secs(30)),
            write_timeout: Some(Duration::from_secs(15)),
        };

        let mut peer = HttpPeer::new("10.0.0.1:80", false, String::new());
        apply_connection_options(&mut peer, &opts);

        assert_eq!(
            peer.options.connection_timeout,
            Some(Duration::from_secs(5)),
            "connection_timeout should be set"
        );
        assert_eq!(
            peer.options.total_connection_timeout,
            Some(Duration::from_secs(10)),
            "total_connection_timeout should be set"
        );
        assert_eq!(
            peer.options.idle_timeout,
            Some(Duration::from_secs(60)),
            "idle_timeout should be set"
        );
        assert_eq!(
            peer.options.read_timeout,
            Some(Duration::from_secs(30)),
            "read_timeout should be set"
        );
        assert_eq!(
            peer.options.write_timeout,
            Some(Duration::from_secs(15)),
            "write_timeout should be set"
        );
    }

    #[test]
    fn apply_connection_options_none_values() {
        let opts = ConnectionOptions::default();

        let mut peer = HttpPeer::new("10.0.0.1:80", false, String::new());
        apply_connection_options(&mut peer, &opts);

        assert!(
            peer.options.connection_timeout.is_none(),
            "default connection_timeout should be None"
        );
        assert!(
            peer.options.total_connection_timeout.is_none(),
            "default total_connection_timeout should be None"
        );
    }
}
