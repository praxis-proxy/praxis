//! Conversions between Pingora types and Praxis transport-agnostic types.
//!
//! Keeps the filter layer decoupled from Pingora internals.

use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::Session;
use praxis_core::connectivity::ConnectionOptions;
use praxis_filter::{Rejection, Request, Response};
use tracing::warn;

// -----------------------------------------------------------------------------
// Pingora - Request / Response Conversion
// -----------------------------------------------------------------------------

/// Build a transport-agnostic `Request` from a Pingora session.
// Hot path: called per-request, cross-crate boundary.
#[inline]
pub(crate) fn request_header_from_session(session: &Session) -> Request {
    let req = session.req_header();

    Request {
        method: req.method.clone(),
        uri: req.uri.clone(),
        headers: req.headers.clone(),
    }
}

/// Build a transport-agnostic `Response` from a Pingora response header.
// Hot path: called per-request, cross-crate boundary.
#[inline]
pub(crate) fn response_header_from_pingora(upstream: &pingora_http::ResponseHeader) -> Response {
    Response {
        status: upstream.status,
        headers: upstream.headers.clone(),
    }
}

/// Sync a modified filter `Response` back into the Pingora response header.
///
/// Removes headers that filters deleted, then inserts or overwrites
/// the remaining headers so the Pingora response exactly mirrors the
/// filter [`Response`].
///
/// Uses Pingora's `remove_header` API (not raw `HeaderMap::clear`)
/// to keep the internal header-name ordering map consistent.
///
/// [`Response`]: praxis_filter::Response
pub(crate) fn sync_response_to_pingora(filter_resp: &Response, pingora_resp: &mut pingora_http::ResponseHeader) {
    // Collect names present in Pingora but absent from the filter
    // response. These were removed by a filter and must be stripped.
    let stale: Vec<String> = pingora_resp
        .headers
        .keys()
        .filter(|k| !filter_resp.headers.contains_key(*k))
        .map(|k| k.as_str().to_owned())
        .collect();

    for name in &stale {
        let _ = pingora_resp.remove_header(name);
    }

    for (name, value) in &filter_resp.headers {
        let header_name = name.as_str().to_owned();
        let header_value = match value.to_str() {
            Ok(v) => v.to_owned(),
            Err(_) => {
                warn!(header = %name, "dropping non-UTF-8 response header value");
                continue;
            },
        };
        let _ = pingora_resp.insert_header(header_name, header_value);
    }
}

// -----------------------------------------------------------------------------
// Pingora - Rejection
// -----------------------------------------------------------------------------

/// Send a rejection response to the client, including any headers and body
/// from the [`Rejection`].
///
/// Disables downstream keep-alive so Pingora closes the connection
/// after the response rather than waiting for a follow-up request.
///
/// [`Rejection`]: praxis_filter::Rejection
pub(crate) async fn send_rejection(session: &mut Session, rejection: Rejection) {
    // Prevent Pingora from reading the next request on this
    // connection. Without this, the H1 server logs a spurious
    // "Client prematurely closed connection" when the client
    // disconnects after receiving the one-shot response.
    session.set_keepalive(None);

    let mut header = pingora_http::ResponseHeader::build(rejection.status, Some(rejection.headers.len()))
        .expect("valid rejection status");

    for (name, value) in &rejection.headers {
        let _ = header.insert_header(name.clone(), value.clone());
    }

    let has_body = rejection.body.is_some();

    if let Some(ref body) = rejection.body {
        let _ = header.insert_header("content-length".to_owned(), body.len().to_string());
    }

    let _ = session.write_response_header(Box::new(header), !has_body).await;

    if let Some(body) = rejection.body {
        let _ = session.write_response_body(Some(body), true).await;
    }
}

// -----------------------------------------------------------------------------
// Pingora - Connection Options
// -----------------------------------------------------------------------------

/// Apply `ConnectionOptions` timeouts to a Pingora `HttpPeer`.
// Hot path: called per upstream_peer, cross-crate boundary.
#[inline]
pub(crate) fn apply_connection_options(peer: &mut HttpPeer, opts: &ConnectionOptions) {
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

    use http::{HeaderMap, HeaderValue, StatusCode};
    use praxis_core::connectivity::ConnectionOptions;
    use praxis_filter::Response;

    use super::*;

    // ---------------------------------------------------------
    // Response Header Conversion
    // ---------------------------------------------------------

    #[test]
    fn response_header_preserves_status() {
        let upstream = pingora_http::ResponseHeader::build(200, None).unwrap();
        let resp = response_header_from_pingora(&upstream);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn response_header_preserves_headers() {
        let mut upstream = pingora_http::ResponseHeader::build(200, Some(2)).unwrap();
        let _ = upstream.insert_header("x-custom", "value");
        let _ = upstream.insert_header("content-type", "text/plain");

        let resp = response_header_from_pingora(&upstream);
        assert_eq!(resp.headers.get("x-custom").unwrap(), "value");
        assert_eq!(resp.headers.get("content-type").unwrap(), "text/plain");
    }

    #[test]
    fn response_header_empty_headers() {
        let upstream = pingora_http::ResponseHeader::build(404, None).unwrap();
        let resp = response_header_from_pingora(&upstream);
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
        assert!(resp.headers.is_empty());
    }

    // ---------------------------------------------------------
    // Sync Response To Pingora
    // ---------------------------------------------------------

    #[test]
    fn sync_response_copies_headers() {
        let mut filter_resp = Response {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        };
        filter_resp
            .headers
            .insert("x-response-id", HeaderValue::from_static("abc123"));

        let mut pingora_resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        sync_response_to_pingora(&filter_resp, &mut pingora_resp);

        assert_eq!(pingora_resp.headers.get("x-response-id").unwrap(), "abc123");
    }

    #[test]
    fn sync_response_multiple_headers() {
        let mut filter_resp = Response {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        };
        filter_resp.headers.insert("x-a", HeaderValue::from_static("1"));
        filter_resp.headers.insert("x-b", HeaderValue::from_static("2"));

        let mut pingora_resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        sync_response_to_pingora(&filter_resp, &mut pingora_resp);

        assert_eq!(pingora_resp.headers.get("x-a").unwrap(), "1");
        assert_eq!(pingora_resp.headers.get("x-b").unwrap(), "2");
    }

    // ---------------------------------------------------------
    // Apply Connection Options
    // ---------------------------------------------------------

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

        assert_eq!(peer.options.connection_timeout, Some(Duration::from_secs(5)));
        assert_eq!(peer.options.total_connection_timeout, Some(Duration::from_secs(10)));
        assert_eq!(peer.options.idle_timeout, Some(Duration::from_secs(60)));
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(30)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(15)));
    }

    #[test]
    fn sync_response_removes_deleted_headers() {
        let mut pingora_resp = pingora_http::ResponseHeader::build(200, Some(3)).unwrap();
        let _ = pingora_resp.insert_header("x-a", "1");
        let _ = pingora_resp.insert_header("x-b", "2");
        let _ = pingora_resp.insert_header("x-c", "3");

        // Filter response has A and C but not B (simulating removal).
        let mut filter_resp = Response {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        };
        filter_resp.headers.insert("x-a", HeaderValue::from_static("1"));
        filter_resp.headers.insert("x-c", HeaderValue::from_static("3"));

        sync_response_to_pingora(&filter_resp, &mut pingora_resp);

        assert_eq!(pingora_resp.headers.get("x-a").unwrap(), "1");
        assert!(
            pingora_resp.headers.get("x-b").is_none(),
            "deleted header must not survive sync"
        );
        assert_eq!(pingora_resp.headers.get("x-c").unwrap(), "3");
    }

    #[test]
    fn sync_response_preserves_status_code() {
        let mut pingora_resp = pingora_http::ResponseHeader::build(404, None).unwrap();

        let filter_resp = Response {
            status: StatusCode::NOT_FOUND,
            headers: HeaderMap::new(),
        };

        sync_response_to_pingora(&filter_resp, &mut pingora_resp);

        assert_eq!(pingora_resp.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn sync_response_adds_new_headers() {
        let mut pingora_resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        // No headers on the Pingora response initially.

        let mut filter_resp = Response {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        };
        filter_resp
            .headers
            .insert("x-new-header", HeaderValue::from_static("added-by-filter"));

        sync_response_to_pingora(&filter_resp, &mut pingora_resp);

        assert_eq!(pingora_resp.headers.get("x-new-header").unwrap(), "added-by-filter");
    }

    #[test]
    fn sync_response_overwrites_modified_headers() {
        let mut pingora_resp = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
        let _ = pingora_resp.insert_header("server", "nginx");

        let mut filter_resp = Response {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        };
        filter_resp.headers.insert("server", HeaderValue::from_static("praxis"));

        sync_response_to_pingora(&filter_resp, &mut pingora_resp);

        assert_eq!(pingora_resp.headers.get("server").unwrap(), "praxis");
    }

    #[test]
    fn apply_connection_options_none_values() {
        let opts = ConnectionOptions::default();

        let mut peer = HttpPeer::new("10.0.0.1:80", false, String::new());
        apply_connection_options(&mut peer, &opts);

        assert!(peer.options.connection_timeout.is_none());
        assert!(peer.options.total_connection_timeout.is_none());
    }
}
