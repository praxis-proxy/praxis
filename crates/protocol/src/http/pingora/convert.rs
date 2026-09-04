// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Conversions between Pingora types and Praxis transport-agnostic types.

use pingora_proxy::Session;
use praxis_filter::{Rejection, Request, Response};
use tracing::debug;

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
/// Disables downstream keep-alive by default so the connection closes after
/// a short-circuit response. Complete responses may explicitly preserve it.
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
pub(crate) async fn send_rejection(session: &mut Session, rejection: Rejection) {
    debug!(status = rejection.status, "sending rejection response");
    if !rejection.preserve_keepalive {
        session.set_keepalive(None);
    }

    let mut header = build_rejection_header(&rejection);
    let has_body = rejection.body.is_some();
    if let Some(body) = &rejection.body {
        let _insert = header.insert_header("content-length", body.len().to_string());
    }
    if let Err(e) = session.write_response_header(Box::new(header), !has_body).await {
        debug!(error = %e, "failed to write rejection response header");
        return;
    }
    if let Some(body) = rejection.body
        && let Err(e) = session.write_response_body(Some(body), true).await
    {
        debug!(error = %e, "failed to write rejection response body");
    }
}

/// Build a Pingora [`ResponseHeader`] from a [`Rejection`], falling back
/// to 500 if the status code is invalid.
///
/// [`ResponseHeader`]: pingora_http::ResponseHeader
/// [`Rejection`]: praxis_filter::Rejection
fn build_rejection_header(rejection: &Rejection) -> pingora_http::ResponseHeader {
    let header_count = Some(
        rejection
            .headers
            .len()
            .saturating_add(rejection.header_map.as_ref().map_or(0, |headers| headers.len())),
    );
    let mut header = match pingora_http::ResponseHeader::build(rejection.status, header_count) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(status = rejection.status, error = %e, "invalid rejection status; using 500");
            #[expect(clippy::expect_used, reason = "500 is a valid status code")]
            pingora_http::ResponseHeader::build(500, header_count).expect("500 is a valid status code")
        },
    };
    append_rejection_headers(&mut header, rejection);
    header
}

/// Append a rejection's filter-supplied headers, dropping reserved ones.
///
/// Reserved internal (x-praxis-* / x-ext-*) headers never reach the client:
/// the upstream-response and terminal-response paths both strip them, and a
/// rejection built from filter-supplied headers must hold the same invariant.
fn append_rejection_headers(header: &mut pingora_http::ResponseHeader, rejection: &Rejection) {
    for (name, value) in &rejection.headers {
        if praxis_core::reserved_headers::is_reserved(name) {
            debug!(header = %name, "dropping reserved internal header from rejection response");
            continue;
        }
        let _append = header.append_header(name.clone(), value.clone());
    }
    if let Some(headers) = &rejection.header_map {
        for (name, value) in headers.iter() {
            if praxis_core::reserved_headers::is_reserved(name.as_str()) {
                debug!(header = %name, "dropping reserved internal header from rejection response");
                continue;
            }
            let _append = header.append_header(name.clone(), value.clone());
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
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use http::StatusCode;

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
    fn rejection_header_strips_reserved_internal_headers() {
        let mut header_map = http::HeaderMap::new();
        header_map.insert("x-ext-protocol-task", http::HeaderValue::from_static("meta"));
        header_map.insert("x-request-id", http::HeaderValue::from_static("abc-123"));
        let mut rejection = Rejection::status(403)
            .with_header("x-praxis-route", "internal-cluster")
            .with_header("content-type", "text/plain");
        rejection.header_map = Some(Box::new(header_map));

        let header = build_rejection_header(&rejection);
        assert!(
            header.headers.get("x-praxis-route").is_none(),
            "reserved x-praxis-* header must never reach the client via a rejection"
        );
        assert!(
            header.headers.get("x-ext-protocol-task").is_none(),
            "reserved x-ext-* header must never reach the client via a rejection header_map"
        );
        assert_eq!(
            header.headers.get("content-type").map(http::HeaderValue::as_bytes),
            Some(b"text/plain".as_slice()),
            "non-reserved rejection headers must be preserved"
        );
        assert_eq!(
            header.headers.get("x-request-id").map(http::HeaderValue::as_bytes),
            Some(b"abc-123".as_slice()),
            "non-reserved header_map entries must be preserved"
        );
    }

    #[test]
    fn rejection_header_strips_mixed_case_reserved_from_string_list() {
        // A filter (static_response, rate_limit, policy, ...) can supply a
        // response header with arbitrary case via Rejection::with_header, which
        // lands in the string-list branch. The reserved check must be
        // case-insensitive so a mixed-case X-Praxis-*/X-Ext-* header cannot
        // slip past it (pingora preserves original casing on HTTP/1.1).
        let rejection = Rejection::status(403)
            .with_header("X-Praxis-Route", "internal-cluster")
            .with_header("X-Ext-Agent-Task", "meta")
            .with_header("X-Custom", "keep");

        let header = build_rejection_header(&rejection);
        assert!(
            header.headers.get("x-praxis-route").is_none(),
            "a mixed-case reserved x-praxis-* header must be dropped from a rejection"
        );
        assert!(
            header.headers.get("x-ext-agent-task").is_none(),
            "a mixed-case reserved x-ext-agent-* header must be dropped from a rejection"
        );
        assert_eq!(
            header.headers.get("x-custom").map(http::HeaderValue::as_bytes),
            Some(b"keep".as_slice()),
            "non-reserved rejection headers must still be preserved"
        );
    }

    #[test]
    fn rejection_header_preserves_duplicate_values() {
        let rejection = Rejection::status(200)
            .with_header("set-cookie", "first=1")
            .with_header("set-cookie", "second=2");

        let header = build_rejection_header(&rejection);
        let values: Vec<_> = header
            .headers
            .get_all("set-cookie")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();

        assert_eq!(values, ["first=1", "second=2"]);
    }

    #[test]
    fn rejection_header_preserves_opaque_values() {
        let mut rejection = Rejection::status(200);
        rejection
            .header_map
            .get_or_insert_with(Default::default)
            .append("x-opaque", http::HeaderValue::from_bytes(&[b'a', 0x80, b'z']).unwrap());

        let header = build_rejection_header(&rejection);

        assert_eq!(header.headers["x-opaque"].as_bytes(), &[b'a', 0x80, b'z']);
    }

    #[test]
    fn invalid_rejection_status_falls_back_to_500() {
        // Bypass the validating constructor to model a hostile custom
        // filter handing the converter an out-of-range status.
        let rejection = Rejection {
            body: None,
            headers: Vec::new(),
            header_map: None,
            preserve_keepalive: false,
            status: 99,
        };
        let header = build_rejection_header(&rejection);
        assert_eq!(header.status.as_u16(), 500, "invalid status codes must map to 500");
    }
}
