// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Host header validation and Max-Forwards handling per [RFC 9110]/[RFC 9112].
//!
//! [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110
//! [RFC 9112]: https://datatracker.ietf.org/doc/html/rfc9112

use pingora_proxy::Session;
use praxis_filter::Rejection;
use tracing::debug;

use super::stream_buffer::build_trace_response;

// -----------------------------------------------------------------------------
// Host Header Validation
// -----------------------------------------------------------------------------

/// Validate the Host header per [RFC 9112 Section 3.2] and [RFC 9110 Section 7.2].
///
/// Returns `Some(rejection)` if the request must be rejected:
/// - Missing Host on HTTP/1.1 ([RFC 9112 Section 3.2])
/// - Multiple Host headers with differing values ([RFC 9110 Section 7.2])
///
/// When duplicate Host headers carry identical values, the duplicates
/// are collapsed to a single header (benign canonicalization).
///
/// [RFC 9110 Section 7.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.2
/// [RFC 9112 Section 3.2]: https://datatracker.ietf.org/doc/html/rfc9112#section-3.2
pub(super) fn validate_host_header(session: &mut Session) -> Option<Rejection> {
    let is_http11 = session.req_header().version == http::Version::HTTP_11;
    let hosts = session.req_header().headers.get_all(http::header::HOST);
    let mut iter = hosts.iter();

    let Some(first) = iter.next() else {
        if is_http11 {
            debug!("rejecting HTTP/1.1 request with missing Host header");
            return Some(Rejection::status(400));
        }
        return None;
    };

    let second = iter.next()?;

    if second.as_bytes() != first.as_bytes() {
        debug!("rejecting request with conflicting Host headers");
        return Some(Rejection::status(400));
    }

    for v in iter {
        if v.as_bytes() != first.as_bytes() {
            debug!("rejecting request with conflicting Host headers");
            return Some(Rejection::status(400));
        }
    }

    debug!("canonicalizing duplicate identical Host headers");
    let canonical = first.clone();
    let _remove = session.req_header_mut().remove_header("host");
    let _insert = session.req_header_mut().insert_header(http::header::HOST, canonical);

    None
}

// -----------------------------------------------------------------------------
// Max-Forwards (RFC 9110 Section 7.6.2)
// -----------------------------------------------------------------------------

/// Handle `Max-Forwards` on TRACE and OPTIONS requests per [RFC 9110 Section 7.6.2].
///
/// When `Max-Forwards` is present and zero, the proxy responds directly
/// instead of forwarding. When positive, it decrements and forwards.
/// For non-TRACE/OPTIONS methods, or when the header is absent, returns `None`.
///
/// [RFC 9110 Section 7.6.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.2
pub(super) async fn handle_max_forwards(session: &mut Session) -> Option<bool> {
    let method = &session.req_header().method;
    if !matches!(*method, http::Method::TRACE | http::Method::OPTIONS) {
        return None;
    }

    let mf = session
        .req_header()
        .headers
        .get("max-forwards")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u32>().ok())?;

    if mf == 0 {
        debug!(method = %method, "Max-Forwards is 0; responding without forwarding");
        let rejection = if *method == http::Method::TRACE {
            build_trace_response(session)
        } else {
            Rejection::status(200)
        };
        crate::http::pingora::convert::send_rejection(session, rejection).await;
        return Some(true);
    }

    debug!(method = %method, max_forwards = mf - 1, "decrementing Max-Forwards");
    let _insert = session
        .req_header_mut()
        .insert_header("max-forwards", (mf - 1).to_string());
    None
}
