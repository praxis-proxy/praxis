// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

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
    let version = session.req_header().version;
    let hosts = session.req_header().headers.get_all(http::header::HOST);

    match check_host_values(version, &hosts) {
        HostCheck::Valid => None,
        HostCheck::Reject(rejection) => Some(rejection),
        HostCheck::Canonicalize(canonical) => {
            debug!("canonicalizing duplicate identical Host headers");
            let _remove = session.req_header_mut().remove_header("host");
            let _insert = session.req_header_mut().insert_header(http::header::HOST, canonical);
            None
        },
    }
}

/// Result of pure host header validation.
enum HostCheck {
    /// Single valid host header present (or absent on HTTP/1.0).
    Valid,
    /// Duplicate identical hosts — caller should collapse to one.
    Canonicalize(http::HeaderValue),
    /// Reject with the given status.
    Reject(Rejection),
}

/// Pure validation of Host header values, independent of
/// Pingora [`Session`].
///
/// [`Session`]: pingora_proxy::Session
fn check_host_values(version: http::Version, hosts: &http::header::GetAll<'_, http::HeaderValue>) -> HostCheck {
    let mut iter = hosts.iter();

    let Some(first) = iter.next() else {
        if version == http::Version::HTTP_11 {
            debug!("rejecting HTTP/1.1 request with missing Host header");
            return HostCheck::Reject(Rejection::status(400));
        }
        return HostCheck::Valid;
    };

    if first.as_bytes().iter().all(u8::is_ascii_whitespace) {
        debug!("rejecting request with empty or whitespace-only Host header");
        return HostCheck::Reject(Rejection::status(400));
    }

    let Some(second) = iter.next() else {
        return HostCheck::Valid;
    };

    if second.as_bytes() != first.as_bytes() {
        debug!("rejecting request with conflicting Host headers");
        return HostCheck::Reject(Rejection::status(400));
    }

    for v in iter {
        if v.as_bytes() != first.as_bytes() {
            debug!("rejecting request with conflicting Host headers");
            return HostCheck::Reject(Rejection::status(400));
        }
    }

    HostCheck::Canonicalize(first.clone())
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

    let mf = parse_max_forwards(session)?;

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

/// Parse `Max-Forwards` from a Pingora session.
fn parse_max_forwards(session: &Session) -> Option<u32> {
    session
        .req_header()
        .headers
        .get("max-forwards")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Host Header Validation (RFC 9110 §7.2 / RFC 9112 §3.2)
    // -----------------------------------------------------------------------

    #[test]
    fn missing_host_http11_rejected() {
        let headers = http::HeaderMap::new();
        let result = check_host_values(http::Version::HTTP_11, &headers.get_all(http::header::HOST));
        assert!(
            matches!(result, HostCheck::Reject(_)),
            "HTTP/1.1 without Host must be rejected"
        );
    }

    #[test]
    fn missing_host_http10_allowed() {
        let headers = http::HeaderMap::new();
        let result = check_host_values(http::Version::HTTP_10, &headers.get_all(http::header::HOST));
        assert!(
            matches!(result, HostCheck::Valid),
            "HTTP/1.0 without Host should be allowed"
        );
    }

    #[test]
    fn single_valid_host_accepted() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, "example.com".parse().unwrap());
        let result = check_host_values(http::Version::HTTP_11, &headers.get_all(http::header::HOST));
        assert!(
            matches!(result, HostCheck::Valid),
            "single valid Host should be accepted"
        );
    }

    #[test]
    fn whitespace_only_host_rejected() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, "   ".parse().unwrap());
        let result = check_host_values(http::Version::HTTP_11, &headers.get_all(http::header::HOST));
        assert!(
            matches!(result, HostCheck::Reject(_)),
            "whitespace-only Host must be rejected"
        );
    }

    #[test]
    fn empty_host_rejected() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, "".parse().unwrap());
        let result = check_host_values(http::Version::HTTP_11, &headers.get_all(http::header::HOST));
        assert!(matches!(result, HostCheck::Reject(_)), "empty Host must be rejected");
    }

    #[test]
    fn conflicting_duplicate_hosts_rejected() {
        let mut headers = http::HeaderMap::new();
        headers.append(http::header::HOST, "a.example.com".parse().unwrap());
        headers.append(http::header::HOST, "b.example.com".parse().unwrap());
        let result = check_host_values(http::Version::HTTP_11, &headers.get_all(http::header::HOST));
        assert!(
            matches!(result, HostCheck::Reject(_)),
            "conflicting Host headers must be rejected"
        );
    }

    #[test]
    fn three_hosts_third_conflicts_rejected() {
        let mut headers = http::HeaderMap::new();
        headers.append(http::header::HOST, "same.com".parse().unwrap());
        headers.append(http::header::HOST, "same.com".parse().unwrap());
        headers.append(http::header::HOST, "different.com".parse().unwrap());
        let result = check_host_values(http::Version::HTTP_11, &headers.get_all(http::header::HOST));
        assert!(
            matches!(result, HostCheck::Reject(_)),
            "third conflicting Host must be rejected"
        );
    }

    #[test]
    fn identical_duplicate_hosts_canonicalized() {
        let mut headers = http::HeaderMap::new();
        headers.append(http::header::HOST, "example.com".parse().unwrap());
        headers.append(http::header::HOST, "example.com".parse().unwrap());
        let result = check_host_values(http::Version::HTTP_11, &headers.get_all(http::header::HOST));
        assert!(
            matches!(&result, HostCheck::Canonicalize(v) if v.as_bytes() == b"example.com"),
            "identical duplicate Hosts should be canonicalized"
        );
    }

    #[test]
    fn missing_host_http2_allowed() {
        let headers = http::HeaderMap::new();
        let result = check_host_values(http::Version::HTTP_2, &headers.get_all(http::header::HOST));
        assert!(
            matches!(result, HostCheck::Valid),
            "HTTP/2 without Host should be allowed"
        );
    }

    // -----------------------------------------------------------------------
    // Max-Forwards
    // -----------------------------------------------------------------------

    #[test]
    fn max_forwards_applies_to_trace() {
        assert!(
            is_max_forwards_method(&http::Method::TRACE),
            "Max-Forwards should apply to TRACE"
        );
    }

    #[test]
    fn max_forwards_applies_to_options() {
        assert!(
            is_max_forwards_method(&http::Method::OPTIONS),
            "Max-Forwards should apply to OPTIONS"
        );
    }

    #[test]
    fn max_forwards_does_not_apply_to_get() {
        assert!(
            !is_max_forwards_method(&http::Method::GET),
            "Max-Forwards should not apply to GET"
        );
    }

    #[test]
    fn max_forwards_does_not_apply_to_post() {
        assert!(
            !is_max_forwards_method(&http::Method::POST),
            "Max-Forwards should not apply to POST"
        );
    }

    #[test]
    fn max_forwards_does_not_apply_to_put() {
        assert!(
            !is_max_forwards_method(&http::Method::PUT),
            "Max-Forwards should not apply to PUT"
        );
    }

    #[test]
    fn max_forwards_does_not_apply_to_delete() {
        assert!(
            !is_max_forwards_method(&http::Method::DELETE),
            "Max-Forwards should not apply to DELETE"
        );
    }

    #[test]
    fn max_forwards_does_not_apply_to_head() {
        assert!(
            !is_max_forwards_method(&http::Method::HEAD),
            "Max-Forwards should not apply to HEAD"
        );
    }

    #[test]
    fn max_forwards_does_not_apply_to_patch() {
        assert!(
            !is_max_forwards_method(&http::Method::PATCH),
            "Max-Forwards should not apply to PATCH"
        );
    }

    // -----------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------

    fn is_max_forwards_method(method: &http::Method) -> bool {
        matches!(*method, http::Method::TRACE | http::Method::OPTIONS)
    }
}
