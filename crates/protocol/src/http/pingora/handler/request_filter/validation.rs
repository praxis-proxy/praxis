// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Host header, request path, and Max-Forwards validation per [RFC 9110]/[RFC 9112].
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
    /// Duplicate identical hosts; caller should collapse to one. Defence in
    /// depth: the Pingora fork already rejects duplicate Host headers.
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

    if !is_valid_host_grammar(first) {
        debug!("rejecting request with malformed Host header");
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

/// Whether a Host value matches `uri-host [ ":" port ]` per
/// [RFC 9110 Section 7.2].
///
/// Parsing as an [`Authority`] rejects whitespace, path delimiters and
/// stray colons; userinfo is not part of the Host grammar. [`Authority`]
/// does not validate the port text at all, so the port (possibly empty,
/// as `port = *DIGIT` allows) is checked separately, as is anything
/// trailing an IP-literal's closing bracket.
///
/// [RFC 9110 Section 7.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.2
/// [`Authority`]: http::uri::Authority
fn is_valid_host_grammar(value: &http::HeaderValue) -> bool {
    let Ok(authority) = http::uri::Authority::try_from(value.as_bytes()) else {
        return false;
    };
    let text = authority.as_str();
    if text.contains('@') {
        return false;
    }

    let port = if text.starts_with('[') {
        let Some((_, rest)) = text.split_once(']') else {
            return false;
        };
        if rest.is_empty() {
            return true;
        }
        let Some(port) = rest.strip_prefix(':') else {
            return false;
        };
        port
    } else if text.contains(['[', ']']) {
        return false;
    } else {
        let Some((_, port)) = text.split_once(':') else {
            return true;
        };
        port
    };

    port.is_empty() || (port.bytes().all(|byte| byte.is_ascii_digit()) && port.parse::<u16>().is_ok())
}

// -----------------------------------------------------------------------------
// Request Path Validation
// -----------------------------------------------------------------------------

/// Reject request paths containing `..` segments.
///
/// Routing and path-conditioned filters match the raw request path,
/// while upstreams typically resolve dot-segments per
/// [RFC 3986 Section 5.2.4]. A path like `/public/../admin` would
/// therefore match a `/public` route yet reach `/admin` upstream.
/// Rejecting these paths up front closes that gap for every filter.
/// Percent-encoded dot variants (`%2e%2e`) are rejected too.
///
/// [RFC 3986 Section 5.2.4]: https://datatracker.ietf.org/doc/html/rfc3986#section-5.2.4
pub(super) fn validate_request_path(session: &Session) -> Option<Rejection> {
    check_request_path(session.req_header().uri.path())
}

/// Pure path check behind [`validate_request_path`].
fn check_request_path(path: &str) -> Option<Rejection> {
    praxis_filter::has_dot_dot_traversal(path).then(|| {
        debug!("rejecting request path with dot-dot segment");
        Rejection::status(400)
    })
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Request Path Validation
    // -------------------------------------------------------------------------

    #[test]
    fn dot_dot_path_rejected() {
        assert!(
            check_request_path("/a/../b").is_some_and(|r| r.status == 400),
            "dot-dot segment should be rejected with 400"
        );
    }

    #[test]
    fn encoded_dot_dot_path_rejected() {
        assert!(
            check_request_path("/a/%2e%2e/b").is_some_and(|r| r.status == 400),
            "percent-encoded dot-dot segment should be rejected with 400"
        );
    }

    #[test]
    fn route_escape_path_rejected() {
        assert!(
            check_request_path("/public/../admin").is_some(),
            "path escaping a prefix route should be rejected"
        );
    }

    #[test]
    fn plain_and_double_slash_paths_accepted() {
        assert!(
            check_request_path("/a/b..c/d").is_none(),
            "dots inside a segment are allowed"
        );
        assert!(
            check_request_path("//etc/passwd").is_none(),
            "double slash is left to routing"
        );
        assert!(check_request_path("/a/./b").is_none(), "single-dot segment is allowed");
    }

    // -------------------------------------------------------------------------
    // Host Header Validation (RFC 9110 §7.2 / RFC 9112 §3.2)
    // -------------------------------------------------------------------------

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

    fn single_host_check(value: &'static str) -> HostCheck {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, http::HeaderValue::from_static(value));
        check_host_values(http::Version::HTTP_11, &headers.get_all(http::header::HOST))
    }

    #[test]
    fn malformed_host_grammar_rejected() {
        for value in ["a b", "h/p", "h:abc", "h:99999", "h:+80", "user@h", "[::1]x", "a[::1]"] {
            assert!(
                matches!(single_host_check(value), HostCheck::Reject(_)),
                "malformed Host {value:?} must be rejected"
            );
        }
    }

    #[test]
    fn well_formed_host_grammar_accepted() {
        for value in [
            "example.com",
            "example.com.",
            "example.com:443",
            "example.com:",
            "[::1]",
            "[::1]:8080",
            "localhost",
        ] {
            assert!(
                matches!(single_host_check(value), HostCheck::Valid),
                "well-formed Host {value:?} must be accepted"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Max-Forwards
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    fn is_max_forwards_method(method: &http::Method) -> bool {
        matches!(*method, http::Method::TRACE | http::Method::OPTIONS)
    }

    /// Build a proxy session that has read the given raw HTTP/1.1
    /// request. The returned client half must stay alive so response
    /// writes have somewhere to go.
    async fn session_for(raw: &str) -> (Session, tokio::io::DuplexStream) {
        use tokio::io::AsyncWriteExt as _;

        let (mut client, server) = tokio::io::duplex(1_048_576);
        client.write_all(raw.as_bytes()).await.unwrap();
        let mut session = Session::new_h1(Box::new(server));
        let read = session.read_request().await.unwrap();
        assert!(read, "the session must parse the request header");
        (session, client)
    }

    #[tokio::test]
    async fn conflicting_third_host_value_rejected() {
        let (mut session, _client) = session_for("GET / HTTP/1.1\r\nHost: one.example\r\n\r\n").await;
        session.req_header_mut().append_header("host", "one.example").unwrap();
        session.req_header_mut().append_header("host", "two.example").unwrap();

        let rejection = validate_host_header(&mut session);
        assert!(
            rejection.is_some_and(|r| r.status == 400),
            "a conflicting third Host value must reject with 400"
        );
    }

    #[tokio::test]
    async fn trace_with_zero_max_forwards_is_answered_directly() {
        let (mut session, _client) = session_for("TRACE / HTTP/1.1\r\nHost: x\r\nMax-Forwards: 0\r\n\r\n").await;
        let handled = handle_max_forwards(&mut session).await;
        assert_eq!(handled, Some(true), "TRACE with Max-Forwards 0 must be answered");
    }

    #[tokio::test]
    async fn options_with_zero_max_forwards_is_answered_directly() {
        let (mut session, _client) = session_for("OPTIONS / HTTP/1.1\r\nHost: x\r\nMax-Forwards: 0\r\n\r\n").await;
        let handled = handle_max_forwards(&mut session).await;
        assert_eq!(handled, Some(true), "OPTIONS with Max-Forwards 0 must be answered");
    }

    #[tokio::test]
    async fn positive_max_forwards_is_decremented() {
        let (mut session, _client) = session_for("TRACE / HTTP/1.1\r\nHost: x\r\nMax-Forwards: 3\r\n\r\n").await;
        let handled = handle_max_forwards(&mut session).await;
        assert_eq!(handled, None, "positive Max-Forwards must forward");
        let value = session
            .req_header()
            .headers
            .get("max-forwards")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        assert_eq!(value.as_deref(), Some("2"), "Max-Forwards must be decremented");
    }

    #[tokio::test]
    async fn get_requests_ignore_max_forwards() {
        let (mut session, _client) = session_for("GET / HTTP/1.1\r\nHost: x\r\nMax-Forwards: 0\r\n\r\n").await;
        let handled = handle_max_forwards(&mut session).await;
        assert_eq!(handled, None, "GET must ignore Max-Forwards");
    }
}
