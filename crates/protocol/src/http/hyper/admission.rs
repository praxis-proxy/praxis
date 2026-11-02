// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Overload admission and pre-pipeline request validation.
//!
//! Admission is the Pingora handler's `early_request_filter`: memory
//! pressure, file descriptors, the process-wide and per-listener connection
//! limits, each refused with a `503` and `Retry-After`. Validation is the
//! start of its `request_filter`: the shared inbound admission (transfer
//! codings, `Host`, traversal, header normalization, reserved headers) over
//! the parsed request head, then `Max-Forwards` on `TRACE` and `OPTIONS`.

use std::sync::Arc;

use http::{HeaderValue, Method, request::Parts};
use praxis_filter::Rejection;
use tracing::{debug, warn};

use super::{listener::ListenerShared, reply::LocalReply};
use crate::http::pingora::{
    context::PingoraRequestCtx,
    handler::{
        inbound_admission::{AdmissionRequest, admit_inbound},
        request_filter::{stream_buffer::trace_response_for, validation::parse_max_forwards_header},
    },
    metrics,
};

// -----------------------------------------------------------------------------
// Overload Admission
// -----------------------------------------------------------------------------

/// Admit a request past the overload gates, taking the permits and guards
/// it holds for its lifetime; the `503` to answer with when a gate refuses.
#[expect(
    clippy::used_underscore_binding,
    reason = "the context names its permits for their only use, being dropped"
)]
pub(super) fn admit(listener: &ListenerShared, ctx: &mut PingoraRequestCtx) -> Option<LocalReply> {
    if praxis_core::memory::is_exceeded() {
        return Some(refuse(metrics::OVERLOAD_REASON_MEMORY, "5", "memory pressure exceeded"));
    }

    let Some(fd_admission) = praxis_core::fd::try_admit() else {
        return Some(refuse(
            metrics::OVERLOAD_REASON_FILE_DESCRIPTORS,
            "1",
            "file descriptor limit nearly exhausted",
        ));
    };
    ctx.fd_admission = Some(fd_admission);

    let (exceeded, permit) = crate::connections::try_acquire_global();
    ctx._global_connection_permit = permit;
    if exceeded {
        return Some(refuse(
            metrics::OVERLOAD_REASON_GLOBAL_CONNECTIONS,
            "1",
            "global max connections exceeded",
        ));
    }

    if !take_listener_permit(listener, ctx) {
        return Some(refuse(
            metrics::OVERLOAD_REASON_LISTENER_CONNECTIONS,
            "1",
            "max connections exceeded",
        ));
    }
    ctx._active_request = Some(metrics::ActiveRequestGuard::acquire(listener.name.clone()));
    None
}

/// Take a permit from the listener's `max_connections` limit when it has
/// one; `false` when the limit is exhausted.
#[expect(
    clippy::used_underscore_binding,
    reason = "the context names its permits for their only use, being dropped"
)]
fn take_listener_permit(listener: &ListenerShared, ctx: &mut PingoraRequestCtx) -> bool {
    let Some(limit) = &listener.connection_limit else {
        return true;
    };
    let Ok(permit) = Arc::clone(limit).try_acquire_owned() else {
        return false;
    };
    ctx._connection_permit = Some(permit);
    true
}

/// Count an overload refusal and build its `503`.
fn refuse(reason_label: &'static str, retry_after: &'static str, reason: &'static str) -> LocalReply {
    metrics::record_overload_reject(reason_label);
    warn!(reason, "rejecting request");
    let mut reply = LocalReply::status(503);
    reply
        .headers
        .insert(http::header::RETRY_AFTER, HeaderValue::from_static(retry_after));
    reply
}

// -----------------------------------------------------------------------------
// Request Validation
// -----------------------------------------------------------------------------

/// Run the shared inbound admission over the request head, canonicalizing
/// it in place; the rejection to send when it refuses the request.
///
/// First come the refusals Pingora's own request parsing makes before the
/// shared admission sees a head: `CONNECT`, which a reverse proxy does not
/// tunnel; an HTTP/1 request-target in absolute form ([RFC 9112 Section
/// 3.2]) whose authority is not exactly the `Host` header; and a repeated
/// `Host`, even when the values agree. An absolute-form target that passes
/// is reduced to its origin form, so the request routes by the configured
/// pipeline and never by the authority a client named.
///
/// [RFC 9112 Section 3.2]: https://datatracker.ietf.org/doc/html/rfc9112#section-3.2
pub(super) fn validate(parts: &mut Parts) -> Option<Rejection> {
    if let Some(reason) = refused_head(parts) {
        debug!(reason, "rejecting request before admission");
        return Some(Rejection::status(400));
    }
    if is_http1(parts) && parts.uri.authority().is_some() {
        parts.uri = origin_form(&parts.uri);
    }
    admit_inbound(&mut PartsAdmission { parts })
}

/// Handle `Max-Forwards` on `TRACE` and `OPTIONS` ([RFC 9110 Section
/// 7.6.2]): answer a zero here, decrement anything else.
///
/// [RFC 9110 Section 7.6.2]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.2
pub(super) fn max_forwards(parts: &mut Parts) -> Option<Rejection> {
    if !matches!(parts.method, Method::TRACE | Method::OPTIONS) {
        return None;
    }
    let remaining = parse_max_forwards_header(&parts.headers)?;
    if remaining == 0 {
        debug!(method = %parts.method, "Max-Forwards is 0; responding without forwarding");
        return Some(if parts.method == Method::TRACE {
            trace_response_for(&parts.method, &parts.uri, parts.version, &parts.headers)
        } else {
            Rejection::status(200)
        });
    }

    let decremented = remaining.saturating_sub(1);
    debug!(method = %parts.method, max_forwards = decremented, "decrementing Max-Forwards");
    parts.headers.insert("max-forwards", HeaderValue::from(decremented));
    None
}

/// Why Pingora's request parsing would refuse this head, if it would.
fn refused_head(parts: &Parts) -> Option<&'static str> {
    if parts.method == Method::CONNECT {
        return Some("CONNECT is not proxied");
    }
    if is_http1(parts)
        && let Some(reason) = refused_absolute_form(parts)
    {
        return Some(reason);
    }
    if parts.headers.get_all(http::header::HOST).iter().nth(1).is_some() {
        return Some("more than one Host header");
    }
    None
}

/// Why an HTTP/1 absolute-form request-target is refused, if it is: Pingora
/// takes one only when it names an authority with no userinfo that matches
/// the `Host` header byte for byte.
fn refused_absolute_form(parts: &Parts) -> Option<&'static str> {
    let Some(authority) = parts.uri.authority() else {
        return parts
            .uri
            .scheme()
            .is_some()
            .then_some("request-target names a scheme without an authority");
    };
    if authority.as_str().contains('@') {
        return Some("userinfo in request target");
    }
    let host = parts.headers.get(http::header::HOST)?;
    (host.as_bytes() != authority.as_str().as_bytes()).then_some("Host header differs from request-target authority")
}

/// Whether the request came in over HTTP/1. An HTTP/2 request always
/// carries `:scheme` and `:authority`, which hyper folds into the URI, so
/// only on HTTP/1 does a URI with an authority mean proxy form.
fn is_http1(parts: &Parts) -> bool {
    matches!(
        parts.version,
        http::Version::HTTP_09 | http::Version::HTTP_10 | http::Version::HTTP_11
    )
}

/// The origin form of `uri`: its path and query, `/` when it has none.
fn origin_form(uri: &http::Uri) -> http::Uri {
    uri.path_and_query()
        .map_or_else(|| http::Uri::from_static("/"), |target| http::Uri::from(target.clone()))
}

/// The inbound admission's view of a hyper request head.
struct PartsAdmission<'parts> {
    /// The request head being admitted.
    parts: &'parts mut Parts,
}

impl AdmissionRequest for PartsAdmission<'_> {
    fn version(&self) -> http::Version {
        self.parts.version
    }

    fn path(&self) -> &str {
        self.parts.uri.path()
    }

    fn headers(&self) -> &http::HeaderMap {
        &self.parts.headers
    }

    fn set_header(&mut self, name: http::header::HeaderName, value: HeaderValue) {
        self.parts.headers.remove(&name);
        self.parts.headers.insert(name, value);
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
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_hosts_are_refused_even_when_identical() {
        let mut parts = head(Method::GET, &[("host", "a.example"), ("host", "a.example")]);

        assert_eq!(
            validate(&mut parts).map(|rejection| rejection.status),
            Some(400),
            "a repeated Host is refused like Pingora's parser refuses it"
        );
    }

    #[test]
    fn connect_is_refused() {
        let mut parts = head(Method::CONNECT, &[("host", "a.example:443")]);

        assert_eq!(
            validate(&mut parts).map(|rejection| rejection.status),
            Some(400),
            "a reverse proxy does not tunnel CONNECT"
        );
    }

    #[test]
    fn absolute_form_with_another_host_is_refused_on_http1() {
        let mut parts = head(Method::GET, &[("host", "other.example")]);
        parts.uri = "http://a.example/path".parse().unwrap();

        assert_eq!(
            validate(&mut parts).map(|rejection| rejection.status),
            Some(400),
            "an authority that differs from Host is refused"
        );
    }

    #[test]
    fn absolute_form_with_userinfo_is_refused_on_http1() {
        let mut parts = head(Method::GET, &[("host", "a.example")]);
        parts.uri = "http://user@a.example/path".parse().unwrap();

        assert_eq!(
            validate(&mut parts).map(|rejection| rejection.status),
            Some(400),
            "userinfo in the request target is refused"
        );
    }

    #[test]
    fn absolute_form_matching_host_is_taken_in_origin_form() {
        let mut parts = head(Method::GET, &[("host", "a.example:8080")]);
        parts.uri = "http://a.example:8080/path?q=1".parse().unwrap();

        assert!(
            validate(&mut parts).is_none(),
            "an authority equal to Host is accepted, as Pingora accepts it"
        );
        assert_eq!(parts.uri, "/path?q=1", "the target is reduced to its origin form");
        assert_eq!(
            parts.headers.get("host").unwrap(),
            "a.example:8080",
            "Host is left as the client sent it"
        );
    }

    #[test]
    fn http2_targets_carry_scheme_and_authority() {
        let mut parts = head(Method::GET, &[]);
        parts.uri = "https://a.example/path".parse().unwrap();
        parts.version = http::Version::HTTP_2;

        assert!(
            validate(&mut parts).is_none(),
            "an HTTP/2 request's :scheme and :authority are not proxy form"
        );
    }

    #[test]
    fn duplicate_identical_content_lengths_are_collapsed_in_place() {
        let mut parts = head(
            Method::POST,
            &[("host", "a"), ("content-length", "3"), ("content-length", "3")],
        );

        assert!(
            validate(&mut parts).is_none(),
            "identical duplicate lengths are admitted"
        );
        assert_eq!(
            parts.headers.get_all(http::header::CONTENT_LENGTH).iter().count(),
            1,
            "the duplicates are collapsed on the forwarded head"
        );
    }

    #[test]
    fn reserved_client_headers_are_refused() {
        let mut parts = head(Method::GET, &[("host", "a"), ("x-praxis-route", "1")]);

        assert_eq!(
            validate(&mut parts).map(|rejection| rejection.status),
            Some(400),
            "a client-supplied reserved header must be refused"
        );
    }

    #[test]
    fn zero_max_forwards_answers_trace_and_options_locally() {
        let mut trace = head(
            Method::TRACE,
            &[("host", "a"), ("max-forwards", "0"), ("cookie", "secret")],
        );
        let mut options = head(Method::OPTIONS, &[("host", "a"), ("max-forwards", "0")]);

        let echoed = max_forwards(&mut trace).expect("TRACE with Max-Forwards 0 is answered");
        let body = String::from_utf8(echoed.body.unwrap().to_vec()).unwrap();

        assert!(
            body.starts_with("TRACE / HTTP/1.1"),
            "the request line is echoed: {body}"
        );
        assert!(!body.contains("secret"), "sensitive headers are redacted: {body}");
        assert_eq!(
            max_forwards(&mut options).map(|rejection| rejection.status),
            Some(200),
            "OPTIONS with Max-Forwards 0 is answered with 200"
        );
    }

    #[test]
    fn positive_max_forwards_is_decremented() {
        let mut parts = head(Method::OPTIONS, &[("host", "a"), ("max-forwards", "3")]);

        assert!(
            max_forwards(&mut parts).is_none(),
            "a positive Max-Forwards is forwarded"
        );
        assert_eq!(parts.headers.get("max-forwards").unwrap(), "2", "and decremented");
    }

    #[test]
    fn max_forwards_is_ignored_on_other_methods() {
        let mut parts = head(Method::GET, &[("host", "a"), ("max-forwards", "0")]);

        assert!(max_forwards(&mut parts).is_none(), "GET ignores Max-Forwards");
        assert_eq!(parts.headers.get("max-forwards").unwrap(), "0", "and leaves it alone");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A request head with `method`, target `/`, and `headers`.
    fn head(method: Method, headers: &[(&'static str, &'static str)]) -> Parts {
        let mut builder = http::Request::builder().method(method).uri("/");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap().into_parts().0
    }
}
