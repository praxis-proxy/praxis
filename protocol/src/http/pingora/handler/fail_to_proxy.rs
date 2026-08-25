// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Structured error responses for fatal proxy errors.

use bytes::Bytes;
use http::HeaderValue;
use pingora_core::ErrorType;
use pingora_proxy::{FailToProxy, Session};
use praxis_filter::{ErrorResponseContext, ErrorResponseFormatterHandle, FormattedErrorResponse, Rejection};
use tracing::{debug, error};

use crate::http::pingora::context::PingoraRequestCtx;

/// Classified proxy error with HTTP status and machine-readable fields.
struct ProxyError {
    /// Machine-readable error code (e.g. `upstream_connect_refused`).
    code: &'static str,
    /// Human-readable error message.
    message: &'static str,
    /// HTTP status code (e.g. 502, 504).
    status: u16,
}

/// Handle a fatal proxy error by writing a structured error response
/// to the downstream client.
///
/// External filters can store an [`ErrorResponseFormatterHandle`] in
/// the request extensions to control the downstream envelope. Requests
/// without a custom formatter use RFC 9457 Problem Details.
///
/// Guards against double-writes (filter rejections that already sent a
/// response), dead downstream connections, and HEAD requests (body
/// suppressed). Writable downstream failures (e.g. client body read
/// timeout) receive a structured 400 response.
#[expect(
    clippy::large_stack_frames,
    clippy::too_many_lines,
    reason = "linear error classification inlines each response-writing branch and adds structured error fields"
)]
pub(super) async fn execute(
    session: &mut Session,
    e: &pingora_core::Error,
    ctx: &mut PingoraRequestCtx,
) -> FailToProxy {
    let etype = e.etype().clone();
    let pending_rejection = ctx.pending_rejection.take();
    let formatter = ctx.extensions.get::<ErrorResponseFormatterHandle>();

    if let ErrorType::HTTPStatus(code) = etype {
        if let Some(rejection) = pending_rejection {
            return handle_pending_rejection(session, code, rejection).await;
        }
        return handle_http_status(session, code, formatter).await;
    }

    let source = e.esource();
    if matches!(source, pingora_core::ErrorSource::Downstream) {
        return handle_downstream(session, &etype, formatter).await;
    }

    let err = classify_error(&etype, source);

    let upstream_address = ctx
        .upstream_for_retry
        .as_ref()
        .map_or("unknown", |u| u.address.as_ref());
    error!(
        error_code = err.code,
        error_message = err.message,
        status = err.status,
        upstream_address,
        "upstream error"
    );

    if final_response_written(session) {
        debug!(
            status = err.status,
            err.code, "response already written, skipping proxy error body"
        );
        return done(err.status);
    }

    write_error_response(session, err, formatter).await
}

/// Structured response for explicit HTTP status errors.
///
/// Filter rejections typically write their own response before raising
/// `HTTPStatus`; the double-write guard returns immediately in that case.
async fn handle_http_status(
    session: &mut Session,
    code: u16,
    formatter: Option<&ErrorResponseFormatterHandle>,
) -> FailToProxy {
    if final_response_written(session) {
        return done(code);
    }
    let err = ProxyError {
        code: "proxy_status_error",
        message: status_title(code),
        status: code,
    };
    write_error_response(session, err, formatter).await
}

/// Deliver a rejection raised during the response phase with its full
/// configured headers and body.
///
/// A response-phase `Reject` cannot write to the session directly (the
/// upstream response is mid-flight), so the rejection crosses the error
/// boundary via the request context and is written here.
async fn handle_pending_rejection(session: &mut Session, code: u16, rejection: Rejection) -> FailToProxy {
    if final_response_written(session) {
        return done(code);
    }
    crate::http::pingora::convert::send_rejection(session, rejection).await;
    done(code)
}

/// Handle a downstream-origin error.
///
/// Dead connections (write failure, read failure, closed) are silently
/// abandoned. Writable failures (e.g. body read timeout) receive a
/// structured 400 response, matching Pingora's default status choice.
async fn handle_downstream(
    session: &mut Session,
    etype: &ErrorType,
    formatter: Option<&ErrorResponseFormatterHandle>,
) -> FailToProxy {
    if is_connection_dead(etype) {
        debug!("downstream connection dead, skipping error response");
        return done(0);
    }
    if final_response_written(session) {
        return done(400);
    }
    let err = ProxyError {
        code: "downstream_request_error",
        message: "Request error",
        status: 400,
    };
    write_error_response(session, err, formatter).await
}

/// Whether the downstream connection is too broken to write a response.
fn is_connection_dead(etype: &ErrorType) -> bool {
    matches!(
        etype,
        ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed
    )
}

/// Build and write the error response to the downstream session.
async fn write_error_response(
    session: &mut Session,
    err: ProxyError,
    formatter: Option<&ErrorResponseFormatterHandle>,
) -> FailToProxy {
    let FormattedErrorResponse { body, content_type } = format_error_response(&err, formatter);

    let Some(header) = build_header(err.status, body.len(), content_type) else {
        return done(err.status);
    };

    let is_head = session.req_header().method == http::Method::HEAD;
    send_error_response(session, header, body, is_head).await;
    done(err.status)
}

/// Format an error with an installed formatter or the default RFC 9457 envelope.
fn format_error_response(err: &ProxyError, formatter: Option<&ErrorResponseFormatterHandle>) -> FormattedErrorResponse {
    if let Some(formatter) = formatter {
        let context = ErrorResponseContext::new(err.code, err.message, err.status);
        return formatter.format(&context);
    }

    FormattedErrorResponse::new(
        format!(
            r#"{{"type":"about:blank","title":"{}","status":{},"detail":"{}"}}"#,
            status_title(err.status),
            err.status,
            err.message,
        ),
        HeaderValue::from_static("application/problem+json"),
    )
}

/// Canonical HTTP reason phrase for RFC 9457 `about:blank` titles.
fn status_title(status: u16) -> &'static str {
    http::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("Proxy Error")
}

/// Write the error response directly to the downstream session.
///
/// The raw downstream writer intentionally bypasses response modules. Synthetic
/// proxy errors must not be transformed by filters such as compression after
/// their content length and provider envelope have been finalized.
async fn send_error_response(session: &mut Session, header: pingora_http::ResponseHeader, body: Bytes, is_head: bool) {
    let response_body = if is_head { Bytes::new() } else { body };
    if let Err(e) = session
        .as_downstream_mut()
        .write_error_response(header, response_body)
        .await
    {
        debug!(error = %e, "failed to write error response");
    }
}

/// Build a response header with content-type and content-length.
fn build_header(status: u16, content_length: usize, content_type: HeaderValue) -> Option<pingora_http::ResponseHeader> {
    let mut header = match pingora_http::ResponseHeader::build(status, Some(3)) {
        Ok(h) => h,
        Err(err) => {
            error!(status, error = %err, "failed to build error response header");
            return None;
        },
    };

    // Synthetic error bodies bypass Pingora's response modules. Ask downstream
    // intermediaries to preserve the finalized representation as well.
    if header.insert_header("content-type", content_type).is_err()
        || header
            .insert_header("content-length", content_length.to_string())
            .is_err()
        || header.insert_header("cache-control", "no-transform").is_err()
    {
        error!("failed to set error response headers");
        return None;
    }

    Some(header)
}

/// Whether a final downstream response has already been written.
fn final_response_written(session: &Session) -> bool {
    session.response_written().is_some_and(is_final_response)
}

/// Whether a response header blocks a later final error response.
pub(super) fn is_final_response(header: &pingora_http::ResponseHeader) -> bool {
    !header.status.is_informational() || header.status == http::StatusCode::SWITCHING_PROTOCOLS
}

/// Construct a `FailToProxy` result.
const fn done(error_code: u16) -> FailToProxy {
    FailToProxy {
        error_code,
        can_reuse_downstream: false,
    }
}

/// Map a Pingora error type and source to a classified proxy error.
fn classify_error(etype: &ErrorType, source: &pingora_core::ErrorSource) -> ProxyError {
    let (status, code, message) = classify_error_tuple(etype, source);
    ProxyError { code, message, status }
}

/// Error classification lookup table.
fn classify_error_tuple(etype: &ErrorType, source: &pingora_core::ErrorSource) -> (u16, &'static str, &'static str) {
    use pingora_core::ErrorSource::{Internal, Unset, Upstream};
    match (etype, source) {
        (ErrorType::ConnectRefused, _) => (502, "upstream_connect_refused", "Upstream connection refused"),
        (ErrorType::ConnectTimedout, _) => (504, "upstream_connect_timeout", "Upstream connection timed out"),
        (ErrorType::ConnectNoRoute, _) => (502, "upstream_connect_no_route", "No route to upstream"),
        (ErrorType::ConnectError, _) => (502, "upstream_connect_error", "Upstream connection error"),
        (ErrorType::TLSHandshakeFailure, _) => (502, "upstream_tls_failure", "Upstream TLS handshake failed"),
        (ErrorType::TLSHandshakeTimedout, _) => (504, "upstream_tls_timeout", "Upstream TLS handshake timed out"),
        (ErrorType::InvalidCert, _) => (502, "upstream_invalid_cert", "Upstream certificate invalid"),
        (ErrorType::ReadTimedout, Upstream) => (504, "upstream_read_timeout", "Upstream read timed out"),
        (ErrorType::WriteTimedout, Upstream) => (504, "upstream_write_timeout", "Upstream write timed out"),
        (ErrorType::ReadError, Upstream) => (502, "upstream_read_error", "Upstream read error"),
        (ErrorType::WriteError, Upstream) => (502, "upstream_write_error", "Upstream write error"),
        (ErrorType::ConnectionClosed, Upstream) => (502, "upstream_connection_closed", "Upstream connection closed"),
        (ErrorType::H2Error | ErrorType::InvalidH2, Upstream) => (502, "upstream_h2_error", "Upstream HTTP/2 error"),
        (_, Internal | Unset) => (500, "internal_proxy_error", "Internal proxy error"),
        _ => (502, "upstream_error", "Upstream error"),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn problem_details_body_has_rfc9457_fields() {
        let err = ProxyError {
            code: "upstream_connect_refused",
            message: "Upstream connection refused",
            status: 502,
        };
        let response = format_error_response(&err, None);
        let body = String::from_utf8(response.body.to_vec()).unwrap();
        assert_eq!(
            response.content_type,
            HeaderValue::from_static("application/problem+json")
        );
        assert!(body.contains(r#""type":"about:blank""#), "body: {body}");
        assert!(body.contains(r#""title":"Bad Gateway""#), "body: {body}");
        assert!(body.contains(r#""status":502"#), "body: {body}");
        assert!(
            body.contains(r#""detail":"Upstream connection refused""#),
            "body: {body}"
        );
    }

    #[test]
    fn custom_formatter_receives_classified_error() {
        let err = ProxyError {
            code: "upstream_connect_refused",
            message: "Upstream connection refused",
            status: 502,
        };
        let formatter = ErrorResponseFormatterHandle::new(TestFormatter);

        let response = format_error_response(&err, Some(&formatter));

        assert_eq!(
            response.body,
            Bytes::from_static(br#"{"code":"upstream_connect_refused","status":502}"#)
        );
        assert_eq!(
            response.content_type,
            HeaderValue::from_static("application/vnd.praxis.test+json")
        );
    }

    #[test]
    fn status_title_uses_canonical_reason_phrase() {
        assert_eq!(status_title(400), "Bad Request");
        assert_eq!(status_title(401), "Unauthorized");
        assert_eq!(status_title(403), "Forbidden");
        assert_eq!(status_title(413), "Payload Too Large");
        assert_eq!(status_title(429), "Too Many Requests");
        assert_eq!(status_title(500), "Internal Server Error");
        assert_eq!(status_title(502), "Bad Gateway");
        assert_eq!(status_title(503), "Service Unavailable");
        assert_eq!(status_title(504), "Gateway Timeout");
    }

    #[test]
    fn status_title_falls_back_for_nonstandard_codes() {
        assert_eq!(status_title(599), "Proxy Error");
    }

    #[test]
    fn informational_100_allows_later_final_error() {
        let header = pingora_http::ResponseHeader::build(100, None).unwrap();

        assert!(
            !is_final_response(&header),
            "100 Continue should not block a later final error response"
        );
    }

    #[test]
    fn switching_protocols_counts_as_final_response() {
        let header = pingora_http::ResponseHeader::build(101, None).unwrap();

        assert!(
            is_final_response(&header),
            "101 Switching Protocols should block later error responses"
        );
    }

    #[test]
    fn non_informational_counts_as_final_response() {
        let header = pingora_http::ResponseHeader::build(200, None).unwrap();

        assert!(
            is_final_response(&header),
            "200 response should block later error responses"
        );
    }

    #[test]
    fn connect_refused_maps_to_502() {
        check(
            &ErrorType::ConnectRefused,
            &pingora_core::ErrorSource::Upstream,
            502,
            "upstream_connect_refused",
        );
    }

    #[test]
    fn connect_timeout_maps_to_504() {
        check(
            &ErrorType::ConnectTimedout,
            &pingora_core::ErrorSource::Upstream,
            504,
            "upstream_connect_timeout",
        );
    }

    #[test]
    fn read_timeout_upstream_maps_to_504() {
        check(
            &ErrorType::ReadTimedout,
            &pingora_core::ErrorSource::Upstream,
            504,
            "upstream_read_timeout",
        );
    }

    #[test]
    fn write_timeout_upstream_maps_to_504() {
        check(
            &ErrorType::WriteTimedout,
            &pingora_core::ErrorSource::Upstream,
            504,
            "upstream_write_timeout",
        );
    }

    #[test]
    fn read_error_upstream_maps_to_502() {
        check(
            &ErrorType::ReadError,
            &pingora_core::ErrorSource::Upstream,
            502,
            "upstream_read_error",
        );
    }

    #[test]
    fn write_error_upstream_maps_to_502() {
        check(
            &ErrorType::WriteError,
            &pingora_core::ErrorSource::Upstream,
            502,
            "upstream_write_error",
        );
    }

    #[test]
    fn connection_closed_upstream_maps_to_502() {
        check(
            &ErrorType::ConnectionClosed,
            &pingora_core::ErrorSource::Upstream,
            502,
            "upstream_connection_closed",
        );
    }

    #[test]
    fn tls_failure_maps_to_502() {
        check(
            &ErrorType::TLSHandshakeFailure,
            &pingora_core::ErrorSource::Upstream,
            502,
            "upstream_tls_failure",
        );
    }

    #[test]
    fn tls_timeout_maps_to_504() {
        check(
            &ErrorType::TLSHandshakeTimedout,
            &pingora_core::ErrorSource::Upstream,
            504,
            "upstream_tls_timeout",
        );
    }

    #[test]
    fn invalid_cert_maps_to_502() {
        check(
            &ErrorType::InvalidCert,
            &pingora_core::ErrorSource::Upstream,
            502,
            "upstream_invalid_cert",
        );
    }

    #[test]
    fn h2_error_upstream_maps_to_502() {
        check(
            &ErrorType::H2Error,
            &pingora_core::ErrorSource::Upstream,
            502,
            "upstream_h2_error",
        );
    }

    #[test]
    fn connect_no_route_maps_to_502() {
        check(
            &ErrorType::ConnectNoRoute,
            &pingora_core::ErrorSource::Upstream,
            502,
            "upstream_connect_no_route",
        );
    }

    #[test]
    fn connect_error_maps_to_502() {
        check(
            &ErrorType::ConnectError,
            &pingora_core::ErrorSource::Upstream,
            502,
            "upstream_connect_error",
        );
    }

    #[test]
    fn internal_error_maps_to_500() {
        check(
            &ErrorType::InternalError,
            &pingora_core::ErrorSource::Internal,
            500,
            "internal_proxy_error",
        );
    }

    #[test]
    fn unset_source_maps_to_500() {
        check(
            &ErrorType::InternalError,
            &pingora_core::ErrorSource::Unset,
            500,
            "internal_proxy_error",
        );
    }

    #[test]
    fn unknown_upstream_error_maps_to_502() {
        check(
            &ErrorType::UnknownError,
            &pingora_core::ErrorSource::Upstream,
            502,
            "upstream_error",
        );
    }

    #[test]
    fn read_error_with_non_upstream_source_falls_through() {
        check(
            &ErrorType::ReadError,
            &pingora_core::ErrorSource::Internal,
            500,
            "internal_proxy_error",
        );
    }

    #[test]
    fn write_error_is_dead() {
        assert!(is_connection_dead(&ErrorType::WriteError));
    }

    #[test]
    fn read_error_is_dead() {
        assert!(is_connection_dead(&ErrorType::ReadError));
    }

    #[test]
    fn connection_closed_is_dead() {
        assert!(is_connection_dead(&ErrorType::ConnectionClosed));
    }

    #[test]
    fn read_timeout_is_not_dead() {
        assert!(!is_connection_dead(&ErrorType::ReadTimedout));
    }

    #[test]
    fn connect_refused_is_not_dead() {
        assert!(!is_connection_dead(&ErrorType::ConnectRefused));
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    struct TestFormatter;

    impl praxis_filter::ErrorResponseFormatter for TestFormatter {
        fn format(&self, context: &ErrorResponseContext<'_>) -> FormattedErrorResponse {
            FormattedErrorResponse::new(
                format!(r#"{{"code":"{}","status":{}}}"#, context.code, context.status),
                HeaderValue::from_static("application/vnd.praxis.test+json"),
            )
        }
    }

    fn check(etype: &ErrorType, source: &pingora_core::ErrorSource, expected_status: u16, expected_code: &str) {
        let err = classify_error(etype, source);
        assert_eq!(
            err.status, expected_status,
            "{etype:?}/{source:?} should map to status {expected_status}"
        );
        assert_eq!(
            err.code, expected_code,
            "{etype:?}/{source:?} should map to code {expected_code}"
        );
    }
}
