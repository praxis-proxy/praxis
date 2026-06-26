// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Structured error responses for fatal proxy errors.

use bytes::Bytes;
use pingora_core::ErrorType;
use pingora_proxy::{FailToProxy, Session};
use praxis_filter::ErrorResponseFormat;
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
/// The response format is determined by [`ErrorResponseFormat`] stored
/// in the request extensions. AI classifier filters set this to
/// [`OpenAi`] or [`Anthropic`] during request processing; all other
/// requests get the default [`ProblemDetails`] (RFC 9457) format.
///
/// Guards against double-writes (filter rejections that already sent a
/// response), dead downstream connections, and HEAD requests (body
/// suppressed). Writable downstream failures (e.g. client body read
/// timeout) receive a structured 400 response.
///
/// [`OpenAi`]: ErrorResponseFormat::OpenAi
/// [`Anthropic`]: ErrorResponseFormat::Anthropic
/// [`ProblemDetails`]: ErrorResponseFormat::ProblemDetails
pub(super) async fn execute(session: &mut Session, e: &pingora_core::Error, ctx: &PingoraRequestCtx) -> FailToProxy {
    let etype = e.etype().clone();
    let format = ctx.extensions.get::<ErrorResponseFormat>().copied().unwrap_or_default();

    if let ErrorType::HTTPStatus(code) = etype {
        return handle_http_status(session, code, format).await;
    }

    let source = e.esource();
    if matches!(source, pingora_core::ErrorSource::Downstream) {
        return handle_downstream(session, &etype, format).await;
    }

    let err = classify_error(&etype, source);

    if final_response_written(session) {
        debug!(
            status = err.status,
            err.code, "response already written, skipping proxy error body"
        );
        return done(err.status);
    }

    write_error_response(session, err, format).await
}

/// Structured response for explicit HTTP status errors.
///
/// Filter rejections typically write their own response before raising
/// `HTTPStatus`; the double-write guard returns immediately in that case.
async fn handle_http_status(session: &mut Session, code: u16, format: ErrorResponseFormat) -> FailToProxy {
    if final_response_written(session) {
        return done(code);
    }
    let err = ProxyError {
        code: "proxy_status_error",
        message: status_title(code),
        status: code,
    };
    write_error_response(session, err, format).await
}

/// Handle a downstream-origin error.
///
/// Dead connections (write failure, read failure, closed) are silently
/// abandoned. Writable failures (e.g. body read timeout) receive a
/// structured 400 response, matching Pingora's default status choice.
async fn handle_downstream(session: &mut Session, etype: &ErrorType, format: ErrorResponseFormat) -> FailToProxy {
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
    write_error_response(session, err, format).await
}

/// Whether the downstream connection is too broken to write a response.
fn is_connection_dead(etype: &ErrorType) -> bool {
    matches!(
        etype,
        ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed
    )
}

/// Build and write the error response to the downstream session.
async fn write_error_response(session: &mut Session, err: ProxyError, format: ErrorResponseFormat) -> FailToProxy {
    let (body, content_type) = format_error_body(&err, format);
    let body_bytes = Bytes::from(body);

    session.set_keepalive(None);

    let Some(header) = build_header(err.status, body_bytes.len(), content_type) else {
        return done(err.status);
    };

    let is_head = session.req_header().method == http::Method::HEAD;
    send_error_response(session, header, body_bytes, is_head).await;
    done(err.status)
}

/// Format the error body and content-type for the given format.
fn format_error_body(err: &ProxyError, format: ErrorResponseFormat) -> (String, &'static str) {
    match format {
        ErrorResponseFormat::OpenAi => (
            format!(
                r#"{{"error":{{"message":"{}","type":"proxy_error","code":"{}"}}}}"#,
                err.message, err.code,
            ),
            "application/json",
        ),
        ErrorResponseFormat::Anthropic => (
            format!(
                r#"{{"type":"error","error":{{"type":"{}","message":"{}"}},"request_id":null}}"#,
                anthropic_error_type(err.status),
                err.message,
            ),
            "application/json",
        ),
        ErrorResponseFormat::ProblemDetails => (
            format!(
                r#"{{"type":"about:blank","title":"{}","status":{},"detail":"{}"}}"#,
                status_title(err.status),
                err.status,
                err.message,
            ),
            "application/problem+json",
        ),
    }
}

/// RFC 9457 title for common proxy error status codes.
fn status_title(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Proxy Error",
    }
}

/// Anthropic error type for the given HTTP status code.
fn anthropic_error_type(status: u16) -> &'static str {
    match status {
        429 => "rate_limit_error",
        500 => "api_error",
        504 => "timeout_error",
        529 => "overloaded_error",
        _ => "api_error",
    }
}

/// Write the error response header and optional body to the downstream session.
async fn send_error_response(session: &mut Session, header: pingora_http::ResponseHeader, body: Bytes, is_head: bool) {
    let end_of_stream = is_head;
    if let Err(e) = session.write_response_header(Box::new(header), end_of_stream).await {
        debug!(error = %e, "failed to write error response header");
        return;
    }
    if !is_head && let Err(e) = session.write_response_body(Some(body), true).await {
        debug!(error = %e, "failed to write error response body");
    }
}

/// Build a response header with content-type and content-length.
fn build_header(status: u16, content_length: usize, content_type: &str) -> Option<pingora_http::ResponseHeader> {
    let mut header = match pingora_http::ResponseHeader::build(status, Some(2)) {
        Ok(h) => h,
        Err(err) => {
            error!(status, error = %err, "failed to build error response header");
            return None;
        },
    };

    if header.insert_header("content-type", content_type).is_err()
        || header
            .insert_header("content-length", content_length.to_string())
            .is_err()
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
fn is_final_response(header: &pingora_http::ResponseHeader) -> bool {
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

    #[test]
    fn default_format_is_problem_details() {
        assert_eq!(ErrorResponseFormat::default(), ErrorResponseFormat::ProblemDetails);
    }

    #[test]
    fn problem_details_body_has_rfc9457_fields() {
        let err = ProxyError {
            code: "upstream_connect_refused",
            message: "Upstream connection refused",
            status: 502,
        };
        let (body, ct) = format_error_body(&err, ErrorResponseFormat::ProblemDetails);
        assert_eq!(ct, "application/problem+json");
        assert!(body.contains(r#""type":"about:blank""#), "body: {body}");
        assert!(body.contains(r#""title":"Bad Gateway""#), "body: {body}");
        assert!(body.contains(r#""status":502"#), "body: {body}");
        assert!(
            body.contains(r#""detail":"Upstream connection refused""#),
            "body: {body}"
        );
    }

    #[test]
    fn openai_body_has_error_envelope() {
        let err = ProxyError {
            code: "upstream_connect_refused",
            message: "Upstream connection refused",
            status: 502,
        };
        let (body, ct) = format_error_body(&err, ErrorResponseFormat::OpenAi);
        assert_eq!(ct, "application/json");
        assert!(body.contains(r#""type":"proxy_error""#), "body: {body}");
        assert!(body.contains(r#""code":"upstream_connect_refused""#), "body: {body}");
        assert!(
            body.contains(r#""message":"Upstream connection refused""#),
            "body: {body}"
        );
    }

    #[test]
    fn anthropic_body_has_error_envelope() {
        let err = ProxyError {
            code: "upstream_connect_refused",
            message: "Upstream connection refused",
            status: 502,
        };
        let (body, ct) = format_error_body(&err, ErrorResponseFormat::Anthropic);
        assert_eq!(ct, "application/json");
        assert!(body.contains(r#""type":"error""#), "body: {body}");
        assert!(body.contains(r#""type":"api_error""#), "body: {body}");
        assert!(body.contains(r#""request_id":null"#), "body: {body}");
        assert!(
            body.contains(r#""message":"Upstream connection refused""#),
            "body: {body}"
        );
    }

    #[test]
    fn anthropic_timeout_uses_timeout_error_type() {
        let err = ProxyError {
            code: "upstream_read_timeout",
            message: "Upstream read timed out",
            status: 504,
        };
        let (body, _) = format_error_body(&err, ErrorResponseFormat::Anthropic);
        assert!(body.contains(r#""type":"timeout_error""#), "body: {body}");
    }

    #[test]
    fn anthropic_error_type_maps_status_codes() {
        assert_eq!(anthropic_error_type(429), "rate_limit_error");
        assert_eq!(anthropic_error_type(504), "timeout_error");
        assert_eq!(anthropic_error_type(529), "overloaded_error");
        assert_eq!(anthropic_error_type(500), "api_error");
        assert_eq!(anthropic_error_type(502), "api_error");
    }

    #[test]
    fn status_title_maps_common_codes() {
        assert_eq!(status_title(502), "Bad Gateway");
        assert_eq!(status_title(504), "Gateway Timeout");
        assert_eq!(status_title(500), "Internal Server Error");
        assert_eq!(status_title(503), "Service Unavailable");
        assert_eq!(status_title(418), "Proxy Error");
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

    // ---- is_connection_dead --------------------------------------------------

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
}
