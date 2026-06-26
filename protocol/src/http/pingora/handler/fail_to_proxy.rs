// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Structured error responses for fatal proxy errors.
//!
//! Produces RFC 9457 Problem Details (`application/problem+json`)
//! responses when the proxy cannot reach the upstream.

use bytes::Bytes;
use pingora_core::ErrorType;
use pingora_proxy::{FailToProxy, Session};
use tracing::{debug, error};

/// Classified proxy error with HTTP status and machine-readable fields.
struct ProxyError {
    /// HTTP status code (e.g. 502, 504).
    status: u16,
    /// Machine-readable error code (e.g. `upstream_connect_refused`).
    code: &'static str,
    /// Human-readable error message.
    message: &'static str,
}

/// Handle a fatal proxy error by writing an RFC 9457 Problem Details
/// response to the downstream client.
///
/// Guards against double-writes (filter rejections that already sent a
/// response), downstream errors (client already gone), and HEAD requests
/// (body suppressed).
pub(super) async fn execute(session: &mut Session, e: &pingora_core::Error) -> FailToProxy {
    let etype = e.etype().clone();

    if let ErrorType::HTTPStatus(code) = etype {
        if final_response_written(session) {
            return done(code);
        }
        return write_status_error(session, code).await;
    }

    let source = e.esource();
    if matches!(source, pingora_core::ErrorSource::Downstream) {
        debug!("downstream error, skipping error response");
        return done(0);
    }

    let err = classify_error(&etype, source);

    if final_response_written(session) {
        debug!(
            status = err.status,
            err.code, "response already written, skipping proxy error body"
        );
        return done(err.status);
    }

    write_error_response(session, err).await
}

/// Write Pingora's default status response for explicit HTTP status errors.
async fn write_status_error(session: &mut Session, status: u16) -> FailToProxy {
    if let Err(e) = session.respond_error(status).await {
        debug!(error = %e, "failed to write status error response");
    }
    done(status)
}

/// Build and write the error response to the downstream session.
async fn write_error_response(session: &mut Session, err: ProxyError) -> FailToProxy {
    let body = format!(
        r#"{{"type":"about:blank","title":"{}","status":{},"detail":"{}"}}"#,
        status_title(err.status),
        err.status,
        err.message,
    );
    let body_bytes = Bytes::from(body);

    session.set_keepalive(None);

    let Some(header) = build_header(err.status, body_bytes.len()) else {
        return done(err.status);
    };

    let is_head = session.req_header().method == http::Method::HEAD;
    send_error_response(session, header, body_bytes, is_head).await;
    done(err.status)
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
fn build_header(status: u16, content_length: usize) -> Option<pingora_http::ResponseHeader> {
    let mut header = match pingora_http::ResponseHeader::build(status, Some(2)) {
        Ok(h) => h,
        Err(err) => {
            error!(status, error = %err, "failed to build error response header");
            return None;
        },
    };

    if header
        .insert_header("content-type", "application/problem+json")
        .is_err()
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
    ProxyError { status, code, message }
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
    fn problem_details_body_has_rfc9457_fields() {
        let status = 502;
        let title = status_title(status);
        let body = format!(
            r#"{{"type":"about:blank","title":"{title}","status":{status},"detail":"Upstream connection refused"}}"#,
        );
        assert!(body.contains(r#""type":"about:blank""#));
        assert!(body.contains(r#""title":"Bad Gateway""#));
        assert!(body.contains(r#""status":502"#));
        assert!(body.contains(r#""detail":"Upstream connection refused""#));
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
}
