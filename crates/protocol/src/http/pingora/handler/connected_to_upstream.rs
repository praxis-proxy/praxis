// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Upstream attempt hooks: open an HTTP client span before connecting, then
//! add connection details or a bounded failure result.
//!
//! Pingora calls `upstream_peer` before dialing and calls it again after
//! `fail_to_connect` accepts a retry. That lifecycle lets failed dials have
//! real client spans without fabricating a span after the failure.

use pingora_core::{protocols::Digest, upstreams::peer::HttpPeer};
use tracing::Span;

use super::super::context::PingoraRequestCtx;

// -----------------------------------------------------------------------------
// Execution
// -----------------------------------------------------------------------------

/// Open spans for the selected upstream attempt before Pingora connects.
///
/// Called from `upstream_peer`, once a peer has been selected. Connection reuse
/// and TLS details are recorded later by [`record_connected`].
pub(super) fn open_attempt(peer: &HttpPeer, ctx: &mut PingoraRequestCtx) {
    close_attempt(ctx);
    if ctx.request_span.is_disabled() {
        return;
    }

    let (address, port) = peer_address_and_port(peer);
    let method = ctx
        .request_snapshot
        .as_ref()
        .map_or("HTTP", |request| request.method.as_str());
    let client_span = make_client_span(&ctx.request_span, method, &address, port);
    ctx.upstream_client_span = client_span.clone();
    ctx.upstream_exchange_span = make_exchange_span(&client_span, &address, port);
}

/// Record connection metadata after the dial succeeds or a pooled connection is reused.
pub(super) fn record_connected(reused: bool, digest: Option<&Digest>, ctx: &PingoraRequestCtx) {
    if ctx.upstream_client_span.is_disabled() {
        return;
    }

    ctx.upstream_client_span.record("upstream.connection.reused", reused);
    ctx.upstream_exchange_span.record("upstream.connection.reused", reused);
    if let Some(version) = digest
        .and_then(|value| value.ssl_digest.as_ref())
        .map(|ssl| ssl.version.as_ref())
    {
        ctx.upstream_exchange_span.record("upstream.tls.version", version);
    }
}

/// Record a bounded upstream error and close the failed attempt spans.
pub(super) fn record_attempt_failure(error: &pingora_core::Error, ctx: &mut PingoraRequestCtx) {
    if ctx.upstream_client_span.is_disabled() {
        return;
    }

    let error_type = bounded_upstream_error_type(error.etype());
    for span in [&ctx.upstream_exchange_span, &ctx.upstream_client_span] {
        span.record("otel.status_code", "ERROR");
        span.record("error.type", &error_type);
    }
    close_attempt(ctx);
}

/// Return a low-cardinality error type without exposing error context strings.
fn bounded_upstream_error_type(error: &pingora_core::ErrorType) -> String {
    use pingora_core::ErrorType;
    let error_type = match error {
        ErrorType::ConnectTimedout => "connect_timeout",
        ErrorType::ConnectRefused => "connect_refused",
        ErrorType::ConnectNoRoute => "connect_no_route",
        ErrorType::TLSHandshakeFailure => "tls_handshake_failure",
        ErrorType::TLSHandshakeTimedout => "tls_handshake_timeout",
        ErrorType::InvalidCert => "tls_certificate_invalid",
        ErrorType::ConnectionClosed => "connection_closed",
        ErrorType::ReadError => "read_error",
        ErrorType::ReadTimedout => "read_timeout",
        ErrorType::WriteError => "write_error",
        ErrorType::WriteTimedout => "write_timeout",
        ErrorType::H2Error | ErrorType::H2Downgrade | ErrorType::InvalidH2 => "http2_error",
        ErrorType::HTTPStatus(code) => return code.to_string(),
        _ => "upstream_error",
    };
    error_type.to_owned()
}

/// Drop the attempt's child spans, with the exchange ending before its client.
fn close_attempt(ctx: &mut PingoraRequestCtx) {
    let exchange_span = std::mem::replace(&mut ctx.upstream_exchange_span, Span::none());
    drop(exchange_span);
    let client_span = std::mem::replace(&mut ctx.upstream_client_span, Span::none());
    drop(client_span);
}

/// Create the HTTP client span for one proxy attempt.
fn make_client_span(parent: &Span, method: &str, address: &str, port: u16) -> Span {
    tracing::info_span!(
        parent: parent,
        "http_client_request",
        "otel.name" = method,
        "otel.kind" = "client",
        "otel.status_code" = tracing::field::Empty,
        "http.request.method" = method,
        "http.response.status_code" = tracing::field::Empty,
        "error.type" = tracing::field::Empty,
        "server.address" = address,
        "server.port" = port,
        "upstream.connection.reused" = tracing::field::Empty,
    )
}

/// Create the internal connection/exchange span below the attempt span.
fn make_exchange_span(client_span: &Span, address: &str, port: u16) -> Span {
    tracing::info_span!(
        parent: client_span,
        "upstream_exchange",
        "otel.name" = "upstream_exchange",
        "otel.status_code" = tracing::field::Empty,
        "error.type" = tracing::field::Empty,
        "upstream.address" = address,
        "upstream.port" = port,
        "upstream.connection.reused" = tracing::field::Empty,
        "upstream.tls.version" = tracing::field::Empty,
        "http.response.status_code" = tracing::field::Empty,
        "http.response.body.size" = tracing::field::Empty,
    )
}

/// Extract the upstream address string and port from an [`HttpPeer`].
///
/// Inet sockets yield the IP string and port; other socket types
/// yield `"unix"` and port 0.
fn peer_address_and_port(peer: &HttpPeer) -> (String, u16) {
    match peer._address.as_inet() {
        Some(inet) => (inet.ip().to_string(), inet.port()),
        None => ("unix".to_owned(), 0),
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
    clippy::field_reassign_with_default,
    clippy::too_many_lines,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn noop_when_request_span_disabled() {
        let mut ctx = PingoraRequestCtx::default();
        assert!(
            ctx.request_span.is_disabled(),
            "default request_span should be disabled"
        );

        let peer = make_peer("127.0.0.1:8080");
        open_attempt(&peer, &mut ctx);

        assert!(
            ctx.upstream_exchange_span.is_disabled(),
            "exchange span should remain disabled when request span is disabled"
        );
    }

    #[test]
    fn execute_with_new_connection_does_not_panic() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_span = tracing::info_span!("test_request", "http.response.status_code" = tracing::field::Empty,);

        let peer = make_peer("10.0.0.1:9090");
        open_attempt(&peer, &mut ctx);
        record_connected(false, None, &ctx);
    }

    #[test]
    fn execute_with_reused_connection_does_not_panic() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_span = tracing::info_span!("test_request");

        let peer = make_peer("10.0.0.1:8080");
        open_attempt(&peer, &mut ctx);
    }

    #[test]
    fn execute_with_tls_digest_does_not_panic() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_span = tracing::info_span!("test_request");

        let peer = make_peer("10.0.0.1:443");
        let digest = make_tls_digest("TLSv1.3");
        open_attempt(&peer, &mut ctx);
        record_connected(false, Some(&digest), &ctx);
    }

    #[test]
    fn execute_without_tls_digest_does_not_panic() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_span = tracing::info_span!("test_request");

        let peer = make_peer("10.0.0.1:80");
        open_attempt(&peer, &mut ctx);
        record_connected(false, None, &ctx);
    }

    #[test]
    fn execute_with_empty_ssl_digest_does_not_panic() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_span = tracing::info_span!("test_request");

        let peer = make_peer("10.0.0.1:443");
        let digest = Digest::default();
        open_attempt(&peer, &mut ctx);
        record_connected(false, Some(&digest), &ctx);
    }

    #[test]
    fn failed_attempt_retry_opens_fresh_client_and_exchange_spans() {
        let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).finish();
        tracing::subscriber::with_default(subscriber, || {
            let mut ctx = PingoraRequestCtx::default();
            ctx.request_span = tracing::info_span!("test_request");

            let peer = make_peer("10.0.0.1:8080");
            open_attempt(&peer, &mut ctx);
            let first_client_span_id = ctx.upstream_client_span.id().expect("client span should exist");
            let first_exchange_span_id = ctx.upstream_exchange_span.id().expect("exchange span should exist");

            record_attempt_failure(
                &pingora_core::Error::explain(
                    pingora_core::ErrorType::ConnectRefused,
                    "secret context must not be recorded",
                ),
                &mut ctx,
            );
            assert!(
                ctx.upstream_client_span.is_disabled(),
                "failed client span must be closed"
            );
            assert!(
                ctx.upstream_exchange_span.is_disabled(),
                "failed exchange span must be closed"
            );

            let peer2 = make_peer("10.0.0.2:9090");
            open_attempt(&peer2, &mut ctx);
            record_connected(true, None, &ctx);

            assert_ne!(ctx.upstream_client_span.id(), Some(first_client_span_id));
            assert_ne!(ctx.upstream_exchange_span.id(), Some(first_exchange_span_id));
            assert!(
                !ctx.upstream_exchange_span.is_disabled(),
                "exchange span should be created"
            );
        });
    }

    #[test]
    fn failed_connect_records_bounded_error_and_closes_attempt() {
        let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).finish();
        tracing::subscriber::with_default(subscriber, || {
            let mut ctx = PingoraRequestCtx::default();
            ctx.request_span = tracing::info_span!("test_request");
            open_attempt(&make_peer("10.0.0.1:8080"), &mut ctx);

            let error = pingora_core::Error::explain(
                pingora_core::ErrorType::ConnectRefused,
                "sensitive backend error detail",
            );
            record_attempt_failure(&error, &mut ctx);

            assert!(
                ctx.upstream_client_span.is_disabled(),
                "failed CLIENT span must be closed"
            );
            assert!(
                ctx.upstream_exchange_span.is_disabled(),
                "failed exchange span must be closed"
            );
            assert_eq!(bounded_upstream_error_type(error.etype()), "connect_refused");
            assert_ne!(bounded_upstream_error_type(error.etype()), error.to_string());
        });
    }

    #[test]
    fn peer_address_and_port_extracts_ip_and_port() {
        let peer = make_peer("192.168.1.100:3000");
        let (addr, port) = peer_address_and_port(&peer);

        assert_eq!(addr, "192.168.1.100", "should extract IP address");
        assert_eq!(port, 3000, "should extract port");
    }

    #[test]
    fn peer_address_and_port_ipv4_loopback() {
        let peer = make_peer("127.0.0.1:8080");
        let (addr, port) = peer_address_and_port(&peer);

        assert_eq!(addr, "127.0.0.1", "should extract IPv4 loopback address");
        assert_eq!(port, 8080, "should extract port");
    }

    #[test]
    fn peer_address_and_port_high_port() {
        let peer = make_peer("10.0.0.1:65535");
        let (addr, port) = peer_address_and_port(&peer);

        assert_eq!(addr, "10.0.0.1", "should extract IP address");
        assert_eq!(port, 65535, "should extract high port number");
    }

    #[test]
    fn peer_address_and_port_port_zero() {
        let peer = make_peer("10.0.0.1:0");
        let (addr, port) = peer_address_and_port(&peer);

        assert_eq!(addr, "10.0.0.1", "should extract IP address");
        assert_eq!(port, 0, "should extract port zero");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Create a test [`HttpPeer`] with the given address (no TLS).
    fn make_peer(address: &str) -> HttpPeer {
        HttpPeer::new(address, false, String::new())
    }

    /// Create a [`Digest`] with a TLS version for tests.
    fn make_tls_digest(version: &'static str) -> Digest {
        use std::sync::Arc;

        use pingora_core::protocols::tls::digest::SslDigest;

        let ssl = SslDigest::new("AES256-GCM-SHA384", version, None, None, Vec::new());
        Digest {
            ssl_digest: Some(Arc::new(ssl)),
            ..Digest::default()
        }
    }
}
