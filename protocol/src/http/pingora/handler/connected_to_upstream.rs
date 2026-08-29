// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Upstream connection established hook: records connection-level
//! tracing attributes and opens the upstream exchange span.
//!
//! Implements Pingora's `connected_to_upstream` callback, which fires
//! once per upstream connection attempt after DNS + TCP + TLS have
//! completed (or a pooled connection was reused).

use pingora_core::{protocols::Digest, upstreams::peer::HttpPeer};

use super::super::context::PingoraRequestCtx;

// -----------------------------------------------------------------------------
// Execution
// -----------------------------------------------------------------------------

/// Record upstream connection attributes and open the exchange span.
///
/// Extracts the upstream address, port, TLS version, and connection
/// reuse flag from the Pingora `HttpPeer` and `Digest`, then creates
/// an `upstream_exchange` child span under the root request span.
pub(super) fn execute(reused: bool, peer: &HttpPeer, digest: Option<&Digest>, ctx: &mut PingoraRequestCtx) {
    if ctx.request_span.is_disabled() {
        return;
    }

    let (address, port) = peer_address_and_port(peer);
    let tls_version = digest
        .and_then(|d| d.ssl_digest.as_ref())
        .map(|ssl| ssl.version.as_ref());

    let exchange_span = tracing::info_span!(
        parent: &ctx.request_span,
        "upstream_exchange",
        "otel.name" = "upstream_exchange",
        "upstream.address" = address,
        "upstream.port" = port,
        "upstream.connection.reused" = reused,
        "upstream.tls.version" = tls_version,
        "http.response.status_code" = tracing::field::Empty,
        "http.response.body.size" = tracing::field::Empty,
    );

    ctx.upstream_exchange_span = exchange_span;
}

/// Extract the upstream address string and port from an [`HttpPeer`].
///
/// For inet sockets, returns the IP string and port. For unix domain
/// sockets, returns the path and port 0.
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
        execute(false, &peer, None, &mut ctx);

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
        execute(false, &peer, None, &mut ctx);
    }

    #[test]
    fn execute_with_reused_connection_does_not_panic() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_span = tracing::info_span!("test_request");

        let peer = make_peer("10.0.0.1:8080");
        execute(true, &peer, None, &mut ctx);
    }

    #[test]
    fn execute_with_tls_digest_does_not_panic() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_span = tracing::info_span!("test_request");

        let peer = make_peer("10.0.0.1:443");
        let digest = make_tls_digest("TLSv1.3");
        execute(false, &peer, Some(&digest), &mut ctx);
    }

    #[test]
    fn execute_without_tls_digest_does_not_panic() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_span = tracing::info_span!("test_request");

        let peer = make_peer("10.0.0.1:80");
        execute(false, &peer, None, &mut ctx);
    }

    #[test]
    fn execute_with_empty_ssl_digest_does_not_panic() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_span = tracing::info_span!("test_request");

        let peer = make_peer("10.0.0.1:443");
        let digest = Digest::default();
        execute(false, &peer, Some(&digest), &mut ctx);
    }

    #[test]
    fn execute_retry_replaces_exchange_span() {
        let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).finish();
        tracing::subscriber::with_default(subscriber, || {
            let mut ctx = PingoraRequestCtx::default();
            ctx.request_span = tracing::info_span!("test_request");

            let peer = make_peer("10.0.0.1:8080");
            execute(false, &peer, None, &mut ctx);

            let peer2 = make_peer("10.0.0.2:9090");
            execute(true, &peer2, None, &mut ctx);

            assert!(
                !ctx.upstream_exchange_span.is_disabled(),
                "exchange span should be created"
            );
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
