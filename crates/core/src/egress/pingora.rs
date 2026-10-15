// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The Pingora network backend's egress: its connector, its sessions, and
//! the [`HttpPeer`] a [`PeerSpec`] becomes.
//!
//! [`HttpPeer`]: pingora_core::upstreams::peer::HttpPeer
//! [`PeerSpec`]: crate::egress::PeerSpec

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use pingora_core::{
    connectors::{ConnectorOptions, http::Connector as HttpConnector},
    protocols::http::{client::HttpSession, custom::client::Session as _},
    upstreams::peer::HttpPeer,
    utils::tls::WrappedX509,
};
use pingora_http::RequestHeader;

use super::{Completion, Connector, EgressError, PeerSpec, RequestHead, ResponseHead, Session};
use crate::connectivity::peer::{apply_cached_tls, apply_connection_options, ca_from_cached};

// -----------------------------------------------------------------------------
// HttpPeer
// -----------------------------------------------------------------------------

/// Build the Pingora peer for `spec`.
///
/// The peer dials exactly like a proxied request to the same cluster would:
/// same connection options, same cached TLS material. Runtime trust anchors
/// apply only when the cluster configured no CA of its own.
///
/// ```
/// use praxis_core::egress::{PeerSpec, pingora::http_peer};
///
/// let mut spec = PeerSpec::plain("127.0.0.1:8080".parse().unwrap());
/// spec.pool_group = 7;
///
/// let peer = http_peer(&spec);
/// assert_eq!(peer.group_key, 7);
/// ```
#[must_use]
pub fn http_peer(spec: &PeerSpec) -> HttpPeer {
    let mut peer = HttpPeer::new(spec.address, spec.tls, (*spec.sni).to_owned());
    peer.group_key = spec.pool_group;
    apply_connection_options(&mut peer, &spec.connection);

    if let Some(tls) = &spec.tls_config {
        apply_cached_tls(&mut peer, tls, &spec.address.to_string());
    }

    if spec.tls
        && peer.options.ca.is_none()
        && let Some(anchors) = &spec.trust_anchors
        && let Some(converted) =
            anchors.converted_or_init(|| -> Arc<[WrappedX509]> { Arc::from(ca_from_cached(anchors)) })
    {
        peer.options.ca = Some(Arc::clone(converted));
    }

    peer
}

// -----------------------------------------------------------------------------
// PingoraConnector
// -----------------------------------------------------------------------------

/// The Pingora connector: one shared [`HttpConnector`] and its pool.
///
/// ```
/// use praxis_core::egress::{Connector as _, pingora::PingoraConnector};
/// praxis_tls::provider::install(); // required before any connector is built
///
/// let connector = PingoraConnector::new(128);
/// let _clone = connector.clone();
/// ```
#[derive(Clone)]
pub struct PingoraConnector {
    /// Shared Pingora HTTP connector.
    pub(crate) inner: Arc<HttpConnector<()>>,
}

impl std::fmt::Debug for PingoraConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingoraConnector")
            .field("pool", &"Connector<()>")
            .finish()
    }
}

impl Connector for PingoraConnector {
    type Session = PingoraSession;

    fn new(keepalive_pool_size: usize) -> Self {
        let options = ConnectorOptions::new(keepalive_pool_size);
        Self {
            inner: Arc::new(HttpConnector::new(Some(options))),
        }
    }

    #[expect(
        clippy::large_stack_frames,
        clippy::large_futures,
        reason = "Pingora's session future is large and the caller already boxes the connect"
    )]
    async fn connect(&self, peer: &PeerSpec, timeout: Duration) -> Result<PingoraSession, EgressError> {
        let mut http_peer = http_peer(peer);
        clamp_peer_timeouts(&mut http_peer, timeout);

        let (inner, reused) = self
            .inner
            .get_http_session(&http_peer)
            .await
            .map_err(|err| EgressError::Connect(err.to_string()))?;

        Ok(PingoraSession {
            inner,
            peer: http_peer,
            reused,
        })
    }

    #[expect(clippy::large_stack_frames, reason = "Pingora's session types are large")]
    async fn release(&self, session: PingoraSession, keepalive: bool) {
        let PingoraSession { mut inner, peer, .. } = session;
        if keepalive {
            self.inner.release_http_session(inner, &peer, None).await;
            return;
        }

        inner.shutdown().await;
        // An H2 stream is one of many on its connection: releasing it keeps
        // the connection alive for the others. An H1 connection stays shut,
        // because unread bytes would corrupt the next response on it.
        if matches!(inner, HttpSession::H2(_)) {
            self.inner.release_http_session(inner, &peer, None).await;
        }
    }
}

// -----------------------------------------------------------------------------
// PingoraSession
// -----------------------------------------------------------------------------

/// One Pingora client session plus the peer it was opened for.
pub struct PingoraSession {
    /// The live Pingora session.
    inner: HttpSession<()>,

    /// The peer the session was opened for; the pool key on release.
    peer: HttpPeer,

    /// Whether the connection served a request before this one.
    reused: bool,
}

impl std::fmt::Debug for PingoraSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingoraSession")
            .field("peer", &self.peer)
            .field("reused", &self.reused)
            .finish_non_exhaustive()
    }
}

impl Session for PingoraSession {
    fn reused(&self) -> bool {
        self.reused
    }

    async fn send_request_head(&mut self, head: RequestHead) -> Result<(), EgressError> {
        let mut header = RequestHeader::build(head.method, head.target.as_bytes(), Some(head.headers.len()))
            .map_err(|err| EgressError::InvalidRequest(err.to_string()))?;

        for (name, value) in &head.headers {
            header
                .append_header(name.clone(), value.clone())
                .map_err(|err| EgressError::InvalidRequest(err.to_string()))?;
        }

        self.inner
            .write_request_header(Box::new(header))
            .await
            .map_err(|err| io_error(&err))
    }

    async fn send_request_body(&mut self, chunk: Bytes, end_of_stream: bool) -> Result<(), EgressError> {
        self.inner
            .write_request_body(chunk, end_of_stream)
            .await
            .map_err(|err| io_error(&err))
    }

    async fn finish_request(&mut self) -> Result<(), EgressError> {
        self.inner
            .finish_request_body()
            .await
            .map(|_finished| ())
            .map_err(|err| io_error(&err))
    }

    async fn read_response_head(&mut self) -> Result<(), EgressError> {
        self.inner.read_response_header().await.map_err(|err| io_error(&err))
    }

    fn response_head(&self) -> Result<ResponseHead<'_>, EgressError> {
        let header = self
            .inner
            .response_header()
            .ok_or_else(|| EgressError::Io("no response header received".to_owned()))?;

        Ok(ResponseHead {
            headers: &header.headers,
            status: header.status.as_u16(),
            version: header.version,
        })
    }

    fn response_done(&mut self) -> bool {
        self.inner.response_done()
    }

    async fn read_response_body(&mut self) -> Result<Option<Bytes>, EgressError> {
        self.inner.read_response_body().await.map_err(|err| io_error(&err))
    }

    fn completion(&mut self) -> Result<Completion, EgressError> {
        let finished = match &mut self.inner {
            HttpSession::H1(h1) => h1.is_body_done(),
            HttpSession::H2(h2) => h2.check_response_end_or_error().map_err(|err| io_error(&err))?,
            HttpSession::Custom(custom) => custom.response_finished(),
        };

        Ok(if finished {
            Completion::Finished
        } else {
            Completion::Incomplete
        })
    }

    fn clear_read_timeout(&mut self) {
        self.inner.set_read_timeout(None);
    }

    async fn shutdown(&mut self) {
        self.inner.shutdown().await;
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Clamp connection setup timeouts so they never outlive the exchange.
fn clamp_peer_timeouts(peer: &mut HttpPeer, timeout: Duration) {
    peer.options.connection_timeout = Some(bounded(peer.options.connection_timeout, timeout));
    peer.options.total_connection_timeout = Some(bounded(peer.options.total_connection_timeout, timeout));
}

/// Keep an operator-configured timeout when it is stricter than the exchange's.
fn bounded(configured: Option<Duration>, timeout: Duration) -> Duration {
    configured.map_or(timeout, |configured| configured.min(timeout))
}

/// Map a Pingora transport error onto the exchange error.
fn io_error(err: &pingora_core::Error) -> EgressError {
    EgressError::Io(err.to_string())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use praxis_tls::CachedCaCerts;

    use super::*;
    use crate::connectivity::ConnectionOptions;

    #[test]
    fn http_peer_carries_group_and_connection_options() {
        let mut spec = PeerSpec::plain("127.0.0.1:8080".parse().unwrap());
        spec.pool_group = 42;
        spec.connection = Arc::new(ConnectionOptions {
            read_timeout: Some(Duration::from_secs(3)),
            ..ConnectionOptions::default()
        });

        let peer = http_peer(&spec);

        assert_eq!(peer.group_key, 42, "the pool partition must become the group key");
        assert_eq!(
            peer.options.read_timeout,
            Some(Duration::from_secs(3)),
            "connection options must map onto the peer"
        );
        assert!(peer.options.ca.is_none(), "a plain peer carries no trust anchors");
    }

    #[test]
    fn trust_anchors_apply_to_tls_peers_without_a_cluster_ca() {
        let anchors = Arc::new(CachedCaCerts::new(vec![vec![1, 2, 3]]));
        let mut spec = PeerSpec::new("127.0.0.1:8443".parse().unwrap(), true, "upstream.test");
        spec.trust_anchors = Some(Arc::clone(&anchors));

        let peer = http_peer(&spec);

        assert!(
            peer.options.ca.is_some(),
            "runtime trust anchors must reach a TLS peer with no cluster CA"
        );

        let first = Arc::as_ptr(peer.options.ca.as_ref().unwrap());
        let second = Arc::as_ptr(http_peer(&spec).options.ca.as_ref().unwrap());
        assert_eq!(first, second, "the conversion must be memoized on the cached anchors");
    }

    #[test]
    fn trust_anchors_are_ignored_for_plain_peers() {
        let mut spec = PeerSpec::plain("127.0.0.1:8080".parse().unwrap());
        spec.trust_anchors = Some(Arc::new(CachedCaCerts::new(vec![vec![1, 2, 3]])));

        assert!(
            http_peer(&spec).options.ca.is_none(),
            "trust anchors mean nothing without TLS"
        );
    }

    #[test]
    fn a_tls_peer_without_cluster_tls_verifies_certificate_and_hostname() {
        let spec = PeerSpec::new("203.0.113.10:443".parse().unwrap(), true, "idp.example.com");

        let peer = http_peer(&spec);

        assert!(peer.options.verify_cert, "certificate verification stays on by default");
        assert!(
            peer.options.verify_hostname,
            "hostname verification stays on by default"
        );
        assert_eq!(peer.sni, "idp.example.com", "the server name carries over unchanged");
    }

    #[test]
    fn clamp_peer_timeouts_bounds_connection_setup() {
        let mut peer = HttpPeer::new("127.0.0.1:8080", false, String::new());
        peer.options.connection_timeout = Some(Duration::from_secs(1));
        peer.options.total_connection_timeout = Some(Duration::from_secs(20));

        clamp_peer_timeouts(&mut peer, Duration::from_secs(10));

        assert_eq!(
            peer.options.connection_timeout,
            Some(Duration::from_secs(1)),
            "a stricter operator timeout is kept"
        );
        assert_eq!(
            peer.options.total_connection_timeout,
            Some(Duration::from_secs(10)),
            "a looser operator timeout is cut to the exchange timeout"
        );
    }

    #[tokio::test]
    #[expect(clippy::too_many_lines, reason = "test setup and transport invariants")]
    async fn response_head_borrows_the_transport_headers() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        praxis_tls::provider::install();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = PeerSpec::plain(listener.local_addr().unwrap());
        let backend = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::with_capacity(4096);
            while !request.ends_with(b"\r\n\r\n") {
                assert_ne!(socket.read_buf(&mut request).await.unwrap(), 0, "complete request head");
            }
            socket
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\nX-Test: kept\r\n\r\n")
                .await
                .unwrap();
        });
        let connector = PingoraConnector::new(1);
        let mut session = Box::pin(connector.connect(&peer, Duration::from_secs(5)))
            .await
            .unwrap();
        assert!(matches!(session.response_head(), Err(EgressError::Io(_))));
        session
            .send_request_head(RequestHead {
                method: http::Method::GET,
                target: "/".to_owned(),
                headers: http::HeaderMap::new(),
            })
            .await
            .unwrap();
        session.finish_request().await.unwrap();
        session.read_response_head().await.unwrap();

        let head = session.response_head().unwrap();
        let transport = session.inner.response_header().unwrap();
        assert!(std::ptr::eq(head.headers, &transport.headers));
        assert_eq!(head.status, 204);
        assert_eq!(head.version, http::Version::HTTP_11);
        assert_eq!(head.headers.get("x-test").unwrap(), "kept");
        assert_eq!(head.headers.get("connection").unwrap(), "close");
        assert!(session.response_done(), "the original head still frames the response");
        Box::pin(connector.release(session, false)).await;
        backend.await.unwrap();
    }

    #[test]
    fn clones_share_one_pool() {
        praxis_tls::provider::install();
        let first = PingoraConnector::new(4);

        let second = first.clone();

        assert!(
            Arc::ptr_eq(&first.inner, &second.inner),
            "a cloned connector must share the pool"
        );
    }
}
