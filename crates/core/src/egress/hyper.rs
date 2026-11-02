// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The hyper backend's egress: its connector, sessions and connection pool.
//!
//! [`HyperConnector`] dials with hyper's HTTP/1 and HTTP/2 client
//! connections over tokio TCP, wrapped in `tokio-rustls` for TLS, and keeps
//! them in a pool Praxis owns instead of hyper-util's client. Each
//! [`HyperSession`] is one exchange on one of those connections. The hyper
//! HTTP adapter and the sub-request client each build a connector of this
//! type; sharing one pool between them is a follow-up.
//!
//! [`HyperConnector`]: crate::egress::hyper::HyperConnector
//! [`HyperSession`]: crate::egress::hyper::HyperSession

/// The request body hyper reads from a session.
mod body;
/// One upstream connection: dialing it, driving it, sharing it.
mod connection;
/// The bounded pool of idle and shared connections.
mod pool;
/// One HTTP exchange on a pooled connection.
mod session;
/// Upstream TLS: identities, cached client configs, server names.
mod tls;

use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use tokio::time::Instant;
use tracing::trace;

pub use self::session::HyperSession;
use self::{
    connection::{SetupTimeouts, dial},
    pool::{Pool, PoolKey},
    tls::TlsConfigs,
};
use super::{Connector, EgressError, PeerSpec};

// -----------------------------------------------------------------------------
// HyperConnector
// -----------------------------------------------------------------------------

/// The hyper connector: a Praxis-owned pool of HTTP/1 and HTTP/2 connections.
///
/// Clones share one pool. It keeps at most `keepalive_pool_size`
/// connections across every peer and lets the one unused longest go when
/// full; an idle connection closes after its cluster's idle timeout, and an
/// HTTP/1 connection the peer closed is never handed out again. An HTTP/2
/// connection is shared, one per pool key, by every exchange to that peer.
/// The pool key is the resolved address, server name, TLS on or off, pool
/// partition, configured HTTP version and the identity of the cluster's TLS
/// material, so connections never cross between peers with different trust.
///
/// Connection setup honours the cluster's connection timeouts, each cut to
/// the exchange timeout passed to [`connect`]; responses honour its read
/// timeout and sends its write timeout.
///
/// ```
/// use praxis_core::egress::{Connector as _, hyper::HyperConnector};
///
/// let connector = HyperConnector::new(128);
/// let _clone = connector.clone();
/// ```
///
/// [`connect`]: Connector::connect
#[derive(Clone)]
pub struct HyperConnector {
    /// What every clone shares.
    shared: Arc<Shared>,
}

impl Connector for HyperConnector {
    type Session = HyperSession;

    fn new(keepalive_pool_size: usize) -> Self {
        Self {
            shared: Arc::new(Shared {
                capacity: keepalive_pool_size,
                pool: Mutex::new(Pool::new(keepalive_pool_size)),
                tls: TlsConfigs::default(),
            }),
        }
    }

    async fn connect(&self, peer: &PeerSpec, timeout: Duration) -> Result<HyperSession, EgressError> {
        let key = PoolKey::new(peer);
        let pooled = self.shared.pool().checkout(&key, Instant::now());
        if let Some(connection) = pooled {
            trace!(peer = %peer.address, "reusing a pooled upstream connection");
            return Ok(HyperSession::new(connection, key, peer));
        }

        let timeouts = SetupTimeouts::new(&peer.connection, timeout);
        let connection = Box::pin(dial(peer, &self.shared.tls, timeouts)).await?;
        let shared = connection.share();
        let session = HyperSession::new(connection, key.clone(), peer);
        if let Some(shared) = shared {
            self.shared.pool().put(key, shared);
        }
        Ok(session)
    }

    async fn release(&self, session: HyperSession, keepalive: bool) {
        if let Some((key, connection)) = session.into_reusable(keepalive).await {
            self.shared.pool().put(key, connection);
        }
    }
}

impl fmt::Debug for HyperConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HyperConnector")
            .field("capacity", &self.shared.capacity)
            .finish_non_exhaustive()
    }
}

/// What every clone of a connector shares.
struct Shared {
    /// Most connections the pool keeps.
    capacity: usize,

    /// The pooled connections.
    pool: Mutex<Pool>,

    /// Upstream TLS client configs.
    tls: TlsConfigs,
}

impl Shared {
    /// Lock the pool, recovering it if a holder panicked.
    fn pool(&self) -> MutexGuard<'_, Pool> {
        self.pool.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// An error and its causes, outermost first, as one message.
fn describe(err: &(dyn std::error::Error + 'static)) -> String {
    std::iter::successors(Some(err), |err| err.source())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use std::{
        net::SocketAddr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Method, Version};
    use praxis_tls::{CachedCaCerts, CachedClusterTls, ClusterTls, ListenerTls, test_utils::TestCerts};
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
    use tokio::{
        io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
        sync::Notify,
        task::JoinHandle,
    };

    use super::*;
    use crate::{
        config::UpstreamHttpVersion,
        egress::{Completion, RequestHead, Session as _},
    };

    #[tokio::test]
    #[expect(clippy::too_many_lines, reason = "one exchange checked end to end")]
    async fn exchange_round_trips_head_and_body() {
        let upstream = Upstream::start(
            Mode::Answer,
            b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-test: kept\r\n\r\nhello",
        )
        .await;
        let connector = HyperConnector::new(4);
        let mut session = connector
            .connect(&upstream.peer(), Duration::from_secs(5))
            .await
            .unwrap();

        assert!(
            matches!(session.response_head(), Err(EgressError::Io(_))),
            "no head exists before the response arrives"
        );
        exchange(&mut session).await;
        let head = session.response_head().unwrap();
        assert_eq!(head.status, 200, "the status comes through");
        assert_eq!(head.version, Version::HTTP_11, "the response version comes through");
        assert_eq!(
            head.headers.get("x-test").unwrap(),
            "kept",
            "response headers come through"
        );
        assert!(!session.response_done(), "a body follows the head");
        assert_eq!(
            session.read_response_body().await.unwrap().unwrap(),
            "hello",
            "the body comes through"
        );
        assert!(session.response_done(), "the declared length was read");
        assert_eq!(
            session.completion().unwrap(),
            Completion::Finished,
            "the body ended cleanly"
        );
        assert!(
            session.read_response_body().await.unwrap().is_none(),
            "nothing follows the body"
        );
        assert_eq!(session.peer_address(), upstream.address, "the session names its peer");
        connector.release(session, true).await;
    }

    #[tokio::test]
    async fn second_exchange_reuses_the_pooled_connection() {
        let upstream = Upstream::start(Mode::Answer, OK).await;
        let connector = HyperConnector::new(4);

        let first = round_trip(&connector, &upstream.peer()).await;
        let second = round_trip(&connector, &upstream.peer()).await;

        assert!(!first, "the first exchange opens a fresh connection");
        assert!(second, "the second exchange rides the pooled connection");
        assert_eq!(upstream.accepted(), 1, "only one connection was opened");
    }

    #[tokio::test]
    async fn clones_share_one_pool() {
        let upstream = Upstream::start(Mode::Answer, OK).await;
        let connector = HyperConnector::new(4);
        let clone = connector.clone();

        round_trip(&connector, &upstream.peer()).await;

        assert!(
            round_trip(&clone, &upstream.peer()).await,
            "a clone reuses what the original pooled"
        );
        assert_eq!(upstream.accepted(), 1, "clones dial through the same pool");
    }

    #[tokio::test]
    async fn full_pool_evicts_the_oldest_connection() {
        let first = Upstream::start(Mode::Answer, OK).await;
        let second = Upstream::start(Mode::Answer, OK).await;
        let third = Upstream::start(Mode::Answer, OK).await;
        let connector = HyperConnector::new(2);

        for upstream in [&first, &second, &third] {
            round_trip(&connector, &upstream.peer()).await;
        }

        eventually(|| first.closed() == 1, "the oldest connection is closed when evicted").await;
        assert_eq!(second.closed() + third.closed(), 0, "the newer connections stay pooled");
        assert!(
            round_trip(&connector, &second.peer()).await,
            "a kept connection is reused"
        );
        assert!(
            !round_trip(&connector, &first.peer()).await,
            "the evicted peer needs a new connection"
        );
        assert_eq!(first.accepted(), 2, "the evicted peer was dialed again");
    }

    #[tokio::test]
    async fn idle_connection_closes_after_its_idle_timeout() {
        let upstream = Upstream::start(Mode::Answer, OK).await;
        let connector = HyperConnector::new(4);
        let mut peer = upstream.peer();
        Arc::make_mut(&mut peer.connection).idle_timeout = Some(Duration::from_millis(50));

        round_trip(&connector, &peer).await;

        eventually(|| upstream.closed() == 1, "the idle connection is closed").await;
        assert!(
            !round_trip(&connector, &peer).await,
            "an expired connection is not handed out"
        );
        assert_eq!(upstream.accepted(), 2, "a new connection replaces the expired one");
    }

    #[tokio::test]
    async fn connection_the_peer_closed_is_not_handed_out() {
        let upstream = Upstream::start(Mode::AnswerOnce, OK).await;
        let connector = HyperConnector::new(4);

        round_trip(&connector, &upstream.peer()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            !round_trip(&connector, &upstream.peer()).await,
            "a connection the peer closed must be discarded at checkout"
        );
        assert_eq!(upstream.accepted(), 2, "a new connection replaces the closed one");
    }

    #[tokio::test]
    async fn connection_closed_while_pooled_is_discarded_at_checkout() {
        let hang_up = Arc::new(Notify::new());
        let upstream = Upstream::start_hanging_up(Arc::clone(&hang_up)).await;
        let connector = HyperConnector::new(4);
        round_trip(&connector, &upstream.peer()).await;
        let pooled = connector.shared.pool().len();

        hang_up.notify_one();
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(pooled, 1, "the connection was pooled before the peer closed it");
        assert!(
            !round_trip(&connector, &upstream.peer()).await,
            "a connection the peer closed while pooled must be discarded at checkout"
        );
        assert_eq!(upstream.accepted(), 2, "a new connection replaces the closed one");
    }

    #[tokio::test]
    async fn response_announcing_close_is_not_pooled() {
        let upstream = Upstream::start(Mode::Answer, CLOSING).await;
        let connector = HyperConnector::new(4);

        round_trip(&connector, &upstream.peer()).await;

        eventually(
            || upstream.closed() == 1,
            "the connection the response announced as closing is closed",
        )
        .await;
        assert!(
            !round_trip(&connector, &upstream.peer()).await,
            "a connection announced as closing is never handed out again"
        );
        assert_eq!(upstream.accepted(), 2, "the next exchange dialed a new connection");
    }

    #[tokio::test]
    async fn stale_connection_failure_is_reported_on_a_reused_session() {
        let upstream = Upstream::start_hanging_up(Arc::new(Notify::new())).await;
        let connector = HyperConnector::new(4);
        round_trip(&connector, &upstream.peer()).await;
        let mut session = connector
            .connect(&upstream.peer(), Duration::from_secs(5))
            .await
            .unwrap();
        session.send_request_head(head(Method::GET)).await.unwrap();
        session.finish_request().await.unwrap();

        let result = session.read_response_head().await;

        assert!(session.reused(), "the failed exchange rode the pooled connection");
        assert!(
            matches!(&result, Err(EgressError::Io(_))),
            "a peer that closes on the next request fails the exchange: {result:?}"
        );
        assert!(
            matches!(session.completion(), Err(EgressError::Io(_))),
            "the failure is what the exchange completes with"
        );
    }

    #[tokio::test]
    async fn release_without_keepalive_closes_the_connection() {
        let upstream = Upstream::start(Mode::Answer, OK).await;
        let connector = HyperConnector::new(4);
        let mut session = connector
            .connect(&upstream.peer(), Duration::from_secs(5))
            .await
            .unwrap();
        exchange(&mut session).await;
        read_body(&mut session).await;

        connector.release(session, false).await;

        eventually(|| upstream.closed() == 1, "the upstream sees the connection close").await;
        assert!(!round_trip(&connector, &upstream.peer()).await, "nothing was pooled");
    }

    #[tokio::test]
    async fn release_with_keepalive_before_the_body_ends_does_not_pool() {
        let upstream = Upstream::start(Mode::Answer, UNFINISHED).await;
        let connector = HyperConnector::new(4);
        let mut session = connector
            .connect(&upstream.peer(), Duration::from_secs(5))
            .await
            .unwrap();
        exchange(&mut session).await;

        connector.release(session, true).await;
        let pooled = connector.shared.pool().len();
        let next = connector
            .connect(&upstream.peer(), Duration::from_secs(5))
            .await
            .unwrap();

        assert_eq!(pooled, 0, "a connection with an unread body is not pooled");
        assert!(!next.reused(), "the next exchange gets a fresh connection");
        eventually(|| upstream.closed() == 1, "the abandoned connection is closed").await;
    }

    #[tokio::test]
    async fn dropped_session_closes_its_http1_connection() {
        let upstream = Upstream::start(Mode::Answer, UNFINISHED).await;
        let connector = HyperConnector::new(4);
        let mut session = connector
            .connect(&upstream.peer(), Duration::from_secs(5))
            .await
            .unwrap();
        exchange(&mut session).await;
        assert_eq!(
            session.read_response_body().await.unwrap().unwrap(),
            "hello",
            "the first chunk arrives"
        );

        drop(session);

        eventually(
            || upstream.closed() == 1,
            "a dropped session must not strand its connection",
        )
        .await;
    }

    #[tokio::test]
    async fn interim_heads_come_back_before_the_final_one() {
        let upstream = Upstream::start(
            Mode::Answer,
            b"HTTP/1.1 103 Early Hints\r\nlink: </app.css>\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
        )
        .await;
        let connector = HyperConnector::new(4);
        let mut session = connector
            .connect(&upstream.peer(), Duration::from_secs(5))
            .await
            .unwrap();

        exchange(&mut session).await;
        let interim = session.response_head().unwrap();
        assert_eq!(interim.status, 103, "the interim head comes first");
        assert_eq!(
            interim.headers.get("link").unwrap(),
            "</app.css>",
            "with its own headers"
        );
        session.read_response_head().await.unwrap();

        assert_eq!(session.response_head().unwrap().status, 204, "the final head follows");
        assert!(session.response_done(), "a 204 has no body");
        assert!(
            matches!(session.read_response_head().await, Err(EgressError::Io(_))),
            "no head follows the final one"
        );
    }

    #[tokio::test]
    async fn read_timeout_expires_with_a_named_error() {
        let upstream = Upstream::start(Mode::Stall, OK).await;
        let connector = HyperConnector::new(4);
        let mut peer = upstream.peer();
        Arc::make_mut(&mut peer.connection).read_timeout = Some(Duration::from_millis(50));
        let mut session = connector.connect(&peer, Duration::from_secs(5)).await.unwrap();
        session.send_request_head(head(Method::GET)).await.unwrap();
        session.finish_request().await.unwrap();

        let result = session.read_response_head().await;

        assert!(
            matches!(&result, Err(EgressError::Io(message)) if message.contains("read timeout")),
            "a silent upstream must trip the read timeout: {result:?}"
        );
    }

    #[tokio::test]
    async fn write_timeout_expires_with_a_named_error() {
        let upstream = Upstream::start(Mode::Stall, OK).await;
        let connector = HyperConnector::new(4);
        let mut peer = upstream.peer();
        Arc::make_mut(&mut peer.connection).write_timeout = Some(Duration::from_millis(100));
        let mut session = connector.connect(&peer, Duration::from_secs(5)).await.unwrap();
        session.send_request_head(head(Method::POST)).await.unwrap();
        let chunk = Bytes::from(vec![0_u8; 1_048_576]);

        let mut result = Ok(());
        for _ in 0..512 {
            result = session.send_request_body(chunk.clone(), false).await;
            if result.is_err() {
                break;
            }
        }

        assert!(
            matches!(&result, Err(EgressError::Io(message)) if message.contains("write timeout")),
            "an upstream that stops reading must trip the write timeout: {result:?}"
        );
    }

    #[tokio::test]
    async fn request_body_sends_wait_until_the_upstream_reads() {
        let release = Arc::new(Notify::new());
        let upstream = Upstream::start_held(Arc::clone(&release)).await;
        let connector = HyperConnector::new(4);
        let mut session = connector
            .connect(&upstream.peer(), Duration::from_secs(5))
            .await
            .unwrap();
        session.send_request_head(head(Method::POST)).await.unwrap();
        let chunk = Bytes::from(vec![0_u8; CHUNK_SIZE]);

        let mut accepted = 0_usize;
        let waiting = loop {
            let mut send = Box::pin(session.send_request_body(chunk.clone(), false));
            if tokio::time::timeout(STALL, &mut send).await.is_err() {
                break Some(send);
            }
            accepted = accepted.saturating_add(1);
            if accepted == MAX_CHUNKS {
                break None;
            }
        };
        let mut waiting = waiting.expect("a send must start waiting once the upstream stops reading");
        release.notify_one();
        let resumed = tokio::time::timeout(Duration::from_secs(10), &mut waiting).await;

        assert!(
            matches!(resumed, Ok(Ok(()))),
            "the waiting send goes through once the upstream reads, after {accepted} chunks: {resumed:?}"
        );
    }

    #[tokio::test]
    async fn total_connection_timeout_bounds_the_tls_handshake() {
        praxis_tls::provider::install();
        let upstream = Upstream::start(Mode::Stall, OK).await;
        let connector = HyperConnector::new(4);
        let mut peer = PeerSpec::new(upstream.address, true, "localhost");
        peer.tls_config = Some(unverified_tls());
        Arc::make_mut(&mut peer.connection).total_connection_timeout = Some(Duration::from_millis(100));

        let result = connector.connect(&peer, Duration::from_secs(5)).await;

        assert!(
            matches!(&result, Err(EgressError::Connect(message)) if message.contains("total connection timeout")),
            "a stalled handshake must trip the total connection timeout: {result:?}"
        );
    }

    #[tokio::test]
    async fn refused_connection_is_a_connect_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let result = HyperConnector::new(4)
            .connect(&PeerSpec::plain(address), Duration::from_secs(5))
            .await;

        assert!(
            matches!(result, Err(EgressError::Connect(_))),
            "nothing listening must fail the connect: {result:?}"
        );
    }

    #[tokio::test]
    async fn request_trailers_are_refused_on_http1() {
        let upstream = Upstream::start(Mode::Answer, OK).await;
        let connector = HyperConnector::new(4);
        let mut session = connector
            .connect(&upstream.peer(), Duration::from_secs(5))
            .await
            .unwrap();
        session.send_request_head(head(Method::POST)).await.unwrap();

        let result = session.send_request_trailers(HeaderMap::new()).await;

        assert!(
            matches!(result, Err(EgressError::InvalidRequest(_))),
            "HTTP/1 cannot carry request trailers here: {result:?}"
        );
    }

    #[tokio::test]
    #[expect(clippy::too_many_lines, reason = "one exchange checked end to end")]
    async fn http2_prior_knowledge_round_trips_with_trailers() {
        let upstream = Upstream::start_h2().await;
        let connector = HyperConnector::new(4);
        let mut peer = upstream.peer();
        Arc::make_mut(&mut peer.connection).http_version = UpstreamHttpVersion::H2;
        let mut session = connector.connect(&peer, Duration::from_secs(5)).await.unwrap();

        exchange(&mut session).await;

        assert_eq!(
            session.negotiated_version(),
            Version::HTTP_2,
            "prior knowledge speaks HTTP/2"
        );
        let head = session.response_head().unwrap();
        assert_eq!(head.status, 200, "the status comes through");
        assert_eq!(
            head.headers.get("x-scheme").unwrap(),
            "http",
            "plain TCP sends the http scheme"
        );
        assert_eq!(
            head.headers.get("x-authority").unwrap(),
            "upstream.test",
            "the Host header becomes the authority"
        );
        assert_eq!(read_body(&mut session).await, b"got:0", "the body comes through");
        assert_eq!(
            session.take_trailers().unwrap().get("grpc-status").unwrap(),
            "0",
            "response trailers are kept for the caller"
        );
        assert_eq!(
            session.completion().unwrap(),
            Completion::Finished,
            "the stream ended cleanly"
        );
        connector.release(session, true).await;

        assert!(
            round_trip(&connector, &peer).await,
            "the next stream shares the connection"
        );
        assert_eq!(upstream.accepted(), 1, "HTTP/2 streams multiplex on one connection");
    }

    #[tokio::test]
    async fn http2_streams_request_bodies_and_trailers() {
        let upstream = Upstream::start_h2().await;
        let connector = HyperConnector::new(4);
        let mut peer = upstream.peer();
        Arc::make_mut(&mut peer.connection).http_version = UpstreamHttpVersion::H2;
        let mut session = connector.connect(&peer, Duration::from_secs(5)).await.unwrap();
        let mut trailers = HeaderMap::new();
        trailers.insert("x-checksum", HeaderValue::from_static("abc"));

        session.send_request_head(head(Method::POST)).await.unwrap();
        session
            .send_request_body(Bytes::from_static(b"abc"), false)
            .await
            .unwrap();
        session
            .send_request_body(Bytes::from_static(b"def"), false)
            .await
            .unwrap();
        session.send_request_trailers(trailers).await.unwrap();
        session.read_response_head().await.unwrap();

        assert_eq!(read_body(&mut session).await, b"got:6", "every streamed chunk arrived");
        assert_eq!(
            session.take_trailers().unwrap().get("x-checksum").unwrap(),
            "abc",
            "the request trailers reached the upstream"
        );
    }

    #[tokio::test]
    async fn http2_connection_carries_concurrent_sessions() {
        let upstream = Upstream::start_h2().await;
        let connector = HyperConnector::new(4);
        let mut peer = upstream.peer();
        Arc::make_mut(&mut peer.connection).http_version = UpstreamHttpVersion::H2;
        let mut first = connector.connect(&peer, Duration::from_secs(5)).await.unwrap();
        first.send_request_head(head(Method::POST)).await.unwrap();
        first
            .send_request_body(Bytes::from_static(b"abc"), false)
            .await
            .unwrap();

        let mut second = connector.connect(&peer, Duration::from_secs(5)).await.unwrap();
        exchange(&mut second).await;
        let second_body = read_body(&mut second).await;
        first.finish_request().await.unwrap();
        first.read_response_head().await.unwrap();

        assert!(!first.reused(), "the first session opened the connection");
        assert!(second.reused(), "the second session joined it while the first was open");
        assert_eq!(second_body, b"got:0", "the second stream finished first");
        assert_eq!(
            read_body(&mut first).await,
            b"got:3",
            "the first stream finished after it"
        );
        assert_eq!(upstream.accepted(), 1, "both sessions shared one connection");
    }

    #[tokio::test]
    async fn tls_round_trip_verifies_against_the_cluster_ca() {
        praxis_tls::provider::install();
        let certs = praxis_tls::test_utils::gen_test_certs();
        let upstream = Upstream::start_tls(&certs).await;
        let connector = HyperConnector::new(4);
        let mut peer = PeerSpec::new(upstream.address, true, "localhost");
        peer.tls_config = Some(trusting_tls(&certs));
        let mut session = connector.connect(&peer, Duration::from_secs(5)).await.unwrap();

        exchange(&mut session).await;

        assert_eq!(
            session.response_head().unwrap().status,
            200,
            "the exchange completes over TLS"
        );
        assert!(session.tls_protocol_version().is_some(), "the TLS version is reported");
        assert_eq!(
            session.negotiated_version(),
            Version::HTTP_11,
            "an HTTP/1 cluster offers only http/1.1"
        );
        assert_eq!(read_body(&mut session).await, b"ok", "the body comes through");
        connector.release(session, true).await;
        assert!(round_trip(&connector, &peer).await, "TLS connections are pooled too");
    }

    #[tokio::test]
    async fn tls_negotiates_http2_through_alpn() {
        praxis_tls::provider::install();
        let certs = praxis_tls::test_utils::gen_test_certs();
        let upstream = Upstream::start_tls(&certs).await;
        let connector = HyperConnector::new(4);
        let mut peer = PeerSpec::new(upstream.address, true, "localhost");
        peer.tls_config = Some(trusting_tls(&certs));
        Arc::make_mut(&mut peer.connection).http_version = UpstreamHttpVersion::Auto;
        let mut session = connector.connect(&peer, Duration::from_secs(5)).await.unwrap();

        exchange(&mut session).await;

        assert_eq!(session.negotiated_version(), Version::HTTP_2, "the server picked h2");
        assert_eq!(
            session.response_head().unwrap().headers.get("x-scheme").unwrap(),
            "https",
            "TLS sends the https scheme"
        );
    }

    #[tokio::test]
    async fn tls_refuses_a_certificate_it_cannot_verify() {
        praxis_tls::provider::install();
        let certs = praxis_tls::test_utils::gen_test_certs();
        let upstream = Upstream::start_tls(&certs).await;
        let peer = PeerSpec::new(upstream.address, true, "localhost");

        let result = HyperConnector::new(4).connect(&peer, Duration::from_secs(5)).await;

        assert!(
            matches!(&result, Err(EgressError::Connect(message)) if message.contains("TLS handshake")),
            "a certificate from an untrusted CA must fail the handshake: {result:?}"
        );
    }

    #[tokio::test]
    async fn unverified_tls_accepts_an_untrusted_certificate() {
        praxis_tls::provider::install();
        let certs = praxis_tls::test_utils::gen_test_certs();
        let upstream = Upstream::start_tls(&certs).await;
        let mut peer = PeerSpec::new(upstream.address, true, "localhost");
        peer.tls_config = Some(unverified_tls());

        assert!(
            !round_trip(&HyperConnector::new(4), &peer).await,
            "verification off lets the handshake through"
        );
    }

    #[tokio::test]
    async fn unverified_tls_accepts_a_self_signed_certificate() {
        praxis_tls::provider::install();
        let certs = self_signed_certs();
        let upstream = Upstream::start_tls(&certs).await;
        let connector = HyperConnector::new(4);

        let refused = connector
            .connect(
                &PeerSpec::new(upstream.address, true, "localhost"),
                Duration::from_secs(5),
            )
            .await;
        let reused = round_trip(&connector, &upstream.tls_peer("localhost", unverified_tls())).await;

        assert!(
            matches!(&refused, Err(EgressError::Connect(message)) if message.contains("invalid peer certificate")),
            "a verifying peer refuses the self-signed certificate: {refused:?}"
        );
        assert!(!reused, "verification off accepts the self-signed certificate");
        assert_eq!(
            upstream.named_handshakes(),
            1,
            "the DNS server name still goes out as SNI with verification off"
        );
    }

    #[tokio::test]
    async fn unverified_connection_never_serves_a_verifying_peer() {
        praxis_tls::provider::install();
        let certs = praxis_tls::test_utils::gen_test_certs();
        let stranger = praxis_tls::test_utils::gen_test_certs();
        let upstream = Upstream::start_tls(&certs).await;
        let connector = HyperConnector::new(4);
        round_trip(&connector, &upstream.tls_peer("localhost", unverified_tls())).await;

        let result = connector
            .connect(
                &upstream.tls_peer("localhost", trusting_tls(&stranger)),
                Duration::from_secs(5),
            )
            .await;

        assert!(
            matches!(&result, Err(EgressError::Connect(message)) if message.contains("invalid peer certificate")),
            "a verifying peer must verify its own connection, not reuse an unverified one: {result:?}"
        );
        assert_eq!(upstream.accepted(), 2, "the verifying peer dialed for itself");
    }

    #[tokio::test]
    async fn separately_loaded_tls_material_never_shares_a_connection() {
        praxis_tls::provider::install();
        let certs = praxis_tls::test_utils::gen_test_certs();
        let upstream = Upstream::start_tls(&certs).await;
        let connector = HyperConnector::new(4);
        let first = upstream.tls_peer("localhost", trusting_tls(&certs));
        let second = upstream.tls_peer("localhost", trusting_tls(&certs));

        round_trip(&connector, &first).await;

        assert!(
            !round_trip(&connector, &second).await,
            "another cluster's TLS material gets its own connection"
        );
        assert!(
            round_trip(&connector, &first).await,
            "each cluster still reuses its own connection"
        );
        assert_eq!(upstream.accepted(), 2, "one connection per cluster");
    }

    #[tokio::test]
    async fn cluster_ca_takes_precedence_over_runtime_trust_anchors() {
        praxis_tls::provider::install();
        let certs = praxis_tls::test_utils::gen_test_certs();
        let stranger = praxis_tls::test_utils::gen_test_certs();
        let upstream = Upstream::start_tls(&certs).await;
        let connector = HyperConnector::new(4);
        let mut trusted = upstream.tls_peer("localhost", trusting_tls(&certs));
        trusted.trust_anchors = Some(anchors(&stranger));
        let mut distrusted = upstream.tls_peer("localhost", trusting_tls(&stranger));
        distrusted.trust_anchors = Some(anchors(&certs));

        let refused = connector.connect(&distrusted, Duration::from_secs(5)).await;

        assert!(
            matches!(&refused, Err(EgressError::Connect(message)) if message.contains("invalid peer certificate")),
            "runtime anchors that trust the upstream must not override a cluster CA that does not: {refused:?}"
        );
        assert!(
            !round_trip(&connector, &trusted).await,
            "a cluster CA that trusts the upstream is enough, whatever the runtime anchors say"
        );
    }

    #[tokio::test]
    async fn runtime_trust_anchors_verify_a_cluster_without_its_own_ca() {
        praxis_tls::provider::install();
        let certs = praxis_tls::test_utils::gen_test_certs();
        let upstream = Upstream::start_tls(&certs).await;
        let mut peer = PeerSpec::new(upstream.address, true, "localhost");
        peer.trust_anchors = Some(anchors(&certs));

        assert!(
            !round_trip(&HyperConnector::new(4), &peer).await,
            "the runtime anchors verify an upstream whose cluster names no CA"
        );
    }

    #[tokio::test]
    async fn strict_http2_refuses_tls_without_alpn_but_auto_falls_back() {
        praxis_tls::provider::install();
        let certs = praxis_tls::test_utils::gen_test_certs();
        let upstream = Upstream::start_tls_with_alpn(&certs, false).await;
        let mut peer = upstream.tls_peer("localhost", trusting_tls(&certs));
        let connector = HyperConnector::new(4);
        Arc::make_mut(&mut peer.connection).http_version = UpstreamHttpVersion::H2;
        let result = connector.connect(&peer, Duration::from_secs(5)).await;
        assert!(
            matches!(result, Err(EgressError::Connect(message)) if message.contains("ALPN h2")),
            "strict HTTP/2 must fail before sending an HTTP/1 request"
        );
        Arc::make_mut(&mut peer.connection).http_version = UpstreamHttpVersion::Auto;
        let mut session = connector.connect(&peer, Duration::from_secs(5)).await.unwrap();
        assert_eq!(
            session.negotiated_version(),
            Version::HTTP_11,
            "auto can use HTTP/1 without ALPN"
        );
        exchange(&mut session).await;
        assert_eq!(
            read_body(&mut session).await,
            b"ok",
            "the fallback serves a real request"
        );
    }

    #[tokio::test]
    async fn tls_refuses_a_certificate_for_another_name() {
        praxis_tls::provider::install();
        let certs = praxis_tls::test_utils::gen_test_certs();
        let upstream = Upstream::start_tls(&certs).await;
        let peer = upstream.tls_peer("other.test", trusting_tls(&certs));

        let result = HyperConnector::new(4).connect(&peer, Duration::from_secs(5)).await;

        assert!(
            matches!(&result, Err(EgressError::Connect(message)) if message.contains("not valid for name")),
            "a trusted certificate issued for another name must fail the handshake: {result:?}"
        );
    }

    #[tokio::test]
    async fn ip_literal_server_name_is_not_matched_against_dns_names() {
        praxis_tls::provider::install();
        let certs = praxis_tls::test_utils::gen_test_certs();
        let upstream = Upstream::start_tls(&certs).await;
        let peer = upstream.tls_peer("127.0.0.1", trusting_tls(&certs));

        let result = HyperConnector::new(4).connect(&peer, Duration::from_secs(5)).await;

        assert!(
            matches!(&result, Err(EgressError::Connect(message)) if message.contains("not valid for name")),
            "a certificate naming only localhost does not cover 127.0.0.1: {result:?}"
        );
    }

    #[tokio::test]
    async fn ip_literal_server_name_connects_without_verification() {
        praxis_tls::provider::install();
        let certs = praxis_tls::test_utils::gen_test_certs();
        let upstream = Upstream::start_tls(&certs).await;
        let peer = upstream.tls_peer("127.0.0.1", unverified_tls());

        assert!(
            !round_trip(&HyperConnector::new(4), &peer).await,
            "an IP server name completes the handshake and the exchange"
        );
    }

    #[tokio::test]
    async fn ip_literal_server_name_is_verified_against_an_ip_san() {
        praxis_tls::provider::install();
        let certs = ip_san_certs();
        let upstream = Upstream::start_tls(&certs).await;
        let connector = HyperConnector::new(4);
        let peer = upstream.tls_peer("127.0.0.1", trusting_tls(&certs));

        let reused = round_trip(&connector, &peer).await;

        assert!(!reused, "a trusted certificate whose IP SAN matches verifies");
        assert_eq!(
            upstream.named_handshakes(),
            0,
            "rustls sends no SNI for an IP server name"
        );
    }

    #[test]
    fn describe_joins_an_error_and_its_causes() {
        let error = Wrapped(std::io::Error::other("socket reset"));

        assert_eq!(
            describe(&error),
            "request failed: socket reset",
            "every cause is named, outermost first"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// The request body chunk the backpressure test sends.
    const CHUNK_SIZE: usize = 1_048_576; // 1 MiB

    /// A `200 OK` announcing that the connection closes after it.
    const CLOSING: &[u8] = b"HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: 2\r\n\r\nok";

    /// Most chunks sent before a send must have started waiting.
    const MAX_CHUNKS: usize = 256; // 256 MiB in 1 MiB chunks

    /// A plain `200 OK` with a two-byte body.
    const OK: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";

    /// How long a send may take before it counts as waiting.
    const STALL: Duration = Duration::from_millis(200); // 200 ms

    /// A chunked `200 OK` whose body never ends.
    const UNFINISHED: &[u8] = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n";

    /// How a test upstream treats its connections.
    #[derive(Clone, Copy, Debug)]
    enum Mode {
        /// Answer every request and keep the connection open.
        Answer,

        /// Answer one request, then close the connection.
        AnswerOnce,

        /// Hold the connection without reading or answering.
        Stall,
    }

    /// A local upstream that counts the connections it sees.
    struct Upstream {
        /// Connections accepted.
        accepted: Arc<AtomicUsize>,

        /// Where it listens.
        address: SocketAddr,

        /// Connections the client closed.
        closed: Arc<AtomicUsize>,

        /// TLS handshakes whose client sent a server name (SNI).
        named_handshakes: Arc<AtomicUsize>,

        /// The accept loop.
        task: JoinHandle<()>,
    }

    impl Upstream {
        /// Connections accepted so far.
        fn accepted(&self) -> usize {
            self.accepted.load(Ordering::SeqCst)
        }

        /// Connections the client has closed so far.
        fn closed(&self) -> usize {
            self.closed.load(Ordering::SeqCst)
        }

        /// Accept connections and hand each to `serve`.
        async fn listen<S, F>(serve: S) -> Self
        where
            S: Fn(TcpStream, Arc<AtomicUsize>) -> F + Send + 'static,
            F: Future<Output = ()> + Send + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let accepted = Arc::new(AtomicUsize::new(0));
            let closed = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&accepted);
            let closes = Arc::clone(&closed);
            let task = tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    counted.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(serve(socket, Arc::clone(&closes)));
                }
            });
            Self {
                accepted,
                address,
                closed,
                named_handshakes: Arc::new(AtomicUsize::new(0)),
                task,
            }
        }

        /// TLS handshakes completed so far whose client sent a server name.
        fn named_handshakes(&self) -> usize {
            self.named_handshakes.load(Ordering::SeqCst)
        }

        /// A plain peer for this upstream.
        fn peer(&self) -> PeerSpec {
            PeerSpec::plain(self.address)
        }

        /// An HTTP/1 upstream answering every request with `response`.
        async fn start(mode: Mode, response: &'static [u8]) -> Self {
            Self::listen(move |socket, closed| async move { serve_http1(socket, mode, response, closed).await }).await
        }

        /// A prior-knowledge HTTP/2 upstream that echoes what it received.
        async fn start_h2() -> Self {
            Self::listen(|socket, _closed| serve_h2(socket)).await
        }

        /// An HTTP/1 upstream that answers the first request on each
        /// connection with `OK`, then closes the connection once `hang_up`
        /// is notified or the next request arrives.
        async fn start_hanging_up(hang_up: Arc<Notify>) -> Self {
            Self::listen(move |socket, _closed| answer_then_hang_up(socket, Arc::clone(&hang_up))).await
        }

        /// An upstream that reads nothing until `release` is notified, then
        /// reads everything it is sent and never answers.
        async fn start_held(release: Arc<Notify>) -> Self {
            Self::listen(move |socket, _closed| read_once_released(socket, Arc::clone(&release))).await
        }

        /// A TLS upstream with the generated certificate, speaking HTTP/2
        /// when ALPN picks it and HTTP/1.1 otherwise, and counting the
        /// handshakes that carried a server name.
        async fn start_tls(certs: &TestCerts) -> Self {
            Self::start_tls_with_alpn(certs, true).await
        }

        /// The test upstream's certificate and optional ALPN advertisement.
        fn tls_acceptor(certs: &TestCerts, alpn: bool) -> tokio_rustls::TlsAcceptor {
            let tls = ListenerTls::new_validated(certs.cert_path.to_str().unwrap(), certs.key_path.to_str().unwrap())
                .unwrap();
            let mut config = praxis_tls::setup::build_server_config(&tls, true).unwrap();
            if !alpn {
                Arc::make_mut(&mut config).alpn_protocols.clear();
            }
            tokio_rustls::TlsAcceptor::from(config)
        }

        /// A TLS upstream with optional ALPN advertisement.
        async fn start_tls_with_alpn(certs: &TestCerts, alpn: bool) -> Self {
            let acceptor = Self::tls_acceptor(certs, alpn);
            let named_handshakes = Arc::new(AtomicUsize::new(0));
            let named = Arc::clone(&named_handshakes);
            let mut upstream = Self::listen(move |socket, closed| {
                let acceptor = acceptor.clone();
                let named = Arc::clone(&named);
                async move {
                    let Ok(stream) = acceptor.accept(socket).await else {
                        return;
                    };
                    if stream.get_ref().1.server_name().is_some() {
                        named.fetch_add(1, Ordering::SeqCst);
                    }
                    if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
                        serve_h2(stream).await;
                    } else {
                        serve_http1(stream, Mode::Answer, OK, closed).await;
                    }
                }
            })
            .await;
            upstream.named_handshakes = named_handshakes;
            upstream
        }

        /// A TLS peer for this upstream, verified against `sni` with
        /// `tls_config`.
        fn tls_peer(&self, sni: &str, tls_config: CachedClusterTls) -> PeerSpec {
            let mut peer = PeerSpec::new(self.address, true, sni);
            peer.tls_config = Some(tls_config);
            peer
        }
    }

    impl Drop for Upstream {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// An error with a cause, for [`describe`].
    ///
    /// [`describe`]: describe
    #[derive(Debug, thiserror::Error)]
    #[error("request failed")]
    struct Wrapped(#[source] std::io::Error);

    /// Runtime trust anchors loaded from the generated CA.
    fn anchors(certs: &TestCerts) -> Arc<CachedCaCerts> {
        Arc::new(CachedCaCerts::from_pem_file(certs.ca_cert_path.to_str().unwrap()).unwrap())
    }

    /// Answer the first request on `stream` with `OK`, then hold the
    /// connection until `hang_up` is notified or more bytes arrive, and
    /// close it.
    async fn answer_then_hang_up(mut stream: TcpStream, hang_up: Arc<Notify>) {
        let mut request = Vec::with_capacity(1024);
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            if stream.read_buf(&mut request).await.unwrap_or(0) == 0 {
                return;
            }
        }
        stream.write_all(OK).await.unwrap();

        let mut next = vec![0_u8; 1024];
        tokio::select! {
            () = hang_up.notified() => {},
            _read = stream.read(&mut next) => {},
        }
    }

    /// Wait up to two seconds for `condition`.
    async fn eventually<F: Fn() -> bool>(condition: F, what: &str) {
        for _ in 0..200 {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(condition(), "timed out waiting: {what}");
    }

    /// Send a bodiless GET and read the first response head.
    async fn exchange(session: &mut HyperSession) {
        session.send_request_head(head(Method::GET)).await.unwrap();
        session.finish_request().await.unwrap();
        session.read_response_head().await.unwrap();
    }

    /// A request head for `/` with the `Host` the tests expect.
    fn head(method: Method) -> RequestHead {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, HeaderValue::from_static("upstream.test"));
        RequestHead {
            headers,
            method,
            target: "/".to_owned(),
        }
    }

    /// A fresh CA and a server certificate it issued for `127.0.0.1` alone,
    /// as an IP SAN with no DNS name.
    fn ip_san_certs() -> TestCerts {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "IP SAN Test CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
        server_params.distinguished_name.push(DnType::CommonName, "127.0.0.1");
        let server = server_params.signed_by(&server_key, &issuer).unwrap();
        write_certs(&ca.pem(), &server.pem(), &server_key.serialize_pem())
    }

    /// Read the rest of the response body.
    async fn read_body(session: &mut HyperSession) -> Vec<u8> {
        let mut body = Vec::new();
        while let Some(chunk) = session.read_response_body().await.unwrap() {
            body.extend_from_slice(&chunk);
        }
        body
    }

    /// Read nothing from `stream` until `release` is notified, then read
    /// whatever arrives until the client closes.
    async fn read_once_released(mut stream: TcpStream, release: Arc<Notify>) {
        release.notified().await;
        let mut sink = vec![0_u8; 65_536]; // 64 KiB
        while stream.read(&mut sink).await.unwrap_or(0) > 0 {}
    }

    /// Run one full exchange to `peer` and release it with keepalive;
    /// returns whether the connection was reused.
    async fn round_trip(connector: &HyperConnector, peer: &PeerSpec) -> bool {
        let mut session = connector.connect(peer, Duration::from_secs(5)).await.unwrap();
        let reused = session.reused();
        exchange(&mut session).await;
        read_body(&mut session).await;
        assert_eq!(
            session.completion().unwrap(),
            Completion::Finished,
            "the exchange finished"
        );
        connector.release(session, true).await;
        reused
    }

    /// A self-signed certificate for `localhost` with no CA behind it; the
    /// bundle names the certificate itself as its CA.
    fn self_signed_certs() -> TestCerts {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        params.distinguished_name.push(DnType::CommonName, "localhost");
        let cert = params.self_signed(&key).unwrap();
        write_certs(&cert.pem(), &cert.pem(), &key.serialize_pem())
    }

    /// Serve HTTP/1 requests on `stream` according to `mode`.
    async fn serve_http1<S>(mut stream: S, mode: Mode, response: &'static [u8], closed: Arc<AtomicUsize>)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if matches!(mode, Mode::Stall) {
            tokio::time::sleep(Duration::from_secs(60)).await;
            return;
        }

        let mut request = Vec::with_capacity(1024);
        while stream.read_buf(&mut request).await.unwrap_or(0) > 0 {
            while let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                request.drain(..end.saturating_add(4));
                stream.write_all(response).await.unwrap();
                if matches!(mode, Mode::AnswerOnce) {
                    return;
                }
            }
        }
        closed.fetch_add(1, Ordering::SeqCst);
    }

    /// Serve HTTP/2 on `stream`, answering each request with what it
    /// received: the authority and scheme as headers, the body length as
    /// the body, and its trailers (or `grpc-status: 0`) as trailers.
    async fn serve_h2<S>(stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut connection = h2::server::handshake(stream).await.unwrap();
        while let Some(Ok((request, respond))) = connection.accept().await {
            tokio::spawn(answer_h2(request, respond));
        }
    }

    /// Answer one HTTP/2 request for [`serve_h2`].
    ///
    /// [`serve_h2`]: serve_h2
    async fn answer_h2(request: http::Request<h2::RecvStream>, mut respond: h2::server::SendResponse<Bytes>) {
        let authority = request.uri().authority().map(ToString::to_string).unwrap_or_default();
        let scheme = request.uri().scheme_str().unwrap_or_default().to_owned();
        let mut body = request.into_body();
        let mut received = 0_usize;
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            received = received.saturating_add(chunk.len());
            body.flow_control().release_capacity(chunk.len()).unwrap();
        }
        let mut trailers = body.trailers().await.unwrap().unwrap_or_default();
        trailers.entry("grpc-status").or_insert(HeaderValue::from_static("0"));

        let response = http::Response::builder()
            .status(200)
            .header("x-authority", authority)
            .header("x-scheme", scheme)
            .body(())
            .unwrap();
        let mut stream = respond.send_response(response, false).unwrap();
        stream.send_data(Bytes::from(format!("got:{received}")), false).unwrap();
        stream.send_trailers(trailers).unwrap();
    }

    /// Cluster TLS trusting the generated CA.
    fn trusting_tls(certs: &TestCerts) -> CachedClusterTls {
        CachedClusterTls::try_from_config(&ClusterTls {
            ca: Some(praxis_tls::CaConfig {
                ca_path: certs.ca_cert_path.to_str().unwrap().to_owned(),
                crl_paths: Vec::new(),
            }),
            ..ClusterTls::default()
        })
        .unwrap()
    }

    /// Cluster TLS with verification off.
    fn unverified_tls() -> CachedClusterTls {
        CachedClusterTls::try_from_config(&ClusterTls {
            verify: false,
            ..ClusterTls::default()
        })
        .unwrap()
    }

    /// Write a CA, server certificate and key as PEM files in a temporary
    /// directory the returned bundle keeps alive.
    fn write_certs(ca: &str, cert: &str, key: &str) -> TestCerts {
        let dir = tempfile::TempDir::new().unwrap();
        let ca_cert_path = dir.path().join("ca.pem");
        let cert_path = dir.path().join("server.pem");
        let key_path = dir.path().join("server-key.pem");

        std::fs::write(&ca_cert_path, ca).unwrap();
        std::fs::write(&cert_path, cert).unwrap();
        std::fs::write(&key_path, key).unwrap();
        TestCerts {
            temp_dir: Some(dir),
            ca_cert_path,
            cert_path,
            key_path,
        }
    }
}
