// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The connector's pool: idle HTTP/1 connections and shared HTTP/2 ones,
//! bounded as a whole and keyed so a connection only ever serves the kind
//! of peer it was opened for.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
};

use tokio::time::Instant;
use tracing::trace;

use super::{
    connection::{Connection, HttpVersions, Protocol},
    tls::TlsIdentity,
};
use crate::egress::PeerSpec;

// -----------------------------------------------------------------------------
// PoolKey
// -----------------------------------------------------------------------------

/// What a pooled connection was opened for. Connections never move between
/// keys, so peers with different trust settings never share one.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct PoolKey {
    /// The resolved address dialed.
    address: SocketAddr,

    /// The pool partition.
    pool_group: u64,

    /// The server name presented and verified.
    sni: Arc<str>,

    /// Whether the connection runs over TLS.
    tls: bool,

    /// The TLS material the connection was verified with.
    tls_identity: TlsIdentity,

    /// The HTTP versions the peer allows.
    versions: HttpVersions,
}

impl PoolKey {
    /// The key for dialing `peer`.
    pub(super) fn new(peer: &PeerSpec) -> Self {
        Self {
            address: peer.address,
            pool_group: peer.pool_group,
            sni: Arc::clone(&peer.sni),
            tls: peer.tls,
            tls_identity: TlsIdentity::of(peer),
            versions: HttpVersions::from(peer.connection.http_version),
        }
    }
}

// -----------------------------------------------------------------------------
// Pool
// -----------------------------------------------------------------------------

/// Pooled connections, at most `capacity` of them across every key.
///
/// An HTTP/1 connection leaves the pool while a session uses it. An HTTP/2
/// connection stays in the pool, one per key, and every checkout gets
/// another handle on it. When the pool is full the connection that has
/// gone longest without use is let go.
#[derive(Debug)]
pub(super) struct Pool {
    /// Most connections kept at once.
    capacity: usize,

    /// Pooled connections by the order they were last returned or used,
    /// oldest first.
    entries: BTreeMap<u64, Entry>,

    /// Each key's entries, oldest first.
    keys: HashMap<PoolKey, VecDeque<u64>>,

    /// The order number for the next entry.
    next: u64,
}

impl Pool {
    /// An empty pool that keeps at most `capacity` connections.
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: BTreeMap::new(),
            keys: HashMap::new(),
            next: 0,
        }
    }

    /// A connection for `key`, if one is pooled and still usable.
    ///
    /// The most recently returned connection wins. Connections found closed
    /// by the peer or idle past their timeout are dropped on the way.
    pub(super) fn checkout(&mut self, key: &PoolKey, now: Instant) -> Option<Connection> {
        while let Some(entry) = self.take_newest(key) {
            if entry.connection.is_idle_expired(now) || !entry.connection.is_usable() {
                trace!(peer = %entry.connection.peer_address(), "dropping a stale pooled connection");
                entry.connection.discard();
                continue;
            }

            let Some(shared) = entry.connection.share() else {
                return Some(entry.connection);
            };
            self.push(entry);
            return Some(shared);
        }
        None
    }

    /// Drop `order` from `key`'s entries.
    fn forget(&mut self, key: &PoolKey, order: u64) {
        let Some(orders) = self.keys.get_mut(key) else {
            return;
        };
        orders.retain(|&listed| listed != order);
        if orders.is_empty() {
            self.keys.remove(key);
        }
    }

    /// The number of pooled connections.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Add `entry` as the newest.
    fn push(&mut self, entry: Entry) {
        let order = self.next;
        self.next = self.next.wrapping_add(1);
        self.keys.entry(entry.key.clone()).or_default().push_back(order);
        self.entries.insert(order, entry);
    }

    /// Return a connection for `key` to the pool.
    ///
    /// An HTTP/2 connection already pooled moves to the back of the
    /// eviction order; one that is not takes the key's slot unless another
    /// usable HTTP/2 connection holds it.
    pub(super) fn put(&mut self, key: PoolKey, connection: Connection) {
        if connection.protocol() == Protocol::Http2 && !self.take_shared_slot(&key, &connection) {
            return;
        }

        self.push(Entry { connection, key });
        while self.entries.len() > self.capacity {
            let Some((order, oldest)) = self.entries.pop_first() else {
                break;
            };
            self.forget(&oldest.key, order);
            trace!(peer = %oldest.connection.peer_address(), "evicting the oldest pooled connection");
            oldest.connection.discard();
        }
    }

    /// Remove and return `key`'s newest entry.
    fn take_newest(&mut self, key: &PoolKey) -> Option<Entry> {
        let orders = self.keys.get_mut(key)?;
        let order = orders.pop_back();
        if orders.is_empty() {
            self.keys.remove(key);
        }
        self.entries.remove(&order?)
    }

    /// Clear the way for `connection` to be `key`'s shared HTTP/2 entry by
    /// dropping the key's current one, which is this same connection or an
    /// unusable one. Returns `false` when another usable HTTP/2 connection
    /// already holds the slot.
    fn take_shared_slot(&mut self, key: &PoolKey, connection: &Connection) -> bool {
        let entries = &self.entries;
        let current = self.keys.get(key).and_then(|orders| {
            orders.iter().copied().find(|order| {
                entries
                    .get(order)
                    .is_some_and(|entry| entry.connection.protocol() == Protocol::Http2)
            })
        });
        let Some(order) = current else {
            return true;
        };

        if let Some(entry) = self.entries.get(&order)
            && !entry.connection.is_same(connection)
            && entry.connection.is_usable()
        {
            return false;
        }
        if let Some(replaced) = self.entries.remove(&order) {
            self.forget(key, order);
            replaced.connection.discard();
        }
        true
    }
}

/// One pooled connection and the key it serves.
#[derive(Debug)]
struct Entry {
    /// The pooled handle.
    connection: Connection,

    /// The key the connection serves.
    key: PoolKey,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use std::time::Duration;

    use praxis_tls::{CachedClusterTls, ClusterTls};
    use tokio::{
        io::AsyncReadExt as _,
        net::{TcpListener, TcpStream},
    };

    use super::*;
    use crate::{
        config::UpstreamHttpVersion,
        egress::hyper::{
            connection::{SetupTimeouts, dial},
            tls::TlsConfigs,
        },
    };

    #[test]
    fn key_matches_the_same_peer() {
        let peer = PeerSpec::new("127.0.0.1:8443".parse().unwrap(), true, "api.test");

        assert_eq!(
            PoolKey::new(&peer),
            PoolKey::new(&peer.clone()),
            "a peer always maps to one key"
        );
    }

    #[test]
    fn key_separates_partitions_names_and_versions() {
        let base = PeerSpec::new("127.0.0.1:8443".parse().unwrap(), true, "api.test");
        let mut grouped = base.clone();
        grouped.pool_group = 7;
        let renamed = PeerSpec::new(base.address, true, "other.test");
        let plain = PeerSpec::new(base.address, false, "api.test");
        let mut h2 = base.clone();
        Arc::make_mut(&mut h2.connection).http_version = UpstreamHttpVersion::H2;

        let key = PoolKey::new(&base);
        for (other, why) in [
            (grouped, "pool partitions"),
            (renamed, "server names"),
            (plain, "TLS and plain TCP"),
            (h2, "HTTP versions"),
        ] {
            assert_ne!(key, PoolKey::new(&other), "{why} must not share connections");
        }
    }

    #[test]
    fn key_separates_cluster_tls_material() {
        let mut verified = PeerSpec::new("127.0.0.1:8443".parse().unwrap(), true, "api.test");
        verified.tls_config = Some(CachedClusterTls::try_from_config(&ClusterTls::default()).unwrap());
        let mut unverified = verified.clone();
        unverified.tls_config = Some(
            CachedClusterTls::try_from_config(&ClusterTls {
                verify: false,
                ..ClusterTls::default()
            })
            .unwrap(),
        );

        assert_ne!(
            PoolKey::new(&verified),
            PoolKey::new(&unverified),
            "a connection opened without verification must never serve a verifying peer"
        );
    }

    #[test]
    fn empty_pool_has_nothing_to_check_out() {
        let mut pool = Pool::new(4);
        let peer = PeerSpec::plain("127.0.0.1:80".parse().unwrap());

        assert!(
            pool.checkout(&PoolKey::new(&peer), Instant::now()).is_none(),
            "nothing was pooled"
        );
        assert_eq!(pool.len(), 0, "a miss leaves the pool empty");
    }

    #[tokio::test]
    async fn checkout_closes_a_connection_idle_past_its_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut peer = PeerSpec::plain(listener.local_addr().unwrap());
        Arc::make_mut(&mut peer.connection).idle_timeout = Some(Duration::from_secs(60));
        let key = PoolKey::new(&peer);
        let mut pool = Pool::new(4);
        let (connection, mut upstream) = idle_connection(&peer, &listener).await;
        pool.put(key.clone(), connection);
        let later = Instant::now().checked_add(Duration::from_secs(61)).unwrap();

        let fresh = pool
            .checkout(&key, Instant::now())
            .expect("a connection inside its idle timeout is handed out");
        pool.put(key.clone(), fresh);
        let expired = pool.checkout(&key, later);
        let closed = tokio::time::timeout(Duration::from_secs(5), upstream.read(&mut [0_u8; 1])).await;

        assert!(
            expired.is_none(),
            "a connection idle past its timeout is not handed out"
        );
        assert_eq!(pool.len(), 0, "the expired connection leaves the pool");
        assert!(
            matches!(closed, Ok(Ok(0))),
            "the expired connection is closed: {closed:?}"
        );
    }

    #[tokio::test]
    async fn full_pool_evicts_the_oldest_entry_whatever_its_key() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first = PeerSpec::plain(listener.local_addr().unwrap());
        let mut second = first.clone();
        second.pool_group = 1;
        let mut pool = Pool::new(2);
        let (oldest, mut oldest_upstream) = idle_connection(&first, &listener).await;
        let (other, mut other_upstream) = idle_connection(&second, &listener).await;
        let (newest, mut newest_upstream) = idle_connection(&first, &listener).await;

        pool.put(PoolKey::new(&first), oldest);
        pool.put(PoolKey::new(&second), other);
        pool.put(PoolKey::new(&first), newest);

        assert_eq!(pool.len(), 2, "a full pool keeps its capacity");
        assert!(
            closes(&mut oldest_upstream).await,
            "the connection returned first goes first"
        );
        assert!(
            !closes(&mut other_upstream).await,
            "a newer connection under another key stays"
        );
        assert!(
            !closes(&mut newest_upstream).await,
            "the newest connection under the evicted key stays"
        );
    }

    #[tokio::test]
    async fn pool_of_capacity_zero_keeps_nothing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = PeerSpec::plain(listener.local_addr().unwrap());
        let key = PoolKey::new(&peer);
        let mut pool = Pool::new(0);
        let (connection, mut upstream) = idle_connection(&peer, &listener).await;

        pool.put(key.clone(), connection);

        assert_eq!(pool.len(), 0, "a pool with no room keeps no connection");
        assert!(closes(&mut upstream).await, "the returned connection is closed at once");
        assert!(pool.checkout(&key, Instant::now()).is_none(), "nothing is handed out");
    }

    #[tokio::test]
    async fn connection_closed_before_its_return_is_dropped_at_checkout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = PeerSpec::plain(listener.local_addr().unwrap());
        let key = PoolKey::new(&peer);
        let mut pool = Pool::new(4);
        let (connection, upstream) = idle_connection(&peer, &listener).await;
        drop(upstream);
        eventually(|| !connection.is_usable(), "the client notices the peer closed").await;

        pool.put(key.clone(), connection);
        let pooled = pool.len();
        let checked_out = pool.checkout(&key, Instant::now());

        assert_eq!(
            pooled, 1,
            "a returned HTTP/1 connection is pooled without a liveness check"
        );
        assert!(
            checked_out.is_none(),
            "a connection the peer closed is never handed out"
        );
        assert_eq!(pool.len(), 0, "the closed connection leaves the pool at checkout");
    }

    #[tokio::test]
    async fn checkout_hands_out_the_most_recently_returned_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = PeerSpec::plain(listener.local_addr().unwrap());
        let key = PoolKey::new(&peer);
        let mut pool = Pool::new(4);
        let (earlier, mut earlier_upstream) = idle_connection(&peer, &listener).await;
        let (later, mut later_upstream) = idle_connection(&peer, &listener).await;
        pool.put(key.clone(), earlier);
        pool.put(key.clone(), later);

        pool.checkout(&key, Instant::now())
            .expect("a pooled connection is handed out")
            .discard();

        assert!(
            closes(&mut later_upstream).await,
            "the connection returned last is handed out first"
        );
        assert!(
            !closes(&mut earlier_upstream).await,
            "the earlier connection stays pooled"
        );
        assert_eq!(pool.len(), 1, "one connection is left for the key");
    }

    #[tokio::test]
    async fn http2_checkout_shares_the_pooled_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = http2_peer(&listener);
        let key = PoolKey::new(&peer);
        let mut pool = Pool::new(4);
        pool.put(key.clone(), http2_connection(&peer, &listener).await);

        let first = pool
            .checkout(&key, Instant::now())
            .expect("the HTTP/2 connection is handed out");
        let second = pool.checkout(&key, Instant::now()).expect("and handed out again");

        assert!(first.is_same(&second), "every checkout shares the one connection");
        assert_eq!(pool.len(), 1, "a shared connection stays pooled");
    }

    #[tokio::test]
    async fn second_http2_connection_does_not_displace_the_first() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = http2_peer(&listener);
        let key = PoolKey::new(&peer);
        let mut pool = Pool::new(4);
        let first = http2_connection(&peer, &listener).await;
        let first_handle = first.share().unwrap();
        let second = http2_connection(&peer, &listener).await;

        pool.put(key.clone(), first);
        pool.put(key.clone(), second);
        let checked_out = pool.checkout(&key, Instant::now()).unwrap();

        assert_eq!(pool.len(), 1, "one HTTP/2 connection serves a key");
        assert!(
            checked_out.is_same(&first_handle),
            "the usable connection already pooled keeps the slot"
        );
    }

    #[tokio::test]
    async fn returning_a_pooled_http2_connection_keeps_one_entry() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = http2_peer(&listener);
        let key = PoolKey::new(&peer);
        let mut pool = Pool::new(4);
        let connection = http2_connection(&peer, &listener).await;
        let original = connection.share().unwrap();
        pool.put(key.clone(), connection);

        let handle = pool.checkout(&key, Instant::now()).unwrap();
        pool.put(key.clone(), handle);
        let pooled = pool.len();
        let next = pool.checkout(&key, Instant::now()).unwrap();

        assert_eq!(pooled, 1, "a handle on a pooled connection adds no entry");
        assert!(next.is_same(&original), "the same connection is still pooled");
    }

    #[tokio::test]
    async fn closed_http2_connection_gives_up_its_slot() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = http2_peer(&listener);
        let key = PoolKey::new(&peer);
        let mut pool = Pool::new(4);
        let closed = http2_connection(&peer, &listener).await;
        let watcher = closed.share().unwrap();
        pool.put(key.clone(), closed);
        watcher.close();
        eventually(|| !watcher.is_usable(), "the closed connection stops taking streams").await;
        let replacement = http2_connection(&peer, &listener).await;
        let replacement_handle = replacement.share().unwrap();

        pool.put(key.clone(), replacement);
        let checked_out = pool.checkout(&key, Instant::now()).unwrap();

        assert_eq!(pool.len(), 1, "the closed connection's entry is replaced");
        assert!(
            checked_out.is_same(&replacement_handle),
            "the slot goes to the usable connection"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Whether the upstream end of a connection sees it closed within
    /// 200 ms.
    async fn closes(upstream: &mut TcpStream) -> bool {
        let read = tokio::time::timeout(Duration::from_millis(200), upstream.read(&mut [0_u8; 1])).await;
        matches!(read, Ok(Ok(0)))
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

    /// A prior-knowledge HTTP/2 connection from `peer` to `listener`, whose
    /// upstream end serves HTTP/2 until the client goes away.
    async fn http2_connection(peer: &PeerSpec, listener: &TcpListener) -> Connection {
        let timeouts = SetupTimeouts::new(&peer.connection, Duration::from_secs(5));
        let mut connection = Box::pin(dial(peer, &TlsConfigs::default(), timeouts)).await.unwrap();
        let (upstream, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let Ok(mut served) = h2::server::handshake(upstream).await else {
                return;
            };
            while let Some(Ok(_stream)) = served.accept().await {}
        });

        connection.ready().await.unwrap();
        connection
    }

    /// A plain peer for `listener` that speaks HTTP/2 only.
    fn http2_peer(listener: &TcpListener) -> PeerSpec {
        let mut peer = PeerSpec::plain(listener.local_addr().unwrap());
        Arc::make_mut(&mut peer.connection).http_version = UpstreamHttpVersion::H2;
        peer
    }

    /// A plain HTTP/1 connection from `peer` to `listener`, ready for a
    /// request and idle with its idle timer running, and the upstream end
    /// of its socket.
    async fn idle_connection(peer: &PeerSpec, listener: &TcpListener) -> (Connection, TcpStream) {
        let timeouts = SetupTimeouts::new(&peer.connection, Duration::from_secs(5));
        let mut connection = Box::pin(dial(peer, &TlsConfigs::default(), timeouts)).await.unwrap();
        let (upstream, _) = listener.accept().await.unwrap();

        connection.ready().await.unwrap();
        drop(connection.begin_exchange(peer.connection.idle_timeout));
        (connection, upstream)
    }
}
