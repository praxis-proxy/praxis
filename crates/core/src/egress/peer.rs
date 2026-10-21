// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Where to connect: the backend-neutral description of one upstream peer.

use std::{net::SocketAddr, sync::Arc};

use praxis_tls::{CachedCaCerts, CachedClusterTls};

use crate::{
    circuit::PeerKey,
    connectivity::{
        ConnectionOptions, Upstream,
        peer::{AddressResolutionError, MissingServerName, resolve_upstream_checked, tls_server_name},
    },
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Pool partition for callers that do not isolate their connections.
pub const DEFAULT_POOL_GROUP: u64 = 0;

// -----------------------------------------------------------------------------
// PeerSpec
// -----------------------------------------------------------------------------

/// Everything a backend needs to dial one peer and pool the connection.
///
/// The address is already resolved: the DNS policy (private-range refusal,
/// trusted hosts, per-call lookups) has run by the time a backend sees a
/// peer, so a backend never resolves names itself.
///
/// ```
/// use praxis_core::egress::PeerSpec;
///
/// let peer = PeerSpec::plain("127.0.0.1:8080".parse().unwrap());
/// assert!(!peer.tls);
/// assert!(peer.sni.is_empty());
/// assert_eq!(peer.circuit_key().to_string(), "127.0.0.1:8080");
/// ```
#[derive(Clone, Debug)]
pub struct PeerSpec {
    /// Resolved socket address to dial.
    pub address: SocketAddr,

    /// Timeouts and the HTTP version to speak.
    pub connection: Arc<ConnectionOptions>,

    /// Pool partition. Connections never move between partitions, so a
    /// caller with its own trust settings (the policy engine) keeps its
    /// pooled connections apart from the clusters'.
    pub pool_group: u64,

    /// Server name presented and verified for TLS; empty for plain TCP.
    pub sni: Arc<str>,

    /// Whether to wrap the connection in TLS.
    pub tls: bool,

    /// Per-cluster TLS material: CA, client certificate, verification toggle.
    pub tls_config: Option<CachedClusterTls>,

    /// Trust anchors used when `tls_config` names no CA of its own (the
    /// runtime `upstream_ca_file`).
    pub trust_anchors: Option<Arc<CachedCaCerts>>,
}

impl PeerSpec {
    /// A peer at `address`, over TLS when `tls` is set, verified against `sni`.
    ///
    /// ```
    /// use praxis_core::egress::{DEFAULT_POOL_GROUP, PeerSpec};
    ///
    /// let peer = PeerSpec::new("10.0.0.1:443".parse().unwrap(), true, "api.example.com");
    /// assert!(peer.tls);
    /// assert_eq!(&*peer.sni, "api.example.com");
    /// assert_eq!(peer.pool_group, DEFAULT_POOL_GROUP);
    /// ```
    #[must_use]
    pub fn new(address: SocketAddr, tls: bool, sni: &str) -> Self {
        Self {
            address,
            connection: Arc::new(ConnectionOptions::default()),
            pool_group: DEFAULT_POOL_GROUP,
            sni: Arc::from(sni),
            tls,
            tls_config: None,
            trust_anchors: None,
        }
    }

    /// The circuit-breaker identity of this peer: address plus server name.
    #[must_use]
    pub fn circuit_key(&self) -> PeerKey {
        PeerKey::new(self.address, Arc::clone(&self.sni))
    }

    /// Resolve a configured [`Upstream`] into a dialable peer.
    ///
    /// A hostname that resolves into a private or reserved range is refused
    /// unless `allow_private` (`insecure_options.allow_private_upstreams`)
    /// is set or the host is trusted. The server name comes from the
    /// cluster's TLS config or is derived from the address; a TLS upstream
    /// left with no name is refused rather than dialed unverified.
    ///
    /// # Errors
    ///
    /// Returns [`UpstreamPeerError`] when the address does not resolve or is
    /// refused, or when TLS is on without a server name.
    pub async fn from_upstream(upstream: &Upstream, allow_private: bool) -> Result<Self, UpstreamPeerError> {
        let address = resolve_upstream_checked(upstream, allow_private).await?;

        let sni = upstream
            .tls
            .as_ref()
            .map(|tls| tls_server_name(tls, &upstream.address))
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            address,
            connection: Arc::clone(&upstream.connection),
            pool_group: DEFAULT_POOL_GROUP,
            sni: Arc::from(sni.as_str()),
            tls: upstream.tls.is_some(),
            tls_config: upstream.tls.clone(),
            trust_anchors: None,
        })
    }

    /// A plain-TCP peer with default connection options.
    #[must_use]
    pub fn plain(address: SocketAddr) -> Self {
        Self::new(address, false, "")
    }
}

// -----------------------------------------------------------------------------
// UpstreamPeerError
// -----------------------------------------------------------------------------

/// Why an [`Upstream`] could not become a [`PeerSpec`].
#[derive(Debug, thiserror::Error)]
pub enum UpstreamPeerError {
    /// The upstream address failed to resolve or was refused.
    #[error(transparent)]
    Resolve(#[from] AddressResolutionError),

    /// TLS is on but there is no server name to verify the certificate against.
    #[error(transparent)]
    MissingServerName(#[from] MissingServerName),
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn plain_peer_has_no_tls_and_default_pool_group() {
        let peer = PeerSpec::plain("10.0.0.1:80".parse().unwrap());

        assert!(!peer.tls, "a plain peer must not use TLS");
        assert!(peer.sni.is_empty(), "a plain peer has no server name");
        assert_eq!(peer.pool_group, DEFAULT_POOL_GROUP, "default pool partition");
        assert!(peer.tls_config.is_none(), "no cluster TLS material");
        assert!(peer.trust_anchors.is_none(), "no runtime trust anchors");
    }

    #[test]
    fn circuit_key_includes_the_server_name() {
        let peer = PeerSpec::new("10.0.0.1:443".parse().unwrap(), true, "api.example.com");

        assert_eq!(
            peer.circuit_key(),
            PeerKey::new("10.0.0.1:443".parse().unwrap(), "api.example.com"),
            "the circuit key must carry address and server name"
        );
    }

    #[tokio::test]
    async fn from_upstream_resolves_a_literal_plain_upstream() {
        let upstream = Upstream {
            address: Arc::from("127.0.0.1:9"),
            authority: None,
            base_path: None,
            connection: Arc::new(ConnectionOptions::default()),
            tls: None,
        };

        let peer = PeerSpec::from_upstream(&upstream, false)
            .await
            .expect("a literal loopback address bypasses the private-IP check");

        assert_eq!(
            peer.address,
            "127.0.0.1:9".parse::<SocketAddr>().unwrap(),
            "the literal address is dialed as given"
        );
        assert!(!peer.tls, "no cluster TLS means a plain peer");
        assert!(
            Arc::ptr_eq(&peer.connection, &upstream.connection),
            "connection options are shared, not copied"
        );
    }
}
