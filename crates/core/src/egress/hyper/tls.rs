// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Upstream TLS for the hyper connector: which material a peer dials with,
//! one client config per material and protocol offer, and the name the
//! upstream certificate is verified against.

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak},
};

use praxis_tls::{CachedCaCerts, CachedClientCert, CachedClusterTls};
use tokio_rustls::rustls::{
    self, ClientConfig, ConfigBuilder, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::{
        WantsClientCert,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
};
use tracing::{debug, warn};

use super::connection::HttpVersions;
use crate::egress::{EgressError, PeerSpec};

// -----------------------------------------------------------------------------
// TlsIdentity
// -----------------------------------------------------------------------------

/// Which TLS material a peer dials with: the cluster CA, client certificate
/// and verification toggle, and the runtime trust anchors when the cluster
/// names no CA. Material compares by allocation, not by content.
///
/// The identity holds weak handles on the material, so while anything keyed
/// by it is alive no other material can take over those allocations and two
/// equal identities always name the same material.
#[derive(Clone, Debug, Default)]
pub(super) struct TlsIdentity {
    /// The cluster CA.
    ca: Option<Weak<CachedCaCerts>>,

    /// The cluster client certificate.
    client_cert: Option<Weak<CachedClientCert>>,

    /// The runtime trust anchors, when the cluster names no CA.
    trust_anchors: Option<Weak<CachedCaCerts>>,

    /// Whether the upstream certificate is verified.
    verify: bool,
}

impl TlsIdentity {
    /// Whether every piece of the material is still in use somewhere.
    fn is_live(&self) -> bool {
        self.ca.as_ref().is_none_or(|ca| ca.strong_count() > 0)
            && self.client_cert.as_ref().is_none_or(|cert| cert.strong_count() > 0)
            && self
                .trust_anchors
                .as_ref()
                .is_none_or(|anchors| anchors.strong_count() > 0)
    }

    /// The identity `peer` dials with; the empty identity for plain TCP.
    pub(super) fn of(peer: &PeerSpec) -> Self {
        if !peer.tls {
            return Self::default();
        }

        let cluster = peer.tls_config.as_ref();
        let ca = cluster.and_then(CachedClusterTls::ca);
        Self {
            ca: ca.map(Arc::downgrade),
            client_cert: cluster.and_then(CachedClusterTls::client_cert).map(Arc::downgrade),
            trust_anchors: peer.trust_anchors.as_ref().filter(|_| ca.is_none()).map(Arc::downgrade),
            verify: cluster.is_none_or(CachedClusterTls::verify),
        }
    }

    /// The allocations and flag the identity compares by.
    fn parts(&self) -> (usize, usize, usize, bool) {
        (
            allocation(self.ca.as_ref()),
            allocation(self.client_cert.as_ref()),
            allocation(self.trust_anchors.as_ref()),
            self.verify,
        )
    }
}

impl PartialEq for TlsIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.parts() == other.parts()
    }
}

impl Eq for TlsIdentity {}

impl Hash for TlsIdentity {
    fn hash<State: Hasher>(&self, state: &mut State) {
        self.parts().hash(state);
    }
}

// -----------------------------------------------------------------------------
// TlsConfigs
// -----------------------------------------------------------------------------

/// The connector's upstream client configs, built once per TLS identity and
/// protocol offer and reused for every connection after that.
#[derive(Debug, Default)]
pub(super) struct TlsConfigs {
    /// Built configs by the identity and offer they were built for.
    cache: Mutex<ConfigCache>,

    /// The system trust store, loaded the first time a peer needs it.
    system_roots: OnceLock<Arc<RootCertStore>>,
}

impl TlsConfigs {
    /// Build the client config for `peer` and `versions`.
    fn build(&self, peer: &PeerSpec, versions: HttpVersions) -> Result<ClientConfig, EgressError> {
        let provider = CryptoProvider::get_default()
            .cloned()
            .ok_or_else(|| EgressError::Connect("no rustls crypto provider is installed".to_owned()))?;
        let builder = self.verifying(peer, &provider)?;

        let mut config = match peer.tls_config.as_ref().and_then(CachedClusterTls::client_cert) {
            Some(cert) => {
                let (chain, key) = client_identity(cert)?;
                builder
                    .with_client_auth_cert(chain, key)
                    .map_err(|err| config_error("client certificate", &err))?
            },
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = versions.alpn();
        config.require_ems = true;

        if praxis_tls::provider::required() && !config.fips() {
            return Err(EgressError::Connect(
                "FIPS mode is required but the upstream TLS config would not run in it".to_owned(),
            ));
        }
        Ok(config)
    }

    /// The client config for dialing `peer` while offering `versions`.
    ///
    /// Trust comes from the cluster CA, else the runtime trust anchors, else
    /// the system store; a cluster that turns verification off accepts any
    /// certificate but still checks the handshake signatures. The client
    /// certificate is presented when the cluster has one, and TLS 1.2 peers
    /// must support the extended master secret ([RFC 7627]).
    ///
    /// # Errors
    ///
    /// [`EgressError::Connect`] when no crypto provider is installed, the
    /// cluster CA holds no usable certificate, the client certificate or key
    /// is unusable, or FIPS mode is required and the config would not run
    /// in it.
    ///
    /// [RFC 7627]: https://datatracker.ietf.org/doc/html/rfc7627
    /// [`EgressError::Connect`]: EgressError::Connect
    pub(super) fn client_config(
        &self,
        peer: &PeerSpec,
        versions: HttpVersions,
    ) -> Result<Arc<ClientConfig>, EgressError> {
        let key = (TlsIdentity::of(peer), versions);
        let cached = self.lock().get(&key).map(Arc::clone);
        if let Some(config) = cached {
            return Ok(config);
        }

        let built = Arc::new(self.build(peer, versions)?);
        let mut cache = self.lock();
        cache.retain(|(identity, _), _| identity.is_live());
        let config = Arc::clone(cache.entry(key).or_insert(built));
        drop(cache);
        Ok(config)
    }

    /// Lock the config cache, recovering it if a holder panicked.
    fn lock(&self) -> MutexGuard<'_, ConfigCache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The roots to verify against: `ca` when given, else the system store.
    fn roots(&self, ca: Option<&CachedCaCerts>) -> Result<Arc<RootCertStore>, EgressError> {
        match ca {
            Some(ca) => roots_from(ca).map(Arc::new),
            None => Ok(Arc::clone(self.system_roots.get_or_init(load_system_roots))),
        }
    }

    /// A config builder over `provider` that verifies the upstream the way
    /// `peer`'s cluster asks.
    fn verifying(
        &self,
        peer: &PeerSpec,
        provider: &Arc<CryptoProvider>,
    ) -> Result<ConfigBuilder<ClientConfig, WantsClientCert>, EgressError> {
        let cluster = peer.tls_config.as_ref();
        let builder = ClientConfig::builder_with_provider(Arc::clone(provider))
            .with_safe_default_protocol_versions()
            .map_err(|err| config_error("protocol versions", &err))?;

        if cluster.is_none_or(CachedClusterTls::verify) {
            let ca = cluster.and_then(CachedClusterTls::ca).or(peer.trust_anchors.as_ref());
            return Ok(builder.with_root_certificates(self.roots(ca.map(Arc::as_ref))?));
        }
        Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert::new(provider))))
    }
}

/// Built client configs by the identity and protocol offer they serve.
type ConfigCache = HashMap<(TlsIdentity, HttpVersions), Arc<ClientConfig>>;

// -----------------------------------------------------------------------------
// Server Name
// -----------------------------------------------------------------------------

/// The name the upstream certificate is verified against.
///
/// An IP literal (what the server name carries for an IP upstream) becomes
/// an IP name, which rustls checks against the certificate's IP SANs and
/// sends no SNI for. A peer with no server name is verified against its
/// address rather than dialed unverified.
///
/// # Errors
///
/// [`EgressError::Connect`] when the server name is neither a valid DNS name
/// nor an IP address.
///
/// [`EgressError::Connect`]: EgressError::Connect
pub(super) fn server_name(peer: &PeerSpec) -> Result<ServerName<'static>, EgressError> {
    if peer.sni.is_empty() {
        return Ok(ServerName::IpAddress(peer.address.ip().into()));
    }

    ServerName::try_from(&*peer.sni)
        .map(|name| name.to_owned())
        .map_err(|err| EgressError::Connect(format!("invalid upstream server name {:?}: {err}", &*peer.sni)))
}

// -----------------------------------------------------------------------------
// AcceptAnyServerCert
// -----------------------------------------------------------------------------

/// Accepts whatever certificate the upstream presents, for clusters that
/// turn verification off, while still checking the handshake signatures
/// with the installed provider.
#[derive(Debug)]
struct AcceptAnyServerCert {
    /// Signature algorithms of the installed provider.
    algorithms: WebPkiSupportedAlgorithms,
}

impl AcceptAnyServerCert {
    /// A verifier checking signatures with `provider`.
    const fn new(provider: &CryptoProvider) -> Self {
        Self {
            algorithms: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// The address of the allocation `handle` points at, zero for none.
fn allocation<T>(handle: Option<&Weak<T>>) -> usize {
    handle.map_or(0, |handle| handle.as_ptr().addr())
}

/// The client certificate chain and key in the form rustls keeps.
///
/// rustls owns the chain and key for the config's lifetime, so they are
/// copied out of the cached material; this runs once per identity.
fn client_identity(
    cert: &CachedClientCert,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), EgressError> {
    let chain = cert
        .cert_der()
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect();
    let key = PrivateKeyDer::try_from(cert.key_der().to_vec())
        .map_err(|err| EgressError::Connect(format!("upstream client key: {err}")))?;
    Ok((chain, key))
}

/// A config-building failure as a connect error.
fn config_error(what: &str, err: &rustls::Error) -> EgressError {
    EgressError::Connect(format!("upstream TLS {what}: {err}"))
}

/// Load the system trust store, logging the parts that fail to load.
fn load_system_roots() -> Arc<RootCertStore> {
    let loaded = rustls_native_certs::load_native_certs();
    for err in &loaded.errors {
        warn!(error = %err, "could not load part of the system trust store for upstream TLS");
    }

    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(loaded.certs);
    if added == 0 {
        warn!(
            ignored,
            "the system trust store has no usable certificate; verified TLS upstreams will be refused"
        );
    } else {
        debug!(added, ignored, "loaded the system trust store for upstream TLS");
    }
    Arc::new(roots)
}

/// A root store of the usable certificates in `ca`.
fn roots_from(ca: &CachedCaCerts) -> Result<RootCertStore, EgressError> {
    let mut roots = RootCertStore::empty();
    for der in ca.der_certs() {
        if let Err(err) = roots.add(CertificateDer::from(der.as_slice())) {
            warn!(error = %err, "skipping an unusable upstream CA certificate");
        }
    }

    if roots.is_empty() {
        return Err(EgressError::Connect(
            "none of the upstream CA certificates is usable".to_owned(),
        ));
    }
    Ok(roots)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use praxis_tls::{CaConfig, ClusterTls};

    use super::*;

    #[test]
    fn plain_peers_share_the_empty_identity() {
        let mut peer = PeerSpec::plain("127.0.0.1:80".parse().unwrap());
        peer.trust_anchors = Some(Arc::new(CachedCaCerts::new(vec![vec![1]])));

        assert_eq!(
            TlsIdentity::of(&peer),
            TlsIdentity::default(),
            "TLS material means nothing to a plain peer"
        );
    }

    #[test]
    fn identity_compares_cluster_material_by_allocation() {
        let certs = praxis_tls::test_utils::gen_test_certs();
        let cluster = cluster_tls(&certs, true);
        let first = tls_peer(Some(cluster.clone()));
        let second = tls_peer(Some(cluster));
        let rebuilt = tls_peer(Some(cluster_tls(&certs, true)));

        assert_eq!(
            TlsIdentity::of(&first),
            TlsIdentity::of(&second),
            "peers sharing the cached material share an identity"
        );
        assert_ne!(
            TlsIdentity::of(&first),
            TlsIdentity::of(&rebuilt),
            "the same files loaded again are different material"
        );
        assert_ne!(
            TlsIdentity::of(&first),
            TlsIdentity::of(&tls_peer(Some(cluster_tls(&certs, false)))),
            "turning verification off changes the identity"
        );
    }

    #[test]
    fn runtime_anchors_count_only_without_a_cluster_ca() {
        let certs = praxis_tls::test_utils::gen_test_certs();
        let anchors = Arc::new(CachedCaCerts::new(vec![vec![1]]));
        let mut with_ca = tls_peer(Some(cluster_tls(&certs, true)));
        let without_anchors = with_ca.clone();
        with_ca.trust_anchors = Some(Arc::clone(&anchors));
        let mut bare = tls_peer(None);
        let bare_without_anchors = bare.clone();
        bare.trust_anchors = Some(anchors);

        assert_eq!(
            TlsIdentity::of(&with_ca),
            TlsIdentity::of(&without_anchors),
            "a cluster CA overrides the runtime anchors"
        );
        assert_ne!(
            TlsIdentity::of(&bare),
            TlsIdentity::of(&bare_without_anchors),
            "without a cluster CA the runtime anchors decide trust"
        );
    }

    #[test]
    fn identity_is_live_until_its_material_is_dropped() {
        let anchors = Arc::new(CachedCaCerts::new(vec![vec![1]]));
        let mut peer = tls_peer(None);
        peer.trust_anchors = Some(anchors);
        let identity = TlsIdentity::of(&peer);

        assert!(identity.is_live(), "the peer still holds the anchors");
        drop(peer);
        assert!(!identity.is_live(), "nothing holds the anchors any more");
    }

    #[test]
    fn client_config_is_built_once_per_identity_and_offer() {
        praxis_tls::provider::install();
        let configs = TlsConfigs::default();
        let certs = praxis_tls::test_utils::gen_test_certs();
        let peer = tls_peer(Some(cluster_tls(&certs, true)));

        let first = configs.client_config(&peer, HttpVersions::Http1).unwrap();
        let again = configs.client_config(&peer.clone(), HttpVersions::Http1).unwrap();
        let either = configs.client_config(&peer, HttpVersions::Either).unwrap();

        assert!(Arc::ptr_eq(&first, &again), "the same identity reuses its config");
        assert!(!Arc::ptr_eq(&first, &either), "another offer gets its own config");
        assert_eq!(
            first.alpn_protocols,
            vec![b"http/1.1".to_vec()],
            "HTTP/1 offers http/1.1"
        );
        assert_eq!(
            either.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "either version prefers h2"
        );
        assert!(
            first.require_ems,
            "TLS 1.2 upstreams must support the extended master secret"
        );
    }

    #[test]
    fn client_config_drops_entries_whose_material_is_gone() {
        praxis_tls::provider::install();
        let certs = praxis_tls::test_utils::gen_test_certs();
        let configs = TlsConfigs::default();
        let stale = anchored_peer(&certs);
        configs.client_config(&stale, HttpVersions::Http1).unwrap();
        drop(stale);

        configs
            .client_config(&anchored_peer(&certs), HttpVersions::Http1)
            .unwrap();

        assert_eq!(configs.lock().len(), 1, "a config whose material is gone is pruned");
    }

    #[test]
    fn client_config_refuses_trust_anchors_with_no_usable_certificate() {
        praxis_tls::provider::install();
        let mut peer = tls_peer(None);
        peer.trust_anchors = Some(Arc::new(CachedCaCerts::new(vec![vec![1, 2, 3]])));

        let result = TlsConfigs::default().client_config(&peer, HttpVersions::Http1);

        assert!(
            matches!(&result, Err(EgressError::Connect(message)) if message.contains("CA")),
            "unusable trust anchors must fail the connect: {result:?}"
        );
    }

    #[test]
    fn server_name_keeps_dns_names_and_ip_literals_apart() {
        let dns = PeerSpec::new("10.0.0.1:443".parse().unwrap(), true, "api.example.com");
        let ip = PeerSpec::new("10.0.0.1:443".parse().unwrap(), true, "10.0.0.1");
        let unnamed = PeerSpec::new("10.0.0.2:443".parse().unwrap(), true, "");

        assert!(
            matches!(server_name(&dns).unwrap(), ServerName::DnsName(_)),
            "a host name verifies as a DNS name"
        );
        assert!(
            matches!(server_name(&ip).unwrap(), ServerName::IpAddress(_)),
            "an IP literal verifies as an IP name"
        );
        assert_eq!(
            server_name(&unnamed).unwrap(),
            ServerName::IpAddress("10.0.0.2".parse::<std::net::IpAddr>().unwrap().into()),
            "a peer without a server name is verified against its address"
        );
    }

    #[test]
    fn server_name_refuses_an_invalid_name() {
        let peer = PeerSpec::new("10.0.0.1:443".parse().unwrap(), true, "bad name!");

        assert!(
            matches!(server_name(&peer), Err(EgressError::Connect(_))),
            "an invalid server name fails the connect"
        );
    }

    #[test]
    fn unverified_peers_accept_any_certificate_but_keep_provider_schemes() {
        praxis_tls::provider::install();
        let provider = CryptoProvider::get_default().unwrap();
        let verifier = AcceptAnyServerCert::new(provider);

        verifier
            .verify_server_cert(
                &CertificateDer::from(vec![0_u8; 4]),
                &[],
                &ServerName::try_from("upstream.test").unwrap(),
                &[],
                UnixTime::now(),
            )
            .unwrap();

        assert_eq!(
            verifier.supported_verify_schemes(),
            provider.signature_verification_algorithms.supported_schemes(),
            "signatures are still checked with the installed provider"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A TLS peer trusting freshly loaded runtime anchors.
    fn anchored_peer(certs: &praxis_tls::test_utils::TestCerts) -> PeerSpec {
        let mut peer = tls_peer(None);
        let anchors = CachedCaCerts::from_pem_file(certs.ca_cert_path.to_str().unwrap()).unwrap();
        peer.trust_anchors = Some(Arc::new(anchors));
        peer
    }

    /// Cached cluster TLS trusting the generated CA.
    fn cluster_tls(certs: &praxis_tls::test_utils::TestCerts, verify: bool) -> CachedClusterTls {
        CachedClusterTls::try_from_config(&ClusterTls {
            ca: Some(CaConfig {
                ca_path: certs.ca_cert_path.to_str().unwrap().to_owned(),
                crl_paths: Vec::new(),
            }),
            verify,
            ..ClusterTls::default()
        })
        .unwrap()
    }

    /// A TLS peer for `localhost` with the given cluster material.
    fn tls_peer(tls_config: Option<CachedClusterTls>) -> PeerSpec {
        let mut peer = PeerSpec::new("127.0.0.1:8443".parse().unwrap(), true, "localhost");
        peer.tls_config = tls_config;
        peer
    }
}
