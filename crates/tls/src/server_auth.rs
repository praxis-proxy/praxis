// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Server certificate verifier that pins a peer's SPIFFE identity.
//!
//! A client dialing a known peer over mTLS: the peer certificate must chain to
//! the configured CA and carry the expected SPIFFE ID as its single URI SAN.
//! Binding to the identity, not the certificate, survives SVID rotation, and the
//! hostname check is skipped because the SAN pin replaces it.
//!
//! This module is the rustls plumbing. The SPIFFE X509-SVID leaf validation
//! (standard section 5.2) lives in [`crate::spiffe`]. The crypto provider is a
//! parameter, so a FIPS deployment supplies a validated module (rustls-openssl).

use std::sync::Arc;

use rustls::{
    RootCertStore, SignatureScheme,
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor,
    },
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject as _},
    server::ParsedCertificate,
};

use crate::{TlsError, spiffe::svid_id_matches};

/// Pins the peer to a SPIFFE identity for a client dialing a known peer.
///
/// The certificate must chain to `roots` and carry `expected` as its single URI
/// SAN. The hostname is deliberately not checked.
///
/// Revocation is not checked: SPIFFE X.509-SVIDs are short-lived, so expiry, not
/// CRL or OCSP, is the revocation mechanism, matching the trust-anchor API which
/// carries no revocation list.
#[derive(Debug)]
pub struct SpiffePinnedPeer {
    /// Authorities the chain is verified against.
    roots: Arc<RootCertStore>,

    /// Signature algorithms of the active crypto provider.
    algorithms: WebPkiSupportedAlgorithms,

    /// SPIFFE identity the verified certificate must carry.
    expected: Arc<str>,
}

impl SpiffePinnedPeer {
    /// Pin the peer identified by `expected`, trusting `roots`, using `provider`
    /// for signature verification.
    #[must_use]
    pub fn new(provider: &CryptoProvider, roots: Arc<RootCertStore>, expected: Arc<str>) -> Self {
        Self {
            roots,
            algorithms: provider.signature_verification_algorithms,
            expected,
        }
    }
}

impl ServerCertVerifier for SpiffePinnedPeer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // RFC 5280 §6 chain path, §4.2.1.12 serverAuth EKU.
        verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(end_entity)?,
            &self.roots,
            intermediates,
            now,
            self.algorithms.all,
        )?;
        // X509-SVID §5.2 leaf, then the exact pin.
        if svid_id_matches(end_entity.as_ref(), &self.expected) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

// -----------------------------------------------------------------------------
// Public Functions
// -----------------------------------------------------------------------------

/// Build a rustls client configuration that pins `expected_spiffe`.
///
/// Trusts `ca_pem` (a PEM bundle) and presents `identity_pem` (a combined
/// certificate-and-key PEM) as the client certificate when given.
///
/// `provider` is the sole cryptographic boundary: this code does no crypto of its
/// own. A FIPS deployment passes a validated provider (rustls-openssl over the
/// system OpenSSL module) and the whole verification stays within it.
///
/// # Errors
///
/// Returns [`TlsError::ClientConfigError`] when `expected_spiffe` is not a valid
/// leaf SPIFFE id, the CA bundle is empty or malformed, the client identity PEM is
/// malformed, or the backend rejects the configuration.
pub fn pinned_client_config(
    provider: Arc<CryptoProvider>,
    ca_pem: &[u8],
    expected_spiffe: &str,
    identity_pem: Option<&[u8]>,
) -> Result<rustls::ClientConfig, TlsError> {
    // A pin that is not a valid SPIFFE id can never match a peer: reject it here
    // rather than build a config that fails every handshake.
    if !crate::spiffe::is_leaf_spiffe_id(expected_spiffe) {
        return Err(TlsError::ClientConfigError {
            detail: format!("expected SPIFFE id is not a valid leaf id: {expected_spiffe}"),
        });
    }

    let roots = crate::client_auth::roots_from_pem(ca_pem).map_err(|detail| TlsError::ClientConfigError { detail })?;
    let verifier = SpiffePinnedPeer::new(&provider, Arc::new(roots), Arc::from(expected_spiffe));
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| TlsError::ClientConfigError {
            detail: format!("protocol versions: {err}"),
        })?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier));

    let mut config = match identity_pem {
        Some(pem) => {
            let (chain, key) = split_identity(pem)?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|err| TlsError::ClientConfigError {
                    detail: format!("client identity: {err}"),
                })?
        },
        None => builder.with_no_client_auth(),
    };
    // Extended Master Secret (RFC 7627) on TLS 1.2, as the listeners require;
    // see `setup::require_extended_master_secret` for why.
    config.require_ems = true;
    crate::provider::check_config_fips(config.fips(), "upstream client")?;

    Ok(config)
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Split a combined certificate-and-key PEM into a chain and its private key.
fn split_identity(pem: &[u8]) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsError> {
    let chain = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| TlsError::ClientConfigError {
            detail: format!("client certificate PEM: {err}"),
        })?;
    let key = PrivateKeyDer::from_pem_slice(pem).map_err(|err| TlsError::ClientConfigError {
        detail: format!("client key PEM: {err}"),
    })?;
    Ok((chain, key))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn the_pinned_identity_is_accepted() {
        let (ca, leaf) = mint("Grid CA", &["spiffe://grid.internal/signals"], &Eku::ServerAndClient);
        let verifier = verifier(&ca, "spiffe://grid.internal/signals");
        verify(&verifier, &leaf).expect("the pinned identity verifies");
    }

    #[test]
    fn a_different_identity_is_refused() {
        let (ca, leaf) = mint("Grid CA", &["spiffe://grid.internal/other"], &Eku::ServerAndClient);
        let verifier = verifier(&ca, "spiffe://grid.internal/signals");
        verify(&verifier, &leaf).expect_err("a CA-signed but unpinned identity is refused");
    }

    #[test]
    fn a_certificate_off_the_ca_is_refused() {
        let (_rogue, leaf) = mint("Rogue CA", &["spiffe://grid.internal/signals"], &Eku::ServerAndClient);
        let (grid_ca, _unused) = mint("Grid CA", &["spiffe://grid.internal/signals"], &Eku::ServerAndClient);
        let verifier = verifier(&grid_ca, "spiffe://grid.internal/signals");
        verify(&verifier, &leaf).expect_err("a certificate off the trusted CA is refused");
    }

    #[test]
    fn two_uri_sans_name_nobody() {
        let (ca, leaf) = mint(
            "Grid CA",
            &["spiffe://grid.internal/signals", "spiffe://grid.internal/other"],
            &Eku::ServerAndClient,
        );
        let verifier = verifier(&ca, "spiffe://grid.internal/signals");
        verify(&verifier, &leaf).expect_err("two names match no pin");
    }

    #[test]
    fn a_client_only_certificate_is_refused() {
        // Right CA, right SAN, but marked for client use: it cannot be the server.
        let (ca, leaf) = mint("Grid CA", &["spiffe://grid.internal/signals"], &Eku::ClientOnly);
        let verifier = verifier(&ca, "spiffe://grid.internal/signals");
        verify(&verifier, &leaf).expect_err("a client-only EKU is refused for server auth");
    }

    #[test]
    fn an_absent_eku_is_accepted() {
        let (ca, leaf) = mint("Grid CA", &["spiffe://grid.internal/signals"], &Eku::Absent);
        let verifier = verifier(&ca, "spiffe://grid.internal/signals");
        verify(&verifier, &leaf).expect("a certificate without an EKU extension is accepted");
    }

    #[test]
    fn a_ca_bundle_with_no_certificates_is_rejected() {
        let err = pinned_client_config(provider(), b"not a certificate", "spiffe://grid.internal/signals", None);
        assert!(
            matches!(err, Err(TlsError::ClientConfigError { .. })),
            "an unparseable CA bundle is a config error"
        );
    }

    #[test]
    fn an_invalid_pin_is_rejected_at_build_time() {
        // A pin that is not a valid SPIFFE id can never match: reject it early.
        let (ca_pem, _leaf, _key) = mint_serving("Grid CA", "spiffe://grid.internal/signals");
        let err = pinned_client_config(provider(), &ca_pem, "not-a-spiffe-id", None);
        assert!(
            matches!(err, Err(TlsError::ClientConfigError { .. })),
            "a non-SPIFFE pin is a config error"
        );
    }

    #[test]
    fn a_noncanonical_pin_is_rejected_at_build_time() {
        // SPIFFE trust domains are canonically lowercase, so an uppercase pin would
        // never match a conforming SVID: it is a config error up front.
        let (ca_pem, _leaf, _key) = mint_serving("Grid CA", "spiffe://grid.internal/signals");
        let err = pinned_client_config(provider(), &ca_pem, "spiffe://GRID.INTERNAL/signals", None);
        assert!(
            matches!(err, Err(TlsError::ClientConfigError { .. })),
            "a noncanonical trust-domain pin is a config error"
        );
    }

    #[test]
    fn a_client_identity_is_presented() {
        // The Some(identity) branch: split_identity parses the chain and key, and
        // with_client_auth_cert accepts them.
        let (ca_pem, _cert, identity_pem) = mint_identity_pem("Grid CA", "spiffe://grid.internal/client");
        pinned_client_config(
            provider(),
            &ca_pem,
            "spiffe://grid.internal/signals",
            Some(&identity_pem),
        )
        .expect("a well-formed client identity builds a config");
    }

    #[test]
    fn a_malformed_client_identity_is_rejected() {
        // An identity PEM carrying no private key is rejected.
        let (ca_pem, _cert, _identity) = mint_identity_pem("Grid CA", "spiffe://grid.internal/client");
        let err = pinned_client_config(
            provider(),
            &ca_pem,
            "spiffe://grid.internal/signals",
            Some(b"not a certificate"),
        );
        assert!(
            matches!(err, Err(TlsError::ClientConfigError { .. })),
            "a malformed client identity PEM is a config error"
        );
    }

    #[test]
    fn a_client_identity_without_a_key_is_rejected() {
        // split_identity's key path: a certificate is present but no private key.
        let (ca_pem, cert_only, _identity) = mint_identity_pem("Grid CA", "spiffe://grid.internal/client");
        let err = pinned_client_config(provider(), &ca_pem, "spiffe://grid.internal/signals", Some(&cert_only));
        assert!(
            matches!(err, Err(TlsError::ClientConfigError { .. })),
            "a client identity PEM with no private key is a config error"
        );
    }

    #[test]
    fn a_pinned_peer_completes_the_handshake() {
        let (ca_pem, leaf, key) = mint_serving("Grid CA", "spiffe://grid.internal/signals");
        let config =
            pinned_client_config(provider(), &ca_pem, "spiffe://grid.internal/signals", None).expect("client config");
        assert!(
            config.require_ems,
            "TLS 1.2 sessions must require the Extended Master Secret"
        );
        handshake(config, leaf, key).expect("the pinned peer's handshake completes");
    }

    #[test]
    fn a_publicly_valid_but_unpinned_peer_is_rejected_end_to_end() {
        // The server presents a leaf from a CA the config does not trust: it must be
        // rejected, proving trust is scoped to the pinned CA.
        let (_other_ca, other_leaf, other_key) = mint_serving("Other CA", "spiffe://grid.internal/signals");
        let (grid_ca_pem, _grid_leaf, _grid_key) = mint_serving("Grid CA", "spiffe://grid.internal/signals");
        let config = pinned_client_config(provider(), &grid_ca_pem, "spiffe://grid.internal/signals", None)
            .expect("client config");
        handshake(config, other_leaf, other_key).expect_err("a peer off the pinned CA is rejected end to end");
    }

    #[test]
    fn an_expired_certificate_is_rejected() {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
            KeyUsagePurpose, SanType,
        };

        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "Grid CA");
        let ca_der = ca_params.self_signed(&ca_key).expect("ca cert").der().clone();
        let issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        leaf.distinguished_name.push(DnType::CommonName, "peer");
        leaf.subject_alt_names.push(SanType::URI(
            "spiffe://grid.internal/signals".try_into().expect("uri san"),
        ));
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf.not_before = rcgen::date_time_ymd(2000, 1, 1);
        leaf.not_after = rcgen::date_time_ymd(2000, 12, 31);
        let leaf_der = leaf.signed_by(&leaf_key, &issuer).expect("leaf cert").der().clone();

        let verifier = verifier(&ca_der, "spiffe://grid.internal/signals");
        verify(&verifier, &leaf_der).expect_err("an expired certificate is rejected");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls_openssl::default_provider())
    }

    /// Extended key usage a minted leaf should carry.
    enum Eku {
        ServerAndClient,
        ClientOnly,
        Absent,
    }

    /// Run an in-memory TLS handshake with `client_config`, the server presenting
    /// `server_leaf`/`server_key`. Returns the client's verification result.
    fn handshake(
        client_config: rustls::ClientConfig,
        server_leaf: CertificateDer<'static>,
        server_key: PrivateKeyDer<'static>,
    ) -> Result<(), rustls::Error> {
        let server_config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("server versions")
            .with_no_client_auth()
            .with_single_cert(vec![server_leaf], server_key)
            .expect("server cert");
        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).expect("server conn");
        let name = ServerName::try_from("peer.grid").expect("server name");
        let mut client = rustls::ClientConnection::new(Arc::new(client_config), name).expect("client conn");

        for _ in 0..16 {
            let mut c2s = Vec::new();
            client.write_tls(&mut c2s).expect("client write");
            let mut c2s_reader = c2s.as_slice();
            while !c2s_reader.is_empty() {
                server.read_tls(&mut c2s_reader).expect("server read");
            }
            server.process_new_packets()?;

            let mut s2c = Vec::new();
            server.write_tls(&mut s2c).expect("server write");
            let mut s2c_reader = s2c.as_slice();
            while !s2c_reader.is_empty() {
                client.read_tls(&mut s2c_reader).expect("client read");
            }
            // The certificate verifier runs here, so a rejection surfaces as Err.
            client.process_new_packets()?;

            if !client.is_handshaking() {
                return Ok(());
            }
        }
        Err(rustls::Error::General("handshake did not complete".to_owned()))
    }

    /// Mint a CA and a leaf it signs carrying `leaf_uris` as URI SANs and `eku`.
    fn mint(ca_cn: &str, leaf_uris: &[&str], eku: &Eku) -> (CertificateDer<'static>, CertificateDer<'static>) {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
            KeyUsagePurpose, SanType,
        };

        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, ca_cn);
        let ca_der = ca_params.self_signed(&ca_key).expect("ca cert").der().clone();
        let issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        leaf_params.distinguished_name.push(DnType::CommonName, "peer");
        for uri in leaf_uris {
            leaf_params
                .subject_alt_names
                .push(SanType::URI((*uri).try_into().expect("uri san")));
        }
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = match eku {
            Eku::ServerAndClient => vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth],
            Eku::ClientOnly => vec![ExtendedKeyUsagePurpose::ClientAuth],
            Eku::Absent => vec![],
        };
        let leaf_der = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf cert")
            .der()
            .clone();
        (ca_der, leaf_der)
    }

    /// Mint a CA (as PEM), the leaf certificate PEM, and the combined
    /// certificate-and-key identity PEM a client can present as its own identity.
    fn mint_identity_pem(ca_cn: &str, leaf_uri: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
            KeyUsagePurpose, SanType,
        };

        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, ca_cn);
        let ca_pem = ca_params.self_signed(&ca_key).expect("ca cert").pem().into_bytes();
        let issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        leaf_params.distinguished_name.push(DnType::CommonName, "peer");
        leaf_params
            .subject_alt_names
            .push(SanType::URI(leaf_uri.try_into().expect("uri san")));
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
        let cert_pem = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf cert")
            .pem()
            .into_bytes();
        let mut identity_pem = cert_pem.clone();
        identity_pem.extend_from_slice(leaf_key.serialize_pem().as_bytes());
        (ca_pem, cert_pem, identity_pem)
    }

    /// Mint a CA (as PEM), a leaf it signs, and the leaf's private key, so the
    /// leaf can serve in a real handshake.
    fn mint_serving(ca_cn: &str, leaf_uri: &str) -> (Vec<u8>, CertificateDer<'static>, PrivateKeyDer<'static>) {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
            KeyUsagePurpose, SanType,
        };

        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, ca_cn);
        let ca_pem = ca_params.self_signed(&ca_key).expect("ca cert").pem().into_bytes();
        let issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        leaf_params.distinguished_name.push(DnType::CommonName, "peer");
        leaf_params
            .subject_alt_names
            .push(SanType::URI(leaf_uri.try_into().expect("uri san")));
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
        let leaf_der = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf cert")
            .der()
            .clone();
        let key = PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        (ca_pem, leaf_der, key)
    }

    fn verifier(ca: &CertificateDer<'_>, expected: &str) -> SpiffePinnedPeer {
        let mut roots = RootCertStore::empty();
        roots.add(ca.clone()).expect("add ca");
        SpiffePinnedPeer::new(&provider(), Arc::new(roots), Arc::from(expected))
    }

    fn verify(verifier: &SpiffePinnedPeer, leaf: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let name = ServerName::try_from("peer.grid").expect("server name");
        verifier
            .verify_server_cert(leaf, &[], &name, &[], UnixTime::now())
            .map(|_verified| ())
    }
}
