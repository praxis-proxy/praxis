// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Hot-reloadable TLS certificate resolver and client verifier.
//!
//! [`ReloadableCertResolver`] wraps an [`ArcSwap<CertifiedKey>`] and
//! implements [`ResolvesServerCert`] so that new TLS handshakes
//! atomically pick up rotated certificates without restarting.
//!
//! [`ReloadableClientVerifier`] wraps a [`ClientCertVerifier`] behind
//! [`ArcSwap`] so that CRL and CA certificate changes can be picked
//! up without a proxy restart.
//!
//! [`ReloadableCertResolver`]: crate::reload::ReloadableCertResolver
//! [`ReloadableClientVerifier`]: crate::reload::ReloadableClientVerifier
//! [`ArcSwap<CertifiedKey>`]: arc_swap::ArcSwap
//! [`ArcSwap`]: arc_swap::ArcSwap
//! [`ResolvesServerCert`]: rustls::server::ResolvesServerCert
//! [`ClientCertVerifier`]: rustls::server::danger::ClientCertVerifier

use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, UnixTime},
    server::{
        ClientHello, ResolvesServerCert,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::CertifiedKey,
};

use crate::{CertKeyPair, ClientCertMode, TlsError, client_auth, setup::loader};

// -----------------------------------------------------------------------------
// ReloadableCertResolver
// -----------------------------------------------------------------------------

/// Atomically swappable certificate resolver for hot-reload.
///
/// Holds a [`CertifiedKey`] behind an [`ArcSwap`] so that calls to
/// [`reload`] publish a new certificate without blocking in-flight
/// TLS handshakes.
///
/// ```ignore
/// let resolver = ReloadableCertResolver::new(&pair)?;
/// // rustls calls resolver.resolve(client_hello) during handshake
/// resolver.reload(&pair)?; // swap to a new cert atomically
/// ```
///
/// [`CertifiedKey`]: rustls::sign::CertifiedKey
/// [`ArcSwap`]: arc_swap::ArcSwap
/// [`reload`]: ReloadableCertResolver::reload
pub struct ReloadableCertResolver {
    /// The currently active certified key, atomically swappable.
    current: Arc<ArcSwap<CertifiedKey>>,
}

impl ReloadableCertResolver {
    /// Load the initial certificate and build a resolver.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] if the certificate or key cannot be
    /// loaded or parsed.
    ///
    /// [`TlsError`]: crate::TlsError
    pub fn new(pair: &CertKeyPair) -> Result<Self, TlsError> {
        let certified = loader::load_certified_key(pair)?;
        Ok(Self {
            current: Arc::new(ArcSwap::from_pointee(certified)),
        })
    }

    /// Reload the certificate from disk, validate, and atomically swap.
    ///
    /// On success the new cert is served to all subsequent TLS
    /// handshakes. On failure the previous cert remains active and
    /// an error is returned.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] if the new certificate or key cannot be
    /// loaded or parsed.
    ///
    /// [`TlsError`]: crate::TlsError
    pub fn reload(&self, pair: &CertKeyPair) -> Result<(), TlsError> {
        let certified = loader::load_certified_key(pair)?;
        self.current.store(Arc::new(certified));
        tracing::info!(
            cert_path = %pair.cert_path,
            "TLS certificate reloaded"
        );
        Ok(())
    }

    /// Return an [`Arc`] handle to the inner [`ArcSwap`] for sharing
    /// with the watcher task.
    ///
    /// [`Arc`]: std::sync::Arc
    /// [`ArcSwap`]: arc_swap::ArcSwap
    pub fn arc(&self) -> Arc<ArcSwap<CertifiedKey>> {
        Arc::clone(&self.current)
    }
}

impl std::fmt::Debug for ReloadableCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReloadableCertResolver")
            .field("has_cert", &true)
            .finish()
    }
}

impl ResolvesServerCert for ReloadableCertResolver {
    // SNI is intentionally ignored: this resolver is used only for
    // single-cert listeners (validation rejects hot_reload with
    // multiple certs). The one stored cert serves all hostnames.
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.load_full())
    }
}

// -----------------------------------------------------------------------------
// ReloadableClientVerifier
// -----------------------------------------------------------------------------

/// Inner state holding the current client certificate verifier.
///
/// Wrapped in [`ArcSwap`] so verification delegates to the latest
/// verifier after a CRL or CA reload.
///
/// [`ArcSwap`]: arc_swap::ArcSwap
pub struct VerifierState {
    /// The active verifier built from the current CA and CRL files.
    pub(crate) verifier: Arc<dyn ClientCertVerifier>,
}

/// Atomically swappable client certificate verifier for CRL/CA
/// hot-reload.
///
/// Wraps a [`ClientCertVerifier`] behind [`ArcSwap`] so that CRL
/// and CA certificate changes on disk can be picked up without a
/// proxy restart. All verification methods delegate to the latest
/// inner verifier.
///
/// Root hint subjects (the CA distinguished names sent to clients
/// in `CertificateRequest`) are cached at creation time. Updating
/// them requires a reference with `&self` lifetime, which is
/// incompatible with atomic swaps. This is acceptable because:
///
/// - CRL changes never affect root hints.
/// - CA changes update the verification logic; hints are advisory and stale hints do not weaken security.
///
/// ```ignore
/// let verifier = ReloadableClientVerifier::new(
///     "/etc/ssl/client-ca.pem",
///     ClientCertMode::Require,
///     &[],
/// )?;
/// // Later, when CRL changes:
/// verifier.reload(
///     "/etc/ssl/client-ca.pem",
///     ClientCertMode::Require,
///     &["/etc/ssl/crl.pem".to_owned()],
/// )?;
/// ```
///
/// [`ClientCertVerifier`]: rustls::server::danger::ClientCertVerifier
/// [`ArcSwap`]: arc_swap::ArcSwap
pub struct ReloadableClientVerifier {
    /// Swappable verifier state.
    inner: Arc<ArcSwap<VerifierState>>,

    /// Whether client auth is mandatory (cached from initial mode).
    mandatory: bool,

    /// Cached root hint subjects from initial CA load.
    root_hints: Vec<DistinguishedName>,
}

impl ReloadableClientVerifier {
    /// Build a reloadable verifier from the initial CA and CRL files.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] if the CA or CRL files cannot be loaded.
    ///
    /// [`TlsError`]: crate::TlsError
    pub fn new(ca_path: &str, mode: ClientCertMode, crl_paths: &[String]) -> Result<Self, TlsError> {
        let verifier = client_auth::build_client_verifier(ca_path, mode, crl_paths)?;
        let root_hints = verifier.root_hint_subjects().to_vec();
        Ok(Self {
            inner: Arc::new(ArcSwap::from_pointee(VerifierState { verifier })),
            mandatory: mode == ClientCertMode::Require,
            root_hints,
        })
    }

    /// Reload the client verifier from disk, atomically swapping
    /// the inner verifier on success.
    ///
    /// On failure the previous verifier remains active.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] if the CA or CRL files cannot be loaded.
    ///
    /// [`TlsError`]: crate::TlsError
    pub fn reload(&self, ca_path: &str, mode: ClientCertMode, crl_paths: &[String]) -> Result<(), TlsError> {
        let verifier = client_auth::build_client_verifier(ca_path, mode, crl_paths)?;
        self.inner.store(Arc::new(VerifierState { verifier }));
        tracing::info!(ca_path, "client verifier hot-reloaded successfully");
        Ok(())
    }

    /// Return an [`Arc`] handle to the inner [`ArcSwap`] for sharing
    /// with the watcher task.
    ///
    /// [`Arc`]: std::sync::Arc
    /// [`ArcSwap`]: arc_swap::ArcSwap
    pub(crate) fn arc(&self) -> Arc<ArcSwap<VerifierState>> {
        Arc::clone(&self.inner)
    }
}

impl std::fmt::Debug for ReloadableClientVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReloadableClientVerifier")
            .field("mandatory", &self.mandatory)
            .finish()
    }
}

impl ClientCertVerifier for ReloadableClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.root_hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.inner
            .load_full()
            .verifier
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .load_full()
            .verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .load_full()
            .verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.load_full().verifier.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.load_full().verifier.requires_raw_public_keys()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use crate::test_utils::{ensure_crypto_provider, gen_ca_file, gen_test_certs};

    #[test]
    fn new_and_resolve_returns_cert() {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };

        let resolver = ReloadableCertResolver::new(&pair).expect("resolver creation should succeed");
        let loaded = resolver.current.load_full();
        assert!(!loaded.cert.is_empty(), "resolved cert chain should not be empty");
    }

    #[test]
    fn reload_swaps_certificate() {
        let certs1 = gen_test_certs();
        let pair1 = CertKeyPair {
            cert_path: certs1.cert_path.to_str().expect("cert1 path").to_owned(),
            default: false,
            key_path: certs1.key_path.to_str().expect("key1 path").to_owned(),
            server_names: Vec::new(),
        };

        let resolver = ReloadableCertResolver::new(&pair1).expect("initial load should succeed");
        let before = resolver.current.load_full();

        let certs2 = gen_test_certs();
        let pair2 = CertKeyPair {
            cert_path: certs2.cert_path.to_str().expect("cert2 path").to_owned(),
            default: false,
            key_path: certs2.key_path.to_str().expect("key2 path").to_owned(),
            server_names: Vec::new(),
        };

        resolver.reload(&pair2).expect("reload should succeed");
        let after = resolver.current.load_full();

        assert_ne!(
            before.cert[0].as_ref(),
            after.cert[0].as_ref(),
            "reloaded cert should differ from original"
        );
    }

    #[test]
    fn reload_invalid_cert_keeps_old() {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };

        let resolver = ReloadableCertResolver::new(&pair).expect("initial load should succeed");
        let before = resolver.current.load_full();

        let bad_pair = CertKeyPair {
            cert_path: "/nonexistent/cert.pem".to_owned(),
            default: false,
            key_path: "/nonexistent/key.pem".to_owned(),
            server_names: Vec::new(),
        };

        let err = resolver.reload(&bad_pair);
        assert!(err.is_err(), "reload with bad path should fail");

        let after = resolver.current.load_full();
        assert_eq!(
            before.cert[0].as_ref(),
            after.cert[0].as_ref(),
            "cert should be unchanged after failed reload"
        );
    }

    #[test]
    fn debug_impl_does_not_panic() {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };
        let resolver = ReloadableCertResolver::new(&pair).expect("resolver creation");
        let dbg = format!("{resolver:?}");
        assert!(
            dbg.contains("ReloadableCertResolver"),
            "Debug output should contain struct name"
        );
    }

    #[test]
    fn concurrent_resolve_during_reload_returns_consistent_cert() {
        let (_c1, pair1) = make_pair();
        let resolver = Arc::new(ReloadableCertResolver::new(&pair1).expect("initial load"));
        let cert1_der = resolver.current.load_full().cert[0].as_ref().to_vec();

        let (_c2, pair2) = make_pair();
        let resolver_clone = Arc::clone(&resolver);
        let handle = std::thread::spawn(move || {
            resolver_clone.reload(&pair2).expect("reload should succeed");
        });

        let observed: Vec<_> = (0..100)
            .map(|_| resolver.current.load_full().cert[0].as_ref().to_vec())
            .collect();
        handle.join().expect("reload thread should not panic");
        let cert2_der = resolver.current.load_full().cert[0].as_ref().to_vec();

        for (i, cert) in observed.iter().enumerate() {
            assert!(
                *cert == cert1_der || *cert == cert2_der,
                "observation {i} must be old or new cert, not a torn read"
            );
        }
    }

    #[test]
    fn arc_handle_reflects_reload() {
        let (_c1, pair1) = make_pair();
        let resolver = ReloadableCertResolver::new(&pair1).expect("initial load");
        let handle = resolver.arc();
        let before = handle.load_full();
        assert!(
            !before.cert.is_empty(),
            "arc() handle should return non-empty cert chain"
        );

        let (_c2, pair2) = make_pair();
        resolver.reload(&pair2).expect("reload should succeed");
        let after = handle.load_full();

        assert_ne!(
            before.cert[0].as_ref(),
            after.cert[0].as_ref(),
            "arc() handle should reflect reloaded cert"
        );
    }

    #[test]
    fn reloadable_verifier_new_returns_valid_verifier() {
        ensure_crypto_provider();
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path");

        let verifier = ReloadableClientVerifier::new(ca_path, ClientCertMode::Require, &[])
            .expect("valid CA should produce a verifier");
        assert!(
            verifier.client_auth_mandatory(),
            "Require mode should make auth mandatory"
        );
        assert!(verifier.offer_client_auth(), "verifier should offer client auth");
        assert!(
            !verifier.root_hint_subjects().is_empty(),
            "root hints should contain at least one CA subject"
        );
    }

    #[test]
    fn reloadable_verifier_request_mode_not_mandatory() {
        ensure_crypto_provider();
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path");

        let verifier = ReloadableClientVerifier::new(ca_path, ClientCertMode::Request, &[])
            .expect("valid CA should produce a verifier");
        assert!(
            !verifier.client_auth_mandatory(),
            "Request mode should not make auth mandatory"
        );
    }

    #[test]
    fn reloadable_verifier_reload_swaps_inner() {
        ensure_crypto_provider();
        let ca1 = gen_ca_file();
        let ca1_path = ca1.ca_path.to_str().expect("ca1 path");

        let verifier = ReloadableClientVerifier::new(ca1_path, ClientCertMode::Require, &[]).expect("initial verifier");
        let schemes_before = verifier.supported_verify_schemes();

        let ca2 = gen_ca_file();
        let ca2_path = ca2.ca_path.to_str().expect("ca2 path");

        verifier
            .reload(ca2_path, ClientCertMode::Require, &[])
            .expect("reload should succeed");
        let schemes_after = verifier.supported_verify_schemes();

        assert_eq!(
            schemes_before, schemes_after,
            "supported verify schemes should be consistent across reloads"
        );
    }

    #[test]
    fn reloadable_verifier_reload_failure_keeps_old() {
        ensure_crypto_provider();
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path");

        let verifier = ReloadableClientVerifier::new(ca_path, ClientCertMode::Require, &[]).expect("initial verifier");
        let hints_before = verifier.root_hint_subjects().len();

        let err = verifier.reload("/nonexistent/ca.pem", ClientCertMode::Require, &[]);
        assert!(err.is_err(), "reload with bad path should fail");
        assert_eq!(
            verifier.root_hint_subjects().len(),
            hints_before,
            "root hints should be unchanged after failed reload"
        );
        assert!(
            verifier.offer_client_auth(),
            "verifier should still offer client auth after failed reload"
        );
    }

    #[test]
    fn reloadable_verifier_debug_impl() {
        ensure_crypto_provider();
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path");

        let verifier = ReloadableClientVerifier::new(ca_path, ClientCertMode::Require, &[]).expect("verifier creation");
        let dbg = format!("{verifier:?}");
        assert!(
            dbg.contains("ReloadableClientVerifier"),
            "Debug output should contain struct name"
        );
    }

    #[test]
    fn reloadable_verifier_arc_handle_reflects_swap() {
        ensure_crypto_provider();
        let ca1 = gen_ca_file();
        let ca1_path = ca1.ca_path.to_str().expect("ca1 path");

        let verifier = ReloadableClientVerifier::new(ca1_path, ClientCertMode::Require, &[]).expect("initial verifier");
        let handle = verifier.arc();
        let state_before = handle.load_full();
        assert!(
            state_before.verifier.offer_client_auth(),
            "initial state should offer client auth"
        );

        let ca2 = gen_ca_file();
        let ca2_path = ca2.ca_path.to_str().expect("ca2 path");
        verifier
            .reload(ca2_path, ClientCertMode::Require, &[])
            .expect("reload should succeed");

        let state_after = handle.load_full();
        assert!(
            state_after.verifier.offer_client_auth(),
            "reloaded state should still offer client auth"
        );
    }

    // ---------------------------------------------------------------------------
    // Test Utilities
    // ---------------------------------------------------------------------------

    /// Build a [`CertKeyPair`] from freshly generated test certs.
    fn make_pair() -> (crate::test_utils::TestCerts, CertKeyPair) {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };
        (certs, pair)
    }
}
