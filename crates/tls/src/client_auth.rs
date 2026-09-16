// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Client certificate verifier construction for listener mTLS.
//!
//! When the `config-reload` feature is enabled and a listener uses
//! [`ReloadableClientVerifier`], CRL and CA files are monitored
//! for changes and the verifier is atomically rebuilt on disk
//! modifications.
//!
//! [`ReloadableClientVerifier`]: crate::reload::ReloadableClientVerifier

use std::sync::Arc;

use rustls::{
    DistinguishedName, RootCertStore, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime, pem::PemObject as _},
    server::{
        WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};

use crate::{ClientCertMode, TlsError, spiffe::svid_id_allowed};

// -----------------------------------------------------------------------------
// Verifier Builder
// -----------------------------------------------------------------------------

/// Build a [`ClientCertVerifier`] from a CA PEM file and verification mode.
///
/// When `crl_paths` is non-empty, the verifier checks presented client
/// certificates against the provided CRLs and rejects revoked certificates.
///
/// For [`ClientCertMode::RequireNamed`], `trusted_spiffe_ids` is the set of
/// SPIFFE IDs authorized at the handshake. An empty set accepts any valid
/// X.509-SVID leaf; a non-empty set requires the peer's SPIFFE ID to be a member.
///
/// # Errors
///
/// Returns [`TlsError`] if the CA or CRL files cannot be read or parsed,
/// or if `mode` is [`ClientCertMode::None`].
///
/// ```ignore
/// use std::sync::Arc;
///
/// use crate::{ClientCertMode, client_auth::build_client_verifier};
///
/// let verifier = build_client_verifier(
///     "/etc/ssl/client-ca.pem",
///     ClientCertMode::Require,
///     &[],
///     &[],
/// )
/// .expect("valid CA file");
/// ```
///
/// [`ClientCertVerifier`]: rustls::server::danger::ClientCertVerifier
/// [`TlsError`]: crate::TlsError
/// [`ClientCertMode::None`]: crate::ClientCertMode::None
pub(crate) fn build_client_verifier(
    ca_path: &str,
    mode: ClientCertMode,
    crl_paths: &[String],
    trusted_spiffe_ids: &[String],
) -> Result<Arc<dyn ClientCertVerifier>, TlsError> {
    let root_store = load_ca_root_store(ca_path)?;
    let mut builder = WebPkiClientVerifier::builder(Arc::new(root_store));

    if !crl_paths.is_empty() {
        let crls = load_crls(crl_paths)?;
        builder = builder.with_crls(crls);
    }

    let verifier_err = |detail: String| TlsError::FileLoadError {
        path: ca_path.to_owned(),
        detail,
    };

    match mode {
        ClientCertMode::Request => builder
            .allow_unauthenticated()
            .build()
            .map_err(|e| verifier_err(format!("failed to build verifier: {e}"))),
        ClientCertMode::Require => builder
            .build()
            .map_err(|e| verifier_err(format!("failed to build verifier: {e}"))),
        ClientCertMode::RequireNamed => builder
            .build()
            .map(|inner| named_verifier(inner, trusted_spiffe_ids))
            .map_err(|e| verifier_err(format!("failed to build verifier: {e}"))),
        ClientCertMode::None => Err(TlsError::ClientVerifierNotRequired),
    }
}

/// Wrap an inner verifier in a [`NamedPeerVerifier`].
///
/// Warns when the allowlist is empty: `RequireNamed` then accepts any valid
/// X.509-SVID the client CA signs, which is a safe default but easy to set
/// unintentionally.
fn named_verifier(inner: Arc<dyn ClientCertVerifier>, trusted_spiffe_ids: &[String]) -> Arc<dyn ClientCertVerifier> {
    if trusted_spiffe_ids.is_empty() {
        tracing::warn!(
            "client_cert_mode is require_named with an empty trusted_spiffe_ids: \
             any valid SVID the client CA signs is accepted"
        );
    }
    let allowed: Arc<[Arc<str>]> = trusted_spiffe_ids.iter().map(|id| Arc::from(id.as_str())).collect();
    Arc::new(NamedPeerVerifier { inner, allowed })
}

// -----------------------------------------------------------------------------
// NamedPeerVerifier
// -----------------------------------------------------------------------------

/// Authorizes a peer at the handshake by the SPIFFE ID in its client certificate.
///
/// Chain is verified first, so the name is read only from a certificate that
/// already validated against the configured authority. Rejecting here ends the
/// handshake, before any request.
#[derive(Debug)]
struct NamedPeerVerifier {
    /// Verifier that validates the chain before the name is read.
    inner: Arc<dyn ClientCertVerifier>,

    /// Authorized SPIFFE IDs, immutable and shared. Empty accepts any valid
    /// X.509-SVID leaf. Read-only on the verify path, so no lock is taken.
    allowed: Arc<[Arc<str>]>,
}

impl ClientCertVerifier for NamedPeerVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // RFC 5280 §6: chain before name.
        let verified = self.inner.verify_client_cert(end_entity, intermediates, now)?;

        // X509-SVID §5.2 leaf, then allowlist.
        if svid_id_allowed(end_entity.as_ref(), &self.allowed) {
            Ok(verified)
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }
}

// -----------------------------------------------------------------------------
// CRL Loading
// -----------------------------------------------------------------------------

/// Load CRL files from PEM-encoded paths.
fn load_crls(paths: &[String]) -> Result<Vec<CertificateRevocationListDer<'static>>, TlsError> {
    let mut crls = Vec::new();
    for path in paths {
        let pem = zeroize::Zeroizing::new(std::fs::read(path).map_err(|e| TlsError::FileLoadError {
            path: path.clone(),
            detail: e.to_string(),
        })?);

        let parsed: Vec<_> = CertificateRevocationListDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::FileLoadError {
                path: path.clone(),
                detail: format!("failed to parse CRL PEM: {e}"),
            })?;
        if parsed.is_empty() {
            return Err(TlsError::FileLoadError {
                path: path.clone(),
                detail: "no CRLs found in PEM file".to_owned(),
            });
        }
        crls.extend(parsed);
    }
    Ok(crls)
}

/// Build a [`RootCertStore`] from a PEM bundle.
///
/// Returns an error detail string the caller maps to its own [`TlsError`]
/// variant, so the same bytes-to-store logic serves both a file-loading listener
/// and an in-memory client config.
///
/// # Errors
///
/// Returns a detail string when the PEM is malformed, contains no certificates,
/// or a certificate is rejected as a trust anchor.
///
/// [`RootCertStore`]: rustls::RootCertStore
pub(crate) fn roots_from_pem(pem: &[u8]) -> Result<RootCertStore, String> {
    let certs: Vec<_> = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse PEM: {e}"))?;
    if certs.is_empty() {
        return Err("no certificates found in PEM".to_owned());
    }

    let mut root_store = RootCertStore::empty();
    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| format!("failed to add CA cert: {e}"))?;
    }
    Ok(root_store)
}

/// Load CA certificates from a PEM file into a [`RootCertStore`].
///
/// [`RootCertStore`]: rustls::RootCertStore
fn load_ca_root_store(ca_path: &str) -> Result<RootCertStore, TlsError> {
    let ca_pem = zeroize::Zeroizing::new(std::fs::read(ca_path).map_err(|e| TlsError::FileLoadError {
        path: ca_path.to_owned(),
        detail: e.to_string(),
    })?);
    roots_from_pem(&ca_pem).map_err(|detail| TlsError::FileLoadError {
        path: ca_path.to_owned(),
        detail,
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use crate::test_utils::{ensure_crypto_provider, gen_ca_file};

    #[test]
    fn build_client_verifier_require_with_valid_ca() {
        ensure_crypto_provider();
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let verifier = build_client_verifier(ca_path, ClientCertMode::Require, &[], &[])
            .expect("require mode with valid CA should succeed");
        assert!(
            verifier.client_auth_mandatory(),
            "require mode should mandate client auth"
        );
    }

    #[test]
    fn build_client_verifier_request_with_valid_ca() {
        ensure_crypto_provider();
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let verifier = build_client_verifier(ca_path, ClientCertMode::Request, &[], &[])
            .expect("request mode with valid CA should succeed");
        assert!(
            !verifier.client_auth_mandatory(),
            "request mode should not mandate client auth"
        );
    }

    #[test]
    fn build_client_verifier_none_mode_returns_error() {
        ensure_crypto_provider();
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let err =
            build_client_verifier(ca_path, ClientCertMode::None, &[], &[]).expect_err("mode=None should return error");
        assert!(
            matches!(err, TlsError::ClientVerifierNotRequired),
            "error should be ClientVerifierNotRequired, got: {err}"
        );
    }

    #[test]
    fn build_client_verifier_invalid_ca_path_returns_error() {
        let err = build_client_verifier("/nonexistent/ca.pem", ClientCertMode::Require, &[], &[])
            .expect_err("nonexistent CA should fail");
        assert!(
            matches!(err, TlsError::FileLoadError { .. }),
            "error should be FileLoadError, got: {err}"
        );
    }

    #[test]
    fn load_ca_root_store_with_valid_ca() {
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let store = load_ca_root_store(ca_path).expect("valid CA file should load");
        assert!(!store.is_empty(), "root store should contain at least one certificate");
    }

    #[test]
    fn load_ca_root_store_empty_pem_returns_error() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let empty_path = temp_dir.path().join("empty.pem");
        std::fs::write(&empty_path, "").expect("write empty PEM should succeed");

        let err = load_ca_root_store(empty_path.to_str().expect("path should be valid UTF-8"))
            .expect_err("empty PEM should fail");
        assert!(
            matches!(&err, TlsError::FileLoadError { detail, .. } if detail.contains("no certificates")),
            "error should mention no certificates, got: {err}"
        );
    }

    #[test]
    fn load_ca_root_store_nonexistent_file_returns_error() {
        let err = load_ca_root_store("/nonexistent/ca.pem").expect_err("nonexistent file should fail");
        assert!(
            matches!(err, TlsError::FileLoadError { .. }),
            "error should be FileLoadError, got: {err}"
        );
    }

    #[test]
    fn load_crls_nonexistent_file_returns_error() {
        let err = load_crls(&["/nonexistent/crl.pem".to_owned()]).expect_err("nonexistent CRL file should fail");
        assert!(
            matches!(err, TlsError::FileLoadError { .. }),
            "error should be FileLoadError, got: {err}"
        );
        assert!(
            err.to_string().contains("load"),
            "error should mention file loading, got: {err}"
        );
    }

    #[test]
    fn load_crls_empty_pem_returns_error() {
        let temp = tempfile::NamedTempFile::new().expect("tempfile creation should succeed");
        std::fs::write(temp.path(), "").expect("write empty file should succeed");
        let path = temp.path().to_str().expect("path should be valid UTF-8").to_owned();

        let err = load_crls(&[path]).expect_err("empty PEM should fail");
        assert!(
            err.to_string().contains("no CRLs found"),
            "error should mention no CRLs found, got: {err}"
        );
    }

    /// Generate a CA PEM and an empty CRL PEM signed by that CA.
    fn gen_ca_and_crl(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let ca_key = rcgen::KeyPair::generate().expect("CA key generation");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "CRL Test CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-sign");
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);

        let crl = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2026, 1, 1),
            next_update: rcgen::date_time_ymd(2036, 1, 1),
            crl_number: rcgen::SerialNumber::from_slice(&[1]),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&issuer)
        .expect("CRL signing");

        let ca_path = dir.join("ca.pem");
        let crl_path = dir.join("crl.pem");
        std::fs::write(&ca_path, ca_cert.pem()).expect("write CA PEM");
        std::fs::write(&crl_path, crl.pem().expect("CRL PEM encoding")).expect("write CRL PEM");
        (ca_path, crl_path)
    }

    #[test]
    fn build_client_verifier_with_valid_crl() {
        ensure_crypto_provider();
        let dir = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let (ca_path, crl_path) = gen_ca_and_crl(dir.path());

        let verifier = build_client_verifier(
            ca_path.to_str().expect("ca path should be valid UTF-8"),
            ClientCertMode::Require,
            &[crl_path.to_str().expect("crl path should be valid UTF-8").to_owned()],
            &[],
        )
        .expect("require mode with valid CA and CRL should succeed");
        assert!(
            verifier.client_auth_mandatory(),
            "require mode with CRLs should still mandate client auth"
        );
    }

    #[test]
    fn load_crls_parses_generated_crl() {
        let dir = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let (_ca_path, crl_path) = gen_ca_and_crl(dir.path());

        let crls = load_crls(&[crl_path.to_str().expect("crl path should be valid UTF-8").to_owned()])
            .expect("valid CRL PEM should parse");
        assert_eq!(crls.len(), 1, "exactly one CRL should be parsed");
    }

    #[test]
    fn load_ca_root_store_rejects_garbage_certificate_der() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let bad_path = temp_dir.path().join("bad.pem");
        std::fs::write(
            &bad_path,
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        )
        .expect("write bad PEM should succeed");

        let err = load_ca_root_store(bad_path.to_str().expect("path should be valid UTF-8"))
            .expect_err("garbage certificate DER should fail");
        assert!(
            matches!(&err, TlsError::FileLoadError { detail, .. } if detail.contains("failed to add CA cert")),
            "error should mention the failing add, got: {err}"
        );
    }

    // ---- NamedPeerVerifier ----

    #[test]
    fn require_named_mode_mandates_client_auth() {
        ensure_crypto_provider();
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let verifier = build_client_verifier(ca_path, ClientCertMode::RequireNamed, &[], &[])
            .expect("require-named mode with valid CA should succeed");
        assert!(
            verifier.client_auth_mandatory(),
            "require-named mode should mandate client auth"
        );
    }

    #[test]
    fn require_named_mode_with_allowlist_mandates_client_auth() {
        ensure_crypto_provider();
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let verifier = build_client_verifier(
            ca_path,
            ClientCertMode::RequireNamed,
            &[],
            &["spiffe://grid.internal/site/pool-a".to_owned()],
        )
        .expect("require-named mode with an allowlist should succeed");
        assert!(
            verifier.client_auth_mandatory(),
            "require-named mode with an allowlist should mandate client auth"
        );
    }

    // ---- NamedPeerVerifier authorization decision ----

    /// Mint a CA (written to a temp PEM) and a client leaf it signs carrying
    /// `leaf_uris` as URI SANs with a clientAuth EKU. Returns the temp dir (kept
    /// alive so the CA file outlives the call), the CA path, and the leaf DER.
    fn mint_client(leaf_uris: &[&str]) -> (tempfile::TempDir, std::path::PathBuf, CertificateDer<'static>) {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, SanType,
        };

        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "Grid CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
        let issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        leaf_params.distinguished_name.push(DnType::CommonName, "peer");
        for uri in leaf_uris {
            leaf_params
                .subject_alt_names
                .push(SanType::URI((*uri).try_into().expect("uri san")));
        }
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let leaf_der = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf cert")
            .der()
            .clone();

        let dir = tempfile::TempDir::new().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, ca_cert.pem()).expect("write ca pem");
        (dir, ca_path, leaf_der)
    }

    /// Build a `RequireNamed` verifier over `ca_path` + `allowlist` and run the
    /// leaf through `verify_client_cert` (chain, then X509-SVID §5.2, then allowlist).
    fn named_verify(
        ca_path: &std::path::Path,
        allowlist: &[String],
        leaf: &CertificateDer<'_>,
    ) -> Result<(), rustls::Error> {
        ensure_crypto_provider();
        let verifier = build_client_verifier(
            ca_path.to_str().expect("ca path utf-8"),
            ClientCertMode::RequireNamed,
            &[],
            allowlist,
        )
        .expect("build require-named verifier");
        verifier
            .verify_client_cert(leaf, &[], UnixTime::now())
            .map(|_verified| ())
    }

    #[test]
    fn a_named_peer_in_the_allowlist_is_accepted() {
        let id = "spiffe://grid.internal/site/pool-a";
        let (_dir, ca_path, leaf) = mint_client(&[id]);
        named_verify(&ca_path, &[id.to_owned()], &leaf).expect("an allowlisted SVID is accepted");
    }

    #[test]
    fn a_named_peer_outside_the_allowlist_is_refused() {
        let (_dir, ca_path, leaf) = mint_client(&["spiffe://grid.internal/site/pool-b"]);
        let err = named_verify(&ca_path, &["spiffe://grid.internal/site/pool-a".to_owned()], &leaf)
            .expect_err("a CA-signed but unlisted SVID is refused");
        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
            ),
            "an unlisted peer should fail application verification, got: {err}"
        );
    }

    #[test]
    fn a_named_peer_in_a_foreign_trust_domain_is_refused() {
        // Same path, different trust domain: the allowlist match is over the
        // whole id, so a foreign domain is not a member.
        let (_dir, ca_path, leaf) = mint_client(&["spiffe://evil.example/site/pool-a"]);
        named_verify(&ca_path, &["spiffe://grid.internal/site/pool-a".to_owned()], &leaf)
            .expect_err("a foreign trust domain is not an allowlist member");
    }

    #[test]
    fn an_empty_allowlist_accepts_any_ca_signed_svid() {
        let (_dir, ca_path, leaf) = mint_client(&["spiffe://grid.internal/site/anyone"]);
        named_verify(&ca_path, &[], &leaf).expect("an empty allowlist accepts any valid SVID the CA signs");
    }

    #[test]
    fn a_listed_non_spiffe_leaf_is_refused() {
        // A clientAuth leaf that chains, but whose only SAN is a non-SPIFFE URI:
        // it fails the X509-SVID §5.2 leaf gate before the allowlist is consulted,
        // even though the exact string is listed.
        let (_dir, ca_path, leaf) = mint_client(&["https://grid.internal/not-spiffe"]);
        named_verify(&ca_path, &["https://grid.internal/not-spiffe".to_owned()], &leaf)
            .expect_err("a non-SPIFFE leaf is refused even when its URI string is listed");
    }

    #[test]
    fn a_leaf_off_the_trusted_ca_is_refused() {
        // The rogue leaf carries the right name and is listed, but is signed by a
        // different CA: chain-before-name rejects it before the allowlist.
        let id = "spiffe://grid.internal/site/pool-a";
        let (_rogue_dir, _rogue_ca, rogue_leaf) = mint_client(&[id]);
        let (_dir, trusted_ca, _unused) = mint_client(&[id]);
        let err =
            named_verify(&trusted_ca, &[id.to_owned()], &rogue_leaf).expect_err("a leaf off the trusted CA is refused");
        assert!(
            matches!(err, rustls::Error::InvalidCertificate(_)),
            "an off-CA leaf should be a certificate error, got: {err}"
        );
    }
}
