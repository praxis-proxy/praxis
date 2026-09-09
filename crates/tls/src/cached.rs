// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Pre-parsed TLS certificate data for eager caching.
//!
//! Certs and keys are read from disk once at config time, parsed
//! from PEM into DER byte vectors, and stored in [`Arc`]-wrapped
//! containers. Per-connection code converts the DER bytes into
//! library-specific types without touching the filesystem.

use std::{
    any::Any,
    fmt,
    sync::{Arc, OnceLock},
};

use rustls::pki_types::PrivateKeyDer;
use zeroize::Zeroizing;

use crate::TlsError;

// -----------------------------------------------------------------------------
// ConvertedSlot
// -----------------------------------------------------------------------------

/// Memoized library-specific conversion of cached DER material.
///
/// The TLS crate cannot name protocol-library types, so the slot is
/// type erased: the consumer supplies both the conversion closure and
/// the concrete type. Populated once on first use; clones start empty.
struct ConvertedSlot(OnceLock<Box<dyn Any + Send + Sync>>);

impl ConvertedSlot {
    /// Return the memoized value, initializing it on first use.
    ///
    /// Returns `None` only if a previously stored value has a
    /// different type than `T`.
    fn get_or_init<T, F>(&self, init: F) -> Option<&T>
    where
        T: Send + Sync + 'static,
        F: FnOnce() -> T,
    {
        self.0.get_or_init(|| Box::new(init())).downcast_ref::<T>()
    }
}

impl Default for ConvertedSlot {
    fn default() -> Self {
        Self(OnceLock::new())
    }
}

impl Clone for ConvertedSlot {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl fmt::Debug for ConvertedSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.get().is_some() {
            "ConvertedSlot(initialized)"
        } else {
            "ConvertedSlot(empty)"
        })
    }
}

// -----------------------------------------------------------------------------
// CachedCaCerts
// -----------------------------------------------------------------------------

/// DER-encoded CA certificates loaded and parsed at config time.
///
/// ```
/// use praxis_tls::CachedCaCerts;
///
/// let cached = CachedCaCerts::new(vec![vec![1, 2, 3]]);
/// assert_eq!(cached.der_certs().len(), 1);
/// ```
#[derive(Clone, Debug)]
pub struct CachedCaCerts {
    /// Memoized library-specific conversion of the DER certificates.
    converted: ConvertedSlot,

    /// DER-encoded certificate bytes.
    der_certs: Vec<Vec<u8>>,
}

impl CachedCaCerts {
    /// Wrap pre-parsed DER certificate bytes.
    pub fn new(der_certs: Vec<Vec<u8>>) -> Self {
        Self {
            converted: ConvertedSlot::default(),
            der_certs,
        }
    }

    /// Borrow the DER-encoded certificates.
    pub fn der_certs(&self) -> &[Vec<u8>] {
        &self.der_certs
    }

    /// Return the memoized library-specific conversion of these
    /// certificates, initializing it on first use.
    ///
    /// The conversion runs at most once per instance; shared clones of
    /// the containing [`Arc`] observe the same value. Returns `None`
    /// only if a previously stored conversion has a different type.
    pub fn converted_or_init<T, F>(&self, init: F) -> Option<&T>
    where
        T: Send + Sync + 'static,
        F: FnOnce() -> T,
    {
        self.converted.get_or_init(init)
    }

    /// Read and parse a PEM CA file into cached DER certificates.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] if the file cannot be read, contains no
    /// certificates, or has invalid PEM encoding.
    ///
    /// [`TlsError`]: crate::TlsError
    pub fn from_pem_file(ca_path: &str) -> Result<Self, TlsError> {
        let certs = load_and_validate_certs(ca_path, "CA")?;
        tracing::info!(ca_path, count = certs.len(), "cached CA certificates");
        Ok(Self::new(certs))
    }
}

// -----------------------------------------------------------------------------
// CachedClientCert
// -----------------------------------------------------------------------------

/// DER-encoded private key bytes with a redacted [`Debug`] representation.
#[derive(Clone)]
struct CachedPrivateKeyDer(
    /// DER-encoded private key bytes, zeroized when dropped.
    Zeroizing<Vec<u8>>,
);

impl CachedPrivateKeyDer {
    /// Wrap DER-encoded private key bytes.
    fn new(key_der: Zeroizing<Vec<u8>>) -> Self {
        Self(key_der)
    }

    /// Borrow the underlying DER bytes for TLS client certificate setup.
    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for CachedPrivateKeyDer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// DER-encoded client certificate and private key loaded at config time.
///
/// The private key is wrapped in [`Zeroizing`] so it is cleared
/// from memory when the struct is dropped.
///
/// ```
/// use praxis_tls::CachedClientCert;
/// use zeroize::Zeroizing;
///
/// let cached = CachedClientCert::new(vec![vec![1, 2, 3]], Zeroizing::new(vec![4, 5, 6]));
/// assert_eq!(cached.cert_der().len(), 1);
/// assert_eq!(cached.key_der(), &[4, 5, 6]);
/// ```
///
/// [`Zeroizing`]: zeroize::Zeroizing
#[derive(Clone)]
pub struct CachedClientCert {
    /// DER-encoded certificate chain.
    cert_der: Vec<Vec<u8>>,

    /// Memoized library-specific conversion of the cert and key.
    converted: ConvertedSlot,

    /// DER-encoded private key (zeroized on drop).
    key_der: CachedPrivateKeyDer,
}

impl fmt::Debug for CachedClientCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cert_count = self.cert_der.len();
        let cert_der_total_bytes = self.cert_der.iter().map(Vec::len).sum::<usize>();

        f.debug_struct("CachedClientCert")
            .field("cert_count", &cert_count)
            .field("cert_der_total_bytes", &cert_der_total_bytes)
            .field("key_der", &self.key_der)
            .finish()
    }
}

impl CachedClientCert {
    /// Wrap pre-parsed DER certificate chain and private key.
    pub fn new(cert_der: Vec<Vec<u8>>, key_der: Zeroizing<Vec<u8>>) -> Self {
        Self {
            cert_der,
            converted: ConvertedSlot::default(),
            key_der: CachedPrivateKeyDer::new(key_der),
        }
    }

    /// Borrow the DER-encoded certificate chain.
    pub fn cert_der(&self) -> &[Vec<u8>] {
        &self.cert_der
    }

    /// Return the memoized library-specific conversion of this cert and
    /// key, initializing it on first use.
    ///
    /// The conversion runs at most once per instance; shared clones of
    /// the containing [`Arc`] observe the same value. Returns `None`
    /// only if a previously stored conversion has a different type.
    pub fn converted_or_init<T, F>(&self, init: F) -> Option<&T>
    where
        T: Send + Sync + 'static,
        F: FnOnce() -> T,
    {
        self.converted.get_or_init(init)
    }

    /// Borrow the DER-encoded private key.
    pub fn key_der(&self) -> &[u8] {
        self.key_der.as_slice()
    }

    /// Read and parse PEM cert + key files into cached DER data.
    ///
    /// The identity is validated before it is cached: the end-entity
    /// certificate must parse as X.509 and the private key must match
    /// it. A malformed or mismatched identity is therefore rejected at
    /// config time instead of failing every upstream handshake.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] if either file cannot be read, contains
    /// no valid PEM data, the key file has no private key, or the
    /// certificate and key do not form a usable client identity.
    ///
    /// [`TlsError`]: crate::TlsError
    pub fn from_pem_files(cert_path: &str, key_path: &str) -> Result<Self, TlsError> {
        let cert_der = load_and_validate_certs(cert_path, "client cert")?;
        let key = parse_key_pem(key_path)?;
        validate_client_identity(cert_path, key_path, &cert_der, &key)?;
        tracing::info!(cert_path, "cached client certificate");
        Ok(Self::new(cert_der, Zeroizing::new(key.secret_der().to_vec())))
    }
}

// -----------------------------------------------------------------------------
// CachedClusterTls
// -----------------------------------------------------------------------------

/// Pre-parsed TLS material for a cluster, ready for per-connection use.
///
/// Created at config time by [`CachedClusterTls::try_from_config`] and
/// stored on the cluster entry. Avoids any filesystem I/O on the
/// connection path.
///
/// ```
/// use praxis_tls::{CachedClusterTls, ClusterTls};
///
/// let tls = ClusterTls::default();
/// let cached = CachedClusterTls::try_from_config(&tls).unwrap();
/// assert!(cached.ca().is_none());
/// assert!(cached.client_cert().is_none());
/// ```
///
/// [`CachedClusterTls::try_from_config`]: CachedClusterTls::try_from_config
#[derive(Clone, Debug)]
pub struct CachedClusterTls {
    /// Cached CA certificates.
    ca: Option<Arc<CachedCaCerts>>,

    /// Cached client certificate and key.
    client_cert: Option<Arc<CachedClientCert>>,

    /// SNI hostname for outbound connections.
    ///
    /// [`Arc<str>`] so the per-request clone in the load balancer's
    /// upstream construction is reference-counted, not reallocated.
    sni: Option<Arc<str>>,

    /// Whether to verify upstream certificates.
    verify: bool,
}

impl CachedClusterTls {
    /// Build cached TLS material from a [`ClusterTls`] config.
    ///
    /// Reads and parses any referenced cert/key/CA files eagerly.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] if any referenced file cannot be read
    /// or parsed.
    ///
    /// [`ClusterTls`]: crate::ClusterTls
    /// [`TlsError`]: crate::TlsError
    pub fn try_from_config(tls: &crate::ClusterTls) -> Result<Self, TlsError> {
        let ca = tls
            .ca
            .as_ref()
            .map(|c| CachedCaCerts::from_pem_file(&c.ca_path).map(Arc::new))
            .transpose()?;

        let client_cert = tls
            .client_cert
            .as_ref()
            .map(|c| CachedClientCert::from_pem_files(&c.cert_path, &c.key_path).map(Arc::new))
            .transpose()?;

        Ok(Self {
            ca,
            client_cert,
            sni: tls.sni.as_deref().map(Arc::from),
            verify: tls.verify,
        })
    }

    /// Cached CA certificates, if configured.
    pub fn ca(&self) -> Option<&Arc<CachedCaCerts>> {
        self.ca.as_ref()
    }

    /// Cached client certificate and key, if configured.
    pub fn client_cert(&self) -> Option<&Arc<CachedClientCert>> {
        self.client_cert.as_ref()
    }

    /// SNI hostname for outbound connections.
    pub fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }

    /// Set the SNI hostname.
    ///
    /// Accepts anything convertible into `Arc<str>`; pass a `&str` to
    /// allocate the shared buffer once rather than building a `String`
    /// first and copying it.
    pub fn set_sni<S: Into<Arc<str>>>(&mut self, sni: S) {
        self.sni = Some(sni.into());
    }

    /// Whether to verify upstream certificates.
    pub fn verify(&self) -> bool {
        self.verify
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Read a PEM certificate file, parse its certificates, and validate
/// that at least one is present.
fn load_and_validate_certs(path: &str, context: &str) -> Result<Vec<Vec<u8>>, TlsError> {
    tracing::debug!(path, context, "loading certificates");
    let certs = parse_cert_pem(path)?;
    if certs.is_empty() {
        return Err(TlsError::FileLoadError {
            path: path.to_owned(),
            detail: format!("no certificates found in {context} file"),
        });
    }
    Ok(certs)
}

/// Read a PEM certificate file and return DER-encoded certificate bytes.
fn parse_cert_pem(cert_path: &str) -> Result<Vec<Vec<u8>>, TlsError> {
    use rustls::pki_types::{CertificateDer, pem::PemObject as _};

    let pem = read_pem_file(cert_path)?;
    CertificateDer::pem_slice_iter(&pem)
        .map(|item| item.map(|cert| cert.to_vec()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::FileLoadError {
            path: cert_path.to_owned(),
            detail: e.to_string(),
        })
}

/// Read a PEM private key file and return the parsed private key.
///
/// Parsing allocates a fresh copy of the secret DER that this function
/// owns and drops once the bytes have been copied into the cache, so
/// the parsed key is wrapped in [`Zeroizing`] to scrub that copy
/// instead of releasing it intact.
///
/// [`Zeroizing`]: zeroize::Zeroizing
fn parse_key_pem(key_path: &str) -> Result<Zeroizing<PrivateKeyDer<'static>>, TlsError> {
    use rustls::pki_types::pem::PemObject as _;

    let pem = read_pem_file(key_path)?;
    PrivateKeyDer::from_pem_slice(&pem)
        .map(Zeroizing::new)
        .map_err(|e| TlsError::FileLoadError {
            path: key_path.to_owned(),
            detail: if matches!(e, rustls::pki_types::pem::Error::NoItemsFound) {
                "no private key found".to_owned()
            } else {
                e.to_string()
            },
        })
}

/// Check that a client certificate and private key form a usable identity.
///
/// Loads the key through the active crypto provider (rejecting key
/// types no provider can sign with), parses the end-entity certificate
/// as X.509, and compares its subject public key with the key's. This
/// mirrors the gate the listener path applies in
/// [`load_certified_key`], so an unusable cluster identity fails at
/// config time rather than on every upstream connection.
///
/// Intermediate certificates in the chain are not verified here: the
/// upstream handshake is what validates the chain itself.
///
/// [`load_certified_key`]: crate::setup::loader::load_certified_key
fn validate_client_identity(
    cert_path: &str,
    key_path: &str,
    cert_der: &[Vec<u8>],
    key: &PrivateKeyDer<'static>,
) -> Result<(), TlsError> {
    use rustls::{pki_types::CertificateDer, sign::CertifiedKey};

    let signing_key = crate::setup::default_crypto_provider()
        .key_provider
        .load_private_key(key.clone_key())
        .map_err(|e| TlsError::FileLoadError {
            path: key_path.to_owned(),
            detail: format!("unsupported private key type: {e}"),
        })?;

    let certs = cert_der.iter().cloned().map(CertificateDer::from).collect();
    CertifiedKey::new(certs, signing_key)
        .keys_match()
        .map_err(|e| TlsError::FileLoadError {
            path: cert_path.to_owned(),
            detail: format!("client certificate is not a valid X.509 certificate matching the private key: {e}"),
        })
}

/// Read a file into a zeroizing byte vector, mapping I/O errors
/// to [`TlsError`].
///
/// PEM files may contain private key material in combined
/// cert+key bundles, so all reads are wrapped in [`Zeroizing`]
/// to clear memory on drop.
///
/// [`TlsError`]: crate::TlsError
/// [`Zeroizing`]: zeroize::Zeroizing
fn read_pem_file(path: &str) -> Result<Zeroizing<Vec<u8>>, TlsError> {
    std::fs::read(path)
        .map(Zeroizing::new)
        .map_err(|e| TlsError::FileLoadError {
            path: path.to_owned(),
            detail: e.to_string(),
        })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use crate::test_utils::{gen_ca_file, gen_test_certs};

    #[test]
    fn cached_ca_certs_stores_der() {
        let certs = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let cached = CachedCaCerts::new(certs.clone());
        assert_eq!(cached.der_certs().len(), 2, "should store two CA certs");
        assert_eq!(cached.der_certs()[0], certs[0], "first cert DER should match");
    }

    #[test]
    fn cached_client_cert_stores_der() {
        let cert_der = vec![vec![10, 20]];
        let key_der = Zeroizing::new(vec![30, 40]);
        let cached = CachedClientCert::new(cert_der.clone(), key_der.clone());
        assert_eq!(cached.cert_der().len(), 1, "should store one client cert");
        assert_eq!(cached.key_der(), &*key_der, "key DER should match");
    }

    #[test]
    fn cached_ca_from_pem_file_nonexistent() {
        let err = CachedCaCerts::from_pem_file("/nonexistent/ca.pem");
        assert!(err.is_err(), "nonexistent file should fail");
    }

    #[test]
    fn cached_ca_from_pem_file_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("empty.pem");
        std::fs::write(&path, "").unwrap();

        let err = CachedCaCerts::from_pem_file(path.to_str().unwrap());
        assert!(err.is_err(), "empty PEM should fail");
    }

    #[test]
    fn cached_ca_from_pem_file_valid() {
        let ca = gen_ca_file();
        let cached = CachedCaCerts::from_pem_file(ca.ca_path.to_str().unwrap()).expect("valid CA PEM should parse");
        assert_eq!(cached.der_certs().len(), 1, "should parse one CA cert");
    }

    #[test]
    fn cached_ca_from_pem_file_multi_cert() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("multi-ca.pem");

        let key1 = rcgen::KeyPair::generate().unwrap();
        let mut params1 = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params1.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params1.distinguished_name.push(rcgen::DnType::CommonName, "CA One");
        let cert1 = params1.self_signed(&key1).unwrap();

        let key2 = rcgen::KeyPair::generate().unwrap();
        let mut params2 = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params2.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params2.distinguished_name.push(rcgen::DnType::CommonName, "CA Two");
        let cert2 = params2.self_signed(&key2).unwrap();

        let pem = format!("{}{}", cert1.pem(), cert2.pem());
        std::fs::write(&path, pem).unwrap();

        let cached = CachedCaCerts::from_pem_file(path.to_str().unwrap()).expect("multi-cert PEM should parse");
        assert_eq!(cached.der_certs().len(), 2, "should parse two CA certs");
    }

    #[test]
    fn cached_client_cert_from_pem_nonexistent() {
        let err = CachedClientCert::from_pem_files("/no/cert.pem", "/no/key.pem");
        assert!(err.is_err(), "nonexistent files should fail");
    }

    #[test]
    fn cached_client_cert_from_pem_missing_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, "").unwrap();
        std::fs::write(&key_path, "").unwrap();

        let err = CachedClientCert::from_pem_files(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
        assert!(err.is_err(), "empty key PEM should fail");
    }

    #[test]
    fn cached_client_cert_from_pem_empty_cert() {
        let pair = gen_test_certs();
        let dir = tempfile::TempDir::new().unwrap();
        let empty_cert = dir.path().join("empty.pem");
        std::fs::write(&empty_cert, "").unwrap();

        let err = CachedClientCert::from_pem_files(empty_cert.to_str().unwrap(), pair.key_path.to_str().unwrap());
        assert!(err.is_err(), "empty cert PEM should fail");
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("no certificates found"),
            "error should mention missing certificates: {msg}"
        );
    }

    #[test]
    fn cached_client_cert_from_pem_valid() {
        let pair = gen_test_certs();
        let cached =
            CachedClientCert::from_pem_files(pair.cert_path.to_str().unwrap(), pair.key_path.to_str().unwrap())
                .expect("valid cert+key PEM should parse");
        assert!(!cached.cert_der().is_empty(), "should parse at least one cert");
        assert!(!cached.key_der().is_empty(), "key DER should not be empty");
    }

    #[test]
    fn parsed_private_key_is_returned_in_a_scrubbing_wrapper() {
        use zeroize::Zeroize as _;

        let identity = gen_test_certs();
        // The annotation pins the contract: the parsed key must come back in a
        // wrapper that scrubs the secret DER it owns when it is dropped, not as
        // a bare `PrivateKeyDer` whose buffer is released intact.
        let mut key: Zeroizing<PrivateKeyDer<'static>> =
            parse_key_pem(identity.key_path.to_str().unwrap()).expect("valid key PEM should parse");

        let before = key.secret_der().to_vec();
        assert!(
            before.iter().any(|b| *b != 0),
            "the parsed key should hold secret bytes"
        );

        key.zeroize();
        assert_ne!(
            key.secret_der(),
            before.as_slice(),
            "the secret DER must not survive zeroization"
        );
        assert!(
            key.secret_der().iter().all(|b| *b == 0),
            "any remaining key bytes must be cleared"
        );
    }

    #[test]
    fn client_cert_with_mismatched_key_rejected() {
        let identity = gen_test_certs();
        let other = gen_test_certs();

        let err =
            CachedClientCert::from_pem_files(identity.cert_path.to_str().unwrap(), other.key_path.to_str().unwrap())
                .expect_err("a key from a different identity must be rejected");

        let msg = err.to_string();
        assert!(
            msg.contains("matching the private key"),
            "error should report the cert/key mismatch: {msg}"
        );
    }

    #[test]
    fn client_cert_with_malformed_certificate_rejected() {
        let identity = gen_test_certs();
        let dir = tempfile::TempDir::new().unwrap();
        let cert_path = dir.path().join("garbage.pem");
        // A well-formed PEM frame whose payload is not an X.509 certificate:
        // base64 decoding alone accepts it, X.509 parsing must not.
        std::fs::write(
            &cert_path,
            "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let err = CachedClientCert::from_pem_files(cert_path.to_str().unwrap(), identity.key_path.to_str().unwrap())
            .expect_err("a PEM block that is not an X.509 certificate must be rejected");

        let msg = err.to_string();
        assert!(
            msg.contains("valid X.509 certificate"),
            "error should report the invalid certificate: {msg}"
        );
    }

    #[test]
    fn client_cert_chain_with_leaf_first_accepted() {
        let identity = gen_test_certs();
        let dir = tempfile::TempDir::new().unwrap();
        let chain_path = dir.path().join("chain.pem");
        let leaf = std::fs::read_to_string(&identity.cert_path).unwrap();
        let issuer = std::fs::read_to_string(&identity.ca_cert_path).unwrap();
        std::fs::write(&chain_path, format!("{leaf}{issuer}")).unwrap();

        let cached =
            CachedClientCert::from_pem_files(chain_path.to_str().unwrap(), identity.key_path.to_str().unwrap())
                .expect("a leaf-first chain with its matching key must stay accepted");
        assert_eq!(cached.cert_der().len(), 2, "both chain certificates should be cached");
    }

    #[test]
    fn cached_cluster_tls_no_certs() {
        let tls = crate::ClusterTls::default();
        let cached = CachedClusterTls::try_from_config(&tls).expect("default tls should succeed");
        assert!(cached.ca().is_none(), "no CA should be cached");
        assert!(cached.client_cert().is_none(), "no client cert should be cached");
        assert!(cached.verify(), "verify should default to true");
    }

    #[test]
    fn cached_cluster_tls_with_ca() {
        let ca = gen_ca_file();
        let tls = crate::ClusterTls {
            ca: Some(crate::CaConfig {
                ca_path: ca.ca_path.to_str().unwrap().to_owned(),
                crl_paths: Vec::new(),
            }),
            ..crate::ClusterTls::default()
        };
        let cached = CachedClusterTls::try_from_config(&tls).expect("tls with CA should succeed");
        assert!(cached.ca().is_some(), "CA should be cached");
        assert_eq!(cached.ca().unwrap().der_certs().len(), 1, "should cache one CA cert");
    }

    #[test]
    fn cached_cluster_tls_with_client_cert() {
        let pair = gen_test_certs();
        let tls = crate::ClusterTls {
            client_cert: Some(crate::CertKeyPair {
                cert_path: pair.cert_path.to_str().unwrap().to_owned(),
                default: false,
                key_path: pair.key_path.to_str().unwrap().to_owned(),
                server_names: Vec::new(),
            }),
            ..crate::ClusterTls::default()
        };
        let cached = CachedClusterTls::try_from_config(&tls).expect("tls with client cert should succeed");
        assert!(cached.client_cert().is_some(), "client cert should be cached");
    }

    #[test]
    fn cached_cluster_tls_sni_accessors() {
        let tls = crate::ClusterTls {
            sni: Some("api.example.com".to_owned()),
            ..crate::ClusterTls::default()
        };
        let cached = CachedClusterTls::try_from_config(&tls).unwrap();
        assert_eq!(cached.sni(), Some("api.example.com"), "sni should match");
    }

    #[test]
    fn cached_cluster_tls_set_sni() {
        let tls = crate::ClusterTls::default();
        let mut cached = CachedClusterTls::try_from_config(&tls).unwrap();
        assert!(cached.sni().is_none(), "sni should start as None");
        cached.set_sni("new.example.com".to_owned());
        assert_eq!(cached.sni(), Some("new.example.com"), "sni should be updated");
    }

    #[test]
    fn cached_cluster_tls_verify_disabled() {
        let tls = crate::ClusterTls {
            verify: false,
            ..crate::ClusterTls::default()
        };
        let cached = CachedClusterTls::try_from_config(&tls).unwrap();
        assert!(!cached.verify(), "verify should be false");
    }

    #[test]
    fn cached_cluster_tls_invalid_ca_path_fails() {
        let tls = crate::ClusterTls {
            ca: Some(crate::CaConfig {
                ca_path: "/nonexistent/ca.pem".to_owned(),
                crl_paths: Vec::new(),
            }),
            ..crate::ClusterTls::default()
        };
        assert!(
            CachedClusterTls::try_from_config(&tls).is_err(),
            "invalid CA path should fail"
        );
    }

    #[test]
    fn cached_cluster_tls_invalid_client_cert_fails() {
        let tls = crate::ClusterTls {
            client_cert: Some(crate::CertKeyPair {
                cert_path: "/nonexistent/cert.pem".to_owned(),
                default: false,
                key_path: "/nonexistent/key.pem".to_owned(),
                server_names: Vec::new(),
            }),
            ..crate::ClusterTls::default()
        };
        assert!(
            CachedClusterTls::try_from_config(&tls).is_err(),
            "invalid client cert path should fail"
        );
    }

    #[test]
    fn converted_slot_initializes_once() {
        let cached = CachedCaCerts::new(vec![vec![1, 2, 3]]);
        let mut calls = 0_u32;
        let first = *cached
            .converted_or_init(|| {
                calls += 1;
                42_u64
            })
            .unwrap();
        let second = *cached.converted_or_init(|| 99_u64).unwrap();
        assert_eq!(calls, 1, "conversion must run exactly once");
        assert_eq!(first, 42, "first call stores the converted value");
        assert_eq!(second, 42, "second call returns the memoized value");
    }

    #[test]
    fn converted_slot_type_mismatch_returns_none() {
        let cached = CachedCaCerts::new(vec![vec![1]]);
        let _stored = cached.converted_or_init(|| 1_u64);
        assert!(
            cached.converted_or_init(|| "other".to_owned()).is_none(),
            "a mismatched type must not observe the stored value"
        );
    }

    #[test]
    fn converted_slot_clone_starts_empty() {
        let cached = CachedCaCerts::new(vec![vec![1]]);
        let _stored = cached.converted_or_init(|| 7_u64);
        let cloned = cached.clone();
        let value = *cloned.converted_or_init(|| 8_u64).unwrap();
        assert_eq!(value, 8, "clones must not share the memoized conversion");
    }

    #[test]
    fn client_cert_converted_slot_initializes_once() {
        let cached = CachedClientCert::new(vec![vec![1]], Zeroizing::new(vec![2]));
        let first = *cached.converted_or_init(|| 5_u64).unwrap();
        let second = *cached.converted_or_init(|| 6_u64).unwrap();
        assert_eq!(first, second, "client cert conversion must be memoized");
    }

    #[test]
    fn cached_ca_clone() {
        let cached = CachedCaCerts::new(vec![vec![1, 2, 3]]);
        let cloned = cached.clone();
        assert_eq!(cached.der_certs(), cloned.der_certs(), "cloned CA certs should match");
    }

    #[test]
    fn cached_client_cert_debug_redacts_key() {
        let cert_der = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let key_der = [0xCA, 0xFE, 0xBA, 0xBE];
        let cached = CachedClientCert::new(vec![cert_der], Zeroizing::new(key_der.to_vec()));
        let debug = format!("{cached:?}");
        assert!(debug.contains("REDACTED"), "Debug output should redact the key");
        assert!(debug.contains("cert_count"), "Debug output should retain cert metadata");
        assert!(!debug.contains("222"), "Debug output must not contain cert DER bytes");
        assert!(!debug.contains("202"), "Debug output must not contain key bytes");
        assert!(!debug.contains("254"), "Debug output must not contain key bytes");
        assert!(!debug.contains("186"), "Debug output must not contain key bytes");
    }

    #[test]
    fn cached_cluster_tls_debug_redacts_client_key() {
        let key_der = [250, 251, 252];
        let client_cert = CachedClientCert::new(vec![vec![10]], Zeroizing::new(key_der.to_vec()));
        let cached = CachedClusterTls {
            ca: None,
            client_cert: Some(Arc::new(client_cert)),
            sni: Some(Arc::from("api.example.com")),
            verify: true,
        };

        let debug = format!("{cached:?}");
        assert!(debug.contains("REDACTED"), "Debug output should redact the client key");
        assert!(!debug.contains("250"), "Debug output must not contain key bytes");
        assert!(!debug.contains("251"), "Debug output must not contain key bytes");
        assert!(!debug.contains("252"), "Debug output must not contain key bytes");
    }

    #[test]
    fn cached_client_cert_clone() {
        let cached = CachedClientCert::new(vec![vec![10]], Zeroizing::new(vec![20]));
        let cloned = cached.clone();
        assert_eq!(cached.cert_der(), cloned.cert_der(), "cloned cert DER should match");
        assert_eq!(cached.key_der(), cloned.key_der(), "cloned key DER should match");
    }

    #[test]
    fn cached_cluster_tls_clone_preserves_arc() {
        let ca = gen_ca_file();
        let tls = crate::ClusterTls {
            ca: Some(crate::CaConfig {
                ca_path: ca.ca_path.to_str().unwrap().to_owned(),
                crl_paths: Vec::new(),
            }),
            ..crate::ClusterTls::default()
        };
        let cached = CachedClusterTls::try_from_config(&tls).unwrap();
        let cloned = cached.clone();
        assert!(
            Arc::ptr_eq(cached.ca().unwrap(), cloned.ca().unwrap()),
            "cloned CachedClusterTls should share CA Arc"
        );
    }
}
