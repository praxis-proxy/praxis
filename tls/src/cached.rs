// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Pre-parsed TLS certificate data for eager caching.
//!
//! Certs and keys are read from disk once at config time, parsed
//! from PEM into DER byte vectors, and stored in [`Arc`]-wrapped
//! containers. Per-connection code converts the DER bytes into
//! library-specific types without touching the filesystem.

use std::sync::Arc;

use crate::TlsError;

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
#[derive(Debug, Clone)]
pub struct CachedCaCerts {
    /// DER-encoded certificate bytes.
    der_certs: Vec<Vec<u8>>,
}

impl CachedCaCerts {
    /// Wrap pre-parsed DER certificate bytes.
    pub fn new(der_certs: Vec<Vec<u8>>) -> Self {
        Self { der_certs }
    }

    /// Borrow the DER-encoded certificates.
    pub fn der_certs(&self) -> &[Vec<u8>] {
        &self.der_certs
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
        tracing::debug!(ca_path, "loading CA certificates");

        let certs = parse_cert_pem(ca_path)?;

        if certs.is_empty() {
            return Err(TlsError::FileLoadError {
                path: ca_path.to_owned(),
                detail: "no certificates found in CA file".to_owned(),
            });
        }

        tracing::info!(ca_path, count = certs.len(), "cached CA certificates");
        Ok(Self::new(certs))
    }
}

// -----------------------------------------------------------------------------
// CachedClientCert
// -----------------------------------------------------------------------------

/// DER-encoded client certificate and private key loaded at config time.
///
/// ```
/// use praxis_tls::CachedClientCert;
///
/// let cached = CachedClientCert::new(vec![vec![1, 2, 3]], vec![4, 5, 6]);
/// assert_eq!(cached.cert_der().len(), 1);
/// assert_eq!(cached.key_der(), &[4, 5, 6]);
/// ```
#[derive(Debug, Clone)]
pub struct CachedClientCert {
    /// DER-encoded certificate chain.
    cert_der: Vec<Vec<u8>>,

    /// DER-encoded private key.
    key_der: Vec<u8>,
}

impl CachedClientCert {
    /// Wrap pre-parsed DER certificate chain and private key.
    pub fn new(cert_der: Vec<Vec<u8>>, key_der: Vec<u8>) -> Self {
        Self { cert_der, key_der }
    }

    /// Borrow the DER-encoded certificate chain.
    pub fn cert_der(&self) -> &[Vec<u8>] {
        &self.cert_der
    }

    /// Borrow the DER-encoded private key.
    pub fn key_der(&self) -> &[u8] {
        &self.key_der
    }

    /// Read and parse PEM cert + key files into cached DER data.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] if either file cannot be read, contains
    /// no valid PEM data, or the key file has no private key.
    ///
    /// [`TlsError`]: crate::TlsError
    pub fn from_pem_files(cert_path: &str, key_path: &str) -> Result<Self, TlsError> {
        tracing::debug!(cert_path, key_path, "loading client certificate");

        let cert_der = parse_cert_pem(cert_path)?;
        let key_der = parse_key_pem(key_path)?;

        tracing::info!(cert_path, "cached client certificate");
        Ok(Self::new(cert_der, key_der))
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
#[derive(Debug, Clone)]
pub struct CachedClusterTls {
    /// Cached CA certificates.
    ca: Option<Arc<CachedCaCerts>>,

    /// Cached client certificate and key.
    client_cert: Option<Arc<CachedClientCert>>,

    /// SNI hostname for outbound connections.
    sni: Option<String>,

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
            sni: tls.sni.clone(),
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
    pub fn set_sni(&mut self, sni: String) {
        self.sni = Some(sni);
    }

    /// Whether to verify upstream certificates.
    pub fn verify(&self) -> bool {
        self.verify
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Read a PEM certificate file and return DER-encoded certificate bytes.
fn parse_cert_pem(cert_path: &str) -> Result<Vec<Vec<u8>>, TlsError> {
    let pem = read_pem_file(cert_path)?;
    rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::FileLoadError {
            path: cert_path.to_owned(),
            detail: e.to_string(),
        })
        .map(|certs| certs.into_iter().map(|c| c.to_vec()).collect())
}

/// Read a PEM private key file and return the DER-encoded key bytes.
fn parse_key_pem(key_path: &str) -> Result<Vec<u8>, TlsError> {
    let pem = read_pem_file(key_path)?;
    rustls_pemfile::private_key(&mut &pem[..])
        .map_err(|e| TlsError::FileLoadError {
            path: key_path.to_owned(),
            detail: e.to_string(),
        })?
        .ok_or_else(|| TlsError::FileLoadError {
            path: key_path.to_owned(),
            detail: "no private key found".to_owned(),
        })
        .map(|k| k.secret_der().to_vec())
}

/// Read a file into a byte vector, mapping I/O errors to [`TlsError`].
///
/// [`TlsError`]: crate::TlsError
fn read_pem_file(path: &str) -> Result<Vec<u8>, TlsError> {
    std::fs::read(path).map_err(|e| TlsError::FileLoadError {
        path: path.to_owned(),
        detail: e.to_string(),
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use std::sync::Arc;

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
        let key_der = vec![30, 40];
        let cached = CachedClientCert::new(cert_der.clone(), key_der.clone());
        assert_eq!(cached.cert_der().len(), 1, "should store one client cert");
        assert_eq!(cached.key_der(), &key_der, "key DER should match");
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
    fn cached_client_cert_from_pem_valid() {
        let pair = gen_test_certs();
        let cached =
            CachedClientCert::from_pem_files(pair.cert_path.to_str().unwrap(), pair.key_path.to_str().unwrap())
                .expect("valid cert+key PEM should parse");
        assert!(!cached.cert_der().is_empty(), "should parse at least one cert");
        assert!(!cached.key_der().is_empty(), "key DER should not be empty");
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
    fn cached_ca_clone() {
        let cached = CachedCaCerts::new(vec![vec![1, 2, 3]]);
        let cloned = cached.clone();
        assert_eq!(cached.der_certs(), cloned.der_certs(), "cloned CA certs should match");
    }

    #[test]
    fn cached_client_cert_clone() {
        let cached = CachedClientCert::new(vec![vec![10]], vec![20]);
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
