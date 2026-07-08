// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Certificate and key loading utilities.

use std::sync::Arc;

use rustls::{crypto::CryptoProvider, sign::CertifiedKey};
use zeroize::Zeroizing;

use crate::{CertKeyPair, TlsError};

// -----------------------------------------------------------------------------
// Crypto Provider
// -----------------------------------------------------------------------------

/// Return the process-wide default [`CryptoProvider`], or fall back to
/// `aws_lc_rs` if none has been installed yet.
///
/// ```ignore
/// let provider = praxis_tls::setup::default_crypto_provider();
/// assert!(!provider.cipher_suites.is_empty());
/// ```
///
/// [`CryptoProvider`]: rustls::crypto::CryptoProvider
pub(crate) fn default_crypto_provider() -> Arc<CryptoProvider> {
    CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
}

// -----------------------------------------------------------------------------
// Certificate Loading
// -----------------------------------------------------------------------------

/// Load a [`CertifiedKey`] from a [`CertKeyPair`].
///
/// [`CertifiedKey`]: rustls::sign::CertifiedKey
/// [`CertKeyPair`]: crate::CertKeyPair
pub(crate) fn load_certified_key(pair: &CertKeyPair) -> Result<CertifiedKey, TlsError> {
    let (certs, key) = load_cert_and_key(pair)?;
    let provider = default_crypto_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| TlsError::FileLoadError {
            path: pair.key_path.clone(),
            detail: format!("unsupported private key type: {e}"),
        })?;
    let certified = CertifiedKey::new(certs, signing_key);
    certified.keys_match().map_err(|e| TlsError::FileLoadError {
        path: pair.cert_path.clone(),
        detail: format!("certificate and private key do not match: {e}"),
    })?;
    Ok(certified)
}

/// Load certificate chain and private key from PEM files.
pub(super) fn load_cert_and_key(
    pair: &CertKeyPair,
) -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    TlsError,
> {
    let cert_pem = Zeroizing::new(std::fs::read(&pair.cert_path).map_err(|e| TlsError::FileLoadError {
        path: pair.cert_path.clone(),
        detail: format!("failed to read cert: {e}"),
    })?);

    let key_pem = Zeroizing::new(std::fs::read(&pair.key_path).map_err(|e| TlsError::FileLoadError {
        path: pair.key_path.clone(),
        detail: format!("failed to read key: {e}"),
    })?);

    let certs = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::FileLoadError {
            path: pair.cert_path.clone(),
            detail: format!("failed to parse cert PEM: {e}"),
        })?;

    if certs.is_empty() {
        return Err(TlsError::FileLoadError {
            path: pair.cert_path.clone(),
            detail: "no certificates found in PEM file".to_owned(),
        });
    }

    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| TlsError::FileLoadError {
            path: pair.key_path.clone(),
            detail: format!("failed to parse key PEM: {e}"),
        })?
        .ok_or_else(|| TlsError::FileLoadError {
            path: pair.key_path.clone(),
            detail: "no private key found in PEM file".to_owned(),
        })?;

    Ok((certs, key))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use crate::test_utils::gen_test_certs;

    #[test]
    fn default_crypto_provider_returns_provider() {
        let provider = default_crypto_provider();
        assert!(
            !provider.cipher_suites.is_empty(),
            "crypto provider should have at least one cipher suite"
        );
    }

    #[test]
    fn load_cert_and_key_valid_pair() {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };

        let (chain, _key) = load_cert_and_key(&pair).expect("valid pair should load");
        assert!(!chain.is_empty(), "certificate chain should not be empty");
    }

    #[test]
    fn load_cert_and_key_missing_cert_file() {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: "/nonexistent/cert.pem".to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };

        let err = load_cert_and_key(&pair).expect_err("missing cert should fail");
        assert!(
            matches!(&err, TlsError::FileLoadError { path, .. } if path == "/nonexistent/cert.pem"),
            "error should reference the cert path, got: {err}"
        );
    }

    #[test]
    fn load_cert_and_key_missing_key_file() {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: "/nonexistent/key.pem".to_owned(),
            server_names: Vec::new(),
        };

        let err = load_cert_and_key(&pair).expect_err("missing key should fail");
        assert!(
            matches!(&err, TlsError::FileLoadError { path, .. } if path == "/nonexistent/key.pem"),
            "error should reference the key path, got: {err}"
        );
    }

    #[test]
    fn load_cert_and_key_empty_cert_file() {
        let certs = gen_test_certs();
        let dir = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let empty_cert = dir.path().join("empty.pem");
        std::fs::write(&empty_cert, "").expect("write empty cert should succeed");

        let pair = CertKeyPair {
            cert_path: empty_cert.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };

        let err = load_cert_and_key(&pair).expect_err("empty cert should fail");
        assert!(
            err.to_string().contains("no certificates found"),
            "error should mention no certificates found, got: {err}"
        );
    }

    #[test]
    fn load_cert_and_key_empty_key_file() {
        let certs = gen_test_certs();
        let dir = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let empty_key = dir.path().join("empty-key.pem");
        std::fs::write(&empty_key, "").expect("write empty key should succeed");

        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
            default: false,
            key_path: empty_key.to_str().expect("key path").to_owned(),
            server_names: Vec::new(),
        };

        let err = load_cert_and_key(&pair).expect_err("empty key should fail");
        assert!(
            err.to_string().contains("no private key found"),
            "error should mention no private key found, got: {err}"
        );
    }

    #[test]
    fn cert_key_mismatch_returns_error() {
        let certs_a = gen_test_certs();
        let certs_b = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs_a.cert_path.to_str().expect("path").to_owned(),
            default: false,
            key_path: certs_b.key_path.to_str().expect("path").to_owned(),
            server_names: Vec::new(),
        };
        let err = load_certified_key(&pair).expect_err("mismatched cert/key should fail");
        assert!(
            err.to_string().contains("do not match"),
            "error should mention cert/key mismatch, got: {err}"
        );
    }

    #[test]
    fn garbage_pem_cert_returns_error() {
        let certs = gen_test_certs();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let garbage = dir.path().join("garbage.pem");
        std::fs::write(&garbage, b"\x00\x01\x02\xff garbage data").expect("write garbage");
        let pair = CertKeyPair {
            cert_path: garbage.to_str().expect("path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("path").to_owned(),
            server_names: Vec::new(),
        };
        let err = load_cert_and_key(&pair).expect_err("garbage PEM should fail");
        assert!(
            err.to_string().contains("no certificates found"),
            "error should mention no certificates, got: {err}"
        );
    }

    #[test]
    fn key_file_with_cert_content_returns_error() {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("path").to_owned(),
            default: false,
            key_path: certs.cert_path.to_str().expect("path").to_owned(),
            server_names: Vec::new(),
        };
        let err = load_cert_and_key(&pair).expect_err("cert as key should fail");
        assert!(
            err.to_string().contains("no private key found"),
            "using cert file as key should say no key found, got: {err}"
        );
    }

    #[test]
    fn cert_file_with_key_content_returns_error() {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.key_path.to_str().expect("path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("path").to_owned(),
            server_names: Vec::new(),
        };
        let err = load_cert_and_key(&pair).expect_err("key as cert should fail");
        assert!(
            err.to_string().contains("no certificates found"),
            "using key file as cert should say no certs found, got: {err}"
        );
    }
}
