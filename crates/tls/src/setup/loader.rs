// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Certificate and key loading utilities for TLS setup.
//!
//! This module provides validated loading of certificates and private keys
//! from PEM-encoded files. All loading paths use [`Zeroizing`] wrappers to
//! clear sensitive key material from memory when dropped. Loaded certificate
//! and key pairs are validated to ensure they match before being accepted,
//! with detailed error messages that distinguish key-mismatch failures from
//! parse errors.
//!
//! The module is consumed by the parent [`setup`][crate::setup] module to
//! construct `rustls::ServerConfig` instances for listeners and upstream
//! cluster TLS.
//!
//! [`Zeroizing`]: zeroize::Zeroizing

use std::sync::Arc;

use rustls::{
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
    sign::CertifiedKey,
};
use zeroize::Zeroizing;

use crate::{CertKeyPair, TlsError};

// -----------------------------------------------------------------------------
// Crypto Provider
// -----------------------------------------------------------------------------

/// Return the process-wide [`CryptoProvider`] installed during bootstrap.
///
/// Fails with [`TlsError::NoCryptoProvider`] when none is installed. This
/// used to fall back to `aws_lc_rs`, which meant the provider actually in use
/// depended on construction order rather than on configuration — see
/// [`crate::provider`].
///
/// ```ignore
/// let provider = praxis_tls::setup::default_crypto_provider()?;
/// assert!(!provider.cipher_suites.is_empty());
/// ```
///
/// [`CryptoProvider`]: rustls::crypto::CryptoProvider
/// [`TlsError::NoCryptoProvider`]: crate::TlsError::NoCryptoProvider
pub(crate) fn default_crypto_provider() -> Result<Arc<CryptoProvider>, TlsError> {
    crate::provider::installed_provider()
}

// -----------------------------------------------------------------------------
// Certificate Loading
// -----------------------------------------------------------------------------

/// Load and validate a certificate/key pair into a [`CertifiedKey`].
///
/// Loads the certificate chain and private key from the paths in [`CertKeyPair`],
/// validates that the certificate and key are cryptographically consistent (the
/// key's public component matches the certificate), and constructs a signing key
/// using the process-wide [`CryptoProvider`].
///
/// Returns a [`TlsError::FileLoadError`] if the files cannot be read, parsed,
/// or validated. The error detail distinguishes key-mismatch failures from
/// certificate parse failures and signing-key exposure failures so operators
/// are not sent chasing the wrong problem.
///
/// [`CertifiedKey`]: rustls::sign::CertifiedKey
/// [`CertKeyPair`]: crate::CertKeyPair
/// [`CryptoProvider`]: rustls::crypto::CryptoProvider
/// [`TlsError::FileLoadError`]: crate::TlsError::FileLoadError
pub(crate) fn load_certified_key(pair: &CertKeyPair) -> Result<CertifiedKey, TlsError> {
    let (certs, key) = load_cert_and_key(pair)?;
    certify(certs, key, pair)
}

/// Bind a certificate chain to its private key through the installed crypto
/// provider, rejecting an unsupported key type or a chain that does not match.
pub(crate) fn certify(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    pair: &CertKeyPair,
) -> Result<CertifiedKey, TlsError> {
    let provider = default_crypto_provider()?;
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|err| TlsError::FileLoadError {
            path: pair.key_path.clone(),
            detail: format!("unsupported private key type: {err}"),
        })?;
    let certified = CertifiedKey::new(certs, signing_key);
    certified.keys_match().map_err(|err| TlsError::FileLoadError {
        path: pair.cert_path.clone(),
        detail: keys_match_error_detail(&err),
    })?;
    Ok(certified)
}

/// Describe a `keys_match` failure without misreporting a parse/exposure error.
///
/// `keys_match` also fails when the certificate cannot be parsed
/// (`InvalidCertificate`) or the signing key cannot expose its public key
/// (`Unknown`); reporting those as "do not match" sends operators chasing the
/// wrong problem.
fn keys_match_error_detail(error: &rustls::Error) -> String {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "rustls::Error is non_exhaustive; only the two InconsistentKeys cases are special-cased"
    )]
    match error {
        rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch) => {
            format!("certificate and private key do not match: {error}")
        },
        rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown) => format!(
            "could not verify the certificate against the private key \
             (the signing key cannot expose its public key): {error}"
        ),
        _ => format!("failed to validate the certificate against the private key: {error}"),
    }
}

/// Load and parse certificate chain and private key from PEM files.
///
/// Reads the PEM-encoded certificate and key files, parses them into DER
/// form, and validates that at least one certificate is present and exactly
/// one private key is found. File contents are wrapped in [`Zeroizing`] to
/// clear sensitive key material from memory.
///
/// Returns the parsed certificate chain and private key on success, or a
/// [`TlsError::FileLoadError`] if files cannot be read or parsed, if no
/// certificates or keys are found, or if the PEM structure is invalid.
///
/// [`Zeroizing`]: zeroize::Zeroizing
/// [`TlsError::FileLoadError`]: crate::TlsError::FileLoadError
pub(crate) fn load_cert_and_key(
    pair: &CertKeyPair,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsError> {
    let cert_pem = Zeroizing::new(std::fs::read(&pair.cert_path).map_err(|err| TlsError::FileLoadError {
        path: pair.cert_path.clone(),
        detail: format!("failed to read cert: {err}"),
    })?);

    let key_pem = Zeroizing::new(std::fs::read(&pair.key_path).map_err(|err| TlsError::FileLoadError {
        path: pair.key_path.clone(),
        detail: format!("failed to read key: {err}"),
    })?);

    let certs = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| TlsError::FileLoadError {
            path: pair.cert_path.clone(),
            detail: format!("failed to parse cert PEM: {err}"),
        })?;

    if certs.is_empty() {
        return Err(TlsError::FileLoadError {
            path: pair.cert_path.clone(),
            detail: "no certificates found in PEM file".to_owned(),
        });
    }

    let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|err| TlsError::FileLoadError {
        path: pair.key_path.clone(),
        detail: if matches!(err, rustls::pki_types::pem::Error::NoItemsFound) {
            "no private key found in PEM file".to_owned()
        } else {
            format!("failed to parse key PEM: {err}")
        },
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
        crate::provider::install();
        let provider = default_crypto_provider().expect("provider installed above");
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
    fn unparseable_der_cert_is_not_reported_as_key_mismatch() {
        let certs = gen_test_certs();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let bad_cert = dir.path().join("bad-der.pem");
        std::fs::write(
            &bad_cert,
            b"-----BEGIN CERTIFICATE-----\nbm90YWNlcnQ=\n-----END CERTIFICATE-----\n",
        )
        .expect("write cert");
        let pair = CertKeyPair {
            cert_path: bad_cert.to_str().expect("path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("path").to_owned(),
            server_names: Vec::new(),
        };
        let err = load_certified_key(&pair).expect_err("garbage DER cert should fail");
        assert!(
            !err.to_string().contains("do not match"),
            "an unparseable certificate must not be reported as a key mismatch, got: {err}"
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

    #[test]
    fn malformed_key_pem_returns_error() {
        let certs = gen_test_certs();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let bad_key = dir.path().join("bad-key.pem");
        // Use invalid base64 that will fail PEM parsing
        std::fs::write(
            &bad_key,
            b"-----BEGIN PRIVATE KEY-----\ninvalid base64 !!!\n-----END PRIVATE KEY-----\n",
        )
        .expect("write malformed key");
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("path").to_owned(),
            default: false,
            key_path: bad_key.to_str().expect("path").to_owned(),
            server_names: Vec::new(),
        };
        let err = load_cert_and_key(&pair).expect_err("malformed key PEM should fail");
        assert!(
            err.to_string().contains("failed to parse key PEM"),
            "malformed key should report parse error, got: {err}"
        );
    }

    #[test]
    fn malformed_cert_pem_structure_returns_error() {
        let certs = gen_test_certs();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let bad_cert = dir.path().join("bad-structure.pem");
        std::fs::write(
            &bad_cert,
            b"-----BEGIN CERTIFICATE-----\ninvalid base64 !!!\n-----END CERTIFICATE-----\n",
        )
        .expect("write bad cert");
        let pair = CertKeyPair {
            cert_path: bad_cert.to_str().expect("path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("path").to_owned(),
            server_names: Vec::new(),
        };
        let err = load_cert_and_key(&pair).expect_err("malformed cert structure should fail");
        assert!(
            err.to_string().contains("failed to parse cert PEM"),
            "malformed cert structure should report parse error, got: {err}"
        );
    }

    #[test]
    fn cert_with_multiple_certificates_loads_chain() {
        let certs = gen_test_certs();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let chain_path = dir.path().join("chain.pem");

        // Read existing cert and CA, combine into a chain
        let cert_pem = std::fs::read(&certs.cert_path).expect("read cert");
        let ca_pem = std::fs::read(&certs.ca_cert_path).expect("read CA");
        let mut chain_bytes = Vec::new();
        chain_bytes.extend_from_slice(&cert_pem);
        chain_bytes.extend_from_slice(&ca_pem);
        std::fs::write(&chain_path, chain_bytes).expect("write chain");

        let pair = CertKeyPair {
            cert_path: chain_path.to_str().expect("path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("path").to_owned(),
            server_names: Vec::new(),
        };

        let (chain, _key) = load_cert_and_key(&pair).expect("chain should load");
        assert!(
            chain.len() >= 2,
            "certificate chain should contain at least 2 certificates (leaf + CA)"
        );
    }

    #[test]
    fn keys_match_error_detail_coverage() {
        // Test KeyMismatch variant
        let mismatch_err = rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch);
        let mismatch_msg = keys_match_error_detail(&mismatch_err);
        assert!(
            mismatch_msg.contains("do not match"),
            "KeyMismatch should mention 'do not match', got: {mismatch_msg}"
        );

        // Test Unknown variant
        let unknown_err = rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown);
        let unknown_msg = keys_match_error_detail(&unknown_err);
        assert!(
            unknown_msg.contains("cannot expose its public key"),
            "Unknown should mention public key exposure issue, got: {unknown_msg}"
        );

        // Test other error variant (using a different rustls error)
        let other_err = rustls::Error::General("test error".to_owned());
        let other_msg = keys_match_error_detail(&other_err);
        assert!(
            other_msg.contains("failed to validate"),
            "Other errors should use generic validation message, got: {other_msg}"
        );
    }

    #[test]
    fn load_certified_key_with_valid_pair() {
        let certs = gen_test_certs();
        let pair = CertKeyPair {
            cert_path: certs.cert_path.to_str().expect("path").to_owned(),
            default: false,
            key_path: certs.key_path.to_str().expect("path").to_owned(),
            server_names: Vec::new(),
        };

        let certified = load_certified_key(&pair).expect("valid pair should create CertifiedKey");
        assert!(!certified.cert.is_empty(), "certified key should contain certificates");
    }

    #[test]
    fn multiple_certs_in_file_loads_all() {
        let dir = tempfile::TempDir::new().expect("tempdir");

        // Generate two separate cert chains
        let certs1 = gen_test_certs();
        let certs2 = gen_test_certs();

        let multi_cert = dir.path().join("multi.pem");
        let cert1 = std::fs::read(&certs1.cert_path).expect("read cert1");
        let cert2 = std::fs::read(&certs2.cert_path).expect("read cert2");

        let mut combined = Vec::new();
        combined.extend_from_slice(&cert1);
        combined.push(b'\n');
        combined.extend_from_slice(&cert2);
        std::fs::write(&multi_cert, combined).expect("write multi cert");

        let pair = CertKeyPair {
            cert_path: multi_cert.to_str().expect("path").to_owned(),
            default: false,
            key_path: certs1.key_path.to_str().expect("path").to_owned(),
            server_names: Vec::new(),
        };

        let (certs, _key) = load_cert_and_key(&pair).expect("multiple certs should load");
        assert!(certs.len() >= 2, "should load multiple certificates from file");
    }

    #[test]
    fn load_cert_and_key_io_error_messages() {
        let pair = CertKeyPair {
            cert_path: "/nonexistent/cert.pem".to_owned(),
            default: false,
            key_path: "/nonexistent/key.pem".to_owned(),
            server_names: Vec::new(),
        };

        let err = load_cert_and_key(&pair).expect_err("nonexistent files should fail");
        let err_str = err.to_string();
        assert!(
            err_str.contains("failed to read cert") || err_str.contains("cert.pem"),
            "error should mention cert reading failure, got: {err_str}"
        );
    }
}
