// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Shared test utilities for TLS certificate generation.

use std::path::PathBuf;

use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair};

// -----------------------------------------------------------------------------
// Crypto Provider
// -----------------------------------------------------------------------------

/// Install a process-wide default [`CryptoProvider`] for tests.
///
/// rustls has no implicit fallback here — the Pingora fork enables
/// `custom-provider` — so a test that builds any config must install one
/// first. Delegates to [`crate::provider::install`] so tests exercise
/// whichever provider the build selected, rather than pinning one of their
/// own. Idempotent.
///
/// [`CryptoProvider`]: rustls::crypto::CryptoProvider
pub(crate) fn ensure_crypto_provider() {
    crate::provider::install();
}

// -----------------------------------------------------------------------------
// Test Certificate Types
// -----------------------------------------------------------------------------

/// Generated test certificate bundle with temp dir lifetime.
pub struct TestCerts {
    /// Temp directory holding the cert files (kept alive for the struct lifetime).
    pub temp_dir: Option<tempfile::TempDir>,

    /// Path to the CA certificate PEM.
    pub ca_cert_path: PathBuf,

    /// Path to the server certificate PEM.
    pub cert_path: PathBuf,

    /// Path to the server private key PEM.
    pub key_path: PathBuf,
}

/// Generated CA certificate file with temp dir lifetime.
pub(crate) struct TestCa {
    /// Temp directory holding the cert file.
    pub(crate) _temp_dir: tempfile::TempDir,

    /// Path to the CA certificate PEM file.
    pub(crate) ca_path: PathBuf,
}

// -----------------------------------------------------------------------------
// Certificate Generation
// -----------------------------------------------------------------------------

/// Generate a self-signed CA and server certificate for testing.
///
/// # Panics
///
/// Panics if temporary directory creation fails or certificate generation fails.
pub fn gen_test_certs() -> TestCerts {
    let temp_dir = tempfile::TempDir::new().expect("tempdir");
    let certs = gen_certs_at(temp_dir.path(), "Test CA");
    TestCerts {
        temp_dir: Some(temp_dir),
        ca_cert_path: certs.ca_cert_path,
        cert_path: certs.cert_path,
        key_path: certs.key_path,
    }
}

/// Generate new certs in an existing directory, overwriting existing files.
#[cfg(feature = "config-reload")]
pub(crate) fn gen_test_certs_in(dir: &std::path::Path) -> TestCerts {
    let certs = gen_certs_at(dir, "Test CA 2");
    TestCerts {
        temp_dir: None,
        ca_cert_path: certs.ca_cert_path,
        cert_path: certs.cert_path,
        key_path: certs.key_path,
    }
}

/// Generate a self-signed CA certificate file for testing.
pub(crate) fn gen_ca_file() -> TestCa {
    ensure_crypto_provider();
    let ca_key = KeyPair::generate().expect("CA key generation");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, "Test CA");
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-sign");

    let temp_dir = tempfile::TempDir::new().expect("tempdir");
    let ca_path = temp_dir.path().join("ca.pem");
    std::fs::write(&ca_path, ca_cert.pem()).expect("write CA PEM");

    TestCa {
        _temp_dir: temp_dir,
        ca_path,
    }
}

/// Generate a test certificate with custom Subject Alternative Names.
pub(crate) fn gen_test_certs_with_sans(sans: Vec<String>) -> TestCerts {
    let temp_dir = tempfile::TempDir::new().expect("tempdir");
    let certs = gen_certs_with_sans_at(temp_dir.path(), "Test CA", sans);
    TestCerts {
        temp_dir: Some(temp_dir),
        ca_cert_path: certs.ca_cert_path,
        cert_path: certs.cert_path,
        key_path: certs.key_path,
    }
}

// -----------------------------------------------------------------------------
// Shared Implementation
// -----------------------------------------------------------------------------

/// Internal result from cert generation (no temp dir ownership).
#[expect(
    clippy::struct_field_names,
    reason = "_path suffix distinguishes PathBuf from cert contents"
)]
struct GeneratedCerts {
    /// Path to the CA certificate PEM.
    ca_cert_path: PathBuf,

    /// Path to the server certificate PEM.
    cert_path: PathBuf,

    /// Path to the server private key PEM.
    key_path: PathBuf,
}

/// Generate a CA and server cert in `dir` with the given CA common name.
fn gen_certs_at(dir: &std::path::Path, ca_cn: &str) -> GeneratedCerts {
    gen_certs_with_sans_at(dir, ca_cn, vec!["localhost".to_owned()])
}

/// Generate a CA and server cert with custom SANs in `dir`.
fn gen_certs_with_sans_at(dir: &std::path::Path, ca_cn: &str, sans: Vec<String>) -> GeneratedCerts {
    // Any test that needs certificates will load them, and loading verifies
    // the cert against its key through the installed provider. Hooking the
    // fixture means no test has to remember.
    ensure_crypto_provider();
    let ca_key = KeyPair::generate().expect("CA key generation");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, ca_cn);
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-sign");
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let cn = sans.first().map_or("localhost", String::as_str).to_owned();
    let server_key = KeyPair::generate().expect("server key generation");
    let mut server_params = CertificateParams::new(sans).expect("server params");
    server_params.distinguished_name.push(DnType::CommonName, cn);
    let server_cert = server_params.signed_by(&server_key, &issuer).expect("server cert sign");

    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server-key.pem");
    let ca_cert_path = dir.join("ca.pem");

    std::fs::write(&cert_path, server_cert.pem()).expect("write cert PEM");
    std::fs::write(&key_path, server_key.serialize_pem()).expect("write key PEM");
    std::fs::write(&ca_cert_path, ca_cert.pem()).expect("write CA PEM");

    GeneratedCerts {
        ca_cert_path,
        cert_path,
        key_path,
    }
}
