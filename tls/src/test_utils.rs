// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Shared test utilities for TLS certificate generation.

use std::path::PathBuf;

use rcgen::{CertificateParams, DnType, IsCa, KeyPair};

// -----------------------------------------------------------------------------
// Test Certificate Types
// -----------------------------------------------------------------------------

/// Generated test certificate bundle with temp dir lifetime.
pub(crate) struct TestCerts {
    /// Temp directory holding the cert files.
    pub(crate) _temp_dir: Option<tempfile::TempDir>,

    /// Path to the CA certificate PEM.
    pub(crate) ca_cert_path: PathBuf,

    /// Path to the server certificate PEM.
    pub(crate) cert_path: PathBuf,

    /// Path to the server private key PEM.
    pub(crate) key_path: PathBuf,
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
pub(crate) fn gen_test_certs() -> TestCerts {
    let temp_dir = tempfile::TempDir::new().expect("tempdir");
    let certs = gen_certs_at(temp_dir.path(), "Test CA");
    TestCerts {
        _temp_dir: Some(temp_dir),
        ca_cert_path: certs.ca_cert_path,
        cert_path: certs.cert_path,
        key_path: certs.key_path,
    }
}

/// Generate new certs in an existing directory, overwriting existing files.
#[cfg(feature = "hot-reload")]
pub(crate) fn gen_test_certs_in(dir: &std::path::Path) -> TestCerts {
    let certs = gen_certs_at(dir, "Test CA 2");
    TestCerts {
        _temp_dir: None,
        ca_cert_path: certs.ca_cert_path,
        cert_path: certs.cert_path,
        key_path: certs.key_path,
    }
}

/// Generate a self-signed CA certificate file for testing.
pub(crate) fn gen_ca_file() -> TestCa {
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

// -----------------------------------------------------------------------------
// Shared Implementation
// -----------------------------------------------------------------------------

/// Internal result from cert generation (no temp dir ownership).
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
    let ca_key = KeyPair::generate().expect("CA key generation");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, ca_cn);
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-sign");

    let server_key = KeyPair::generate().expect("server key generation");
    let mut server_params = CertificateParams::new(vec!["localhost".to_owned()]).expect("server params");
    server_params.distinguished_name.push(DnType::CommonName, "localhost");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("server cert sign");

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
