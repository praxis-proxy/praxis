// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! Shared TLS listener setup: builds `rustls::ServerConfig` from [`ListenerTls`].
//!
//! When a listener has multiple certificates, an [`SniCertResolver`]
//! is constructed so rustls selects the correct certificate based on
//! the client's SNI hostname.
//!
//! [`ListenerTls`]: crate::ListenerTls
//! [`SniCertResolver`]: crate::setup::SniCertResolver

mod loader;
mod sni;

use std::sync::Arc;

pub(crate) use loader::default_crypto_provider;
use rustls::{ServerConfig, version};

use crate::{ClientCertMode, ListenerTls, TlsError, TlsVersion, client_auth};

// -----------------------------------------------------------------------------
// TLS Setup
// -----------------------------------------------------------------------------

/// Build a `rustls::ServerConfig` from a [`ListenerTls`], applying mTLS
/// verifier, TLS version constraints, and multi-cert SNI resolution.
///
/// When `certificates` has a single entry, uses `with_single_cert`.
/// When multiple entries exist, builds an [`SniCertResolver`] and
/// uses `with_cert_resolver`.
///
/// # Errors
///
/// Returns [`TlsError`] if certificate/key files cannot be loaded
/// or the mTLS CA is invalid.
///
/// ```no_run
/// use praxis_tls::{ListenerTls, setup};
///
/// let dir = tempfile::TempDir::new().unwrap();
/// let cert = dir.path().join("cert.pem");
/// let key = dir.path().join("key.pem");
/// std::fs::write(&cert, b"").unwrap();
/// std::fs::write(&key, b"").unwrap();
///
/// let tls = ListenerTls::new_validated(cert.to_str().unwrap(), key.to_str().unwrap()).unwrap();
/// let server_config = setup::build_server_config(&tls).unwrap();
/// ```
///
/// [`TlsError`]: crate::TlsError
/// [`ListenerTls`]: crate::ListenerTls
/// [`SniCertResolver`]: crate::setup::SniCertResolver
#[allow(
    clippy::too_many_lines,
    clippy::indexing_slicing,
    reason = "validated; sequential branches"
)]
pub fn build_server_config(tls: &ListenerTls) -> Result<Arc<ServerConfig>, TlsError> {
    let versions = match tls.min_version {
        Some(TlsVersion::Tls13) => vec![&version::TLS13],
        Some(TlsVersion::Tls12) | None => vec![&version::TLS12, &version::TLS13],
    };
    let provider = default_crypto_provider();
    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| TlsError::FileLoadError {
            path: tls.certificates[0].cert_path.clone(),
            detail: format!("failed to set TLS protocol versions: {e}"),
        })?;

    let builder = if tls.client_cert_mode == ClientCertMode::None {
        builder.with_no_client_auth()
    } else {
        let ca_path =
            tls.client_ca
                .as_ref()
                .map(|ca| ca.ca_path.as_str())
                .ok_or_else(|| TlsError::MissingClientCa {
                    mode: tls.client_cert_mode.clone(),
                })?;
        let verifier = client_auth::build_client_verifier(ca_path, &tls.client_cert_mode)?;
        builder.with_client_cert_verifier(verifier)
    };

    let primary = &tls.certificates[0];
    let mut config = if tls.certificates.len() == 1 {
        let (certs, key) = loader::load_cert_and_key(primary)?;
        builder
            .with_single_cert(certs, key)
            .map_err(|e| TlsError::FileLoadError {
                path: primary.cert_path.clone(),
                detail: format!("failed to build ServerConfig: {e}"),
            })?
    } else {
        let resolver = sni::build_sni_resolver(&tls.certificates)?;
        builder.with_cert_resolver(Arc::new(resolver))
    };

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CaConfig, CertKeyPair, ClientCertMode, TlsVersion};

    #[test]
    fn build_server_config_single_cert() {
        let certs = gen_test_certs();
        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
                key_path: certs.key_path.to_str().expect("key path").to_owned(),
                server_names: Vec::new(),
            }],
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            min_version: None,
        };

        let config = build_server_config(&tls).expect("single-cert build should succeed");
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "ALPN should include h2 and http/1.1"
        );
    }

    #[test]
    fn build_server_config_multi_cert_uses_sni_resolver() {
        let certs1 = gen_test_certs();
        let certs2 = gen_test_certs();
        let tls = ListenerTls {
            certificates: vec![
                CertKeyPair {
                    cert_path: certs1.cert_path.to_str().expect("cert1 path").to_owned(),
                    key_path: certs1.key_path.to_str().expect("key1 path").to_owned(),
                    server_names: vec!["alpha.example.com".to_owned()],
                },
                CertKeyPair {
                    cert_path: certs2.cert_path.to_str().expect("cert2 path").to_owned(),
                    key_path: certs2.key_path.to_str().expect("key2 path").to_owned(),
                    server_names: Vec::new(),
                },
            ],
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            min_version: None,
        };

        let config = build_server_config(&tls).expect("multi-cert build should succeed");
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "ALPN should be set on multi-cert config"
        );
    }

    #[test]
    fn build_server_config_mtls_require() {
        let server = gen_test_certs();
        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: server.cert_path.to_str().expect("cert path").to_owned(),
                key_path: server.key_path.to_str().expect("key path").to_owned(),
                server_names: Vec::new(),
            }],
            client_ca: Some(CaConfig {
                ca_path: server.ca_cert_path.to_str().expect("ca path").to_owned(),
            }),
            client_cert_mode: ClientCertMode::Require,
            min_version: None,
        };

        let config = build_server_config(&tls).expect("mTLS require build should succeed");
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "ALPN should be set on mTLS config"
        );
    }

    #[test]
    fn build_server_config_min_version_tls13() {
        let certs = gen_test_certs();
        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
                key_path: certs.key_path.to_str().expect("key path").to_owned(),
                server_names: Vec::new(),
            }],
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            min_version: Some(TlsVersion::Tls13),
        };

        let config = build_server_config(&tls).expect("TLS 1.3 build should succeed");
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "ALPN should be set on TLS 1.3 config"
        );
    }

    #[test]
    fn build_server_config_error_no_certificates() {
        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: "/nonexistent/cert.pem".to_owned(),
                key_path: "/nonexistent/key.pem".to_owned(),
                server_names: Vec::new(),
            }],
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            min_version: None,
        };

        let err = build_server_config(&tls).expect_err("missing cert files should fail");
        assert!(
            matches!(err, TlsError::FileLoadError { .. }),
            "error should be FileLoadError, got: {err}"
        );
    }

    #[test]
    fn needs_custom_config_false_for_plain_single_cert() {
        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: "/a".to_owned(),
                key_path: "/b".to_owned(),
                server_names: Vec::new(),
            }],
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            min_version: None,
        };
        assert!(
            !needs_custom_config(&tls),
            "plain single-cert should not need custom config"
        );
    }

    #[test]
    fn needs_custom_config_true_for_mtls() {
        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: "/a".to_owned(),
                key_path: "/b".to_owned(),
                server_names: Vec::new(),
            }],
            client_ca: Some(CaConfig {
                ca_path: "/ca.pem".to_owned(),
            }),
            client_cert_mode: ClientCertMode::Require,
            min_version: None,
        };
        assert!(needs_custom_config(&tls), "mTLS config should need custom config");
    }

    #[test]
    fn needs_custom_config_true_for_min_version() {
        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: "/a".to_owned(),
                key_path: "/b".to_owned(),
                server_names: Vec::new(),
            }],
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            min_version: Some(TlsVersion::Tls13),
        };
        assert!(needs_custom_config(&tls), "min_version should need custom config");
    }

    #[test]
    fn needs_custom_config_true_for_multi_cert() {
        let tls = ListenerTls {
            certificates: vec![
                CertKeyPair {
                    cert_path: "/a".to_owned(),
                    key_path: "/b".to_owned(),
                    server_names: Vec::new(),
                },
                CertKeyPair {
                    cert_path: "/c".to_owned(),
                    key_path: "/d".to_owned(),
                    server_names: Vec::new(),
                },
            ],
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            min_version: None,
        };
        assert!(needs_custom_config(&tls), "multi-cert should need custom config");
    }

    // ---------------------------------------------------------------------------
    // Test Utilities
    // ---------------------------------------------------------------------------

    /// Returns `true` if the [`ListenerTls`] requires a custom
    /// `ServerConfig` build (mTLS, TLS version constraints, or
    /// multi-cert).
    ///
    /// [`ListenerTls`]: crate::ListenerTls
    fn needs_custom_config(tls: &ListenerTls) -> bool {
        let has_mtls = tls.client_cert_mode != ClientCertMode::None;
        let has_version = tls.min_version.is_some();
        let has_multi_cert = tls.certificates.len() > 1;
        has_mtls || has_version || has_multi_cert
    }

    /// Generated test certificate bundle with temp dir lifetime.
    pub(super) struct TestCerts {
        /// Path to the server certificate PEM.
        pub(super) cert_path: std::path::PathBuf,

        /// Path to the server private key PEM.
        pub(super) key_path: std::path::PathBuf,

        /// Path to the CA certificate PEM.
        pub(super) ca_cert_path: std::path::PathBuf,

        /// Temp directory holding the cert files.
        pub(super) _temp_dir: tempfile::TempDir,
    }

    /// Generate a self-signed CA and server certificate for testing.
    pub(super) fn gen_test_certs() -> TestCerts {
        use rcgen::{CertificateParams, DnType, IsCa, KeyPair};

        let ca_key = KeyPair::generate().expect("CA key generation should succeed");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params should be valid");
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "Test CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-sign should succeed");

        let server_key = KeyPair::generate().expect("server key generation should succeed");
        let mut server_params =
            CertificateParams::new(vec!["localhost".to_owned()]).expect("server params should be valid");
        server_params.distinguished_name.push(DnType::CommonName, "localhost");
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .expect("server cert sign should succeed");

        let temp_dir = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let cert_path = temp_dir.path().join("server.pem");
        let key_path = temp_dir.path().join("server-key.pem");
        let ca_cert_path = temp_dir.path().join("ca.pem");

        std::fs::write(&cert_path, server_cert.pem()).expect("write cert PEM should succeed");
        std::fs::write(&key_path, server_key.serialize_pem()).expect("write key PEM should succeed");
        std::fs::write(&ca_cert_path, ca_cert.pem()).expect("write CA PEM should succeed");

        TestCerts {
            cert_path,
            key_path,
            ca_cert_path,
            _temp_dir: temp_dir,
        }
    }
}
