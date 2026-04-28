// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Shared TLS listener setup: builds `rustls::ServerConfig` from [`ListenerTls`].
//!
//! When a listener has multiple certificates, an `SniCertResolver`
//! is constructed so rustls selects the correct certificate based on
//! the client's SNI hostname.
//!
//! [`ListenerTls`]: crate::ListenerTls

pub(crate) mod loader;
mod sni;

use std::sync::Arc;

pub(crate) use loader::default_crypto_provider;
use rustls::{ServerConfig, server::WantsServerCert, version};

use crate::{CipherSuiteId, ClientCertMode, ListenerTls, TlsError, TlsVersion, client_auth};

/// ALPN protocols advertised on every TLS listener.
fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

// -----------------------------------------------------------------------------
// TLS Setup
// -----------------------------------------------------------------------------

/// Build a `rustls::ServerConfig` from a [`ListenerTls`], applying mTLS
/// verifier, TLS version constraints, and multi-cert SNI resolution.
///
/// When `certificates` has a single entry, uses `with_single_cert`.
/// When multiple entries exist, builds an `SniCertResolver` and
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
#[allow(clippy::too_many_lines, reason = "sequential branches")]
pub fn build_server_config(tls: &ListenerTls) -> Result<Arc<ServerConfig>, TlsError> {
    let builder = build_server_config_base(tls)?;

    let primary = tls.certificates.first().ok_or(TlsError::NoCertificates)?;
    let mut config = if tls.certificates.len() == 1 {
        let (certs, key) = loader::load_cert_and_key(primary)?;
        builder
            .with_single_cert(certs, key)
            .map_err(|e| TlsError::ServerConfigError {
                detail: format!("failed to build ServerConfig: {e}"),
            })?
    } else {
        let resolver = sni::build_sni_resolver(&tls.certificates)?;
        builder.with_cert_resolver(Arc::new(resolver))
    };

    config.alpn_protocols = alpn_protocols();
    Ok(Arc::new(config))
}

/// Build a `rustls::ServerConfig` that uses a [`ReloadableCertResolver`]
/// for hot-reload support.
///
/// Returns the server config and a shared [`ArcSwap`] handle. The
/// watcher task stores new certificates into this handle; the
/// resolver reads from it during TLS handshakes.
///
/// # Errors
///
/// Returns [`TlsError`] if the initial certificate cannot be loaded
/// or the mTLS CA is invalid.
///
/// [`TlsError`]: crate::TlsError
/// [`ReloadableCertResolver`]: crate::reload::ReloadableCertResolver
/// [`ArcSwap`]: arc_swap::ArcSwap
#[cfg(feature = "hot-reload")]
#[allow(
    clippy::type_complexity,
    reason = "return type is inherently complex due to ArcSwap + CertifiedKey"
)]
pub fn build_reloadable_server_config(
    tls: &ListenerTls,
) -> Result<(Arc<ServerConfig>, Arc<arc_swap::ArcSwap<rustls::sign::CertifiedKey>>), TlsError> {
    let builder = build_server_config_base(tls)?;

    let primary = tls.certificates.first().ok_or(TlsError::NoCertificates)?;
    let resolver = crate::reload::ReloadableCertResolver::new(primary)?;
    let swap_handle = resolver.arc();

    let mut config = builder.with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = alpn_protocols();

    Ok((Arc::new(config), swap_handle))
}

// -----------------------------------------------------------------------------
// Shared Builder Setup
// -----------------------------------------------------------------------------

/// Build the common `ServerConfig` builder: selects TLS versions,
/// installs the crypto provider, and configures client auth.
fn build_server_config_base(
    tls: &ListenerTls,
) -> Result<rustls::ConfigBuilder<ServerConfig, WantsServerCert>, TlsError> {
    let versions = match tls.min_version {
        Some(TlsVersion::Tls13) => vec![&version::TLS13],
        Some(TlsVersion::Tls12) | None => vec![&version::TLS12, &version::TLS13],
    };
    let provider = maybe_filter_provider(default_crypto_provider(), tls.cipher_suites.as_deref());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| TlsError::ServerConfigError {
            detail: format!("failed to set TLS protocol versions: {e}"),
        })?;

    if tls.client_cert_mode == ClientCertMode::None {
        Ok(builder.with_no_client_auth())
    } else {
        let ca_path =
            tls.client_ca
                .as_ref()
                .map(|ca| ca.ca_path.as_str())
                .ok_or_else(|| TlsError::MissingClientCa {
                    mode: tls.client_cert_mode.clone(),
                })?;
        let verifier = client_auth::build_client_verifier(ca_path, &tls.client_cert_mode)?;
        Ok(builder.with_client_cert_verifier(verifier))
    }
}

// -----------------------------------------------------------------------------
// Cipher Suite Filtering
// -----------------------------------------------------------------------------

/// Return a provider with only the requested cipher suites, or the
/// original provider when no filter is specified.
fn maybe_filter_provider(
    provider: Arc<rustls::crypto::CryptoProvider>,
    cipher_suites: Option<&[CipherSuiteId]>,
) -> Arc<rustls::crypto::CryptoProvider> {
    let Some(ids) = cipher_suites else {
        return provider;
    };

    let allowed: Vec<_> = ids.iter().map(CipherSuiteId::to_rustls).collect();

    let filtered: Vec<_> = provider
        .cipher_suites
        .iter()
        .filter(|s| allowed.iter().any(|a| a.suite() == s.suite()))
        .copied()
        .collect();

    tracing::info!(
        requested = ids.len(),
        matched = filtered.len(),
        "cipher suite filter applied"
    );

    Arc::new(rustls::crypto::CryptoProvider {
        cipher_suites: filtered,
        ..(*provider).clone()
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use crate::{CaConfig, CertKeyPair, ClientCertMode, TlsVersion, test_utils::gen_test_certs};

    #[test]
    fn build_server_config_single_cert() {
        let certs = gen_test_certs();
        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
                default: false,
                key_path: certs.key_path.to_str().expect("key path").to_owned(),
                server_names: Vec::new(),
            }],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            hot_reload: None,
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
                    default: false,
                    key_path: certs1.key_path.to_str().expect("key1 path").to_owned(),
                    server_names: vec!["alpha.example.com".to_owned()],
                },
                CertKeyPair {
                    cert_path: certs2.cert_path.to_str().expect("cert2 path").to_owned(),
                    default: true,
                    key_path: certs2.key_path.to_str().expect("key2 path").to_owned(),
                    server_names: Vec::new(),
                },
            ],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            hot_reload: None,
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
                default: false,
                key_path: server.key_path.to_str().expect("key path").to_owned(),
                server_names: Vec::new(),
            }],
            cipher_suites: None,
            client_ca: Some(CaConfig {
                ca_path: server.ca_cert_path.to_str().expect("ca path").to_owned(),
            }),
            client_cert_mode: ClientCertMode::Require,
            hot_reload: None,
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
                default: false,
                key_path: certs.key_path.to_str().expect("key path").to_owned(),
                server_names: Vec::new(),
            }],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            hot_reload: None,
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
    fn build_server_config_error_missing_files() {
        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: "/nonexistent/cert.pem".to_owned(),
                default: false,
                key_path: "/nonexistent/key.pem".to_owned(),
                server_names: Vec::new(),
            }],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            hot_reload: None,
            min_version: None,
        };

        let err = build_server_config(&tls).expect_err("missing cert files should fail");
        assert!(
            matches!(err, TlsError::FileLoadError { .. }),
            "error should be FileLoadError, got: {err}"
        );
    }

    #[test]
    fn build_server_config_error_empty_certificates() {
        let tls = ListenerTls {
            certificates: Vec::new(),
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            hot_reload: None,
            min_version: None,
        };

        let err = build_server_config(&tls).expect_err("empty certificates should fail");
        assert!(
            matches!(err, TlsError::NoCertificates),
            "error should be NoCertificates, got: {err}"
        );
    }

    #[test]
    fn needs_custom_config_false_for_plain_single_cert() {
        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: "/a".to_owned(),
                default: false,
                key_path: "/b".to_owned(),
                server_names: Vec::new(),
            }],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            hot_reload: None,
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
                default: false,
                key_path: "/b".to_owned(),
                server_names: Vec::new(),
            }],
            cipher_suites: None,
            client_ca: Some(CaConfig {
                ca_path: "/ca.pem".to_owned(),
            }),
            client_cert_mode: ClientCertMode::Require,
            hot_reload: None,
            min_version: None,
        };
        assert!(needs_custom_config(&tls), "mTLS config should need custom config");
    }

    #[test]
    fn needs_custom_config_true_for_min_version() {
        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: "/a".to_owned(),
                default: false,
                key_path: "/b".to_owned(),
                server_names: Vec::new(),
            }],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            hot_reload: None,
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
                    default: false,
                    key_path: "/b".to_owned(),
                    server_names: vec!["a.example.com".to_owned()],
                },
                CertKeyPair {
                    cert_path: "/c".to_owned(),
                    default: true,
                    key_path: "/d".to_owned(),
                    server_names: Vec::new(),
                },
            ],
            cipher_suites: None,
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            hot_reload: None,
            min_version: None,
        };
        assert!(needs_custom_config(&tls), "multi-cert should need custom config");
    }

    #[test]
    fn build_server_config_with_cipher_suites() {
        let certs = gen_test_certs();
        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: certs.cert_path.to_str().expect("cert path").to_owned(),
                default: false,
                key_path: certs.key_path.to_str().expect("key path").to_owned(),
                server_names: Vec::new(),
            }],
            cipher_suites: Some(vec![CipherSuiteId::Tls13Aes256GcmSha384]),
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            hot_reload: None,
            min_version: None,
        };

        let config = build_server_config(&tls).expect("cipher-suite-restricted build should succeed");
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "ALPN should be set on cipher-suite-restricted config"
        );
    }

    #[test]
    fn maybe_filter_provider_none_returns_original() {
        let provider = default_crypto_provider();
        let original_count = provider.cipher_suites.len();

        let result = maybe_filter_provider(Arc::clone(&provider), None);
        assert_eq!(
            result.cipher_suites.len(),
            original_count,
            "None filter should return all suites"
        );
    }

    #[test]
    fn maybe_filter_provider_restricts_suites() {
        let provider = default_crypto_provider();
        let ids = [CipherSuiteId::Tls13Aes256GcmSha384];

        let result = maybe_filter_provider(provider, Some(&ids));
        assert_eq!(
            result.cipher_suites.len(),
            1,
            "filtering to one suite should yield exactly one suite"
        );
        assert_eq!(
            result.cipher_suites[0].suite(),
            CipherSuiteId::Tls13Aes256GcmSha384.to_rustls().suite(),
            "filtered suite should match the requested one"
        );
    }

    #[test]
    fn maybe_filter_provider_preserves_order() {
        let provider = default_crypto_provider();
        let ids = [
            CipherSuiteId::Tls13Chacha20Poly1305Sha256,
            CipherSuiteId::Tls13Aes128GcmSha256,
        ];

        let result = maybe_filter_provider(provider, Some(&ids));
        assert_eq!(
            result.cipher_suites.len(),
            2,
            "filtering to two suites should yield exactly two"
        );
    }

    #[test]
    fn needs_custom_config_true_for_cipher_suites() {
        let tls = ListenerTls {
            certificates: vec![CertKeyPair {
                cert_path: "/a".to_owned(),
                default: false,
                key_path: "/b".to_owned(),
                server_names: Vec::new(),
            }],
            cipher_suites: Some(vec![CipherSuiteId::Tls13Aes256GcmSha384]),
            client_ca: None,
            client_cert_mode: ClientCertMode::None,
            hot_reload: None,
            min_version: None,
        };
        assert!(needs_custom_config(&tls), "cipher_suites should need custom config");
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    /// Returns `true` if the [`ListenerTls`] requires a custom
    /// `ServerConfig` build (mTLS, TLS version constraints, cipher
    /// suite restrictions, or multi-cert).
    ///
    /// [`ListenerTls`]: crate::ListenerTls
    fn needs_custom_config(tls: &ListenerTls) -> bool {
        let has_mtls = tls.client_cert_mode != ClientCertMode::None;
        let has_version = tls.min_version.is_some();
        let has_multi_cert = tls.certificates.len() > 1;
        let has_cipher_suites = tls.cipher_suites.is_some();
        has_mtls || has_version || has_multi_cert || has_cipher_suites
    }
}
